#!/usr/bin/env python3
"""Extract API-operation candidates from acquired client artifacts without executing them.

The extractor uses Krineon's structural JavaScript tokenizer plus a bounded
expression/call AST for supported syntax. Unsupported or dynamic expressions
remain symbolic. Literal strings are hints and cannot become confirmed
endpoints without a resolved call or runtime observation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

try:
    from .framework_analysis_pipeline import (
        Token,
        build_relations,
        decode_source_map,
        dotted_name,
        lex_javascript,
        scan_javascript,
    )
    from .semantic_ir import stable_id
    from .web_contract import WebContractError, atomic_json, canonical_origin
except ImportError:
    from framework_analysis_pipeline import (
        Token,
        build_relations,
        decode_source_map,
        dotted_name,
        lex_javascript,
        scan_javascript,
    )
    from semantic_ir import stable_id
    from web_contract import WebContractError, atomic_json, canonical_origin


MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS = 2000
CONFIDENCE = {"literal-hint", "ast-resolved", "runtime-observed", "independently-replayed"}
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
SENSITIVE_FIELD = re.compile(r"(?i)(?:authorization|cookie|token|secret|password|api[-_]?key)")
PATH_HINT = re.compile(r"^(?:https?|wss?)://|^/|^\./|^\.\./")
SECRETISH = re.compile(r"(?i)^(?:bearer\s+|sk[-_]|eyJ[a-zA-Z0-9_-]{8,}|[a-f0-9]{40,}$)")
OPAQUE_PATH_SEGMENT = re.compile(
    r"(?i)^(?:[a-f0-9]{24,}|[A-Za-z0-9_-]{32,}|eyJ[A-Za-z0-9_.-]{16,})$"
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def ensure_under(root: Path, value: str) -> Path:
    path = Path(value)
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise WebContractError("artifact paths must stay under artifactRoot") from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise WebContractError(f"artifact is missing or unsafe: {candidate}")
    if candidate.stat().st_size > MAX_ARTIFACT_BYTES:
        raise WebContractError(f"artifact exceeds 16 MiB: {candidate}")
    return candidate


def matching(tokens: list[Token], start: int, opened: str, closed: str) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].value == opened:
            depth += 1
        elif tokens[index].value == closed:
            depth -= 1
            if depth == 0:
                return index
    return None


def call_arguments(tokens: list[Token], open_index: int) -> list[list[Token]]:
    close = matching(tokens, open_index, "(", ")")
    if close is None:
        return []
    rows: list[list[Token]] = []
    current: list[Token] = []
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    for token in tokens[open_index + 1 : close]:
        if token.value in depths:
            depths[token.value] += 1
        elif token.value in pairs:
            depths[pairs[token.value]] = max(0, depths[pairs[token.value]] - 1)
        if token.value == "," and not any(depths.values()):
            rows.append(current)
            current = []
        else:
            current.append(token)
    if current or rows:
        rows.append(current)
    return rows


def symbolic(tokens: list[Token]) -> str:
    values = []
    for token in tokens:
        if token.kind == "string":
            values.append(json.dumps(token.value))
        elif token.kind == "template":
            values.append("`{dynamic}`" if token.value == "<interpolated>" else f"`{token.value}`")
        else:
            values.append(token.value)
    return "".join(values)[:2000]


def identifiers(tokens: list[Token]) -> list[str]:
    ignored = {
        "new", "true", "false", "null", "undefined", "return", "await",
        "method", "headers", "body", "query", "variables", "url", "baseURL",
    }
    return sorted({token.value for token in tokens if token.kind == "identifier" and token.value not in ignored})


def resolve_expression(
    tokens: list[Token], constants: dict[str, str], *, maximum_depth: int = 8
) -> tuple[str, list[str], bool]:
    if maximum_depth < 1 or not tokens:
        return "{dynamic}", identifiers(tokens), False
    while len(tokens) >= 2 and tokens[0].value == "(" and matching(tokens, 0, "(", ")") == len(tokens) - 1:
        tokens = tokens[1:-1]
    if len(tokens) == 1:
        token = tokens[0]
        if token.kind in {"string", "template"} and token.value != "<interpolated>":
            return token.value, [], True
        if token.kind == "identifier" and token.value in constants:
            return constants[token.value], [], True
        return "{" + token.value + "}", [token.value] if token.kind == "identifier" else [], False
    depth = 0
    pieces: list[list[Token]] = []
    current: list[Token] = []
    for token in tokens:
        if token.value in {"(", "[", "{"}:
            depth += 1
        elif token.value in {")", "]", "}"}:
            depth = max(0, depth - 1)
        if token.value == "+" and depth == 0:
            pieces.append(current)
            current = []
        else:
            current.append(token)
    if pieces:
        pieces.append(current)
        resolved = [resolve_expression(piece, constants, maximum_depth=maximum_depth - 1) for piece in pieces]
        return "".join(item[0] for item in resolved), sorted({name for item in resolved for name in item[1]}), all(item[2] for item in resolved)
    if len(tokens) >= 3 and tokens[0].value == "new" and tokens[1].value == "URL" and tokens[2].value == "(":
        args = call_arguments(tokens, 2)
        if args:
            path, path_deps, path_exact = resolve_expression(args[0], constants, maximum_depth=maximum_depth - 1)
            if len(args) > 1:
                base, base_deps, base_exact = resolve_expression(args[1], constants, maximum_depth=maximum_depth - 1)
                return urljoin(base, path), sorted(set(path_deps + base_deps)), path_exact and base_exact
            return path, path_deps, path_exact
    return "{" + symbolic(tokens) + "}", identifiers(tokens), False


def resolve_url_expression(
    tokens: list[Token], constants: dict[str, str], artifact_url: str
) -> tuple[str, list[str], bool]:
    """Resolve URL constructors using module semantics where explicitly stated."""

    if (
        len(tokens) >= 3
        and tokens[0].value == "new"
        and tokens[1].value == "URL"
        and tokens[2].value == "("
    ):
        args = call_arguments(tokens, 2)
        if args:
            path, dependencies, exact = resolve_expression(args[0], constants)
            if len(args) > 1 and symbolic(args[1]) == "import.meta.url":
                return urljoin(artifact_url, path), dependencies, exact
    return resolve_expression(tokens, constants)


def object_fields(tokens: list[Token]) -> list[str]:
    fields = []
    for index, token in enumerate(tokens[:-1]):
        if token.kind in {"identifier", "string"} and tokens[index + 1].value == ":":
            # Field names describe protocol shape; field values never enter the catalog.
            fields.append(token.value)
    return sorted(set(fields))[:200]


def option_value(tokens: list[Token], name: str) -> list[Token]:
    for index, token in enumerate(tokens[:-1]):
        if token.value == name and tokens[index + 1].value == ":":
            result: list[Token] = []
            depth = 0
            for item in tokens[index + 2 :]:
                if item.value in {"(", "[", "{"}:
                    depth += 1
                elif item.value in {")", "]", "}"}:
                    if depth == 0:
                        break
                    depth -= 1
                if item.value == "," and depth == 0:
                    break
                result.append(item)
            return result
    return []


def source_map_location(map_path: Path | None, root: Path, line: int, column: int) -> dict[str, Any]:
    if map_path is None:
        return {"status": "unavailable"}
    try:
        document = read_object(map_path)
        entries = decode_source_map(map_path, root, document)
    except (OSError, ValueError, WebContractError):
        return {"status": "invalid", "sourceMapSha256": sha256_bytes(map_path.read_bytes())}
    candidates = [row for row in entries if int(row["generatedLine"]) == line]
    if not candidates:
        return {"status": "available-unmapped", "sourceMapSha256": sha256_bytes(map_path.read_bytes())}
    selected = min(candidates, key=lambda row: abs(int(row["generatedColumn"]) - column))
    return {
        "status": "mapped",
        "sourceMapSha256": sha256_bytes(map_path.read_bytes()),
        "source": selected["source"],
        "line": selected["originalLine"],
        "column": selected["originalColumn"],
    }


def normalize_candidate(value: str, document_url: str) -> tuple[str, str, list[dict[str, str]]]:
    if not value:
        return "", "", []
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        absolute = value
    elif value.startswith("/"):
        absolute = urljoin(document_url, value)
    else:
        absolute = urljoin(document_url, value)
    parsed = urlsplit(absolute)
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        return "", value, []
    http_origin = ("https" if parsed.scheme == "wss" else "http" if parsed.scheme == "ws" else parsed.scheme) + "://" + parsed.netloc
    try:
        origin = canonical_origin(http_origin)
    except WebContractError:
        return "", value, []
    path = safe_path_template(parsed.path or "/")
    return origin, path, [
        {"name": name, "value": "{value}"}
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
    ]


def safe_url_template(value: str, document_url: str) -> str:
    """Retain URL shape without publishing concrete query values."""

    absolute = urljoin(document_url, value)
    parsed = urlsplit(absolute)
    fields = parse_qsl(parsed.query, keep_blank_values=True)
    query = "&".join(f"{name}={{value}}" for name, _value in fields)
    host = parsed.hostname or ""
    if parsed.port is not None:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme, host, safe_path_template(parsed.path), query, ""))


def safe_path_template(path: str) -> str:
    return "/".join(
        "{opaque}" if OPAQUE_PATH_SEGMENT.fullmatch(segment) else segment
        for segment in path.split("/")
    ) or "/"


def literal_kind(value: str) -> str:
    lowered = value.lower()
    if re.search(r"\.(?:js|mjs|css|map|png|jpe?g|svg|woff2?)(?:[?#]|$)", lowered):
        return "static-asset"
    if "example." in lowered or "/docs" in lowered or "/documentation" in lowered:
        return "documentation-or-example"
    return "literal-candidate"


def constants_and_clients(tokens: list[Token]) -> tuple[dict[str, str], dict[str, str]]:
    constants: dict[str, str] = {}
    clients: dict[str, str] = {}
    for index, token in enumerate(tokens):
        if token.value != "=" or index < 1 or tokens[index - 1].kind != "identifier":
            continue
        target = tokens[index - 1].value
        end = index + 1
        depth = 0
        while end < len(tokens):
            if tokens[end].value in {"(", "[", "{"}:
                depth += 1
            elif tokens[end].value in {")", "]", "}"}:
                depth = max(0, depth - 1)
            if depth == 0 and tokens[end].value == ";":
                break
            end += 1
        expression = tokens[index + 1 : end]
        value, deps, exact = resolve_expression(expression, constants)
        if exact and not deps and len(value) <= 4096:
            constants[target] = value
        text = symbolic(expression)
        if "axios.create(" in text or ".create(" in text:
            base = option_value(expression, "baseURL")
            if base:
                clients[target] = resolve_expression(base, constants)[0]
    return constants, clients


def wrapper_names(tokens: list[Token]) -> set[str]:
    wrappers: set[str] = set()
    for index, token in enumerate(tokens[:-2]):
        if token.value == "function" and tokens[index + 1].kind == "identifier":
            open_body = next((i for i in range(index + 2, min(len(tokens), index + 200)) if tokens[i].value == "{"), None)
            if open_body is None:
                continue
            close = matching(tokens, open_body, "{", "}")
            body = tokens[open_body + 1 : close] if close is not None else []
            if any(item.value in {"fetch", "axios", "XMLHttpRequest"} for item in body):
                wrappers.add(tokens[index + 1].value)
        if token.value == "=>" and index >= 3:
            assignment = next(
                (
                    cursor
                    for cursor in range(index - 1, max(-1, index - 30), -1)
                    if tokens[cursor].value == "="
                    and cursor > 0
                    and tokens[cursor - 1].kind == "identifier"
                ),
                None,
            )
            name = tokens[assignment - 1].value if assignment is not None else ""
            body = tokens[index + 1 : min(len(tokens), index + 80)]
            if name and any(item.value in {"fetch", "axios", "XMLHttpRequest"} for item in body):
                wrappers.add(name)
    return wrappers


def wrapper_url_templates(
    tokens: list[Token], constants: dict[str, str], wrappers: set[str]
) -> dict[str, dict[str, Any]]:
    """Resolve small arrow wrappers without evaluating application code."""

    templates: dict[str, dict[str, Any]] = {}
    for index, token in enumerate(tokens):
        if token.value != "=>":
            continue
        assignment = next(
            (
                cursor
                for cursor in range(index - 1, max(-1, index - 30), -1)
                if tokens[cursor].value == "="
                and cursor > 0
                and tokens[cursor - 1].kind == "identifier"
            ),
            None,
        )
        if assignment is None:
            continue
        name = tokens[assignment - 1].value
        if name not in wrappers:
            continue
        parameters = [
            item.value
            for item in tokens[assignment + 1 : index]
            if item.kind == "identifier"
        ]
        if not parameters:
            continue
        body = tokens[index + 1 : min(len(tokens), index + 120)]
        for local_index, item in enumerate(body):
            if item.value != "(" or local_index < 1:
                continue
            callee, _start = dotted_name(body, local_index - 1)
            if callee not in {"fetch", "axios"}:
                continue
            args = call_arguments(body, local_index)
            if not args:
                continue
            template, dependencies, _exact = resolve_expression(args[0], constants)
            if not any(parameter in dependencies for parameter in parameters):
                continue
            templates[name] = {
                "template": template,
                "parameters": parameters,
                "confidence": "bounded-wrapper-template",
            }
            break
    return templates


def call_candidates(
    *,
    tokens: list[Token],
    constants: dict[str, str],
    clients: dict[str, str],
    wrappers: set[str],
    wrapper_templates: dict[str, dict[str, Any]],
    artifact: dict[str, Any],
    script_hash: str,
    map_path: Path | None,
    root: Path,
    deployment_epoch: str,
    framework_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    document_url = str(
        artifact.get("documentBaseUrl")
        or artifact.get("documentUrl")
        or artifact.get("referringPage")
        or artifact.get("url")
        or ""
    )
    artifact_url = str(artifact.get("url") or document_url)
    for index, token in enumerate(tokens):
        if token.value != "(" or index < 1:
            continue
        callee, start = dotted_name(tokens, index - 1)
        if not callee:
            continue
        args = call_arguments(tokens, index)
        leaf = callee.rsplit(".", 1)[-1]
        receiver = callee.rsplit(".", 1)[0] if "." in callee else ""
        kind = ""
        method = ""
        url_tokens: list[Token] = []
        graphql_operation = ""
        rpc_action = ""
        if callee == "fetch" or leaf in wrappers:
            kind, method = "http-api", "GET"
            url_tokens = args[0] if args else []
            if len(args) > 1:
                method_tokens = option_value(args[1], "method")
                if method_tokens:
                    method_value = resolve_expression(method_tokens, constants)[0].upper()
                    if method_value in HTTP_METHODS:
                        method = method_value
        elif callee == "axios" and args:
            kind, method = "http-api", "GET"
            url_tokens = option_value(args[0], "url")
            method_tokens = option_value(args[0], "method")
            if method_tokens:
                method_value = resolve_expression(method_tokens, constants)[0].upper()
                if method_value in HTTP_METHODS:
                    method = method_value
        elif leaf.lower() in {value.lower() for value in HTTP_METHODS} and (receiver in clients or receiver in {"axios", "client", "api"}):
            kind, method = "http-api", leaf.upper()
            url_tokens = args[0] if args else []
        elif leaf == "open" and len(args) >= 2:
            kind = "xhr"
            method = resolve_expression(args[0], constants)[0].upper()
            url_tokens = args[1]
        elif leaf in {"WebSocket", "EventSource"}:
            kind = "websocket" if leaf == "WebSocket" else "event-stream"
            method = "CONNECT" if leaf == "WebSocket" else "GET"
            url_tokens = args[0] if args else []
        elif leaf in {"query", "mutate", "subscribe"} or "graphql" in callee.lower():
            kind = "graphql"
            method = "POST"
            url_tokens = []
            operation_tokens = option_value(args[0], "query") if args else []
            graphql_operation = symbolic(operation_tokens)[:500]
        elif leaf in {"request", "call", "dispatch", "invoke"} and args:
            method_tokens = option_value(args[0], "method")
            if method_tokens:
                kind = "rpc"
                method = "POST"
                rpc_action = resolve_expression(method_tokens, constants)[0]
        if not kind:
            continue
        resolved, dynamic_values, exact = (
            resolve_url_expression(url_tokens, constants, artifact_url)
            if url_tokens
            else ("", [], False)
        )
        if leaf in wrapper_templates and args:
            invocation_values = [resolve_expression(argument, constants) for argument in args]
            wrapper = wrapper_templates[leaf]
            wrapper_value = str(wrapper["template"])
            wrapper_dependencies: list[str] = []
            wrapper_exact = True
            for position, parameter in enumerate(wrapper["parameters"]):
                if position >= len(invocation_values):
                    wrapper_dependencies.append(parameter)
                    wrapper_exact = False
                    continue
                value, dependencies, value_exact = invocation_values[position]
                wrapper_value = wrapper_value.replace("{" + parameter + "}", value)
                wrapper_dependencies.extend(dependencies)
                wrapper_exact = wrapper_exact and value_exact
            resolved = wrapper_value
            dynamic_values = sorted(set(wrapper_dependencies))
            exact = wrapper_exact and "{" not in wrapper_value
        if receiver in clients and resolved:
            resolved = urljoin(clients[receiver].rstrip("/") + "/", resolved.lstrip("/"))
        origin, path_template, query = normalize_candidate(resolved, document_url)
        option_tokens = args[1] if kind == "http-api" and len(args) > 1 else (args[0] if args else [])
        header_names = [
            field for field in object_fields(option_value(option_tokens, "headers"))
        ]
        auth_deps = sorted(
            name for name in header_names if re.search(r"(?i)(auth|csrf|xsrf|signature|token|cookie)", name)
        )
        content_type_tokens = option_value(option_value(option_tokens, "headers"), "Content-Type") or option_value(option_value(option_tokens, "headers"), "content-type")
        content_type = resolve_expression(content_type_tokens, constants)[0] if content_type_tokens else ""
        body_tokens = option_value(option_tokens, "body")
        query_fields = sorted({item["name"] for item in query})
        body_fields = object_fields(body_tokens)
        query_text = ""
        parsed_resolved = urlsplit(urljoin(document_url, resolved)) if resolved else None
        if parsed_resolved is not None:
            for name, value in parse_qsl(parsed_resolved.query, keep_blank_values=True):
                if name.lower() in {"query", "operation", "operationname"}:
                    query_text = value
                    break
        if kind == "http-api" and ("graphql" in path_template.lower() or query_text):
            kind = "graphql"
            operation_match = re.search(
                r"(?i)\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)",
                query_text,
            )
            graphql_operation = (
                operation_match.group(1)
                if operation_match
                else query_text[:200]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", query_text)
                else ""
            )
        option_text = symbolic(option_tokens)
        persisted_match = re.search(
            r"(?i)(?:sha256Hash|persistedQuery)[^a-f0-9]{0,64}([a-f0-9]{64})",
            option_text,
        )
        persisted_hash = persisted_match.group(1).lower() if persisted_match else ""
        source_location = {"line": token.line, "column": token.column}
        source_mapping = source_map_location(map_path, root, token.line, token.column)
        supporting_facts = [
            fact
            for fact in framework_facts
            if int(fact.get("line") or 0) == token.line
            and fact.get("kind") in {"call-operation", "dynamic-import", "static-import"}
            and (
                fact.get("kind") != "call-operation"
                or str(fact.get("callee") or "") == callee
            )
        ]
        endpoint_key = [
            origin,
            path_template,
            method,
            kind,
            graphql_operation,
            persisted_hash,
            rpc_action,
            content_type,
        ]
        rows.append(
            {
                "endpointId": stable_id("WEB-E", *endpoint_key),
                "canonicalOrigin": origin,
                "rawPathTemplate": safe_url_template(resolved, document_url) if resolved else "",
                "semanticPathTemplate": path_template,
                "candidateMethods": [method] if method else [],
                "requestContentType": content_type,
                "symbolicQueryFields": query_fields,
                "symbolicBodyFields": body_fields,
                "operationKind": kind,
                "graphqlOperation": graphql_operation,
                "persistedQueryHash": persisted_hash,
                "rpcAction": rpc_action,
                "originatingScriptSha256": script_hash,
                "sourceLocation": source_location,
                "sourceMapMapping": source_mapping,
                "initiatorAction": str(artifact.get("journey") or ""),
                "actor": str(artifact.get("identityId") or "anonymous"),
                "tenant": str(artifact.get("tenant") or ""),
                "session": str(artifact.get("session") or ""),
                "workflowPrerequisites": list(artifact.get("workflowPrerequisites") or []),
                "authDependencies": auth_deps,
                "csrfDependencies": [name for name in auth_deps if re.search(r"(?i)(csrf|xsrf)", name)],
                "signingDependencies": [name for name in auth_deps if "sign" in name.lower()],
                "dynamicValueDependencies": dynamic_values,
                "confidence": "ast-resolved",
                "expressionFullyResolved": exact,
                "effectClassification": "unknown",
                "scopeApprovalStatus": "candidate-not-authorized",
                "deploymentEpoch": deployment_epoch,
                "validationAttempts": [],
                "relatedResources": [],
                "consumerHypotheses": [],
                "callee": callee,
                "frameworkFactIds": [str(fact.get("id")) for fact in supporting_facts],
                "frameworkFactConfidence": "structural-candidate" if supporting_facts else "unlinked",
                "provenance": {
                    "kind": "bounded-call-ast",
                    "artifactUrl": artifact.get("url"),
                    "artifactSha256": script_hash,
                    "retrievalOrigin": artifact.get("retrievalOrigin"),
                    "frameworkFactIds": [str(fact.get("id")) for fact in supporting_facts],
                    "confidenceBasis": "resolved call expression; runtime confirmation remains separate",
                },
            }
        )
    return rows


def runtime_requests(events_path: Path, observation: dict[str, Any], epoch: str) -> list[dict[str, Any]]:
    events = json.loads(events_path.read_text(encoding="utf-8"))
    if not isinstance(events, list):
        raise WebContractError("CDP events must be an array")
    responses: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict) or event.get("method") != "Network.responseReceived":
            continue
        params = event.get("params") or {}
        responses[str(params.get("requestId") or "")] = params
    rows = []
    for event in events:
        if not isinstance(event, dict) or event.get("method") != "Network.requestWillBeSent":
            continue
        params = event.get("params") or {}
        request = params.get("request") or {}
        url = str(request.get("url") or "")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            continue
        origin, path, query = normalize_candidate(url, url)
        method = str(request.get("method") or "GET").upper()
        headers = request.get("headers") or {}
        content_type = next((str(value) for name, value in headers.items() if str(name).lower() == "content-type"), "") if isinstance(headers, dict) else ""
        initiator = params.get("initiator") or {}
        response_params = responses.get(str(params.get("requestId") or ""), {})
        response = response_params.get("response") or {}
        kind = "websocket" if parsed.scheme in {"ws", "wss"} else (
            "graphql" if "graphql" in path.lower() else "http-api"
        )
        graphql_operation = ""
        if kind == "graphql":
            values = dict(parse_qsl(parsed.query, keep_blank_values=True))
            raw_operation = (
                values.get("operationName")
                or values.get("operation")
                or values.get("query")
                or ""
            )
            operation_match = re.search(
                r"(?i)\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)",
                raw_operation,
            )
            graphql_operation = operation_match.group(1) if operation_match else (
                raw_operation
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw_operation)
                else ""
            )
        rows.append(
            {
                "endpointId": stable_id(
                    "WEB-E", origin, path, method, kind, graphql_operation, "", content_type
                ),
                "canonicalOrigin": origin,
                "rawPathTemplate": safe_url_template(url, url),
                "semanticPathTemplate": path,
                "candidateMethods": [method],
                "requestContentType": content_type,
                "symbolicQueryFields": sorted({item["name"] for item in query}),
                "symbolicBodyFields": [],
                "operationKind": kind,
                "graphqlOperation": graphql_operation,
                "persistedQueryHash": "",
                "rpcAction": "",
                "originatingScriptSha256": "",
                "sourceLocation": {},
                "sourceMapMapping": {"status": "runtime-initiator"},
                "initiatorAction": str(initiator.get("type") or "browser"),
                "initiator": {
                    "type": initiator.get("type"),
                    "url": (initiator.get("url") or "")[:2000],
                    "stackPresent": isinstance(initiator.get("stack"), dict),
                },
                "runtimeResponse": {
                    "status": int(response.get("status") or 0),
                    "mimeType": str(response.get("mimeType") or ""),
                    "resourceType": str(response_params.get("type") or ""),
                    "fromDiskCache": bool(response.get("fromDiskCache")),
                    "fromServiceWorker": bool(response.get("fromServiceWorker")),
                },
                "actor": str(observation.get("identityId") or "anonymous"),
                "tenant": str(observation.get("expectedTenant") or ""),
                "session": str((observation.get("identity") or {}).get("session") or ""),
                "workflowPrerequisites": [str(observation.get("stepId") or "")],
                "authDependencies": [],
                "csrfDependencies": [],
                "signingDependencies": [],
                "dynamicValueDependencies": [],
                "confidence": "runtime-observed",
                "expressionFullyResolved": True,
                "effectClassification": "unknown",
                "scopeApprovalStatus": "observed-not-authorized-for-replay",
                "deploymentEpoch": epoch,
                "validationAttempts": [],
                "relatedResources": [],
                "consumerHypotheses": [],
                "provenance": {
                    "kind": "cdp-network-event",
                    "requestId": params.get("requestId"),
                    "loaderId": params.get("loaderId"),
                },
            }
        )
    return rows


def extract(manifest_path: Path, root: Path) -> dict[str, Any]:
    manifest = read_object(manifest_path)
    if manifest.get("schemaVersion") != 1:
        raise WebContractError("artifact manifest schemaVersion must be 1")
    epoch = str(manifest.get("deploymentEpoch") or "")
    if not epoch:
        raise WebContractError("artifact manifest requires deploymentEpoch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > MAX_ARTIFACTS:
        raise WebContractError("artifact manifest requires 1..2000 artifacts")
    candidates: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    artifact_ledger: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    framework_fact_count = 0
    framework_relation_count = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("retrievalApproved") is not True:
            raise WebContractError("every artifact requires reviewed retrievalApproved=true")
        path = ensure_under(root, str(artifact.get("path") or ""))
        payload = path.read_bytes()
        content_hash = sha256_bytes(payload)
        expected = str(artifact.get("sha256") or content_hash)
        if expected != content_hash:
            raise WebContractError(f"artifact hash mismatch: {path}")
        source = payload.decode("utf-8", errors="replace")
        tokens = lex_javascript(source)
        framework_facts, _inventory = scan_javascript(
            path,
            root,
            "acquired-client-artifact",
            set(),
            set(),
            MAX_ARTIFACT_BYTES,
        )
        framework_relations = build_relations(root, framework_facts)
        framework_fact_count += len(framework_facts)
        framework_relation_count += len(framework_relations)
        constants, clients = constants_and_clients(tokens)
        wrappers = wrapper_names(tokens)
        wrapper_templates = wrapper_url_templates(tokens, constants, wrappers)
        map_path = ensure_under(root, str(artifact["sourceMapPath"])) if artifact.get("sourceMapPath") else None
        rows = call_candidates(
            tokens=tokens,
            constants=constants,
            clients=clients,
            wrappers=wrappers,
            wrapper_templates=wrapper_templates,
            artifact=artifact,
            script_hash=content_hash,
            map_path=map_path,
            root=root,
            deployment_epoch=epoch,
            framework_facts=framework_facts,
        )
        candidates.extend(rows)
        for token in tokens:
            if token.kind not in {"string", "template"} or token.value == "<interpolated>":
                continue
            if not PATH_HINT.search(token.value) or SECRETISH.search(token.value):
                continue
            literal_base = str(
                artifact.get("documentBaseUrl")
                or artifact.get("documentUrl")
                or artifact.get("url")
                or ""
            )
            origin, path_template, query = normalize_candidate(token.value, literal_base)
            hints.append(
                {
                    "hintId": stable_id("WEB-H", content_hash, token.line, token.column, token.value),
                    "canonicalOrigin": origin,
                    "rawValue": safe_url_template(
                        token.value,
                        literal_base,
                    )[:2000],
                    "semanticPathTemplate": path_template,
                    "queryFields": sorted({item["name"] for item in query}),
                    "classification": literal_kind(token.value),
                    "confidence": "literal-hint",
                    "originatingScriptSha256": content_hash,
                    "sourceLocation": {"line": token.line, "column": token.column},
                    "scopeApprovalStatus": "candidate-not-authorized",
                }
            )
        artifact_ledger.append(
            {
                "url": artifact.get("url"),
                "path": str(path.relative_to(root)),
                "sha256": content_hash,
                "size": len(payload),
                "kind": artifact.get("kind", "script"),
                "deploymentEpoch": epoch,
                "retrievalOrigin": artifact.get("retrievalOrigin"),
                "referringPage": artifact.get("referringPage"),
                "identityId": artifact.get("identityId", "anonymous"),
                "tenant": artifact.get("tenant", ""),
                "journey": artifact.get("journey", ""),
                "sourceMap": {
                    "available": map_path is not None,
                    "path": str(map_path.relative_to(root)) if map_path else "",
                    "provenance": artifact.get("sourceMapProvenance", "not-observed"),
                },
                "astFrontend": {
                    "kind": "bounded-structural-expression-and-call-ast",
                    "tokens": len(tokens),
                    "resolvedConstants": len(constants),
                    "customWrappers": sorted(wrappers),
                    "resolvedWrapperTemplates": sorted(wrapper_templates),
                    "unsupportedSyntaxMayRemain": True,
                },
                "frameworkAnalysis": {
                    "facts": len(framework_facts),
                    "relations": len(framework_relations),
                    "callFacts": sum(
                        1 for fact in framework_facts if fact.get("kind") == "call-operation"
                    ),
                    "moduleFacts": sum(
                        1
                        for fact in framework_facts
                        if fact.get("kind") in {"static-import", "dynamic-import"}
                    ),
                    "confidence": "structural-candidate",
                },
            }
        )
        unresolved.extend(
            {
                "endpointId": row["endpointId"],
                "expression": row["rawPathTemplate"],
                "dependencies": row["dynamicValueDependencies"],
            }
            for row in rows
            if not row["expressionFullyResolved"]
        )
    runtime = []
    for item in manifest.get("runtimeObservations", []):
        if not isinstance(item, dict):
            raise WebContractError("runtimeObservations entries must be objects")
        observation_path = ensure_under(root, str(item.get("browserObservationPath") or ""))
        events_path = ensure_under(root, str(item.get("cdpEventsPath") or ""))
        runtime.extend(runtime_requests(events_path, read_object(observation_path), epoch))
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-js-api-extraction",
        "deploymentEpoch": epoch,
        "manifestSha256": sha256_bytes(manifest_path.read_bytes()),
        "bundleCodeExecutedByExtractor": False,
        "artifactLedger": artifact_ledger,
        "endpointCandidates": candidates,
        "literalHints": hints,
        "runtimeOperations": runtime,
        "unresolvedExpressions": unresolved,
        "unavailableArtifacts": list(manifest.get("unavailableArtifacts") or []),
        "journeys": list(manifest.get("journeys") or []),
        "coverageGaps": list(manifest.get("coverageGaps") or []) + [
            "Runtime-computed, server-only, feature-gated, unvisited, and role-dependent endpoints may remain unknown.",
            "The bounded AST frontend does not claim complete ECMAScript or application coverage.",
        ],
        "frameworkFacts": {
            "path": manifest.get("frameworkFactsPath", ""),
            "extractedFromAcquiredArtifacts": framework_fact_count,
            "structuralRelations": framework_relation_count,
            "usedAsHintsOnly": True,
            "unknownCallsPromoted": False,
            "confidenceConvention": "structural-candidate until runtime-observed or independently-replayed",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = Path(args.manifest).expanduser().resolve()
        root = Path(args.artifact_root).expanduser().resolve()
        result = extract(manifest, root)
        atomic_json(Path(args.output).expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"astCandidates": len(result["endpointCandidates"]), "runtimeOperations": len(result["runtimeOperations"]), "literalHints": len(result["literalHints"]), "coverageGaps": len(result["coverageGaps"])}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
