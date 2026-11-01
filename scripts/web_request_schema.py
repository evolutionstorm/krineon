#!/usr/bin/env python3
"""Strict metadata and dual raw/semantic schema for imported web requests."""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

try:
    import yaml
except ImportError:  # pragma: no cover - reported at the trusted importer boundary.
    yaml = None

try:
    from .web_contract import (
        EFFECT_CLASSES,
        WebCampaignContract,
        WebContractError,
        canonical_origin,
        require_identifier,
    )
except ImportError:
    from web_contract import (
        EFFECT_CLASSES,
        WebCampaignContract,
        WebContractError,
        canonical_origin,
        require_identifier,
    )


SECRET_PLACEHOLDER = re.compile(
    r"^(?:\{\{secret:|\$\{secret:)([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\}?\}$"
)
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
PSEUDO_NAME = re.compile(r"^:[a-z0-9-]+$")


if yaml is not None:
    class UniqueSafeLoader(yaml.SafeLoader):
        pass


    def _unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise WebContractError("metadata mapping keys must be strings")
            if key in mapping:
                raise WebContractError(f"duplicate metadata key: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping


    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
    )


def load_metadata(text: str) -> dict[str, Any]:
    if yaml is None:
        raise WebContractError(
            "PyYAML is required for strict krineon-web metadata parsing"
        )
    if (
        "!!" in text
        or re.search(r"(?m)(?:^|[\s\[{,])[&*][A-Za-z0-9_-]+", text)
        or re.search(r"(?m)^\s*<<\s*:", text)
    ):
        raise WebContractError("metadata tags, anchors, aliases, and merge keys are forbidden")
    try:
        value = yaml.load(text, Loader=UniqueSafeLoader)
    except WebContractError:
        raise
    except yaml.YAMLError as exc:
        raise WebContractError(f"invalid krineon-web metadata: {exc}") from exc
    if not isinstance(value, dict):
        raise WebContractError("krineon-web metadata must be a mapping")
    return value


def _allowed_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value).difference(allowed)
    if unknown:
        raise WebContractError(
            f"{label} contains unknown keys: " + ", ".join(sorted(unknown))
        )


def validate_metadata(
    metadata: dict[str, Any], contract: WebCampaignContract
) -> dict[str, Any]:
    _allowed_keys(
        metadata,
        {
            "schemaVersion",
            "baseUrl",
            "origin",
            "purpose",
            "defaultWorkflow",
            "identities",
            "requests",
        },
        "metadata",
    )
    if metadata.get("schemaVersion") != 1:
        raise WebContractError("request bundle schemaVersion must be 1")
    base_url = str(metadata.get("baseUrl") or "")
    parsed_base = urlsplit(base_url)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
        raise WebContractError("baseUrl must be an absolute HTTP(S) URL")
    base_origin = canonical_origin(f"{parsed_base.scheme}://{parsed_base.netloc}")
    matches = [item for item in contract.origins.values() if item.origin == base_origin]
    if len(matches) != 1:
        raise WebContractError("baseUrl does not select one declared contract origin")
    default_origin = str(metadata.get("origin") or matches[0].id)
    if default_origin != matches[0].id:
        raise WebContractError("metadata origin conflicts with baseUrl")
    default_purpose = str(metadata.get("purpose") or matches[0].purpose)
    if default_purpose != matches[0].purpose:
        raise WebContractError("metadata purpose conflicts with contract origin purpose")
    default_workflow = require_identifier(
        metadata.get("defaultWorkflow") or "default", "defaultWorkflow"
    )

    identities = metadata.get("identities", {})
    if not isinstance(identities, dict):
        raise WebContractError("identities must be a mapping")
    normalized_identities: dict[str, Any] = {}
    for identity_id, item in identities.items():
        identity_id = require_identifier(identity_id, "identity id")
        if not isinstance(item, dict):
            raise WebContractError(f"identity {identity_id} must be a mapping")
        _allowed_keys(
            item,
            {"tenant", "credentialRef", "roles", "session"},
            f"identity {identity_id}",
        )
        contract_identity = contract.identity(identity_id)
        if contract_identity is None:
            raise WebContractError(f"metadata cannot redefine anonymous as {identity_id}")
        tenant = str(item.get("tenant") or "")
        credential_ref = str(item.get("credentialRef") or "")
        if tenant != contract_identity.expected_tenant:
            raise WebContractError(
                f"identity {identity_id} tenant conflicts with the campaign contract"
            )
        if credential_ref != contract_identity.credential_ref:
            raise WebContractError(
                f"identity {identity_id} credentialRef conflicts with the campaign contract"
            )
        roles = item.get("roles", list(contract_identity.roles))
        if not isinstance(roles, list) or tuple(str(value) for value in roles) != tuple(
            contract_identity.roles
        ):
            raise WebContractError(
                f"identity {identity_id} roles conflict with the campaign contract"
            )
        session = str(item.get("session") or contract_identity.session)
        if session != contract_identity.session:
            raise WebContractError(
                f"identity {identity_id} session conflicts with the campaign contract"
            )
        normalized_identities[identity_id] = {
            "tenant": tenant,
            "credentialRef": credential_ref,
            "roles": list(roles),
            "session": session,
        }

    requests = metadata.get("requests")
    if not isinstance(requests, dict) or not requests:
        raise WebContractError("requests must be a nonempty mapping")
    normalized_requests: dict[str, Any] = {}
    for request_id, item in requests.items():
        request_id = require_identifier(request_id, "request id")
        if not isinstance(item, dict):
            raise WebContractError(f"request {request_id} must be a mapping")
        _allowed_keys(
            item,
            {
                "identity",
                "workflow",
                "origin",
                "purpose",
                "effect",
                "ownedResource",
                "resourceKind",
                "expectedOwner",
                "expectedRule",
                "dependsOn",
                "bodyBase64",
                "bodySidecar",
                "signed",
                "authenticationBoundFields",
                "protocol",
            },
            f"request {request_id}",
        )
        identity_id = str(item.get("identity") or "anonymous")
        if identity_id != "anonymous" and identity_id not in normalized_identities:
            raise WebContractError(
                f"request {request_id} has an ambiguous or undeclared identity"
            )
        origin_id = str(item.get("origin") or default_origin)
        if origin_id != default_origin:
            raise WebContractError(
                f"request {request_id} origin conflicts with bundle baseUrl"
            )
        purpose = str(item.get("purpose") or default_purpose)
        if purpose != default_purpose:
            raise WebContractError(
                f"request {request_id} purpose conflicts with contract origin"
            )
        effect = str(item.get("effect") or "unknown")
        if effect not in EFFECT_CLASSES:
            raise WebContractError(f"request {request_id} has an invalid effect")
        owned_resource = str(item.get("ownedResource") or "")
        expected_rule = str(item.get("expectedRule") or "")
        if not owned_resource or not expected_rule:
            raise WebContractError(
                f"request {request_id} requires ownedResource and expectedRule"
            )
        dependencies = item.get("dependsOn", [])
        if not isinstance(dependencies, list) or any(
            not isinstance(value, str) for value in dependencies
        ):
            raise WebContractError(f"request {request_id} dependsOn must be an array")
        if request_id in dependencies:
            raise WebContractError(f"request {request_id} cannot depend on itself")
        body_fields = [name for name in ("bodyBase64", "bodySidecar") if item.get(name)]
        if len(body_fields) > 1:
            raise WebContractError(
                f"request {request_id} cannot use both bodyBase64 and bodySidecar"
            )
        if item.get("bodyBase64"):
            try:
                base64.b64decode(str(item["bodyBase64"]), validate=True)
            except (ValueError, binascii.Error) as exc:
                raise WebContractError(
                    f"request {request_id} bodyBase64 is invalid"
                ) from exc
        bound_fields = item.get("authenticationBoundFields", [])
        if not isinstance(bound_fields, list) or any(
            not isinstance(value, str) or not value for value in bound_fields
        ):
            raise WebContractError(
                f"request {request_id} authenticationBoundFields must be an array"
            )
        if item.get("signed") is True and not bound_fields:
            raise WebContractError(
                f"signed request {request_id} requires authenticationBoundFields"
            )
        protocol = str(item.get("protocol") or "auto")
        if protocol not in {"auto", "http/1.1", "http/2"}:
            raise WebContractError(f"request {request_id} has an invalid protocol")
        normalized_requests[request_id] = {
            "identity": identity_id,
            "workflow": require_identifier(
                item.get("workflow") or default_workflow,
                f"request {request_id} workflow",
            ),
            "origin": origin_id,
            "purpose": purpose,
            "effect": effect,
            "ownedResource": owned_resource,
            "resourceKind": str(item.get("resourceKind") or "owned-resource"),
            "expectedOwner": str(
                item.get("expectedOwner")
                or (identity_id if identity_id != "anonymous" else "public")
            ),
            "expectedRule": expected_rule,
            "dependsOn": list(dependencies),
            "bodyBase64": item.get("bodyBase64"),
            "bodySidecar": item.get("bodySidecar"),
            "signed": item.get("signed") is True,
            "authenticationBoundFields": list(bound_fields),
            "protocol": protocol,
        }
    for request_id, item in normalized_requests.items():
        unknown = set(item["dependsOn"]).difference(normalized_requests)
        if unknown:
            raise WebContractError(
                f"request {request_id} depends on undeclared requests: "
                + ", ".join(sorted(unknown))
            )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(request_id: str) -> None:
        if request_id in visiting:
            raise WebContractError("request dependency graph contains a cycle")
        if request_id in visited:
            return
        visiting.add(request_id)
        for dependency in normalized_requests[request_id]["dependsOn"]:
            visit(dependency)
        visiting.remove(request_id)
        visited.add(request_id)

    for request_id in normalized_requests:
        visit(request_id)
    return {
        "schemaVersion": 1,
        "baseUrl": base_url,
        "origin": default_origin,
        "purpose": default_purpose,
        "defaultWorkflow": default_workflow,
        "identities": normalized_identities,
        "requests": normalized_requests,
    }


def _header(name: str, value: str, raw_line: str) -> dict[str, str]:
    if not HEADER_NAME.fullmatch(name):
        raise WebContractError(f"invalid HTTP header name: {name}")
    if "\r" in value or "\n" in value:
        raise WebContractError("HTTP header value contains a line break")
    return {
        "name": name,
        "value": value,
        "rawLineBase64": base64.b64encode(raw_line.encode("utf-8")).decode("ascii"),
    }


def _semantic_target(target: str) -> dict[str, Any]:
    parsed = urlsplit(target)
    path = parsed.path or "/"
    return {
        "target": target,
        "path": path,
        "rawQuery": parsed.query,
        "query": [
            {"name": name, "value": value}
            for name, value in parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=False,
                encoding="utf-8",
                errors="strict",
            )
        ],
    }


def parse_http_request(
    raw: str,
    *,
    fence: str,
    metadata: dict[str, Any],
    contract: WebCampaignContract,
    source_dir: Path,
) -> dict[str, Any]:
    line_separator = "\r\n" if "\r\n" in raw else "\n"
    head, separator, inline_body = raw.partition(line_separator + line_separator)
    lines = head.split(line_separator)
    if lines and lines[-1] == "":
        lines.pop()
    byte_exact_headers = bool(separator) and "\r\n" in raw and not re.search(
        r"(?<!\r)\n", raw
    )
    if not lines or not lines[0]:
        raise WebContractError("HTTP request block is empty")
    protocol = "http/2" if fence.lower() == "http2" else "http/1.1"
    declared = metadata["protocol"]
    if declared != "auto" and declared != protocol:
        raise WebContractError("request protocol conflicts with its fenced representation")
    headers: list[dict[str, str]] = []
    pseudo_headers: list[dict[str, str]] = []
    request_line = ""
    method = ""
    target = ""
    version = ""
    if protocol == "http/1.1":
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            raise WebContractError(
                "HTTP/1 request must start with METHOD TARGET HTTP/VERSION"
            )
        method, target, version = parts
        header_lines = lines[1:]
    else:
        header_lines = lines
        seen_regular = False
        for raw_line in header_lines:
            pseudo_match = re.match(r"^(:[a-z0-9-]+):[ \t]*(.*)$", raw_line)
            if pseudo_match:
                if seen_regular:
                    raise WebContractError("HTTP/2 pseudo-headers must precede fields")
                name, value = pseudo_match.groups()
                if not PSEUDO_NAME.fullmatch(name) or any(
                    item["name"] == name for item in pseudo_headers
                ):
                    raise WebContractError("invalid or duplicate HTTP/2 pseudo-header")
                pseudo_headers.append(
                    {
                        "name": name,
                        "value": value,
                        "rawLineBase64": base64.b64encode(
                            raw_line.encode("utf-8")
                        ).decode("ascii"),
                    }
                )
                continue
            seen_regular = True
            if ":" not in raw_line:
                raise WebContractError("HTTP header is missing a colon")
            name, value = raw_line.split(":", 1)
            headers.append(_header(name, value.lstrip(" \t"), raw_line))
        pseudo = {item["name"]: item["value"] for item in pseudo_headers}
        required = {":method", ":scheme", ":authority", ":path"}
        if set(pseudo) != required:
            raise WebContractError(
                "HTTP/2 request requires exactly :method, :scheme, :authority, and :path"
            )
        method, target, version = pseudo[":method"], pseudo[":path"], "HTTP/2"
        if any(item["name"].lower() == "host" for item in headers):
            raise WebContractError("HTTP/2 requests must use :authority, not Host")
    if protocol == "http/1.1":
        for raw_line in header_lines:
            if ":" not in raw_line:
                raise WebContractError("HTTP header is missing a colon")
            name, value = raw_line.split(":", 1)
            headers.append(_header(name, value.lstrip(" \t"), raw_line))
    if not re.fullmatch(r"[A-Za-z]+", method):
        raise WebContractError("request method is invalid")
    method = method.upper()
    body = inline_body.encode("utf-8") if separator else b""
    body_exact = byte_exact_headers
    if metadata.get("bodyBase64"):
        body = base64.b64decode(str(metadata["bodyBase64"]), validate=True)
        body_exact = True
    elif metadata.get("bodySidecar"):
        relative = Path(str(metadata["bodySidecar"]))
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.parts[0] != "sidecars"
        ):
            raise WebContractError(
                "bodySidecar must remain under the Markdown sidecars directory"
            )
        sidecar = (source_dir / relative).resolve()
        sidecar.relative_to((source_dir / "sidecars").resolve())
        if sidecar.is_symlink() or not sidecar.is_file():
            raise WebContractError("body sidecar is not a regular file")
        if sidecar.stat().st_size > 16 * 1024 * 1024:
            raise WebContractError("body sidecar exceeds the 16 MiB import limit")
        body = sidecar.read_bytes()
        body_exact = True

    host_values = [item["value"] for item in headers if item["name"].lower() == "host"]
    if protocol == "http/1.1" and len(host_values) != 1:
        raise WebContractError("HTTP/1 request requires exactly one Host header")
    base = urlsplit(contract.origins[metadata["origin"]].origin)
    if protocol == "http/2":
        pseudo = {item["name"]: item["value"] for item in pseudo_headers}
        request_origin = canonical_origin(
            f"{pseudo[':scheme']}://{pseudo[':authority']}"
        )
    else:
        host_origin = canonical_origin(f"{base.scheme}://{host_values[0]}")
        parsed_target = urlsplit(target)
        if parsed_target.scheme:
            absolute_origin = canonical_origin(
                f"{parsed_target.scheme}://{parsed_target.netloc}"
            )
            if absolute_origin != host_origin:
                raise WebContractError(
                    "absolute request URL conflicts with Host authority"
                )
            request_origin = absolute_origin
        else:
            request_origin = host_origin
    if request_origin != contract.origins[metadata["origin"]].origin:
        raise WebContractError("request authority is not declared by the campaign contract")
    if protocol == "http/1.1" and urlsplit(target).scheme:
        parsed_target = urlsplit(target)
        target_for_policy = (parsed_target.path or "/") + (
            "?" + parsed_target.query if parsed_target.query else ""
        )
    else:
        target_for_policy = target
    admitted = contract.admitted_request(
        origin_id=metadata["origin"],
        path_or_url=target_for_policy,
        method=method,
        effect_class=metadata["effect"],
        require_live_authorization=False,
    )
    exact_raw = raw.encode("utf-8")
    return {
        "schemaVersion": 1,
        "protocol": protocol,
        "byteExact": bool(byte_exact_headers and body_exact),
        "nonByteExactReasons": [
            reason
            for condition, reason in (
                (not byte_exact_headers, "Markdown did not retain CRLF wire delimiters"),
            )
            if condition
        ],
        "exactReplay": {
            "rawBlockBase64": base64.b64encode(exact_raw).decode("ascii"),
            "rawRequestLineBase64": base64.b64encode(
                request_line.encode("utf-8")
            ).decode("ascii"),
            "headers": headers,
            "pseudoHeaders": pseudo_headers,
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "immutableAuthenticationFields": list(
                metadata["authenticationBoundFields"]
            ),
        },
        "semantic": {
            "method": method,
            "httpVersion": version,
            "originId": metadata["origin"],
            "origin": request_origin,
            **_semantic_target(target_for_policy),
            "headers": [
                {"name": item["name"], "value": item["value"]} for item in headers
            ],
            "pseudoHeaders": [
                {"name": item["name"], "value": item["value"]}
                for item in pseudo_headers
            ],
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "bodyBytes": len(body),
            "actionPolicyId": admitted["actionPolicyId"],
        },
        "signed": metadata["signed"],
        "resigningRequiredForMutation": bool(metadata["signed"]),
    }
