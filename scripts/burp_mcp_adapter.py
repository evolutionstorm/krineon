#!/usr/bin/env python3
"""Bind an agent-managed Burp Suite MCP call to Krineon scope and evidence.

The agent client (Codex, OpenCode, or OMP) owns the MCP connection and invokes
the advertised tool. This adapter does not connect to Burp. It registers the
observed tool schemas, validates and reserves one exact bounded call, and then
records the returned private artifact without trusting it as a finding.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .swarm_control import ControlError, ControlStore
    from .web_budget import SharedWebBudget
    from .web_contract import WebCampaignContract, WebContractError, canonical_origin
    from .web_identity import AuthInconclusive, IdentityBroker
except ImportError:
    from swarm_control import ControlError, ControlStore
    from web_budget import SharedWebBudget
    from web_contract import WebCampaignContract, WebContractError, canonical_origin
    from web_identity import AuthInconclusive, IdentityBroker


CLIENTS = {"codex", "opencode", "omp"}
MAX_TOOLS = 256
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
MAX_PRIVATE_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_HISTORY_COUNT = 25
SUPPORTED_SUFFIXES = {
    "get_proxy_http_history_regex": "http-history-read",
    "get_proxy_websocket_history_regex": "websocket-history-read",
    "send_http1_request": "http-send",
    "send_http2_request": "http-send",
    "create_repeater_tab_http2": "repeater-create",
    "create_repeater_tab": "repeater-create",
}
BLOCKED_SUFFIXES = {
    "get_proxy_http_history",
    "get_proxy_websocket_history",
    "send_to_intruder",
    "generate_collaborator_payload",
    "get_collaborator_interactions",
    "set_project_options",
    "set_user_options",
    "set_task_execution_engine_state",
    "set_proxy_intercept_state",
    "set_active_editor_contents",
}
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")


class BurpMcpError(RuntimeError):
    """The MCP session, call, evidence, or authorization is invalid."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_object(path: Path, label: str = "JSON") -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BurpMcpError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BurpMcpError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise BurpMcpError(f"{label} must be a JSON object")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temporary.write_bytes(json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def campaign_root(value: Path) -> Path:
    root = value.expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise BurpMcpError(f"not a Krineon campaign: {root}")
    return root


def campaign_path(root: Path, value: Any, field: str, *, private: bool = False) -> Path:
    raw = str(value or "").strip()
    relative = Path(raw)
    if not raw or relative.is_absolute() or ".." in relative.parts:
        raise BurpMcpError(f"{field} must be campaign-relative")
    cursor = root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise BurpMcpError(f"{field} must not traverse symbolic links")
    path = cursor.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BurpMcpError(f"{field} escapes the campaign") from exc
    if private:
        try:
            path.relative_to(root / "private")
        except ValueError as exc:
            raise BurpMcpError(f"{field} must be stored under campaign/private") from exc
    if not path.is_file():
        raise BurpMcpError(f"{field} is not a regular file")
    if private and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise BurpMcpError(f"{field} must use mode 0600")
    return path


def require_id(value: Any, field: str) -> str:
    text = str(value or "")
    if not IDENTIFIER.fullmatch(text):
        raise BurpMcpError(f"{field} must be a stable identifier")
    return text


def tool_leaf(name: str) -> str:
    leaf = re.split(r"__|[/:]", name.lower())[-1]
    return leaf.replace("-", "_")


def classify_tool(name: str) -> str:
    leaf = tool_leaf(name)
    for suffix, capability in SUPPORTED_SUFFIXES.items():
        if leaf == suffix or leaf.endswith("_" + suffix):
            return capability
    if any(leaf == suffix or leaf.endswith("_" + suffix) for suffix in BLOCKED_SUFFIXES):
        return "blocked"
    return "unclassified"


def observe_component(
    root: Path,
    component_id: str,
    operation: str,
    outcome: str,
    *,
    artifacts: tuple[str, ...] = (),
    detail: str = "",
) -> None:
    store = ControlStore(root)
    try:
        store.component_observe(
            {
                "componentId": component_id,
                "operation": operation,
                "outcome": outcome,
                "latencyMs": 0,
                "artifactRefs": list(artifacts),
                "detail": detail[:500],
            },
            actor="burp-mcp-adapter",
        )
        store.connection.commit()
    finally:
        store.close()


def register_session(root: Path, manifest_path: Path) -> dict[str, Any]:
    raw = read_object(manifest_path, "Burp MCP session manifest")
    if raw.get("schemaVersion") != 1:
        raise BurpMcpError("session manifest requires schemaVersion 1")
    client = str(raw.get("client") or "").lower()
    if client not in CLIENTS:
        raise BurpMcpError("client must be codex, opencode, or omp")
    server = require_id(raw.get("serverName"), "serverName")
    if raw.get("connected") is not True:
        raise BurpMcpError("the agent must confirm that the MCP server is connected")
    if raw.get("dedicatedProject") is not True:
        raise BurpMcpError("Burp MCP requires a dedicated project containing only authorized traffic")
    if raw.get("burpTargetApprovalEnabled") is not True:
        raise BurpMcpError("Burp target approval must remain enabled")
    tools = raw.get("tools")
    if not isinstance(tools, list) or not tools or len(tools) > MAX_TOOLS:
        raise BurpMcpError("tools must be a bounded non-empty array")
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(tools):
        if not isinstance(item, dict):
            raise BurpMcpError(f"tools[{index}] must be an object")
        name = require_id(item.get("name"), f"tools[{index}].name")
        if name in names:
            raise BurpMcpError(f"duplicate MCP tool: {name}")
        names.add(name)
        if item.get("observedFromClient") is not True:
            raise BurpMcpError(
                f"tools[{index}] must be copied from the active client's advertised schema"
            )
        schema = item.get("inputSchema")
        if not isinstance(schema, dict) or not schema:
            raise BurpMcpError(f"tools[{index}].inputSchema must be a non-empty object")
        encoded = canonical(schema)
        if len(encoded) > MAX_SCHEMA_BYTES:
            raise BurpMcpError("MCP tool schema exceeds the retained bound")
        normalized.append(
            {
                "name": name,
                "capability": classify_tool(name),
                "inputSchemaSha256": sha256_bytes(encoded),
            }
        )
    if not any(item["capability"] not in {"blocked", "unclassified"} for item in normalized):
        raise BurpMcpError("the connected server exposes no supported bounded Burp tools")
    session_id = "burp-" + uuid.uuid4().hex[:16]
    record = {
        "schemaVersion": 1,
        "sessionId": session_id,
        "registeredAt": utc_now(),
        "client": client,
        "serverName": server,
        "transport": "agent-managed-mcp",
        "connected": True,
        "dedicatedProject": True,
        "burpTargetApprovalEnabled": True,
        "burpVersion": str(raw.get("burpVersion") or "unknown")[:100],
        "extensionVersion": str(raw.get("extensionVersion") or "unknown")[:100],
        "tools": normalized,
        "policy": {
            "unknownToolsBlocked": True,
            "configurationMutationBlocked": True,
            "intruderAndScannerBlocked": True,
            "collaboratorBlocked": True,
            "toolDescriptionsAreUntrusted": True,
        },
    }
    destination = root / "tools" / "burp-mcp" / "sessions" / f"{session_id}.json"
    write_json(destination, record)
    store = ControlStore(root)
    try:
        component_id = store.ensure_component(
            kind="tool",
            name=f"burp-mcp-{server}",
            version=record["extensionVersion"],
            capabilities=sorted(
                item["capability"] for item in normalized
                if item["capability"] not in {"blocked", "unclassified"}
            ),
            actor="burp-mcp-adapter",
        )
        store.connection.commit()
    finally:
        store.close()
    observe_component(
        root,
        component_id,
        "mcp-session-register",
        "passed",
        artifacts=(destination.relative_to(root).as_posix(),),
    )
    return record


def load_session(root: Path, session_id: Any) -> dict[str, Any]:
    identifier = require_id(session_id, "sessionId")
    record = read_object(
        root / "tools" / "burp-mcp" / "sessions" / f"{identifier}.json",
        "registered Burp MCP session",
    )
    if record.get("connected") is not True:
        raise BurpMcpError("Burp MCP session is not connected")
    return record


def registered_tool(session: dict[str, Any], name: Any) -> dict[str, Any]:
    selected = str(name or "")
    for item in session["tools"]:
        if item["name"] == selected:
            if item["capability"] in {"blocked", "unclassified"}:
                raise BurpMcpError(f"Burp MCP tool is not admitted: {selected}")
            return item
    raise BurpMcpError(f"Burp MCP tool was not registered: {selected}")


def expected_service(origin: str) -> tuple[str, int, bool]:
    parsed = urlsplit(origin)
    secure = parsed.scheme == "https"
    return str(parsed.hostname), int(parsed.port or (443 if secure else 80)), secure


def service_from_arguments(arguments: dict[str, Any]) -> tuple[str, int, bool]:
    host = str(arguments.get("targetHostname") or "").rstrip(".").lower()
    try:
        port = int(arguments.get("targetPort"))
    except (TypeError, ValueError) as exc:
        raise BurpMcpError("targetPort must be an integer") from exc
    secure = arguments.get("usesHttps")
    if not host or not 1 <= port <= 65535 or not isinstance(secure, bool):
        raise BurpMcpError("invalid Burp target service")
    return host, port, secure


def parse_http1(arguments: dict[str, Any]) -> tuple[str, str, str, int, list[str]]:
    content = arguments.get("content")
    if not isinstance(content, str) or not content:
        raise BurpMcpError("HTTP/1 tool arguments require content")
    header_text, separator, body = content.partition("\r\n\r\n")
    if not separator:
        header_text, separator, body = content.partition("\n\n")
    lines = header_text.replace("\r\n", "\n").split("\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise BurpMcpError("invalid HTTP/1 request line")
    method, target = parts[0].upper(), parts[1]
    names: list[str] = []
    hosts: list[str] = []
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise BurpMcpError("invalid or folded HTTP/1 header")
        name, value = line.split(":", 1)
        lower = name.strip().lower()
        names.append(lower)
        if lower == "host":
            hosts.append(value.strip())
    if len(hosts) != 1:
        raise BurpMcpError("HTTP/1 request requires exactly one Host header")
    return method, target, hosts[0], len(body.encode("utf-8")), names


def parse_http2(arguments: dict[str, Any]) -> tuple[str, str, int, list[str]]:
    pseudo = arguments.get("pseudoHeaders")
    headers = arguments.get("headers")
    body = arguments.get("requestBody")
    if not isinstance(pseudo, dict) or not isinstance(headers, dict) or not isinstance(body, str):
        raise BurpMcpError("HTTP/2 arguments require pseudoHeaders, headers, and requestBody")
    normalized = {str(key).lstrip(":").lower(): str(value) for key, value in pseudo.items()}
    for field in ("method", "path", "scheme", "authority"):
        if not normalized.get(field):
            raise BurpMcpError(f"HTTP/2 request is missing :{field}")
    names = [str(name).lower() for name in headers]
    return normalized["method"].upper(), normalized["path"], len(body.encode("utf-8")), names


def derive_request(
    contract: WebCampaignContract,
    origin_id: str,
    capability: str,
    tool_name: str,
    arguments: dict[str, Any],
    operation_class: str,
) -> tuple[str, str, int, list[str]]:
    try:
        origin = contract.origins[origin_id]
    except KeyError as exc:
        raise BurpMcpError(f"unknown origin: {origin_id}") from exc
    expected = expected_service(origin.origin)
    actual = service_from_arguments(arguments)
    if actual != expected:
        raise BurpMcpError("Burp tool target service does not match the selected exact origin")
    leaf = tool_leaf(tool_name)
    if leaf.endswith("http2") or leaf == "send_http2_request":
        method, target, body_bytes, names = parse_http2(arguments)
        pseudo = {str(key).lstrip(":").lower(): str(value) for key, value in arguments["pseudoHeaders"].items()}
        if pseudo["scheme"] != ("https" if expected[2] else "http"):
            raise BurpMcpError("HTTP/2 :scheme does not match the approved origin")
        if canonical_origin(f"{pseudo['scheme']}://{pseudo['authority']}") != origin.origin:
            raise BurpMcpError("HTTP/2 :authority does not match the approved origin")
    else:
        method, target, host_header, body_bytes, names = parse_http1(arguments)
        scheme = "https" if expected[2] else "http"
        if canonical_origin(f"{scheme}://{host_header}") != origin.origin:
            raise BurpMcpError("HTTP/1 Host header does not match the approved origin")
    if target.startswith(("http://", "https://")):
        url = target
    else:
        if not target.startswith("/"):
            raise BurpMcpError("request target must be origin-form or an absolute approved URL")
        url = origin.origin + target
    if operation_class != "http-desynchronization":
        for sensitive in ("host", "content-length", "transfer-encoding"):
            if names.count(sensitive) > 1:
                raise BurpMcpError(f"duplicate {sensitive} requires http-desynchronization approval")
        if "content-length" in names and "transfer-encoding" in names:
            raise BurpMcpError("CL/TE ambiguity requires http-desynchronization approval")
    return method, url, body_bytes, names


def validate_history(
    contract: WebCampaignContract,
    origin_id: str,
    arguments: dict[str, Any],
) -> int:
    contract.require_live_authorization()
    try:
        origin = contract.origins[origin_id]
    except KeyError as exc:
        raise BurpMcpError(f"unknown origin: {origin_id}") from exc
    regex = str(arguments.get("regex") or "")
    host = str(urlsplit(origin.origin).hostname or "").lower()
    normalized_regex = regex.removeprefix("(?i)")
    if normalized_regex != re.escape(host):
        raise BurpMcpError("history regex must equal the escaped approved hostname")
    try:
        count = int(arguments.get("count"))
        offset = int(arguments.get("offset"))
    except (TypeError, ValueError) as exc:
        raise BurpMcpError("history count and offset must be integers") from exc
    if not 1 <= count <= MAX_HISTORY_COUNT or not 0 <= offset <= 100_000:
        raise BurpMcpError("history pagination exceeds the bounded limits")
    return count


def prepare_call(root: Path, contract_path: Path, spec_path: Path) -> dict[str, Any]:
    spec = read_object(spec_path, "Burp MCP call specification")
    if spec.get("schemaVersion") != 1:
        raise BurpMcpError("call specification requires schemaVersion 1")
    session = load_session(root, spec.get("sessionId"))
    tool = registered_tool(session, spec.get("toolName"))
    if tool["capability"] != spec.get("capability"):
        raise BurpMcpError("declared capability does not match the registered MCP tool")
    arguments_path = campaign_path(root, spec.get("argumentsFile"), "argumentsFile", private=True)
    if arguments_path.stat().st_size > MAX_PRIVATE_ARTIFACT_BYTES:
        raise BurpMcpError("private MCP arguments exceed the retained bound")
    arguments_sha_before = sha256_file(arguments_path)
    arguments = read_object(arguments_path, "private MCP arguments")
    arguments_sha = sha256_file(arguments_path)
    if arguments_sha != arguments_sha_before:
        raise BurpMcpError("private MCP arguments changed during preparation")
    contract = WebCampaignContract.load(contract_path)
    origin_id = require_id(spec.get("originId"), "originId")
    identity_id = str(spec.get("identityId") or "anonymous")
    contract.identity_for_origin(identity_id, origin_id)
    effect = str(spec.get("effectClass") or "")
    operation_class = str(spec.get("operationClass") or "ordinary-http")
    intent = str(spec.get("intent") or "").strip()
    if not intent:
        raise BurpMcpError("intent is required")
    try:
        timeout = int(spec.get("timeoutSeconds") or 60)
    except (TypeError, ValueError) as exc:
        raise BurpMcpError("timeoutSeconds must be an integer") from exc
    if not 10 <= timeout <= 300:
        raise BurpMcpError("timeoutSeconds must be between 10 and 300")
    request_bytes = 0
    try:
        requested_result_bytes = int(spec.get("maxResultBytes") or 1024 * 1024)
    except (TypeError, ValueError) as exc:
        raise BurpMcpError("maxResultBytes must be an integer") from exc
    response_limit = min(requested_result_bytes, MAX_PRIVATE_ARTIFACT_BYTES)
    if response_limit <= 0:
        raise BurpMcpError("maxResultBytes must be positive")
    method = "MCP-READ"
    url = contract.origins[origin_id].origin
    admitted: dict[str, Any] | None = None
    if tool["capability"] in {"http-history-read", "websocket-history-read"}:
        validate_history(contract, origin_id, arguments)
        if effect != "read-only":
            raise BurpMcpError("history access must be labelled read-only")
        operation_class = "ordinary-http"
    else:
        method, url, body_bytes, _header_names = derive_request(
            contract, origin_id, tool["capability"], tool["name"], arguments, operation_class
        )
        admitted = contract.admitted_request(
            origin_id=origin_id,
            path_or_url=url,
            method=method,
            effect_class=effect,
            operation="http",
            operation_class=operation_class,
        )
        IdentityBroker(contract).authorize(
            identity_id,
            origin_id=origin_id,
            path_or_url=url,
            transport="http",
        )
        if body_bytes > int(admitted["maxRequestBodyBytes"]):
            raise BurpMcpError("Burp request body exceeds the action-policy limit")
        request_bytes = arguments_path.stat().st_size
        response_limit = min(response_limit, int(admitted["maxResponseBodyBytes"]))
    capability_id = "burp-call-" + uuid.uuid4().hex[:16]
    ledger = SharedWebBudget(contract, root / "evidence" / "web" / "budget-ledger.sqlite3")
    ledger.reserve(
        operation_id=capability_id,
        request_bytes=request_bytes,
        estimated_response_bytes=response_limit,
        storage_bytes=response_limit,
        cleanup=False,
        adapter="burp-mcp",
        origin_id=origin_id,
        action_units=1,
        lease_seconds=timeout + 15,
    )
    now = time.time()
    record = {
        "schemaVersion": 1,
        "capabilityId": capability_id,
        "status": "prepared",
        "preparedAt": utc_now(),
        "expiresAtEpoch": now + timeout,
        "contractSha256": contract.digest,
        "sessionId": session["sessionId"],
        "client": session["client"],
        "serverName": session["serverName"],
        "toolName": tool["name"],
        "toolSchemaSha256": tool["inputSchemaSha256"],
        "capability": tool["capability"],
        "originId": origin_id,
        "url": url,
        "method": method,
        "identityId": identity_id,
        "effectClass": effect,
        "operationClass": operation_class,
        "intent": intent,
        "argumentsFile": arguments_path.relative_to(root).as_posix(),
        "argumentsSha256": arguments_sha,
        "argumentsBytes": arguments_path.stat().st_size,
        "maxResultBytes": response_limit,
        "admittedRequest": admitted,
        "policy": {
            "invokeOnlyThroughRegisteredAgentMcp": True,
            "burpHumanApprovalStillRequired": True,
            "argumentsMustRemainByteIdentical": True,
            "resultContentIsUntrusted": True,
            "findingPromotionAllowed": False,
            "requiresCoordinatorReplay": True,
        },
    }
    destination = root / "tools" / "burp-mcp" / "calls" / f"{capability_id}.json"
    write_json(destination, record)
    return record


def reject_prepared_call(
    ledger: SharedWebBudget,
    call_path: Path,
    call: dict[str, Any],
    capability_id: str,
    reason: str,
) -> None:
    ledger.abort(capability_id, reason)
    call.update(
        {
            "status": "rejected",
            "completedAt": utc_now(),
            "rejectReason": reason[:500],
        }
    )
    write_json(call_path, call)
    raise BurpMcpError(reason)


def complete_call(root: Path, capability_id: str, receipt_path: Path) -> dict[str, Any]:
    capability_id = require_id(capability_id, "capabilityId")
    call_path = root / "tools" / "burp-mcp" / "calls" / f"{capability_id}.json"
    call = read_object(call_path, "prepared Burp MCP call")
    if call.get("status") != "prepared":
        raise BurpMcpError("Burp MCP call is not awaiting completion")
    contract_path = root / "web-campaign.json"
    if not contract_path.is_file():
        raise BurpMcpError("campaign web-campaign.json is missing")
    contract = WebCampaignContract.load(contract_path)
    if contract.digest != call.get("contractSha256"):
        raise BurpMcpError("web campaign contract changed after call preparation")
    ledger = SharedWebBudget(contract, root / "evidence" / "web" / "budget-ledger.sqlite3")
    if time.time() > float(call["expiresAtEpoch"]):
        ledger.abort(capability_id, "MCP completion arrived after capability expiry")
        call["status"] = "expired"
        write_json(call_path, call)
        raise BurpMcpError("Burp MCP call capability expired")
    receipt = read_object(receipt_path, "Burp MCP receipt")
    if receipt.get("schemaVersion") != 1:
        reject_prepared_call(
            ledger,
            call_path,
            call,
            capability_id,
            "Burp MCP receipt requires schemaVersion 1",
        )
    try:
        arguments_path = campaign_path(
            root, call.get("argumentsFile"), "argumentsFile", private=True
        )
    except BurpMcpError as exc:
        reject_prepared_call(
            ledger, call_path, call, capability_id, f"private arguments unavailable: {exc}"
        )
    if sha256_file(arguments_path) != call.get("argumentsSha256"):
        reject_prepared_call(
            ledger, call_path, call, capability_id, "private MCP arguments changed after preparation"
        )
    for field in (
        "capabilityId",
        "serverName",
        "toolName",
        "toolSchemaSha256",
        "argumentsSha256",
    ):
        expected = call[field]
        if receipt.get(field) != expected:
            reject_prepared_call(
                ledger,
                call_path,
                call,
                capability_id,
                f"receipt {field} does not match the prepared call",
            )
    outcome = str(receipt.get("outcome") or "")
    if outcome not in {"success", "denied", "error"}:
        reject_prepared_call(
            ledger,
            call_path,
            call,
            capability_id,
            "receipt outcome must be success, denied, or error",
        )
    dispatched = receipt.get("targetRequestDispatched")
    expected_dispatch = call["capability"] == "http-send" and outcome == "success"
    if dispatched is not expected_dispatch:
        reject_prepared_call(
            ledger,
            call_path,
            call,
            capability_id,
            "receipt targetRequestDispatched is inconsistent",
        )
    try:
        result_path = campaign_path(
            root, receipt.get("resultFile"), "resultFile", private=True
        )
    except BurpMcpError as exc:
        reject_prepared_call(
            ledger, call_path, call, capability_id, f"private MCP result unavailable: {exc}"
        )
    result_bytes = result_path.stat().st_size
    if result_bytes > int(call["maxResultBytes"]):
        reject_prepared_call(
            ledger, call_path, call, capability_id, "MCP result exceeds maxResultBytes"
        )
    result_sha = sha256_file(result_path)
    result_content = result_path.read_bytes()
    if result_path.stat().st_size != result_bytes or sha256_file(result_path) != result_sha:
        reject_prepared_call(
            ledger, call_path, call, capability_id, "private MCP result changed during retention"
        )
    truncated = bool(receipt.get("truncated")) or b"... (truncated)" in result_content
    if outcome == "success":
        ledger.reconcile_response(
            capability_id,
            result_bytes,
            storage_bytes=result_bytes,
        )
    else:
        ledger.abort(capability_id, f"Burp MCP {outcome}")
    call.update(
        {
            "status": "completed" if outcome == "success" else outcome,
            "completedAt": utc_now(),
            "outcome": outcome,
            "targetRequestDispatched": dispatched,
            "privateResultFile": result_path.relative_to(root).as_posix(),
            "resultBytes": result_bytes,
            "resultSha256": result_sha,
            "truncated": truncated,
            "eligibleForNegativeConclusion": False,
            "eligibleForSecurityConclusion": False,
            "nextStep": (
                "Import and independently replay the exact request/response before using it as evidence."
                if outcome == "success"
                else "Resolve the MCP denial or environment error without changing scope."
            ),
        }
    )
    write_json(call_path, call)
    session = load_session(root, call["sessionId"])
    component_id = f"tool:burp-mcp-{session['serverName']}"
    observe_component(
        root,
        component_id,
        call["capability"],
        "passed" if outcome == "success" else "failed",
        artifacts=(call_path.relative_to(root).as_posix(),),
        detail=f"outcome={outcome}; truncated={truncated}",
    )
    return call


def abort_call(root: Path, capability_id: str, reason: str) -> dict[str, Any]:
    capability_id = require_id(capability_id, "capabilityId")
    call_path = root / "tools" / "burp-mcp" / "calls" / f"{capability_id}.json"
    call = read_object(call_path, "prepared Burp MCP call")
    if call.get("status") != "prepared":
        raise BurpMcpError("Burp MCP call is not awaiting completion")
    contract = WebCampaignContract.load(root / "web-campaign.json")
    SharedWebBudget(
        contract, root / "evidence" / "web" / "budget-ledger.sqlite3"
    ).abort(capability_id, reason)
    call.update({"status": "aborted", "completedAt": utc_now(), "abortReason": reason[:500]})
    write_json(call_path, call)
    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("campaign", type=Path)
    register.add_argument("manifest", type=Path)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("campaign", type=Path)
    prepare.add_argument("contract", type=Path)
    prepare.add_argument("spec", type=Path)
    complete = sub.add_parser("complete")
    complete.add_argument("campaign", type=Path)
    complete.add_argument("capability_id")
    complete.add_argument("receipt", type=Path)
    abort = sub.add_parser("abort")
    abort.add_argument("campaign", type=Path)
    abort.add_argument("capability_id")
    abort.add_argument("reason")
    args = parser.parse_args(argv)
    try:
        root = campaign_root(args.campaign)
        if args.command == "register":
            result = register_session(root, args.manifest.expanduser().resolve())
        elif args.command == "prepare":
            contract = args.contract.expanduser().resolve()
            if contract != root / "web-campaign.json":
                raise BurpMcpError("Burp MCP must use campaign/web-campaign.json")
            result = prepare_call(root, contract, args.spec.expanduser().resolve())
        elif args.command == "complete":
            result = complete_call(root, args.capability_id, args.receipt.expanduser().resolve())
        else:
            result = abort_call(root, args.capability_id, args.reason)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (
        AuthInconclusive,
        BurpMcpError,
        WebContractError,
        ControlError,
        OSError,
        sqlite3.Error,
    ) as exc:
        print(f"Burp MCP adapter rejected the operation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
