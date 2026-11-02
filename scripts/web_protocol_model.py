#!/usr/bin/env python3
"""Model WebSocket and Server-Sent Events from retained Chrome CDP evidence.

This module performs no network activity.  It converts already-redacted CDP
events into protocol channels, message-shape observations, and explicit
coverage gaps.  Raw frame bodies are never copied into the output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


MAX_EVENTS = 250_000
MAX_SHAPE_DEPTH = 5
SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|passwd|authorization|cookie|credential|api[_-]?key|session)",
    re.I,
)


def stable_id(prefix: str, *values: Any) -> str:
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{prefix}-{hashlib.sha256(encoded.encode()).hexdigest()[:20]}"


def evidence_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        return value.split("#", 1)[0]
    host = parsed.hostname or ""
    if parsed.port is not None:
        host += f":{parsed.port}"
    query = "&".join(
        f"{name}={{value}}"
        for name, _item in parse_qsl(parsed.query, keep_blank_values=True)
    )
    return urlunsplit((parsed.scheme, host, parsed.path, query, ""))


def load_events(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise WebContractError("CDP evidence must contain at most 250000 events")
    return [event for event in value if isinstance(event, dict)]


def bounded_shape(value: Any, depth: int = 0) -> Any:
    """Return a value-free structural description suitable for evidence."""

    if depth >= MAX_SHAPE_DEPTH:
        return "depth-limit"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(str(item) for item in value)[:100]:
            if SENSITIVE_KEY.search(key):
                result[key] = "redacted-field"
            else:
                result[key] = bounded_shape(value.get(key), depth + 1)
        return result
    if isinstance(value, list):
        samples = [bounded_shape(item, depth + 1) for item in value[:8]]
        unique: list[Any] = []
        for sample in samples:
            if sample not in unique:
                unique.append(sample)
        return {"type": "array", "itemShapes": unique, "observedItems": len(value)}
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"


def payload_shape(payload: str, opcode: int | None = None) -> dict[str, Any]:
    encoded = payload.encode("utf-8", "replace")
    result: dict[str, Any] = {
        "byteLength": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "opcode": opcode,
    }
    if opcode == 2:
        result["format"] = "binary"
        return result
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError, json.JSONDecodeError):
        result["format"] = "text"
        result["lineCount"] = min(payload.count("\n") + 1, 10000)
        return result
    result["format"] = "json"
    shape = bounded_shape(parsed)
    result["shape"] = shape
    result["shapeId"] = stable_id("MSG-SHAPE", shape)
    if isinstance(parsed, dict):
        for field in ("type", "event", "method", "op", "action", "topic"):
            candidate = parsed.get(field)
            if isinstance(candidate, str) and len(candidate) <= 160 and not SENSITIVE_KEY.search(field):
                result["discriminatorField"] = field
                result["discriminator"] = candidate
                break
    return result


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).lower(): str(item) for key, item in value.items()}


def build(
    events_path: Path,
    *,
    workflow_id: str = "",
    step_id: str = "",
    identity_id: str = "anonymous",
    tenant: str = "",
    deployment_epoch: str = "",
) -> dict[str, Any]:
    events = load_events(events_path)
    requests: dict[str, dict[str, Any]] = {}
    websocket: dict[str, dict[str, Any]] = {}
    sse: dict[str, dict[str, Any]] = {}

    def ws_channel(request_id: str) -> dict[str, Any]:
        request = requests.get(request_id, {})
        return websocket.setdefault(
            request_id,
            {
                "id": stable_id("WS", deployment_epoch, request_id, request.get("url", "")),
                "transport": "websocket",
                "requestId": request_id,
                "url": evidence_url(str(request.get("url") or "")),
                "identityId": identity_id,
                "tenant": tenant,
                "workflowId": workflow_id,
                "stepId": step_id,
                "deploymentEpoch": deployment_epoch,
                "handshake": {"observed": False},
                "frames": [],
                "closed": False,
            },
        )

    for event in events:
        method = str(event.get("method") or "")
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        request_id = str(params.get("requestId") or "")
        if method == "Network.requestWillBeSent":
            request = params.get("request") if isinstance(params.get("request"), dict) else {}
            requests[request_id] = {
                "url": evidence_url(str(request.get("url") or "")),
                "method": str(request.get("method") or ""),
                "resourceType": str(params.get("type") or ""),
            }
        elif method == "Network.webSocketCreated":
            requests.setdefault(request_id, {})["url"] = evidence_url(
                str(params.get("url") or "")
            )
            ws_channel(request_id)["initiatorObserved"] = isinstance(params.get("initiator"), dict)
        elif method == "Network.webSocketWillSendHandshakeRequest":
            request = params.get("request") if isinstance(params.get("request"), dict) else {}
            headers = _headers(request.get("headers"))
            channel = ws_channel(request_id)
            channel["handshake"].update(
                {
                    "observed": True,
                    "requestHeaders": sorted(headers),
                    "originHeaderPresent": "origin" in headers,
                    "cookieHeaderPresent": "cookie" in headers,
                    "authorizationHeaderPresent": "authorization" in headers,
                }
            )
        elif method == "Network.webSocketHandshakeResponseReceived":
            response = params.get("response") if isinstance(params.get("response"), dict) else {}
            headers = _headers(response.get("headers"))
            channel = ws_channel(request_id)
            channel["handshake"].update(
                {
                    "observed": True,
                    "status": int(response.get("status") or 0),
                    "responseHeaders": sorted(headers),
                    "acceptedProtocol": headers.get("sec-websocket-protocol", ""),
                    "setCookiePresent": "set-cookie" in headers,
                }
            )
        elif method in {"Network.webSocketFrameSent", "Network.webSocketFrameReceived"}:
            frame = params.get("response") if isinstance(params.get("response"), dict) else {}
            direction = "sent" if method.endswith("FrameSent") else "received"
            ws_channel(request_id)["frames"].append(
                {
                    "direction": direction,
                    "timestamp": params.get("timestamp"),
                    **payload_shape(str(frame.get("payloadData") or ""), int(frame.get("opcode") or 1)),
                }
            )
        elif method == "Network.webSocketClosed":
            channel = ws_channel(request_id)
            channel["closed"] = True
            channel["closedTimestamp"] = params.get("timestamp")
        elif method == "Network.responseReceived":
            response = params.get("response") if isinstance(params.get("response"), dict) else {}
            mime = str(response.get("mimeType") or "").lower()
            headers = _headers(response.get("headers"))
            if mime == "text/event-stream" or "text/event-stream" in headers.get("content-type", "").lower():
                request = requests.get(request_id, {})
                sse.setdefault(
                    request_id,
                    {
                        "id": stable_id("SSE", deployment_epoch, request_id, response.get("url", "")),
                        "transport": "server-sent-events",
                        "requestId": request_id,
                        "url": evidence_url(
                            str(response.get("url") or request.get("url") or "")
                        ),
                        "requestMethod": request.get("method", ""),
                        "status": int(response.get("status") or 0),
                        "identityId": identity_id,
                        "tenant": tenant,
                        "workflowId": workflow_id,
                        "stepId": step_id,
                        "deploymentEpoch": deployment_epoch,
                        "events": [],
                    },
                )
        elif method == "Network.eventSourceMessageReceived":
            request = requests.get(request_id, {})
            channel = sse.setdefault(
                request_id,
                {
                    "id": stable_id("SSE", deployment_epoch, request_id, request.get("url", "")),
                    "transport": "server-sent-events",
                    "requestId": request_id,
                    "url": request.get("url", ""),
                    "requestMethod": request.get("method", ""),
                    "status": 0,
                    "identityId": identity_id,
                    "tenant": tenant,
                    "workflowId": workflow_id,
                    "stepId": step_id,
                    "deploymentEpoch": deployment_epoch,
                    "events": [],
                },
            )
            channel["events"].append(
                {
                    "eventName": str(params.get("eventName") or "message")[:160],
                    "eventIdPresent": bool(params.get("eventId")),
                    "timestamp": params.get("timestamp"),
                    **payload_shape(str(params.get("data") or ""), 1),
                }
            )

    channels = list(websocket.values()) + list(sse.values())
    operations: list[dict[str, Any]] = []
    for channel in channels:
        messages = channel.get("frames", channel.get("events", []))
        counts = Counter(
            (
                str(message.get("direction") or "received"),
                str(message.get("discriminatorField") or ""),
                str(message.get("discriminator") or ""),
                str(message.get("shapeId") or message.get("format") or "unknown"),
            )
            for message in messages
        )
        for key, count in sorted(counts.items()):
            direction, discriminator_field, discriminator, shape_id = key
            operations.append(
                {
                    "id": stable_id("PROTO-OP", channel["id"], key),
                    "channelId": channel["id"],
                    "transport": channel["transport"],
                    "direction": direction,
                    "discriminatorField": discriminator_field,
                    "discriminator": discriminator,
                    "shapeId": shape_id,
                    "observedCount": count,
                    "authority": {
                        "identityId": identity_id,
                        "tenant": tenant,
                        "source": "approved-browser-observation",
                    },
                }
            )

    return {
        "schemaVersion": 1,
        "kind": "krineon-websocket-sse-protocol-model",
        "eventsSha256": hashlib.sha256(events_path.read_bytes()).hexdigest(),
        "workflowId": workflow_id,
        "stepId": step_id,
        "identityId": identity_id,
        "tenant": tenant,
        "deploymentEpoch": deployment_epoch,
        "channels": channels,
        "operations": operations,
        "coverage": {
            "websocketChannels": len(websocket),
            "sseChannels": len(sse),
            "sentFrames": sum(1 for channel in websocket.values() for frame in channel["frames"] if frame["direction"] == "sent"),
            "receivedFrames": sum(1 for channel in websocket.values() for frame in channel["frames"] if frame["direction"] == "received"),
            "sseMessages": sum(len(channel["events"]) for channel in sse.values()),
        },
        "coverageGaps": [
            "Only messages observed during this approved browser journey are modeled.",
            "Message shape does not establish authorization or permission semantics.",
            "Binary frames retain only length and hash until a target-specific decoder is approved.",
            "Reconnect, expiry, cross-identity, and cross-tenant behavior require separate bounded experiments.",
        ],
        "retention": {
            "rawPayloadsCopied": False,
            "boundedOperationDiscriminatorsCopied": True,
            "otherMessageValuesCopied": False,
            "sensitiveFieldValuesCopied": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events")
    parser.add_argument("--output", required=True)
    parser.add_argument("--workflow-id", default="")
    parser.add_argument("--step-id", default="")
    parser.add_argument("--identity-id", default="anonymous")
    parser.add_argument("--tenant", default="")
    parser.add_argument("--deployment-epoch", default="")
    args = parser.parse_args(argv)
    try:
        result = build(
            Path(args.events).expanduser().resolve(),
            workflow_id=args.workflow_id,
            step_id=args.step_id,
            identity_id=args.identity_id,
            tenant=args.tenant,
            deployment_epoch=args.deployment_epoch,
        )
        atomic_json(Path(args.output).expanduser().resolve(), result, mode=0o600)
        print(json.dumps(result["coverage"], indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, WebContractError) as error:
        print(f"protocol model error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
