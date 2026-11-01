#!/usr/bin/env python3
"""Execute one approved HTTP/2 workflow step without conflating HTTP/1.1 evidence.

The adapter requires the optional ``h2`` package and a TLS origin that
negotiates ALPN ``h2``. It never downgrades to HTTP/1.1.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import ssl
import sys
import time
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .web_budget import SharedWebBudget
    from .web_contract import WebCampaignContract, WebContractError, atomic_json, sha256_bytes
    from .web_execution_broker import body_bytes
    from .web_identity import IdentityBroker
    from .web_policy import WebPolicyEngine, validate_step_envelope
    from .web_secret_store import SecretStore
    from .web_workflow import load_object, verify
except ImportError:
    from web_budget import SharedWebBudget
    from web_contract import WebCampaignContract, WebContractError, atomic_json, sha256_bytes
    from web_execution_broker import body_bytes
    from web_identity import IdentityBroker
    from web_policy import WebPolicyEngine, validate_step_envelope
    from web_secret_store import SecretStore
    from web_workflow import load_object, verify


def execute_step(
    *,
    campaign: Path,
    contract: WebCampaignContract,
    workflow: dict[str, Any],
    step: dict[str, Any],
    ledger: SharedWebBudget,
    output: Path,
    secret_store: SecretStore | None,
) -> dict[str, Any]:
    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError as exc:
        raise WebContractError(
            "HTTP/2 adapter requires the optional h2 package; no HTTP/1.1 fallback is allowed"
        ) from exc
    if str(step.get("transport") or "") != "http2":
        raise WebContractError("HTTP/2 adapter requires step.transport=http2")
    limits = validate_step_envelope(step)
    origin_id = str(step.get("originId") or "")
    origin = contract.origins.get(origin_id)
    if origin is None:
        raise WebContractError("HTTP/2 step uses an unknown origin")
    path = str(step.get("path") or "")
    url = origin.origin + path
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise WebContractError("HTTP/2 adapter requires TLS and ALPN h2")
    policy = WebPolicyEngine(contract)
    method = str(step.get("method") or "GET").upper()
    effect = str(step.get("effectClass") or "unknown")
    operation_class = str(step.get("operationClass") or "ordinary-http")
    decision = policy.admit(
        origin_id=origin_id,
        url=url,
        method=method,
        effect_class=effect,
        operation_class=operation_class,
        intent=str(limits["intent"]),
    )
    admitted = contract.admitted_request(
        origin_id=origin_id,
        path_or_url=url,
        method=method,
        effect_class=effect,
        operation="http",
        operation_class=operation_class,
    )
    identity_broker = IdentityBroker(
        contract,
        secret_store=secret_store,
        lease_root=campaign / "evidence" / "web" / "identity-leases",
    )
    identity = identity_broker.authorize(
        str(step.get("identityId") or "anonymous"),
        origin_id=origin_id,
        path_or_url=url,
        transport="http",
    )
    body, content_type = body_bytes(step.get("body"))
    if len(body) > min(int(limits["maxInputBytes"]), int(admitted["maxRequestBodyBytes"])):
        raise WebContractError("HTTP/2 request exceeds its input cap")
    headers: list[tuple[str, str]] = [
        (":method", method),
        (":scheme", "https"),
        (":authority", decision.host_header),
        (":path", admitted["path"]),
    ]
    forbidden = {"host", "connection", "transfer-encoding", "upgrade", "authorization", "cookie"}
    for name, value in step.get("headers", []):
        lowered = str(name).lower()
        if lowered in forbidden:
            raise WebContractError(f"HTTP/2 adapter controls header: {name}")
        headers.append((lowered, str(value)))
    if content_type and not any(name == "content-type" for name, _ in headers):
        headers.append(("content-type", content_type))
    if identity is not None:
        credential = identity_broker.resolve(identity)
        headers.extend((name.lower(), value) for name, value in identity_broker.injection_headers(identity, credential))
    request_bytes = len(body) + sum(len(name) + len(value) for name, value in headers)
    maximum = int(admitted["maxResponseBodyBytes"])
    operation_id = "op-" + hashlib.sha256(
        f"{workflow['id']}\0{step['id']}\0{time.time_ns()}".encode()
    ).hexdigest()[:40]
    ledger.reserve(
        operation_id=operation_id,
        request_bytes=request_bytes,
        estimated_response_bytes=maximum,
        cleanup=False,
        adapter="http2",
        origin_id=origin_id,
        lease_seconds=int(limits["timeoutSeconds"]) + 5,
    )
    raw: socket.socket | None = None
    response_body = bytearray()
    response_headers: list[tuple[str, str]] = []
    trailers: list[tuple[str, str]] = []
    status = None
    peer = ""
    cancellation_stop = threading.Event()
    cancellation_thread: threading.Thread | None = None
    try:
        last_error: OSError | None = None
        for address in decision.addresses:
            try:
                raw = socket.create_connection((address, decision.port), int(limits["timeoutSeconds"]))
                peer = str(raw.getpeername()[0])
                policy.verify_connected(decision, peer)
                break
            except OSError as exc:
                last_error = exc
                if raw is not None:
                    raw.close()
                    raw = None
        if raw is None:
            raise WebContractError(f"no authorized HTTP/2 destination was reachable: {last_error}")
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        tls = context.wrap_socket(raw, server_hostname=decision.sni)
        raw = tls
        if tls.selected_alpn_protocol() != "h2":
            raise WebContractError("server did not negotiate h2; downgrade is forbidden")
        def cancel_transport() -> None:
            while not cancellation_stop.wait(0.05):
                if ledger.is_cancelled(operation_id):
                    if raw is not None:
                        try:
                            raw.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        raw.close()
                    return

        cancellation_thread = threading.Thread(
            target=cancel_transport,
            name=f"krineon-http2-cancel-{operation_id}",
            daemon=True,
        )
        cancellation_thread.start()
        configuration = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        connection = h2.connection.H2Connection(config=configuration)
        connection.initiate_connection()
        raw.sendall(connection.data_to_send())
        stream_id = connection.get_next_available_stream_id()
        connection.send_headers(stream_id, headers, end_stream=not body)
        if body:
            connection.send_data(stream_id, body, end_stream=True)
        raw.sendall(connection.data_to_send())
        ended = False
        deadline = time.monotonic() + int(limits["timeoutSeconds"])
        while not ended and time.monotonic() < deadline:
            data = raw.recv(65536)
            if not data:
                break
            for event in connection.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    response_headers.extend((str(name), str(value)) for name, value in event.headers)
                    status_values = [value for name, value in response_headers if name == ":status"]
                    status = int(status_values[-1]) if status_values else None
                elif isinstance(event, h2.events.DataReceived):
                    response_body.extend(event.data)
                    if len(response_body) > maximum:
                        raise WebContractError("HTTP/2 response exceeds its byte cap")
                    connection.acknowledge_received_data(event.flow_controlled_length, stream_id)
                elif isinstance(event, h2.events.TrailersReceived):
                    trailers.extend((str(name), str(value)) for name, value in event.headers)
                elif isinstance(event, h2.events.StreamEnded):
                    ended = True
            outbound = connection.data_to_send()
            if outbound:
                raw.sendall(outbound)
        if not ended:
            raise WebContractError("HTTP/2 stream did not end within its timeout")
        ledger.reconcile_response(operation_id, len(response_body), storage_bytes=len(response_body))
    except Exception as exc:
        ledger.abort(operation_id, f"{type(exc).__name__}: {exc}")
        raise
    finally:
        cancellation_stop.set()
        if raw is not None:
            raw.close()
        if cancellation_thread is not None:
            cancellation_thread.join(timeout=1)
    record = {
        "schemaVersion": 1,
        "workflowId": workflow["id"],
        "stepId": step["id"],
        "transport": "HTTP/2",
        "noHttp1Fallback": True,
        "identity": {
            "id": identity.id if identity else "anonymous",
            "expectedTenant": identity.expected_tenant if identity else "",
        },
        "resource": step.get("resource", {}),
        "network": {
            "connectedAddress": peer,
            "sni": decision.sni,
            "authority": decision.host_header,
            "rawPath": decision.raw_path,
            "normalizedPath": decision.normalized_path,
            "alpn": "h2",
        },
        "response": {
            "status": status,
            "headers": response_headers,
            "trailers": trailers,
            "bodyBase64": base64.b64encode(bytes(response_body)).decode(),
            "bodySha256": sha256_bytes(bytes(response_body)),
            "bodySize": len(response_body),
        },
    }
    output.mkdir(parents=True, exist_ok=False)
    atomic_json(output / "http2-observation.json", record, mode=0o600)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("contract")
    parser.add_argument("workflow")
    parser.add_argument("--signature")
    parser.add_argument("--step", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger")
    parser.add_argument("--secret-store")
    args = parser.parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    workflow_path = Path(args.workflow).expanduser().resolve()
    signature = Path(args.signature).expanduser().resolve() if args.signature else workflow_path.with_suffix(workflow_path.suffix + ".sig")
    try:
        contract = WebCampaignContract.load(contract_path)
        check = verify(campaign, contract_path, workflow_path, signature)
        if not check["passed"]:
            raise WebContractError("workflow approval failed: " + ", ".join(check["errors"]))
        workflow = load_object(workflow_path)
        matches = [step for step in workflow["steps"] if step.get("id") == args.step]
        if len(matches) != 1:
            raise WebContractError("--step must select exactly one workflow step")
        ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else campaign / "evidence" / "web" / "budget-ledger.sqlite3"
        result = execute_step(
            campaign=campaign,
            contract=contract,
            workflow=workflow,
            step=matches[0],
            ledger=SharedWebBudget(contract, ledger_path),
            output=Path(args.output).expanduser().resolve(),
            secret_store=SecretStore(args.secret_store, forbidden_root=campaign, forbidden_roots=contract.raw["requestInputs"].get("sourceRoots", [])) if args.secret_store else None,
        )
        print(json.dumps({"stepId": result["stepId"], "status": result["response"]["status"]}, indent=2))
        return 0
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
