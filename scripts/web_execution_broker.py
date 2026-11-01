#!/usr/bin/env python3
"""Execute coordinator-signed web workflows through one bounded HTTP broker."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import threading
import zlib
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .experiment_control import authority_paths, sign_file
    from .web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        redact,
        sha256_bytes,
    )
    from .web_oracle import evaluate
    from .web_identity import AuthInconclusive, IdentityBroker
    from .web_secret_store import SecretStore
    from .web_workflow import load_object, verify
    from .web_budget import SharedWebBudget
    from .web_policy import (
        WebPolicyEngine,
        TargetDecision,
        classify_access_response,
        validate_http_replay_headers,
        validate_step_envelope,
    )
except ImportError:
    from experiment_control import authority_paths, sign_file
    from web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        redact,
        sha256_bytes,
    )
    from web_oracle import evaluate
    from web_identity import AuthInconclusive, IdentityBroker
    from web_secret_store import SecretStore
    from web_workflow import load_object, verify
    from web_budget import SharedWebBudget
    from web_policy import (
        WebPolicyEngine,
        TargetDecision,
        classify_access_response,
        validate_http_replay_headers,
        validate_step_envelope,
    )


FORBIDDEN_REQUEST_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
}


class PolicyHTTPConnection(http.client.HTTPConnection):
    """Connect only to an address admitted by the web policy engine."""

    def __init__(
        self,
        decision: TargetDecision,
        policy: WebPolicyEngine,
        *,
        timeout: float,
        tls_context: ssl.SSLContext | None,
    ):
        super().__init__(decision.hostname, decision.port, timeout=timeout)
        self.decision = decision
        self.policy = policy
        self.tls_context = tls_context
        self.connected_peer = ""

    def connect(self) -> None:
        last_error: Exception | None = None
        for address in self.decision.addresses:
            raw: socket.socket | ssl.SSLSocket | None = None
            try:
                raw = socket.create_connection((address, self.decision.port), self.timeout)
                peer = str(raw.getpeername()[0])
                self.policy.verify_connected(self.decision, peer)
                if self.tls_context is not None:
                    raw = self.tls_context.wrap_socket(
                        raw, server_hostname=self.decision.sni
                    )
                self.sock = raw
                self.connected_peer = peer
                return
            except (OSError, WebContractError) as exc:
                if raw is not None:
                    raw.close()
                last_error = exc
        raise WebContractError(
            f"no currently authorized destination was reachable: {last_error}"
        )


def decode_response_body(
    wire: bytes, content_encoding: str, maximum: int
) -> tuple[bytes, str]:
    encoding = content_encoding.strip().lower()
    if encoding in {"", "identity"}:
        if len(wire) > maximum:
            raise WebContractError("response exceeds decompressed-byte cap")
        return wire, "identity"
    if encoding not in {"gzip", "deflate"}:
        raise WebContractError(f"unsupported response content encoding: {encoding}")
    window = 16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
    decoder = zlib.decompressobj(window)
    decoded = decoder.decompress(wire, maximum + 1)
    if len(decoded) > maximum or decoder.unconsumed_tail:
        raise WebContractError("response exceeds decompressed-byte cap")
    decoded += decoder.flush(maximum - len(decoded) + 1)
    if len(decoded) > maximum:
        raise WebContractError("response exceeds decompressed-byte cap")
    return decoded, encoding


def header_digest(headers: list[tuple[str, str]]) -> str:
    normalized = "\n".join(f"{name.lower()}:{value}" for name, value in headers)
    return sha256_bytes(normalized.encode("utf-8", "replace"))


def body_bytes(value: Any) -> tuple[bytes, str | None]:
    if value is None:
        return b"", None
    if isinstance(value, str):
        return value.encode("utf-8"), "text/plain; charset=utf-8"
    if not isinstance(value, dict):
        raise WebContractError("request body must be text or a structured body object")
    if "json" in value:
        return (
            json.dumps(value["json"], separators=(",", ":")).encode("utf-8"),
            "application/json",
        )
    if "text" in value:
        return str(value["text"]).encode("utf-8"), str(
            value.get("contentType") or "text/plain; charset=utf-8"
        )
    if "base64" in value:
        return base64.b64decode(str(value["base64"]), validate=True), str(
            value.get("contentType") or "application/octet-stream"
        )
    raise WebContractError("body object requires json, text, or base64")


def json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise WebContractError("JSON pointer must be empty or start with /")
    current = value
    for token in pointer[1:].split("/"):
        part = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise WebContractError(f"JSON pointer does not exist: {pointer}")
    return current


EXTRACTION_KINDS = {
    "resource-id",
    "csrf-token",
    "nonce",
    "etag",
    "job-id",
    "pagination-cursor",
    "expiry",
    "generic",
}


def extract_values(
    step: dict[str, Any],
    body: bytes,
    response_headers: list[tuple[str, str]],
    *,
    identity_id: str,
    tenant: str,
    origin_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    specs = step.get("extract", [])
    if not isinstance(specs, list):
        raise WebContractError("step.extract must be an array")
    if not specs:
        return {}, {}
    parsed: Any | None = None
    public: dict[str, Any] = {}
    private: dict[str, Any] = {}
    for spec in specs:
        if not isinstance(spec, dict) or not str(spec.get("id") or ""):
            raise WebContractError("each extraction requires an id")
        kind = str(spec.get("kind") or "generic")
        if kind not in EXTRACTION_KINDS:
            raise WebContractError(f"unsupported extraction kind: {kind}")
        source = str(spec.get("source") or "json-pointer")
        if source == "json-pointer":
            if parsed is None:
                try:
                    parsed = json.loads(body)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise WebContractError(
                        "JSON extraction requested for a non-JSON response"
                    ) from exc
            value = json_pointer(parsed, str(spec.get("pointer") or ""))
        elif source == "header":
            header = str(spec.get("header") or "").lower()
            matches = [value for name, value in response_headers if name.lower() == header]
            if len(matches) != 1:
                raise WebContractError("header extraction requires exactly one matching header")
            value = matches[0]
        else:
            raise WebContractError("extraction source must be json-pointer or header")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        lifetime = spec.get("lifetimeSeconds")
        if lifetime is not None and (isinstance(lifetime, bool) or int(lifetime) < 1):
            raise WebContractError("extraction lifetimeSeconds must be positive")
        binding = {
            "producerRequest": str(step["id"]),
            "identityId": identity_id,
            "tenant": tenant,
            "originId": origin_id,
            "resourceId": str(step.get("resource", {}).get("id") or ""),
            "transferableAcrossTenants": False,
            "lifetimeSeconds": int(lifetime) if lifetime is not None else None,
        }
        public[str(spec["id"])] = {
            "sha256": sha256_bytes(encoded),
            "type": type(value).__name__,
            "kind": kind,
            "present": True,
            "binding": binding,
        }
        private[str(spec["id"])] = {**public[str(spec["id"])], "value": value}
    return public, private


class SessionJar:
    def __init__(self) -> None:
        self.cookies: dict[tuple[str, str], dict[str, str]] = {}

    def header(self, session: str, origin_id: str) -> str | None:
        values = self.cookies.get((session, origin_id), {})
        if not values:
            return None
        return "; ".join(f"{name}={value}" for name, value in sorted(values.items()))

    def update(
        self, session: str, origin_id: str, response_headers: list[tuple[str, str]]
    ) -> None:
        jar = self.cookies.setdefault((session, origin_id), {})
        for name, value in response_headers:
            if name.lower() != "set-cookie":
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for key, morsel in parsed.items():
                if morsel["max-age"] == "0" or morsel.value == "":
                    jar.pop(key, None)
                else:
                    jar[key] = morsel.value


class WebExecutionBroker:
    def __init__(
        self,
        campaign: Path,
        contract: WebCampaignContract,
        workflow: dict[str, Any],
        ledger: BudgetLedger | SharedWebBudget,
        output_dir: Path,
        secret_store: SecretStore | None = None,
        *,
        allow_bounded_concurrency: bool = False,
        dispatch_barrier: threading.Barrier | None = None,
        completion_barrier: threading.Barrier | None = None,
        finalization_barrier: threading.Barrier | None = None,
    ):
        self.campaign = campaign
        self.contract = contract
        self.workflow = workflow
        self.ledger = ledger
        self.output_dir = output_dir
        self.sessions = SessionJar()
        self.secrets: list[str] = []
        self.last_request_at: dict[str, float] = {}
        self.policy = WebPolicyEngine(contract)
        self.private_steps: list[dict[str, Any]] = []
        self.public_steps: list[dict[str, Any]] = []
        self.run_id = "run-" + secrets.token_hex(12)
        self.identities = IdentityBroker(
            contract,
            secret_store=secret_store,
            lease_root=campaign / "evidence" / "web" / "identity-leases",
        )
        self.allow_bounded_concurrency = allow_bounded_concurrency
        self.dispatch_barrier = dispatch_barrier
        self.completion_barrier = completion_barrier
        self.finalization_barrier = finalization_barrier

    @staticmethod
    def wait_pair_barrier(barrier: threading.Barrier | None, stage: str) -> None:
        if barrier is None:
            return
        try:
            barrier.wait(timeout=15)
        except threading.BrokenBarrierError as exc:
            raise WebContractError(
                f"bounded pair failed to synchronize at {stage}"
            ) from exc

    def budget_operation_id(self, step_id: str, *, cleanup: bool) -> str:
        material = f"{self.run_id}\0{step_id}\0{int(cleanup)}".encode("utf-8")
        return "op-" + hashlib.sha256(material).hexdigest()[:40]

    def rate_limit(self, origin_id: str) -> None:
        origin = self.contract.origins[origin_id]
        global_rate = float(self.contract.raw["budget"]["maxRequestsPerSecond"])
        effective = min(global_rate, origin.max_requests_per_second)
        if hasattr(self.ledger, "wait_rate"):
            self.ledger.wait_rate(origin_id, effective)
            return
        interval = 1.0 / effective
        previous = self.last_request_at.get(origin_id)
        if previous is not None:
            remaining = interval - (time.monotonic() - previous)
            if remaining > 0:
                time.sleep(min(remaining, 5.0))
        self.last_request_at[origin_id] = time.monotonic()

    def execute_step(self, step: dict[str, Any], *, cleanup: bool) -> str:
        step_id = str(step["id"])
        limits = validate_step_envelope(step, cleanup=cleanup)
        origin_id = str(step.get("originId") or "")
        origin = self.contract.origins.get(origin_id)
        if origin is None:
            raise WebContractError(f"unknown origin: {origin_id}")
        path_or_url = str(step.get("path") or step.get("url") or "")
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else origin.origin + path_or_url
        method = str(step.get("method") or "GET").upper()
        effect = str(step.get("effectClass") or "unknown")
        operation_class = str(step.get("operationClass") or "ordinary-http")
        decision = self.policy.admit(
            origin_id=origin_id,
            url=url,
            method=method,
            effect_class=effect,
            operation_class=operation_class,
            intent=str(limits["intent"]),
        )
        admitted = self.contract.admitted_request(
            origin_id=origin_id,
            path_or_url=url,
            method=method,
            effect_class=effect,
            cleanup=cleanup,
            operation="http",
            operation_class=operation_class,
        )
        if admitted["operationClass"] == "bounded-concurrency":
            race = self.contract.raw["authorization"]["boundedRaceApproval"]
            if (
                not self.allow_bounded_concurrency
                or race.get("approved") is not True
                or int(race.get("maxParticipants") or 0) != 2
            ):
                raise WebContractError(
                    "bounded concurrency requires the approved paired broker adapter"
                )
        elif admitted["operationClass"] == "websocket":
            raise WebContractError(
                f"operation class {admitted['operationClass']} requires a separate adapter"
            )
        identity = self.identities.authorize(
            str(step.get("identityId") or "anonymous"),
            origin_id=origin_id,
            path_or_url=url,
            transport="http",
        )
        body, default_content_type = body_bytes(step.get("body"))
        max_request = min(int(admitted["maxRequestBodyBytes"]), int(limits["maxInputBytes"]))
        if len(body) > max_request:
            raise WebContractError(f"request body exceeds maximum for step {step_id}")
        headers: list[tuple[str, str]] = []
        for item in step.get("headers", []):
            name, value = str(item[0]), str(item[1])
            if name.lower() in FORBIDDEN_REQUEST_HEADERS:
                raise WebContractError(f"broker-controlled header is forbidden: {name}")
            if "\r" in name + value or "\n" in name + value:
                raise WebContractError("request header contains a line break")
            headers.append((name, value))
        replay_context = validate_http_replay_headers(step, headers)
        researcher_headers = self.contract.raw.get("program", {}).get("researcherHeaders", {})
        if not isinstance(researcher_headers, dict):
            raise WebContractError("program.researcherHeaders must be an object")
        for name, value in researcher_headers.items():
            if str(name).lower() in FORBIDDEN_REQUEST_HEADERS:
                raise WebContractError("researcher headers cannot override broker credentials")
            headers.append((str(name), str(value)))
        if default_content_type and not any(name.lower() == "content-type" for name, _ in headers):
            headers.append(("Content-Type", default_content_type))
        session = str(step.get("session") or (identity.session if identity else "anonymous"))
        if session != (identity.session if identity else "anonymous"):
            raise WebContractError("workflow session must match the selected contract identity")
        credential_headers: list[tuple[str, str]] = []
        credential_header_names: set[str] = set()
        if identity is not None:
            secret = self.identities.resolve(identity)
            self.secrets.append(secret)
            credential_headers = self.identities.injection_headers(identity, secret)
            credential_header_names = {name.lower() for name, _ in credential_headers}
        session_cookie = self.sessions.header(session, origin_id)
        credential_cookie = next((value for name, value in credential_headers if name.lower() == "cookie"), "")
        if session_cookie or credential_cookie:
            headers.append(("Cookie", "; ".join(value for value in (credential_cookie, session_cookie) if value)))
        headers.extend((name, value) for name, value in credential_headers if name.lower() != "cookie")
        headers.extend([
            ("Host", decision.host_header),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ])
        estimated_response = int(admitted["maxResponseBodyBytes"])
        request_size = len(body) + sum(len(name) + len(value) + 4 for name, value in headers)
        operation_id = self.budget_operation_id(step_id, cleanup=cleanup)
        reserve_kwargs = {
            "operation_id": operation_id,
            "request_bytes": request_size,
            "estimated_response_bytes": estimated_response,
            "cleanup": cleanup,
            "adapter": "http1-application-aware",
        }
        if isinstance(self.ledger, SharedWebBudget):
            reserve_kwargs.update(
                origin_id=origin_id,
                action_units=1,
                lease_seconds=int(limits["timeoutSeconds"]) + 5,
            )
        self.ledger.reserve(**reserve_kwargs)
        self.rate_limit(origin_id)
        self.wait_pair_barrier(self.dispatch_barrier, "dispatch")
        timeout = min(float(limits["timeoutSeconds"]), float(self.contract.raw["budget"]["maxWallSeconds"]))
        tls_context = ssl.create_default_context() if decision.sni else None
        connection = PolicyHTTPConnection(
            decision, self.policy, timeout=timeout, tls_context=tls_context
        )
        wire_body = b""
        response_body = b""
        response_headers: list[tuple[str, str]] = []
        status: int | None = None
        started = time.monotonic()
        completed = False
        cancellation_stop = threading.Event()
        cancellation_thread: threading.Thread | None = None
        try:
            if hasattr(self.ledger, "is_cancelled") and self.ledger.is_cancelled(operation_id):
                raise WebContractError("dispatch capability was cancelled before connection")
            connection.connect()
            if hasattr(self.ledger, "is_cancelled"):
                def cancel_transport() -> None:
                    while not cancellation_stop.wait(0.05):
                        if self.ledger.is_cancelled(operation_id):
                            if connection.sock is not None:
                                try:
                                    connection.sock.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass
                            connection.close()
                            return

                cancellation_thread = threading.Thread(
                    target=cancel_transport,
                    name=f"krineon-cancel-{step_id}",
                    daemon=True,
                )
                cancellation_thread.start()
            connection.putrequest(method, admitted["path"], skip_host=True, skip_accept_encoding=True)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            status = response.status
            response_headers = response.getheaders()
            wire_body = response.read(estimated_response + 1)
            if len(wire_body) > estimated_response:
                raise WebContractError("wire response exceeds maxResponseBodyBytes")
            encoding = next((value for name, value in response_headers if name.lower() == "content-encoding"), "identity")
            response_body, decoded_as = decode_response_body(
                wire_body,
                encoding,
                int(self.contract.raw["budget"]["maxDecompressedBytes"]),
            )
            if hasattr(self.ledger, "is_cancelled") and self.ledger.is_cancelled(operation_id):
                raise WebContractError("dispatch capability was cancelled during response")
            self.ledger.reconcile_response(operation_id, len(wire_body), **({"storage_bytes": len(wire_body)} if isinstance(self.ledger, SharedWebBudget) else {}))
            completed = True
        except Exception as exc:
            if hasattr(self.ledger, "abort"):
                self.ledger.abort(operation_id, f"{type(exc).__name__}: {exc}")
            raise WebContractError(f"HTTP step {step_id} failed: {type(exc).__name__}: {exc}") from exc
        finally:
            cancellation_stop.set()
            connection.close()
            if cancellation_thread is not None:
                cancellation_thread.join(timeout=1)
        if not completed:
            raise WebContractError(f"HTTP step {step_id} did not reconcile its budget")
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        location = next((value for name, value in response_headers if name.lower() == "location"), "")
        redirect_policy: dict[str, Any] | None = None
        if status in {301, 302, 303, 307, 308} and location:
            try:
                target = self.policy.admit_redirect(
                    source=decision,
                    location=location,
                    method=method,
                    effect_class=effect,
                    operation_class=operation_class,
                    intent=str(limits["intent"]),
                )
                redirect_policy = {"authorizedCandidate": True, "originId": target.origin_id, "url": target.origin + target.raw_path}
            except WebContractError as exc:
                redirect_policy = {"authorizedCandidate": False, "reason": str(exc)}
        access_state = classify_access_response(
            status=int(status or 0),
            headers=response_headers,
            body=response_body,
            authenticated=identity is not None,
            location=location,
        )
        health_reason = None
        if status == 429:
            health_reason = f"target returned 429 at step {step_id}"
        elif status is not None and status >= 500:
            health_reason = f"target returned elevated error {status} at step {step_id}"
        elif elapsed_ms > float(limits["timeoutSeconds"]) * 900:
            health_reason = f"unexpected latency at step {step_id}"
        if health_reason:
            access_state = {
                "state": "environment-blocked",
                "eligibleForSecurityConclusion": False,
                "reason": health_reason,
                "httpStatus": status,
            }
        if health_reason and hasattr(self.ledger, "pause"):
            self.ledger.pause(health_reason)
        elif access_state["state"] in {"environment-blocked", "auth-inconclusive"} and hasattr(self.ledger, "pause"):
            self.ledger.pause(
                f"{access_state['state']} at step {step_id}: {access_state['reason']}"
            )
        self.sessions.update(session, origin_id, response_headers)
        identity_id = identity.id if identity else "anonymous"
        tenant = identity.expected_tenant if identity else ""
        if access_state["eligibleForSecurityConclusion"]:
            public_extractions, private_extractions = extract_values(
                step,
                response_body,
                response_headers,
                identity_id=identity_id,
                tenant=tenant,
                origin_id=origin_id,
            )
        else:
            public_extractions, private_extractions = {}, {}
        retained_headers = [[name, "<redacted>" if name.lower() in {"authorization", "cookie", "proxy-authorization", "x-api-key", "api-key", *credential_header_names} else value] for name, value in headers]
        identity_record = {
            "id": identity_id,
            "expectedTenant": tenant,
            "roles": list(identity.roles) if identity else [],
            "session": session,
            "credentialVersion": identity.secret_version if identity else "",
        }
        network = {
            "resolvedAddresses": list(decision.addresses),
            "connectedAddress": connection.connected_peer,
            "sni": decision.sni,
            "hostAuthority": decision.host_header,
            "rawPath": decision.raw_path,
            "normalizedPath": decision.normalized_path,
            "redirect": redirect_policy,
            "transport": "http/1.1",
        }
        private = {
            "id": step_id,
            "request": {
                "url": admitted["url"], "method": method, "headers": retained_headers,
                "bodyBase64": base64.b64encode(body).decode("ascii"),
                "effectClass": effect, "operationClass": operation_class, "cleanup": cleanup,
                "limits": limits, "clientFidelity": replay_context,
            },
            "identity": identity_record,
            "resource": step.get("resource", {}),
            "observationContext": step.get("observationContext", {}),
            "network": network,
            "response": {
                "status": status, "headers": response_headers,
                "wireBodyBase64": base64.b64encode(wire_body).decode("ascii"),
                "bodyBase64": base64.b64encode(response_body).decode("ascii"),
                "wireBodySha256": sha256_bytes(wire_body),
                "bodySha256": sha256_bytes(response_body), "bodySize": len(response_body),
                "elapsedMs": elapsed_ms, "contentDecoding": decoded_as,
                "extractions": private_extractions, "accessState": access_state,
            },
        }
        public = {
            "id": step_id,
            "request": {
                "url": redact(admitted["url"], self.secrets), "method": method,
                "effectClass": effect, "operationClass": operation_class, "cleanup": cleanup,
                "bodySha256": sha256_bytes(body), "bodySize": len(body), "limits": limits,
                "clientFidelity": replay_context,
            },
            "identity": identity_record,
            "resource": step.get("resource", {}),
            "observationContext": step.get("observationContext", {}),
            "network": network,
            "response": {
                "status": status, "headerSha256": header_digest(response_headers),
                "headerNames": sorted({name.lower() for name, _ in response_headers}),
                "wireBodySha256": sha256_bytes(wire_body),
                "bodySha256": sha256_bytes(response_body), "bodySize": len(response_body),
                "elapsedMs": elapsed_ms, "contentDecoding": decoded_as,
                "extractions": public_extractions, "accessState": access_state,
            },
        }
        self.private_steps.append(private)
        self.public_steps.append(public)
        return str(access_state["state"])

    def run(self) -> dict[str, Any]:
        self.contract.require_live_authorization()
        self.output_dir.mkdir(parents=True, exist_ok=False)
        failure: str | None = None
        run_state = "completed"
        try:
            for step in self.workflow["steps"]:
                if str(step.get("type") or "http") != "http":
                    raise WebContractError(
                        "HTTP broker accepts only HTTP steps; use the admitted browser or Nuclei adapter"
                    )
                operation_class = str(
                    step.get("operationClass") or "ordinary-http"
                )
                if operation_class == "request-signing":
                    raise WebContractError(
                        "request signing requires a reviewed protocol-specific adapter; "
                        "generic signing hooks are forbidden"
                    )
                if operation_class in {
                    "credential-refresh",
                    "oauth-refresh",
                    "csrf-handling",
                }:
                    identity_id = str(step.get("identityId") or "anonymous")
                    if identity_id == "anonymous":
                        raise WebContractError(
                            "credential refresh requires one contract identity"
                        )
                    with self.identities.lease(identity_id, "credential-refresh"):
                        step_state = self.execute_step(step, cleanup=False)
                else:
                    step_state = self.execute_step(step, cleanup=False)
                if step_state in {"environment-blocked", "auth-inconclusive"}:
                    run_state = step_state
                    break
        except (OSError, ValueError, WebContractError) as exc:
            failure = str(exc)
        try:
            self.wait_pair_barrier(self.completion_barrier, "completion")
        except WebContractError as exc:
            failure = failure or str(exc)
        cleanup_errors: list[str] = []
        for step in self.workflow.get("cleanupSteps", []):
            try:
                operation_class = str(
                    step.get("operationClass") or "ordinary-http"
                )
                if operation_class == "request-signing":
                    raise WebContractError(
                        "request signing requires a reviewed protocol-specific adapter; "
                        "generic signing hooks are forbidden"
                    )
                if operation_class in {
                    "credential-refresh",
                    "oauth-refresh",
                    "csrf-handling",
                }:
                    identity_id = str(step.get("identityId") or "anonymous")
                    if identity_id == "anonymous":
                        raise WebContractError(
                            "credential refresh requires one contract identity"
                        )
                    with self.identities.lease(identity_id, "credential-refresh"):
                        self.execute_step(step, cleanup=True)
                else:
                    self.execute_step(step, cleanup=True)
            except (OSError, ValueError, WebContractError) as exc:
                cleanup_errors.append(f"{step.get('id')}: {exc}")
        try:
            self.wait_pair_barrier(self.finalization_barrier, "finalization")
        except WebContractError as exc:
            failure = failure or str(exc)
        private_record = {
            "schemaVersion": 1,
            "runId": self.run_id,
            "workflowId": self.workflow["id"],
            "contractSha256": self.contract.digest,
            "steps": self.private_steps,
            "failure": failure,
            "runState": run_state,
            "cleanupErrors": cleanup_errors,
            "prerequisiteVersion": self.workflow.get("prerequisiteVersion"),
        }
        public_record = {
            "schemaVersion": 1,
            "runId": self.run_id,
            "workflowId": self.workflow["id"],
            "contractSha256": self.contract.digest,
            "driver": "krineon-controlled-web-broker",
            "steps": self.public_steps,
            "failure": failure,
            "runState": run_state,
            "cleanupErrors": cleanup_errors,
            "prerequisiteVersion": self.workflow.get("prerequisiteVersion"),
            "limitations": [],
        }
        if run_state == "completed" and failure is None:
            oracle_results = [
                evaluate(oracle, public_record) for oracle in self.workflow["oracles"]
            ]
        else:
            oracle_results = [
                {
                    "oracleId": str(oracle.get("id") or ""),
                    "status": run_state if failure is None else "execution-failed",
                    "securityViolationConfirmed": False,
                    "eligibleForSecurityConclusion": False,
                    "reason": failure or "bot/auth/environment state blocked evaluation",
                }
                for oracle in self.workflow["oracles"]
            ]
        public_record["oracleResults"] = oracle_results
        public_record["securityInvariantDisagreement"] = any(
            item["securityViolationConfirmed"] for item in oracle_results
        )
        private_path = self.output_dir / "private-evidence.json"
        public_path = self.output_dir / "observation.json"
        atomic_json(private_path, private_record, mode=0o600)
        budget_path = self.output_dir / "budget-ledger.json"
        atomic_json(budget_path, self.ledger.read(), mode=0o600)
        public_record["privateEvidenceSha256"] = sha256_bytes(private_path.read_bytes())
        public_record["budgetLedgerSha256"] = sha256_bytes(budget_path.read_bytes())
        atomic_json(public_path, public_record, mode=0o600)
        private_key, _ = authority_paths(self.campaign)
        if not private_key.is_file():
            raise WebContractError("campaign experiment authority is not initialized")
        sign_file(private_key, public_path, self.output_dir / "observation.json.sig")
        return public_record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("contract")
    parser.add_argument("workflow")
    parser.add_argument("--signature")
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger")
    parser.add_argument(
        "--secret-store",
        help="private secret store outside the campaign; environment secrets take precedence",
    )
    args = parser.parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    workflow_path = Path(args.workflow).expanduser().resolve()
    signature = (
        Path(args.signature).expanduser().resolve()
        if args.signature
        else workflow_path.with_suffix(workflow_path.suffix + ".sig")
    )
    output = Path(args.output).expanduser().resolve()
    lease: ExecutionLease | None = None
    try:
        contract = WebCampaignContract.load(contract_path)
        verification = verify(campaign, contract_path, workflow_path, signature)
        if not verification["passed"]:
            raise WebContractError(
                "workflow approval failed: " + ", ".join(verification["errors"])
            )
        workflow = load_object(workflow_path)
        lease = ExecutionLease(campaign / "evidence" / "web" / "execution.lock", "http")
        lease.acquire()
        ledger_path = (
            Path(args.ledger).expanduser().resolve()
            if args.ledger
            else campaign / "evidence" / "web" / "budget-ledger.sqlite3"
        )
        result = WebExecutionBroker(
            campaign,
            contract,
            workflow,
            SharedWebBudget(contract, ledger_path),
            output,
            SecretStore(
                args.secret_store,
                forbidden_root=campaign,
                forbidden_roots=contract.raw["requestInputs"].get("sourceRoots", []),
            )
            if args.secret_store
            else None,
        ).run()
        print(json.dumps({
            "workflowId": result["workflowId"],
            "securityInvariantDisagreement": result["securityInvariantDisagreement"],
            "failure": result["failure"],
            "output": str(output),
        }, indent=2))
        return 0 if result["failure"] is None and not result["cleanupErrors"] else 1
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if lease is not None:
            lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
