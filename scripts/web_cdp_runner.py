#!/usr/bin/env python3
"""Run a signed web discovery step in sandboxed Chromium through CDP.

This adapter currently permits only loopback application origins. Remote web
navigation fails closed until OS-enforced egress confinement can route every
browser and child-process request through the controlled broker.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import secrets
import platform
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_to_bytes, urljoin, urlsplit, urlunsplit

try:
    from .experiment_control import authority_paths, sign_file
    from .chromium_replay import (
        CDPClient,
        ChromiumReplayError,
        WebSocket,
        drain_stream,
        sandbox_evidence,
        terminate_process,
        validate_browser_flags,
        wait_for_devtools,
    )
    from .web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        canonical_origin,
        redact,
        sha256_bytes,
    )
    from .web_workflow import load_object, verify
    from .web_identity import IdentityBroker
    from .web_secret_store import SecretStore
    from .web_budget import SharedWebBudget
    from .web_policy import WebPolicyEngine, classify_access_response
    from .web_artifact_graph import build as build_client_artifact_graph
    from .web_protocol_model import build as build_protocol_model
except ImportError:
    from experiment_control import authority_paths, sign_file
    from chromium_replay import (
        CDPClient,
        ChromiumReplayError,
        WebSocket,
        drain_stream,
        sandbox_evidence,
        terminate_process,
        validate_browser_flags,
        wait_for_devtools,
    )
    from web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        canonical_origin,
        redact,
        sha256_bytes,
    )
    from web_workflow import load_object, verify
    from web_identity import IdentityBroker
    from web_secret_store import SecretStore
    from web_budget import SharedWebBudget
    from web_policy import WebPolicyEngine, classify_access_response
    from web_artifact_graph import build as build_client_artifact_graph
    from web_protocol_model import build as build_protocol_model


DISCOVERY_EXPRESSION = r"""
(async () => ({
  url: location.href,
  baseUrl: document.baseURI,
  title: document.title,
  bodyTextSample: (document.body?.innerText || '').slice(0, 4096),
  passwordFieldCount: document.querySelectorAll('input[type=password]').length,
  links: [...document.querySelectorAll('a[href]')].slice(0, 500).map(a => a.href),
  forms: [...document.forms].slice(0, 200).map(f => ({
    action: f.action,
    method: (f.method || 'get').toUpperCase(),
    fields: [...f.elements].slice(0, 200).map(e => ({name: e.name || '', type: e.type || e.tagName}))
  })),
  scripts: [...document.scripts].slice(0, 500).map(s => s.src || '<inline>'),
  inlineScripts: [...document.scripts].filter(s => !s.src).slice(0, 100).map((s, i) => ({index: i, text: (s.textContent || '').slice(0, 262144)})),
  resources: performance.getEntriesByType('resource').slice(0, 1000).map(r => ({name: r.name, initiatorType: r.initiatorType})),
  windowProperties: Object.getOwnPropertyNames(window).slice(0, 2000),
  localStorageKeys: Object.keys(localStorage).slice(0, 200),
  sessionStorageKeys: Object.keys(sessionStorage).slice(0, 200),
  cookieNames: document.cookie.split(';').map(v => v.split('=', 1)[0].trim()).filter(Boolean).slice(0, 200),
  serviceWorkers: ('serviceWorker' in navigator) ? (await navigator.serviceWorker.getRegistrations()).map(r => r.scope) : []
}))()
"""


def is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def evidence_url(value: str) -> str:
    """Retain request shape while keeping URL credential values out of manifests."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        return value.split("#", 1)[0]
    host = parsed.hostname or ""
    if parsed.port is not None:
        host += f":{parsed.port}"
    query = "&".join(
        f"{name}={{value}}"
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
    )
    return urlunsplit((parsed.scheme, host, parsed.path, query, ""))


def embedded_source_map(value: str, maximum_bytes: int) -> bytes | None:
    if not value.startswith("data:") or "," not in value:
        return None
    metadata, encoded = value.split(",", 1)
    if "json" not in metadata.lower():
        return None
    try:
        payload = (
            base64.b64decode(encoded, validate=True)
            if metadata.lower().endswith(";base64")
            else unquote_to_bytes(encoded)
        )
        if len(payload) > maximum_bytes:
            return None
        document = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return None
    return payload if isinstance(document, dict) and document.get("version") == 3 else None


def bounded_tree_size(root: Path, maximum: int) -> int:
    total = 0
    for candidate in root.rglob("*"):
        if candidate.is_file() and not candidate.is_symlink():
            total += candidate.stat().st_size
            if total > maximum:
                raise WebContractError("browser profile exceeds campaign storage cap")
    return total


def collect_client_artifacts(
    *,
    client: CDPClient,
    admitted_origin: str,
    approved_loaded_origins: set[str],
    discovery: dict[str, Any],
    output: Path,
    identity_id: str,
    tenant: str,
    session: str,
    journey: str,
    deployment_epoch: str,
    deadline: float,
    maximum_bytes: int,
) -> dict[str, Any]:
    """Retain only client code Chrome loaded from an admitted origin."""

    directory = output / "client-artifacts"
    directory.mkdir(mode=0o700)
    requests: dict[str, dict[str, Any]] = {}
    responses: list[tuple[dict[str, Any], str | None]] = []
    for event in list(client.events):
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        if event.get("method") == "Network.requestWillBeSent":
            requests[str(params.get("requestId") or "")] = params
        elif event.get("method") == "Network.responseReceived":
            responses.append((params, event.get("sessionId")))
    retained: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    total = 0
    seen: set[tuple[str, str]] = set()
    for params, session_id in responses[:2000]:
        response = params.get("response") if isinstance(params.get("response"), dict) else {}
        url = str(response.get("url") or "")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        try:
            response_origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
        except WebContractError:
            continue
        resource_type = str(params.get("type") or "")
        mime = str(response.get("mimeType") or "").lower()
        manifest_like = "manifest" in Path(parsed.path).name.lower()
        if response_origin not in approved_loaded_origins or not (
            resource_type in {"Script", "Manifest", "Worker", "ServiceWorker"}
            or "javascript" in mime
            or (manifest_like and "json" in mime)
        ):
            continue
        request_id = str(params.get("requestId") or "")
        try:
            result = client.command(
                "Network.getResponseBody",
                {"requestId": request_id},
                session_id=str(session_id) if session_id else None,
                deadline=deadline,
            )
            body_value = str(result.get("body") or "")
            payload = (
                base64.b64decode(body_value, validate=True)
                if result.get("base64Encoded") is True
                else body_value.encode("utf-8")
            )
        except (ChromiumReplayError, ValueError, binascii.Error) as exc:
            unavailable.append(
                {
                    "url": evidence_url(url),
                    "reason": f"loaded response body unavailable: {exc}",
                }
            )
            continue
        if len(payload) > maximum_bytes or total + len(payload) > maximum_bytes:
            unavailable.append(
                {"url": evidence_url(url), "reason": "artifact byte cap"}
            )
            continue
        digest = sha256_bytes(payload)
        if (url, digest) in seen:
            continue
        seen.add((url, digest))
        suffix = ".json" if "json" in mime else ".js"
        retained_path = directory / f"{digest}{suffix}"
        retained_path.write_bytes(payload)
        retained_path.chmod(0o600)
        total += len(payload)
        request = requests.get(request_id, {})
        initiator = request.get("initiator") if isinstance(request.get("initiator"), dict) else {}
        source_map = re.search(
            rb"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)", payload
        )
        map_candidate = source_map.group(1).decode("utf-8", "replace") if source_map else ""
        map_path = ""
        map_provenance = "not-observed"
        if map_candidate.startswith("data:"):
            map_payload = embedded_source_map(
                map_candidate,
                min(maximum_bytes, 8 * 1024 * 1024),
            )
            if map_payload is not None and total + len(map_payload) <= maximum_bytes:
                map_digest = sha256_bytes(map_payload)
                retained_map = directory / f"{map_digest}.map"
                retained_map.write_bytes(map_payload)
                retained_map.chmod(0o600)
                total += len(map_payload)
                map_path = retained_map.relative_to(output).as_posix()
                map_provenance = "embedded-in-loaded-script"
            else:
                unavailable.append(
                    {
                        "url": evidence_url(url),
                        "reason": "embedded source map was invalid or exceeded the byte cap",
                        "sourceArtifactSha256": digest,
                    }
                )
        retained.append(
            {
                "path": retained_path.relative_to(output).as_posix(),
                "url": evidence_url(url),
                "sha256": digest,
                "size": len(payload),
                "kind": resource_type.lower() or "script",
                "mimeType": mime,
                "retrievalOrigin": "approved-real-chromium-cdp",
                "sameDocumentOrigin": response_origin == admitted_origin,
                "referringPage": evidence_url(str(discovery.get("url") or "")),
                "documentUrl": evidence_url(str(discovery.get("url") or "")),
                "documentBaseUrl": evidence_url(str(discovery.get("baseUrl") or discovery.get("url") or "")),
                "identityId": identity_id,
                "tenant": tenant,
                "session": session,
                "journey": journey,
                "workflowPrerequisites": [journey],
                "deploymentEpoch": deployment_epoch,
                "initiator": {
                    "type": initiator.get("type"),
                    "url": evidence_url(str(initiator.get("url") or ""))[:2000],
                    "stackPresent": isinstance(initiator.get("stack"), dict),
                },
                "sourceMapCandidate": (
                    "data:application/json,[retained-or-rejected]"
                    if map_candidate.startswith("data:")
                    else map_candidate
                ),
                "sourceMapPath": map_path,
                "sourceMapProvenance": map_provenance,
                "sourceMapFetched": False,
                "retrievalApproved": True,
            }
        )
        if map_candidate and not map_candidate.startswith("data:"):
            unavailable.append(
                {
                    "url": evidence_url(urljoin(url, map_candidate)),
                    "reason": "source map referenced but not automatically fetched",
                    "sourceArtifactSha256": digest,
                }
            )
    for inline in discovery.get("inlineScripts", [])[:100]:
        if not isinstance(inline, dict):
            continue
        payload = str(inline.get("text") or "").encode("utf-8")
        if not payload or len(payload) > maximum_bytes or total + len(payload) > maximum_bytes:
            continue
        digest = sha256_bytes(payload)
        retained_path = directory / f"{digest}.inline.js"
        retained_path.write_bytes(payload)
        retained_path.chmod(0o600)
        total += len(payload)
        retained.append(
            {
                "path": retained_path.relative_to(output).as_posix(),
                "url": f"{evidence_url(str(discovery.get('url') or ''))}#inline-{inline.get('index', 0)}",
                "sha256": digest,
                "size": len(payload),
                "kind": "inline-script",
                "mimeType": "text/javascript",
                "retrievalOrigin": "approved-real-chromium-dom",
                "sameDocumentOrigin": True,
                "referringPage": evidence_url(str(discovery.get("url") or "")),
                "documentUrl": evidence_url(str(discovery.get("url") or "")),
                "documentBaseUrl": evidence_url(str(discovery.get("baseUrl") or discovery.get("url") or "")),
                "identityId": identity_id,
                "tenant": tenant,
                "session": session,
                "journey": journey,
                "workflowPrerequisites": [journey],
                "deploymentEpoch": deployment_epoch,
                "sourceMapFetched": False,
                "retrievalApproved": True,
            }
        )
    return {
        "schemaVersion": 1,
        "deploymentEpoch": deployment_epoch,
        "artifacts": retained,
        "unavailableArtifacts": unavailable,
        "totalBytes": total,
        "automaticSourceMapProbing": False,
        "thirdPartyArtifactsFetched": False,
    }


def discover(
    *,
    campaign: Path,
    binary: Path,
    contract: WebCampaignContract,
    workflow: dict[str, Any],
    step: dict[str, Any],
    ledger: BudgetLedger | SharedWebBudget,
    output: Path,
    timeout: float,
    secret_store: SecretStore | None = None,
    headed: bool = False,
    required_capabilities: set[str] | None = None,
) -> dict[str, Any]:
    admitted = contract.admitted_request(
        origin_id=str(step.get("originId") or ""),
        path_or_url=str(step.get("path") or step.get("url") or ""),
        method=str(step.get("method") or "GET"),
        effect_class=str(step.get("effectClass") or "read-only"),
        operation="browser",
        operation_class=str(step.get("operationClass") or "browser-discovery"),
    )
    parsed = urlsplit(admitted["url"])
    if not is_loopback(parsed.hostname):
        raise WebContractError(
            "remote CDP navigation is blocked until OS-enforced broker-only egress is available"
        )
    identities = IdentityBroker(
        contract,
        secret_store=secret_store,
        lease_root=campaign / "evidence" / "web" / "identity-leases",
    )
    policy = WebPolicyEngine(contract)
    identity = identities.authorize(
        str(step.get("identityId") or "anonymous"),
        origin_id=admitted["originId"],
        path_or_url=admitted["url"],
        transport="browser",
    )
    credential = identities.resolve(identity) if identity is not None else ""
    if admitted["method"] != "GET" or admitted["effectClass"] != "read-only":
        raise WebContractError("browser discovery permits only read-only GET navigation")
    if not binary.is_file():
        raise WebContractError(f"Chromium binary does not exist: {binary}")
    validate_browser_flags([])
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + timeout
    run_id = "run-" + secrets.token_hex(12)
    request_counter = 0
    reserved_operations: list[str] = []
    admission_errors: list[dict[str, str]] = []
    approved_loaded_origins = {admitted["origin"]}

    def admit_subrequest(url: str, method: str) -> bool:
        nonlocal request_counter
        parsed_url = urlsplit(url)
        if parsed_url.scheme in {"about", "data", "blob"}:
            return True
        try:
            origin_value = canonical_origin(f"{parsed_url.scheme}://{parsed_url.netloc}")
            matches = [item for item in contract.origins.values() if item.origin == origin_value]
            if len(matches) != 1:
                raise WebContractError("browser subrequest origin is not admitted")
            if identity is not None:
                identities.authorize(
                    identity.id,
                    origin_id=matches[0].id,
                    path_or_url=url,
                    transport="browser",
                )
            policy.admit(
                origin_id=matches[0].id,
                url=url,
                method=method,
                effect_class="read-only" if method in {"GET", "HEAD", "OPTIONS"} else "unknown",
                operation_class="browser-discovery",
                intent=str(step.get("intent") or "browser-discovery"),
                operation="browser",
            )
            request_counter += 1
            operation_id = "op-" + hashlib.sha256(
                f"{run_id}\0{step['id']}\0{request_counter}".encode("utf-8")
            ).hexdigest()[:40]
            subrequest = contract.admitted_request(
                origin_id=matches[0].id,
                path_or_url=url,
                method=method,
                effect_class="read-only" if method in {"GET", "HEAD", "OPTIONS"} else "unknown",
                operation="browser",
                operation_class="browser-discovery",
            )
            ledger.reserve(
                operation_id=operation_id,
                request_bytes=len(url.encode("utf-8")) + len(method),
                estimated_response_bytes=int(subrequest["maxResponseBodyBytes"]),
                cleanup=False,
                adapter="cdp",
                **(
                    {
                        "origin_id": matches[0].id,
                        "browser_events": 0,
                        "lease_seconds": max(1, int(timeout) + 5),
                    }
                    if isinstance(ledger, SharedWebBudget)
                    else {}
                ),
            )
            reserved_operations.append(operation_id)
            approved_loaded_origins.add(matches[0].origin)
            return True
        except (OSError, ValueError, WebContractError) as exc:
            admission_errors.append({"url": url, "method": method, "reason": str(exc)})
            return False

    with tempfile.TemporaryDirectory(prefix="krineon-web-cdp-") as profile_value:
        profile = Path(profile_value)
        command = [
            str(binary),
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--metrics-recording-only",
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=127.0.0.1;localhost",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "about:blank",
        ]
        if not headed:
            command.insert(5, "--headless=new")
        process = subprocess.Popen(
            command,
            cwd=str(binary.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        cancellation_stop = threading.Event()
        cancellation_thread: threading.Thread | None = None
        if isinstance(ledger, SharedWebBudget):
            def cancel_browser() -> None:
                while not cancellation_stop.wait(0.05):
                    if ledger.is_cancelled():
                        terminate_process(process)
                        return

            cancellation_thread = threading.Thread(
                target=cancel_browser,
                name="krineon-browser-cancellation",
                daemon=True,
            )
            cancellation_thread.start()
        stdout_data = bytearray()
        stderr_data = bytearray()
        stdout_state = {"truncated": False}
        stderr_state = {"truncated": False}
        assert process.stdout is not None and process.stderr is not None
        threads = [
            threading.Thread(
                target=drain_stream,
                args=(process.stdout, 1024 * 1024, stdout_data, stdout_state),
                daemon=True,
            ),
            threading.Thread(
                target=drain_stream,
                args=(process.stderr, 1024 * 1024, stderr_data, stderr_state),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        websocket: WebSocket | None = None
        client: CDPClient | None = None
        completed = False
        try:
            endpoint = wait_for_devtools(profile, process, deadline)
            websocket = WebSocket(endpoint, max(0.1, deadline - time.monotonic()), 8 * 1024 * 1024)
            client = CDPClient(
                websocket,
                admitted["origin"],
                int(contract.raw["budget"].get("maxBrowserEvents", 10000)),
            )
            client.auto_attach_policy = True
            client.request_admission = admit_subrequest
            client.allow_redirects = bool(
                contract.raw["authorization"].get("allowRedirects")
            )
            version = client.command("Browser.getVersion", deadline=deadline)
            client.command(
                "Browser.setDownloadBehavior",
                {"behavior": "deny", "eventsEnabled": True},
                deadline=deadline,
            )
            client.command(
                "Target.setDiscoverTargets", {"discover": True}, deadline=deadline
            )
            client.command(
                "Target.setAutoAttach",
                {
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                },
                deadline=deadline,
            )
            created = client.command(
                "Target.createTarget", {"url": "about:blank"}, deadline=deadline
            )
            attached = client.command(
                "Target.attachToTarget",
                {"targetId": created["targetId"], "flatten": True},
                deadline=deadline,
            )
            session_id = attached["sessionId"]
            for method in ("Page.enable", "Runtime.enable", "Network.enable", "Log.enable"):
                client.command(method, session_id=session_id, deadline=deadline)
            if identity is not None:
                injected_headers = identities.injection_headers(identity, credential)
                cookie_values = [
                    value for name, value in injected_headers if name.lower() == "cookie"
                ]
                if cookie_values:
                    cookie_name, cookie_value = cookie_values[0].split("=", 1)
                    client.command(
                        "Network.setCookie",
                        {
                            "name": cookie_name,
                            "value": cookie_value,
                            "url": admitted["origin"],
                            "secure": admitted["origin"].startswith("https://"),
                            "httpOnly": True,
                            "sameSite": "Lax",
                        },
                        session_id=session_id,
                        deadline=deadline,
                    )
                scoped_headers = {
                    name: value
                    for name, value in injected_headers
                    if name.lower() != "cookie"
                }

                def inject_scoped_headers(
                    url: str, method: str, original: dict[str, str]
                ) -> dict[str, str]:
                    origin_value = canonical_origin(
                        f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
                    )
                    matches = [
                        item
                        for item in contract.origins.values()
                        if item.origin == origin_value
                    ]
                    if len(matches) != 1:
                        return original
                    identities.authorize(
                        identity.id,
                        origin_id=matches[0].id,
                        path_or_url=url,
                        transport="browser",
                    )
                    return {**original, **scoped_headers}

                client.request_header_injector = inject_scoped_headers
            client.command(
                "Fetch.enable", {"patterns": [{"urlPattern": "*"}]},
                session_id=session_id, deadline=deadline
            )
            event_index = len(client.events)
            client.command(
                "Page.navigate", {"url": admitted["url"]},
                session_id=session_id, deadline=deadline
            )
            client.wait_for(
                "Page.loadEventFired", session_id=session_id, deadline=deadline,
                after_index=event_index
            )
            # Give module-scheduled dynamic imports one bounded observation turn.
            # This does not dispatch an application action or execute bundle text
            # in the extractor; it only lets work already scheduled by the page settle.
            client.command(
                "Runtime.evaluate",
                {
                    "expression": "new Promise(resolve => setTimeout(resolve, 100))",
                    "awaitPromise": True,
                    "returnByValue": True,
                },
                session_id=session_id,
                deadline=deadline,
            )
            evaluated = client.command(
                "Runtime.evaluate",
                {
                    "expression": DISCOVERY_EXPRESSION,
                    "awaitPromise": True,
                    "returnByValue": True,
                },
                session_id=session_id,
                deadline=deadline,
            )
            if evaluated.get("exceptionDetails"):
                raise ChromiumReplayError("fixed discovery expression failed")
            discovery = evaluated.get("result", {}).get("value")
            if not isinstance(discovery, dict):
                raise ChromiumReplayError("fixed discovery expression returned no object")
            deployment_epoch = str(step.get("deploymentEpoch") or contract.digest)
            client_artifacts = collect_client_artifacts(
                client=client,
                admitted_origin=admitted["origin"],
                approved_loaded_origins=approved_loaded_origins,
                discovery=discovery,
                output=output,
                identity_id=identity.id if identity else "anonymous",
                tenant=identity.expected_tenant if identity else "",
                session=identity.session if identity else "",
                journey=str(step.get("journey") or step["id"]),
                deployment_epoch=deployment_epoch,
                deadline=deadline,
                maximum_bytes=min(
                    int(contract.raw["budget"]["totalStorageBytes"]),
                    64 * 1024 * 1024,
                ),
            )
            client_artifacts["runtimeObservations"] = [
                {
                    "browserObservationPath": "browser-observation.json",
                    "cdpEventsPath": "cdp-events.redacted.json",
                }
            ]
            client_artifacts["journeys"] = [
                {
                    "workflowId": workflow["id"],
                    "stepId": step["id"],
                    "identityId": identity.id if identity else "anonymous",
                    "tenant": identity.expected_tenant if identity else "",
                }
            ]
            client_artifacts["coverageGaps"] = [
                "Only artifacts loaded from admitted origins by this approved journey were retained.",
                "Referenced source maps were recorded but not automatically fetched.",
                "Role-dependent, feature-gated, and unvisited chunks may remain unknown.",
            ]
            client_manifest_path = output / "client-artifact-manifest.json"
            atomic_json(client_manifest_path, client_artifacts, mode=0o600)
            main_response: dict[str, Any] = {}
            for event in client.events:
                if event.get("method") != "Network.responseReceived":
                    continue
                response = (event.get("params") or {}).get("response") or {}
                if response.get("url") == admitted["url"]:
                    main_response = response
                    break
            response_headers = [
                (str(name), str(value))
                for name, value in (main_response.get("headers") or {}).items()
            ]
            access_state = classify_access_response(
                status=int(main_response.get("status") or 0),
                headers=response_headers,
                body=str((discovery or {}).get("bodyTextSample") or "").encode(
                    "utf-8", "replace"
                ),
                authenticated=identity is not None,
                location="",
            )
            if (
                identity is not None
                and int((discovery or {}).get("passwordFieldCount") or 0) > 0
                and access_state["state"] == "application-response"
            ):
                access_state = {
                    "state": "auth-inconclusive",
                    "eligibleForSecurityConclusion": False,
                    "reason": "authenticated browser session received a login form",
                    "loginHtmlWith200": int(main_response.get("status") or 0) == 200,
                    "httpStatus": int(main_response.get("status") or 0),
                }
            negotiated = {
                "network-events": True,
                "console-exceptions": True,
                "dom-and-storage-discovery": isinstance(discovery, dict),
                "service-worker-discovery": isinstance(discovery, dict)
                and isinstance(discovery.get("serviceWorkers"), list),
                "early-target-auto-attach": True,
                "fetch-scope-enforcement": True,
                "fresh-process-per-run": True,
                "fresh-profile-per-run": True,
                "normal-web-security": True,
                "browser-generated-request-context": True,
                "challenge-state-classification": True,
                "loopback-random-cdp": endpoint.startswith("ws://127.0.0.1:"),
                "downloads-denied": True,
                "headed": headed,
                "headless": not headed,
            }
            feature_errors: dict[str, str] = {}
            dom_snapshot: dict[str, Any] | None = None
            accessibility: dict[str, Any] | None = None
            screenshot_data = ""
            try:
                dom_snapshot = client.command(
                    "DOMSnapshot.captureSnapshot",
                    {"computedStyles": []},
                    session_id=session_id,
                    deadline=deadline,
                )
            except ChromiumReplayError as exc:
                feature_errors["DOMSnapshot.captureSnapshot"] = str(exc)
            try:
                client.command("Accessibility.enable", session_id=session_id, deadline=deadline)
                accessibility = client.command(
                    "Accessibility.getFullAXTree",
                    session_id=session_id,
                    deadline=deadline,
                )
            except ChromiumReplayError as exc:
                feature_errors["Accessibility.getFullAXTree"] = str(exc)
            try:
                screenshot_data = str(
                    client.command(
                        "Page.captureScreenshot",
                        {"format": "png", "captureBeyondViewport": False},
                        session_id=session_id,
                        deadline=deadline,
                    ).get("data")
                    or ""
                )
            except ChromiumReplayError as exc:
                feature_errors["Page.captureScreenshot"] = str(exc)
            required = required_capabilities or set()
            unavailable = sorted(name for name in required if not negotiated.get(name, False))
            if unavailable:
                raise WebContractError(
                    "required CDP capabilities are unavailable: " + ", ".join(unavailable)
                )
            processes = client.command("SystemInfo.getProcessInfo", deadline=deadline).get(
                "processInfo", []
            )
            sentinel = output / "sandbox-sentinel.txt"
            sentinel.write_text("krineon sandbox sentinel\n", encoding="utf-8")
            sandbox = sandbox_evidence(
                processes,
                [],
                browser_pid=process.pid,
                sentinel_path=sentinel,
            )
            sanitized_events = redact(client.events, [credential] if credential else [])
            event_path = output / "cdp-events.redacted.json"
            atomic_json(event_path, sanitized_events, mode=0o600)
            artifact_graph = build_client_artifact_graph(client_manifest_path, output)
            artifact_graph_path = output / "client-artifact-graph.json"
            atomic_json(artifact_graph_path, artifact_graph, mode=0o600)
            protocol_model = build_protocol_model(
                event_path,
                workflow_id=str(workflow["id"]),
                step_id=str(step["id"]),
                identity_id=identity.id if identity else "anonymous",
                tenant=identity.expected_tenant if identity else "",
                deployment_epoch=deployment_epoch,
            )
            protocol_model_path = output / "web-protocol-model.json"
            atomic_json(protocol_model_path, protocol_model, mode=0o600)
            artifacts = {
                "domSnapshotSha256": sha256_bytes(
                    json.dumps(dom_snapshot or {}, sort_keys=True).encode()
                ),
                "domDocumentCount": len((dom_snapshot or {}).get("documents", [])),
                "accessibilitySha256": sha256_bytes(
                    json.dumps(accessibility or {}, sort_keys=True).encode()
                ),
                "accessibilityNodeCount": len((accessibility or {}).get("nodes", [])),
                "featureErrors": feature_errors,
            }
            artifact_path = output / "browser-artifacts.json"
            atomic_json(artifact_path, artifacts, mode=0o600)
            screenshot_size = 0
            if screenshot_data:
                try:
                    screenshot = base64.b64decode(screenshot_data, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise WebContractError("CDP returned an invalid screenshot") from exc
                if len(screenshot) > int(contract.raw["budget"]["totalStorageBytes"]):
                    raise WebContractError("screenshot exceeds campaign storage cap")
                screenshot_path = output / "bounded-screenshot.png"
                screenshot_path.write_bytes(screenshot)
                screenshot_path.chmod(0o600)
                screenshot_size = len(screenshot)
                artifacts["screenshotSha256"] = sha256_bytes(screenshot)
                artifacts["screenshotSize"] = screenshot_size
                atomic_json(artifact_path, artifacts, mode=0o600)
            retained_storage = (
                event_path.stat().st_size
                + artifact_path.stat().st_size
                + client_manifest_path.stat().st_size
                + artifact_graph_path.stat().st_size
                + protocol_model_path.stat().st_size
                + int(client_artifacts["totalBytes"])
                + screenshot_size
            )
            profile_size = bounded_tree_size(
                profile, int(contract.raw["budget"]["totalStorageBytes"])
            )
            if retained_storage + profile_size > int(
                contract.raw["budget"]["totalStorageBytes"]
            ):
                raise WebContractError(
                    "browser profile plus retained evidence exceeds campaign storage cap"
                )
            if isinstance(ledger, SharedWebBudget):
                for index, operation_id in enumerate(reserved_operations):
                    if not ledger.is_cancelled(operation_id):
                        ledger.reconcile_response(
                            operation_id,
                            0,
                            storage_bytes=retained_storage if index == 0 else 0,
                            browser_events=len(client.events) if index == 0 else 0,
                        )
                if access_state["state"] in {
                    "environment-blocked",
                    "auth-inconclusive",
                }:
                    ledger.pause(
                        f"{access_state['state']} at browser step {step['id']}: "
                        f"{access_state['reason']}"
                    )
            result = {
                "schemaVersion": 1,
                "runId": run_id,
                "workflowId": workflow["id"],
                "stepId": step["id"],
                "driver": "direct-cdp",
                "mode": "headed" if headed else "headless",
                "browserBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "platform": platform.platform(),
                "launchFlags": command[1:-1],
                "url": admitted["url"],
                "identityId": identity.id if identity else "anonymous",
                "expectedTenant": identity.expected_tenant if identity else "",
                "credentialVersion": identity.secret_version if identity else "",
                "identity": {
                    "roles": list(identity.roles) if identity else [],
                    "session": identity.session if identity else "",
                    "tenant": identity.expected_tenant if identity else "",
                },
                "resource": step.get("resource", {}),
                "observationContext": step.get("observationContext", {}),
                "browser": version,
                "browserRequestContext": {
                    "generatedByChrome": True,
                    "copiedUserAgent": False,
                    "copiedClientHints": False,
                    "normalWebSecurity": True,
                    "transport": "real-chromium-cdp",
                },
                "accessState": access_state,
                "cdpCapabilities": negotiated,
                "cdpFeatureErrors": feature_errors,
                "cdpEventCount": len(client.events),
                "cdpEventsDropped": client.events_dropped,
                "cdpEventsSha256": sha256_bytes(event_path.read_bytes()),
                "artifactsSha256": sha256_bytes(artifact_path.read_bytes()),
                "clientArtifactManifest": client_manifest_path.name,
                "clientArtifactManifestSha256": sha256_bytes(
                    client_manifest_path.read_bytes()
                ),
                "clientArtifactGraph": artifact_graph_path.name,
                "clientArtifactGraphSha256": sha256_bytes(
                    artifact_graph_path.read_bytes()
                ),
                "clientArtifactGraphUnresolved": len(
                    artifact_graph["unresolvedArtifacts"]
                ),
                "clientArtifactCount": len(client_artifacts["artifacts"]),
                "clientArtifactBytes": int(client_artifacts["totalBytes"]),
                "webProtocolModel": protocol_model_path.name,
                "webProtocolModelSha256": sha256_bytes(
                    protocol_model_path.read_bytes()
                ),
                "webProtocolCoverage": protocol_model["coverage"],
                "deploymentEpoch": deployment_epoch,
                "profileSizeBeforeVerifiedCleanup": profile_size,
                "downloadsAllowed": False,
                "freshProfile": True,
                "sandbox": sandbox,
                "discovery": discovery,
                "requestCount": request_counter,
                "blockedRequests": admission_errors,
                "cdpBlockedRequests": client.blocked_external,
                "targetCrashed": client.crashed,
                "networkContainment": "loopback-only proxy and resolver confinement plus CDP admission",
                "limitations": [
                    "Remote browser traffic remains blocked until an application-aware mediator and OS egress isolation can account response bytes.",
                    "Loopback browser subrequests are request-counted centrally; only retained client-artifact bytes are exported as response evidence.",
                    "Source maps referenced by loaded scripts are not automatically requested.",
                ],
            }
            observation_path = output / "browser-observation.json"
            budget_path = output / "budget-ledger.json"
            atomic_json(budget_path, ledger.read(), mode=0o600)
            result["budgetLedgerSha256"] = sha256_bytes(budget_path.read_bytes())
            atomic_json(observation_path, result, mode=0o600)
            private_key, _ = authority_paths(campaign)
            if not private_key.is_file():
                raise WebContractError("campaign experiment authority is not initialized")
            sign_file(private_key, observation_path, output / "browser-observation.json.sig")
            completed = True
            return result
        finally:
            if client is not None and not completed:
                try:
                    failure_events = redact(
                        client.events, [credential] if credential else []
                    )
                    failure_event_path = output / "cdp-events.failure.redacted.json"
                    atomic_json(failure_event_path, failure_events, mode=0o600)
                    method_counts: dict[str, int] = {}
                    for event in client.events:
                        method = str(event.get("method") or "command-response")
                        method_counts[method] = method_counts.get(method, 0) + 1
                    failure_diagnostic = {
                        "schemaVersion": 1,
                        "kind": "krineon-cdp-failure-diagnostic",
                        "eventsRetained": len(client.events),
                        "eventsDropped": client.events_dropped,
                        "methodCounts": dict(sorted(method_counts.items())),
                        "blockedExternal": [
                            evidence_url(value) for value in client.blocked_external
                        ],
                        "admissionErrors": redact(
                            [
                                {
                                    **row,
                                    "url": evidence_url(str(row.get("url") or "")),
                                }
                                for row in admission_errors
                            ],
                            [credential] if credential else [],
                        ),
                        "networkFailureCount": len(client.network_failures),
                        "lastEvents": [
                            {
                                "method": str(event.get("method") or ""),
                                "sessionIdPresent": bool(event.get("sessionId")),
                            }
                            for event in client.events[-50:]
                        ],
                    }
                    atomic_json(
                        output / "failure-diagnostic.json",
                        failure_diagnostic,
                        mode=0o600,
                    )
                except (OSError, ValueError, TypeError):
                    pass
            cancellation_stop.set()
            if websocket is not None:
                websocket.close()
            terminate_process(process)
            for thread in threads:
                thread.join(timeout=3)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            if cancellation_thread is not None:
                cancellation_thread.join(timeout=1)
            (output / "chromium.stdout.log").write_bytes(bytes(stdout_data))
            (output / "chromium.stderr.log").write_bytes(bytes(stderr_data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("contract")
    parser.add_argument("workflow")
    parser.add_argument("--signature")
    parser.add_argument("--step", required=True)
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--secret-store")
    args = parser.parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    workflow_path = Path(args.workflow).expanduser().resolve()
    signature = (
        Path(args.signature).expanduser().resolve()
        if args.signature
        else workflow_path.with_suffix(workflow_path.suffix + ".sig")
    )
    lease: ExecutionLease | None = None
    try:
        contract = WebCampaignContract.load(contract_path)
        verification = verify(campaign, contract_path, workflow_path, signature)
        if not verification["passed"]:
            raise WebContractError(
                "workflow approval failed: " + ", ".join(verification["errors"])
            )
        workflow = load_object(workflow_path)
        matches = [step for step in workflow["steps"] if step.get("id") == args.step]
        if len(matches) != 1 or str(matches[0].get("type") or "") != "browser":
            raise WebContractError("--step must select one browser workflow step")
        lease = ExecutionLease(
            campaign / "evidence" / "web" / "execution.lock", "chromium-cdp"
        )
        lease.acquire()
        ledger_path = (
            Path(args.ledger).expanduser().resolve()
            if args.ledger
            else campaign / "evidence" / "web" / "budget-ledger.sqlite3"
        )
        result = discover(
            campaign=campaign,
            binary=Path(args.chromium).expanduser().resolve(),
            contract=contract,
            workflow=workflow,
            step=matches[0],
            ledger=SharedWebBudget(contract, ledger_path),
            output=Path(args.output).expanduser().resolve(),
            timeout=args.timeout,
            headed=args.headed,
            secret_store=(
                SecretStore(
                    args.secret_store,
                    forbidden_root=campaign,
                    forbidden_roots=contract.raw["requestInputs"].get(
                        "sourceRoots", []
                    ),
                )
                if args.secret_store
                else None
            ),
        )
        print(json.dumps({
            "stepId": result["stepId"],
            "requestCount": result["requestCount"],
            "sandboxVerified": result["sandbox"]["verified"],
            "blockedRequests": len(result["blockedRequests"]),
        }, indent=2))
        return 0
    except (OSError, ValueError, WebContractError, ChromiumReplayError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if lease is not None:
            lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
