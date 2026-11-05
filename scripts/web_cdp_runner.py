#!/usr/bin/env python3
"""Run a signed web discovery step in sandboxed Chromium through CDP.

Loopback applications are exercised directly. Remote navigation is admitted
only through a signed, loopback broker contract whose OS containment blocks
direct browser and DNS egress.
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
        path_matches_prefix,
        redact,
        sha256_bytes,
    )
    from .web_workflow import load_object, verify, validate_browser_actions
    from .web_identity import IdentityBroker
    from .web_secret_store import SecretStore
    from .web_budget import SharedWebBudget
    from .web_policy import WebPolicyEngine, classify_access_response
    from .web_artifact_graph import build as build_client_artifact_graph
    from .web_protocol_model import build as build_protocol_model
    from .websocket_experiment_frontier import build as build_websocket_frontier
    from .web_rea_bootstrap import run_when_available as run_web_rea
    from .web_research_governance import binding_from
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
        path_matches_prefix,
        redact,
        sha256_bytes,
    )
    from web_workflow import load_object, verify, validate_browser_actions
    from web_identity import IdentityBroker
    from web_secret_store import SecretStore
    from web_budget import SharedWebBudget
    from web_policy import WebPolicyEngine, classify_access_response
    from web_artifact_graph import build as build_client_artifact_graph
    from web_protocol_model import build as build_protocol_model
    from websocket_experiment_frontier import build as build_websocket_frontier
    from web_rea_bootstrap import run_when_available as run_web_rea
    from web_research_governance import binding_from


DISCOVERY_EXPRESSION = r"""
(async () => {
  const selectorFor = element => {
    if (element.id) {
      const value = `#${CSS.escape(element.id)}`;
      if (document.querySelectorAll(value).length === 1) return value;
    }
    if (element.name) {
      const value = `${element.tagName.toLowerCase()}[name="${CSS.escape(element.name)}"]`;
      if (document.querySelectorAll(value).length === 1) return value;
    }
    const testId = element.getAttribute('data-testid');
    if (testId) {
      const value = `[data-testid="${CSS.escape(testId)}"]`;
      if (document.querySelectorAll(value).length === 1) return value;
    }
    return '';
  };
  const visible = element => !!element && !element.disabled && element.getClientRects().length > 0;
  return ({
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
  interactiveControls: [...document.querySelectorAll('a[href],button,input,select,textarea,[role="button"],[role="link"],[contenteditable="true"]')]
    .filter(visible).slice(0, 1000).map(element => ({
      selector: selectorFor(element),
      tag: element.tagName.toLowerCase(),
      type: (element.type || '').toLowerCase(),
      name: element.name || '',
      role: element.getAttribute('role') || '',
      text: (element.innerText || element.getAttribute('aria-label') || element.placeholder || '').slice(0, 256),
      href: element.href || '',
      required: !!element.required,
      checked: 'checked' in element ? !!element.checked : null,
      formAction: element.form?.action || '',
      formMethod: (element.form?.method || '').toUpperCase(),
      supportsAutomaticAction: !!selectorFor(element)
    })),
  scripts: [...document.scripts].slice(0, 500).map(s => s.src || '<inline>'),
  inlineScripts: [...document.scripts].filter(s => !s.src).slice(0, 100).map((s, i) => ({index: i, text: (s.textContent || '').slice(0, 262144)})),
  resources: performance.getEntriesByType('resource').slice(0, 1000).map(r => ({name: r.name, initiatorType: r.initiatorType})),
  windowProperties: Object.getOwnPropertyNames(window).slice(0, 2000),
  localStorageKeys: Object.keys(localStorage).slice(0, 200),
  sessionStorageKeys: Object.keys(sessionStorage).slice(0, 200),
  cookieNames: document.cookie.split(';').map(v => v.split('=', 1)[0].trim()).filter(Boolean).slice(0, 200),
  serviceWorkers: ('serviceWorker' in navigator) ? (await navigator.serviceWorker.getRegistrations()).map(r => r.scope) : []
  });
})()
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


def browser_action_expression(action: dict[str, Any], value: str | None) -> str:
    """Return fixed driver code with data inserted only as JSON literals."""

    selector = json.dumps(str(action["selector"]))
    action_type = str(action["type"])
    if action_type == "wait-for-selector":
        return (
            "new Promise(resolve => { const s=" + selector + ";"
            "const found=()=>document.querySelector(s); if(found()) return resolve({ok:true,type:'wait-for-selector'});"
            "const observer=new MutationObserver(()=>{if(found()){observer.disconnect();resolve({ok:true,type:'wait-for-selector'});}});"
            "observer.observe(document,{subtree:true,childList:true});"
            "setTimeout(()=>{observer.disconnect();resolve({ok:false,reason:'selector-timeout'});},2000); })"
        )
    prefix = (
        "(() => { const element=document.querySelector(" + selector + ");"
        "if(!element) return {ok:false,reason:'selector-not-found'};"
    )
    if action_type == "click":
        return prefix + "element.click(); return {ok:true,type:'click'}; })()"
    if action_type == "double-click":
        return (
            prefix
            + "element.dispatchEvent(new MouseEvent('dblclick',{bubbles:true,cancelable:true,view:window}));"
            + "return {ok:true,type:'double-click'}; })()"
        )
    if action_type == "focus":
        return prefix + "element.focus(); return {ok:true,type:'focus'}; })()"
    if action_type == "hover":
        return (
            prefix
            + "element.dispatchEvent(new MouseEvent('mouseover',{bubbles:true,view:window}));"
            + "element.dispatchEvent(new MouseEvent('mouseenter',{bubbles:false,view:window}));"
            + "return {ok:true,type:'hover'}; })()"
        )
    if action_type == "press":
        return prefix + "element.focus(); return {ok:true,type:'press-ready'}; })()"
    if action_type in {"check", "uncheck"}:
        desired = "true" if action_type == "check" else "false"
        return (
            prefix
            + "if(!('checked' in element)) return {ok:false,reason:'not-checkable'};"
            + "const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked')?.set;"
            + "if(!setter) return {ok:false,reason:'checked-setter-unavailable'};"
            + f"setter.call(element,{desired});"
            + "element.dispatchEvent(new Event('input',{bubbles:true}));"
            + "element.dispatchEvent(new Event('change',{bubbles:true}));"
            + f"return {{ok:true,type:'{action_type}'}}; }})()"
        )
    if action_type == "submit":
        return (
            prefix
            + "const form=element instanceof HTMLFormElement?element:element.form;"
            + "if(!form) return {ok:false,reason:'form-not-found'};"
            + "if(element !== form && typeof form.requestSubmit === 'function') form.requestSubmit(element);"
            + "else if(typeof form.requestSubmit === 'function') form.requestSubmit();"
            + "else form.submit();return {ok:true,type:'submit'}; })()"
        )
    encoded_value = json.dumps(value if value is not None else "")
    if action_type == "fill":
        return (
            prefix
            + "const value=" + encoded_value + ";"
            "const proto=element instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
            "const setter=Object.getOwnPropertyDescriptor(proto,'value')?.set;"
            "if(!setter) return {ok:false,reason:'value-setter-unavailable'};"
            "setter.call(element,value);element.dispatchEvent(new Event('input',{bubbles:true}));"
            "element.dispatchEvent(new Event('change',{bubbles:true}));return {ok:true,type:'fill'}; })()"
        )
    if action_type == "select":
        return (
            prefix
            + "element.value=" + encoded_value + ";"
            "element.dispatchEvent(new Event('input',{bubbles:true}));"
            "element.dispatchEvent(new Event('change',{bubbles:true}));return {ok:true,type:'select'}; })()"
        )
    raise WebContractError("unsupported browser action")


def login_link_expression() -> str:
    """Find one same-origin login link without probing guessed routes."""

    return r"""
(() => {
  const candidates = [...document.querySelectorAll('a[href]')].map((a, index) => {
    let u; try { u = new URL(a.href, location.href); } catch (_) { return null; }
    if (u.origin !== location.origin) return null;
    const text = `${a.textContent || ''} ${a.getAttribute('aria-label') || ''} ${u.pathname}`.toLowerCase();
    let score = 0;
    if (/\b(sign[ -]?in|log[ -]?in)\b/.test(text)) score += 10;
    if (/(session|auth|account)/.test(u.pathname.toLowerCase())) score += 3;
    return {url: u.href, score, index};
  }).filter(Boolean).filter(v => v.score > 0).sort((a,b) => b.score-a.score || a.index-b.index);
  if (!candidates.length) return {ok:false, reason:'login-link-not-found'};
  if (candidates.length > 1 && candidates[0].score === candidates[1].score)
    return {ok:false, reason:'ambiguous-login-links'};
  return {ok:true, url:candidates[0].url};
})()
"""


def automatic_login_expression(
    login: dict[str, Any], username: str, password: str, *, username_submitted: bool = False
) -> str:
    """Fill and submit one detected login form using only fixed driver code."""

    configuration = json.dumps(
        {
            "usernameSelector": str(login.get("usernameSelector") or ""),
            "passwordSelector": str(login.get("passwordSelector") or ""),
            "submitSelector": str(login.get("submitSelector") or ""),
            "username": username,
            "password": password,
            "usernameSubmitted": username_submitted,
        }
    )
    return r"""
(() => {
  const cfg = CONFIGURATION;
  const visible = e => !!e && !e.disabled && e.getClientRects().length > 0;
  const query = selector => { try { return selector ? document.querySelector(selector) : null; } catch (_) { return null; } };
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
  const password = query(cfg.passwordSelector) || (passwords.length === 1 ? passwords[0] : null);
  if (!password) return {ok:false, reason:passwords.length > 1 ? 'ambiguous-password-fields' : 'password-field-not-found'};
  const form = password.form || password.closest('form');
  const scope = form || document;
  const usernameCandidates = [...scope.querySelectorAll('input')].filter(e => visible(e) && e !== password && !['hidden','password','checkbox','radio','submit','button'].includes((e.type || '').toLowerCase())).map((e, index) => {
    const hint = `${e.autocomplete || ''} ${e.name || ''} ${e.id || ''} ${e.type || ''}`.toLowerCase();
    let score = 0;
    if ((e.autocomplete || '').toLowerCase() === 'username') score += 20;
    if ((e.type || '').toLowerCase() === 'email') score += 12;
    if (/(user|email|login|account)/.test(hint)) score += 8;
    return {e, score, index};
  }).sort((a,b) => b.score-a.score || a.index-b.index);
  const username = query(cfg.usernameSelector) || (usernameCandidates.length ? usernameCandidates[0].e : null);
  if (!username && !cfg.usernameSubmitted) return {ok:false, reason:'username-field-not-found'};
  if (!cfg.usernameSelector && usernameCandidates.length > 1 && usernameCandidates[0].score === usernameCandidates[1].score)
    return {ok:false, reason:'ambiguous-username-fields'};
  const setValue = (element, value) => {
    const proto = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
    if (!setter) return false;
    setter.call(element, value);
    element.dispatchEvent(new Event('input', {bubbles:true}));
    element.dispatchEvent(new Event('change', {bubbles:true}));
    return true;
  };
  if ((username && !setValue(username, cfg.username)) || !setValue(password, cfg.password))
    return {ok:false, reason:'native-value-setter-unavailable'};
  const submit = query(cfg.submitSelector) || (form ? form.querySelector('button[type="submit"],input[type="submit"],button:not([type])') : null);
  const beforeUrl = location.href;
  const formAction = form ? form.action : '';
  const formMethod = form ? (form.method || 'get').toUpperCase() : '';
  if (submit) submit.click();
  else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
  else return {ok:false, reason:'submit-control-not-found'};
  return {ok:true, type:'automatic-login', beforeUrl, formAction, formMethod};
})()
""".replace("CONFIGURATION", configuration)


def automatic_username_step_expression(
    login: dict[str, Any], username: str
) -> str:
    """Submit the username stage of an observed two-step login flow."""

    configuration = json.dumps(
        {
            "usernameSelector": str(login.get("usernameSelector") or ""),
            "submitSelector": str(login.get("submitSelector") or ""),
            "username": username,
        }
    )
    return r"""
(() => {
  const cfg = CONFIGURATION;
  const visible = e => !!e && !e.disabled && e.getClientRects().length > 0;
  const query = selector => { try { return selector ? document.querySelector(selector) : null; } catch (_) { return null; } };
  const candidates = [...document.querySelectorAll('input')].filter(e => visible(e) && !['hidden','password','checkbox','radio','submit','button'].includes((e.type || '').toLowerCase())).map((e, index) => {
    const hint = `${e.autocomplete || ''} ${e.name || ''} ${e.id || ''} ${e.type || ''}`.toLowerCase();
    let score = 0;
    if ((e.autocomplete || '').toLowerCase() === 'username') score += 20;
    if ((e.type || '').toLowerCase() === 'email') score += 12;
    if (/(user|email|login|account)/.test(hint)) score += 8;
    return {e, score, index};
  }).filter(v => v.score > 0).sort((a,b) => b.score-a.score || a.index-b.index);
  const username = query(cfg.usernameSelector) || (candidates.length ? candidates[0].e : null);
  if (!username) return {ok:false, reason:'username-stage-not-found'};
  if (!cfg.usernameSelector && candidates.length > 1 && candidates[0].score === candidates[1].score)
    return {ok:false, reason:'ambiguous-username-fields'};
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (!setter) return {ok:false, reason:'native-value-setter-unavailable'};
  setter.call(username, cfg.username);
  username.dispatchEvent(new Event('input', {bubbles:true}));
  username.dispatchEvent(new Event('change', {bubbles:true}));
  const form = username.form || username.closest('form');
  const submit = query(cfg.submitSelector) || (form ? form.querySelector('button[type="submit"],input[type="submit"],button:not([type])') : null);
  const beforeUrl = location.href;
  if (submit) submit.click();
  else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
  else return {ok:false, reason:'submit-control-not-found'};
  return {ok:true, type:'automatic-login-username-stage', beforeUrl};
})()
""".replace("CONFIGURATION", configuration)


def password_ready_expression(login: dict[str, Any]) -> str:
    configuration = json.dumps(
        {"passwordSelector": str(login.get("passwordSelector") or "")}
    )
    return r"""
(() => {
  const cfg = CONFIGURATION;
  const visible = e => !!e && !e.disabled && e.getClientRects().length > 0;
  let selected = null;
  try { selected = cfg.passwordSelector ? document.querySelector(cfg.passwordSelector) : null; } catch (_) {}
  const fields = [...document.querySelectorAll('input[type="password"]')].filter(visible);
  return {ok: visible(selected) || fields.length === 1, count: fields.length};
})()
""".replace("CONFIGURATION", configuration)


def automatic_login_status_expression(
    login: dict[str, Any], before_url: str
) -> str:
    configuration = json.dumps(
        {
            "beforeUrl": before_url,
            "successSelector": str(login.get("successSelector") or ""),
            "successPathPrefix": str(login.get("successPathPrefix") or ""),
            "passwordSelector": str(login.get("passwordSelector") or ""),
        }
    )
    return r"""
(() => {
  const cfg = CONFIGURATION;
  const visible = e => !!e && e.getClientRects().length > 0;
  const query = selector => { try { return selector ? document.querySelector(selector) : null; } catch (_) { return null; } };
  const successElement = query(cfg.successSelector);
  const password = query(cfg.passwordSelector) || [...document.querySelectorAll('input[type="password"]')].find(visible);
  const pathMatched = !!cfg.successPathPrefix && location.pathname.startsWith(cfg.successPathPrefix) && !visible(password);
  const transitioned = location.href !== cfg.beforeUrl && !visible(password);
  return {ok: visible(successElement) || pathMatched || transitioned, urlChanged: location.href !== cfg.beforeUrl, passwordVisible: visible(password)};
})()
""".replace("CONFIGURATION", configuration)


def browser_network_flags(
    *, loopback_target: bool, broker: dict[str, Any] | None
) -> list[str]:
    if not loopback_target and not isinstance(broker, dict):
        raise WebContractError("remote Chromium requires a validated browser broker")
    return [
        "--proxy-server="
        + (
            str(broker["proxyUrl"])
            if not loopback_target and isinstance(broker, dict)
            else "http://127.0.0.1:9"
        ),
        "--proxy-bypass-list="
        + ("<-loopback>" if not loopback_target else "127.0.0.1;localhost"),
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ]


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
    loopback_target = is_loopback(parsed.hostname)
    broker = contract.raw["networkContainment"].get("browserBroker")
    if not loopback_target:
        if contract.raw["networkContainment"].get("remoteBrowserTraffic") != "os-egress-enforced":
            raise WebContractError(
                "remote CDP navigation is blocked until OS-enforced broker-only egress is available"
            )
        if not isinstance(broker, dict) or admitted["originId"] not in set(
            map(str, broker.get("allowedOriginIds", []))
        ):
            raise WebContractError("remote CDP origin is not admitted by the browser broker")
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
    credential = ""
    form_login_credentials: tuple[str, str] | None = None
    secret_redactions: list[str] = []
    if identity is not None:
        if identity.credential_type == "form-login":
            form_login_credentials = identities.form_login_credentials(identity)
            secret_redactions.extend(form_login_credentials)
        else:
            credential = identities.resolve(identity)
            secret_redactions.append(credential)
    if admitted["method"] != "GET" or admitted["effectClass"] != "read-only":
        raise WebContractError("browser entry navigation must be a read-only GET")
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
    browser_actions = validate_browser_actions(step)
    expected_requests: list[dict[str, Any]] = []
    active_action = {"id": None}
    automatic_action_mutations: dict[str, dict[str, int]] = {}
    automatic_login_state = {
        "active": False,
        "used": 0,
        "limit": (
            int(identity.login.get("maxSubmitRequests", 3))
            if identity is not None and isinstance(identity.login, dict)
            else 0
        ),
    }
    for action in browser_actions:
        for request in action.get("expectedRequests", []):
            expected_requests.append({**request, "actionId": action["id"], "used": 0})
        if action.get("useOwnedFullTestRequestPolicy") is True:
            full_testing = contract.raw["authorization"]["ownedFullTesting"]
            limit = int(action.get("maxMutationRequests", 3))
            automatic_action_mutations[str(action["id"])] = {
                "used": 0,
                "limit": limit,
            }
            action_origin_ids = (
                identity.allowed_origin_ids
                if identity is not None
                else frozenset({str(step["originId"])})
            )
            for action_origin_id in action_origin_ids:
                origin = contract.origins[action_origin_id]
                for method in full_testing["defaultMutationMethods"]:
                    for prefix in origin.allowed_path_prefixes:
                        expected_requests.append(
                            {
                                "originId": origin.id,
                                "pathPrefix": prefix,
                                "method": method,
                                "effectClass": "disposable-write",
                                "maxCount": limit,
                                "required": False,
                                "automaticFullPolicy": True,
                                "actionId": action["id"],
                                "used": 0,
                            }
                        )

    def expected_request(url: str, method: str, origin_id: str) -> dict[str, Any] | None:
        path = urlsplit(url).path or "/"
        for request in expected_requests:
            automatic_limit = automatic_action_mutations.get(
                str(request["actionId"])
            )
            if (
                str(request["actionId"]) == str(active_action["id"])
                and
                str(request["originId"]) == origin_id
                and str(request["method"]).upper() == method.upper()
                and path_matches_prefix(path, str(request["pathPrefix"]))
                and int(request["used"]) < int(request["maxCount"])
                and (
                    automatic_limit is None
                    or int(automatic_limit["used"]) < int(automatic_limit["limit"])
                )
            ):
                return request
        return None

    def admit_subrequest(request: dict[str, Any]) -> bool:
        nonlocal request_counter
        url = str(request.get("url") or "")
        method = str(request.get("method") or "GET").upper()
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
            safe_method = method.upper() in {"GET", "HEAD", "OPTIONS"}
            expected = expected_request(url, method, matches[0].id)
            automatic_login_request = bool(
                automatic_login_state["active"]
                and identity is not None
                and identity.credential_type == "form-login"
                and matches[0].id in identity.allowed_origin_ids
                and method.upper() == "POST"
                and int(automatic_login_state["used"])
                < int(automatic_login_state["limit"])
            )
            if automatic_login_state["active"] and safe_method and parsed_url.query:
                decoded_url = unquote_to_bytes(url).decode("utf-8", "replace")
                if any(secret and secret in decoded_url for secret in secret_redactions):
                    raise WebContractError(
                        "automatic login refused to place credentials in a GET URL"
                    )
            if not safe_method and expected is None and not automatic_login_request:
                raise WebContractError(
                    "browser mutation was not declared by a signed action contract"
                )
            effect_class = (
                str(expected["effectClass"])
                if expected is not None
                else "sensitive" if automatic_login_request else "read-only"
            )
            operation_class = (
                "credential-refresh"
                if automatic_login_request
                else "browser-action" if expected is not None else "browser-discovery"
            )
            policy.admit(
                origin_id=matches[0].id,
                url=url,
                method=method,
                effect_class=effect_class,
                operation_class=operation_class,
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
                effect_class=effect_class,
                operation="browser",
                operation_class=operation_class,
            )
            post_data = request.get("postData")
            if post_data is None and request.get("hasPostData") is True:
                raise WebContractError(
                    "browser request body is unavailable for byte accounting"
                )
            body_bytes = (
                len(str(post_data).encode("utf-8")) if post_data is not None else 0
            )
            if body_bytes > int(subrequest["maxRequestBodyBytes"]):
                raise WebContractError("browser request body exceeds its action-policy cap")
            header_bytes = sum(
                len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                for name, value in (
                    request.get("headers", {}).items()
                    if isinstance(request.get("headers"), dict)
                    else []
                )
            )
            if expected is not None:
                expected["used"] = int(expected["used"]) + 1
                if expected.get("automaticFullPolicy") is True:
                    mutation_counter = automatic_action_mutations[
                        str(expected["actionId"])
                    ]
                    mutation_counter["used"] = int(mutation_counter["used"]) + 1
            if automatic_login_request:
                automatic_login_state["used"] = int(automatic_login_state["used"]) + 1
            request_bytes = (
                len(url.encode("utf-8"))
                + len(method.encode("ascii", "ignore"))
                + header_bytes
                + body_bytes
            )
            ledger.reserve(
                operation_id=operation_id,
                request_bytes=request_bytes,
                estimated_response_bytes=int(subrequest["maxResponseBodyBytes"]),
                cleanup=False,
                adapter="cdp",
                **(
                    {
                        "origin_id": matches[0].id,
                        "browser_events": 0,
                        "lease_seconds": max(1, int(timeout) + 5),
                        "research_binding": binding_from(workflow, step),
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
            *browser_network_flags(
                loopback_target=loopback_target,
                broker=broker if isinstance(broker, dict) else None,
            ),
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
            client.request_admission_detail = admit_subrequest
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
            if identity is not None and identity.credential_type != "form-login":
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
            navigation_url = admitted["url"]
            if identity is not None and isinstance(identity.login, dict):
                start_path = str(identity.login.get("startPath") or "")
                if start_path:
                    navigation_url = urljoin(admitted["origin"] + "/", start_path.lstrip("/"))
            event_index = len(client.events)
            client.command(
                "Page.navigate", {"url": navigation_url},
                session_id=session_id, deadline=deadline
            )
            client.wait_for(
                "Page.loadEventFired", session_id=session_id, deadline=deadline,
                after_index=event_index
            )
            action_results: list[dict[str, Any]] = []
            automatic_login_result: dict[str, Any] | None = None
            if identity is not None and isinstance(identity.login, dict):
                if form_login_credentials is None:
                    raise WebContractError("form-login credentials were not resolved")
                username, password = form_login_credentials
                password_presence = client.command(
                    "Runtime.evaluate",
                    {
                        "expression": "document.querySelectorAll('input[type=password]').length",
                        "returnByValue": True,
                    },
                    session_id=session_id,
                    deadline=deadline,
                ).get("result", {}).get("value", 0)
                if not int(password_presence or 0):
                    current_path = str(
                        client.command(
                            "Runtime.evaluate",
                            {
                                "expression": "location.pathname",
                                "returnByValue": True,
                            },
                            session_id=session_id,
                            deadline=deadline,
                        ).get("result", {}).get("value", "")
                    ).lower()
                    login_context = bool(
                        identity.login.get("startPath")
                        or re.search(r"(?:login|sign[-_]?in|auth|session)", current_path)
                    )
                    if not login_context:
                        link_result = client.command(
                            "Runtime.evaluate",
                            {
                                "expression": login_link_expression(),
                                "returnByValue": True,
                            },
                            session_id=session_id,
                            deadline=deadline,
                        ).get("result", {}).get("value")
                        if not isinstance(link_result, dict) or link_result.get("ok") is not True:
                            raise WebContractError(
                                "automatic login could not locate an unambiguous login form or link"
                            )
                        login_url = str(link_result.get("url") or "")
                        login_origin = canonical_origin(
                            f"{urlsplit(login_url).scheme}://{urlsplit(login_url).netloc}"
                        )
                        if login_origin != admitted["origin"]:
                            raise WebContractError("automatic login link left the admitted origin")
                        identities.authorize(
                            identity.id,
                            origin_id=admitted["originId"],
                            path_or_url=login_url,
                            transport="browser",
                        )
                        login_event_index = len(client.events)
                        client.command(
                            "Page.navigate", {"url": login_url},
                            session_id=session_id, deadline=deadline,
                        )
                        client.wait_for(
                            "Page.loadEventFired", session_id=session_id, deadline=deadline,
                            after_index=login_event_index,
                        )
                active_action["id"] = "automatic-login"
                automatic_login_state["active"] = True
                try:
                    login_deadline = min(
                        deadline,
                        time.monotonic() + int(identity.login["timeoutSeconds"]),
                    )
                    ready = client.command(
                        "Runtime.evaluate",
                        {
                            "expression": password_ready_expression(identity.login),
                            "returnByValue": True,
                        },
                        session_id=session_id,
                        deadline=login_deadline,
                    ).get("result", {}).get("value")
                    username_submitted = False
                    if not isinstance(ready, dict) or ready.get("ok") is not True:
                        username_stage = client.command(
                            "Runtime.evaluate",
                            {
                                "expression": automatic_username_step_expression(
                                    identity.login, username
                                ),
                                "returnByValue": True,
                            },
                            session_id=session_id,
                            deadline=login_deadline,
                        ).get("result", {}).get("value")
                        if not isinstance(username_stage, dict) or username_stage.get("ok") is not True:
                            reason = (
                                str(username_stage.get("reason") or "username-stage-failed")
                                if isinstance(username_stage, dict)
                                else "username-stage-failed"
                            )
                            raise WebContractError(
                                f"automatic two-step login failed: {reason}"
                            )
                        while time.monotonic() < login_deadline:
                            try:
                                ready = client.command(
                                    "Runtime.evaluate",
                                    {
                                        "expression": password_ready_expression(
                                            identity.login
                                        ),
                                        "returnByValue": True,
                                    },
                                    session_id=session_id,
                                    deadline=login_deadline,
                                ).get("result", {}).get("value")
                                if isinstance(ready, dict) and ready.get("ok") is True:
                                    break
                            except ChromiumReplayError:
                                pass
                            time.sleep(0.05)
                        if not isinstance(ready, dict) or ready.get("ok") is not True:
                            raise WebContractError(
                                "automatic two-step login did not reach a password stage"
                            )
                        username_submitted = True
                    evaluated_login = client.command(
                        "Runtime.evaluate",
                        {
                            "expression": automatic_login_expression(
                                identity.login,
                                username,
                                password,
                                username_submitted=username_submitted,
                            ),
                            "returnByValue": True,
                        },
                        session_id=session_id,
                        deadline=deadline,
                    )
                    login_submission = evaluated_login.get("result", {}).get("value")
                    if (
                        evaluated_login.get("exceptionDetails")
                        or not isinstance(login_submission, dict)
                        or login_submission.get("ok") is not True
                    ):
                        reason = (
                            str(login_submission.get("reason") or "login-action-failed")
                            if isinstance(login_submission, dict)
                            else "login-action-failed"
                        )
                        raise WebContractError(f"automatic login failed: {reason}")
                    before_url = str(login_submission.get("beforeUrl") or navigation_url)
                    status: dict[str, Any] | None = None
                    while time.monotonic() < login_deadline:
                        try:
                            evaluated_status = client.command(
                                "Runtime.evaluate",
                                {
                                    "expression": automatic_login_status_expression(
                                        identity.login, before_url
                                    ),
                                    "returnByValue": True,
                                },
                                session_id=session_id,
                                deadline=login_deadline,
                            )
                            candidate = evaluated_status.get("result", {}).get("value")
                            if isinstance(candidate, dict):
                                status = candidate
                                if candidate.get("ok") is True:
                                    break
                        except ChromiumReplayError:
                            pass
                        time.sleep(0.05)
                    if not isinstance(status, dict) or status.get("ok") is not True:
                        raise WebContractError(
                            "automatic login did not produce an observable authenticated transition"
                        )
                    automatic_login_result = {
                        "attempted": True,
                        "observedTransition": True,
                        "usernameRefUsed": True,
                        "passwordRefUsed": True,
                        "submitRequests": int(automatic_login_state["used"]),
                        "successSelectorConfigured": bool(
                            identity.login.get("successSelector")
                        ),
                        "successPathConfigured": bool(
                            identity.login.get("successPathPrefix")
                        ),
                    }
                    action_results.append(
                        {
                            "id": "automatic-login",
                            "type": "automatic-login",
                            "usedSecretRef": True,
                            "observedTransition": True,
                        }
                    )
                finally:
                    automatic_login_state["active"] = False
                    active_action["id"] = None

                current_url = client.command(
                    "Runtime.evaluate",
                    {"expression": "location.href", "returnByValue": True},
                    session_id=session_id,
                    deadline=deadline,
                ).get("result", {}).get("value", "")
                if evidence_url(str(current_url)) != evidence_url(admitted["url"]):
                    target_event_index = len(client.events)
                    client.command(
                        "Page.navigate", {"url": admitted["url"]},
                        session_id=session_id, deadline=deadline,
                    )
                    client.wait_for(
                        "Page.loadEventFired", session_id=session_id, deadline=deadline,
                        after_index=target_event_index,
                    )
            for action in browser_actions:
                active_action["id"] = action["id"]
                action_value: str | None = None
                if action.get("secretRef") is not None:
                    if secret_store is None:
                        raise WebContractError(
                            "browser action secretRef requires the private secret broker"
                        )
                    action_value = secret_store.get(str(action["secretRef"])).decode(
                        "utf-8", "strict"
                    )
                    secret_redactions.append(action_value)
                elif action.get("value") is not None:
                    action_value = str(action["value"])
                action_type = str(action["type"])
                if action_type == "navigate":
                    destination = str(action.get("url") or action.get("path") or "")
                    target_url = urljoin(admitted["origin"] + "/", destination)
                    target_origin = canonical_origin(
                        f"{urlsplit(target_url).scheme}://{urlsplit(target_url).netloc}"
                    )
                    if target_origin != admitted["origin"]:
                        raise WebContractError(
                            "declarative browser navigation left the admitted origin"
                        )
                    if identity is not None:
                        identities.authorize(
                            identity.id,
                            origin_id=admitted["originId"],
                            path_or_url=target_url,
                            transport="browser",
                        )
                    navigation_index = len(client.events)
                    client.command(
                        "Page.navigate", {"url": target_url},
                        session_id=session_id, deadline=deadline,
                    )
                    client.wait_for(
                        "Page.loadEventFired", session_id=session_id, deadline=deadline,
                        after_index=navigation_index,
                    )
                    action_result = {"ok": True, "type": "navigate"}
                elif action_type == "wait-for-url":
                    destination = str(action.get("url") or action.get("path") or "")
                    expected_url = urljoin(admitted["origin"] + "/", destination)
                    expected_origin = canonical_origin(
                        f"{urlsplit(expected_url).scheme}://{urlsplit(expected_url).netloc}"
                    )
                    if expected_origin != admitted["origin"]:
                        raise WebContractError(
                            "declarative URL wait left the admitted origin"
                        )
                    action_result = {"ok": False, "type": "wait-for-url"}
                    while time.monotonic() < deadline:
                        current_url = client.command(
                            "Runtime.evaluate",
                            {"expression": "location.href", "returnByValue": True},
                            session_id=session_id, deadline=deadline,
                        ).get("result", {}).get("value", "")
                        if evidence_url(str(current_url)) == evidence_url(expected_url):
                            action_result["ok"] = True
                            break
                        time.sleep(0.05)
                else:
                    evaluated_action = client.command(
                        "Runtime.evaluate",
                        {
                            "expression": browser_action_expression(action, action_value),
                            "awaitPromise": True,
                            "returnByValue": True,
                        },
                        session_id=session_id,
                        deadline=deadline,
                    )
                    if evaluated_action.get("exceptionDetails"):
                        raise ChromiumReplayError(
                            f"fixed browser action failed: {action['id']}"
                        )
                    action_result = evaluated_action.get("result", {}).get("value")
                    if action_type == "press" and isinstance(action_result, dict) and action_result.get("ok") is True:
                        key = str(action["key"])
                        client.command(
                            "Input.dispatchKeyEvent",
                            {"type": "keyDown", "key": key},
                            session_id=session_id, deadline=deadline,
                        )
                        client.command(
                            "Input.dispatchKeyEvent",
                            {"type": "keyUp", "key": key},
                            session_id=session_id, deadline=deadline,
                        )
                if not isinstance(action_result, dict) or action_result.get("ok") is not True:
                    raise WebContractError(
                        f"browser action did not complete: {action['id']}"
                    )
                action_results.append(
                    {
                        "id": action["id"],
                        "type": action["type"],
                        "selectorSha256": (
                            sha256_bytes(str(action["selector"]).encode())
                            if action.get("selector") else ""
                        ),
                        "destinationSha256": (
                            sha256_bytes(
                                str(action.get("url") or action.get("path") or "").encode()
                            )
                            if action_type in {"navigate", "wait-for-url"} else ""
                        ),
                        "usedSecretRef": action.get("secretRef") is not None,
                        "automaticRequestPolicy": action.get(
                            "useOwnedFullTestRequestPolicy"
                        ) is True,
                    }
                )
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
                active_action["id"] = None
            missing_expected = [
                f"{request['actionId']}:{request['method']}:{request['pathPrefix']}"
                for request in expected_requests
                if request.get("required", True) is True and int(request["used"]) == 0
            ]
            if missing_expected:
                raise WebContractError(
                    "browser actions did not produce their signed expected requests: "
                    + ", ".join(missing_expected)
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
            sanitized_events = redact(client.events, secret_redactions)
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
            websocket_frontier = build_websocket_frontier(
                protocol_model,
                [
                    {
                        "id": value.id,
                        "tenant": value.expected_tenant,
                        "roles": list(value.roles),
                        "verified": value.verification_status == "verified",
                    }
                    for value in contract.identities.values()
                ],
            )
            websocket_frontier_path = output / "websocket-experiment-frontier.json"
            atomic_json(websocket_frontier_path, websocket_frontier, mode=0o600)
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
                + websocket_frontier_path.stat().st_size
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
                "driver": "direct-cdp" if loopback_target else "brokered-cdp",
                "mode": "headed" if headed else "headless",
                "browserBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "platform": platform.platform(),
                "launchFlags": command[1:-1],
                "url": admitted["url"],
                "identityId": identity.id if identity else "anonymous",
                "expectedTenant": identity.expected_tenant if identity else "",
                "credentialVersion": (
                    identity.secret_version
                    if identity and identity.credential_type != "form-login"
                    else "form-login-pair" if identity else ""
                ),
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
                "websocketExperimentFrontier": websocket_frontier_path.name,
                "websocketExperimentFrontierSha256": sha256_bytes(
                    websocket_frontier_path.read_bytes()
                ),
                "websocketResearchCoverage": websocket_frontier["coverage"],
                "deploymentEpoch": deployment_epoch,
                "profileSizeBeforeVerifiedCleanup": profile_size,
                "downloadsAllowed": False,
                "freshProfile": True,
                "sandbox": sandbox,
                "discovery": discovery,
                "browserActions": action_results,
                "automaticLogin": automatic_login_result,
                "requestCount": request_counter,
                "blockedRequests": admission_errors,
                "cdpBlockedRequests": client.blocked_external,
                "targetCrashed": client.crashed,
                "networkContainment": (
                    {
                        "mode": "os-enforced-broker-only",
                        "brokerId": broker["brokerId"],
                        "brokerVersion": broker["brokerVersion"],
                        "directEgressBlocked": True,
                        "dnsOutsideBrokerBlocked": True,
                        "evidence": list(broker["evidence"]),
                    }
                    if not loopback_target and isinstance(broker, dict)
                    else "loopback-only proxy and resolver confinement plus CDP admission"
                ),
                "limitations": [
                    (
                        "Remote traffic was brokered under OS-enforced direct-egress and DNS containment."
                        if not loopback_target
                        else "Remote browser traffic remains blocked until broker-only OS containment is signed."
                    ),
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
                    failure_events = redact(client.events, secret_redactions)
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
                            secret_redactions,
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
        rea_status = run_web_rea(
            campaign,
            Path(args.output).expanduser().resolve(),
        )
        print(json.dumps({
            "stepId": result["stepId"],
            "requestCount": result["requestCount"],
            "sandboxVerified": result["sandbox"]["verified"],
            "blockedRequests": len(result["blockedRequests"]),
            "websocketExperiments": result["websocketResearchCoverage"],
            "reaClientAnalysis": {
                "state": rea_status["state"],
                "artifactCount": rea_status["artifactCount"],
                "hypothesisCount": rea_status.get("hypothesisCount", 0),
            },
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
