#!/usr/bin/env python3
"""Build an offline, evidence-linked application behavior surface map.

Inputs are discovery hints, never authority to execute them. The mapper performs
no network traffic and labels every statement as observed, owner-specified,
source-supported, or hypothesized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


CONFIDENCE = {"observed", "owner-specified", "source-supported", "hypothesized"}
MAX_INPUT_BYTES = 64 * 1024 * 1024
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
ACTION_WORDS = (
    "create", "read", "view", "get", "update", "edit", "delete", "remove",
    "approve", "cancel", "redeem", "invite", "transfer", "publish", "revoke",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise WebContractError(f"input exceeds 64 MiB: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def evidence(source: Path, kind: str, selector: str, confidence: str) -> dict[str, Any]:
    if confidence not in CONFIDENCE:
        raise WebContractError(f"invalid evidence confidence: {confidence}")
    return {
        "source": str(source),
        "sha256": digest(source),
        "kind": kind,
        "selector": selector,
        "confidence": confidence,
    }


def action_hint(request: dict[str, Any]) -> tuple[str, str]:
    name = " ".join(
        str(request.get(field) or "")
        for field in ("id", "workflowId", "expectedRule")
    ).lower()
    for word in ACTION_WORDS:
        if re.search(rf"(?:^|[^a-z]){re.escape(word)}(?:[^a-z]|$)", name):
            normalized = {"view": "read", "get": "read", "edit": "update", "remove": "delete"}.get(word, word)
            return normalized, "owner-specified"
    method = str((request.get("request") or {}).get("semantic", {}).get("method") or "").upper()
    return (f"http:{method.lower()}" if method else "unknown", "hypothesized")


def state_effect(action: str) -> tuple[str, str]:
    if action == "create":
        return "absent", "active"
    if action in {"delete", "revoke", "cancel"}:
        return "active", "invalidated"
    if action in {"update", "approve", "transfer", "publish", "redeem"}:
        return "active", "changed"
    return "unknown", "unchanged"


class MarkupInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").upper(),
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            self._form["fields"].append(
                {"name": values.get("name", ""), "type": values.get("type", tag)}
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def build_surface_map(
    *,
    bundles: list[Path],
    browser_observations: list[Path],
    html_files: list[Path],
    javascript_files: list[Path],
    api_specs: list[Path],
    graphql_schemas: list[Path],
    endpoint_catalogs: list[Path] | None = None,
) -> dict[str, Any]:
    inputs: list[dict[str, Any]] = []
    identities: dict[str, dict[str, Any]] = {}
    resources: dict[str, dict[str, Any]] = {}
    operations: list[dict[str, Any]] = []
    representations: list[dict[str, Any]] = []
    browser: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    endpoint_models: list[dict[str, Any]] = []

    for path in bundles:
        value = load_json(path)
        if value.get("kind") != "krineon-web-request-bundle":
            raise WebContractError(f"not a Krineon request bundle: {path}")
        inputs.append(evidence(path, "request-bundle", "$", "observed"))
        metadata_identities = (value.get("metadata") or {}).get("identities") or {}
        for identity_id in value.get("coverage", {}).get("identityLabels", []):
            item = metadata_identities.get(identity_id, {}) if isinstance(metadata_identities, dict) else {}
            identities[str(identity_id)] = {
                "id": str(identity_id),
                "tenant": str(item.get("tenant") or "unknown"),
                "roles": list(item.get("roles") or []),
                "session": str(item.get("session") or "unknown"),
                "confidence": "owner-specified" if item else "observed",
                "evidence": [evidence(path, "identity", f"coverage.identityLabels:{identity_id}", "observed")],
            }
        for index, request in enumerate(value.get("requests", [])):
            if not isinstance(request, dict):
                continue
            resource = request.get("resource") or {}
            resource_id = str(resource.get("id") or request.get("id") or f"request-{index}")
            owner = str(resource.get("expectedOwner") or "unknown")
            resources.setdefault(
                resource_id,
                {
                    "id": resource_id,
                    "kind": str(resource.get("kind") or "unknown"),
                    "owner": owner,
                    "tenant": str((identities.get(owner) or {}).get("tenant") or "unknown"),
                    "visibility": "private" if owner not in {"", "public", "unknown"} else "unknown",
                    "sensitivity": "unknown",
                    "parent": "",
                    "confidence": "owner-specified",
                    "evidence": [],
                },
            )["evidence"].append(
                evidence(path, "resource", f"requests[{index}].resource", "owner-specified")
            )
            action, action_confidence = action_hint(request)
            pre_state, post_state = state_effect(action)
            semantic = (request.get("request") or {}).get("semantic") or {}
            operations.append(
                {
                    "id": str(request.get("id") or f"request-{index}"),
                    "workflowId": str(request.get("workflowId") or "unknown"),
                    "actor": str(request.get("identityId") or "anonymous"),
                    "resourceId": resource_id,
                    "action": action,
                    "method": str(semantic.get("method") or ""),
                    "path": str(semantic.get("path") or semantic.get("target") or ""),
                    "effect": str(request.get("effectClass") or "unknown"),
                    "prerequisites": list(request.get("dependsOn") or []),
                    "preState": pre_state,
                    "postState": post_state,
                    "expectedRule": str(request.get("expectedRule") or ""),
                    "confidence": action_confidence,
                    "evidence": evidence(path, "operation", f"requests[{index}]", "observed"),
                }
            )
            representation = request.get("request") or {}
            representations.append(
                {
                    "operationId": str(request.get("id") or f"request-{index}"),
                    "protocol": str(representation.get("protocol") or "unknown"),
                    "signed": bool(representation.get("signed")),
                    "authenticationBoundFields": list(
                        (representation.get("exactReplay") or {}).get(
                            "immutableAuthenticationFields", []
                        )
                    ),
                    "byteExact": bool(representation.get("byteExact")),
                    "confidence": "observed",
                }
            )

    for path in browser_observations:
        value = load_json(path)
        inputs.append(evidence(path, "browser-observation", "$", "observed"))
        discovery = value.get("discovery") or {}
        browser.append(
            {
                "stepId": str(value.get("stepId") or ""),
                "url": str(discovery.get("url") or value.get("url") or ""),
                "links": list(discovery.get("links") or []),
                "forms": list(discovery.get("forms") or []),
                "scripts": list(discovery.get("scripts") or []),
                "resources": list(discovery.get("resources") or []),
                "serviceWorkers": list(discovery.get("serviceWorkers") or []),
                "storageKeys": {
                    "local": list(discovery.get("localStorageKeys") or []),
                    "session": list(discovery.get("sessionStorageKeys") or []),
                },
                "accessState": value.get("accessState") or {},
                "confidence": "observed",
                "evidence": evidence(path, "browser-discovery", "discovery", "observed"),
            }
        )

    for path in html_files:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise WebContractError(f"HTML input exceeds 64 MiB: {path}")
        parser = MarkupInventory()
        parser.feed(path.read_text(encoding="utf-8", errors="replace"))
        inputs.append(evidence(path, "html", "$", "source-supported"))
        hints.append(
            {
                "kind": "html-surface",
                "links": parser.links[:1000],
                "forms": parser.forms[:500],
                "scripts": parser.scripts[:1000],
                "confidence": "source-supported",
                "evidence": evidence(path, "html", "markup", "source-supported"),
            }
        )

    for path in javascript_files:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise WebContractError(f"JavaScript input exceeds 64 MiB: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        candidates = sorted(
            set(re.findall(r"(?:fetch\s*\(|axios\.[a-z]+\s*\(|new\s+WebSocket\s*\()\s*['\"]([^'\"]+)", text))
        )[:1000]
        boundaries = [
            name
            for name, pattern in {
                "postMessage": r"\bpostMessage\s*\(",
                "message-listener": r"addEventListener\s*\(\s*['\"]message",
                "localStorage": r"\blocalStorage\b",
                "service-worker": r"serviceWorker\.register\s*\(",
                "cache-api": r"\bcaches\.(?:open|match|keys)\s*\(",
            }.items()
            if re.search(pattern, text)
        ]
        inputs.append(evidence(path, "javascript", "$", "source-supported"))
        hints.append(
            {
                "kind": "javascript-surface",
                "endpointCandidates": candidates,
                "trustBoundarySignals": boundaries,
                "permission": "discovery-hint-only",
                "confidence": "source-supported",
                "evidence": evidence(path, "javascript", "bounded-regex-census", "source-supported"),
            }
        )

    for path in api_specs:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise WebContractError(f"API specification exceeds 64 MiB: {path}")
        text = path.read_text(encoding="utf-8")
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            if yaml is None:
                raise WebContractError("YAML API specifications require PyYAML")
            value = yaml.safe_load(text)
        if not isinstance(value, dict):
            raise WebContractError(f"API specification must be an object: {path}")
        paths = value.get("paths") or {}
        endpoints = []
        if isinstance(paths, dict):
            for route, operations_value in paths.items():
                if not isinstance(operations_value, dict):
                    continue
                for method, operation in operations_value.items():
                    if str(method).lower() in METHODS:
                        endpoints.append(
                            {
                                "path": str(route),
                                "method": str(method).upper(),
                                "operationId": str((operation or {}).get("operationId") or "") if isinstance(operation, dict) else "",
                            }
                        )
        inputs.append(evidence(path, "api-specification", "$", "owner-specified"))
        hints.append(
            {
                "kind": "api-specification",
                "endpoints": endpoints[:5000],
                "permission": "discovery-hint-only",
                "activeIntrospectionUsed": False,
                "confidence": "owner-specified",
                "evidence": evidence(path, "api-specification", "paths", "owner-specified"),
            }
        )

    for path in graphql_schemas:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise WebContractError(f"GraphQL schema exceeds 64 MiB: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        fields = sorted(set(re.findall(r"(?m)^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\([^)]*\))?\s*:", text)))[:5000]
        inputs.append(evidence(path, "graphql-schema", "$", "owner-specified"))
        hints.append(
            {
                "kind": "graphql-schema",
                "fieldCandidates": fields,
                "permission": "discovery-hint-only",
                "activeIntrospectionUsed": False,
                "confidence": "owner-specified",
                "evidence": evidence(path, "graphql-schema", "schema-fields", "owner-specified"),
            }
        )

    for path in endpoint_catalogs or []:
        value = load_json(path)
        if value.get("kind") != "krineon-web-endpoint-catalog":
            raise WebContractError(f"not a Krineon endpoint catalog: {path}")
        inputs.append(evidence(path, "endpoint-catalog", "$", "observed"))
        for endpoint in value.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            endpoint_models.append(
                {
                    "endpointId": endpoint.get("endpointId"),
                    "origin": endpoint.get("canonicalOrigin"),
                    "pathTemplate": endpoint.get("semanticPathTemplate"),
                    "methods": endpoint.get("candidateMethods", []),
                    "operationKind": endpoint.get("operationKind"),
                    "actors": endpoint.get("actors", []),
                    "tenants": endpoint.get("tenants", []),
                    "workflowPrerequisites": endpoint.get(
                        "workflowPrerequisites", []
                    ),
                    "confidence": endpoint.get("confidence"),
                    "effectClassification": endpoint.get(
                        "effectClassification", "unknown"
                    ),
                    "scopeApprovalStatus": endpoint.get(
                        "scopeApprovalStatus", "candidate-not-authorized"
                    ),
                }
            )
        hints.extend(
            {
                "kind": "endpoint-workflow-hypothesis",
                "confidence": item.get("confidence", "hypothesized"),
                "hypothesis": item,
                "permission": "discovery-hint-only",
                "evidence": evidence(
                    path,
                    "endpoint-catalog",
                    f"workflowHypotheses[{index}]",
                    "hypothesized",
                ),
            }
            for index, item in enumerate(value.get("workflowHypotheses", []))
            if isinstance(item, dict)
        )

    return {
        "schemaVersion": 1,
        "kind": "krineon-web-surface-map",
        "networkRequestsPerformed": 0,
        "authorityGrantedByDiscovery": False,
        "inputs": inputs,
        "identityModel": sorted(identities.values(), key=lambda item: item["id"]),
        "resourceModel": sorted(resources.values(), key=lambda item: item["id"]),
        "operationModel": operations,
        "trustRepresentationModel": representations,
        "browserModel": browser,
        "endpointModel": endpoint_models,
        "discoveryHints": hints,
        "limitations": [
            "API and source candidates are hints, not permission to execute endpoints.",
            "No active GraphQL introspection, URL brute force, or directory enumeration was performed.",
            "HTTP methods and UI visibility do not establish business authorization policy.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-bundle", action="append", default=[])
    parser.add_argument("--browser-observation", action="append", default=[])
    parser.add_argument("--html", action="append", default=[])
    parser.add_argument("--javascript", action="append", default=[])
    parser.add_argument("--api-spec", action="append", default=[])
    parser.add_argument("--graphql-schema", action="append", default=[])
    parser.add_argument("--endpoint-catalog", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        value = build_surface_map(
            bundles=[Path(item).expanduser().resolve() for item in args.request_bundle],
            browser_observations=[Path(item).expanduser().resolve() for item in args.browser_observation],
            html_files=[Path(item).expanduser().resolve() for item in args.html],
            javascript_files=[Path(item).expanduser().resolve() for item in args.javascript],
            api_specs=[Path(item).expanduser().resolve() for item in args.api_spec],
            graphql_schemas=[Path(item).expanduser().resolve() for item in args.graphql_schema],
            endpoint_catalogs=[Path(item).expanduser().resolve() for item in args.endpoint_catalog],
        )
        if not value["inputs"]:
            raise WebContractError("surface mapping requires at least one bounded input")
        output = Path(args.output).expanduser().resolve()
        atomic_json(output, value, mode=0o600)
        print(json.dumps({"identities": len(value["identityModel"]), "resources": len(value["resourceModel"]), "operations": len(value["operationModel"])}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
