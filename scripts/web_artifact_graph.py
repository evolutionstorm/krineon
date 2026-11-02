#!/usr/bin/env python3
"""Build a recursive client-artifact and permission graph without target traffic.

The input is a CDP-retained client-artifact manifest.  Existing artifacts are
walked recursively; unresolved same-origin chunks become explicit acquisition
experiments that must pass through Krineon's approved browser workflow.  This
script never fetches a URL and never treats client-side permission data as
server-side authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

try:
    from .web_contract import WebContractError, atomic_json, canonical_origin
except ImportError:
    from web_contract import WebContractError, atomic_json, canonical_origin


MAX_ARTIFACTS = 4000
MAX_BYTES = 256 * 1024 * 1024
JS_REFERENCE_PATTERNS = (
    re.compile(r"(?:import\s*\(|importScripts\s*\(|new\s+Worker\s*\()\s*['\"]([^'\"]+)", re.I),
    re.compile(r"(?:src|href|url|file|chunk)\s*[:=]\s*['\"]([^'\"]+\.(?:js|mjs|json))(?:\?[^'\"]*)?['\"]", re.I),
    re.compile(r"['\"]((?:/|\./|\.\./)[^'\"]+\.(?:js|mjs|json))(?:\?[^'\"]*)?['\"]", re.I),
)
ROUTE_PATTERN = re.compile(r"(?:path|route|href|to)\s*[:=]\s*['\"](/[^'\"]*)['\"]", re.I)
PERMISSION_PATTERN = re.compile(
    r"(?:permission|permissions|role|roles|scope|scopes|acl|entitlement|featureFlag|feature_flag)\s*[:=]\s*"
    r"(?:\[\s*)?['\"]([A-Za-z0-9_.:/-]{2,160})['\"]",
    re.I,
)
MENU_ENDPOINT_PATTERN = re.compile(
    r"['\"](/[^'\"]*(?:permission|role|menu|navigation|entitlement|feature)[^'\"]*)['\"]",
    re.I,
)


def stable_id(prefix: str, *values: Any) -> str:
    value = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:20]}"


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def safe_artifact(root: Path, value: str) -> Path:
    unresolved = root / value
    if unresolved.is_symlink():
        raise WebContractError(f"artifact must not be a symlink: {value}")
    path = unresolved.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise WebContractError("artifact path escapes its retained root") from error
    if not path.is_file():
        raise WebContractError(f"artifact is missing or unsafe: {value}")
    return path


def supported_reference(value: str) -> bool:
    parsed = urlsplit(value)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return False
    lowered = parsed.path.lower()
    return lowered.endswith((".js", ".mjs", ".json")) and not lowered.endswith(".map")


def references(text: str, base_url: str) -> list[str]:
    found: set[str] = set()
    for pattern in JS_REFERENCE_PATTERNS:
        for value in pattern.findall(text):
            resolved = urljoin(base_url, value)
            if supported_reference(resolved):
                found.add(resolved.split("#", 1)[0])
    # Webpack-style numeric-id to hash maps.  These are candidates rather than
    # proof of a deployed filename, so retain them separately under a synthetic
    # URL instead of guessing a request.
    return sorted(found)


def nearby_permissions(text: str, route_match: re.Match[str], radius: int = 600) -> list[str]:
    start = max(0, route_match.start() - radius)
    end = min(len(text), route_match.end() + radius)
    return sorted(set(PERMISSION_PATTERN.findall(text[start:end])))[:100]


def build(manifest_path: Path, artifact_root: Path) -> dict[str, Any]:
    manifest = load_object(manifest_path)
    if manifest.get("schemaVersion") != 1:
        raise WebContractError("artifact manifest schemaVersion must be 1")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= MAX_ARTIFACTS:
        raise WebContractError("artifact manifest requires 1..4000 artifacts")
    by_url: dict[str, dict[str, Any]] = {}
    total = 0
    for raw in artifacts:
        if not isinstance(raw, dict):
            raise WebContractError("artifacts must be objects")
        url = str(raw.get("url") or "").split("#", 1)[0]
        path = safe_artifact(artifact_root, str(raw.get("path") or ""))
        total += path.stat().st_size
        if total > MAX_BYTES:
            raise WebContractError("artifact graph input exceeds 256 MiB")
        if url:
            by_url[url] = {**raw, "_path": path}
    edges: list[dict[str, Any]] = []
    unresolved: dict[str, dict[str, Any]] = {}
    routes: dict[str, dict[str, Any]] = {}
    permission_nodes: set[str] = set()
    permission_edges: list[dict[str, Any]] = []
    menu_endpoints: set[str] = set()
    visited: set[str] = set()
    queue = list(sorted(by_url))
    while queue:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        artifact = by_url[url]
        path = artifact["_path"]
        if path.suffix.lower() not in {".js", ".mjs", ".json"} and "javascript" not in str(artifact.get("mimeType") or ""):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for target in references(text, url):
            edge = {
                "source": url,
                "target": target,
                "kind": "client-artifact-reference",
                "resolved": target in by_url,
                "sourceSha256": artifact.get("sha256"),
            }
            edges.append(edge)
            if target in by_url:
                if target not in visited:
                    queue.append(target)
            else:
                try:
                    source_origin = canonical_origin(
                        f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
                    )
                    target_origin = canonical_origin(
                        f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
                    )
                except WebContractError:
                    continue
                unresolved[target] = {
                    "url": target,
                    "sameOrigin": source_origin == target_origin,
                    "sourceArtifact": artifact.get("path"),
                    "sourceSha256": artifact.get("sha256"),
                    "journey": artifact.get("journey"),
                    "identityId": artifact.get("identityId"),
                    "tenant": artifact.get("tenant"),
                }
        for match in ROUTE_PATTERN.finditer(text):
            route = match.group(1)
            permissions = nearby_permissions(text, match)
            route_id = stable_id("ROUTE", route)
            routes.setdefault(
                route,
                {
                    "id": route_id,
                    "path": route,
                    "artifacts": [],
                    "permissionCandidates": [],
                    "confidence": "source-supported-client-policy-only",
                },
            )
            routes[route]["artifacts"].append(str(artifact.get("path") or ""))
            routes[route]["permissionCandidates"] = sorted(
                set(routes[route]["permissionCandidates"]) | set(permissions)
            )
            for permission in permissions:
                permission_nodes.add(permission)
                permission_edges.append(
                    {
                        "source": stable_id("PERM", permission),
                        "relation": "client-enables-route",
                        "target": route_id,
                        "artifact": artifact.get("path"),
                        "serverAuthorizationClaimed": False,
                    }
                )
        menu_endpoints.update(MENU_ENDPOINT_PATTERN.findall(text))
    route_rows = []
    for row in routes.values():
        row["artifacts"] = sorted(set(row["artifacts"]))
        route_rows.append(row)
    acquisition = []
    for item in sorted(unresolved.values(), key=lambda value: value["url"]):
        acquisition.append(
            {
                "id": stable_id("ARTIFACT-EXP", item["url"], item.get("identityId"), item.get("journey")),
                "question": "Does an approved legitimate journey load this referenced client artifact?",
                "url": item["url"],
                "identityId": item.get("identityId"),
                "tenant": item.get("tenant"),
                "prerequisiteJourney": item.get("journey"),
                "sameOrigin": item["sameOrigin"],
                "effectClass": "read-only",
                "execution": "requires-web-contract-and-browser-approval",
                "expectedEvidence": [
                    "real Chrome request and response metadata",
                    "retained body SHA-256",
                    "deployment epoch",
                    "negative result when the legitimate journey does not load it",
                ],
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "krineon-recursive-client-artifact-graph",
        "deploymentEpoch": manifest.get("deploymentEpoch"),
        "manifestSha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "artifactCount": len(artifacts),
        "visitedArtifactCount": len(visited),
        "edges": edges,
        "unresolvedArtifacts": list(sorted(unresolved.values(), key=lambda value: value["url"])),
        "acquisitionExperiments": acquisition,
        "permissionGraph": {
            "permissions": [
                {"id": stable_id("PERM", value), "name": value}
                for value in sorted(permission_nodes)
            ],
            "routes": sorted(route_rows, key=lambda value: value["path"]),
            "edges": permission_edges,
            "menuOrPermissionEndpointCandidates": sorted(menu_endpoints),
            "authorityWarning": (
                "Client permission and route data are discovery hints only. "
                "They do not prove a server authorization rule or permit execution."
            ),
        },
        "coverageGaps": [
            "Unresolved artifacts require a separately approved legitimate browser journey.",
            "Runtime-computed filenames may not be recoverable statically.",
            "Client permission data does not establish server-side policy.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = build(
            Path(args.manifest).expanduser().resolve(),
            Path(args.artifact_root).expanduser().resolve(),
        )
        atomic_json(Path(args.output).expanduser().resolve(), result, mode=0o600)
        print(json.dumps({
            "artifacts": result["artifactCount"],
            "edges": len(result["edges"]),
            "unresolved": len(result["unresolvedArtifacts"]),
            "routes": len(result["permissionGraph"]["routes"]),
        }, indent=2))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, WebContractError) as error:
        print(f"artifact graph error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
