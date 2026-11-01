#!/usr/bin/env python3
"""Inspect and admit complete Nuclei HTTP templates for a Krineon campaign.

The policy parses YAML, recursively expands reviewed local workflow references,
and computes the exact request cost. It does not execute Nuclei or target
traffic. Tags, severity, signatures, and upstream ignore lists are never used
as proof that a template is safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


ALLOWED_TRACKS = {"first-principles", "known-issue-baseline"}
FIRST_PRINCIPLES_PROVENANCE = {"generic-invariant", "target-derived-custom"}
HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
FORBIDDEN_PROTOCOL_KEYS = {
    "headless",
    "dns",
    "file",
    "code",
    "javascript",
    "network",
    "ssl",
    "websocket",
}
FORBIDDEN_BEHAVIOR_KEYS = {
    "flow",
    "payloads",
    "attack",
    "race",
    "race_count",
    "threads",
    "fuzzing",
    "clusterbomb",
    "pitchfork",
    "iterate_all",
}
EXTERNAL = re.compile(r"(?i)(?:https?://|interactsh|oast\.|env\s*\(|file\s*\(|readfile\s*\(|exec\s*\()")
RAW_LINE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$")


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_inside(root: Path, value: Any, field: str) -> Path:
    relative = Path(text(value, field))
    if relative.is_absolute() or ".." in relative.parts:
        raise WebContractError(f"{field} escapes the reviewed root")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise WebContractError(f"{field} escapes the reviewed root") from error
    if not path.is_file():
        raise WebContractError(f"{field} does not exist: {relative}")
    return path


def parse_yaml(path: Path) -> dict[str, Any]:
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise WebContractError("Nuclei templates must contain one YAML object")
    return documents[0]


def walk_pairs(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key).lower().replace("-", "_"), item
            yield from walk_pairs(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_pairs(item)


def manifest_entries(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-nuclei-reviewed-template-manifest":
        raise WebContractError("input is not a reviewed Nuclei manifest")
    for field in ("id", "templateCommit", "reviewPolicy"):
        text(raw.get(field), field)
    if raw["reviewPolicy"] != "complete-expanded-template":
        raise WebContractError("manifest must require complete expanded-template review")
    values = raw.get("templates")
    if not isinstance(values, list):
        raise WebContractError("reviewed manifest templates must be an array")
    result: dict[str, dict[str, Any]] = {}
    for item in values:
        if not isinstance(item, dict):
            raise WebContractError("reviewed template entries must be objects")
        template_id = text(item.get("id"), "template.id")
        if template_id in result:
            raise WebContractError("reviewed template ids must be unique")
        if item.get("track") not in ALLOWED_TRACKS:
            raise WebContractError("reviewed template track is unsupported")
        review = item.get("independentAdmissionReview")
        fixture = item.get("ownedFixtureExecution")
        if not isinstance(review, dict) or review.get("status") != "confirmed":
            raise WebContractError("every template requires independent admission review")
        if not isinstance(fixture, dict) or fixture.get("status") != "confirmed":
            raise WebContractError("every template requires owned fixture execution")
        for field in ("reviewer", "evidence"):
            text(review.get(field), f"independentAdmissionReview.{field}")
        for field in ("fixture", "evidence"):
            text(fixture.get(field), f"ownedFixtureExecution.{field}")
        approval = item.get("approval")
        if not isinstance(approval, dict) or approval.get("effect") != "read-only":
            raise WebContractError("first Nuclei adapter admits read-only templates only")
        methods = approval.get("methods")
        if not isinstance(methods, list) or not methods or not set(methods).issubset(HTTP_METHODS):
            raise WebContractError("template approval contains an unsupported method")
        paths = approval.get("allowedPathPrefixes")
        if not isinstance(paths, list) or not paths or any(not str(value).startswith("/") for value in paths):
            raise WebContractError("template approval requires explicit path prefixes")
        origins = approval.get("allowedOriginIds")
        if not isinstance(origins, list) or not origins or any(not str(value).strip() for value in origins):
            raise WebContractError("template approval requires explicit target origin ids")
        if approval.get("redirects") is not False:
            raise WebContractError("template approval cannot permit redirects")
        for field in ("maxRequests", "maxRequestBytes", "maxResponseBytes"):
            value = approval.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise WebContractError(f"template approval {field} must be non-negative")
        text(approval.get("ownedFixtureNamespace"), "approval.ownedFixtureNamespace")
        if item.get("agentGenerated") is True and review.get("reviewer") in {
            "originating-agent",
            item.get("generatedBy"),
        }:
            raise WebContractError("agent-generated templates require an independent reviewer")
        result[template_id] = item
    return result


def workflow_references(document: dict[str, Any]) -> list[str]:
    references: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            if "template" in value:
                references.append(str(value["template"]))
            for key, item in value.items():
                if key != "template":
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    if "workflows" in document:
        collect(document["workflows"])
    return references


def referenced_entry(reference: str, entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    matches = [
        item
        for item in entries.values()
        if reference in {item["id"], item["path"]}
    ]
    if len(matches) != 1:
        raise WebContractError("workflow references an unreviewed or ambiguous template")
    return matches[0]


def inspect_http_document(
    document: dict[str, Any], approval: dict[str, Any], *, maximum_request_bytes: int
) -> dict[str, Any]:
    if any(key in document for key in FORBIDDEN_PROTOCOL_KEYS):
        raise WebContractError("template uses a disabled Nuclei protocol engine")
    for key, item in walk_pairs(document):
        if key in FORBIDDEN_PROTOCOL_KEYS:
            raise WebContractError("template uses a disabled Nuclei protocol engine")
        if key in FORBIDDEN_BEHAVIOR_KEYS:
            raise WebContractError("template uses payload expansion, flow, race, fuzzing, or code-like behavior")
        if key in {"redirects", "host_redirects", "cookie_reuse"} and item is not False:
            raise WebContractError("template permits redirects or cross-request cookie state")
        if key == "max_redirects" and item not in {0, "0", None}:
            raise WebContractError("template permits redirects")
    serialized = yaml.safe_dump(document, sort_keys=True)
    stripped = serialized.replace("{{BaseURL}}", "").replace("{{Hostname}}", "")
    if EXTERNAL.search(stripped):
        raise WebContractError("template contains an external callback, URL, environment, file, or code reference")
    blocks = document.get("http", document.get("requests"))
    if not isinstance(blocks, list) or not blocks:
        raise WebContractError("template has no reviewed HTTP request blocks")
    request_count = 0
    methods: set[str] = set()
    paths: set[str] = set()
    maximum_body = 0
    for block in blocks:
        if not isinstance(block, dict):
            raise WebContractError("HTTP request blocks must be objects")
        raw = block.get("raw")
        if raw is not None:
            if not isinstance(raw, list) or not raw:
                raise WebContractError("raw HTTP requests must be a non-empty list")
            for value in raw:
                request = str(value)
                lines = request.splitlines()
                if not lines:
                    raise WebContractError("raw HTTP request is empty")
                match = RAW_LINE.fullmatch(lines[0].strip())
                if not match or match.group(1) not in HTTP_METHODS:
                    raise WebContractError("raw Nuclei request uses an unsupported method or target")
                method, target = match.groups()
                if target not in {"{{Path}}", "/fixture/canary"}:
                    raise WebContractError("raw request target is not an exact reviewed path")
                if re.search(r"(?im)^(?:Authorization|Cookie|Proxy-Authorization)\s*:", request):
                    raise WebContractError("template embeds credentials in scanner-visible request data")
                body = request.partition("\r\n\r\n")[2]
                maximum_body = max(maximum_body, len(body.encode()))
                methods.add(method)
                paths.add(target)
                request_count += 1
        else:
            method = str(block.get("method") or "GET").upper()
            if method not in HTTP_METHODS:
                raise WebContractError("Nuclei HTTP block uses a state-changing method")
            values = block.get("path")
            if not isinstance(values, list) or not values:
                raise WebContractError("Nuclei HTTP block requires explicit paths")
            for value in values:
                path = str(value)
                if not path.startswith("{{BaseURL}}/"):
                    raise WebContractError("Nuclei path must remain under the exact loopback BaseURL")
                relative = path[len("{{BaseURL}}") :]
                if "{{" in relative or "}}" in relative:
                    raise WebContractError("Nuclei path contains an unbounded dynamic expansion")
                methods.add(method)
                paths.add(relative)
                request_count += 1
            headers = block.get("headers", {})
            if not isinstance(headers, dict):
                raise WebContractError("Nuclei headers must be a static object")
            if any(str(name).lower() in {"authorization", "cookie", "proxy-authorization", "host"} for name in headers):
                raise WebContractError("template embeds credentials or overrides Host")
            body = str(block.get("body") or "")
            maximum_body = max(maximum_body, len(body.encode()))
    if not methods.issubset(set(approval["methods"])):
        raise WebContractError("expanded template method exceeds its specific approval")
    if request_count != approval["maxRequests"]:
        raise WebContractError("expanded request count differs from template-specific approval")
    if request_count < 1:
        raise WebContractError("expanded template has no requests")
    if maximum_body > min(maximum_request_bytes, approval["maxRequestBytes"]):
        raise WebContractError("expanded request body exceeds its approved byte bound")
    for path in paths:
        if path == "{{Path}}":
            continue
        if not any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in approval["allowedPathPrefixes"]):
            raise WebContractError("expanded template path exceeds its specific approval")
    return {
        "requestCount": request_count,
        "methods": sorted(methods),
        "paths": sorted(paths),
        "maximumRequestBodyBytes": maximum_body,
    }


def validate_profile(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-nuclei-profile":
        raise WebContractError("input is not a Krineon Nuclei profile")
    for field in ("id", "track"):
        text(raw.get(field), field)
    if raw["track"] not in ALLOWED_TRACKS:
        raise WebContractError("Nuclei profile track is unsupported")
    if raw.get("optional") is not True:
        raise WebContractError("Nuclei must remain optional")
    engine = raw.get("engine")
    if not isinstance(engine, dict):
        raise WebContractError("Nuclei profile requires pinned engine metadata")
    for field in ("path", "sha256", "versionOutputSha256", "helpOutputSha256"):
        text(engine.get(field), f"engine.{field}")
    required = engine.get("requiredCapabilities")
    if not isinstance(required, list) or not required:
        raise WebContractError("Nuclei profile requires detected engine capabilities")
    selected = raw.get("selectedTemplateIds")
    if not isinstance(selected, list) or len(selected) > int(raw.get("limits", {}).get("maxTemplates", -1)):
        raise WebContractError("selected Nuclei templates exceed the profile limit")
    config = raw.get("effectiveConfiguration")
    if not isinstance(config, dict):
        raise WebContractError("Nuclei profile requires effective configuration")
    for field in (
        "automaticUpdates",
        "remoteTemplateDownloads",
        "cloudUpload",
        "externalAiGeneration",
        "issueCreation",
        "discoveryIntegrations",
        "interactsh",
        "headless",
        "code",
        "javascript",
        "file",
        "network",
        "dns",
        "redirects",
    ):
        if config.get(field) is not False:
            raise WebContractError(f"effectiveConfiguration.{field} must be disabled")
    if config.get("maxRedirects") != 0 or config.get("retries") != 0:
        raise WebContractError("Nuclei redirects and retries must be zero")
    for field in ("rateLimit", "bulkSize", "concurrency", "maxJsonlBytes", "maxWallSeconds"):
        value = config.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise WebContractError(f"effectiveConfiguration.{field} must be positive")
    if config["bulkSize"] != 1 or config["concurrency"] != 1:
        raise WebContractError("first Nuclei adapter requires bulk size and concurrency of one")
    execution = raw.get("execution")
    required_true = (
        "ambientHomeDisabled",
        "identityScopedCredentialsRemainInBroker",
        "networkSandboxRequired",
        "alternateEngineEgressTestRequired",
    )
    required_false = (
        "targetTrafficByNuclei",
        "automaticTargetDiscovery",
        "allAddressScanning",
        "blanketCredentialHeaders",
        "credentialsInProcessArguments",
    )
    if not isinstance(execution, dict) or execution.get("mode") != "broker-response-loopback-replay":
        raise WebContractError("Nuclei must run only against a broker response replay")
    if any(execution.get(field) is not True for field in required_true) or any(
        execution.get(field) is not False for field in required_false
    ):
        raise WebContractError("Nuclei execution containment is incomplete")
    output = raw.get("output")
    if not isinstance(output, dict) or any(
        output.get(field) is not True
        for field in (
            "captureJsonl",
            "captureEffectiveCommand",
            "captureAcceptedRejectedTemplates",
            "captureProvenance",
            "semanticReplayRequired",
        )
    ) or output.get("publicSensitiveHttpExchanges") is not False:
        raise WebContractError("Nuclei output and replay policy is incomplete")
    return dict(raw)


def admit_templates(profile_raw: dict[str, Any], manifest_raw: dict[str, Any], root: Path) -> dict[str, Any]:
    profile = validate_profile(profile_raw)
    entries = manifest_entries(manifest_raw)
    selected_ids = list(map(str, profile["selectedTemplateIds"]))
    unknown = sorted(set(selected_ids).difference(entries))
    if unknown:
        raise WebContractError("profile selects templates absent from the reviewed manifest")
    admitted: list[dict[str, Any]] = []
    expanded_ids: set[str] = set()
    expansion_stack: set[str] = set()

    def expand(template_id: str) -> tuple[int, list[str]]:
        if template_id in expansion_stack:
            raise WebContractError("Nuclei workflow expansion contains a cycle")
        entry = entries[template_id]
        path = resolve_inside(root, entry["path"], f"template {template_id}.path")
        if sha256_file(path) != entry.get("sha256"):
            raise WebContractError("reviewed Nuclei template content hash changed")
        if entry["track"] != profile["track"]:
            raise WebContractError("selected template belongs to a different research track")
        if profile["track"] == "first-principles" and entry.get("provenance") not in FIRST_PRINCIPLES_PROVENANCE:
            raise WebContractError("first-principles mode rejects known-issue and unproven template provenance")
        if profile["track"] == "known-issue-baseline" and entry.get("provenance") != "known-issue":
            raise WebContractError("known-issue baseline accepts known-issue templates only")
        document = parse_yaml(path)
        expansion_stack.add(template_id)
        references = workflow_references(document)
        if references:
            request_count = 0
            children: list[str] = []
            for reference in references:
                child = referenced_entry(reference, entries)
                count, nested = expand(child["id"])
                request_count += count
                children.extend([child["id"], *nested])
            content = "\n".join(
                [sha256_file(path), *[entries[value]["sha256"] for value in children]]
            ).encode()
            expanded_sha = hashlib.sha256(content).hexdigest()
        else:
            inspection = inspect_http_document(
                document,
                entry["approval"],
                maximum_request_bytes=int(profile["limits"]["maxRequestBytes"]),
            )
            request_count = inspection["requestCount"]
            children = []
            expanded_sha = sha256_file(path)
        expansion_stack.remove(template_id)
        if expanded_sha != entry.get("expandedSha256"):
            raise WebContractError("expanded template/workflow hash changed")
        expanded_ids.add(template_id)
        return request_count, children

    total = 0
    for template_id in selected_ids:
        count, children = expand(template_id)
        total += count
        admitted.append(
            {
                "id": template_id,
                "path": entries[template_id]["path"],
                "sha256": entries[template_id]["sha256"],
                "expandedSha256": entries[template_id]["expandedSha256"],
                "track": entries[template_id]["track"],
                "provenance": entries[template_id]["provenance"],
                "expandedTemplateIds": children,
                "requestCount": count,
                "approval": entries[template_id]["approval"],
                "resultLabel": (
                    "known-issue-or-possible-duplicate"
                    if profile["track"] == "known-issue-baseline"
                    else "observation-only"
                ),
            }
        )
    if total > int(profile["limits"]["maxExpandedRequests"]):
        raise WebContractError("expanded Nuclei request count exceeds the profile bound")
    return {
        "schemaVersion": 1,
        "kind": "krineon-nuclei-template-admission",
        "profileId": profile["id"],
        "track": profile["track"],
        "templateCommit": manifest_raw["templateCommit"],
        "acceptedTemplates": admitted,
        "rejectedTemplates": [],
        "expandedRequestCount": total,
        "businessLogicDependency": False,
        "matchesAreObservations": True,
        "negativeScanEliminatesMechanism": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = admit_templates(
            load_object(args.profile),
            load_object(args.manifest),
            args.root.expanduser().resolve(),
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"accepted": len(result["acceptedTemplates"]), "requests": result["expandedRequestCount"]}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
