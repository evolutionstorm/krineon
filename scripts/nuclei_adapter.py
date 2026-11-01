#!/usr/bin/env python3
"""Probe, prepare, and verify optional Nuclei analysis under Krineon policy.

Nuclei never receives a production target or credential. Approved target
responses are acquired by Krineon's broker, replayed through an ephemeral
loopback fixture, and treated as scanner observations requiring semantic replay.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    from .nuclei_template_policy import admit_templates, load_object, validate_profile
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from nuclei_template_policy import admit_templates, load_object, validate_profile
    from web_contract import WebContractError, atomic_json


CAPABILITY_ALIASES = {
    "disable-update-check": ("-disable-update-check", "-duc"),
    "disable-redirects": ("-disable-redirects", "-dr"),
    "jsonl": ("-jsonl", "-j"),
    "no-interactsh": ("-no-interactsh", "-ni"),
    "rate-limit": ("-rate-limit", "-rl"),
    "bulk-size": ("-bulk-size", "-bs"),
    "concurrency": ("-concurrency", "-c"),
    "retries": ("-retries",),
    "output": ("-output", "-o"),
    "templates": ("-templates", "-t"),
    "target": ("-target", "-u"),
    "max-redirects": ("-max-redirects",),
    "no-color": ("-no-color", "-nc"),
}
SENSITIVE_OUTPUT_FIELDS = {
    "request",
    "response",
    "curl-command",
    "interaction",
    "extracted-results",
}


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_capture(command: list[str], *, timeout: int = 10) -> bytes:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env={"PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent", "NO_COLOR": "1"},
    )
    return completed.stdout[:4 * 1024 * 1024]


def first_supported(binary: Path, candidates: tuple[str, ...]) -> tuple[str, bytes]:
    for candidate in candidates:
        output = run_capture([str(binary), candidate])
        lowered = output.lower()
        if output and b"unknown flag" not in lowered and b"unknown shorthand" not in lowered:
            return candidate, output
    raise WebContractError(f"Nuclei does not expose a supported {'/'.join(candidates)} capability")


def probe_engine(binary_value: str | Path) -> dict[str, Any]:
    binary = Path(binary_value).expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise WebContractError("pinned Nuclei binary is missing or not executable")
    version_flag, version = first_supported(binary, ("-version", "--version"))
    help_flag, help_output = first_supported(binary, ("-h", "--help"))
    help_text = help_output.decode("utf-8", "replace")
    capabilities: dict[str, str] = {}
    for name, aliases in CAPABILITY_ALIASES.items():
        match = next(
            (
                alias
                for alias in aliases
                if re.search(rf"(?m)(?:^|[\s,]){re.escape(alias)}(?:[\s,=]|$)", help_text)
            ),
            None,
        )
        if match:
            capabilities[name] = match
    return {
        "schemaVersion": 1,
        "kind": "krineon-nuclei-engine-probe",
        "binary": str(binary),
        "binarySha256": sha256_file(binary),
        "versionFlag": version_flag,
        "versionOutputSha256": hashlib.sha256(version).hexdigest(),
        "versionOutput": version.decode("utf-8", "replace")[:4096],
        "helpFlag": help_flag,
        "helpOutputSha256": hashlib.sha256(help_output).hexdigest(),
        "capabilities": capabilities,
    }


def prepare_run(
    profile_raw: dict[str, Any],
    manifest_raw: dict[str, Any],
    probe: dict[str, Any],
    *,
    root: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    profile = validate_profile(profile_raw)
    engine = profile["engine"]
    for expected, actual in (
        (engine["sha256"], probe.get("binarySha256")),
        (engine["versionOutputSha256"], probe.get("versionOutputSha256")),
        (engine["helpOutputSha256"], probe.get("helpOutputSha256")),
    ):
        if expected != actual:
            raise WebContractError("pinned Nuclei engine provenance differs from the probe")
    capabilities = probe.get("capabilities")
    if not isinstance(capabilities, dict):
        raise WebContractError("Nuclei engine probe lacks capabilities")
    missing = sorted(set(engine["requiredCapabilities"]).difference(capabilities))
    for capability in ("output", "templates", "target", "max-redirects", "no-color"):
        if capability not in capabilities:
            missing.append(capability)
    if missing:
        raise WebContractError("pinned Nuclei binary lacks required capabilities: " + ", ".join(sorted(set(missing))))
    manifest_policy = profile["templateManifest"]
    if sha256_file(manifest_path) != manifest_policy["sha256"]:
        raise WebContractError("reviewed Nuclei manifest hash changed")
    admission = admit_templates(profile, manifest_raw, root)
    config = profile["effectiveConfiguration"]
    flags = {
        name: capabilities[name]
        for name in set(engine["requiredCapabilities"]).union(
            {"output", "templates", "target", "max-redirects", "no-color"}
        )
    }
    return {
        "schemaVersion": 1,
        "kind": "krineon-nuclei-run-plan",
        "profileId": profile["id"],
        "track": profile["track"],
        "engine": probe,
        "effectiveConfiguration": config,
        "flagSpellings": flags,
        "admission": admission,
        "executionMode": "broker-response-loopback-replay",
        "targetTrafficByNuclei": False,
        "identityCredentialsVisibleToNuclei": False,
        "ambientConfigurationPermitted": False,
        "semanticReplayRequired": True,
        "knownIssueClassification": (
            "known-issue-or-possible-duplicate"
            if profile["track"] == "known-issue-baseline"
            else "not-known-issue-evidence"
        ),
    }


def validate_replay_fixture(
    raw: dict[str, Any], plan: dict[str, Any], *, evidence_root: Path
) -> dict[str, Any]:
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-nuclei-broker-replay":
        raise WebContractError("input is not a broker replay fixture")
    if raw.get("targetTrafficAcquiredBy") != "krineon-web-broker":
        raise WebContractError("Nuclei replay responses must come from Krineon's broker")
    if raw.get("identityScopedCredentialInjection") is not True:
        raise WebContractError("broker replay lacks identity-scoped credential evidence")
    if raw.get("credentialsIncludedInReplay") is not False:
        raise WebContractError("Nuclei replay fixture cannot contain credentials")
    containment = raw.get("containment")
    if not isinstance(containment, dict):
        raise WebContractError("Nuclei replay requires containment evidence")
    for field in ("loopbackOnly", "alternateEngineEgressBlocked", "updatesAndUploadsBlocked"):
        if containment.get(field) is not True:
            raise WebContractError(f"Nuclei containment does not prove {field}")
    if containment.get("engineSha256") != plan["engine"]["binarySha256"]:
        raise WebContractError("containment evidence was measured with another engine")
    references = containment.get("evidence")
    if not isinstance(references, list) or not references:
        raise WebContractError("Nuclei containment requires evidence files")
    containment_proved = False
    for reference in references:
        if not isinstance(reference, dict):
            raise WebContractError("containment evidence references must be objects")
        relative = Path(text(reference.get("path"), "containment.evidence.path"))
        if relative.is_absolute() or ".." in relative.parts:
            raise WebContractError("containment evidence escapes its root")
        path = (evidence_root / relative).resolve()
        path.relative_to(evidence_root.resolve())
        if not path.is_file() or sha256_file(path) != reference.get("sha256"):
            raise WebContractError("containment evidence is missing or changed")
        try:
            proof = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WebContractError("containment evidence must be structured JSON") from error
        if not isinstance(proof, dict):
            raise WebContractError("containment evidence must be a JSON object")
        if (
            proof.get("schemaVersion") == 1
            and proof.get("kind") == "krineon-nuclei-containment-evidence"
            and proof.get("executedBy") == "krineon-coordinator"
            and proof.get("engineSha256") == plan["engine"]["binarySha256"]
            and proof.get("loopbackReplayReachable") is True
            and proof.get("alternateEngineEgressBlocked") is True
            and proof.get("updatesAndUploadsBlocked") is True
        ):
            containment_proved = True
    if not containment_proved:
        raise WebContractError("containment evidence does not prove loopback-only execution")
    allowed: list[tuple[str, str, dict[str, Any]]] = []
    for template in plan["admission"]["acceptedTemplates"]:
        for method in template["approval"]["methods"]:
            for prefix in template["approval"]["allowedPathPrefixes"]:
                allowed.append((method, prefix, template))
    routes = raw.get("routes")
    if not isinstance(routes, list) or not routes:
        raise WebContractError("Nuclei replay fixture requires routes")
    normalized = []
    for route in routes:
        if not isinstance(route, dict):
            raise WebContractError("Nuclei replay routes must be objects")
        method = text(route.get("method"), "route.method").upper()
        path_value = text(route.get("path"), "route.path")
        source_origin = text(route.get("sourceOriginId"), "route.sourceOriginId")
        namespace = text(route.get("ownedFixtureNamespace"), "route.ownedFixtureNamespace")
        candidates = [
            value
            for approved_method, prefix, value in allowed
            if method == approved_method
            and (path_value == prefix or path_value.startswith(prefix.rstrip("/") + "/"))
            and source_origin in value["approval"]["allowedOriginIds"]
            and namespace == value["approval"]["ownedFixtureNamespace"]
        ]
        if len(candidates) != 1:
            raise WebContractError("broker replay route exceeds template-specific approval")
        template = candidates[0]
        if route.get("brokerObservationSigned") is not True:
            raise WebContractError("broker replay route lacks signed observation evidence")
        text(route.get("brokerObservationSha256"), "route.brokerObservationSha256")
        text(route.get("identityBindingVersion"), "route.identityBindingVersion")
        status = route.get("status")
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise WebContractError("broker replay route has an invalid status")
        body = base64.b64decode(str(route.get("bodyBase64") or ""), validate=True)
        if len(body) > int(template["approval"]["maxResponseBytes"]):
            raise WebContractError("broker replay response exceeds its template bound")
        receipt = route.get("budgetReceipt")
        if (
            not isinstance(receipt, dict)
            or receipt.get("chargedBy") != "krineon-web-broker"
            or receipt.get("signed") is not True
            or receipt.get("requestCount") != 1
            or receipt.get("responseBytes") != len(body)
        ):
            raise WebContractError("broker replay route lacks an exact signed budget receipt")
        text(receipt.get("reservationId"), "route.budgetReceipt.reservationId")
        headers = route.get("headers", {})
        if not isinstance(headers, dict) or any(
            str(name).lower() in {"set-cookie", "authorization", "proxy-authorization"}
            for name in headers
        ):
            raise WebContractError("broker replay contains sensitive credential headers")
        normalized.append({**route, "method": method, "path": path_value, "decodedBody": body})
    return {**raw, "routes": normalized}


class ReplayHandler(BaseHTTPRequestHandler):
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    request_count = 0
    maximum_requests = 0
    budget_exceeded = False
    counter_lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self._serve("GET")

    def do_HEAD(self) -> None:
        self._serve("HEAD")

    def do_OPTIONS(self) -> None:
        self._serve("OPTIONS")

    def _serve(self, method: str) -> None:
        with type(self).counter_lock:
            type(self).request_count += 1
            if type(self).request_count > type(self).maximum_requests:
                type(self).budget_exceeded = True
                self.send_response(429)
                self.end_headers()
                return
        route = type(self).routes.get((method, self.path))
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        body = route["decodedBody"]
        self.send_response(route["status"])
        for name, value in route["headers"].items():
            self.send_header(str(name), str(value))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)


def sanitize_jsonl(path: Path, maximum: int) -> tuple[list[dict[str, Any]], str]:
    if not path.is_file():
        return [], hashlib.sha256(b"").hexdigest()
    payload = path.read_bytes()
    if len(payload) > maximum:
        raise WebContractError("Nuclei JSONL output exceeds its bounded size")
    observations = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise WebContractError("Nuclei JSONL records must be objects")
        sanitized = {
            key: item
            for key, item in value.items()
            if str(key).lower() not in SENSITIVE_OUTPUT_FIELDS
        }
        sanitized["scannerObservationOnly"] = True
        sanitized["semanticReplayRequired"] = True
        observations.append(sanitized)
    return observations, hashlib.sha256(payload).hexdigest()


def execute_replay(
    plan: dict[str, Any],
    fixture_raw: dict[str, Any],
    *,
    root: Path,
    evidence_root: Path,
    output: Path,
) -> dict[str, Any]:
    if plan.get("kind") != "krineon-nuclei-run-plan":
        raise WebContractError("input is not a prepared Nuclei run plan")
    fixture = validate_replay_fixture(fixture_raw, plan, evidence_root=evidence_root)
    containment = fixture["containment"]
    launcher = containment.get("launcher")
    if not isinstance(launcher, dict):
        raise WebContractError("Nuclei execution requires a coordinator-controlled sandbox launcher")
    launcher_path = Path(text(launcher.get("path"), "containment.launcher.path")).expanduser().resolve()
    if not launcher_path.is_file() or not os.access(launcher_path, os.X_OK):
        raise WebContractError("Nuclei sandbox launcher is missing or not executable")
    if sha256_file(launcher_path) != launcher.get("sha256"):
        raise WebContractError("Nuclei sandbox launcher hash changed")
    arguments = launcher.get("arguments")
    if not isinstance(arguments, list) or any(not isinstance(value, str) for value in arguments):
        raise WebContractError("Nuclei sandbox launcher arguments must be a string list")
    if launcher.get("interface") != "argv-prefix-double-dash":
        raise WebContractError("Nuclei sandbox launcher interface is unsupported")
    binary = Path(plan["engine"]["binary"]).resolve()
    if not binary.is_file() or sha256_file(binary) != plan["engine"]["binarySha256"]:
        raise WebContractError("prepared Nuclei binary is missing or changed")
    routes = {(value["method"], value["path"]): value for value in fixture["routes"]}
    ReplayHandler.routes = routes
    ReplayHandler.request_count = 0
    ReplayHandler.maximum_requests = int(plan["admission"]["expandedRequestCount"])
    ReplayHandler.budget_exceeded = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output.mkdir(parents=True, exist_ok=False)
    flags = plan["flagSpellings"]
    config = plan["effectiveConfiguration"]
    try:
        with tempfile.TemporaryDirectory(prefix="krineon-nuclei-") as temporary:
            private = Path(temporary)
            result_path = private / "nuclei.jsonl"
            base = f"http://127.0.0.1:{server.server_port}"
            scanner = [str(binary), flags["target"], base]
            for template in plan["admission"]["acceptedTemplates"]:
                template_path = (root / template["path"]).resolve()
                template_path.relative_to(root.resolve())
                if not template_path.is_file() or sha256_file(template_path) != template["sha256"]:
                    raise WebContractError("admitted Nuclei template changed before execution")
                scanner.extend([flags["templates"], str(template_path)])
            scanner.extend(
                [
                    flags["jsonl"],
                    flags["output"],
                    str(result_path),
                    flags["rate-limit"],
                    str(config["rateLimit"]),
                    flags["bulk-size"],
                    str(config["bulkSize"]),
                    flags["concurrency"],
                    str(config["concurrency"]),
                    flags["retries"],
                    str(config["retries"]),
                    flags["max-redirects"],
                    str(config["maxRedirects"]),
                    flags["disable-redirects"],
                    flags["no-interactsh"],
                    flags["disable-update-check"],
                    flags["no-color"],
                ]
            )
            command = [str(launcher_path), *arguments, "--", *scanner]
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(private / "home"),
                "XDG_CONFIG_HOME": str(private / "xdg-config"),
                "XDG_CACHE_HOME": str(private / "xdg-cache"),
                "NO_COLOR": "1",
            }
            for path in (
                Path(environment["HOME"]),
                Path(environment["XDG_CONFIG_HOME"]),
                Path(environment["XDG_CACHE_HOME"]),
            ):
                path.mkdir(mode=0o700)
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=int(config["maxWallSeconds"]),
                    env=environment,
                )
            except subprocess.TimeoutExpired as error:
                raise WebContractError("Nuclei exceeded the approved wall-clock limit") from error
            if ReplayHandler.budget_exceeded:
                raise WebContractError("Nuclei exceeded the runtime loopback request budget")
            if completed.returncode != 0:
                raise WebContractError(
                    f"Nuclei failed under the contained replay (exit {completed.returncode})"
                )
            if len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
                raise WebContractError("Nuclei console output exceeds the bounded size")
            observations, raw_hash = sanitize_jsonl(result_path, int(config["maxJsonlBytes"]))
            match_ids = []
            for value in observations:
                encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                match_id = "nuclei-" + hashlib.sha256(encoded).hexdigest()[:24]
                value["matchId"] = match_id
                match_ids.append(match_id)
            record = {
                "schemaVersion": 1,
                "kind": "krineon-nuclei-observations",
                "profileId": plan["profileId"],
                "track": plan["track"],
                "returnCode": completed.returncode,
                "matchIds": match_ids,
                "observations": observations,
                "rawJsonlSha256": raw_hash,
                "stdoutSha256": hashlib.sha256(completed.stdout).hexdigest(),
                "stderrSha256": hashlib.sha256(completed.stderr).hexdigest(),
                "effectiveCommand": [
                    value.replace(str(private), "<EPHEMERAL_PRIVATE_DIR>")
                    for value in command
                ],
                "acceptedTemplateIds": [
                    value["id"] for value in plan["admission"]["acceptedTemplates"]
                ],
                "rejectedTemplateIds": [],
                "templateCommit": plan["admission"]["templateCommit"],
                "engineSha256": plan["engine"]["binarySha256"],
                "targetTrafficByNuclei": False,
                "brokerTargetRequestsCharged": len(fixture["routes"]),
                "loopbackReplayRequestsCharged": ReplayHandler.request_count,
                "loopbackReplayRequestLimit": ReplayHandler.maximum_requests,
                "credentialsVisibleToNuclei": False,
                "ambientHomeUsed": False,
                "semanticReplayRequired": True,
                "scannerSeverityIsKrineonSeverity": False,
                "negativeScanEliminatesMechanism": False,
            }
            atomic_json(output / "observation.json", record, mode=0o600)
            atomic_json(output / "effective-plan.json", plan, mode=0o600)
            return record
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        ReplayHandler.routes = {}
        ReplayHandler.request_count = 0
        ReplayHandler.maximum_requests = 0
        ReplayHandler.budget_exceeded = False


def verify_replay(matches: dict[str, Any], replay: dict[str, Any]) -> dict[str, Any]:
    if matches.get("kind") != "krineon-nuclei-observations":
        raise WebContractError("input is not a Nuclei observation record")
    if replay.get("schemaVersion") != 1 or replay.get("kind") != "krineon-nuclei-semantic-replay":
        raise WebContractError("input is not a Krineon semantic replay")
    match_ids = sorted(str(value) for value in matches.get("matchIds", []))
    results = replay.get("results")
    if not isinstance(results, list):
        raise WebContractError("semantic replay requires results")
    by_id = {str(value.get("matchId")): value for value in results if isinstance(value, dict)}
    if set(match_ids) != set(by_id):
        raise WebContractError("semantic replay does not cover every scanner match")
    confirmed = []
    for match_id in match_ids:
        item = by_id[match_id]
        if item.get("runner") not in {"krineon-http-broker", "krineon-chrome-cdp-v1"}:
            raise WebContractError("scanner matches require Krineon HTTP or browser replay")
        if item.get("independentIdentity") is not True or item.get("oracleOutcome") not in {
            "confirmed-disagreement",
            "invariant-preserved",
        }:
            raise WebContractError("semantic replay lacks an independent application oracle")
        if item["oracleOutcome"] == "confirmed-disagreement":
            confirmed.append(match_id)
    return {
        "schemaVersion": 1,
        "kind": "krineon-nuclei-replay-verdict",
        "scannerMatchCount": len(match_ids),
        "confirmedInvariantBreakMatchIds": confirmed,
        "matchesPromotedDirectly": False,
        "negativeScanEliminatesMechanism": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("probe")
    probe.add_argument("binary")
    probe.add_argument("--output", required=True, type=Path)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("profile", type=Path)
    prepare.add_argument("manifest", type=Path)
    prepare.add_argument("probe", type=Path)
    prepare.add_argument("--root", type=Path, default=Path.cwd())
    prepare.add_argument("--output", required=True, type=Path)
    run = sub.add_parser("run-replay")
    run.add_argument("plan", type=Path)
    run.add_argument("fixture", type=Path)
    run.add_argument("--root", type=Path, default=Path.cwd())
    run.add_argument("--evidence-root", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    verify = sub.add_parser("verify-replay")
    verify.add_argument("matches", type=Path)
    verify.add_argument("replay", type=Path)
    verify.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            result = probe_engine(args.binary)
        elif args.command == "prepare":
            result = prepare_run(
                load_object(args.profile),
                load_object(args.manifest),
                load_object(args.probe),
                root=args.root.expanduser().resolve(),
                manifest_path=args.manifest.expanduser().resolve(),
            )
        elif args.command == "run-replay":
            result = execute_replay(
                load_object(args.plan),
                load_object(args.fixture),
                root=args.root.expanduser().resolve(),
                evidence_root=args.evidence_root.expanduser().resolve(),
                output=args.output.expanduser().resolve(),
            )
        else:
            result = verify_replay(load_object(args.matches), load_object(args.replay))
        if args.command != "run-replay":
            atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"kind": result["kind"], "accepted": True}, indent=2))
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        WebContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
