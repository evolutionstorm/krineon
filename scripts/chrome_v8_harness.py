#!/usr/bin/env python3
"""Register Chrome/V8 builds and run bounded d8 testcase matrices.

This adapter never downloads, builds, or patches a browser. It hashes explicit
local artifacts and delegates execution to dynamic_harness.py, which requires
an authorized source or local-lab campaign and applies bounded resource limits.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from chromium_replay import (
    ChromiumReplayError,
    OwnedPageServer,
    copy_owned_site,
    run_browser_case,
    safe_entry,
    validate_browser_flags,
)
from platform_support import host_platform, normalize_architecture


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_HARNESS = PROJECT_ROOT / "scripts" / "dynamic_harness.py"
SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
BUILD_ROLES = ("release", "asan", "debug", "jitless", "sandboxed-chrome", "other")
BUILD_KINDS = ("d8", "chrome")


class ChromeV8Error(Exception):
    """User-facing Chrome/V8 adapter error."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ChromeV8Error(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ChromeV8Error(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ChromeV8Error(f"expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def campaign_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def require_profile(root: Path) -> dict[str, Any]:
    campaign = read_json(root / "campaign.json")
    if campaign.get("profile") != "chrome-v8":
        raise ChromeV8Error("campaign is not initialized with --profile chrome-v8")
    return campaign


def builds_path(root: Path) -> Path:
    return root / "chrome-v8" / "builds.json"


def require_builds(root: Path) -> dict[str, Any]:
    require_profile(root)
    return read_json(builds_path(root))


def resolve_file(value: str, *, label: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise ChromeV8Error(f"{label} is not a file: {path}")
    return path


def artifact(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def inspect_binary_architectures(binary: Path) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    architectures: set[str] = set()
    lipo = shutil.which("lipo")
    if platform.system() == "Darwin" and lipo:
        completed = subprocess.run(
            [lipo, "-archs", str(binary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (completed.stdout or completed.stderr).strip()
        observations.append(
            {"tool": lipo, "returnCode": completed.returncode, "output": output[:1000]}
        )
        if completed.returncode == 0:
            architectures.update(
                normalize_architecture(value) for value in output.split()
            )
    file_tool = shutil.which("file")
    if file_tool:
        completed = subprocess.run(
            [file_tool, "-b", str(binary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (completed.stdout or completed.stderr).strip()
        observations.append(
            {
                "tool": file_tool,
                "returnCode": completed.returncode,
                "output": output[:1000],
            }
        )
        if completed.returncode == 0:
            lowered = output.lower()
            if "arm64" in lowered or "aarch64" in lowered:
                architectures.add("arm64")
            if "x86_64" in lowered or "x86-64" in lowered:
                architectures.add("x86_64")
    return {
        "architectures": sorted(value for value in architectures if value != "unknown"),
        "observations": observations,
    }


def build_by_name(database: dict[str, Any], name: str) -> dict[str, Any]:
    for build in database.get("builds", []):
        if build.get("name") == name:
            return build
    raise ChromeV8Error(f"unknown registered build: {name}")


def verify_build(build: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if not str(build.get("revision") or "").strip():
        problems.append("missing revision")
    records = build.get("artifacts")
    if not isinstance(records, list) or not records:
        problems.append("no artifacts")
        return problems
    for record in records:
        path = Path(str(record.get("path") or ""))
        if not path.is_file():
            problems.append(f"missing artifact: {path}")
            continue
        actual = sha256_file(path)
        if actual != record.get("sha256"):
            problems.append(f"artifact digest changed: {path}")
    binary = Path(str(build.get("binary") or ""))
    if binary.is_file():
        detected = inspect_binary_architectures(binary).get("architectures", [])
        expected = normalize_architecture(str(build.get("architecture") or ""))
        if detected and expected not in detected:
            problems.append(
                f"binary architecture mismatch: expected {expected}, detected {', '.join(detected)}"
            )
    return problems


def cmd_register_build(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    database = require_builds(root)
    if not SAFE_NAME.fullmatch(args.name):
        raise ChromeV8Error("build name must use letters, digits, dot, underscore, or dash")
    existing = [item for item in database.get("builds", []) if item.get("name") == args.name]
    if existing and not args.replace:
        raise ChromeV8Error(f"build already registered: {args.name}; use --replace explicitly")

    binary = resolve_file(args.binary, label="binary")
    requested_architecture = normalize_architecture(
        platform.machine() if args.architecture == "auto" else args.architecture
    )
    if not re.fullmatch(r"[a-z0-9_]+", requested_architecture):
        raise ChromeV8Error("architecture must use letters, digits, or underscore")
    architecture_evidence = inspect_binary_architectures(binary)
    detected_architectures = architecture_evidence["architectures"]
    if detected_architectures and requested_architecture not in detected_architectures:
        raise ChromeV8Error(
            "registered architecture does not match binary: "
            f"requested {requested_architecture}, detected {', '.join(detected_architectures)}"
        )
    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else binary.parent
    if not cwd.is_dir():
        raise ChromeV8Error(f"working directory is not a directory: {cwd}")
    artifacts: dict[str, dict[str, Any]] = {str(binary): artifact(binary)}
    for value in args.artifact or []:
        path = resolve_file(value, label="artifact")
        artifacts[str(path)] = artifact(path)
    gn_args = None
    if args.gn_args_file:
        path = resolve_file(args.gn_args_file, label="GN args file")
        gn_args = artifact(path)
        artifacts[str(path)] = gn_args

    checkout = ""
    if args.checkout:
        checkout_path = Path(args.checkout).expanduser().resolve()
        if not checkout_path.is_dir():
            raise ChromeV8Error(f"checkout is not a directory: {checkout_path}")
        checkout = str(checkout_path)

    record = {
        "name": args.name,
        "kind": args.kind,
        "role": args.role,
        "revision": args.revision,
        "architecture": requested_architecture,
        "architectureEvidence": architecture_evidence,
        "host": host_platform(),
        "binary": str(binary),
        "cwd": str(cwd),
        "checkout": checkout,
        "flags": args.flag or [],
        "gnArgs": gn_args,
        "artifacts": list(artifacts.values()),
        "registeredAt": utc_now(),
    }
    database["builds"] = [
        item for item in database.get("builds", []) if item.get("name") != args.name
    ]
    database["builds"].append(record)
    database["updatedAt"] = utc_now()
    write_json(builds_path(root), database)
    print(f"registered {args.kind} build {args.name} ({args.role})")
    print(f"binary sha256: {artifacts[str(binary)]['sha256']}")
    return 0


def audit_payload(root: Path, database: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    roles: set[str] = set()
    browser_ready = False
    for build in database.get("builds", []):
        problems = verify_build(build)
        if build.get("kind") == "d8":
            roles.add(str(build.get("role")))
        if build.get("kind") == "chrome" and build.get("role") == "sandboxed-chrome":
            browser_ready = not problems
        rows.append(
            {
                "name": build.get("name"),
                "kind": build.get("kind"),
                "role": build.get("role"),
                "revision": build.get("revision"),
                "architecture": build.get("architecture"),
                "detectedArchitectures": build.get("architectureEvidence", {}).get(
                    "architectures", []
                ),
                "problems": problems,
                "valid": not problems,
            }
        )
    required = set(database.get("requiredRoles", []))
    missing_roles = sorted(required.difference(roles))
    return {
        "schemaVersion": 1,
        "at": utc_now(),
        "profile": "chrome-v8",
        "builds": rows,
        "missingD8Roles": missing_roles,
        "browserPromotionReady": browser_ready,
        "passed": bool(rows)
        and not missing_roles
        and all(row["valid"] for row in rows),
        "campaign": str(root),
    }


def cmd_audit(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    database = require_builds(root)
    payload = audit_payload(root, database)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for row in payload["builds"]:
            status = "OK" if row["valid"] else "FAIL"
            print(f"{status:<4} {row['name']:<20} {row['kind']:<7} {row['role']}")
            for problem in row["problems"]:
                print(f"     - {problem}")
        if payload["missingD8Roles"]:
            print("missing d8 roles: " + ", ".join(payload["missingD8Roles"]))
        print(f"sandboxed Chrome registered: {payload['browserPromotionReady']}")
    return 0 if payload["passed"] else 1


def selected_d8_builds(database: dict[str, Any], names: list[str] | None) -> list[dict[str, Any]]:
    if names:
        selected = [build_by_name(database, name) for name in names]
    else:
        selected = [item for item in database.get("builds", []) if item.get("kind") == "d8"]
    if not selected:
        raise ChromeV8Error("no d8 builds selected")
    non_d8 = [str(item.get("name")) for item in selected if item.get("kind") != "d8"]
    if non_d8:
        raise ChromeV8Error("matrix supports d8 builds only: " + ", ".join(non_d8))
    return selected


def parse_run_id(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("run: "):
            return line.split(": ", 1)[1].strip()
    raise ChromeV8Error("dynamic harness did not return a run ID")


def run_build(
    root: Path, build: dict[str, Any], testcase: Path, args: argparse.Namespace
) -> dict[str, Any]:
    problems = verify_build(build)
    if problems:
        raise ChromeV8Error(f"registered build {build['name']} is stale: " + "; ".join(problems))
    command = [
        sys.executable,
        str(DYNAMIC_HARNESS),
        "run",
        str(root),
        "--input-file",
        str(testcase),
        "--name",
        f"v8-{build['name']}",
        "--input-mode",
        "file",
        "--cwd",
        str(build["cwd"]),
        "--timeout-ms",
        str(args.timeout_ms),
        "--memory-mb",
        str(args.memory_mb),
        "--max-output-bytes",
        str(args.max_output_bytes),
        "--max-input-bytes",
        str(args.max_input_bytes),
    ]
    for record in build["artifacts"]:
        command.extend(["--target-artifact", str(record["path"])])
    command.extend(["--", str(build["binary"]), *build.get("flags", []), "{input}"])
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise ChromeV8Error(
            f"dynamic replay failed for {build['name']}: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    run_id = parse_run_id(completed.stdout)
    result_path = root / "dynamic" / "runs" / run_id / "cases" / "00000000" / "result.json"
    result = read_json(result_path)
    return {
        "build": build["name"],
        "role": build["role"],
        "revision": build["revision"],
        "architecture": build.get("architecture"),
        "runId": run_id,
        "result": result_path.relative_to(root).as_posix(),
        "outcome": result.get("outcome"),
        "signal": result.get("signal"),
        "sanitizer": result.get("sanitizer"),
        "returnCode": result.get("returnCode"),
        "stdoutSha256": result.get("stdoutSha256"),
        "stderrSha256": result.get("stderrSha256"),
        "durationMs": result.get("durationMs"),
    }


def cmd_matrix(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    database = require_builds(root)
    testcase = resolve_file(args.testcase, label="testcase")
    if testcase.suffix.lower() not in (".js", ".mjs"):
        raise ChromeV8Error("d8 matrix testcases must use .js or .mjs")
    if testcase.stat().st_size > args.max_input_bytes:
        raise ChromeV8Error("testcase exceeds --max-input-bytes")
    builds = selected_d8_builds(database, args.build)
    matrix_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(5)
    matrix_dir = root / "chrome-v8" / "matrices" / matrix_id
    matrix_dir.mkdir(parents=True, exist_ok=False)
    retained_testcase = matrix_dir / "testcase.js"
    shutil.copy2(testcase, retained_testcase)
    rows: list[dict[str, Any]] = []
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "matrixId": matrix_id,
        "createdAt": utc_now(),
        "status": "running",
        "testcase": {
            "path": retained_testcase.relative_to(root).as_posix(),
            "sha256": sha256_file(retained_testcase),
            "size": retained_testcase.stat().st_size,
        },
        "limits": {
            "timeoutMs": args.timeout_ms,
            "memoryMb": args.memory_mb,
            "maxOutputBytes": args.max_output_bytes,
            "maxInputBytes": args.max_input_bytes,
        },
        "builds": [item["name"] for item in builds],
        "results": rows,
    }
    write_json(matrix_dir / "matrix.json", record)
    try:
        for build in builds:
            rows.append(run_build(root, build, retained_testcase, args))
            record["results"] = rows
            write_json(matrix_dir / "matrix.json", record)
    except Exception as exc:
        record["status"] = "failed"
        record["endedAt"] = utc_now()
        record["error"] = str(exc)
        write_json(matrix_dir / "matrix.json", record)
        raise

    outcomes = {str(row["outcome"]) for row in rows}
    successful_hashes = {
        str(row["stdoutSha256"]) for row in rows if row["outcome"] == "ok"
    }
    crashes = [row["build"] for row in rows if row["outcome"] == "crash"]
    record.update(
        {
            "status": "completed",
            "endedAt": utc_now(),
            "summary": {
                "crashBuilds": crashes,
                "outcomeDisagreement": len(outcomes) > 1,
                "stdoutDisagreementAmongSuccessfulBuilds": len(successful_hashes) > 1,
                "requiresTriage": bool(crashes)
                or len(outcomes) > 1
                or len(successful_hashes) > 1,
                "securityConclusion": "lead only; minimize and independently replay before promotion",
            },
        }
    )
    write_json(matrix_dir / "matrix.json", record)
    print(f"matrix: {matrix_id}")
    print(f"results: {len(rows)} builds; crashes: {len(crashes)}")
    print(f"report: {(matrix_dir / 'matrix.json').relative_to(root)}")
    return 0


def parse_json_argument(value: str, *, label: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ChromeV8Error(f"{label} must be valid JSON: {exc}") from exc


def link_browser_replay(
    root: Path,
    finding_id: str,
    replay_id: str,
    *,
    reviewed_by: str,
    review_note: str,
) -> None:
    if not SAFE_NAME.fullmatch(finding_id):
        raise ChromeV8Error("finding ID contains unsupported characters")
    if not reviewed_by.strip() or not review_note.strip():
        raise ChromeV8Error(
            "--finding-id requires non-empty --reviewed-by and --review-note"
        )
    finding_path = root / "findings" / f"{finding_id}.json"
    finding = read_json(finding_path)
    linked = finding.get("browserReplay")
    if not isinstance(linked, dict):
        linked = {}
    replay_ids = linked.get("replayIds")
    if not isinstance(replay_ids, list):
        replay_ids = []
    linked.update(
        {
            "required": True,
            "replayIds": sorted(set(str(value) for value in replay_ids) | {replay_id}),
            "reviewed": True,
            "reviewedBy": reviewed_by.strip(),
            "reviewNotes": review_note.strip(),
        }
    )
    finding["browserReplay"] = linked
    write_json(finding_path, finding)


def cmd_browser_replay(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    database = require_builds(root)
    if args.finding_id and (not args.reviewed_by or not args.review_note):
        raise ChromeV8Error(
            "--finding-id requires non-empty --reviewed-by and --review-note"
        )
    if not args.finding_id and (args.reviewed_by or args.review_note):
        raise ChromeV8Error("review metadata requires --finding-id")
    build = build_by_name(database, args.build)
    if build.get("kind") != "chrome" or build.get("role") != "sandboxed-chrome":
        raise ChromeV8Error(
            "browser replay requires a registered chrome build with role sandboxed-chrome"
        )
    problems = verify_build(build)
    if problems:
        raise ChromeV8Error(f"registered build {build['name']} is stale: " + "; ".join(problems))
    flags = [str(value) for value in build.get("flags", [])] + list(args.chrome_flag or [])
    try:
        validate_browser_flags(flags)
    except ChromiumReplayError as exc:
        raise ChromeV8Error(str(exc)) from exc

    source = Path(args.page_dir).expanduser().resolve()
    try:
        positive_entry = safe_entry(args.entry)
        control_entry = safe_entry(args.control_entry) if args.control_entry else None
    except ChromiumReplayError as exc:
        raise ChromeV8Error(str(exc)) from exc
    positive_expected = parse_json_argument(args.expect_json, label="--expect-json")
    control_expected = parse_json_argument(
        args.control_expect_json, label="--control-expect-json"
    )
    replay_id = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        + "-"
        + secrets.token_hex(5)
    )
    replay_dir = root / "chrome-v8" / "browser-replays" / replay_id
    site_dir = replay_dir / "site"
    replay_dir.mkdir(parents=True, exist_ok=False)
    try:
        site_manifest = copy_owned_site(
            source,
            site_dir,
            max_files=args.max_site_files,
            max_total_bytes=args.max_site_bytes,
            max_file_bytes=args.max_site_file_bytes,
        )
    except ChromiumReplayError as exc:
        raise ChromeV8Error(str(exc)) from exc
    for entry in [positive_entry, control_entry]:
        if entry and not (site_dir / entry).is_file():
            raise ChromeV8Error(f"entry is not present in retained owned page tree: {entry}")

    record: dict[str, Any] = {
        "schemaVersion": 1,
        "replayId": replay_id,
        "createdAt": utc_now(),
        "status": "running",
        "driver": "direct-cdp",
        "ownedLocalOrigin": True,
        "networkPolicy": (
            "loopback owned origin; off-origin HTTP requests blocked by CDP Fetch, "
            "dead loopback proxy, and resolver rules"
        ),
        "build": {
            "name": build["name"],
            "kind": build["kind"],
            "role": build["role"],
            "revision": build["revision"],
            "architecture": build.get("architecture"),
            "architectureEvidence": build.get("architectureEvidence"),
            "binary": artifact(Path(build["binary"])),
            "registeredFlags": list(build.get("flags", [])),
            "replayFlags": list(args.chrome_flag or []),
        },
        "site": {
            "retainedPath": "site",
            "files": site_manifest,
            "sourceFileCount": len(site_manifest),
            "sourceTotalBytes": sum(int(item["size"]) for item in site_manifest),
        },
        "cases": {},
        "limits": {
            "timeoutSeconds": args.timeout_seconds,
            "maxOutputBytes": args.max_output_bytes,
            "maxCdpEvents": args.max_cdp_events,
            "maxCdpMessageBytes": args.max_cdp_message_bytes,
            "maxSiteFiles": args.max_site_files,
            "maxSiteBytes": args.max_site_bytes,
            "maxSiteFileBytes": args.max_site_file_bytes,
        },
    }
    write_json(replay_dir / "replay.json", record)
    try:
        with OwnedPageServer(site_dir) as server:
            record["origin"] = server.origin
            record["cases"]["positive"] = run_browser_case(
                binary=Path(build["binary"]),
                flags=flags,
                server=server,
                entry=positive_entry,
                expression=args.success_expression,
                expected=positive_expected,
                output_dir=replay_dir / "positive",
                timeout_seconds=args.timeout_seconds,
                max_output_bytes=args.max_output_bytes,
                max_cdp_message_bytes=args.max_cdp_message_bytes,
                event_limit=args.max_cdp_events,
                headless=not args.headed,
            )
            write_json(replay_dir / "replay.json", record)
            if control_entry:
                record["cases"]["control"] = run_browser_case(
                    binary=Path(build["binary"]),
                    flags=flags,
                    server=server,
                    entry=control_entry,
                    expression=args.control_expression or args.success_expression,
                    expected=control_expected,
                    output_dir=replay_dir / "control",
                    timeout_seconds=args.timeout_seconds,
                    max_output_bytes=args.max_output_bytes,
                    max_cdp_message_bytes=args.max_cdp_message_bytes,
                    event_limit=args.max_cdp_events,
                    headless=not args.headed,
                )
                write_json(replay_dir / "replay.json", record)
            record["serverRequests"] = server.server.requests
            record["serverRequestsDropped"] = server.server.requests_dropped
    except (ChromiumReplayError, OSError) as exc:
        record["status"] = "failed"
        record["error"] = str(exc)
        record["endedAt"] = utc_now()
        write_json(replay_dir / "replay.json", record)
        raise ChromeV8Error(str(exc)) from exc

    positive = record["cases"]["positive"]
    control = record["cases"].get("control")
    cases = list(record["cases"].values())
    sandbox_verified = bool(cases) and all(
        case.get("sandbox", {}).get("verified") is True for case in cases
    )
    external_attempts = sorted(
        {
            url
            for case in cases
            for url in case.get("blockedExternalRequests", [])
            if isinstance(url, str)
        }
    )
    completed = all(case.get("status") == "completed" for case in cases)
    positive_matched = positive.get("expressionMatched") is True
    control_matched = control is not None and control.get("expressionMatched") is True
    no_crash = all(case.get("targetCrashed") is False for case in cases)
    record.update(
        {
            "status": "completed" if completed else "failed",
            "endedAt": utc_now(),
            "summary": {
                "positiveMatched": positive_matched,
                "controlPresent": control is not None,
                "controlMatched": control_matched,
                "sandboxVerified": sandbox_verified,
                "externalRequestAttempts": external_attempts,
                "targetStayedAlive": no_crash,
                "webReachabilityConfirmed": completed and positive_matched,
                "promotionReady": (
                    completed
                    and positive_matched
                    and control_matched
                    and sandbox_verified
                    and not external_attempts
                    and no_crash
                ),
                "securityConclusion": (
                    "owned-page reachability evidence only; renderer impact is not a sandbox escape"
                ),
            },
        }
    )
    write_json(replay_dir / "replay.json", record)
    if args.finding_id:
        link_browser_replay(
            root,
            args.finding_id,
            replay_id,
            reviewed_by=args.reviewed_by or "",
            review_note=args.review_note or "",
        )
    print(f"browser replay: {replay_id}")
    print(f"driver: direct-cdp; cases: {len(cases)}")
    print(f"web reachable: {record['summary']['webReachabilityConfirmed']}")
    print(f"promotion ready: {record['summary']['promotionReady']}")
    print(f"report: {(replay_dir / 'replay.json').relative_to(root)}")
    return 0 if completed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register-build", help="pin a local d8 or Chrome build")
    register.add_argument("campaign_dir")
    register.add_argument("name")
    register.add_argument("--kind", choices=BUILD_KINDS, required=True)
    register.add_argument("--role", choices=BUILD_ROLES, required=True)
    register.add_argument("--binary", required=True)
    register.add_argument("--revision", required=True)
    register.add_argument(
        "--architecture",
        default="auto",
        help="target architecture; auto records the normalized host architecture",
    )
    register.add_argument("--checkout")
    register.add_argument("--cwd")
    register.add_argument("--gn-args-file")
    register.add_argument("--artifact", action="append")
    register.add_argument("--flag", action="append")
    register.add_argument("--replace", action="store_true")
    register.set_defaults(func=cmd_register_build)

    audit = sub.add_parser("audit", help="verify registered build hashes and role coverage")
    audit.add_argument("campaign_dir")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    matrix = sub.add_parser("matrix", help="run one JavaScript testcase across registered d8 builds")
    matrix.add_argument("campaign_dir")
    matrix.add_argument("--testcase", required=True)
    matrix.add_argument("--build", action="append", help="registered d8 build; repeatable")
    matrix.add_argument("--timeout-ms", type=int, default=5000)
    matrix.add_argument(
        "--memory-mb",
        type=int,
        default=0,
        help="address-space limit; zero is recommended for ASan shadow memory",
    )
    matrix.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)
    matrix.add_argument("--max-input-bytes", type=int, default=4 * 1024 * 1024)
    matrix.set_defaults(func=cmd_matrix)

    browser = sub.add_parser(
        "browser-replay",
        help="replay a retained owned page in registered sandboxed Chromium over CDP",
    )
    browser.add_argument("campaign_dir")
    browser.add_argument("--build", required=True, help="registered sandboxed-chrome build")
    browser.add_argument("--page-dir", required=True, help="owned local page tree")
    browser.add_argument("--entry", default="index.html")
    browser.add_argument("--control-entry")
    browser.add_argument(
        "--success-expression",
        default="globalThis.__KRINEON_REPLAY_RESULT__",
        help="side-effect-free expression evaluated after the positive page loads",
    )
    browser.add_argument("--expect-json", default="true")
    browser.add_argument("--control-expression")
    browser.add_argument("--control-expect-json", default="false")
    browser.add_argument("--chrome-flag", action="append")
    browser.add_argument("--timeout-seconds", type=float, default=15.0)
    browser.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)
    browser.add_argument("--max-cdp-events", type=int, default=10000)
    browser.add_argument("--max-cdp-message-bytes", type=int, default=8 * 1024 * 1024)
    browser.add_argument("--max-site-files", type=int, default=1000)
    browser.add_argument("--max-site-bytes", type=int, default=64 * 1024 * 1024)
    browser.add_argument("--max-site-file-bytes", type=int, default=32 * 1024 * 1024)
    browser.add_argument("--headed", action="store_true")
    browser.add_argument("--finding-id")
    browser.add_argument("--reviewed-by")
    browser.add_argument("--review-note")
    browser.set_defaults(func=cmd_browser_replay)
    return parser


def validate_positive(args: argparse.Namespace) -> None:
    for name in (
        "timeout_ms",
        "timeout_seconds",
        "max_output_bytes",
        "max_input_bytes",
        "max_cdp_events",
        "max_cdp_message_bytes",
        "max_site_files",
        "max_site_bytes",
        "max_site_file_bytes",
    ):
        if hasattr(args, name) and getattr(args, name) < 1:
            raise ChromeV8Error(f"--{name.replace('_', '-')} must be positive")
    if hasattr(args, "memory_mb") and args.memory_mb < 0:
        raise ChromeV8Error("--memory-mb must be nonnegative")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        validate_positive(args)
        return int(args.func(args))
    except (ChromeV8Error, ChromiumReplayError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
