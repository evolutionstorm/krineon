#!/usr/bin/env python3
"""Execute a baseline/control/positive recipe and retain recomputable evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from reality_evidence import evaluate_assertion, sha256_bytes, sha256_file


SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,63}")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def campaign_root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    campaign = root / "campaign.json"
    if not campaign.is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    record = json.loads(campaign.read_text(encoding="utf-8"))
    authorization = record.get("authorization") if isinstance(record, dict) else None
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise RuntimeError("reality execution requires confirmed campaign authorization")
    return root


def safe_relative(root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"path must be campaign-relative: {value}")
    path = (root / relative).resolve()
    path.relative_to(root)
    return path


def replace_tokens(value: str, challenge: str, case: str, repetition: int) -> str:
    return (
        value.replace("{challengeHex}", challenge)
        .replace("{case}", case)
        .replace("{repetition}", str(repetition))
    )


def artifact_manifest(root: Path, recipe: dict[str, Any]) -> list[dict[str, Any]]:
    values = recipe.get("targetArtifacts")
    if not isinstance(values, list) or not values:
        raise RuntimeError("recipe requires targetArtifacts")
    result: list[dict[str, Any]] = []
    for value in values:
        path = safe_relative(root, str(value))
        if not path.is_file():
            raise RuntimeError(f"target artifact is absent: {value}")
        result.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        })
    return result


def execute_case(
    *,
    root: Path,
    output_dir: Path,
    case: dict[str, Any],
    challenge: str,
    repetition: int,
    timeout: float,
    target_paths: set[Path],
) -> dict[str, Any]:
    name = str(case["name"])
    command_value = case.get("command")
    if not isinstance(command_value, list) or not command_value or not all(
        isinstance(item, str) and item for item in command_value
    ):
        raise RuntimeError(f"case {name} requires an explicit command argv")
    command = [replace_tokens(item, challenge, name, repetition) for item in command_value]
    executable = Path(command[0])
    if executable.is_absolute():
        resolved_executable = executable.resolve()
    elif "/" in command[0]:
        resolved_executable = safe_relative(root, command[0])
    else:
        located = shutil.which(command[0])
        if located is None:
            raise RuntimeError(f"case {name} executable is unavailable: {command[0]}")
        resolved_executable = Path(located).resolve()
    command[0] = str(resolved_executable)
    cwd = safe_relative(root, str(case.get("cwd") or "."))
    if not cwd.is_dir():
        raise RuntimeError(f"case {name} working directory is absent")
    invoked_targets: set[Path] = set()
    for argument in command:
        candidate = Path(argument)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        elif "/" in argument or "\\" in argument:
            resolved = (cwd / candidate).resolve()
        else:
            continue
        if resolved in target_paths:
            invoked_targets.add(resolved)
    if not invoked_targets:
        raise RuntimeError(
            f"case {name} command does not invoke a declared target artifact"
        )
    stdin_template = str(case.get("stdinTemplate") or "")
    stdin = replace_tokens(stdin_template, challenge, name, repetition).encode()
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "KRINEON_CHALLENGE_HEX": challenge,
        "KRINEON_CASE": name,
        "KRINEON_REPETITION": str(repetition),
    }
    started = time.time_ns()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate()
    finished = time.time_ns()
    run_dir = output_dir / name / f"{repetition:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "stdout.bin"
    stderr_path = run_dir / "stderr.bin"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    retained_assertions: list[dict[str, Any]] = []
    assertions = case.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise RuntimeError(f"case {name} requires assertions")
    for assertion in assertions:
        if not isinstance(assertion, dict) or not assertion.get("id"):
            raise RuntimeError(f"case {name} contains an invalid assertion")
        matched, observed = evaluate_assertion(
            assertion,
            return_code=process.returncode,
            process_id=process.pid,
            challenge_hex=challenge,
            stdout=stdout,
            stderr=stderr,
        )
        retained_assertions.append({
            "id": str(assertion["id"]),
            "kind": str(assertion.get("kind") or ""),
            "matched": matched,
            "observed": observed,
        })
    return {
        "pid": process.pid,
        "freshProcess": True,
        "startedNs": started,
        "finishedNs": finished,
        "command": command,
        "cwd": cwd.relative_to(root).as_posix(),
        "challengeHex": challenge,
        "stdinSha256": sha256_bytes(stdin),
        "returnCode": process.returncode,
        "timedOut": timed_out,
        "raw": {
            "stdoutPath": stdout_path.relative_to(root).as_posix(),
            "stdoutSha256": sha256_bytes(stdout),
            "stderrPath": stderr_path.relative_to(root).as_posix(),
            "stderrSha256": sha256_bytes(stderr),
        },
        "assertions": retained_assertions,
        "passed": not timed_out and all(item["matched"] for item in retained_assertions),
    }


def run(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    if not SAFE_NAME.fullmatch(args.finding_id):
        raise RuntimeError("finding ID is invalid")
    if not SAFE_NAME.fullmatch(args.worker_id):
        raise RuntimeError("worker ID is invalid")
    recipe_path = safe_relative(root, args.recipe)
    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    if not isinstance(recipe, dict) or recipe.get("schemaVersion") != 1:
        raise RuntimeError("recipe must be a schemaVersion 1 JSON object")
    if recipe.get("findingId") != args.finding_id:
        raise RuntimeError("recipe findingId does not match")
    cases = recipe.get("cases")
    if not isinstance(cases, list) or {str(item.get("name")) for item in cases if isinstance(item, dict)} != {
        "baseline", "negative", "positive"
    }:
        raise RuntimeError("recipe requires exactly baseline, negative, and positive cases")
    artifacts = artifact_manifest(root, recipe)
    target_paths = {
        safe_relative(root, str(artifact["path"])).resolve() for artifact in artifacts
    }
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:10]
    output_dir = root / "evidence" / "machine-runs" / args.finding_id / run_id
    challenges = [secrets.token_hex(args.challenge_bytes) for _ in range(args.repetitions)]
    retained_cases: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        name = str(case["name"])
        case_repetitions = int(case.get("repetitions", args.repetitions))
        if case_repetitions != args.repetitions:
            raise RuntimeError("all cases must use the same repetition count")
        retained_cases[name] = [
            execute_case(
                root=root,
                output_dir=output_dir,
                case=case,
                challenge=challenges[index],
                repetition=index,
                timeout=args.timeout,
                target_paths=target_paths,
            )
            for index in range(args.repetitions)
        ]
    pids = [item["pid"] for runs in retained_cases.values() for item in runs]
    passed = len(pids) == len(set(pids)) and all(
        item["passed"] for runs in retained_cases.values() for item in runs
    )
    attestation = {
        "schemaVersion": 1,
        "producer": "krineon-reality-runner",
        "runId": run_id,
        "findingId": args.finding_id,
        "workerId": args.worker_id,
        "role": args.role,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "status": "passed" if passed else "failed",
        "recipe": {
            "path": recipe_path.relative_to(root).as_posix(),
            "sha256": sha256_file(recipe_path),
        },
        "targetArtifacts": artifacts,
        "challengeSha256s": [sha256_bytes(bytes.fromhex(value)) for value in challenges],
        "cases": retained_cases,
    }
    attestation_path = output_dir / "attestation.json"
    write_json(attestation_path, attestation)
    print(json.dumps({
        "passed": passed,
        "runId": run_id,
        "attestation": attestation_path.relative_to(root).as_posix(),
        "sha256": sha256_file(attestation_path),
    }, indent=2))
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("campaign_dir")
    value.add_argument("finding_id")
    value.add_argument("--recipe", required=True)
    value.add_argument("--worker-id", required=True)
    value.add_argument(
        "--role", choices=("originator", "reviewer", "coordinator"), required=True
    )
    value.add_argument("--repetitions", type=int, default=1)
    value.add_argument("--challenge-bytes", type=int, default=16)
    value.add_argument("--timeout", type=float, default=10.0)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.repetitions < 1 or args.repetitions > 100:
        raise SystemExit("--repetitions must be between 1 and 100")
    if args.challenge_bytes < 8 or args.challenge_bytes > 64:
        raise SystemExit("--challenge-bytes must be between 8 and 64")
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
