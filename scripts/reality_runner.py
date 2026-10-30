#!/usr/bin/env python3
"""Execute a baseline/control/positive recipe and retain recomputable evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import signal
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from reality_evidence import (
    evaluate_assertion,
    parse_debugger_observation,
    sha256_bytes,
    sha256_file,
    trusted_debugger_binary,
)


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


def subject_binding(
    root: Path,
    recipe: dict[str, Any],
    target_paths: set[Path],
) -> tuple[Path, int]:
    value = recipe.get("subjectArtifact")
    subject = safe_relative(root, str(value or ""))
    if subject.resolve() not in target_paths:
        raise RuntimeError("subjectArtifact must name a declared target artifact")
    index = recipe.get("subjectArgvIndex")
    if not isinstance(index, int) or index < 0 or index > 32:
        raise RuntimeError("subjectArgvIndex must be an integer between 0 and 32")
    return subject.resolve(), index


def resolved_argument(root: Path, cwd: Path, value: str) -> Path | None:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve()
    if "/" in value or "\\" in value:
        path = (cwd / candidate).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            return None
        return path
    return None


def controlled_pc_assertion(case: dict[str, Any]) -> bool:
    assertions = case.get("assertions")
    return isinstance(assertions, list) and any(
        isinstance(value, dict) and value.get("kind") == "controlled-pc"
        for value in assertions
    )


def execute_with_debugger(
    *,
    root: Path,
    case: dict[str, Any],
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
    stdin: bytes,
) -> tuple[int | None, int, int, bool, bytes, dict[str, Any] | None, dict[str, Any]]:
    """Run a chosen-PC case under a system-managed GDB or LLDB observer."""

    if stdin:
        raise RuntimeError("controlled-pc debugger cases require an empty stdinTemplate")
    assertions = case.get("assertions", [])
    if any(value.get("kind") != "controlled-pc" for value in assertions):
        raise RuntimeError("controlled-pc debugger cases may contain only controlled-pc assertions")
    observer = case.get("observer")
    if not isinstance(observer, dict) or observer.get("kind") != "debugger":
        raise RuntimeError("controlled-pc requires observer.kind=debugger")
    kind = str(observer.get("tool") or "")
    located = shutil.which(kind)
    if located is None:
        raise RuntimeError(f"required system debugger is unavailable: {kind}")
    debugger = Path(located).resolve()
    trusted, reason = trusted_debugger_binary(root, debugger, kind)
    if not trusted:
        raise RuntimeError("untrusted controlled-pc observer: " + reason)
    version = subprocess.run(
        [str(debugger), "--version"],
        check=False,
        capture_output=True,
        timeout=10,
    )
    version_bytes = version.stdout + version.stderr
    if version.returncode != 0:
        raise RuntimeError("system debugger version probe failed")
    if kind == "gdb":
        observer_command = [
            str(debugger),
            "-q",
            "-nx",
            "-batch",
            "-ex",
            "set pagination off",
            "-ex",
            "run",
            "-ex",
            "info inferiors",
            "-ex",
            "info registers",
            "--args",
            *command,
        ]
    else:
        observer_command = [
            str(debugger),
            "--batch",
            "-o",
            "run",
            "-o",
            "process status",
            "-o",
            "register read pc rip eip",
            "--",
            *command,
        ]
    process = subprocess.Popen(
        observer_command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    timed_out = False
    try:
        debugger_stdout, debugger_stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        debugger_stdout, debugger_stderr = process.communicate()
    raw = debugger_stdout + b"\n--- STDERR ---\n" + debugger_stderr
    observation = parse_debugger_observation(raw, kind)
    target_pid = int(observation.get("targetPid")) if observation else -1
    retained = {
        "source": "trusted-debugger",
        "kind": kind,
        "path": str(debugger),
        "sha256": sha256_file(debugger),
        "versionSha256": sha256_bytes(version_bytes),
        "observerPid": process.pid,
        "command": observer_command,
        "rawBytes": raw,
    }
    return process.returncode, target_pid, process.pid, timed_out, raw, observation, retained


def execute_case(
    *,
    root: Path,
    output_dir: Path,
    case: dict[str, Any],
    challenge: str,
    repetition: int,
    timeout: float,
    target_paths: set[Path],
    subject_path: Path,
    subject_argv_index: int,
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
    if subject_argv_index >= len(command):
        raise RuntimeError(
            f"case {name} command has no subject argument at index {subject_argv_index}"
        )
    invoked_subject = resolved_argument(
        root, cwd, command[subject_argv_index]
    )
    if invoked_subject != subject_path:
        raise RuntimeError(
            f"case {name} command does not invoke subjectArtifact at argv index "
            f"{subject_argv_index}"
        )
    stdin_template = str(case.get("stdinTemplate") or "")
    stdin = replace_tokens(stdin_template, challenge, name, repetition).encode()
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
        "KRINEON_CHALLENGE_HEX": challenge,
        "KRINEON_CASE": name,
        "KRINEON_REPETITION": str(repetition),
    }
    started = time.time_ns()
    observer_record: dict[str, Any] | None = None
    trusted_observer: dict[str, Any] | None = None
    if controlled_pc_assertion(case):
        (
            return_code,
            target_pid,
            observer_pid,
            timed_out,
            observer_raw,
            trusted_observer,
            observer_record,
        ) = execute_with_debugger(
            root=root,
            case=case,
            command=command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            stdin=stdin,
        )
        stdout = b""
        stderr = b""
    else:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
        return_code = process.returncode
        target_pid = process.pid
        observer_pid = process.pid
    finished = time.time_ns()
    run_dir = output_dir / name / f"{repetition:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "stdout.bin"
    stderr_path = run_dir / "stderr.bin"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    retained_observer: dict[str, Any] | None = None
    if observer_record is not None:
        observer_path = run_dir / "debugger.bin"
        observer_path.write_bytes(observer_raw)
        retained_observer = {
            key: value for key, value in observer_record.items() if key != "rawBytes"
        }
        retained_observer.update(
            {
                "rawPath": observer_path.relative_to(root).as_posix(),
                "rawSha256": sha256_bytes(observer_raw),
            }
        )
    retained_assertions: list[dict[str, Any]] = []
    assertions = case.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise RuntimeError(f"case {name} requires assertions")
    for assertion in assertions:
        if not isinstance(assertion, dict) or not assertion.get("id"):
            raise RuntimeError(f"case {name} contains an invalid assertion")
        matched, observed = evaluate_assertion(
            assertion,
            return_code=return_code,
            process_id=target_pid,
            challenge_hex=challenge,
            stdout=stdout,
            stderr=stderr,
            trusted_observer=trusted_observer,
        )
        retained_assertions.append({
            "id": str(assertion["id"]),
            "kind": str(assertion.get("kind") or ""),
            "matched": matched,
            "observed": observed,
        })
    return {
        "pid": target_pid,
        "observerPid": observer_pid,
        "freshProcess": True,
        "startedNs": started,
        "finishedNs": finished,
        "command": command,
        "executionBinding": {
            "subjectArtifact": subject_path.relative_to(root).as_posix(),
            "subjectArgvIndex": subject_argv_index,
            "launcher": str(resolved_executable),
            "launcherSha256": sha256_file(resolved_executable),
        },
        "cwd": cwd.relative_to(root).as_posix(),
        "challengeHex": challenge,
        "stdinSha256": sha256_bytes(stdin),
        "returnCode": return_code,
        "timedOut": timed_out,
        "raw": {
            "stdoutPath": stdout_path.relative_to(root).as_posix(),
            "stdoutSha256": sha256_bytes(stdout),
            "stderrPath": stderr_path.relative_to(root).as_posix(),
            "stderrSha256": sha256_bytes(stderr),
        },
        "observer": retained_observer,
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
    subject_path, subject_argv_index = subject_binding(root, recipe, target_paths)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:10]
    output_dir = root / "evidence" / "machine-runs" / args.finding_id / run_id
    has_controlled_pc = any(controlled_pc_assertion(case) for case in cases)
    if has_controlled_pc and args.challenge_bytes != 8:
        raise RuntimeError("controlled-pc requires --challenge-bytes 8")
    challenges = [
        ("0000" + secrets.token_hex(6))
        if has_controlled_pc
        else secrets.token_hex(args.challenge_bytes)
        for _ in range(args.repetitions)
    ]
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
                subject_path=subject_path,
                subject_argv_index=subject_argv_index,
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
        "subjectArtifact": {
            "path": subject_path.relative_to(root).as_posix(),
            "sha256": sha256_file(subject_path),
            "argvIndex": subject_argv_index,
        },
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
