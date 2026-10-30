#!/usr/bin/env python3
"""Run bounded local dynamic tests, fuzz targets, and preserve crash evidence.

The runner executes explicit argument vectors without a shell. Resource limits
reduce accidental resource exhaustion; they are not a security sandbox. Use a
disposable VM or container for targets that may execute unsafe payloads.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
import random
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from crash_triage import triage_campaign, triage_one
from platform_support import host_platform, resource_limit_plan


ENGINE_VERSION = "2"
INPUT_PLACEHOLDER = "{input}"
MAX_COVERAGE_EDGES = 65536
SAFE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SANITIZER_RE = re.compile(
    r"(?m)(?:^ERROR: (?:Address|Memory|Thread|UndefinedBehavior)Sanitizer[^\n]*"
    r"|^SUMMARY: (?:Address|Memory|Thread|UndefinedBehavior)Sanitizer[^\n]*"
    r"|^(?:Address|Memory|Thread|UndefinedBehavior)Sanitizer:DEADLYSIGNAL[^\n]*"
    r"|^(?:\S+:\d+(?::\d+)?: )?runtime error:[^\n]*)"
)
RESERVED_ENV = {"KRINEON_INPUT_FILE", "KRINEON_COVERAGE_FILE", "TMPDIR"}


class DynamicError(Exception):
    """A user-facing dynamic harness error."""


@dataclasses.dataclass
class Execution:
    input_data: bytes
    result: dict[str, Any]
    stdout: bytes
    stderr: bytes
    coverage_raw: bytes


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DynamicError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DynamicError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DynamicError(f"expected a JSON object in {path}")
    return data


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, data: dict[str, Any]) -> None:
    atomic_write_bytes(path, (json.dumps(data, indent=2, sort_keys=False) + "\n").encode("utf-8"))


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=False) + "\n")
        handle.flush()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def campaign_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def require_dynamic_campaign(root: Path) -> dict[str, Any]:
    campaign = read_json(root / "campaign.json")
    authorization = campaign.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise DynamicError(
            "dynamic testing refused: set campaign.json authorization.confirmed to true "
            "after recording the actual authorization"
        )
    if not str(authorization.get("allowedEnvironment", "")).strip():
        raise DynamicError("dynamic testing refused: record authorization.allowedEnvironment")
    if campaign.get("mode") not in ("source", "local-lab"):
        raise DynamicError("the local process runner supports only source and local-lab campaign modes")
    revision = str(campaign.get("commit", "")).strip()
    if not revision or revision in {"replace-with-tested-revision", "pending-pin"}:
        raise DynamicError("dynamic testing refused: pin the exact tested revision in campaign.json")
    return campaign


def resolve_from_cwd(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return path.resolve()


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise DynamicError(f"target artifact is not a file: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def parse_env(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise DynamicError(f"invalid --env value (expected KEY=VALUE): {item}")
        key, value = item.split("=", 1)
        if not ENV_NAME_RE.fullmatch(key):
            raise DynamicError(f"invalid environment variable name: {key}")
        if key in RESERVED_ENV:
            raise DynamicError(f"environment variable is managed by the runner: {key}")
        result[key] = value
    return result


def build_config(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise DynamicError("provide a target command after --")
    if not SAFE_NAME_RE.fullmatch(args.name):
        raise DynamicError("target name must start with a letter and use at most 64 letters, digits, _ or -")

    cwd = resolve_from_cwd(args.cwd, Path.cwd()) if args.cwd else root
    if not cwd.is_dir():
        raise DynamicError(f"target working directory does not exist: {cwd}")

    executable_value = command[0]
    if os.path.dirname(executable_value):
        executable = resolve_from_cwd(executable_value, cwd)
    else:
        found = shutil.which(executable_value)
        if found is None:
            raise DynamicError(f"target executable not found: {executable_value}")
        executable = Path(found).resolve()
    if not executable.is_file():
        raise DynamicError(f"target executable is not a file: {executable}")
    command[0] = str(executable)

    if args.input_mode == "file" and not any(INPUT_PLACEHOLDER in item for item in command):
        raise DynamicError(f"file input mode requires {INPUT_PLACEHOLDER} in the target command")

    artifacts: dict[str, dict[str, Any]] = {str(executable): artifact_record(executable)}
    for value in args.target_artifact:
        path = resolve_from_cwd(value, cwd)
        record = artifact_record(path)
        artifacts[record["path"]] = record

    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
    }
    environment.update(parse_env(args.env or ()))

    config = {
        "schemaVersion": 1,
        "name": args.name,
        "inputMode": args.input_mode,
        "command": command,
        "cwd": str(cwd),
        "targetArtifacts": list(artifacts.values()),
        "timeoutMs": args.timeout_ms,
        "memoryMb": args.memory_mb,
        "maxOutputBytes": args.max_output_bytes,
        "maxInputBytes": args.max_input_bytes,
        "environment": environment,
        "crashOnNonzero": bool(args.crash_on_nonzero),
    }
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    command = config.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        raise DynamicError("invalid recorded target command")
    if config.get("inputMode") not in ("stdin", "file"):
        raise DynamicError("invalid recorded input mode")
    if config["inputMode"] == "file" and not any(INPUT_PLACEHOLDER in item for item in command):
        raise DynamicError("recorded file input mode has no input placeholder")
    for field, minimum, maximum in (
        ("timeoutMs", 1, 3600000),
        ("memoryMb", 0, 1048576),
        ("maxOutputBytes", 1, 1073741824),
        ("maxInputBytes", 0, 1073741824),
    ):
        value = config.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise DynamicError(f"invalid recorded {field}")
    if not isinstance(config.get("environment"), dict):
        raise DynamicError("invalid recorded environment")
    if not isinstance(config.get("targetArtifacts"), list) or not config["targetArtifacts"]:
        raise DynamicError("recorded target has no pinned artifacts")


def verify_artifacts(config: dict[str, Any]) -> None:
    for record in config["targetArtifacts"]:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise DynamicError("invalid target artifact record")
        path = Path(record["path"])
        if not path.is_file():
            raise DynamicError(f"pinned target artifact is missing: {path}")
        actual = sha256_file(path)
        if actual != record.get("sha256"):
            raise DynamicError(
                f"target artifact changed since recording: {path}\n"
                f"expected {record.get('sha256')}, got {actual}"
            )


def apply_resource_limits(config: dict[str, Any]) -> Any:
    if os.name != "posix":
        return None

    def limits() -> None:
        import resource

        operations: list[tuple[int, tuple[int, int]]] = []
        if hasattr(resource, "RLIMIT_CORE"):
            operations.append((resource.RLIMIT_CORE, (0, 0)))
        if hasattr(resource, "RLIMIT_CPU"):
            cpu_seconds = max(1, math.ceil(config["timeoutMs"] / 1000) + 1)
            operations.append(
                (resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
            )
        if config["memoryMb"] and hasattr(resource, "RLIMIT_AS"):
            address_space = config["memoryMb"] * 1024 * 1024
            operations.append((resource.RLIMIT_AS, (address_space, address_space)))
        for limit, value in operations:
            try:
                resource.setrlimit(limit, value)
            except (OSError, ValueError):
                # The retained resource plan marks Darwin address-space limits
                # as best effort. Wall-clock cleanup remains authoritative.
                continue

    return limits


def read_path_capped(path: Path, limit: int) -> tuple[bytes, bool]:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def capture_process(
    process: subprocess.Popen[bytes], timeout_ms: int, output_limit: int
) -> tuple[int, bool, bytes, bytes, bool, bool, int, int]:
    """Drain both pipes without unbounded buffering or blocking target writes."""
    streams = (process.stdout, process.stderr)
    if streams[0] is None or streams[1] is None:
        raise DynamicError("target output pipes were not created")
    states = {
        streams[0]: {"data": bytearray(), "size": 0, "truncated": False},
        streams[1]: {"data": bytearray(), "size": 0, "truncated": False},
    }
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout_ms / 1000
    drain_deadline: float | None = None
    timed_out = False
    group_cleaned = False
    try:
        while True:
            now = time.monotonic()
            return_code = process.poll()
            if return_code is None and now >= deadline and not timed_out:
                timed_out = True
                kill_process_group(process)
            if return_code is not None and not group_cleaned:
                # Best-effort cleanup for children that remain in the target's
                # process group. A target can intentionally escape with setsid.
                kill_process_group(process)
                group_cleaned = True
                drain_deadline = now + 0.25
            if return_code is not None and not selector.get_map():
                break
            if drain_deadline is not None and now >= drain_deadline:
                for state in states.values():
                    state["truncated"] = True
                break

            events = selector.select(0.05)
            for key, _ in events:
                stream = key.fileobj
                state = states[stream]
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                state["size"] += len(chunk)
                retained = state["data"]
                remaining = output_limit - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
                if len(chunk) > max(0, remaining):
                    state["truncated"] = True
    finally:
        if process.poll() is None:
            kill_process_group(process)
        return_code = process.wait()
        if not group_cleaned:
            kill_process_group(process)
        for stream in streams:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            stream.close()
        selector.close()

    stdout_state = states[streams[0]]
    stderr_state = states[streams[1]]
    return (
        return_code,
        timed_out,
        bytes(stdout_state["data"]),
        bytes(stderr_state["data"]),
        bool(stdout_state["truncated"]),
        bool(stderr_state["truncated"]),
        int(stdout_state["size"]),
        int(stderr_state["size"]),
    )


def signal_label(return_code: int | None) -> str | None:
    if return_code is None or return_code >= 0:
        return None
    try:
        return signal.Signals(-return_code).name
    except ValueError:
        return f"SIG{-return_code}"


def normalize_diagnostic(value: str) -> str:
    value = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", value)
    value = re.sub(r"(?<![A-Za-z0-9_])(?:\d{4,})(?![A-Za-z0-9_])", "N", value)
    value = re.sub(r"(:\d+)(?::\d+)?", ":LINE", value)
    value = re.sub(r"(/[^\s:]+)+/", "/", value)
    return value.strip()


def crash_signature(
    config: dict[str, Any], result: dict[str, Any], stdout: bytes, stderr: bytes
) -> tuple[str, str, str | None]:
    text = (stderr + b"\n" + stdout).decode("utf-8", errors="replace")
    sanitizer_match = SANITIZER_RE.search(text)
    sanitizer = sanitizer_match.group(0) if sanitizer_match else None
    stack_lines = [line for line in text.splitlines() if re.match(r"\s*#\d+\s", line)]
    diagnostic_lines = [
        line
        for line in text.splitlines()
        if SANITIZER_RE.search(line) or re.match(r"\s*#\d+\s", line) or "runtime error:" in line
    ]
    if not diagnostic_lines:
        diagnostic_lines = [line for line in text.splitlines() if line.strip()][:2]
    normalized = [normalize_diagnostic(line) for line in diagnostic_lines[:5]]
    if not sanitizer_match and not stack_lines:
        # A bare signal or exit code has no location information. Be
        # conservative and avoid merging different no-output crash inputs.
        normalized.append(f"input:{result['inputSha256']}")
    target_identity = json.dumps(
        {
            "name": config.get("name"),
            "artifacts": sorted(str(item.get("sha256")) for item in config["targetArtifacts"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    signature = "|".join(
        [
            f"target:{target_identity}",
            str(result.get("signal") or result.get("returnCode")),
            *(item for item in normalized if item),
        ]
    )
    return sha256_bytes(signature.encode("utf-8", errors="replace")), signature[:8000], sanitizer


def execute_input(config: dict[str, Any], input_data: bytes, case_dir: Path | None = None) -> Execution:
    if len(input_data) > config["maxInputBytes"]:
        raise DynamicError(
            f"input is {len(input_data)} bytes; limit is {config['maxInputBytes']} bytes"
        )
    if not Path(config["cwd"]).is_dir():
        raise DynamicError(f"recorded target working directory is missing: {config['cwd']}")

    with tempfile.TemporaryDirectory(prefix="krineon-case-") as temporary:
        work = Path(temporary)
        input_path = work / "input.bin"
        coverage_path = work / "coverage.txt"
        input_path.write_bytes(input_data)
        command = [item.replace(INPUT_PLACEHOLDER, str(input_path)) for item in config["command"]]
        environment = {str(key): str(value) for key, value in config["environment"].items()}
        environment.update(
            {
                "KRINEON_INPUT_FILE": str(input_path),
                "KRINEON_COVERAGE_FILE": str(coverage_path),
                "TMPDIR": str(work),
            }
        )

        if os.name != "posix":
            raise DynamicError("the bounded process runner currently requires a POSIX operating system")
        started = time.monotonic()
        stdin_handle = input_path.open("rb") if config["inputMode"] == "stdin" else None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=stdin_handle if stdin_handle is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=config["cwd"],
                    env=environment,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=apply_resource_limits(config),
                    bufsize=0,
                )
            except OSError as exc:
                raise DynamicError(f"could not execute target {command[0]}: {exc}") from exc
            (
                return_code,
                timed_out,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                stdout_size,
                stderr_size,
            ) = capture_process(process, config["timeoutMs"], config["maxOutputBytes"])
        finally:
            if stdin_handle is not None:
                stdin_handle.close()

        coverage_raw = b""
        coverage_truncated = False
        if coverage_path.is_file():
            coverage_raw, coverage_truncated = read_path_capped(coverage_path, config["maxOutputBytes"])
            if coverage_truncated:
                # Discard a potentially partial final edge after byte truncation.
                coverage_raw = coverage_raw.rsplit(b"\n", 1)[0] if b"\n" in coverage_raw else b""
        coverage_set = {
            line.strip()
            for line in coverage_raw.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        }
        if len(coverage_set) > MAX_COVERAGE_EDGES:
            coverage_truncated = True
        coverage = sorted(coverage_set)[:MAX_COVERAGE_EDGES]

        result: dict[str, Any] = {
            "schemaVersion": 1,
            "platform": host_platform(),
            "resourceLimits": resource_limit_plan(config),
            "inputSha256": sha256_bytes(input_data),
            "inputSize": len(input_data),
            "returnCode": return_code,
            "signal": signal_label(return_code),
            "timedOut": timed_out,
            "durationMs": round((time.monotonic() - started) * 1000, 3),
            "stdoutSha256": sha256_bytes(stdout),
            "stdoutSize": stdout_size,
            "stdoutCapturedSize": len(stdout),
            "stdoutTruncated": stdout_truncated,
            "stderrSha256": sha256_bytes(stderr),
            "stderrSize": stderr_size,
            "stderrCapturedSize": len(stderr),
            "stderrTruncated": stderr_truncated,
            "coverageTruncated": coverage_truncated,
            "coverage": coverage,
        }
        sanitizer_match = SANITIZER_RE.search((stderr + b"\n" + stdout).decode("utf-8", errors="replace"))
        is_crash = (
            not timed_out
            and (
                (return_code is not None and return_code < 0)
                or sanitizer_match is not None
                or (config.get("crashOnNonzero") is True and return_code != 0)
            )
        )
        if timed_out:
            outcome = "timeout"
        elif is_crash:
            outcome = "crash"
        elif return_code == 0:
            outcome = "ok"
        else:
            outcome = "exit"
        result["outcome"] = outcome
        if is_crash:
            fingerprint, signature, sanitizer = crash_signature(config, result, stdout, stderr)
            result["fingerprint"] = fingerprint
            result["signature"] = signature
            result["sanitizer"] = sanitizer

    execution = Execution(input_data, result, stdout, stderr, coverage_raw)
    if case_dir is not None:
        atomic_write_bytes(case_dir / "input.bin", input_data)
        atomic_write_bytes(case_dir / "stdout.bin", stdout)
        atomic_write_bytes(case_dir / "stderr.bin", stderr)
        atomic_write_bytes(case_dir / "coverage.txt", coverage_raw)
        write_json(case_dir / "result.json", result)
    return execution


def new_run(root: Path, campaign: dict[str, Any], config: dict[str, Any], kind: str) -> tuple[str, Path, dict[str, Any]]:
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:10]
    run_dir = root / "dynamic" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    record = {
        "schemaVersion": 1,
        "engineVersion": ENGINE_VERSION,
        "runId": run_id,
        "kind": kind,
        "status": "running",
        "createdAt": utc_now(),
        "campaign": {
            "target": campaign.get("target"),
            "repository": campaign.get("repository"),
            "commit": campaign.get("commit"),
        },
        "config": config,
        "configSha256": sha256_bytes(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
    }
    write_json(run_dir / "run.json", record)
    return run_id, run_dir, record


def finish_run(run_dir: Path, record: dict[str, Any], status: str, summary: dict[str, Any]) -> None:
    record["status"] = status
    record["endedAt"] = utc_now()
    record["summary"] = summary
    write_json(run_dir / "run.json", record)


def persist_case(run_dir: Path, case_number: int, config: dict[str, Any], input_data: bytes) -> tuple[Path, Execution]:
    case_dir = run_dir / "cases" / f"{case_number:08d}"
    execution = execute_input(config, input_data, case_dir)
    return case_dir, execution


def save_crash(
    root: Path,
    run_id: str,
    case_number: int,
    case_dir: Path,
    config: dict[str, Any],
    execution: Execution,
) -> tuple[str, bool]:
    fingerprint = execution.result["fingerprint"]
    crash_dir = root / "dynamic" / "crashes" / fingerprint
    record_path = crash_dir / "crash.json"
    is_new = not record_path.exists()
    occurrence = {
        "at": utc_now(),
        "runId": run_id,
        "case": case_number,
        "casePath": str(case_dir.relative_to(root)),
        "inputSha256": execution.result["inputSha256"],
    }
    if is_new:
        atomic_write_bytes(crash_dir / "input.bin", execution.input_data)
        atomic_write_bytes(crash_dir / "stdout.bin", execution.stdout)
        atomic_write_bytes(crash_dir / "stderr.bin", execution.stderr)
        atomic_write_bytes(crash_dir / "coverage.txt", execution.coverage_raw)
        record = {
            "schemaVersion": 1,
            "engineVersion": ENGINE_VERSION,
            "crashId": fingerprint,
            "fingerprint": fingerprint,
            "signature": execution.result.get("signature"),
            "sanitizer": execution.result.get("sanitizer"),
            "signal": execution.result.get("signal"),
            "returnCode": execution.result.get("returnCode"),
            "stdoutTruncated": execution.result.get("stdoutTruncated"),
            "stderrTruncated": execution.result.get("stderrTruncated"),
            "createdAt": occurrence["at"],
            "lastSeenAt": occurrence["at"],
            "occurrences": 1,
            "firstSeen": occurrence,
            "config": config,
        }
        write_json(record_path, record)
    else:
        record = read_json(record_path)
        record["occurrences"] = int(record.get("occurrences", 0)) + 1
        record["lastSeenAt"] = occurrence["at"]
        write_json(record_path, record)
    append_jsonl(crash_dir / "occurrences.jsonl", occurrence)
    triage_one(root, fingerprint)
    return fingerprint, is_new


def summarize(results: Iterable[dict[str, Any]], coverage: set[str], new_crashes: set[str]) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    total = 0
    for result in results:
        total += 1
        outcome = str(result.get("outcome", "unknown"))
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    return {
        "cases": total,
        "outcomes": outcomes,
        "coverageEdges": len(coverage),
        "uniqueNewCrashes": len(new_crashes),
    }


def cmd_run(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_dynamic_campaign(root)
    config = build_config(args, root)
    verify_artifacts(config)
    input_path = Path(args.input_file).expanduser().resolve()
    if not input_path.is_file():
        raise DynamicError(f"input file does not exist: {input_path}")
    input_data = input_path.read_bytes()
    if len(input_data) > config["maxInputBytes"]:
        raise DynamicError("input exceeds --max-input-bytes")
    run_id, run_dir, record = new_run(root, campaign, config, "run")
    record["input"] = {"path": str(input_path), "sha256": sha256_bytes(input_data), "size": len(input_data)}
    write_json(run_dir / "run.json", record)
    try:
        case_dir, execution = persist_case(run_dir, 0, config, input_data)
        new_crashes: set[str] = set()
        crash_id = None
        if execution.result["outcome"] == "crash":
            crash_id, is_new = save_crash(root, run_id, 0, case_dir, config, execution)
            if is_new:
                new_crashes.add(crash_id)
        summary = summarize([execution.result], set(execution.result["coverage"]), new_crashes)
        finish_run(run_dir, record, "completed", summary)
    except Exception:
        finish_run(run_dir, record, "failed", {"cases": 0})
        raise
    print(f"run: {run_id}")
    print(f"outcome: {execution.result['outcome']} (return code {execution.result['returnCode']})")
    print(f"case: {case_dir.relative_to(root)}")
    if crash_id:
        print(f"crash: {crash_id}")
    return 0


def load_seed(path_value: str, max_size: int) -> tuple[bytes, dict[str, Any]]:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise DynamicError(f"seed file does not exist: {path}")
    data = path.read_bytes()
    if len(data) > max_size:
        raise DynamicError(f"seed exceeds --max-input-bytes: {path}")
    return data, {"path": str(path), "sha256": sha256_bytes(data), "size": len(data)}


def load_dictionary(path_value: str | None) -> tuple[list[bytes], str | None]:
    if path_value is None:
        return [], None
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise DynamicError(f"dictionary file does not exist: {path}")
    raw = path.read_bytes()
    tokens = [line for line in raw.splitlines() if line]
    if len(tokens) > 65536:
        raise DynamicError("dictionary exceeds 65536 tokens")
    return tokens, sha256_bytes(raw)


def mutate_input(
    rng: random.Random,
    data: bytes,
    corpus: list[bytes],
    dictionary: list[bytes],
    max_size: int,
) -> bytes:
    value = bytearray(data)
    interesting = (0, 1, 0x20, 0x41, 0x7F, 0x80, 0xFF)
    for _ in range(1 + rng.randrange(4)):
        operation = rng.randrange(8 if dictionary else 7)
        if operation == 0 and value:
            index = rng.randrange(len(value))
            value[index] ^= 1 << rng.randrange(8)
        elif operation == 1:
            index = rng.randrange(len(value) + 1)
            value[index:index] = bytes([rng.randrange(256)])
        elif operation == 2 and value:
            start = rng.randrange(len(value))
            end = min(len(value), start + 1 + rng.randrange(min(64, len(value) - start)))
            del value[start:end]
        elif operation == 3:
            if value:
                value[rng.randrange(len(value))] = rng.choice(interesting)
            else:
                value.append(rng.choice(interesting))
        elif operation == 4 and value:
            start = rng.randrange(len(value))
            length = 1 + rng.randrange(min(64, len(value) - start))
            block = bytes(value[start : start + length])
            index = rng.randrange(len(value) + 1)
            value[index:index] = block
        elif operation == 5 and corpus:
            other = rng.choice(corpus)
            if other:
                start = rng.randrange(len(other))
                block = other[start : start + 1 + rng.randrange(min(64, len(other) - start))]
                index = rng.randrange(len(value) + 1)
                value[index:index] = block
        elif operation == 6 and value:
            index = rng.randrange(len(value))
            value[index] = rng.randrange(256)
        elif operation == 7 and dictionary:
            token = rng.choice(dictionary)
            index = rng.randrange(len(value) + 1)
            value[index:index] = token
        if len(value) > max_size:
            if max_size == 0:
                value.clear()
            else:
                start = rng.randrange(len(value))
                del value[start : start + len(value) - max_size]
    return bytes(value)


def cmd_fuzz(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_dynamic_campaign(root)
    config = build_config(args, root)
    verify_artifacts(config)
    loaded = [load_seed(value, config["maxInputBytes"]) for value in args.seed_file]
    if not loaded:
        raise DynamicError("at least one --seed-file is required")
    seed_metadata = [metadata for _, metadata in loaded]
    corpus_dir = root / "dynamic" / "corpus" / config["name"]
    loaded_corpus_metadata: list[dict[str, Any]] = []
    if not args.no_load_corpus and corpus_dir.is_dir():
        known_hashes = {metadata["sha256"] for _, metadata in loaded}
        for path in sorted(corpus_dir.glob("*.bin")):
            data, metadata = load_seed(str(path), config["maxInputBytes"])
            if metadata["sha256"] not in known_hashes:
                loaded.append((data, metadata))
                loaded_corpus_metadata.append(metadata)
                known_hashes.add(metadata["sha256"])
    dictionary, dictionary_hash = load_dictionary(args.dictionary)
    run_id, run_dir, record = new_run(root, campaign, config, "fuzz")
    record.update(
        {
            "rngSeed": args.rng_seed,
            "iterations": args.iterations,
            "seeds": seed_metadata,
            "loadedCorpus": loaded_corpus_metadata,
            "dictionarySha256": dictionary_hash,
            "coverageContract": "target writes one edge ID per line to KRINEON_COVERAGE_FILE",
        }
    )
    write_json(run_dir / "run.json", record)

    rng = random.Random(args.rng_seed)
    corpus: list[bytes] = []
    corpus_hashes: set[str] = set()
    for data, _ in loaded:
        digest = sha256_bytes(data)
        if digest not in corpus_hashes:
            corpus.append(data)
            corpus_hashes.add(digest)
            atomic_write_bytes(corpus_dir / f"{digest}.bin", data)
    known_coverage: set[str] = set()
    results: list[dict[str, Any]] = []
    new_crashes: set[str] = set()
    seen_crashes: set[str] = set()
    case_number = 0

    def process_case(input_data: bytes, iteration: int | None) -> bool:
        nonlocal case_number
        case_dir, execution = persist_case(run_dir, case_number, config, input_data)
        result = execution.result
        new_edges = set(result["coverage"]) - known_coverage
        known_coverage.update(new_edges)
        result_for_event = dict(result)
        result_for_event["case"] = case_number
        result_for_event["newCoverageEdges"] = len(new_edges)
        result_for_event["iteration"] = iteration
        digest = result["inputSha256"]
        if new_edges and digest not in corpus_hashes:
            corpus.append(input_data)
            corpus_hashes.add(digest)
            atomic_write_bytes(corpus_dir / f"{digest}.bin", input_data)
            result_for_event["corpusAdded"] = True
        if result["outcome"] == "crash":
            crash_id, is_new = save_crash(root, run_id, case_number, case_dir, config, execution)
            result_for_event["crashId"] = crash_id
            seen_crashes.add(crash_id)
            if is_new:
                new_crashes.add(crash_id)
        append_jsonl(run_dir / "events.jsonl", result_for_event)
        results.append({"outcome": result["outcome"]})
        case_number += 1
        return args.stop_on_crash and bool(seen_crashes)

    try:
        stop = False
        for input_data, _ in loaded:
            if process_case(input_data, None):
                stop = True
                break
        if not stop:
            for iteration in range(args.iterations):
                # Mutate after each execution so newly discovered coverage can
                # influence the very next input.
                base = rng.choice(corpus)
                candidate = mutate_input(rng, base, corpus, dictionary, config["maxInputBytes"])
                if process_case(candidate, iteration):
                    break

        summary = summarize(results, known_coverage, new_crashes)
        summary["uniqueCrashesSeen"] = len(seen_crashes)
        summary["corpusInputs"] = len(corpus)
        finish_run(run_dir, record, "completed", summary)
    except Exception:
        finish_run(run_dir, record, "failed", summarize(results, known_coverage, new_crashes))
        raise

    print(f"run: {run_id}")
    print(f"cases: {len(results)}; coverage edges: {len(known_coverage)}; corpus: {len(corpus)}")
    print(f"unique crashes seen: {len(seen_crashes)}; new crashes: {len(new_crashes)}")
    for crash_id in sorted(seen_crashes):
        print(f"crash: {crash_id}")
    return 0


def find_crash(root: Path, value: str) -> tuple[str, Path, dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f]{8,64}", value):
        raise DynamicError("crash ID must be a hexadecimal fingerprint or unique prefix")
    base = root / "dynamic" / "crashes"
    matches = [path for path in base.glob(f"{value}*") if path.is_dir()] if base.is_dir() else []
    if len(matches) != 1:
        raise DynamicError(f"crash ID does not identify exactly one crash: {value}")
    crash_dir = matches[0]
    return crash_dir.name, crash_dir, read_json(crash_dir / "crash.json")


def save_replay_case(base: Path, config: dict[str, Any], input_data: bytes) -> tuple[Path, Execution]:
    replay_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    case_dir = base / replay_id
    execution = execute_input(config, input_data, case_dir)
    return case_dir, execution


def replay_crash(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_dynamic_campaign(root)
    crash_id, crash_dir, record = find_crash(root, args.crash_id)
    config = record["config"]
    validate_config(config)
    verify_artifacts(config)
    input_name = "minimized.bin" if args.minimized else "input.bin"
    input_path = crash_dir / input_name
    if not input_path.is_file():
        raise DynamicError(f"crash artifact has no {input_name}; run minimization first or omit --minimized")
    input_data = input_path.read_bytes()
    case_dir, execution = save_replay_case(crash_dir / "replays", config, input_data)
    matched = execution.result.get("fingerprint") == record["fingerprint"]
    replay_result = {
        "schemaVersion": 1,
        "engineVersion": ENGINE_VERSION,
        "at": utc_now(),
        "crashId": crash_id,
        "input": input_name,
        "expectedFingerprint": record["fingerprint"],
        "observedFingerprint": execution.result.get("fingerprint"),
        "matched": matched,
        "outcome": execution.result["outcome"],
    }
    write_json(case_dir / "replay.json", replay_result)
    print(f"crash: {crash_id}")
    print(f"outcome: {execution.result['outcome']}; fingerprint match: {str(matched).lower()}")
    print(f"replay: {case_dir.relative_to(root)}")
    return 0 if matched else 1


def replay_case(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_dynamic_campaign(root)
    if not re.fullmatch(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{10}", args.run_id):
        raise DynamicError("invalid run ID")
    run_dir = root / "dynamic" / "runs" / args.run_id
    record = read_json(run_dir / "run.json")
    config = record["config"]
    validate_config(config)
    verify_artifacts(config)
    case_dir = run_dir / "cases" / f"{args.case_number:08d}"
    input_path = case_dir / "input.bin"
    if not input_path.is_file():
        raise DynamicError(f"recorded case does not exist: {case_dir}")
    original = read_json(case_dir / "result.json")
    replay_dir, execution = save_replay_case(run_dir / "replays", config, input_path.read_bytes())
    comparison_fields = (
        "outcome",
        "returnCode",
        "signal",
        "timedOut",
        "fingerprint",
        "stdoutSha256",
        "stderrSha256",
        "stdoutTruncated",
        "stderrTruncated",
        "coverage",
    )
    matched = all(execution.result.get(field) == original.get(field) for field in comparison_fields)
    write_json(
        replay_dir / "replay.json",
        {
            "schemaVersion": 1,
            "engineVersion": ENGINE_VERSION,
            "at": utc_now(),
            "runId": args.run_id,
            "case": args.case_number,
            "matched": matched,
            "comparedFields": comparison_fields,
            "expectedOutcome": original["outcome"],
            "observedOutcome": execution.result["outcome"],
            "expectedFingerprint": original.get("fingerprint"),
            "observedFingerprint": execution.result.get("fingerprint"),
        },
    )
    print(f"outcome: {execution.result['outcome']}; recorded result match: {str(matched).lower()}")
    print(f"replay: {replay_dir.relative_to(root)}")
    return 0 if matched else 1


def cmd_minimize(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_dynamic_campaign(root)
    crash_id, crash_dir, record = find_crash(root, args.crash_id)
    config = record["config"]
    validate_config(config)
    verify_artifacts(config)
    original = (crash_dir / "input.bin").read_bytes()
    expected = record["fingerprint"]
    tests = 0

    def matches(candidate: bytes) -> bool:
        nonlocal tests
        if tests >= args.max_tests:
            return False
        tests += 1
        execution = execute_input(config, candidate)
        return execution.result.get("fingerprint") == expected

    if not matches(original):
        raise DynamicError("original crash no longer matches its recorded fingerprint; minimization stopped")

    current = original
    chunks = 2
    while len(current) >= 2 and tests < args.max_tests:
        chunk_size = math.ceil(len(current) / chunks)
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size :]
            if matches(candidate):
                current = candidate
                chunks = max(2, chunks - 1)
                reduced = True
                break
        if not reduced:
            if chunks >= len(current):
                break
            chunks = min(len(current), chunks * 2)

    for index in range(len(current)):
        if tests >= args.max_tests:
            break
        for replacement in (0, 1, 0x20, 0x41, 0x7F, 0xFF):
            if current[index] == replacement:
                continue
            candidate = current[:index] + bytes([replacement]) + current[index + 1 :]
            if matches(candidate):
                current = candidate
                break

    atomic_write_bytes(crash_dir / "minimized.bin", current)
    minimization = {
        "engineVersion": ENGINE_VERSION,
        "at": utc_now(),
        "originalSize": len(original),
        "minimizedSize": len(current),
        "originalSha256": sha256_bytes(original),
        "minimizedSha256": sha256_bytes(current),
        "tests": tests,
        "maxTests": args.max_tests,
        "testBudgetExhausted": tests >= args.max_tests,
        "expectedFingerprint": expected,
    }
    record["minimization"] = minimization
    write_json(crash_dir / "crash.json", record)
    triage_one(root, crash_id)
    print(f"crash: {crash_id}")
    print(f"minimized {len(original)} -> {len(current)} bytes in {tests} tests")
    return 0


def cmd_regression(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_dynamic_campaign(root)
    base = root / "dynamic" / "crashes"
    crash_dirs = sorted(path for path in base.iterdir() if path.is_dir()) if base.is_dir() else []
    if not crash_dirs:
        raise DynamicError("no recorded crashes to replay")
    regression_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    regression_dir = root / "dynamic" / "regressions" / regression_id
    rows: list[dict[str, Any]] = []
    for crash_dir in crash_dirs:
        record = read_json(crash_dir / "crash.json")
        input_name = "minimized.bin" if (crash_dir / "minimized.bin").is_file() else "input.bin"
        row: dict[str, Any] = {"crashId": crash_dir.name, "input": input_name}
        try:
            config = record["config"]
            validate_config(config)
            verify_artifacts(config)
            case_dir, execution = save_replay_case(regression_dir / "cases" / crash_dir.name, config, (crash_dir / input_name).read_bytes())
            matched = execution.result.get("fingerprint") == record["fingerprint"]
            row.update(
                {
                    "matched": matched,
                    "expectedFingerprint": record["fingerprint"],
                    "observedFingerprint": execution.result.get("fingerprint"),
                    "outcome": execution.result["outcome"],
                    "casePath": str(case_dir.relative_to(root)),
                }
            )
        except DynamicError as exc:
            row.update({"matched": False, "error": str(exc)})
        rows.append(row)
    passed = all(row.get("matched") is True for row in rows)
    report = {
        "schemaVersion": 1,
        "engineVersion": ENGINE_VERSION,
        "regressionId": regression_id,
        "at": utc_now(),
        "passed": passed,
        "crashes": rows,
    }
    write_json(regression_dir / "regression.json", report)
    print(f"regression: {regression_id}")
    print(f"reproduced: {sum(row.get('matched') is True for row in rows)}/{len(rows)}")
    print(f"report: {(regression_dir / 'regression.json').relative_to(root)}")
    return 0 if passed else 1


def cmd_triage(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    if not (root / "campaign.json").is_file():
        raise DynamicError(f"not a Krineon campaign: {root}")
    selected_ids: list[str] = []
    if args.crash_id:
        crash_id, _, _ = find_crash(root, args.crash_id)
        selected_ids.append(crash_id)
        triage, index = triage_one(root, crash_id)
        triages = [triage]
    else:
        triages, index = triage_campaign(root)
        selected_ids = [str(item["crashId"]) for item in triages]
    if not triages:
        raise DynamicError("no recorded crashes to triage")

    if args.finding_id:
        if not args.crash_id:
            raise DynamicError("--finding-id requires --crash-id to avoid linking unrelated crashes")
        finding_path = root / "findings" / f"{args.finding_id}.json"
        if not finding_path.is_file():
            raise DynamicError(f"finding does not exist: {args.finding_id}")
        finding = read_json(finding_path)
        linked = finding.get("dynamicTriage")
        if not isinstance(linked, dict):
            linked = {}
        existing_crash_ids = linked.get("crashIds")
        if not isinstance(existing_crash_ids, list):
            existing_crash_ids = []
        existing_cluster_ids = linked.get("acceptedClusterIds")
        if not isinstance(existing_cluster_ids, list):
            existing_cluster_ids = []
        existing_verdicts = linked.get("machineVerdicts")
        if not isinstance(existing_verdicts, dict):
            existing_verdicts = {}
        crash_ids = sorted(
            set(str(value) for value in existing_crash_ids if value) | set(selected_ids)
        )
        cluster_ids = sorted(
            set(str(value) for value in existing_cluster_ids if value)
            | {str(item["stack"]["clusterId"]) for item in triages}
        )
        verdicts = {
            str(item["crashId"]): str(item["automatedExploitability"]["verdict"])
            for item in triages
        }
        linked.update(
            {
                "required": True,
                "crashIds": crash_ids,
                "index": "dynamic/triage/index.json",
                "acceptedClusterIds": cluster_ids,
                "machineVerdicts": {**existing_verdicts, **verdicts},
                "reviewed": bool(args.review_note and args.reviewed_by),
                "reviewedBy": args.reviewed_by or "",
                "reviewNotes": args.review_note or "",
                "overrideReason": linked.get("overrideReason", ""),
            }
        )
        finding["dynamicTriage"] = linked
        finding.setdefault("gates", {})["automated_triage_reviewed"] = linked["reviewed"]
        write_json(finding_path, finding)

    payload = {
        "triaged": len(triages),
        "crashIds": selected_ids,
        "clusterCount": index["clusterCount"],
        "index": str((root / "dynamic" / "triage" / "index.json").relative_to(root)),
        "results": [
            {
                "crashId": item["crashId"],
                "faultClass": item["firstFault"]["class"],
                "access": item["firstFault"]["access"],
                "clusterId": item["stack"]["clusterId"],
                "controlEvidenceStatus": item["controlEvidence"]["status"],
                "controlClaim": item["controlEvidence"].get("claim"),
                "verdict": item["automatedExploitability"]["verdict"],
                "gateRecommendation": item["automatedExploitability"]["gateRecommendation"],
            }
            for item in triages
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"triaged: {payload['triaged']}; stack clusters: {payload['clusterCount']}")
        for result in payload["results"]:
            print(
                f"{result['crashId']}: {result['faultClass']}/{result['access']} "
                f"control={result['controlEvidenceStatus']} verdict={result['verdict']}"
            )
        print(f"index: {payload['index']}")
    return 0


def add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="stable local target name")
    parser.add_argument("--input-mode", choices=("stdin", "file"), default="stdin")
    parser.add_argument("--cwd", help="target working directory; defaults to the campaign directory")
    parser.add_argument(
        "--target-artifact",
        action="append",
        required=True,
        help="file to pin by SHA-256; repeat for scripts, binaries, and data dependencies",
    )
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--memory-mb", type=int, default=512, help="POSIX address-space limit; 0 disables it")
    parser.add_argument("--max-output-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-input-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--env", action="append", help="explicit target environment KEY=VALUE; recorded in run metadata")
    parser.add_argument("--crash-on-nonzero", action="store_true", help="treat every nonzero exit as a crash")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command_name", required=True)

    run = sub.add_parser("run", help="execute and preserve one input")
    run.add_argument("campaign_dir")
    run.add_argument("--input-file", required=True)
    add_target_arguments(run)
    run.set_defaults(func=cmd_run)

    fuzz = sub.add_parser(
        "fuzz",
        help="deterministic smoke mutator; use fuzzer_orchestrator.py for coverage-guided fuzzing",
    )
    fuzz.add_argument("campaign_dir")
    fuzz.add_argument("--seed-file", action="append", required=True)
    fuzz.add_argument("--iterations", type=int, default=1000)
    fuzz.add_argument("--rng-seed", type=int, default=0)
    fuzz.add_argument("--dictionary", help="optional file containing one mutation token per line")
    fuzz.add_argument("--stop-on-crash", action="store_true")
    fuzz.add_argument("--no-load-corpus", action="store_true", help="do not calibrate previously retained corpus inputs")
    add_target_arguments(fuzz)
    fuzz.set_defaults(func=cmd_fuzz)

    minimize = sub.add_parser("minimize", help="minimize an input while preserving its crash fingerprint")
    minimize.add_argument("campaign_dir")
    minimize.add_argument("crash_id")
    minimize.add_argument("--max-tests", type=int, default=200)
    minimize.set_defaults(func=cmd_minimize)

    replay = sub.add_parser("replay", help="replay a recorded crash or run case")
    replay_sub = replay.add_subparsers(dest="replay_kind", required=True)
    crash = replay_sub.add_parser("crash")
    crash.add_argument("campaign_dir")
    crash.add_argument("crash_id")
    crash.add_argument("--minimized", action="store_true")
    crash.set_defaults(func=replay_crash)
    case = replay_sub.add_parser("case")
    case.add_argument("campaign_dir")
    case.add_argument("run_id")
    case.add_argument("case_number", type=int)
    case.set_defaults(func=replay_case)

    regression = sub.add_parser(
        "regression", help="verify every crash still reproduces against its original pinned target"
    )
    regression.add_argument("campaign_dir")
    regression.set_defaults(func=cmd_regression)

    triage = sub.add_parser(
        "triage", help="classify first faults and validate concrete primitive evidence"
    )
    triage.add_argument("campaign_dir")
    triage.add_argument("--crash-id", help="exact crash ID or unique prefix; omit to refresh all")
    triage.add_argument("--finding-id", help="attach one selected crash to an existing finding")
    triage.add_argument("--reviewed-by", help="reviewer identity for an attached triage decision")
    triage.add_argument("--review-note", help="human interpretation of the machine verdict")
    triage.add_argument("--json", action="store_true")
    triage.set_defaults(func=cmd_triage)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    target_command: list[str] = []
    if "--" in arguments:
        separator = arguments.index("--")
        target_command = arguments[separator + 1 :]
        arguments = arguments[:separator]
    args = build_parser().parse_args(arguments)
    args.command = target_command
    try:
        if hasattr(args, "iterations") and args.iterations < 0:
            raise DynamicError("--iterations must be nonnegative")
        if hasattr(args, "max_tests") and args.max_tests < 1:
            raise DynamicError("--max-tests must be positive")
        if hasattr(args, "case_number") and args.case_number < 0:
            raise DynamicError("case number must be nonnegative")
        if bool(getattr(args, "reviewed_by", None)) != bool(getattr(args, "review_note", None)):
            raise DynamicError("--reviewed-by and --review-note must be supplied together")
        return int(args.func(args))
    except DynamicError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
