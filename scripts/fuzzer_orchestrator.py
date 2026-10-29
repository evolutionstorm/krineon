#!/usr/bin/env python3
"""Operate pinned AFL++, libFuzzer, and Fuzzilli campaigns with durable evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_HARNESS = PROJECT_ROOT / "scripts" / "dynamic_harness.py"
ENGINES = ("aflpp", "libfuzzer", "fuzzilli")
INSTRUMENTATION_KINDS = (
    "afl-clang-fast",
    "libfuzzer-clang",
    "sanitizer-coverage",
    "fuzzilli-reprl",
)
ENGINE_INSTRUMENTATION = {
    "aflpp": {"afl-clang-fast", "sanitizer-coverage"},
    "libfuzzer": {"libfuzzer-clang", "sanitizer-coverage"},
    "fuzzilli": {"fuzzilli-reprl"},
}
SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")


class FuzzerError(Exception):
    """A fuzzer operation could not be executed safely or deterministically."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(5)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FuzzerError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FuzzerError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FuzzerError(f"expected a JSON object in {path}")
    return value


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    data = (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def artifact(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def resolve_file(value: str, *, label: str, executable: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise FuzzerError(f"{label} is not a file: {path}")
    if executable and not os.access(path, os.X_OK):
        raise FuzzerError(f"{label} is not executable: {path}")
    return path


def campaign_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def require_campaign(root: Path) -> dict[str, Any]:
    campaign = read_json(root / "campaign.json")
    authorization = campaign.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise FuzzerError("dynamic fuzzing requires authorization.confirmed: true")
    if not str(authorization.get("allowedEnvironment") or "").strip():
        raise FuzzerError("authorization.allowedEnvironment must name the owned test environment")
    if campaign.get("mode") not in {"source", "local-lab"}:
        raise FuzzerError("external fuzzing is limited to source or local-lab campaigns")
    return campaign


def profile_root(root: Path, name: str) -> Path:
    if not SAFE_NAME.fullmatch(name):
        raise FuzzerError("profile name must use letters, digits, dot, underscore, or dash")
    return root / "dynamic" / "fuzzers" / name


def profile_path(root: Path, name: str) -> Path:
    return profile_root(root, name) / "profile.json"


def require_profile(root: Path, name: str) -> dict[str, Any]:
    require_campaign(root)
    profile = read_json(profile_path(root, name))
    for record_name in ("target", "engineBinary"):
        record = profile.get(record_name)
        if record_name == "engineBinary" and profile.get("engine") == "libfuzzer":
            continue
        if not isinstance(record, dict):
            raise FuzzerError(f"profile has no {record_name} artifact")
        path = Path(str(record.get("path") or ""))
        if not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise FuzzerError(f"registered {record_name} artifact changed: {path}")
    target = profile.get("target")
    if not isinstance(target, dict):
        raise FuzzerError("profile has no target artifact")
    target_path = Path(str(target.get("path") or ""))
    if not target_path.is_file() or sha256_file(target_path) != target.get("sha256"):
        raise FuzzerError(f"registered target artifact changed: {target_path}")
    return profile


def parse_json_array(value: str, *, label: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise FuzzerError(f"{label} must be a JSON array: {exc}") from exc
    if not isinstance(parsed, list) or not parsed or not all(isinstance(item, str) for item in parsed):
        raise FuzzerError(f"{label} must be a non-empty JSON array of strings")
    return parsed


def parse_env(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise FuzzerError(f"environment value must be KEY=VALUE: {value}")
        key, item = value.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise FuzzerError(f"invalid environment key: {key}")
        result[key] = item
    return result


def expand_tokens(command: list[str], values: dict[str, str]) -> list[str]:
    expanded: list[str] = []
    for item in command:
        value = item
        for key, replacement in values.items():
            value = value.replace("{" + key + "}", replacement)
        if re.search(r"\{[A-Za-z0-9_]+\}", value):
            raise FuzzerError(f"unresolved command token: {value}")
        expanded.append(value)
    return expanded


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=5)


def drain_stream(stream: Any, limit: int, destination: bytearray, state: dict[str, bool]) -> None:
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                state["truncated"] = True
    finally:
        stream.close()


class ManagedProcess:
    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        output_dir: Path,
        max_output_bytes: int,
    ):
        output_dir.mkdir(parents=True, exist_ok=True)
        self.command = command
        self.output_dir = output_dir
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdout_state = {"truncated": False}
        self.stderr_state = {"truncated": False}
        self.process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        assert self.process.stdout is not None and self.process.stderr is not None
        self.stdout_thread = threading.Thread(
            target=drain_stream,
            args=(self.process.stdout, max_output_bytes, self.stdout, self.stdout_state),
            daemon=True,
        )
        self.stderr_thread = threading.Thread(
            target=drain_stream,
            args=(self.process.stderr, max_output_bytes, self.stderr, self.stderr_state),
            daemon=True,
        )
        self.stdout_thread.start()
        self.stderr_thread.start()
        self.started_at = utc_now()

    def finish(self) -> dict[str, Any]:
        terminate_process(self.process)
        self.stdout_thread.join(timeout=5)
        self.stderr_thread.join(timeout=5)
        stdout_path = self.output_dir / "stdout.log"
        stderr_path = self.output_dir / "stderr.log"
        stdout_path.write_bytes(bytes(self.stdout))
        stderr_path.write_bytes(bytes(self.stderr))
        return {
            "command": self.command,
            "pid": self.process.pid,
            "startedAt": self.started_at,
            "endedAt": utc_now(),
            "returnCode": self.process.returncode,
            "stdout": {**artifact(stdout_path), "truncated": self.stdout_state["truncated"]},
            "stderr": {**artifact(stderr_path), "truncated": self.stderr_state["truncated"]},
        }


def cmd_register(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    directory = profile_root(root, args.name)
    path = directory / "profile.json"
    if path.exists() and not args.replace:
        raise FuzzerError(f"fuzzer profile already exists: {args.name}; use --replace")
    target = resolve_file(args.target, label="target", executable=True)
    engine_binary: dict[str, Any] | None = None
    if args.engine == "libfuzzer":
        engine_binary = artifact(target)
    else:
        if not args.engine_binary:
            raise FuzzerError(f"--engine-binary is required for {args.engine}")
        engine_binary = artifact(
            resolve_file(args.engine_binary, label="engine binary", executable=True)
        )
    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else target.parent
    if not cwd.is_dir():
        raise FuzzerError(f"working directory is not a directory: {cwd}")
    dictionary = None
    if args.dictionary:
        dictionary = artifact(resolve_file(args.dictionary, label="dictionary"))
    instrumentation = None
    if args.preinstrumented_kind:
        if args.preinstrumented_kind not in ENGINE_INSTRUMENTATION[args.engine]:
            raise FuzzerError(
                f"{args.preinstrumented_kind} is not compatible with {args.engine}"
            )
        if not args.instrumentation_evidence:
            raise FuzzerError(
                "--preinstrumented-kind requires at least one --instrumentation-evidence artifact"
            )
        evidence = [
            artifact(resolve_file(value, label="instrumentation evidence"))
            for value in args.instrumentation_evidence
        ]
        if args.preinstrumented_kind == "fuzzilli-reprl":
            evidence_text = "\n".join(
                Path(item["path"]).read_text(encoding="utf-8", errors="replace")
                for item in evidence
                if Path(item["path"]).stat().st_size <= 8 * 1024 * 1024
            ).lower()
            if "fuzzilli" not in evidence_text and "reprl" not in evidence_text:
                raise FuzzerError(
                    "Fuzzilli preinstrumentation evidence must identify the Fuzzilli/REPRL build switch"
                )
        instrumentation = {
            "kind": args.preinstrumented_kind,
            "record": "registered-preinstrumented-target",
            "verified": True,
            "at": utc_now(),
            "evidence": evidence,
        }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "corpus").mkdir(exist_ok=True)
    profile = {
        "schemaVersion": 1,
        "name": args.name,
        "engine": args.engine,
        "revision": args.revision,
        "registeredAt": utc_now(),
        "target": artifact(target),
        "engineBinary": engine_binary,
        "cwd": str(cwd),
        "targetArgs": list(args.target_arg or []),
        "engineArgs": list(args.engine_arg or []),
        "corpusGlobs": list(args.corpus_glob or []),
        "crashGlobs": list(args.crash_glob or []),
        "dictionary": dictionary,
        "maxInputBytes": args.max_input_bytes,
        "instrumentation": instrumentation,
        "notes": args.note or "",
    }
    atomic_json(path, profile)
    print(f"registered {args.engine} profile: {args.name}")
    print(f"target sha256: {profile['target']['sha256']}")
    return 0


def instrumentation_environment(kind: str, extra: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    if kind == "afl-clang-fast":
        result.update(
            {
                "CC": "afl-clang-fast",
                "CXX": "afl-clang-fast++",
                "AFL_USE_ASAN": "1",
                "AFL_LLVM_CMPLOG": "1",
            }
        )
    elif kind == "libfuzzer-clang":
        compile_flags = (
            "-fsanitize=fuzzer-no-link,address,undefined "
            "-fno-omit-frame-pointer -gline-tables-only"
        )
        link_flags = "-fsanitize=fuzzer,address,undefined"
        result.update(
            {
                "CC": "clang",
                "CXX": "clang++",
                "CFLAGS": compile_flags,
                "CXXFLAGS": compile_flags,
                "LDFLAGS": link_flags,
            }
        )
    elif kind == "sanitizer-coverage":
        flags = (
            "-fsanitize=address,undefined "
            "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls,8bit-counters "
            "-fno-omit-frame-pointer -gline-tables-only"
        )
        result.update({"CC": "clang", "CXX": "clang++", "CFLAGS": flags, "CXXFLAGS": flags})
    elif kind == "fuzzilli-reprl":
        result["KRINEON_FUZZILLI_REPRL_BUILD"] = "1"
    result.update(extra)
    return result


def instrumentation_flags(kind: str) -> str:
    if kind == "afl-clang-fast":
        return "afl-clang-fast with ASan and CmpLog"
    if kind == "libfuzzer-clang":
        return "-fsanitize=fuzzer-no-link,address,undefined"
    if kind == "sanitizer-coverage":
        return "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls,8bit-counters"
    return "v8_enable_fuzzilli=true"


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    output_dir: Path,
    max_output_bytes: int,
) -> dict[str, Any]:
    process = ManagedProcess(
        command,
        cwd=cwd,
        env=env,
        output_dir=output_dir,
        max_output_bytes=max_output_bytes,
    )
    timed_out = False
    try:
        process.process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    result = process.finish()
    result["timedOut"] = timed_out
    return result


def cmd_instrument(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    if args.kind not in ENGINE_INSTRUMENTATION[str(profile["engine"])]:
        raise FuzzerError(f"{args.kind} is not compatible with {profile['engine']}")
    if args.kind == "fuzzilli-reprl" and (
        not args.verify_command_json or not args.verify_output_contains
    ):
        raise FuzzerError(
            "fuzzilli-reprl requires --verify-command-json and --verify-output-contains"
        )
    command = expand_tokens(
        parse_json_array(args.build_command_json, label="--build-command-json"),
        {"instrumentation_flags": instrumentation_flags(args.kind)},
    )
    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else Path(profile["cwd"])
    if not cwd.is_dir():
        raise FuzzerError(f"instrumentation working directory is not a directory: {cwd}")
    target_path = Path(profile["target"]["path"])
    before = artifact(target_path) if target_path.is_file() else None
    injected = instrumentation_environment(args.kind, parse_env(args.env or []))
    env = os.environ.copy()
    env.update(injected)
    operation_id = run_id()
    operation_dir = profile_root(root, args.name) / "instrumentation" / operation_id
    operation_dir.mkdir(parents=True, exist_ok=False)
    result = run_bounded_command(
        command,
        cwd=cwd,
        env=env,
        timeout_seconds=args.timeout_seconds,
        output_dir=operation_dir / "build",
        max_output_bytes=args.max_output_bytes,
    )
    if result["timedOut"] or result["returnCode"] != 0:
        atomic_json(
            operation_dir / "instrumentation.json",
            {
                "schemaVersion": 1,
                "operationId": operation_id,
                "at": utc_now(),
                "kind": args.kind,
                "command": command,
                "cwd": str(cwd),
                "injectedEnvironment": injected,
                "before": before,
                "build": result,
                "verified": False,
                "error": "instrumented build command failed",
            },
        )
        raise FuzzerError("instrumented build command failed; retained output is in " + str(operation_dir))
    if not target_path.is_file():
        atomic_json(
            operation_dir / "instrumentation.json",
            {
                "schemaVersion": 1,
                "operationId": operation_id,
                "at": utc_now(),
                "kind": args.kind,
                "command": command,
                "injectedEnvironment": injected,
                "before": before,
                "build": result,
                "verified": False,
                "error": "registered target was not produced",
            },
        )
        raise FuzzerError("instrumented build did not produce the registered target")
    after = artifact(target_path)
    verification = None
    if args.verify_command_json:
        verify_command = expand_tokens(
            parse_json_array(args.verify_command_json, label="--verify-command-json"),
            {"instrumentation_flags": instrumentation_flags(args.kind)},
        )
        verification = run_bounded_command(
            verify_command,
            cwd=cwd,
            env=env,
            timeout_seconds=args.timeout_seconds,
            output_dir=operation_dir / "verify",
            max_output_bytes=args.max_output_bytes,
        )
        if verification["timedOut"] or verification["returnCode"] != 0:
            atomic_json(
                operation_dir / "instrumentation.json",
                {
                    "schemaVersion": 1,
                    "operationId": operation_id,
                    "at": utc_now(),
                    "kind": args.kind,
                    "command": command,
                    "injectedEnvironment": injected,
                    "before": before,
                    "after": after,
                    "build": result,
                    "verification": verification,
                    "verified": False,
                    "error": "instrumentation verification command failed",
                },
            )
            raise FuzzerError("instrumentation verification command failed")
        if args.verify_output_contains:
            output = "\n".join(
                Path(str(verification[key]["path"])).read_text(
                    encoding="utf-8", errors="replace"
                )
                for key in ("stdout", "stderr")
            )
            if args.verify_output_contains not in output:
                atomic_json(
                    operation_dir / "instrumentation.json",
                    {
                        "schemaVersion": 1,
                        "operationId": operation_id,
                        "at": utc_now(),
                        "kind": args.kind,
                        "command": command,
                        "injectedEnvironment": injected,
                        "before": before,
                        "after": after,
                        "build": result,
                        "verification": verification,
                        "verified": False,
                        "error": "verification output marker missing",
                    },
                )
                raise FuzzerError(
                    "instrumentation verification output did not contain the required marker"
                )
    changed = before is None or before["sha256"] != after["sha256"]
    if not changed and verification is None:
        atomic_json(
            operation_dir / "instrumentation.json",
            {
                "schemaVersion": 1,
                "operationId": operation_id,
                "at": utc_now(),
                "kind": args.kind,
                "command": command,
                "injectedEnvironment": injected,
                "before": before,
                "after": after,
                "build": result,
                "verified": False,
                "error": "target hash unchanged without independent verification",
            },
        )
        raise FuzzerError(
            "target hash did not change; provide --verify-command-json to prove existing instrumentation"
        )
    record = {
        "schemaVersion": 1,
        "operationId": operation_id,
        "at": utc_now(),
        "kind": args.kind,
        "command": command,
        "cwd": str(cwd),
        "injectedEnvironment": injected,
        "instrumentationFlags": instrumentation_flags(args.kind),
        "before": before,
        "after": after,
        "targetChanged": changed,
        "build": result,
        "verification": verification,
        "verified": changed or verification is not None,
        "limitation": (
            "A successful build proves the requested instrumentation path ran. Runtime coverage "
            "must still be rebuilt from the retained corpus."
        ),
    }
    atomic_json(operation_dir / "instrumentation.json", record)
    profile["target"] = after
    if profile.get("engine") == "libfuzzer":
        profile["engineBinary"] = after
    profile["instrumentation"] = {
        "kind": args.kind,
        "record": str((operation_dir / "instrumentation.json").relative_to(root)),
        "verified": record["verified"],
        "at": record["at"],
    }
    atomic_json(profile_path(root, args.name), profile)
    print(f"instrumentation: {operation_id}")
    print(f"target changed: {str(changed).lower()}")
    print(f"record: {(operation_dir / 'instrumentation.json').relative_to(root)}")
    return 0


def corpus_dir(root: Path, name: str) -> Path:
    return profile_root(root, name) / "corpus"


def corpus_snapshot(directory: Path) -> dict[str, Any]:
    rows = [artifact(path) for path in sorted(directory.iterdir()) if path.is_file()]
    normalized = json.dumps(
        [{"sha256": row["sha256"], "size": row["size"]} for row in rows],
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "inputs": len(rows),
        "bytes": sum(int(row["size"]) for row in rows),
        "digest": hashlib.sha256(normalized).hexdigest(),
        "files": rows,
    }


def add_to_corpus(
    root: Path,
    name: str,
    source: Path,
    *,
    max_input_bytes: int,
    provenance: dict[str, Any],
) -> tuple[str, bool]:
    size = source.stat().st_size
    if size > max_input_bytes:
        raise FuzzerError(f"seed exceeds max input size: {source}")
    digest = sha256_file(source)
    suffix = source.suffix[:16] if source.suffix else ".bin"
    destination = corpus_dir(root, name) / f"{digest}{suffix}"
    lock_path = profile_root(root, name) / ".corpus.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = sorted(corpus_dir(root, name).glob(f"{digest}.*"))
        if existing:
            destination = existing[0]
        created = not destination.exists()
        if created:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)
        append_jsonl(
            profile_root(root, name) / "corpus-provenance.jsonl",
            {
                "at": utc_now(),
                "sha256": digest,
                "size": size,
                "retained": str(destination.relative_to(root)),
                "created": created,
                **provenance,
            },
        )
    return digest, created


def iter_seed_files(sources: list[str], extensions: set[str], max_files: int) -> list[Path]:
    rows: list[Path] = []
    for value in sources:
        source = Path(value).expanduser().resolve()
        if source.is_symlink():
            raise FuzzerError(f"seed source is a symlink: {source}")
        candidates = [source] if source.is_file() else sorted(source.rglob("*")) if source.is_dir() else []
        if not candidates:
            raise FuzzerError(f"seed source does not exist or is empty: {source}")
        for candidate in candidates:
            if candidate.is_symlink():
                continue
            if candidate.is_file() and (not extensions or candidate.suffix.lower() in extensions):
                rows.append(candidate)
                if len(rows) > max_files:
                    raise FuzzerError("seed harvest exceeds --max-files")
    return rows


def cmd_seed_harvest(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    extensions = {
        value.lower() if value.startswith(".") else "." + value.lower()
        for value in (args.extension or [])
    }
    sources = iter_seed_files(args.source, extensions, args.max_files)
    total = 0
    added = 0
    skipped_large = 0
    for source in sources:
        size = source.stat().st_size
        total += size
        if total > args.max_total_bytes:
            raise FuzzerError("seed harvest exceeds --max-total-bytes")
        if size > profile["maxInputBytes"]:
            skipped_large += 1
            continue
        _, created = add_to_corpus(
            root,
            args.name,
            source,
            max_input_bytes=profile["maxInputBytes"],
            provenance={"kind": "harvest", "source": str(source)},
        )
        added += int(created)
    print(f"harvested: {len(sources)} files; new corpus inputs: {added}")
    print(f"skipped oversized: {skipped_large}")
    return 0


def cmd_structured_generate(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    template = parse_json_array(args.command_json, label="--command-json")
    generation_id = run_id()
    generation_dir = profile_root(root, args.name) / "generation" / generation_id
    output_dir = generation_dir / "outputs"
    output_dir.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, Any]] = []
    added = 0
    for index in range(args.count):
        output = output_dir / f"{index:08d}{args.suffix}"
        command = expand_tokens(
            template,
            {
                "output": str(output),
                "index": str(index),
                "seed": str(args.seed + index),
                "corpus": str(corpus_dir(root, args.name)),
            },
        )
        result = run_bounded_command(
            command,
            cwd=Path(args.cwd).expanduser().resolve() if args.cwd else Path(profile["cwd"]),
            env=os.environ.copy(),
            timeout_seconds=args.timeout_seconds,
            output_dir=generation_dir / "commands" / f"{index:08d}",
            max_output_bytes=args.max_output_bytes,
        )
        row = {"index": index, "command": command, "result": result, "output": str(output)}
        if result["timedOut"] or result["returnCode"] != 0:
            row["accepted"] = False
            records.append(row)
            continue
        if not output.is_file():
            row["accepted"] = False
            row["error"] = "generator did not create {output}"
            records.append(row)
            continue
        _, created = add_to_corpus(
            root,
            args.name,
            output,
            max_input_bytes=profile["maxInputBytes"],
            provenance={
                "kind": "structured-generator",
                "generationId": generation_id,
                "index": index,
                "command": command,
            },
        )
        row["accepted"] = True
        row["sha256"] = sha256_file(output)
        records.append(row)
        added += int(created)
    record = {
        "schemaVersion": 1,
        "generationId": generation_id,
        "at": utc_now(),
        "commandTemplate": template,
        "seed": args.seed,
        "count": args.count,
        "newCorpusInputs": added,
        "results": records,
    }
    atomic_json(generation_dir / "generation.json", record)
    print(f"generation: {generation_id}")
    print(f"accepted: {sum(row.get('accepted') is True for row in records)}/{len(records)}; new: {added}")
    return 0 if all(row.get("accepted") is True for row in records) else 1


def command_for_workers(
    profile: dict[str, Any],
    run_dir: Path,
    workers: int,
    duration: int,
) -> list[tuple[str, list[str], Path]]:
    engine = profile["engine"]
    target = str(profile["target"]["path"])
    engine_binary = str(profile["engineBinary"]["path"])
    target_args = [str(value) for value in profile.get("targetArgs", [])]
    engine_args = [str(value) for value in profile.get("engineArgs", [])]
    canonical = run_dir.parents[1] / "corpus"
    commands: list[tuple[str, list[str], Path]] = []
    if engine == "libfuzzer":
        crashes = run_dir / "libfuzzer-crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        command = [
            target,
            str(canonical),
            f"-artifact_prefix={crashes}/",
            f"-max_total_time={duration}",
            f"-workers={workers}",
            f"-jobs={workers}",
            "-print_final_stats=1",
        ]
        dictionary = profile.get("dictionary")
        if isinstance(dictionary, dict):
            command.append(f"-dict={dictionary['path']}")
        command.extend(engine_args)
        commands.append(("native-workers", command, run_dir / "workers" / "native"))
    elif engine == "aflpp":
        sync = run_dir / "afl-sync"
        sync.mkdir(parents=True, exist_ok=True)
        dictionary = profile.get("dictionary")
        for index in range(workers):
            worker_id = "main" if index == 0 else f"secondary-{index}"
            role = "-M" if index == 0 else "-S"
            command = [
                engine_binary,
                "-i",
                str(canonical),
                "-o",
                str(sync),
                role,
                worker_id,
                "-V",
                str(duration),
            ]
            if isinstance(dictionary, dict):
                command.extend(["-x", str(dictionary["path"])])
            command.extend([*engine_args, "--", target, *target_args])
            commands.append((worker_id, command, run_dir / "workers" / worker_id))
    elif engine == "fuzzilli":
        storage = run_dir / "fuzzilli-storage"
        (storage / "corpus").mkdir(parents=True, exist_ok=True)
        for seed in canonical.iterdir():
            if seed.is_file():
                shutil.copy2(seed, storage / "corpus" / seed.name)
        command = [
            engine_binary,
            f"--jobs={workers}",
            f"--storagePath={storage}",
            "--resume",
            *engine_args,
            target,
            *target_args,
        ]
        commands.append(("native-jobs", command, run_dir / "workers" / "native"))
    return commands


def output_patterns(profile: dict[str, Any]) -> tuple[list[str], list[str]]:
    configured_corpus = profile.get("corpusGlobs")
    configured_crashes = profile.get("crashGlobs")
    if configured_corpus or configured_crashes:
        return (
            [str(value) for value in configured_corpus or []],
            [str(value) for value in configured_crashes or []],
        )
    engine = str(profile["engine"])
    if engine == "libfuzzer":
        return [], ["libfuzzer-crashes/*"]
    if engine == "aflpp":
        return ["afl-sync/*/queue/*"], ["afl-sync/*/crashes/*", "afl-sync/*/hangs/*"]
    return ["fuzzilli-storage/corpus/**/*"], ["fuzzilli-storage/crashes/**/*"]


def scan_globs(base: Path, patterns: list[str]) -> list[Path]:
    rows: dict[str, Path] = {}
    for pattern in patterns:
        for path in base.glob(pattern):
            if path.is_file() and not path.is_symlink() and not path.name.startswith("README"):
                rows[str(path.resolve())] = path
    return [rows[key] for key in sorted(rows)]


def sync_engine_corpus(root: Path, name: str, profile: dict[str, Any], run_dir: Path) -> int:
    patterns, _ = output_patterns(profile)
    added = 0
    for path in scan_globs(run_dir, patterns):
        if path.stat().st_size > profile["maxInputBytes"]:
            continue
        _, created = add_to_corpus(
            root,
            name,
            path,
            max_input_bytes=profile["maxInputBytes"],
            provenance={
                "kind": "fuzzer-discovery",
                "engine": profile["engine"],
                "run": run_dir.name,
                "source": str(path.relative_to(run_dir)),
            },
        )
        added += int(created)
    return added


def external_crash_record(
    root: Path, name: str, profile: dict[str, Any], run_dir: Path, source: Path
) -> tuple[str, Path, bool]:
    input_digest = sha256_file(source)
    identity = (
        str(profile["target"]["sha256"]) + "\0" + input_digest
    ).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()
    destination = root / "dynamic" / "external-crashes" / digest
    destination.mkdir(parents=True, exist_ok=True)
    input_path = destination / "input.bin"
    created = not input_path.exists()
    if created:
        shutil.copyfile(source, input_path)
        atomic_json(
            destination / "external.json",
            {
                "schemaVersion": 1,
                "externalCrashId": digest,
                "firstSeenAt": utc_now(),
                "profile": name,
                "engine": profile["engine"],
                "input": artifact(input_path),
                "inputSha256": input_digest,
                "targetSha256": profile["target"]["sha256"],
                "replay": None,
                "classification": "unconfirmed external-fuzzer artifact",
            },
        )
    append_jsonl(
        destination / "origins.jsonl",
        {
            "at": utc_now(),
            "profile": name,
            "engine": profile["engine"],
            "run": run_dir.name,
            "source": str(source.relative_to(run_dir)),
        },
    )
    return digest, destination, created


def replay_template(profile: dict[str, Any]) -> list[str]:
    target = str(profile["target"]["path"])
    target_args = [str(value) for value in profile.get("targetArgs", [])]
    if profile["engine"] == "libfuzzer":
        return [target, "-runs=1", "{input}"]
    replaced = ["{input}" if value == "@@" else value for value in target_args]
    if "{input}" not in replaced:
        replaced.append("{input}")
    return [target, *replaced]


def forward_crash(root: Path, name: str, profile: dict[str, Any], crash_dir: Path) -> dict[str, Any]:
    input_path = crash_dir / "input.bin"
    command = [
        sys.executable,
        str(DYNAMIC_HARNESS),
        "run",
        str(root),
        "--input-file",
        str(input_path),
        "--name",
        f"external-{name}",
        "--input-mode",
        "file",
        "--cwd",
        str(profile["cwd"]),
        "--timeout-ms",
        "10000",
        "--max-output-bytes",
        str(4 * 1024 * 1024),
        "--max-input-bytes",
        str(profile["maxInputBytes"]),
        "--target-artifact",
        str(profile["target"]["path"]),
        "--",
        *replay_template(profile),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    crash_id = None
    run_value = None
    for line in completed.stdout.splitlines():
        if line.startswith("crash: "):
            crash_id = line.split(": ", 1)[1].strip()
        elif line.startswith("run: "):
            run_value = line.split(": ", 1)[1].strip()
    result = {
        "at": utc_now(),
        "command": command,
        "exitCode": completed.returncode,
        "stdout": completed.stdout[-16384:],
        "stderr": completed.stderr[-16384:],
        "runId": run_value,
        "crashId": crash_id,
        "confirmed": crash_id is not None,
    }
    record = read_json(crash_dir / "external.json")
    record["replay"] = result
    record["classification"] = (
        "replay-confirmed Krineon crash" if crash_id else "external artifact did not reproduce"
    )
    atomic_json(crash_dir / "external.json", record)
    return result


def ingest_crashes(
    root: Path,
    name: str,
    profile: dict[str, Any],
    run_dir: Path,
    *,
    forward: bool,
) -> tuple[list[dict[str, Any]], int]:
    _, patterns = output_patterns(profile)
    rows: list[dict[str, Any]] = []
    new_count = 0
    for source in scan_globs(run_dir, patterns):
        if source.stat().st_size > profile["maxInputBytes"]:
            continue
        external_id, destination, created = external_crash_record(
            root, name, profile, run_dir, source
        )
        replay = None
        if forward:
            existing = read_json(destination / "external.json").get("replay")
            replay = existing if isinstance(existing, dict) else forward_crash(
                root, name, profile, destination
            )
        rows.append(
            {
                "externalCrashId": external_id,
                "source": str(source.relative_to(run_dir)),
                "new": created,
                "forwarded": replay,
            }
        )
        new_count += int(created)
    return rows, new_count


def collect_engine_stats(engine: str, run_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    patterns = ["afl-sync/*/fuzzer_stats"] if engine == "aflpp" else []
    patterns += ["fuzzilli-storage/statistics*.json"] if engine == "fuzzilli" else []
    for path in scan_globs(run_dir, patterns):
        text = path.read_text(encoding="utf-8", errors="replace")
        parsed: Any = None
        if path.suffix == ".json":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
        else:
            values: dict[str, str] = {}
            for line in text.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    values[key.strip()] = value.strip()
            parsed = values
        records.append(
            {
                "path": str(path.relative_to(run_dir)),
                "sha256": sha256_file(path),
                "parsed": parsed,
            }
        )
    return records


def cmd_launch(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    instrumentation = profile.get("instrumentation")
    if not isinstance(instrumentation, dict) or instrumentation.get("verified") is not True:
        raise FuzzerError(
            "profile has no verified instrumentation; run instrument or register explicit preinstrumented evidence"
        )
    canonical = corpus_dir(root, args.name)
    if not canonical.is_dir() or not any(path.is_file() for path in canonical.iterdir()):
        raise FuzzerError("canonical corpus is empty; run seed-harvest or structured-generate")
    initial_corpus_inputs = sum(1 for path in canonical.iterdir() if path.is_file())
    initial_corpus = corpus_snapshot(canonical)
    launch_id = run_id()
    run_dir = profile_root(root, args.name) / "runs" / launch_id
    run_dir.mkdir(parents=True, exist_ok=False)
    commands = command_for_workers(profile, run_dir, args.workers, args.duration_seconds)
    env = os.environ.copy()
    env.update(parse_env(args.env or []))
    if profile["engine"] == "aflpp":
        env.setdefault("AFL_NO_UI", "1")
        env.setdefault("AFL_AUTORESUME", "1")
    processes: list[tuple[str, ManagedProcess]] = []
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "launchId": launch_id,
        "profile": args.name,
        "engine": profile["engine"],
        "revision": profile["revision"],
        "createdAt": utc_now(),
        "status": "running",
        "workersRequested": args.workers,
        "parallelism": (
            "native jobs/workers" if profile["engine"] in {"libfuzzer", "fuzzilli"} else "AFL master/secondary sync"
        ),
        "commands": [{"worker": worker, "command": command} for worker, command, _ in commands],
        "syncIntervalSeconds": args.sync_interval_seconds,
        "forwardCrashes": args.forward_crashes,
        "target": profile["target"],
        "engineBinary": profile["engineBinary"],
        "instrumentation": profile.get("instrumentation"),
        "initialCorpus": initial_corpus,
    }
    atomic_json(run_dir / "run.json", record)
    try:
        for worker, command, output_dir in commands:
            processes.append(
                (
                    worker,
                    ManagedProcess(
                        command,
                        cwd=Path(profile["cwd"]),
                        env=env,
                        output_dir=output_dir,
                        max_output_bytes=args.max_output_bytes,
                    ),
                )
            )
        deadline = time.monotonic() + args.duration_seconds
        corpus_added = 0
        while time.monotonic() < deadline:
            corpus_added += sync_engine_corpus(root, args.name, profile, run_dir)
            if all(process.process.poll() is not None for _, process in processes):
                break
            time.sleep(min(args.sync_interval_seconds, max(0.05, deadline - time.monotonic())))
        corpus_added += sync_engine_corpus(root, args.name, profile, run_dir)
        crashes, new_crashes = ingest_crashes(
            root,
            args.name,
            profile,
            run_dir,
            forward=args.forward_crashes,
        )
        workers = [
            {"worker": worker, **process.finish()} for worker, process in processes
        ]
        engine_stats = collect_engine_stats(profile["engine"], run_dir)
        final_corpus_inputs = sum(1 for path in canonical.iterdir() if path.is_file())
        final_corpus = corpus_snapshot(canonical)
        record.update(
            {
                "status": "completed",
                "endedAt": utc_now(),
                "workers": workers,
                "engineStats": engine_stats,
                "summary": {
                    "corpusInputs": final_corpus_inputs,
                    "newCorpusInputs": max(0, final_corpus_inputs - initial_corpus_inputs),
                    "corpusImportsFromWorkerOutputs": corpus_added,
                    "externalCrashes": len(crashes),
                    "newExternalCrashes": new_crashes,
                    "replayConfirmedCrashes": sum(
                        row.get("forwarded", {}).get("confirmed") is True for row in crashes
                    ),
                    "coverageRebuilt": False,
                    "crashClassification": (
                        "Only replay-confirmed crashes enter dynamic/crashes and automated triage."
                    ),
                },
                "crashes": crashes,
                "finalCorpus": final_corpus,
            }
        )
    except Exception as exc:
        for _, process in processes:
            terminate_process(process.process)
        record.update({"status": "failed", "endedAt": utc_now(), "error": str(exc)})
        atomic_json(run_dir / "run.json", record)
        raise
    atomic_json(run_dir / "run.json", record)
    print(f"fuzzer run: {launch_id}")
    print(f"engine: {profile['engine']}; parallel workers: {args.workers}")
    print(
        f"corpus: {record['summary']['corpusInputs']}; "
        f"replay-confirmed crashes: {record['summary']['replayConfirmedCrashes']}"
    )
    print(f"record: {(run_dir / 'run.json').relative_to(root)}")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    runs_root = profile_root(root, args.name) / "runs"
    run_dirs = (
        [runs_root / args.run_id]
        if args.run_id
        else sorted(path for path in runs_root.iterdir() if path.is_dir()) if runs_root.is_dir() else []
    )
    added = 0
    crashes = 0
    confirmed = 0
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            raise FuzzerError(f"unknown fuzzer run: {run_dir.name}")
        added += sync_engine_corpus(root, args.name, profile, run_dir)
        rows, _ = ingest_crashes(
            root, args.name, profile, run_dir, forward=args.forward_crashes
        )
        crashes += len(rows)
        confirmed += sum(row.get("forwarded", {}).get("confirmed") is True for row in rows)
    print(f"runs synchronized: {len(run_dirs)}")
    print(f"new corpus inputs: {added}; crash artifacts: {crashes}; confirmed: {confirmed}")
    return 0


def replace_input_token(arguments: list[str], input_path: Path) -> list[str]:
    replaced = [str(input_path) if value in {"@@", "{input}"} else value for value in arguments]
    if str(input_path) not in replaced:
        replaced.append(str(input_path))
    return replaced


def coverage_target_command(profile: dict[str, Any], input_path: Path) -> list[str]:
    target = str(profile["target"]["path"])
    if profile["engine"] == "libfuzzer":
        return [target, "-runs=1", str(input_path)]
    return [
        target,
        *replace_input_token(
            [str(value) for value in profile.get("targetArgs", [])], input_path
        ),
    ]


def cmd_coverage_rebuild(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    instrumentation = profile.get("instrumentation")
    if not isinstance(instrumentation, dict) or instrumentation.get("verified") is not True:
        raise FuzzerError("coverage rebuild requires a verified instrumented target")
    inputs = sorted(path for path in corpus_dir(root, args.name).iterdir() if path.is_file())
    if not inputs:
        raise FuzzerError("canonical corpus is empty")
    coverage_id = run_id()
    output_dir = profile_root(root, args.name) / "coverage" / coverage_id
    output_dir.mkdir(parents=True, exist_ok=False)
    target = Path(profile["target"]["path"])
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "coverageId": coverage_id,
        "mode": args.mode,
        "createdAt": utc_now(),
        "profile": args.name,
        "target": profile["target"],
        "instrumentation": profile.get("instrumentation"),
        "corpusInputs": len(inputs),
        "runs": [],
    }
    if args.mode == "afl-showmap":
        tool = resolve_file(args.tool, label="afl-showmap", executable=True)
        aggregate: set[str] = set()
        for index, input_path in enumerate(inputs):
            map_path = output_dir / "maps" / f"{index:08d}.map"
            map_path.parent.mkdir(parents=True, exist_ok=True)
            target_command = coverage_target_command(profile, input_path)
            command = [
                str(tool),
                "-q",
                "-o",
                str(map_path),
                "--",
                *target_command,
            ]
            result = run_bounded_command(
                command,
                cwd=Path(profile["cwd"]),
                env=os.environ.copy(),
                timeout_seconds=args.timeout_seconds,
                output_dir=output_dir / "commands" / f"{index:08d}",
                max_output_bytes=args.max_output_bytes,
            )
            edges: set[str] = set()
            if map_path.is_file():
                edges = {
                    line.split(":", 1)[0].strip()
                    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                }
                aggregate.update(edges)
            record["runs"].append(
                {
                    "input": artifact(input_path),
                    "command": command,
                    "result": result,
                    "edges": len(edges),
                }
            )
        edge_path = output_dir / "edges.txt"
        edge_path.write_text("\n".join(sorted(aggregate)) + "\n", encoding="utf-8")
        record["coverage"] = {"uniqueEdges": len(aggregate), "artifact": artifact(edge_path)}
        record["tool"] = artifact(tool)
    else:
        profdata_tool = resolve_file(args.llvm_profdata, label="llvm-profdata", executable=True)
        cov_tool = resolve_file(args.llvm_cov, label="llvm-cov", executable=True)
        raw_files: list[Path] = []
        for index, input_path in enumerate(inputs):
            raw = output_dir / "profraw" / f"{index:08d}.profraw"
            raw.parent.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env["LLVM_PROFILE_FILE"] = str(raw)
            command = coverage_target_command(profile, input_path)
            result = run_bounded_command(
                command,
                cwd=Path(profile["cwd"]),
                env=env,
                timeout_seconds=args.timeout_seconds,
                output_dir=output_dir / "commands" / f"{index:08d}",
                max_output_bytes=args.max_output_bytes,
            )
            if raw.is_file():
                raw_files.append(raw)
            record["runs"].append(
                {"input": artifact(input_path), "command": command, "result": result}
            )
        if not raw_files:
            raise FuzzerError("LLVM coverage run produced no .profraw files")
        merged = output_dir / "merged.profdata"
        merge = subprocess.run(
            [str(profdata_tool), "merge", "-sparse", *map(str, raw_files), "-o", str(merged)],
            check=False,
            capture_output=True,
            text=True,
            timeout=args.timeout_seconds,
        )
        if merge.returncode != 0:
            raise FuzzerError("llvm-profdata merge failed: " + merge.stderr[-4000:])
        export_command = [
            str(cov_tool),
            "export",
            str(target),
            f"-instr-profile={merged}",
        ]
        export_result = run_bounded_command(
            export_command,
            cwd=Path(profile["cwd"]),
            env=os.environ.copy(),
            timeout_seconds=args.timeout_seconds,
            output_dir=output_dir / "export-command",
            max_output_bytes=args.max_coverage_bytes,
        )
        if export_result["timedOut"] or export_result["returnCode"] != 0:
            raise FuzzerError("llvm-cov export failed")
        if export_result["stdout"].get("truncated") is True:
            raise FuzzerError("llvm-cov export exceeds --max-coverage-bytes")
        export_path = output_dir / "coverage.json"
        shutil.copyfile(export_result["stdout"]["path"], export_path)
        record["coverage"] = {
            "profrawFiles": len(raw_files),
            "merged": artifact(merged),
            "export": artifact(export_path),
            "exportCommand": export_result,
        }
        record["tools"] = {
            "llvmProfdata": artifact(profdata_tool),
            "llvmCov": artifact(cov_tool),
        }
    record["endedAt"] = utc_now()
    record["status"] = "completed"
    record_path = output_dir / ("coverage.json" if args.mode == "afl-showmap" else "record.json")
    atomic_json(record_path, record)
    coverage_rows = profile.get("coverageRebuilds")
    if not isinstance(coverage_rows, list):
        coverage_rows = []
    coverage_rows.append(
        {
            "coverageId": coverage_id,
            "mode": args.mode,
            "record": str(record_path.relative_to(root)),
            "at": record["endedAt"],
        }
    )
    profile["coverageRebuilds"] = coverage_rows
    atomic_json(profile_path(root, args.name), profile)
    print(f"coverage rebuild: {coverage_id}")
    print(f"mode: {args.mode}; corpus inputs: {len(inputs)}")
    print(f"record: {output_dir.relative_to(root)}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    profile = require_profile(root, args.name)
    runs_root = profile_root(root, args.name) / "runs"
    runs = []
    if runs_root.is_dir():
        for path in sorted(runs_root.iterdir()):
            if path.is_dir() and (path / "run.json").is_file():
                run = read_json(path / "run.json")
                runs.append(
                    {
                        "launchId": run.get("launchId"),
                        "status": run.get("status"),
                        "summary": run.get("summary"),
                    }
                )
    payload = {
        "profile": profile,
        "corpusInputs": sum(1 for path in corpus_dir(root, args.name).iterdir() if path.is_file()),
        "runs": runs,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"profile: {args.name} ({profile['engine']})")
        print(f"corpus inputs: {payload['corpusInputs']}")
        print(f"runs: {len(runs)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="pin an external fuzzer and target")
    register.add_argument("campaign_dir")
    register.add_argument("name")
    register.add_argument("--engine", choices=ENGINES, required=True)
    register.add_argument("--engine-binary")
    register.add_argument("--target", required=True)
    register.add_argument("--revision", required=True)
    register.add_argument("--cwd")
    register.add_argument("--target-arg", action="append")
    register.add_argument("--engine-arg", action="append")
    register.add_argument(
        "--corpus-glob",
        action="append",
        help="version-specific run-directory corpus glob; repeatable",
    )
    register.add_argument(
        "--crash-glob",
        action="append",
        help="version-specific run-directory crash glob; repeatable",
    )
    register.add_argument("--dictionary")
    register.add_argument("--preinstrumented-kind", choices=INSTRUMENTATION_KINDS)
    register.add_argument("--instrumentation-evidence", action="append")
    register.add_argument("--max-input-bytes", type=int, default=16 * 1024 * 1024)
    register.add_argument("--note")
    register.add_argument("--replace", action="store_true")
    register.set_defaults(func=cmd_register)

    instrument = sub.add_parser("instrument", help="run and retain an instrumented build")
    instrument.add_argument("campaign_dir")
    instrument.add_argument("name")
    instrument.add_argument("--kind", choices=INSTRUMENTATION_KINDS, required=True)
    instrument.add_argument("--build-command-json", required=True)
    instrument.add_argument("--verify-command-json")
    instrument.add_argument("--verify-output-contains")
    instrument.add_argument("--cwd")
    instrument.add_argument("--env", action="append")
    instrument.add_argument("--timeout-seconds", type=int, default=3600)
    instrument.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    instrument.set_defaults(func=cmd_instrument)

    harvest = sub.add_parser("seed-harvest", help="deduplicate seeds from source tests and fixtures")
    harvest.add_argument("campaign_dir")
    harvest.add_argument("name")
    harvest.add_argument("--source", action="append", required=True)
    harvest.add_argument("--extension", action="append")
    harvest.add_argument("--max-files", type=int, default=100000)
    harvest.add_argument("--max-total-bytes", type=int, default=4 * 1024 * 1024 * 1024)
    harvest.set_defaults(func=cmd_seed_harvest)

    generate = sub.add_parser("structured-generate", help="run a grammar or structured seed generator")
    generate.add_argument("campaign_dir")
    generate.add_argument("name")
    generate.add_argument("--command-json", required=True)
    generate.add_argument("--count", type=int, default=100)
    generate.add_argument("--seed", type=int, default=0)
    generate.add_argument("--suffix", default=".bin")
    generate.add_argument("--cwd")
    generate.add_argument("--timeout-seconds", type=int, default=60)
    generate.add_argument("--max-output-bytes", type=int, default=1024 * 1024)
    generate.set_defaults(func=cmd_structured_generate)

    launch = sub.add_parser("launch", help="launch native parallel workers and synchronize corpus")
    launch.add_argument("campaign_dir")
    launch.add_argument("name")
    launch.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1))
    launch.add_argument("--duration-seconds", type=int, default=3600)
    launch.add_argument("--sync-interval-seconds", type=float, default=30.0)
    launch.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    launch.add_argument("--env", action="append")
    launch.add_argument("--forward-crashes", action="store_true")
    launch.set_defaults(func=cmd_launch)

    sync = sub.add_parser("sync", help="merge worker corpora and forward crash artifacts")
    sync.add_argument("campaign_dir")
    sync.add_argument("name")
    sync.add_argument("--run-id")
    sync.add_argument("--forward-crashes", action="store_true")
    sync.set_defaults(func=cmd_sync)

    coverage = sub.add_parser("coverage-rebuild", help="rebuild coverage from the canonical corpus")
    coverage.add_argument("campaign_dir")
    coverage.add_argument("name")
    coverage.add_argument("--mode", choices=("afl-showmap", "llvm"), required=True)
    coverage.add_argument("--tool", help="afl-showmap binary")
    coverage.add_argument("--llvm-profdata")
    coverage.add_argument("--llvm-cov")
    coverage.add_argument("--timeout-seconds", type=int, default=30)
    coverage.add_argument("--max-output-bytes", type=int, default=1024 * 1024)
    coverage.add_argument("--max-coverage-bytes", type=int, default=256 * 1024 * 1024)
    coverage.set_defaults(func=cmd_coverage_rebuild)

    status = sub.add_parser("status", help="show corpus and external fuzzer runs")
    status.add_argument("campaign_dir")
    status.add_argument("name")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)
    return parser


def validate_positive(args: argparse.Namespace) -> None:
    for name in (
        "max_input_bytes",
        "timeout_seconds",
        "max_output_bytes",
        "max_files",
        "max_total_bytes",
        "count",
        "workers",
        "duration_seconds",
        "sync_interval_seconds",
        "max_coverage_bytes",
    ):
        if hasattr(args, name) and getattr(args, name) <= 0:
            raise FuzzerError(f"--{name.replace('_', '-')} must be positive")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        validate_positive(args)
        if args.command == "coverage-rebuild":
            if args.mode == "afl-showmap" and not args.tool:
                raise FuzzerError("--tool is required for afl-showmap coverage")
            if args.mode == "llvm" and (not args.llvm_profdata or not args.llvm_cov):
                raise FuzzerError("--llvm-profdata and --llvm-cov are required for LLVM coverage")
        return int(args.func(args))
    except (FuzzerError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
