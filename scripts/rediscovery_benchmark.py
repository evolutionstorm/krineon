#!/usr/bin/env python3
"""Measure blind time-to-rediscover against a frozen local corpus.

The evaluator keeps the oracle file outside the worker workspace.  Krineon
stores only its hash in the campaign.  Search output is JSONL with an
``identity`` field; elapsed time is recorded when an identity first matches a
target-owned test or invariant oracle.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_manifest(root: Path) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return rows


def manifest_digest(rows: list[dict[str, Any]]) -> str:
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def campaign_root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise SystemExit(f"not a Krineon campaign: {root}")
    return root


def benchmark_dir(root: Path, name: str) -> Path:
    if not name or not all(character.isalnum() or character in "-_" for character in name):
        raise SystemExit("benchmark name must contain only letters, digits, hyphen, or underscore")
    return root / "benchmarks" / name


def validate_oracles(path: Path, checkout: Path) -> list[dict[str, Any]]:
    data = read_json(path)
    raw = data.get("oracles") if isinstance(data, dict) else None
    if not isinstance(raw, list) or not raw:
        raise SystemExit("sealed oracle file must contain a non-empty oracles list")
    result = []
    seen: set[str] = set()
    for index, oracle in enumerate(raw):
        if not isinstance(oracle, dict):
            raise SystemExit(f"oracle {index} is not an object")
        oracle_id = str(oracle.get("id") or "").strip()
        basis = str(oracle.get("basis") or "").strip()
        identity = str(oracle.get("identity") or "").strip()
        source_value = str(oracle.get("sourcePath") or "").strip()
        if not oracle_id or oracle_id in seen or not identity or not source_value:
            raise SystemExit(f"oracle {index} has missing or duplicate identity fields")
        if basis not in {"target-test", "target-invariant"}:
            raise SystemExit("oracle basis must be target-test or target-invariant")
        source = (checkout / source_value).resolve()
        try:
            source.relative_to(checkout)
        except ValueError as error:
            raise SystemExit("oracle source escapes the pinned checkout") from error
        if not source.is_file():
            raise SystemExit(f"oracle source does not exist: {source_value}")
        observed = sha256_file(source)
        supplied = str(oracle.get("sourceSha256") or "")
        if supplied != observed:
            raise SystemExit(f"oracle source hash mismatch: {source_value}")
        seen.add(oracle_id)
        result.append(
            {
                "id": oracle_id,
                "basis": basis,
                "identity": identity,
                "sourcePath": source_value,
                "sourceSha256": observed,
            }
        )
    return result


def cmd_freeze(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    destination = benchmark_dir(root, args.name)
    if destination.exists():
        raise SystemExit(f"benchmark already exists: {destination}")
    campaign = read_json(root / "campaign.json")
    checkout_value = args.checkout or campaign.get("localCheckout")
    if not checkout_value:
        raise SystemExit("freeze requires --checkout or campaign.localCheckout")
    checkout = Path(str(checkout_value)).expanduser().resolve()
    corpus = Path(args.corpus).expanduser().resolve()
    oracle_file = Path(args.sealed_oracles).expanduser().resolve()
    oracles = validate_oracles(oracle_file, checkout)
    destination.mkdir(parents=True)
    frozen_corpus = destination / "corpus"
    shutil.copytree(corpus, frozen_corpus)
    corpus_rows = tree_manifest(frozen_corpus)
    targets = []
    for value in args.target_artifact:
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise SystemExit(f"target artifact is not a file: {path}")
        targets.append({"path": str(path), "size": path.stat().st_size, "sha256": sha256_file(path)})
    manifest = {
        "schemaVersion": 1,
        "name": args.name,
        "createdAt": utc_now(),
        "campaignRevision": campaign.get("commit"),
        "checkout": str(checkout),
        "targetArtifacts": targets,
        "corpus": {
            "path": str(frozen_corpus.relative_to(root)),
            "files": corpus_rows,
            "sha256": manifest_digest(corpus_rows),
        },
        "sealedOracleSha256": sha256_file(oracle_file),
        "oracleCount": len(oracles),
        "oracleBases": sorted({oracle["basis"] for oracle in oracles}),
        "oracleIdentitiesExposedToWorker": False,
        "discoveryInputs": {
            "targetOwnedTestsAndInvariantsAllowed": True,
            "patchHistoryMiningAllowed": False,
        },
    }
    write_json(destination / "manifest.json", manifest)
    write_json(
        destination / "status.json",
        {
            "schemaVersion": 1,
            "name": args.name,
            "status": "frozen-unmeasured",
            "hoursToFirstRediscovery": None,
            "recall": None,
            "runs": [],
        },
    )
    print(json.dumps({"benchmark": args.name, "manifest": str((destination / 'manifest.json').relative_to(root))}, indent=2))
    return 0


def verify_frozen(root: Path, manifest: dict[str, Any]) -> None:
    for target in manifest.get("targetArtifacts", []):
        path = Path(str(target.get("path") or "")).resolve()
        if not path.is_file() or sha256_file(path) != target.get("sha256"):
            raise SystemExit(f"frozen target artifact changed: {path}")
    corpus = root / str(manifest["corpus"]["path"])
    rows = tree_manifest(corpus)
    if rows != manifest["corpus"]["files"] or manifest_digest(rows) != manifest["corpus"]["sha256"]:
        raise SystemExit("frozen benchmark corpus changed")


def cmd_run(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    directory = benchmark_dir(root, args.name)
    manifest = read_json(directory / "manifest.json")
    verify_frozen(root, manifest)
    sealed_path = Path(args.sealed_oracles).expanduser().resolve()
    if sha256_file(sealed_path) != manifest.get("sealedOracleSha256"):
        raise SystemExit("sealed oracle file does not match the frozen benchmark")
    checkout = Path(manifest["checkout"]).resolve()
    oracles = validate_oracles(sealed_path, checkout)
    oracle_by_identity = {oracle["identity"]: oracle for oracle in oracles}
    command = json.loads(args.command_json)
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise SystemExit("--command-json must be a non-empty JSON argv array")
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir = directory / "runs" / run_id
    run_dir.mkdir(parents=True)
    stderr_path = run_dir / "stderr.txt"
    stdout_path = run_dir / "stdout.jsonl"
    environment = os.environ.copy()
    environment["KRINEON_BENCHMARK_CORPUS"] = str((root / manifest["corpus"]["path"]).resolve())
    environment["KRINEON_BENCHMARK_CHECKOUT"] = str(checkout)
    environment["KRINEON_BENCHMARK_NAME"] = args.name
    started_wall = utc_now()
    started = time.monotonic()
    matches: dict[str, dict[str, Any]] = {}
    parsed_events = 0
    timed_out = False
    with stderr_path.open("wb") as stderr_handle, stdout_path.open("wb") as stdout_handle:
        process = subprocess.Popen(
            command,
            cwd=str(checkout),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=stderr_handle,
            start_new_session=True,
        )
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        buffer = b""
        while True:
            elapsed = time.monotonic() - started
            if elapsed > args.timeout_seconds and process.poll() is None:
                timed_out = True
                process.kill()
            events = selector.select(timeout=0.05)
            for key, _ in events:
                chunk = key.fileobj.read1(65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stdout_handle.write(chunk)
                stdout_handle.flush()
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        event = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    parsed_events += 1
                    identity = str(event.get("identity") or "") if isinstance(event, dict) else ""
                    if identity in oracle_by_identity and identity not in matches:
                        matches[identity] = {
                            "oracleId": oracle_by_identity[identity]["id"],
                            "basis": oracle_by_identity[identity]["basis"],
                            "elapsedSeconds": time.monotonic() - started,
                            "eventSha256": hashlib.sha256(line).hexdigest(),
                        }
            if process.poll() is not None and not selector.get_map():
                break
    elapsed_seconds = time.monotonic() - started
    first = min((item["elapsedSeconds"] for item in matches.values()), default=None)
    result = {
        "schemaVersion": 1,
        "runId": run_id,
        "startedAt": started_wall,
        "finishedAt": utc_now(),
        "command": command,
        "commandSha256": hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
        "returnCode": process.returncode,
        "timedOut": timed_out,
        "elapsedSeconds": elapsed_seconds,
        "parsedLeadEvents": parsed_events,
        "matchedOracles": sorted(matches.values(), key=lambda item: item["elapsedSeconds"]),
        "matchedOracleCount": len(matches),
        "oracleCount": len(oracles),
        "recall": len(matches) / len(oracles),
        "secondsToFirstRediscovery": first,
        "hoursToFirstRediscovery": first / 3600 if first is not None else None,
        "stdout": {"path": str(stdout_path.relative_to(root)), "sha256": sha256_file(stdout_path)},
        "stderr": {"path": str(stderr_path.relative_to(root)), "sha256": sha256_file(stderr_path)},
        "frozenCorpusSha256": manifest["corpus"]["sha256"],
        "sealedOracleSha256": manifest["sealedOracleSha256"],
    }
    write_json(run_dir / "result.json", result)
    status_path = directory / "status.json"
    status = read_json(status_path)
    status.setdefault("runs", []).append(str((run_dir / "result.json").relative_to(root)))
    if first is not None:
        status.update(
            {
                "status": "measured",
                "hoursToFirstRediscovery": result["hoursToFirstRediscovery"],
                "recall": result["recall"],
                "latestRun": str((run_dir / "result.json").relative_to(root)),
            }
        )
    else:
        status["status"] = "measured-no-rediscovery"
        status["latestRun"] = str((run_dir / "result.json").relative_to(root))
    write_json(status_path, status)
    print(json.dumps(result, indent=2))
    return 0 if first is not None else 1


def cmd_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    status = read_json(benchmark_dir(root, args.name) / "status.json")
    print(json.dumps(status, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("campaign_dir")
    freeze.add_argument("name")
    freeze.add_argument("--checkout")
    freeze.add_argument("--corpus", required=True)
    freeze.add_argument("--sealed-oracles", required=True)
    freeze.add_argument("--target-artifact", action="append", required=True)
    freeze.set_defaults(func=cmd_freeze)
    run = commands.add_parser("run")
    run.add_argument("campaign_dir")
    run.add_argument("name")
    run.add_argument("--sealed-oracles", required=True)
    run.add_argument("--command-json", required=True)
    run.add_argument("--timeout-seconds", type=float, default=3600)
    run.set_defaults(func=cmd_run)
    status = commands.add_parser("status")
    status.add_argument("campaign_dir")
    status.add_argument("name")
    status.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "timeout_seconds", 1) <= 0:
        raise SystemExit("timeout must be positive")
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
