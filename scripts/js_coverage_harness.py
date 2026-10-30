#!/usr/bin/env python3
"""Exercise persistent Node workers and rebuild V8/Istanbul source-mapped coverage."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import glob
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
WORKER = PROJECT / "scripts" / "js_persistent_worker.mjs"
REMAPPER = PROJECT / "scripts" / "js_coverage_remap.mjs"
RESEARCH_HARNESS = PROJECT / "scripts" / "research_harness.py"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def campaign(root: Path) -> dict[str, Any]:
    path = root / "campaign.json"
    if not path.is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    value = json.loads(path.read_text(encoding="utf-8"))
    authorization = value.get("authorization") if isinstance(value, dict) else None
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise RuntimeError("JavaScript execution requires confirmed campaign authorization")
    if value.get("mode") not in {"source", "local-lab"}:
        raise RuntimeError("JavaScript execution is limited to source or local-lab campaigns")
    return value


def resolve_under(root: Path, value: str, label: str, *, file: bool = True) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    candidate.relative_to(root)
    if file and not candidate.is_file():
        raise RuntimeError(f"{label} is not a file: {candidate}")
    if not file and not candidate.is_dir():
        raise RuntimeError(f"{label} is not a directory: {candidate}")
    return candidate


def resolve_project(spec_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = spec_root / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise RuntimeError(f"projectRoot is not a directory: {candidate}")
    return candidate


def resolve_runtime(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute() or "/" in value:
        candidate = candidate.resolve()
    else:
        located = shutil.which(value)
        if not located:
            raise RuntimeError(f"runtime is unavailable: {value}")
        candidate = Path(located).absolute()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError(f"runtime is not executable: {candidate}")
    return candidate


def input_files(project_root: Path, patterns: list[Any], maximum: int) -> list[Path]:
    result: set[Path] = set()
    for pattern in patterns:
        value = str(pattern)
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise RuntimeError(f"input glob must be project-relative: {value}")
        for match in glob.glob(str(project_root / value), recursive=True):
            path = Path(match).resolve()
            path.relative_to(project_root)
            if path.is_file() and not path.is_symlink():
                result.add(path)
                if len(result) > maximum:
                    raise RuntimeError("input set exceeds maxInputs")
    if not result:
        raise RuntimeError("no JavaScript coverage inputs matched")
    return sorted(result)


class PersistentWorker:
    def __init__(
        self,
        *,
        index: int,
        runtime: Path,
        module: Path,
        export_name: str,
        reset_export: str | None,
        input_mode: str,
        output: Path,
        coverage_prefix: Path,
        environment: dict[str, str],
    ):
        self.index = index
        self.output = output
        self.output.mkdir(parents=True, exist_ok=False)
        self.v8_dir = self.output / "v8"
        self.v8_dir.mkdir()
        self.istanbul = self.output / "istanbul.json"
        self.native_edges = self.output / "native-edge-ids.txt"
        self.native_timeline = self.output / "native-timeline.jsonl"
        command = [
            str(runtime),
            "--enable-source-maps",
            str(WORKER),
            "--module",
            str(module),
            "--export",
            export_name,
            "--input-mode",
            input_mode,
        ]
        if reset_export:
            command.extend(["--reset-export", reset_export])
        env = dict(environment)
        env["NODE_V8_COVERAGE"] = str(self.v8_dir)
        env["KRINEON_ISTANBUL_COVERAGE"] = str(self.istanbul)
        env["KRINEON_NATIVE_EDGE_FILE"] = str(self.native_edges)
        env["KRINEON_NATIVE_TIMELINE_FILE"] = str(self.native_timeline)
        env["KRINEON_COVERAGE_INCLUDE_PREFIX"] = str(coverage_prefix)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        assert self.process.stdin and self.process.stdout and self.process.stderr
        self.command = command
        self.responses: queue.Queue[bytes | None] = queue.Queue()
        self.stderr = bytearray()
        self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stdout_thread.start()
        self.stderr_thread.start()
        self.processed = 0

    def _read_stdout(self) -> None:
        assert self.process.stdout
        for line in self.process.stdout:
            self.responses.put(line)
        self.responses.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr
        for chunk in iter(lambda: self.process.stderr.read(65536), b""):
            if len(self.stderr) < 16 * 1024 * 1024:
                self.stderr.extend(chunk[: 16 * 1024 * 1024 - len(self.stderr)])

    def exchange(self, message: dict[str, Any], timeout: float) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError(f"persistent worker {self.index} exited with {self.process.returncode}")
        assert self.process.stdin
        self.process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        self.process.stdin.flush()
        try:
            line = self.responses.get(timeout=timeout)
        except queue.Empty as error:
            raise RuntimeError(f"persistent worker {self.index} timed out") from error
        if line is None:
            raise RuntimeError(f"persistent worker {self.index} closed stdout")
        response = json.loads(line)
        if response.get("id") != message.get("id"):
            raise RuntimeError(f"persistent worker {self.index} response ID mismatch")
        self.processed += int(message.get("command") != "shutdown")
        return response

    def close(self, timeout: float) -> dict[str, Any]:
        shutdown = None
        try:
            if self.process.poll() is None:
                shutdown = self.exchange({"id": f"shutdown-{self.index}", "command": "shutdown"}, timeout)
            self.process.wait(timeout=timeout)
        except Exception:
            self.process.kill()
            self.process.wait(timeout=5)
            raise
        finally:
            if self.process.stdin:
                self.process.stdin.close()
            self.stdout_thread.join(timeout=3)
            self.stderr_thread.join(timeout=3)
            (self.output / "stderr.log").write_bytes(bytes(self.stderr))
        return {
            "index": self.index,
            "pid": self.process.pid,
            "command": self.command,
            "processed": self.processed,
            "shutdown": shutdown,
            "returnCode": self.process.returncode,
            "stderr": artifact(self.output / "stderr.log"),
            "v8CoverageFiles": [artifact(path) for path in sorted(self.v8_dir.glob("*.json"))],
            "istanbulCoverage": artifact(self.istanbul) if self.istanbul.is_file() else None,
            "nativeEdges": artifact(self.native_edges) if self.native_edges.is_file() else None,
            "nativeTimeline": artifact(self.native_timeline) if self.native_timeline.is_file() else None,
        }


def run_worker_inputs(
    worker: PersistentWorker,
    rows: list[tuple[int, Path]],
    *,
    project_root: Path,
    max_input_bytes: int,
    timeout: float,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, path in rows:
        data = path.read_bytes()
        if len(data) > max_input_bytes:
            raise RuntimeError(f"input exceeds maxInputBytes: {path}")
        digest = hashlib.sha256(data).hexdigest()
        response = worker.exchange(
            {
                "id": f"input-{index:08d}",
                "inputBase64": base64.b64encode(data).decode(),
                "metadata": {"path": path.relative_to(project_root).as_posix(), "sha256": digest},
            },
            timeout,
        )
        records.append(
            {
                "index": index,
                "input": {"path": path.relative_to(project_root).as_posix(), "sha256": digest, "size": len(data)},
                "worker": worker.index,
                "response": response,
            }
        )
    return records


def read_edge_ids(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    if path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and isinstance(value.get("edges"), list):
            return {str(row["id"]) for row in value["edges"] if isinstance(row, dict) and row.get("id")}
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def native_coverage_timeline(
    worker_records: list[dict[str, Any]],
    *,
    started_unix_ms: float,
    finished_unix_ms: float,
    plateau_seconds: float,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for worker in worker_records:
        timeline = worker.get("nativeTimeline")
        if not isinstance(timeline, dict):
            continue
        path = Path(str(timeline["path"]))
        for sequence, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or not isinstance(row.get("newEdges"), list):
                raise RuntimeError(f"invalid native coverage event: {path}:{sequence + 1}")
            events.append({**row, "worker": int(worker["index"]), "sequence": sequence})
    events.sort(key=lambda row: (float(row.get("observedAtUnixMs") or 0), row["worker"], row["sequence"]))
    seen: set[str] = set()
    timeline_rows: list[dict[str, Any]] = []
    last_new_ms = started_unix_ms
    for row in events:
        observed_ms = float(row.get("observedAtUnixMs") or started_unix_ms)
        new = {str(edge) for edge in row["newEdges"]} - seen
        seen.update(str(edge) for edge in row["newEdges"])
        if new:
            last_new_ms = observed_ms
        timeline_rows.append(
            {
                "id": row.get("id"),
                "worker": row["worker"],
                "observedAfterSeconds": max(0.0, (observed_ms - started_unix_ms) / 1000),
                "newGlobalEdges": len(new),
                "globalEdgesSeen": len(seen),
                "workerEdgesSeen": int(row.get("workerEdgesSeen") or 0),
            }
        )
    seconds_since_new = max(0.0, (finished_unix_ms - last_new_ms) / 1000)
    return {
        "uniqueEdges": len(seen),
        "eventCount": len(timeline_rows),
        "timeline": timeline_rows,
        "plateauThresholdSeconds": plateau_seconds,
        "secondsSinceLastNewEdge": seconds_since_new,
        "plateauReached": seconds_since_new >= plateau_seconds,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--previous-coverage", type=Path)
    parser.add_argument("--edge-universe", type=Path)
    args = parser.parse_args(argv)
    workers: list[PersistentWorker] = []
    try:
        campaign_root = args.campaign.expanduser().resolve()
        campaign_value = campaign(campaign_root)
        spec_path = args.spec.expanduser().resolve()
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or spec.get("schemaVersion") != 1:
            raise RuntimeError("JavaScript coverage spec must be a schemaVersion 1 object")
        project_root = resolve_project(spec_path.parent, str(spec["projectRoot"]))
        runtime = resolve_runtime(str(spec.get("runtime") or "node"))
        module = resolve_under(project_root, str(spec["module"]), "target module")
        output = args.output.expanduser().resolve()
        output.relative_to(campaign_root)
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        inputs = input_files(project_root, list(spec.get("inputs", [])), int(spec.get("maxInputs", 100000)))
        worker_count = int(spec.get("workers") or 1)
        if not 1 <= worker_count <= 256:
            raise RuntimeError("workers must be between 1 and 256")
        environment = {
            "PATH": str(runtime.parent) + os.pathsep + os.environ.get("PATH", os.defpath),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NODE_ENV": "production",
        }
        for name in spec.get("passEnvironment", []):
            if str(name) in os.environ:
                environment[str(name)] = os.environ[str(name)]
        for name, value in spec.get("environment", {}).items():
            environment[str(name)] = str(value)
        started = time.monotonic()
        started_unix_ms = time.time() * 1000
        for index in range(worker_count):
            workers.append(
                PersistentWorker(
                    index=index,
                    runtime=runtime,
                    module=module,
                    export_name=str(spec.get("export") or "fuzz"),
                    reset_export=str(spec["resetExport"]) if spec.get("resetExport") else None,
                    input_mode=str(spec.get("inputMode") or "buffer"),
                    output=output / "workers" / f"worker-{index:04d}",
                    coverage_prefix=project_root,
                    environment=environment,
                )
            )
        assignments: list[list[tuple[int, Path]]] = [[] for _ in workers]
        for index, path in enumerate(inputs):
            assignments[index % len(workers)].append((index, path))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(workers)) as executor:
            futures = [
                executor.submit(
                    run_worker_inputs,
                    worker,
                    rows,
                    project_root=project_root,
                    max_input_bytes=int(spec.get("maxInputBytes", 16 * 1024 * 1024)),
                    timeout=float(spec.get("inputTimeoutSeconds", 5)),
                )
                for worker, rows in zip(workers, assignments, strict=True)
            ]
            cases = [record for future in futures for record in future.result()]
        worker_records = [worker.close(float(spec.get("shutdownTimeoutSeconds", 10))) for worker in workers]
        workers = []
        finished_unix_ms = time.time() * 1000
        native_coverage = native_coverage_timeline(
            worker_records,
            started_unix_ms=started_unix_ms,
            finished_unix_ms=finished_unix_ms,
            plateau_seconds=float(spec.get("plateauSeconds", 300)),
        )
        v8_files = [item["path"] for row in worker_records for item in row["v8CoverageFiles"]]
        istanbul_files = [row["istanbulCoverage"]["path"] for row in worker_records if row["istanbulCoverage"]]
        for value in spec.get("additionalV8CoverageFiles", []):
            v8_files.append(str(resolve_under(project_root, str(value), "additional V8 coverage")))
        for value in spec.get("additionalIstanbulCoverageFiles", []):
            istanbul_files.append(str(resolve_under(project_root, str(value), "additional Istanbul coverage")))
        remap_spec = output / "coverage-input.json"
        write_json(
            remap_spec,
            {
                "projectRoot": str(project_root),
                "v8CoverageFiles": v8_files,
                "istanbulCoverageFiles": istanbul_files,
                "includePatterns": spec.get("includePatterns", []),
                "excludePatterns": spec.get("excludePatterns", []),
                "boundaryRules": spec.get("boundaryRules", []),
            },
        )
        coverage_path = output / "coverage.json"
        remap = subprocess.run(
            [str(runtime), str(REMAPPER), str(remap_spec), str(coverage_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=int(spec.get("coverageTimeoutSeconds", 120)),
        )
        (output / "coverage.stdout.log").write_text(remap.stdout, encoding="utf-8")
        (output / "coverage.stderr.log").write_text(remap.stderr, encoding="utf-8")
        if remap.returncode != 0 or not coverage_path.is_file():
            raise RuntimeError(f"coverage remap failed: {remap.stderr.strip()}")
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        edge_ids = {str(edge["id"]) for edge in coverage.get("edges", [])}
        edge_path = output / "edge-ids.txt"
        edge_path.write_text("\n".join(sorted(edge_ids)) + "\n", encoding="utf-8")
        previous_path = args.previous_coverage.expanduser().resolve() if args.previous_coverage else None
        previous_ids = read_edge_ids(previous_path)
        new_ids = edge_ids - previous_ids
        holes: list[dict[str, Any]] = []
        next_task = None
        schedule_error = None
        if args.edge_universe:
            universe_path = args.edge_universe.expanduser().resolve()
            universe = json.loads(universe_path.read_text(encoding="utf-8"))
            for row in universe.get("edges", []):
                if isinstance(row, dict) and str(row.get("id") or "") not in edge_ids:
                    holes.append(row)
            write_json(
                output / "coverage-holes.json",
                {
                    "schemaVersion": 1,
                    "producer": "krineon-js-coverage-holes",
                    "universe": artifact(universe_path),
                    "covered": len(edge_ids),
                    "holes": holes,
                    "nextTask": holes[0] if holes else None,
                },
            )
            if holes and (campaign_root / "orchestration.db").is_file():
                hole = holes[0]
                hole_id = str(hole.get("id") or "")
                next_task = "js-coverage-" + hashlib.sha256(hole_id.encode()).hexdigest()[:16]
                scheduled = subprocess.run(
                    [
                        sys.executable,
                        str(RESEARCH_HARNESS),
                        "task-add",
                        str(campaign_root),
                        next_task,
                        "--title",
                        f"Reach uncovered JavaScript edge: {hole.get('label') or hole_id}",
                        "--lane",
                        "coverage-hole",
                        "--objective",
                        (
                            f"Generate a semantic structured input that reaches JavaScript edge "
                            f"{hole_id} in the pinned production bundle and retain the source-mapped coverage record."
                        ),
                        "--approach-family",
                        "structured-generation",
                        "--success-criterion",
                        "JavaScript coverage rebuild records the edge from a retained minimized input.",
                        "--priority",
                        "700",
                        "--max-attempts",
                        "2",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if scheduled.returncode != 0 and "already" not in scheduled.stderr.lower():
                    schedule_error = scheduled.stderr[-4000:]
                    next_task = None
        elapsed = max(time.monotonic() - started, 0.001)
        run = {
            "schemaVersion": 1,
            "producer": "krineon-js-coverage-harness",
            "runId": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8],
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "campaignCommit": campaign_value.get("commit"),
            "projectRoot": str(project_root),
            "spec": artifact(spec_path),
            "runtime": {**artifact(runtime), "version": subprocess.run([str(runtime), "--version"], check=False, capture_output=True, text=True).stdout.strip()},
            "worker": artifact(WORKER),
            "remapper": artifact(REMAPPER),
            "targetModule": artifact(module),
            "inputCount": len(inputs),
            "workerCount": worker_count,
            "workers": worker_records,
            "cases": sorted(cases, key=lambda row: row["index"]),
            "exceptions": sum(row["response"].get("status") == "exception" for row in cases),
            "coverage": {
                "record": artifact(coverage_path),
                "edgeIds": artifact(edge_path),
                "uniqueEdges": len(edge_ids),
                "mappedEdges": coverage.get("mappedEdgeCount"),
                "byBoundary": coverage.get("byBoundary"),
                "newEdges": len(new_ids),
                "newEdgesPerHour": len(new_ids) / (elapsed / 3600),
                "coverageHoles": len(holes),
                "nextCoverageHole": holes[0] if holes else None,
                "nextCoverageTask": next_task,
                "coverageTaskScheduleError": schedule_error,
                "nativePreciseCoverage": native_coverage,
            },
            "elapsedSeconds": elapsed,
            "status": "passed",
        }
        run_path = output / "js-coverage-run.json"
        write_json(run_path, run)
        registered = campaign_value.get("jsCoverageRuns")
        if not isinstance(registered, list):
            registered = []
        registered.append(
            {
                "profile": str(spec.get("profile") or "javascript"),
                "record": run_path.relative_to(campaign_root).as_posix(),
                "sha256": sha256_file(run_path),
                "newEdgesPerHour": run["coverage"]["newEdgesPerHour"],
            }
        )
        campaign_value["jsCoverageRuns"] = registered
        write_json(campaign_root / "campaign.json", campaign_value)
        print(run_path)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as error:
        for worker in workers:
            if worker.process.poll() is None:
                worker.process.kill()
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
