#!/usr/bin/env python3
"""Run evidence-bound Krineon tasks in a fail-closed execution plane.

The runtime deliberately supports offline Docker execution only. Networked web
experiments remain mediated by Krineon's signed web contract and execution
broker rather than by arbitrary worker processes.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

try:
    from .swarm_control import ControlError, ControlStore, stable_id
except ImportError:
    from swarm_control import ControlError, ControlStore, stable_id


IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SECRET_NAME = re.compile(r"(?:token|secret|password|passwd|cookie|authorization|api[_-]?key)", re.I)


class RuntimePlaneError(Exception):
    """The execution recipe or retained runtime state is invalid."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def recipe_contract_bytes(recipe: dict[str, Any]) -> bytes:
    """Hash the executable contract without binding it to one reviewer identity."""
    contract = {
        key: value
        for key, value in recipe.items()
        if key not in {"workerId", "sessionId"}
    }
    return canonical_bytes(contract)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePlaneError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePlaneError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimePlaneError(f"expected a JSON object in {path}")
    return value


def safe_id(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not SAFE_ID.fullmatch(result):
        raise RuntimePlaneError(f"{field} must match {SAFE_ID.pattern}")
    return result


def campaign_root(value: str | Path) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise RuntimePlaneError(f"not a Krineon campaign: {root}")
    return root


def contained_path(root: Path, relative: Any, field: str, *, must_exist: bool = True) -> Path:
    raw = str(relative or "").strip()
    if not raw or Path(raw).is_absolute():
        raise RuntimePlaneError(f"{field} must be a campaign-relative path")
    path = (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise RuntimePlaneError(f"{field} escapes the campaign root") from exc
    if must_exist and not path.exists():
        raise RuntimePlaneError(f"{field} does not exist: {raw}")
    return path


@dataclasses.dataclass(frozen=True)
class Artifact:
    sha256: str
    size: int
    relative_path: str
    kind: str


class RuntimeStore:
    """Durable event ledger, artifact index, task sessions, and replay state."""

    def __init__(self, root: Path):
        self.root = root
        self.runtime_root = root / "evidence" / "runtime"
        self.artifact_root = self.runtime_root / "artifacts" / "sha256"
        self.database_path = self.runtime_root / "runtime.db"
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
              sha256 TEXT PRIMARY KEY,
              size INTEGER NOT NULL,
              relative_path TEXT NOT NULL,
              kind TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              worker_id TEXT NOT NULL,
              agent_identity TEXT NOT NULL,
              provider TEXT NOT NULL,
              model TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('active','checkpointed','closed')),
              checkpoint_artifact TEXT,
              parent_session_id TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              worker_id TEXT NOT NULL,
              session_id TEXT NOT NULL,
              recipe_sha256 TEXT NOT NULL,
              recipe_artifact TEXT NOT NULL,
              target_hashes_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('running','passed','failed','error','timed-out')),
              sandbox_mode TEXT NOT NULL,
              started_at TEXT NOT NULL,
              completed_at TEXT,
              exit_code INTEGER,
              stdout_artifact TEXT,
              stderr_artifact TEXT,
              result_artifact TEXT,
              assertions_json TEXT NOT NULL DEFAULT '[]',
              FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );
            CREATE TABLE IF NOT EXISTS events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT,
              task_id TEXT,
              worker_id TEXT,
              created_at TEXT NOT NULL,
              event_type TEXT NOT NULL,
              tool_call_id TEXT,
              payload_json TEXT NOT NULL,
              artifact_refs_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS replays (
              replay_id TEXT PRIMARY KEY,
              original_run_id TEXT NOT NULL,
              replay_run_id TEXT NOT NULL UNIQUE,
              reviewer_worker_id TEXT NOT NULL,
              reviewer_session_id TEXT NOT NULL,
              verdict TEXT NOT NULL CHECK(verdict IN ('passed','failed','inconclusive')),
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(original_run_id) REFERENCES runs(run_id),
              FOREIGN KEY(replay_run_id) REFERENCES runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS runtime_events_run_idx ON events(run_id,event_id);
            CREATE INDEX IF NOT EXISTS runtime_runs_task_idx ON runs(task_id,started_at);
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def add_artifact(self, payload: bytes, kind: str) -> Artifact:
        digest = sha256_bytes(payload)
        destination = self.artifact_root / digest[:2] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            temporary = destination.with_name(f".{digest}.{os.getpid()}.tmp")
            try:
                temporary.write_bytes(payload)
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        elif sha256_file(destination) != digest:
            raise RuntimePlaneError(f"artifact collision or corruption for {digest}")
        relative = destination.relative_to(self.root).as_posix()
        self.connection.execute(
            "INSERT OR IGNORE INTO artifacts(sha256,size,relative_path,kind,created_at) VALUES(?,?,?,?,?)",
            (digest, len(payload), relative, kind, utc_now()),
        )
        self.connection.commit()
        return Artifact(digest, len(payload), relative, kind)

    def artifact_bytes(self, digest: str) -> bytes:
        if not HEX_SHA256.fullmatch(digest):
            raise RuntimePlaneError("invalid artifact digest")
        row = self.connection.execute(
            "SELECT relative_path FROM artifacts WHERE sha256=?", (digest,)
        ).fetchone()
        if row is None:
            raise RuntimePlaneError(f"unknown artifact: {digest}")
        path = contained_path(self.root, row["relative_path"], "artifact")
        payload = path.read_bytes()
        if sha256_bytes(payload) != digest:
            raise RuntimePlaneError(f"artifact hash mismatch: {digest}")
        return payload

    def event(
        self,
        event_type: str,
        *,
        run_id: str | None = None,
        task_id: str | None = None,
        worker_id: str | None = None,
        tool_call_id: str | None = None,
        payload: dict[str, Any] | None = None,
        artifacts: list[str] | None = None,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO events(run_id,task_id,worker_id,created_at,event_type,tool_call_id,payload_json,artifact_refs_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                run_id,
                task_id,
                worker_id,
                utc_now(),
                event_type,
                tool_call_id,
                json.dumps(payload or {}, sort_keys=True),
                json.dumps(artifacts or [], sort_keys=True),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def create_session(
        self,
        *,
        session_id: str,
        task_id: str,
        worker_id: str,
        agent_identity: str,
        provider: str,
        model: str,
        parent_session_id: str | None = None,
    ) -> dict[str, Any]:
        values = [session_id, task_id, worker_id, agent_identity, provider, model]
        session_id, task_id, worker_id, agent_identity, provider, model = [
            safe_id(value, field)
            for value, field in zip(
                values,
                ("sessionId", "taskId", "workerId", "agentIdentity", "provider", "model"),
                strict=True,
            )
        ]
        if parent_session_id:
            parent_session_id = safe_id(parent_session_id, "parentSessionId")
            if self.connection.execute(
                "SELECT 1 FROM sessions WHERE session_id=?", (parent_session_id,)
            ).fetchone() is None:
                raise RuntimePlaneError("parent model session does not exist")
        now = utc_now()
        try:
            self.connection.execute(
                "INSERT INTO sessions(session_id,task_id,worker_id,agent_identity,provider,model,state,checkpoint_artifact,parent_session_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'active',NULL,?,?,?)",
                (session_id, task_id, worker_id, agent_identity, provider, model, parent_session_id, now, now),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            raise RuntimePlaneError(f"model session already exists: {session_id}") from exc
        self.event(
            "model_session_created",
            task_id=task_id,
            worker_id=worker_id,
            payload={"sessionId": session_id, "agentIdentity": agent_identity, "parent": parent_session_id},
        )
        control = ControlStore(self.root)
        try:
            control.ensure_component(
                kind="provider",
                name=provider,
                capabilities=("model-session",),
                actor="runtime-plane",
            )
            control.ensure_component(
                kind="model",
                name=stable_id("runtime-model", provider, model),
                version=model,
                capabilities=("model-session",),
                actor="runtime-plane",
            )
            control.connection.commit()
        finally:
            control.close()
        return dict(self.connection.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone())

    def session(self, session_id: str, *, active: bool = True) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM sessions WHERE session_id=?", (safe_id(session_id, "sessionId"),)
        ).fetchone()
        if row is None:
            raise RuntimePlaneError(f"unknown model session: {session_id}")
        if active and row["state"] not in {"active", "checkpointed"}:
            raise RuntimePlaneError(f"model session is not active: {session_id}")
        return row

    def checkpoint_session(self, session_id: str, payload: bytes) -> Artifact:
        row = self.session(session_id)
        artifact = self.add_artifact(payload, "model-session-checkpoint")
        self.connection.execute(
            "UPDATE sessions SET state='checkpointed',checkpoint_artifact=?,updated_at=? WHERE session_id=?",
            (artifact.sha256, utc_now(), session_id),
        )
        self.connection.commit()
        self.event(
            "model_session_checkpointed",
            task_id=row["task_id"],
            worker_id=row["worker_id"],
            payload={"sessionId": session_id},
            artifacts=[artifact.sha256],
        )
        return artifact

    def close_session(self, session_id: str) -> dict[str, Any]:
        row = self.session(session_id)
        self.connection.execute(
            "UPDATE sessions SET state='closed',updated_at=? WHERE session_id=?",
            (utc_now(), session_id),
        )
        self.connection.commit()
        self.event(
            "model_session_closed",
            task_id=row["task_id"],
            worker_id=row["worker_id"],
            payload={"sessionId": session_id},
        )
        return dict(self.session(session_id, active=False))


@dataclasses.dataclass(frozen=True)
class ProcessObservation:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Runner = Callable[[dict[str, Any], Path, Path], ProcessObservation]


def validate_recipe(root: Path, value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "schemaVersion", "recipeId", "taskId", "workerId", "sessionId", "workspace",
        "command", "environment", "sandbox", "network", "targetHashes", "assertions",
        "alternateObserver",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimePlaneError("unknown recipe fields: " + ", ".join(unknown))
    if value.get("schemaVersion") != 1:
        raise RuntimePlaneError("recipe.schemaVersion must be 1")
    recipe_id = safe_id(value.get("recipeId"), "recipeId")
    task_id = safe_id(value.get("taskId"), "taskId")
    worker_id = safe_id(value.get("workerId"), "workerId")
    session_id = safe_id(value.get("sessionId"), "sessionId")
    workspace = contained_path(root, value.get("workspace"), "workspace")
    if not workspace.is_dir():
        raise RuntimePlaneError("recipe workspace must be a directory")
    command = value.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise RuntimePlaneError("recipe.command must be a non-empty string array")
    if len(command) > 128 or sum(len(item) for item in command) > 32_768:
        raise RuntimePlaneError("recipe.command exceeds the retained execution limit")
    environment = value.get("environment", {})
    if not isinstance(environment, dict):
        raise RuntimePlaneError("recipe.environment must be an object")
    normalized_environment: dict[str, str] = {}
    for name, raw in environment.items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", str(name)):
            raise RuntimePlaneError(f"invalid environment name: {name}")
        if SECRET_NAME.search(str(name)):
            raise RuntimePlaneError(f"literal secret environment fields are forbidden: {name}")
        value_text = str(raw)
        if len(value_text) > 4096 or "\x00" in value_text:
            raise RuntimePlaneError(f"invalid environment value: {name}")
        normalized_environment[str(name)] = value_text
    sandbox = value.get("sandbox")
    if not isinstance(sandbox, dict) or sandbox.get("mode") != "docker-offline":
        raise RuntimePlaneError("sandbox.mode must be docker-offline")
    image = str(sandbox.get("image") or "")
    if not IMAGE_DIGEST.fullmatch(image):
        raise RuntimePlaneError("sandbox.image must use an exact @sha256 digest")
    timeout = int(sandbox.get("timeoutSeconds") or 0)
    memory = int(sandbox.get("memoryMb") or 0)
    cpus = float(sandbox.get("cpus") or 0)
    pids = int(sandbox.get("pids") or 0)
    if not 1 <= timeout <= 7200:
        raise RuntimePlaneError("sandbox.timeoutSeconds must be between 1 and 7200")
    if not 128 <= memory <= 65_536:
        raise RuntimePlaneError("sandbox.memoryMb must be between 128 and 65536")
    if not 0.1 <= cpus <= 32:
        raise RuntimePlaneError("sandbox.cpus must be between 0.1 and 32")
    if not 16 <= pids <= 4096:
        raise RuntimePlaneError("sandbox.pids must be between 16 and 4096")
    network = value.get("network")
    if not isinstance(network, dict) or network.get("mode") not in {"none", "broker-only"}:
        raise RuntimePlaneError("network.mode must be none or broker-only")
    target_hashes = value.get("targetHashes")
    if not isinstance(target_hashes, dict) or not target_hashes:
        raise RuntimePlaneError("targetHashes must bind at least one workspace file")
    normalized_hashes: dict[str, str] = {}
    for relative, expected in target_hashes.items():
        target = contained_path(workspace, relative, f"targetHashes.{relative}")
        if not target.is_file() or not HEX_SHA256.fullmatch(str(expected)):
            raise RuntimePlaneError(f"invalid target hash binding: {relative}")
        normalized_relative = target.relative_to(workspace).as_posix()
        if normalized_relative in normalized_hashes:
            raise RuntimePlaneError(f"duplicate target hash binding: {relative}")
        normalized_hashes[normalized_relative] = str(expected)
    assertions = value.get("assertions")
    if not isinstance(assertions, dict) or "exitCode" not in assertions:
        raise RuntimePlaneError("assertions.exitCode is required")
    alternate_observer = value.get("alternateObserver")
    if not isinstance(alternate_observer, dict):
        raise RuntimePlaneError("alternateObserver must be an object")
    observer_unknown = sorted(set(alternate_observer) - {"command", "environment", "assertions"})
    if observer_unknown:
        raise RuntimePlaneError("unknown alternateObserver fields: " + ", ".join(observer_unknown))
    observer_command = alternate_observer.get("command")
    if (
        not isinstance(observer_command, list)
        or not observer_command
        or not all(isinstance(item, str) and item for item in observer_command)
    ):
        raise RuntimePlaneError("alternateObserver.command must be a non-empty string array")
    if len(observer_command) > 128 or sum(len(item) for item in observer_command) > 32_768:
        raise RuntimePlaneError("alternateObserver.command exceeds the retained execution limit")
    observer_environment = alternate_observer.get("environment", {})
    if not isinstance(observer_environment, dict):
        raise RuntimePlaneError("alternateObserver.environment must be an object")
    normalized_observer_environment: dict[str, str] = {}
    for name, raw in observer_environment.items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", str(name)):
            raise RuntimePlaneError(f"invalid alternate observer environment name: {name}")
        if SECRET_NAME.search(str(name)):
            raise RuntimePlaneError(f"literal secret environment fields are forbidden: {name}")
        value_text = str(raw)
        if len(value_text) > 4096 or "\x00" in value_text:
            raise RuntimePlaneError(f"invalid alternate observer environment value: {name}")
        normalized_observer_environment[str(name)] = value_text
    alternate_assertions = alternate_observer.get("assertions")
    if not isinstance(alternate_assertions, dict) or "exitCode" not in alternate_assertions:
        raise RuntimePlaneError("alternateObserver.assertions.exitCode is required")

    def require_workspace_command_binding(candidate: list[str], field: str) -> None:
        executable = candidate[0]
        relative: str | None = None
        if executable.startswith("/workspace/"):
            relative = executable[len("/workspace/") :]
        elif executable.startswith("./"):
            relative = executable[2:]
        if relative is not None:
            path = contained_path(workspace, relative, field)
            normalized_relative = path.relative_to(workspace).as_posix()
            if normalized_relative not in normalized_hashes:
                raise RuntimePlaneError(
                    f"{field} executable must appear in targetHashes: {normalized_relative}"
                )

    require_workspace_command_binding(command, "command")
    require_workspace_command_binding(observer_command, "alternateObserver.command")
    normalized = {
        "schemaVersion": 1,
        "recipeId": recipe_id,
        "taskId": task_id,
        "workerId": worker_id,
        "sessionId": session_id,
        "workspace": workspace.relative_to(root).as_posix(),
        "command": command,
        "environment": normalized_environment,
        "sandbox": {
            "mode": "docker-offline", "image": image, "timeoutSeconds": timeout,
            "memoryMb": memory, "cpus": cpus, "pids": pids,
        },
        "network": {"mode": network["mode"]},
        "targetHashes": dict(sorted(normalized_hashes.items())),
        "assertions": assertions,
        "alternateObserver": {
            "command": observer_command,
            "environment": normalized_observer_environment,
            "assertions": alternate_assertions,
        },
    }
    verify_target_hashes(root, normalized)
    return normalized


def verify_target_hashes(root: Path, recipe: dict[str, Any]) -> dict[str, str]:
    workspace = contained_path(root, recipe["workspace"], "workspace")
    observed: dict[str, str] = {}
    for relative, expected in recipe["targetHashes"].items():
        path = contained_path(workspace, relative, f"targetHashes.{relative}")
        actual = sha256_file(path)
        observed[relative] = actual
        if actual != expected:
            raise RuntimePlaneError(f"target hash changed for {relative}: expected {expected}, observed {actual}")
    return observed


def docker_offline_runner(recipe: dict[str, Any], workspace: Path, output: Path) -> ProcessObservation:
    if shutil.which("docker") is None:
        raise RuntimePlaneError("docker is required for docker-offline execution")
    sandbox = recipe["sandbox"]
    command = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", str(sandbox["pids"]),
        "--memory", f"{sandbox['memoryMb']}m", "--cpus", str(sandbox["cpus"]),
        "--tmpfs", f"/tmp:rw,exec,nosuid,nodev,size=512m,uid={os.getuid()},gid={os.getgid()},mode=1777",
        "--mount", f"type=bind,src={workspace},dst=/workspace,readonly",
        "--mount", f"type=bind,src={output},dst=/evidence",
        "--workdir", "/workspace",
    ]
    for name, value in sorted(recipe["environment"].items()):
        command.extend(["--env", f"{name}={value}"])
    command.extend([sandbox["image"], *recipe["command"]])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=sandbox["timeoutSeconds"],
            env={"PATH": os.environ.get("PATH", "")},
        )
        return ProcessObservation(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return ProcessObservation(124, exc.stdout or b"", exc.stderr or b"", timed_out=True)


def evaluate_assertions(assertions: dict[str, Any], observation: ProcessObservation) -> list[dict[str, Any]]:
    stdout = observation.stdout.decode("utf-8", "replace")
    stderr = observation.stderr.decode("utf-8", "replace")
    results: list[dict[str, Any]] = []

    def add(assertion: str, passed: bool, expected: Any, observed: Any) -> None:
        results.append({"assertion": assertion, "passed": bool(passed), "expected": expected, "observed": observed})

    expected_code = int(assertions["exitCode"])
    add("exitCode", observation.exit_code == expected_code, expected_code, observation.exit_code)
    for field, haystack, positive in (
        ("stdoutContains", stdout, True), ("stderrContains", stderr, True),
        ("stdoutNotContains", stdout, False), ("stderrNotContains", stderr, False),
    ):
        values = assertions.get(field, [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise RuntimePlaneError(f"assertions.{field} must be a string array")
        for index, needle in enumerate(values):
            contains = needle in haystack
            add(f"{field}[{index}]", contains if positive else not contains, needle, contains)
    for field, haystack in (("stdoutRegex", stdout), ("stderrRegex", stderr)):
        values = assertions.get(field, [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise RuntimePlaneError(f"assertions.{field} must be a string array")
        for index, pattern in enumerate(values):
            try:
                matched = re.search(pattern, haystack, re.MULTILINE) is not None
            except re.error as exc:
                raise RuntimePlaneError(f"invalid {field} pattern {pattern!r}: {exc}") from exc
            add(f"{field}[{index}]", matched, pattern, matched)
    return results


class ExecutionRuntime:
    def __init__(self, root: Path, runner: Runner = docker_offline_runner):
        self.root = root
        self.store = RuntimeStore(root)
        self.runner = runner

    def close(self) -> None:
        self.store.close()

    def run(
        self,
        recipe_value: dict[str, Any],
        *,
        worker_id: str | None = None,
        session_id: str | None = None,
        replay_of: str | None = None,
    ) -> dict[str, Any]:
        recipe_input = dict(recipe_value)
        if worker_id is not None:
            recipe_input["workerId"] = worker_id
        if session_id is not None:
            recipe_input["sessionId"] = session_id
        recipe = validate_recipe(self.root, recipe_input)
        session = self.store.session(recipe["sessionId"])
        if session["task_id"] != recipe["taskId"] or session["worker_id"] != recipe["workerId"]:
            raise RuntimePlaneError("recipe task/worker does not match the active model session")
        if replay_of:
            original = self.store.connection.execute("SELECT * FROM runs WHERE run_id=?", (replay_of,)).fetchone()
            if original is None:
                raise RuntimePlaneError(f"unknown original run: {replay_of}")
            original_session = self.store.session(original["session_id"], active=False)
            if original["worker_id"] == recipe["workerId"]:
                raise RuntimePlaneError("coordinator replay requires a different worker identity")
            if original_session["agent_identity"] == session["agent_identity"]:
                raise RuntimePlaneError("coordinator replay requires a different agent identity")
        run_id = "run-" + secrets.token_hex(16)
        tool_call_id = "tool-" + secrets.token_hex(12)
        control = ControlStore(self.root)
        try:
            tool_component_id = control.ensure_component(
                kind="tool",
                name=recipe["recipeId"],
                version=sha256_bytes(recipe_contract_bytes(recipe))[:16],
                capabilities=("bounded-execution", recipe["sandbox"]["mode"]),
                actor="runtime-plane",
            )
            control.connection.commit()
        finally:
            control.close()
        telemetry_started = time.monotonic()
        run_dir = self.store.runtime_root / "runs" / run_id
        output_dir = run_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=False)
        recipe_payload = canonical_bytes(recipe)
        recipe_artifact = self.store.add_artifact(recipe_payload, "execution-recipe")
        target_hashes = verify_target_hashes(self.root, recipe)
        started = utc_now()
        self.store.connection.execute(
            "INSERT INTO runs(run_id,task_id,worker_id,session_id,recipe_sha256,recipe_artifact,target_hashes_json,state,sandbox_mode,started_at,assertions_json) "
            "VALUES(?,?,?,?,?,?,?,'running',?,?, '[]')",
            (
                run_id, recipe["taskId"], recipe["workerId"], recipe["sessionId"],
                sha256_bytes(recipe_contract_bytes(recipe)), recipe_artifact.sha256,
                json.dumps(target_hashes, sort_keys=True), recipe["sandbox"]["mode"], started,
            ),
        )
        self.store.connection.commit()
        self.store.event(
            "tool_started", run_id=run_id, task_id=recipe["taskId"], worker_id=recipe["workerId"],
            tool_call_id=tool_call_id,
            payload={
                "recipeId": recipe["recipeId"], "commandDigest": sha256_bytes(canonical_bytes(recipe["command"])),
                "sandbox": recipe["sandbox"]["mode"], "network": recipe["network"]["mode"],
                "replayOf": replay_of,
            },
            artifacts=[recipe_artifact.sha256],
        )
        state = "error"
        observation = ProcessObservation(125, b"", b"")
        error_text = ""
        observer_tool_call_id = "tool-" + secrets.token_hex(12)
        observer_observation = ProcessObservation(125, b"", b"")
        observer_error = ""
        observer_started = False
        try:
            workspace = contained_path(self.root, recipe["workspace"], "workspace")
            observation = self.runner(recipe, workspace, output_dir)
            assertion_results = evaluate_assertions(recipe["assertions"], observation)
            observer_recipe = dict(recipe)
            observer_recipe["command"] = recipe["alternateObserver"]["command"]
            observer_recipe["environment"] = recipe["alternateObserver"]["environment"]
            observer_started = True
            self.store.event(
                "alternate_observer_started",
                run_id=run_id,
                task_id=recipe["taskId"],
                worker_id=recipe["workerId"],
                tool_call_id=observer_tool_call_id,
                payload={
                    "commandDigest": sha256_bytes(canonical_bytes(observer_recipe["command"])),
                    "network": recipe["network"]["mode"],
                },
            )
            try:
                observer_observation = self.runner(observer_recipe, workspace, output_dir)
                alternate_results = evaluate_assertions(
                    recipe["alternateObserver"]["assertions"], observer_observation
                )
            except Exception as exc:
                observer_error = f"{type(exc).__name__}: {exc}"
                observer_observation = ProcessObservation(125, b"", observer_error.encode("utf-8"))
                alternate_results = [{
                    "assertion": "alternate-observer-runtime",
                    "passed": False,
                    "expected": "successful independent observation",
                    "observed": observer_error,
                }]
            state = "timed-out" if observation.timed_out or observer_observation.timed_out else (
                "passed"
                if all(item["passed"] for item in assertion_results)
                and all(item["passed"] for item in alternate_results)
                else "failed"
            )
        except Exception as exc:
            assertion_results = [{"assertion": "runtime", "passed": False, "expected": "successful execution", "observed": f"{type(exc).__name__}: {exc}"}]
            alternate_results = [{"assertion": "alternate-observer-runtime", "passed": False, "expected": "primary execution before observation", "observed": f"{type(exc).__name__}: {exc}"}]
            error_text = f"{type(exc).__name__}: {exc}"
            observation = ProcessObservation(125, b"", error_text.encode("utf-8"))
        stdout_artifact = self.store.add_artifact(observation.stdout, "tool-stdout")
        stderr_artifact = self.store.add_artifact(observation.stderr, "tool-stderr")
        observer_stdout_artifact = self.store.add_artifact(
            observer_observation.stdout, "alternate-observer-stdout"
        )
        observer_stderr_artifact = self.store.add_artifact(
            observer_observation.stderr, "alternate-observer-stderr"
        )
        result = {
            "schemaVersion": 1,
            "runId": run_id,
            "taskId": recipe["taskId"],
            "workerId": recipe["workerId"],
            "sessionId": recipe["sessionId"],
            "replayOf": replay_of,
            "recipeSha256": sha256_bytes(recipe_contract_bytes(recipe)),
            "targetHashes": target_hashes,
            "sandboxMode": recipe["sandbox"]["mode"],
            "networkMode": recipe["network"]["mode"],
            "networkEnforcement": "docker-network-none; approved traffic uses a separate broker",
            "state": state,
            "exitCode": observation.exit_code,
            "timedOut": observation.timed_out,
            "assertionsPassed": all(item["passed"] for item in assertion_results),
            "assertions": assertion_results,
            "alternateObserverPassed": all(item["passed"] for item in alternate_results),
            "alternateObserver": {
                "exitCode": observer_observation.exit_code,
                "timedOut": observer_observation.timed_out,
                "assertions": alternate_results,
                "stdout": dataclasses.asdict(observer_stdout_artifact),
                "stderr": dataclasses.asdict(observer_stderr_artifact),
                "error": observer_error,
            },
            "stdout": dataclasses.asdict(stdout_artifact),
            "stderr": dataclasses.asdict(stderr_artifact),
            "error": error_text,
            "startedAt": started,
            "completedAt": utc_now(),
        }
        result_artifact = self.store.add_artifact(canonical_bytes(result), "execution-result")
        atomic_json(run_dir / "result.json", result)
        self.store.connection.execute(
            "UPDATE runs SET state=?,completed_at=?,exit_code=?,stdout_artifact=?,stderr_artifact=?,result_artifact=?,assertions_json=? WHERE run_id=?",
            (
                state, result["completedAt"], observation.exit_code, stdout_artifact.sha256,
                stderr_artifact.sha256, result_artifact.sha256,
                json.dumps({"primary": assertion_results, "alternate": alternate_results}, sort_keys=True), run_id,
            ),
        )
        self.store.connection.commit()
        if observer_started:
            self.store.event(
                "alternate_observer_finished",
                run_id=run_id,
                task_id=recipe["taskId"],
                worker_id=recipe["workerId"],
                tool_call_id=observer_tool_call_id,
                payload={
                    "exitCode": observer_observation.exit_code,
                    "assertionsPassed": result["alternateObserverPassed"],
                    "error": observer_error,
                },
                artifacts=[observer_stdout_artifact.sha256, observer_stderr_artifact.sha256],
            )
        self.store.event(
            "tool_finished", run_id=run_id, task_id=recipe["taskId"], worker_id=recipe["workerId"],
            tool_call_id=tool_call_id,
            payload={
                "state": state,
                "exitCode": observation.exit_code,
                "assertionsPassed": result["assertionsPassed"],
                "alternateObserverPassed": result["alternateObserverPassed"],
            },
            artifacts=[stdout_artifact.sha256, stderr_artifact.sha256, result_artifact.sha256],
        )
        try:
            control = ControlStore(self.root)
            try:
                control.component_observe(
                    {
                        "componentId": tool_component_id,
                        "taskId": recipe["taskId"],
                        "operation": "runtime-execution",
                        "outcome": "passed" if state == "passed" else "failed",
                        "latencyMs": (time.monotonic() - telemetry_started) * 1000,
                        "artifactRefs": [
                            stdout_artifact.sha256,
                            stderr_artifact.sha256,
                            result_artifact.sha256,
                        ],
                        "detail": state,
                    },
                    actor="runtime-plane",
                )
                control.connection.commit()
            finally:
                control.close()
        except (ControlError, OSError, sqlite3.Error) as exc:
            self.store.event(
                "component_observability_failed",
                run_id=run_id,
                task_id=recipe["taskId"],
                worker_id=recipe["workerId"],
                payload={"componentId": tool_component_id, "errorType": type(exc).__name__},
            )
        self.bridge_event("runtime-run-finished", recipe["taskId"], recipe["workerId"], result)
        return result

    def replay(self, original_run_id: str, reviewer_session_id: str) -> dict[str, Any]:
        original = self.store.connection.execute("SELECT * FROM runs WHERE run_id=?", (original_run_id,)).fetchone()
        if original is None:
            raise RuntimePlaneError(f"unknown original run: {original_run_id}")
        reviewer = self.store.session(reviewer_session_id)
        recipe = json.loads(self.store.artifact_bytes(original["recipe_artifact"]))
        replay_result = self.run(
            recipe,
            worker_id=reviewer["worker_id"],
            session_id=reviewer_session_id,
            replay_of=original_run_id,
        )
        same_recipe = replay_result["recipeSha256"] == original["recipe_sha256"]
        same_targets = replay_result["targetHashes"] == json.loads(original["target_hashes_json"])
        original_assertions = json.loads(original["assertions_json"])
        original_alternate = original_assertions.get("alternate", []) if isinstance(original_assertions, dict) else []
        original_passed = (
            original["state"] == "passed"
            and bool(original_alternate)
            and all(
                isinstance(item, dict) and item.get("passed") is True
                for item in original_alternate
            )
        )
        verdict = "passed" if (
            original_passed
            and replay_result["assertionsPassed"]
            and replay_result["alternateObserverPassed"]
            and same_recipe
            and same_targets
        ) else "failed"
        reason = (
            "fresh reviewer executed the same recipe and target hashes with passing assertions"
            if verdict == "passed"
            else "original and replay did not both satisfy the same machine assertions"
        )
        replay_id = "replay-" + secrets.token_hex(12)
        self.store.connection.execute(
            "INSERT INTO replays(replay_id,original_run_id,replay_run_id,reviewer_worker_id,reviewer_session_id,verdict,reason,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (replay_id, original_run_id, replay_result["runId"], reviewer["worker_id"], reviewer_session_id, verdict, reason, utc_now()),
        )
        self.store.connection.commit()
        record = {
            "replayId": replay_id,
            "originalRunId": original_run_id,
            "replayRunId": replay_result["runId"],
            "reviewerWorkerId": reviewer["worker_id"],
            "reviewerAgentIdentity": reviewer["agent_identity"],
            "verdict": verdict,
            "sameRecipe": same_recipe,
            "sameTargetHashes": same_targets,
            "alternateObserverPassed": replay_result["alternateObserverPassed"],
            "reason": reason,
        }
        self.store.event(
            "coordinator_replay_finished", run_id=replay_result["runId"], task_id=original["task_id"],
            worker_id=reviewer["worker_id"], payload=record,
        )
        return record

    def bridge_event(self, event_type: str, task_id: str, worker_id: str, payload: dict[str, Any]) -> None:
        orchestration = self.root / "orchestration.db"
        if not orchestration.is_file():
            return
        connection = sqlite3.connect(orchestration)
        try:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
            ).fetchone()
            if table:
                connection.execute(
                    "INSERT INTO events(created_at,event_type,task_id,worker_id,payload_json) VALUES(?,?,?,?,?)",
                    (utc_now(), event_type, task_id, worker_id, json.dumps(payload, sort_keys=True)),
                )
                connection.commit()
        finally:
            connection.close()


def runtime_status(root: Path) -> dict[str, Any]:
    store = RuntimeStore(root)
    try:
        counts = {}
        for table in ("sessions", "runs", "events", "artifacts", "replays"):
            counts[table] = int(store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        active = [dict(row) for row in store.connection.execute(
            "SELECT session_id,task_id,worker_id,agent_identity,provider,model,state,updated_at FROM sessions WHERE state!='closed' ORDER BY updated_at DESC"
        )]
        recent = [dict(row) for row in store.connection.execute(
            "SELECT run_id,task_id,worker_id,state,started_at,completed_at FROM runs ORDER BY started_at DESC LIMIT 20"
        )]
        return {"database": store.database_path.relative_to(root).as_posix(), "counts": counts, "activeSessions": active, "recentRuns": recent}
    finally:
        store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="initialize the durable execution plane")
    initialize.add_argument("campaign")
    session = commands.add_parser("session-create", help="register a task-scoped model session")
    session.add_argument("campaign")
    session.add_argument("--session", required=True)
    session.add_argument("--task", required=True)
    session.add_argument("--worker", required=True)
    session.add_argument("--agent", required=True)
    session.add_argument("--provider", required=True)
    session.add_argument("--model", required=True)
    session.add_argument("--parent")
    checkpoint = commands.add_parser("session-checkpoint", help="retain a model-session checkpoint")
    checkpoint.add_argument("campaign")
    checkpoint.add_argument("session")
    checkpoint.add_argument("checkpoint")
    close = commands.add_parser("session-close", help="close a task-scoped model session")
    close.add_argument("campaign")
    close.add_argument("session")
    run = commands.add_parser("run", help="execute one pinned offline recipe")
    run.add_argument("campaign")
    run.add_argument("recipe")
    replay = commands.add_parser("replay", help="re-execute a run under a fresh reviewer identity")
    replay.add_argument("campaign")
    replay.add_argument("run_id")
    replay.add_argument("--reviewer-session", required=True)
    status = commands.add_parser("status", help="show execution-plane state")
    status.add_argument("campaign")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = campaign_root(args.campaign)
        if args.command == "init":
            store = RuntimeStore(root)
            path = store.database_path.relative_to(root).as_posix()
            store.close()
            print(json.dumps({"initialized": True, "database": path}, indent=2))
            return 0
        if args.command == "status":
            print(json.dumps(runtime_status(root), indent=2))
            return 0
        runtime = ExecutionRuntime(root)
        try:
            if args.command == "session-create":
                result = runtime.store.create_session(
                    session_id=args.session, task_id=args.task, worker_id=args.worker,
                    agent_identity=args.agent, provider=args.provider, model=args.model,
                    parent_session_id=args.parent,
                )
            elif args.command == "session-checkpoint":
                checkpoint = contained_path(root, args.checkpoint, "checkpoint")
                result = dataclasses.asdict(runtime.store.checkpoint_session(args.session, checkpoint.read_bytes()))
            elif args.command == "session-close":
                result = runtime.store.close_session(args.session)
            elif args.command == "run":
                recipe = read_object(contained_path(root, args.recipe, "recipe"))
                result = runtime.run(recipe)
            elif args.command == "replay":
                result = runtime.replay(args.run_id, args.reviewer_session)
            else:
                raise RuntimePlaneError(f"unsupported command: {args.command}")
            print(json.dumps(result, indent=2, default=str))
            return 0
        finally:
            runtime.close()
    except RuntimePlaneError as exc:
        print(f"runtime-plane: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
