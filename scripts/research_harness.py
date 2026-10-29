#!/usr/bin/env python3
"""Create and validate evidence-driven, authorized security campaigns.

This harness deliberately does not send requests, exploit targets, or submit
reports. It provides a durable cooperative task coordinator, creates isolated
research workspaces, tracks hypotheses and reviewer identity, checks evidence
gates, and inventories retained artifacts.
"""

from __future__ import annotations

import argparse
import copy
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
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSETS = PROJECT_ROOT / "assets"

CAMPAIGN_DIRS = (
    "tasks",
    "findings",
    "evidence",
    "tools",
    "reports",
    "logs",
    "results",
    "worktrees",
)

ORCHESTRATION_DB = "orchestration.db"
TERMINAL_TASK_STATES = ("completed", "failed", "cancelled", "timed-out", "blocked")
SUCCESS_TASK_STATES = ("completed",)

STATUS_VALUES = (
    "idea",
    "source-confirmed",
    "primitive",
    "candidate",
    "validated",
    "reportable",
    "blocked",
    "disproved",
    "duplicate-risk",
)

CANDIDATE_GATES = (
    "authorization_confirmed",
    "scope_confirmed",
    "exact_version_pinned",
    "root_cause_identified",
    "attacker_control_proven",
    "baseline_control",
    "negative_control",
    "positive_case",
    "concrete_impact",
)

REPORTABLE_GATES = CANDIDATE_GATES + (
    "reproduction_complete",
    "independent_replay",
    "prior_art_checked",
    "official_docs_checked",
    "upstream_tests_checked",
    "patch_status_checked",
    "source_refs_verified",
    "cleanup_verified",
    "secrets_removed",
)

LANES = (
    {
        "wave": 0,
        "id": "coordinator-setup",
        "title": "Scope, revision, and threat-model coordinator",
        "objective": (
            "Freeze authorization, scope, exact artifacts, documented security "
            "promises, public entry points, privileged sinks, and stop conditions."
        ),
        "deliverables": (
            "completed campaign.json",
            "authorization record",
            "entry-point and sink inventory",
            "tool probe",
        ),
    },
    {
        "wave": 1,
        "id": "boundary-map",
        "title": "Trust-boundary and identity mapper",
        "objective": (
            "Map authentication, provenance, tenant/project/build/route identity, "
            "manifest authority, normalization, and validation boundaries."
        ),
        "deliverables": (
            "boundary map",
            "source references",
            "falsifiable hypotheses",
            "searched-surface inventory",
        ),
    },
    {
        "wave": 1,
        "id": "sink-first",
        "title": "Sink-first reachability tracer",
        "objective": (
            "Work backward from execution, module load, file, network, native "
            "parser, key, cache, and policy sinks to public inputs."
        ),
        "deliverables": (
            "sink inventory",
            "guard and dominance map",
            "candidate paths",
            "blocked paths",
        ),
    },
    {
        "wave": 1,
        "id": "state-lifecycle",
        "title": "State, ownership, and lifecycle auditor",
        "objective": (
            "Audit globals, pooling, async settlement, parser errors, ownership, "
            "recycling, realm boundaries, cleanup, and failure-state invariants."
        ),
        "deliverables": (
            "state-owner table",
            "lifecycle diagrams",
            "error/async differences",
            "hypotheses and blockers",
        ),
    },
    {
        "wave": 2,
        "id": "protocol-differential",
        "title": "Producer/consumer and cross-layer differential",
        "objective": (
            "Compare parsing, lengths, encodings, case, paths, methods, headers, "
            "and type domains across every layer that handles the same value."
        ),
        "deliverables": (
            "differential table",
            "minimal harness",
            "baseline and negative control",
            "candidate registry entries",
        ),
    },
    {
        "wave": 2,
        "id": "patch-variants",
        "title": "Patch, sibling-path, and prior-art auditor",
        "objective": (
            "Inspect recent fixes, sibling functions, generated bundles, platform "
            "variants, upstream tests, advisories, and duplicate root causes."
        ),
        "deliverables": (
            "patch matrix",
            "sibling census",
            "prior-art assessment",
            "incomplete-fix hypotheses",
        ),
    },
    {
        "wave": 2,
        "id": "deployment-matrix",
        "title": "Deployment and attacker-acquisition analyst",
        "objective": (
            "Test defaults, supported configurations, hosts, platforms, public "
            "coordinate acquisition, and realistic application carriers."
        ),
        "deliverables": (
            "configuration matrix",
            "remote-acquisition proof or blocker",
            "resource measurements",
            "exact conditions",
        ),
    },
    {
        "wave": 3,
        "id": "independent-replay",
        "title": "Independent clean replay and controls",
        "objective": (
            "Reproduce a candidate without the originating agent's private state, "
            "run fresh-process controls, and preserve raw evidence and cleanup."
        ),
        "deliverables": (
            "clean reproduction",
            "three-case truth table",
            "N/M reliability where applicable",
            "artifact hashes",
        ),
    },
    {
        "wave": 3,
        "id": "adversarial-review",
        "title": "Scope, documentation, duplicate, and severity adversary",
        "objective": (
            "Try to close the candidate as intended behavior, application misuse, "
            "out of scope, stale, unpatched prior art, duplicate, or overstated."
        ),
        "deliverables": (
            "closure arguments",
            "primary-source checks",
            "CVSS metric review",
            "narrow surviving claim",
        ),
    },
    {
        "wave": 4,
        "id": "root-synthesis",
        "title": "Root synthesis and filing package",
        "objective": (
            "Resolve conflicting evidence, run reportable gates, write the "
            "root-cause-first report, and verify a clean package."
        ),
        "deliverables": (
            "submission report",
            "reviewer README",
            "self-contained PoC",
            "SHA256SUMS",
        ),
    },
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def future_time(seconds: int) -> str:
    return (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
    ).replace(microsecond=0).isoformat()


def orchestration_path(root: Path) -> Path:
    return root / ORCHESTRATION_DB


def connect_orchestration(root: Path, *, required: bool = True) -> sqlite3.Connection:
    path = orchestration_path(root)
    if required and not path.is_file():
        raise SystemExit(f"orchestration is not initialized: run queue for {root}")
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def initialize_orchestration_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workers (
          worker_id TEXT PRIMARY KEY,
          agent TEXT NOT NULL,
          role TEXT NOT NULL,
          status TEXT NOT NULL,
          registered_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          task_id TEXT PRIMARY KEY,
          wave INTEGER NOT NULL,
          lane TEXT NOT NULL,
          title TEXT NOT NULL,
          packet TEXT NOT NULL,
          state TEXT NOT NULL,
          priority INTEGER NOT NULL DEFAULT 0,
          depends_json TEXT NOT NULL,
          excluded_workers_json TEXT NOT NULL DEFAULT '[]',
          finding_id TEXT,
          attempt INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL,
          timeout_seconds INTEGER NOT NULL,
          lease_owner TEXT,
          lease_token TEXT,
          lease_expires_at TEXT,
          started_at TEXT,
          completed_at TEXT,
          workspace TEXT,
          result_digest TEXT,
          last_error TEXT,
          cancellation_reason TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(lease_owner) REFERENCES workers(worker_id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
          idempotency_key TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          worker_id TEXT NOT NULL,
          digest TEXT NOT NULL,
          result_path TEXT NOT NULL,
          outcome TEXT NOT NULL,
          submitted_at TEXT NOT NULL,
          FOREIGN KEY(task_id) REFERENCES tasks(task_id),
          FOREIGN KEY(worker_id) REFERENCES workers(worker_id)
        );
        CREATE TABLE IF NOT EXISTS events (
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at TEXT NOT NULL,
          event_type TEXT NOT NULL,
          task_id TEXT,
          worker_id TEXT,
          payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS tasks_state_wave_idx ON tasks(state, wave, priority);
        CREATE INDEX IF NOT EXISTS events_task_idx ON events(task_id, event_id);
        """
    )


def set_metadata(connection: sqlite3.Connection, key: str, value: Any) -> None:
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def get_metadata(connection: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return default if row is None else json.loads(row["value"])


def record_event(
    connection: sqlite3.Connection,
    event_type: str,
    *,
    task_id: str | None = None,
    worker_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        "INSERT INTO events(created_at, event_type, task_id, worker_id, payload_json) "
        "VALUES(?, ?, ?, ?, ?)",
        (utc_now(), event_type, task_id, worker_id, json.dumps(payload or {}, sort_keys=True)),
    )


def validate_identity(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}", value):
        raise argparse.ArgumentTypeError(
            "identity must use letters, digits, and . _ @ : -"
        )
    return value


def task_dependencies(row: sqlite3.Row) -> list[str]:
    value = json.loads(row["depends_json"])
    return [str(item) for item in value]


def dependency_state(connection: sqlite3.Connection, row: sqlite3.Row) -> str:
    dependencies = task_dependencies(row)
    if not dependencies:
        return "ready"
    placeholders = ",".join("?" for _ in dependencies)
    states = {
        item["task_id"]: item["state"]
        for item in connection.execute(
            f"SELECT task_id, state FROM tasks WHERE task_id IN ({placeholders})",
            dependencies,
        )
    }
    missing = [item for item in dependencies if item not in states]
    if missing:
        return "missing"
    if any(states[item] in ("failed", "cancelled", "timed-out", "blocked") for item in dependencies):
        return "blocked"
    if all(states[item] in SUCCESS_TASK_STATES for item in dependencies):
        return "ready"
    return "waiting"


def recover_tasks(connection: sqlite3.Connection) -> dict[str, int]:
    now = dt.datetime.now(dt.timezone.utc)
    recovered = 0
    timed_out = 0
    blocked = 0
    budget_stopped = 0
    if campaign_budget_exhausted(connection):
        for row in connection.execute(
            "SELECT * FROM tasks WHERE state IN ('queued', 'running')"
        ).fetchall():
            next_state = "timed-out" if row["state"] == "running" else "cancelled"
            connection.execute(
                "UPDATE tasks SET state=?,lease_owner=NULL,lease_token=NULL,"
                "lease_expires_at=NULL,last_error=?,cancellation_reason=?,updated_at=? "
                "WHERE task_id=?",
                (
                    next_state,
                    "campaign budget exhausted",
                    "campaign budget exhausted" if next_state == "cancelled" else None,
                    utc_now(),
                    row["task_id"],
                ),
            )
            record_event(
                connection,
                "campaign-budget-stopped",
                task_id=row["task_id"],
                worker_id=row["lease_owner"],
                payload={"previousState": row["state"], "nextState": next_state},
            )
            budget_stopped += 1
        return {
            "recovered": recovered,
            "timedOut": timed_out,
            "blocked": blocked,
            "budgetStopped": budget_stopped,
        }
    for row in connection.execute("SELECT * FROM tasks WHERE state = 'running'").fetchall():
        started = parse_time(row["started_at"]) if row["started_at"] else now
        lease_expired = bool(
            row["lease_expires_at"] and parse_time(row["lease_expires_at"]) <= now
        )
        task_expired = (now - started).total_seconds() >= row["timeout_seconds"]
        if not lease_expired and not task_expired:
            continue
        if task_expired:
            state = "timed-out"
            timed_out += 1
        elif row["attempt"] < row["max_attempts"]:
            state = "queued"
            recovered += 1
        else:
            state = "failed"
        connection.execute(
            "UPDATE tasks SET state=?, lease_owner=NULL, lease_token=NULL, "
            "lease_expires_at=NULL, workspace=NULL, last_error=?, updated_at=? "
            "WHERE task_id=?",
            (
                state,
                "task timeout" if task_expired else "worker lease expired",
                utc_now(),
                row["task_id"],
            ),
        )
        record_event(
            connection,
            "task-timeout" if task_expired else "lease-recovered",
            task_id=row["task_id"],
            worker_id=row["lease_owner"],
            payload={"nextState": state, "attempt": row["attempt"]},
        )
    for row in connection.execute("SELECT * FROM tasks WHERE state = 'queued'").fetchall():
        if dependency_state(connection, row) == "blocked":
            connection.execute(
                "UPDATE tasks SET state='blocked', last_error=?, updated_at=? WHERE task_id=?",
                ("dependency ended unsuccessfully", utc_now(), row["task_id"]),
            )
            record_event(connection, "dependency-blocked", task_id=row["task_id"])
            blocked += 1
    return {
        "recovered": recovered,
        "timedOut": timed_out,
        "blocked": blocked,
        "budgetStopped": budget_stopped,
    }


def campaign_budget_exhausted(connection: sqlite3.Connection) -> bool:
    deadline = get_metadata(connection, "deadlineAt")
    return bool(deadline and parse_time(deadline) <= dt.datetime.now(dt.timezone.utc))


def resolve_local_checkout(campaign: dict[str, Any]) -> Path | None:
    candidates = [campaign.get("localCheckout"), campaign.get("repository")]
    for value in candidates:
        if not value:
            continue
        path = Path(str(value)).expanduser()
        if path.is_dir():
            return path.resolve()
    return None


def provision_workspace(
    root: Path,
    campaign: dict[str, Any],
    worker_id: str,
    task_id: str,
    attempt: int,
    packet: str,
) -> tuple[Path, str]:
    safe_worker = re.sub(r"[^A-Za-z0-9_.-]", "_", worker_id)
    safe_task = re.sub(r"[^A-Za-z0-9_.-]", "_", task_id)
    workspace = root / "worktrees" / safe_worker / f"{safe_task}-a{attempt}"
    if workspace.exists():
        raise RuntimeError(f"workspace already exists: {workspace}")
    workspace.parent.mkdir(parents=True, exist_ok=True)
    checkout = resolve_local_checkout(campaign)
    mode = "isolated-directory"
    if checkout is not None and ((checkout / ".git").exists() or (checkout / ".git").is_file()):
        commit = str(campaign.get("commit") or "HEAD")
        completed = subprocess.run(
            ["git", "-C", str(checkout), "worktree", "add", "--detach", str(workspace), commit],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"git worktree failed: {completed.stderr.strip()}")
        mode = "git-worktree"
    else:
        workspace.mkdir(parents=True)
    task_source = root / packet
    if task_source.is_file():
        shutil.copy2(task_source, workspace / "KRINEON_TASK.md")
    write_json(
        workspace / "KRINEON_ASSIGNMENT.json",
        {
            "schemaVersion": 1,
            "campaign": str(root),
            "workerId": worker_id,
            "taskId": task_id,
            "attempt": attempt,
            "workspaceMode": mode,
            "createdAt": utc_now(),
        },
    )
    return workspace, mode


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"expected a JSON object in {path}")
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def template(name: str) -> dict[str, Any]:
    return read_json(ASSETS / name)


def campaign_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def require_campaign(root: Path) -> dict[str, Any]:
    return read_json(root / "campaign.json")


def registry_path(root: Path) -> Path:
    return root / "registry.json"


def load_registry(root: Path) -> dict[str, Any]:
    return read_json(registry_path(root))


def save_registry(root: Path, registry: dict[str, Any]) -> None:
    registry["updatedAt"] = utc_now()
    write_json(registry_path(root), registry)


def task_markdown(lane: dict[str, Any], campaign: dict[str, Any]) -> str:
    deliverables = "\n".join(f"- {item}" for item in lane["deliverables"])
    return f"""# Task: {lane['title']}

## Campaign

- Target: {campaign['target']}
- Repository: {campaign['repository']}
- Exact revision: {campaign['commit']}
- Mode: {campaign['mode']}
- Wave: {lane['wave']}

Read `AUTHORIZATION.md` and `campaign.json` before taking any dynamic action.
Stay within the recorded environment and stop conditions.

## Primary objective

{lane['objective']}

## Required deliverables

{deliverables}

## Evidence contract

- Pin source references to the tested revision.
- Separate runtime proof, source confirmation, and inference.
- Register blocked and disproved paths as well as candidates.
- State the falsification condition for each hypothesis.
- Do not use a static-tool result as exploit evidence.
- Do not access third-party data, degrade services, or broaden authorization.

## Handoff

Use `assets/agent-handoff.template.md` as the structure. Return exact commands,
artifact paths, controls, blockers, and cleanup state.
"""


def cmd_init(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"refusing to initialize non-empty directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in CAMPAIGN_DIRS:
        (root / name).mkdir(exist_ok=True)

    data = template("campaign.template.json")
    data.update(
        {
            "target": args.target,
            "repository": args.repo,
            "localCheckout": str(Path(args.checkout).expanduser().resolve()) if args.checkout else "",
            "commit": args.commit,
            "mode": args.mode,
            "programUrl": args.program_url or "",
            "createdAt": utc_now(),
            "lanes": [lane["id"] for lane in LANES],
        }
    )
    write_json(root / "campaign.json", data)
    write_json(
        registry_path(root),
        {"schemaVersion": 1, "createdAt": utc_now(), "updatedAt": utc_now(), "findings": []},
    )

    authorization = f"""# Authorization record

- Target: {args.target}
- Repository or asset: {args.repo}
- Exact revision: {args.commit}
- Program URL: {args.program_url or 'not recorded'}
- Authorization confirmed: NO
- Allowed environment: local owned fixture
- Allowed actions: source review and bounded local verification
- Prohibited actions: third-party data access, service degradation, persistence,
  uncontrolled code execution, and activity outside recorded scope
- Stop conditions: complete before dynamic testing

Edit this file and `campaign.json` before any live or shared-system test.
"""
    (root / "AUTHORIZATION.md").write_text(authorization, encoding="utf-8")
    (root / "logs" / ".gitkeep").touch()
    print(f"initialized campaign: {root}")
    print("next: edit AUTHORIZATION.md and campaign.json, then run the plan command")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    selected = set(args.lane or ())
    unknown = selected.difference(lane["id"] for lane in LANES)
    if unknown:
        raise SystemExit(f"unknown lanes: {', '.join(sorted(unknown))}")

    included = [lane for lane in LANES if not selected or lane["id"] in selected]
    planned: list[dict[str, Any]] = []
    for lane in included:
        path = root / "tasks" / f"wave-{lane['wave']}-{lane['id']}.md"
        path.write_text(task_markdown(lane, campaign), encoding="utf-8")
        planned.append(
            {
                "taskId": lane["id"],
                "wave": lane["wave"],
                "lane": lane["id"],
                "title": lane["title"],
                "task": str(path.relative_to(root)),
                "dependsOn": (
                    []
                    if lane["wave"] == 0
                    else [
                        earlier["id"]
                        for earlier in included
                        if earlier["wave"] == lane["wave"] - 1
                    ]
                ),
            }
        )
    write_json(
        root / "launch-plan.json",
        {
            "schemaVersion": 2,
            "generatedAt": utc_now(),
            "maxConcurrency": args.max_concurrency,
            "defaultLeaseSeconds": args.lease_seconds,
            "defaultTaskTimeoutSeconds": args.task_timeout_seconds,
            "defaultMaxAttempts": args.max_attempts,
            "campaignBudgetSeconds": args.budget_seconds,
            "validationRule": "a candidate must be replayed by an agent that did not originate it",
            "tasks": planned,
        },
    )
    print(f"wrote {len(planned)} task packets and launch-plan.json")
    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    plan = read_json(root / "launch-plan.json")
    now = utc_now()
    connection = connect_orchestration(root, required=False)
    try:
        initialize_orchestration_schema(connection)
        with connection:
            set_metadata(connection, "schemaVersion", 1)
            set_metadata(connection, "createdAt", get_metadata(connection, "createdAt", now))
            set_metadata(connection, "maxConcurrency", int(plan.get("maxConcurrency", 3)))
            set_metadata(connection, "defaultLeaseSeconds", int(plan.get("defaultLeaseSeconds", 900)))
            set_metadata(
                connection,
                "defaultTaskTimeoutSeconds",
                int(plan.get("defaultTaskTimeoutSeconds", 7200)),
            )
            set_metadata(connection, "defaultMaxAttempts", int(plan.get("defaultMaxAttempts", 2)))
            budget = int(plan.get("campaignBudgetSeconds", 0))
            set_metadata(connection, "campaignBudgetSeconds", budget)
            if get_metadata(connection, "deadlineAt") is None:
                set_metadata(connection, "deadlineAt", future_time(budget) if budget else None)
            inserted = 0
            refreshed = 0
            for task in plan.get("tasks", []):
                task_id = str(task.get("taskId") or task["lane"])
                values = (
                    task_id,
                    int(task["wave"]),
                    str(task["lane"]),
                    str(task["title"]),
                    str(task["task"]),
                    "queued",
                    json.dumps(task.get("dependsOn", [])),
                    int(plan.get("defaultMaxAttempts", 2)),
                    int(plan.get("defaultTaskTimeoutSeconds", 7200)),
                    now,
                    now,
                )
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO tasks("
                    "task_id,wave,lane,title,packet,state,depends_json,max_attempts,"
                    "timeout_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    values,
                )
                if cursor.rowcount:
                    inserted += 1
                    record_event(connection, "task-queued", task_id=task_id)
                else:
                    existing = connection.execute(
                        "SELECT state FROM tasks WHERE task_id=?", (task_id,)
                    ).fetchone()
                    if existing and existing["state"] == "queued":
                        connection.execute(
                            "UPDATE tasks SET wave=?,lane=?,title=?,packet=?,depends_json=?,"
                            "max_attempts=?,timeout_seconds=?,updated_at=? WHERE task_id=?",
                            (
                                int(task["wave"]),
                                str(task["lane"]),
                                str(task["title"]),
                                str(task["task"]),
                                json.dumps(task.get("dependsOn", [])),
                                int(plan.get("defaultMaxAttempts", 2)),
                                int(plan.get("defaultTaskTimeoutSeconds", 7200)),
                                now,
                                task_id,
                            ),
                        )
                        refreshed += 1
            record_event(
                connection,
                "queue-reconciled",
                payload={"inserted": inserted, "refreshed": refreshed},
            )
        print(f"queued {inserted} new tasks; refreshed {refreshed} queued tasks")
        print(f"durable state: {orchestration_path(root)}")
        return 0
    finally:
        connection.close()


def cmd_worker_register(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    connection = connect_orchestration(root)
    now = utc_now()
    try:
        with connection:
            connection.execute(
                "INSERT INTO workers(worker_id,agent,role,status,registered_at,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(worker_id) DO UPDATE SET "
                "agent=excluded.agent,role=excluded.role,status='active',updated_at=excluded.updated_at",
                (args.worker_id, args.agent, args.role, "active", now, now),
            )
            record_event(
                connection,
                "worker-registered",
                worker_id=args.worker_id,
                payload={"agent": args.agent, "role": args.role},
            )
        print(f"registered worker {args.worker_id} ({args.role}; {args.agent})")
        return 0
    finally:
        connection.close()


def cmd_worker_stop(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            row = connection.execute(
                "SELECT * FROM workers WHERE worker_id=?", (args.worker_id,)
            ).fetchone()
            if row is None:
                raise SystemExit(f"unknown worker: {args.worker_id}")
            running = connection.execute(
                "SELECT task_id FROM tasks WHERE state='running' AND lease_owner=?",
                (args.worker_id,),
            ).fetchall()
            if running and not args.force:
                names = ", ".join(row["task_id"] for row in running)
                raise SystemExit(f"worker owns running tasks: {names}; cancel them or use --force")
            for task in running:
                connection.execute(
                    "UPDATE tasks SET state='queued',lease_owner=NULL,lease_token=NULL,"
                    "lease_expires_at=NULL,workspace=NULL,last_error=?,updated_at=? WHERE task_id=?",
                    ("worker stopped", utc_now(), task["task_id"]),
                )
                record_event(
                    connection,
                    "lease-recovered",
                    task_id=task["task_id"],
                    worker_id=args.worker_id,
                    payload={"reason": "worker stopped"},
                )
            connection.execute(
                "UPDATE workers SET status='stopped',updated_at=? WHERE worker_id=?",
                (utc_now(), args.worker_id),
            )
            record_event(connection, "worker-stopped", worker_id=args.worker_id)
        print(f"stopped worker {args.worker_id}; requeued {len(running)} tasks")
        return 0
    finally:
        connection.close()


def cmd_claim(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    connection = connect_orchestration(root)
    try:
        connection.execute("BEGIN IMMEDIATE")
        worker = connection.execute(
            "SELECT * FROM workers WHERE worker_id=?", (args.worker_id,)
        ).fetchone()
        if worker is None or worker["status"] != "active":
            raise SystemExit(f"worker is not registered and active: {args.worker_id}")
        recovery = recover_tasks(connection)
        if campaign_budget_exhausted(connection):
            connection.commit()
            print("campaign budget exhausted", file=sys.stderr)
            return 4
        max_concurrency = int(get_metadata(connection, "maxConcurrency", 3))
        running = connection.execute(
            "SELECT COUNT(*) AS count FROM tasks WHERE state='running'"
        ).fetchone()["count"]
        if running >= max_concurrency:
            connection.commit()
            print("concurrency limit reached", file=sys.stderr)
            return 3
        chosen = None
        for row in connection.execute(
            "SELECT * FROM tasks WHERE state='queued' ORDER BY priority DESC,wave,created_at,task_id"
        ).fetchall():
            excluded = json.loads(row["excluded_workers_json"])
            if args.worker_id in excluded:
                continue
            if dependency_state(connection, row) == "ready":
                chosen = row
                break
        if chosen is None:
            connection.commit()
            if args.json:
                print(json.dumps({"claimed": False, "recovery": recovery}, indent=2))
            else:
                print("no runnable task")
            return 3
        attempt = int(chosen["attempt"]) + 1
        lease_seconds = args.lease_seconds or int(
            get_metadata(connection, "defaultLeaseSeconds", 900)
        )
        token = secrets.token_urlsafe(24)
        workspace, workspace_mode = provision_workspace(
            root,
            campaign,
            args.worker_id,
            chosen["task_id"],
            attempt,
            chosen["packet"],
        )
        now = utc_now()
        lease_expires_at = future_time(lease_seconds)
        connection.execute(
            "UPDATE tasks SET state='running',attempt=?,lease_owner=?,lease_token=?,"
            "lease_expires_at=?,started_at=?,workspace=?,last_error=NULL,updated_at=? "
            "WHERE task_id=? AND state='queued'",
            (
                attempt,
                args.worker_id,
                token,
                lease_expires_at,
                now,
                str(workspace.relative_to(root)),
                now,
                chosen["task_id"],
            ),
        )
        record_event(
            connection,
            "task-claimed",
            task_id=chosen["task_id"],
            worker_id=args.worker_id,
            payload={
                "attempt": attempt,
                "leaseSeconds": lease_seconds,
                "workspace": str(workspace.relative_to(root)),
                "workspaceMode": workspace_mode,
            },
        )
        connection.commit()
        payload = {
            "claimed": True,
            "taskId": chosen["task_id"],
            "lane": chosen["lane"],
            "title": chosen["title"],
            "packet": chosen["packet"],
            "workspace": str(workspace),
            "attempt": attempt,
            "leaseToken": token,
            "leaseExpiresAt": lease_expires_at,
            "timeoutSeconds": chosen["timeout_seconds"],
            "findingId": chosen["finding_id"],
            "recovery": recovery,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"claimed {chosen['task_id']} as {args.worker_id}")
            print(f"workspace: {workspace}")
            print(f"lease token: {token}")
        return 0
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def require_owned_lease(
    connection: sqlite3.Connection, task_id: str, worker_id: str, token: str
) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    if row is None:
        raise SystemExit(f"unknown task: {task_id}")
    if row["state"] != "running" or row["lease_owner"] != worker_id or row["lease_token"] != token:
        raise SystemExit("task lease does not match worker/token or is no longer running")
    return row


def cmd_heartbeat(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            recover_tasks(connection)
        with connection:
            row = require_owned_lease(
                connection, args.task_id, args.worker_id, args.lease_token
            )
            lease_seconds = args.lease_seconds or int(
                get_metadata(connection, "defaultLeaseSeconds", 900)
            )
            connection.execute(
                "UPDATE tasks SET lease_expires_at=?,updated_at=? WHERE task_id=?",
                (future_time(lease_seconds), utc_now(), row["task_id"]),
            )
            record_event(
                connection,
                "lease-heartbeat",
                task_id=row["task_id"],
                worker_id=args.worker_id,
                payload={"leaseSeconds": lease_seconds},
            )
        print(f"extended lease for {args.task_id}")
        return 0
    finally:
        connection.close()


def update_finding_from_submission(
    root: Path,
    finding_id: str,
    worker_id: str,
    task_id: str,
    digest: str,
    result_path: str,
    result: dict[str, Any],
    *,
    replay: bool,
) -> None:
    path = finding_path(root, finding_id)
    finding = read_json(path)
    if replay:
        originator = str(finding.get("originator") or "").strip()
        if not originator:
            raise SystemExit(f"finding {finding_id} has no recorded originator")
        if originator == worker_id:
            raise SystemExit("originating worker cannot submit the independent replay")
        replay_record = result.get("independentReplay")
        if not isinstance(replay_record, dict) or replay_record.get("passed") is not True:
            raise SystemExit("replay result must contain independentReplay.passed=true")
        if replay_record.get("findingId") != finding_id:
            raise SystemExit("replay result findingId does not match --replay-of")
        if replay_record.get("originator") != originator:
            raise SystemExit("replay result originator does not match finding record")
        if replay_record.get("reviewer") != worker_id:
            raise SystemExit("replay result reviewer does not match submitting worker")
        record = {
            "taskId": task_id,
            "originator": originator,
            "reviewer": worker_id,
            "result": result_path,
            "sha256": digest,
            "submittedAt": utc_now(),
            "passed": True,
        }
        replays = finding.setdefault("independentReplays", [])
        if not any(item.get("sha256") == digest for item in replays):
            replays.append(record)
        reviewers = finding.setdefault("reviewers", [])
        if worker_id not in reviewers:
            reviewers.append(worker_id)
        finding.setdefault("gates", {})["independent_replay"] = True
    else:
        originator = str(finding.get("originator") or "").strip()
        if originator and originator != worker_id:
            reviewers = finding.setdefault("reviewers", [])
            if worker_id not in reviewers:
                reviewers.append(worker_id)
        else:
            finding["originator"] = worker_id
    write_json(path, finding)


def cmd_submit(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    result_source = Path(args.result).expanduser().resolve()
    result = read_json(result_source)
    digest = sha256(result_source)
    connection = connect_orchestration(root)
    try:
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute(
            "SELECT * FROM submissions WHERE idempotency_key=?", (args.idempotency_key,)
        ).fetchone()
        if prior is not None:
            if (
                prior["task_id"] == args.task_id
                and prior["worker_id"] == args.worker_id
                and prior["digest"] == digest
                and prior["outcome"] == args.outcome
            ):
                connection.commit()
                print(f"submission already accepted: {prior['result_path']}")
                return 0
            raise SystemExit("idempotency key already exists with different submission data")
        recover_tasks(connection)
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        task = require_owned_lease(
            connection, args.task_id, args.worker_id, args.lease_token
        )
        replay_of = args.replay_of or (
            task["finding_id"] if task["lane"] == "independent-replay" else None
        )
        finding_id = replay_of or args.finding_id
        result_dir = root / "results" / task["task_id"]
        result_dir.mkdir(parents=True, exist_ok=True)
        result_name = f"attempt-{task['attempt']}-{digest[:16]}.json"
        result_target = result_dir / result_name
        if result_target.exists() and sha256(result_target) != digest:
            raise SystemExit(f"result path collision: {result_target}")
        if not result_target.exists():
            shutil.copy2(result_source, result_target)
        relative_result = result_target.relative_to(root).as_posix()
        if finding_id:
            update_finding_from_submission(
                root,
                finding_id,
                args.worker_id,
                args.task_id,
                digest,
                relative_result,
                result,
                replay=bool(replay_of),
            )
        next_state = "completed" if args.outcome == "completed" else "failed"
        connection.execute(
            "INSERT INTO submissions(idempotency_key,task_id,worker_id,digest,result_path,"
            "outcome,submitted_at) VALUES(?,?,?,?,?,?,?)",
            (
                args.idempotency_key,
                args.task_id,
                args.worker_id,
                digest,
                relative_result,
                args.outcome,
                utc_now(),
            ),
        )
        connection.execute(
            "UPDATE tasks SET state=?,completed_at=?,result_digest=?,lease_expires_at=NULL,"
            "updated_at=? WHERE task_id=?",
            (next_state, utc_now(), digest, utc_now(), args.task_id),
        )
        record_event(
            connection,
            "task-submitted",
            task_id=args.task_id,
            worker_id=args.worker_id,
            payload={
                "outcome": args.outcome,
                "digest": digest,
                "result": relative_result,
                "findingId": finding_id,
            },
        )
        connection.commit()
        print(f"accepted {args.outcome} result: {relative_result}")
        return 0
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def cmd_schedule_replay(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    finding = read_json(finding_path(root, args.finding_id))
    originator = str(finding.get("originator") or "").strip()
    if not originator:
        raise SystemExit("record the finding originator before scheduling replay")
    connection = connect_orchestration(root)
    try:
        with connection:
            existing = connection.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE finding_id=? AND lane='independent-replay'",
                (args.finding_id,),
            ).fetchone()["count"]
            task_id = args.task_id or f"replay-{args.finding_id}-{existing + 1}"
            if connection.execute(
                "SELECT 1 FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone():
                raise SystemExit(f"task already exists: {task_id}")
            packet = root / "tasks" / f"wave-3-{task_id}.md"
            packet.write_text(
                f"""# Independent replay: {args.finding_id}

Finding: `{args.finding_id}`
Originating worker: `{originator}`
Assigned reviewer must be a different registered identity.

Reproduce from the pinned campaign revision without using private originator
state. Preserve the baseline, negative, and positive controls, raw evidence,
environment metadata, hashes, reliability, and cleanup. Submit a JSON result
whose `independentReplay` object contains `findingId`, `originator`, `reviewer`,
and `passed: true` only after a clean replay.
""",
                encoding="utf-8",
            )
            now = utc_now()
            connection.execute(
                "INSERT INTO tasks(task_id,wave,lane,title,packet,state,priority,depends_json,"
                "excluded_workers_json,finding_id,max_attempts,timeout_seconds,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?,?)",
                (
                    task_id,
                    3,
                    "independent-replay",
                    f"Independent replay for {args.finding_id}",
                    packet.relative_to(root).as_posix(),
                    100,
                    json.dumps(args.depends_on or []),
                    json.dumps([originator]),
                    args.finding_id,
                    args.max_attempts,
                    args.timeout_seconds,
                    now,
                    now,
                ),
            )
            record_event(
                connection,
                "replay-scheduled",
                task_id=task_id,
                payload={"findingId": args.finding_id, "excludedOriginator": originator},
            )
        print(f"scheduled {task_id}; excluded originator {originator}")
        return 0
    finally:
        connection.close()


def cmd_cancel(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (args.task_id,)).fetchone()
            if row is None:
                raise SystemExit(f"unknown task: {args.task_id}")
            if row["state"] in TERMINAL_TASK_STATES:
                print(f"task already terminal: {row['state']}")
                return 0
            connection.execute(
                "UPDATE tasks SET state='cancelled',cancellation_reason=?,lease_expires_at=NULL,"
                "updated_at=? WHERE task_id=?",
                (args.reason, utc_now(), args.task_id),
            )
            record_event(
                connection,
                "task-cancelled",
                task_id=args.task_id,
                payload={"reason": args.reason},
            )
            recover_tasks(connection)
        print(f"cancelled {args.task_id}")
        return 0
    finally:
        connection.close()


def cmd_retry(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (args.task_id,)).fetchone()
            if row is None:
                raise SystemExit(f"unknown task: {args.task_id}")
            if row["state"] not in ("failed", "timed-out", "cancelled", "blocked"):
                raise SystemExit(f"task is not retryable from state {row['state']}")
            if row["attempt"] >= row["max_attempts"] and not args.extend_attempts:
                raise SystemExit("attempt budget exhausted; use --extend-attempts explicitly")
            max_attempts = row["max_attempts"] + (1 if args.extend_attempts else 0)
            connection.execute(
                "UPDATE tasks SET state='queued',max_attempts=?,lease_owner=NULL,lease_token=NULL,"
                "lease_expires_at=NULL,completed_at=NULL,cancellation_reason=NULL,last_error=NULL,"
                "updated_at=? WHERE task_id=?",
                (max_attempts, utc_now(), args.task_id),
            )
            record_event(
                connection,
                "task-retried",
                task_id=args.task_id,
                payload={"maxAttempts": max_attempts, "reason": args.reason},
            )
        print(f"requeued {args.task_id}")
        return 0
    finally:
        connection.close()


def cmd_recover(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            result = recover_tasks(connection)
        print(json.dumps(result, indent=2) if args.json else ", ".join(f"{k}={v}" for k, v in result.items()))
        return 0
    finally:
        connection.close()


def orchestration_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    tasks = [dict(row) for row in connection.execute("SELECT * FROM tasks ORDER BY wave,task_id")]
    workers = [dict(row) for row in connection.execute("SELECT * FROM workers ORDER BY worker_id")]
    counts: dict[str, int] = {}
    for task in tasks:
        counts[task["state"]] = counts.get(task["state"], 0) + 1
        task["dependsOn"] = json.loads(task.pop("depends_json"))
        task["excludedWorkers"] = json.loads(task.pop("excluded_workers_json"))
        task.pop("lease_token", None)
    return {
        "metadata": {
            row["key"]: json.loads(row["value"])
            for row in connection.execute("SELECT key,value FROM metadata ORDER BY key")
        },
        "taskCounts": counts,
        "workers": workers,
        "tasks": tasks,
    }


def cmd_orchestration_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        with connection:
            recovery = recover_tasks(connection)
        snapshot = orchestration_snapshot(connection)
        snapshot["recovery"] = recovery
        if args.json:
            print(json.dumps(snapshot, indent=2))
            return 0
        print("tasks: " + ", ".join(f"{key}={value}" for key, value in sorted(snapshot["taskCounts"].items())))
        print(f"workers: {len(snapshot['workers'])}")
        print()
        print(f"{'TASK':<30} {'STATE':<12} {'WORKER':<18} ATTEMPT  DEPENDENCIES")
        print("-" * 100)
        for task in snapshot["tasks"]:
            print(
                f"{task['task_id']:<30} {task['state']:<12} "
                f"{(task['lease_owner'] or '-'):<18} {task['attempt']}/{task['max_attempts']}      "
                f"{','.join(task['dependsOn']) or '-'}"
            )
        return 0
    finally:
        connection.close()


def validate_finding_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,63}", value):
        raise argparse.ArgumentTypeError("finding ID must start with a letter and use letters, digits, _ or -")
    return value


def cmd_register(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    registry = load_registry(root)
    if any(item.get("id") == args.finding_id for item in registry.get("findings", [])):
        raise SystemExit(f"finding already exists: {args.finding_id}")
    finding = template("finding.template.json")
    finding.update(
        {
            "id": args.finding_id,
            "title": args.title,
            "lane": args.lane,
            "status": args.status,
            "originator": args.originator or "",
        }
    )
    path = root / "findings" / f"{args.finding_id}.json"
    write_json(path, finding)
    registry.setdefault("findings", []).append(
        {
            "id": args.finding_id,
            "title": args.title,
            "lane": args.lane,
            "status": args.status,
            "path": str(path.relative_to(root)),
        }
    )
    save_registry(root, registry)
    print(f"registered {args.finding_id}: {path}")
    return 0


def finding_path(root: Path, finding_id: str) -> Path:
    path = root / "findings" / f"{finding_id}.json"
    if not path.is_file():
        raise SystemExit(f"unknown finding: {finding_id}")
    return path


def replay_is_machine_verified(root: Path, finding: dict[str, Any]) -> bool:
    originator = str(finding.get("originator") or "").strip()
    finding_id = str(finding.get("id") or "").strip()
    replays = finding.get("independentReplays")
    if not originator or not finding_id or not isinstance(replays, list):
        return False
    database = orchestration_path(root)
    if not database.is_file():
        return False
    connection = connect_orchestration(root)
    try:
        for replay in replays:
            if not isinstance(replay, dict) or replay.get("passed") is not True:
                continue
            reviewer = str(replay.get("reviewer") or "").strip()
            task_id = str(replay.get("taskId") or "").strip()
            digest = str(replay.get("sha256") or "").strip()
            result_name = str(replay.get("result") or "").strip()
            if not reviewer or reviewer == originator or not task_id or not digest or not result_name:
                continue
            result_path = root / result_name
            if not result_path.is_file() or sha256(result_path) != digest:
                continue
            task = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            submission = connection.execute(
                "SELECT * FROM submissions WHERE task_id=? AND worker_id=? AND digest=? "
                "AND result_path=? AND outcome='completed'",
                (task_id, reviewer, digest, result_name),
            ).fetchone()
            worker = connection.execute(
                "SELECT * FROM workers WHERE worker_id=?", (reviewer,)
            ).fetchone()
            if task is None or submission is None or worker is None:
                continue
            if (
                task["state"] != "completed"
                or task["lane"] != "independent-replay"
                or task["finding_id"] != finding_id
                or originator not in json.loads(task["excluded_workers_json"])
            ):
                continue
            payload = read_json(result_path).get("independentReplay")
            if not isinstance(payload, dict):
                continue
            if (
                payload.get("findingId") == finding_id
                and payload.get("originator") == originator
                and payload.get("reviewer") == reviewer
                and payload.get("passed") is True
            ):
                return True
        return False
    finally:
        connection.close()


def gate_result(
    finding: dict[str, Any], level: str, *, replay_verified: bool = False
) -> dict[str, Any]:
    required_gates = CANDIDATE_GATES if level == "candidate" else REPORTABLE_GATES
    gates = finding.get("gates", {})
    missing_gates = [name for name in required_gates if gates.get(name) is not True]
    missing_fields: list[str] = []
    for field in ("rootCause", "impact"):
        if not str(finding.get(field, "")).strip():
            missing_fields.append(field)
    for field in ("preconditions", "evidence"):
        value = finding.get(field)
        if not isinstance(value, list) or not value:
            missing_fields.append(field)
    controls = finding.get("controls", {})
    for control in ("baseline", "negative", "positive"):
        if not str(controls.get(control, "")).strip():
            missing_fields.append(f"controls.{control}")
    if level == "reportable":
        originator = str(finding.get("originator") or "").strip()
        if not originator:
            missing_fields.append("originator")
        if not replay_verified:
            missing_fields.append("independentReplays")
    passed = not missing_gates and not missing_fields
    return {
        "finding": finding.get("id"),
        "level": level,
        "passed": passed,
        "missingGates": missing_gates,
        "missingFields": missing_fields,
    }


def cmd_gate(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    finding = read_json(finding_path(root, args.finding_id))
    result = gate_result(
        finding,
        args.level,
        replay_verified=(
            replay_is_machine_verified(root, finding) if args.level == "reportable" else False
        ),
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        label = "PASS" if result["passed"] else "FAIL"
        print(f"{label}: {args.finding_id} {args.level} gate")
        if result["missingGates"]:
            print("missing gates:")
            for item in result["missingGates"]:
                print(f"  - {item}")
        if result["missingFields"]:
            print("missing evidence fields:")
            for item in result["missingFields"]:
                print(f"  - {item}")
    return 0 if result["passed"] else 1


def cmd_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    registry = load_registry(root)
    rows = registry.get("findings", [])
    summary: dict[str, int] = {}
    for row in rows:
        summary[row.get("status", "unknown")] = summary.get(row.get("status", "unknown"), 0) + 1
    if args.json:
        print(json.dumps({"campaign": campaign, "statusCounts": summary, "findings": rows}, indent=2))
        return 0
    print(f"target:     {campaign['target']}")
    print(f"repository: {campaign['repository']}")
    print(f"revision:   {campaign['commit']}")
    print(f"mode:       {campaign['mode']}")
    print(f"findings:   {len(rows)}")
    if not rows:
        return 0
    print()
    print(f"{'ID':<14} {'STATUS':<18} {'LANE':<24} TITLE")
    print("-" * 90)
    for row in rows:
        print(f"{row['id']:<14} {row['status']:<18} {row['lane']:<24} {row['title']}")
    return 0


def iter_artifacts(root: Path) -> Iterable[Path]:
    for dirname in ("evidence", "findings", "reports", "results"):
        base = root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS":
                yield path
    for filename in ("campaign.json", "registry.json", "launch-plan.json", "AUTHORIZATION.md"):
        path = root / filename
        if path.is_file():
            yield path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_hash(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    artifacts = list(dict.fromkeys(iter_artifacts(root)))
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in artifacts]
    output = root / "SHA256SUMS"
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    print(f"hashed {len(lines)} artifacts: {output}")
    return 0


TEXT_SUFFIXES = {".md", ".txt", ".json", ".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".yml", ".yaml"}
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(?:/home/[^\s'\"`]+|[A-Za-z]:\\\\Users\\\\[^\s'\"`]+)")
FLOATING_LINK_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/blob/(?:main|master|canary)/")
SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
)


def lint_files(root: Path) -> Iterable[Path]:
    excluded = {".git", "node_modules", ".next", "dist", "build", "worktrees"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in excluded for part in path.relative_to(root).parts):
            continue
        yield path


def cmd_lint(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    findings: list[dict[str, str]] = []
    hard_fail = False
    for path in lint_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root).as_posix()
        for label, regex in SECRET_PATTERNS:
            if regex.search(text):
                findings.append({"severity": "error", "file": rel, "issue": label})
                hard_fail = True
        if LOCAL_PATH_RE.search(text):
            findings.append({"severity": "warning", "file": rel, "issue": "researcher-local absolute path"})
        if FLOATING_LINK_RE.search(text):
            findings.append({"severity": "warning", "file": rel, "issue": "floating GitHub source link"})
        if re.search(r"\b(?:TODO|TBD|FIXME)\b", text):
            findings.append({"severity": "warning", "file": rel, "issue": "unresolved placeholder"})
    if args.json:
        print(json.dumps({"passed": not hard_fail and not (args.strict and findings), "findings": findings}, indent=2))
    elif findings:
        for item in findings:
            print(f"{item['severity'].upper()}: {item['file']}: {item['issue']}")
    else:
        print("PASS: no package-hygiene findings")
    return 1 if hard_fail or (args.strict and findings) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize an empty campaign directory")
    init.add_argument("campaign_dir")
    init.add_argument("--target", required=True)
    init.add_argument("--repo", required=True)
    init.add_argument(
        "--checkout",
        help="optional local Git checkout used to provision isolated worker worktrees",
    )
    init.add_argument("--commit", required=True)
    init.add_argument("--mode", choices=("source", "local-lab", "testnet", "authorized-live"), default="source")
    init.add_argument("--program-url")
    init.set_defaults(func=cmd_init)

    plan = sub.add_parser("plan", help="write wave-based agent task packets")
    plan.add_argument("campaign_dir")
    plan.add_argument("--lane", action="append", help="limit to a lane ID; repeatable")
    plan.add_argument("--max-concurrency", type=int, default=3)
    plan.add_argument("--lease-seconds", type=int, default=900)
    plan.add_argument("--task-timeout-seconds", type=int, default=7200)
    plan.add_argument("--max-attempts", type=int, default=2)
    plan.add_argument(
        "--budget-seconds",
        type=int,
        default=0,
        help="campaign wall-clock budget; zero means no deadline",
    )
    plan.set_defaults(func=cmd_plan)

    queue = sub.add_parser("queue", help="materialize launch-plan tasks in the durable scheduler")
    queue.add_argument("campaign_dir")
    queue.set_defaults(func=cmd_queue)

    worker_register = sub.add_parser("worker-register", help="register or reactivate a worker identity")
    worker_register.add_argument("campaign_dir")
    worker_register.add_argument("worker_id", type=validate_identity)
    worker_register.add_argument("--agent", required=True, help="agent/runtime identity")
    worker_register.add_argument(
        "--role", choices=("coordinator", "originator", "reviewer", "worker"), default="worker"
    )
    worker_register.set_defaults(func=cmd_worker_register)

    worker_stop = sub.add_parser("worker-stop", help="stop a worker and optionally recover its leases")
    worker_stop.add_argument("campaign_dir")
    worker_stop.add_argument("worker_id", type=validate_identity)
    worker_stop.add_argument("--force", action="store_true", help="requeue running leases owned by this worker")
    worker_stop.set_defaults(func=cmd_worker_stop)

    claim = sub.add_parser("claim", help="atomically lease the next dependency-ready task")
    claim.add_argument("campaign_dir")
    claim.add_argument("worker_id", type=validate_identity)
    claim.add_argument("--lease-seconds", type=int)
    claim.add_argument("--json", action="store_true")
    claim.set_defaults(func=cmd_claim)

    heartbeat = sub.add_parser("heartbeat", help="renew a task lease")
    heartbeat.add_argument("campaign_dir")
    heartbeat.add_argument("worker_id", type=validate_identity)
    heartbeat.add_argument("task_id")
    heartbeat.add_argument("--lease-token", required=True)
    heartbeat.add_argument("--lease-seconds", type=int)
    heartbeat.set_defaults(func=cmd_heartbeat)

    submit = sub.add_parser("submit", help="idempotently ingest a leased task result")
    submit.add_argument("campaign_dir")
    submit.add_argument("worker_id", type=validate_identity)
    submit.add_argument("task_id")
    submit.add_argument("--lease-token", required=True)
    submit.add_argument("--result", required=True)
    submit.add_argument("--idempotency-key", required=True)
    submit.add_argument("--outcome", choices=("completed", "failed"), default="completed")
    submit.add_argument("--finding-id", type=validate_finding_id)
    submit.add_argument("--replay-of", type=validate_finding_id)
    submit.set_defaults(func=cmd_submit)

    schedule_replay = sub.add_parser(
        "schedule-replay", help="create a finding-specific task that excludes its originator"
    )
    schedule_replay.add_argument("campaign_dir")
    schedule_replay.add_argument("finding_id", type=validate_finding_id)
    schedule_replay.add_argument("--task-id")
    schedule_replay.add_argument("--depends-on", action="append")
    schedule_replay.add_argument("--max-attempts", type=int, default=2)
    schedule_replay.add_argument("--timeout-seconds", type=int, default=7200)
    schedule_replay.set_defaults(func=cmd_schedule_replay)

    cancel = sub.add_parser("cancel", help="cancel a queued or running task")
    cancel.add_argument("campaign_dir")
    cancel.add_argument("task_id")
    cancel.add_argument("--reason", required=True)
    cancel.set_defaults(func=cmd_cancel)

    retry = sub.add_parser("retry", help="requeue a failed, timed-out, cancelled, or blocked task")
    retry.add_argument("campaign_dir")
    retry.add_argument("task_id")
    retry.add_argument("--reason", required=True)
    retry.add_argument("--extend-attempts", action="store_true")
    retry.set_defaults(func=cmd_retry)

    recover = sub.add_parser("recover", help="recover expired worker leases and dependency blocks")
    recover.add_argument("campaign_dir")
    recover.add_argument("--json", action="store_true")
    recover.set_defaults(func=cmd_recover)

    orchestration_status = sub.add_parser(
        "orchestration-status", help="show durable workers, tasks, leases, and dependencies"
    )
    orchestration_status.add_argument("campaign_dir")
    orchestration_status.add_argument("--json", action="store_true")
    orchestration_status.set_defaults(func=cmd_orchestration_status)

    register = sub.add_parser("register", help="register a stable candidate ID")
    register.add_argument("campaign_dir")
    register.add_argument("finding_id", type=validate_finding_id)
    register.add_argument("--title", required=True)
    register.add_argument("--lane", required=True)
    register.add_argument("--status", choices=STATUS_VALUES, default="idea")
    register.add_argument("--originator", type=validate_identity)
    register.set_defaults(func=cmd_register)

    status = sub.add_parser("status", help="show campaign and registry status")
    status.add_argument("campaign_dir")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    gate = sub.add_parser("gate", help="evaluate candidate or reportable evidence gates")
    gate.add_argument("campaign_dir")
    gate.add_argument("finding_id", type=validate_finding_id)
    gate.add_argument("--level", choices=("candidate", "reportable"), default="candidate")
    gate.add_argument("--json", action="store_true")
    gate.set_defaults(func=cmd_gate)

    hash_cmd = sub.add_parser("hash", help="hash retained findings, evidence, reports, and metadata")
    hash_cmd.add_argument("campaign_dir")
    hash_cmd.set_defaults(func=cmd_hash)

    lint = sub.add_parser("lint", help="scan a campaign for secrets, local paths, floating links, and placeholders")
    lint.add_argument("campaign_dir")
    lint.add_argument("--strict", action="store_true", help="fail on warnings as well as secrets")
    lint.add_argument("--json", action="store_true")
    lint.set_defaults(func=cmd_lint)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
