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
from urllib.parse import urlsplit

try:
    from .path_proof import validate_path_proof
    from .reality_evidence import safe_campaign_path, validate_attestation
except ImportError:  # Direct script execution.
    from path_proof import validate_path_proof
    from reality_evidence import safe_campaign_path, validate_attestation


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSETS = PROJECT_ROOT / "assets"
PROFILES = PROJECT_ROOT / "profiles"
APPROACH_FAMILIES = PROFILES / "approach-families.json"
REALITY_RUNNER = PROJECT_ROOT / "scripts" / "reality_runner.py"

CAMPAIGN_DIRS = (
    "tasks",
    "findings",
    "evidence",
    "tools",
    "reports",
    "logs",
    "results",
    "worktrees",
    "third_party",
    "benchmarks",
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
    "critical_chain_complete",
    "stock_or_supported_reachability",
    "rce_or_critical_impact",
    "no_app_authored_sink",
    "harmless_real_terminal",
    "deployment_feasible",
    "production_equivalent_environment",
    "baseline_control",
    "negative_control",
    "positive_case",
    "concrete_impact",
    "automated_triage_reviewed",
    "path_proof_complete",
)

REPORTABLE_GATES = CANDIDATE_GATES + (
    "reproduction_complete",
    "independent_replay",
    "prior_art_checked",
    "official_docs_checked",
    "upstream_tests_checked",
    "current_version_checked",
    "source_refs_verified",
    "cleanup_verified",
    "secrets_removed",
)

PROFILE_NAMES = ("critical-rce", "chrome-v8")


def approach_family_config() -> dict[str, Any]:
    config = read_json(APPROACH_FAMILIES)
    families = config.get("families")
    mappings = config.get("profileMappings")
    if not isinstance(families, list) or not families or not isinstance(mappings, dict):
        raise SystemExit("invalid approach-family registry")
    required = {"id", "title", "boundary", "mechanism", "invariant", "exploration"}
    ids: set[str] = set()
    for family in families:
        if not isinstance(family, dict) or not required.issubset(family):
            raise SystemExit("invalid approach-family definition")
        family_id = str(family["id"])
        if family_id in ids:
            raise SystemExit(f"duplicate approach family: {family_id}")
        ids.add(family_id)
    for profile_name, profile_mapping in mappings.items():
        if not isinstance(profile_mapping, dict):
            raise SystemExit(f"invalid approach mapping for profile: {profile_name}")
        for lane_id, family_ids in profile_mapping.items():
            if not isinstance(family_ids, list) or not family_ids:
                raise SystemExit(f"lane has no approach families: {profile_name}/{lane_id}")
            unknown = set(str(value) for value in family_ids).difference(ids)
            if unknown:
                raise SystemExit(
                    f"lane {profile_name}/{lane_id} uses unknown approach families: "
                    + ", ".join(sorted(unknown))
                )
    return config


def approach_family_definitions() -> dict[str, dict[str, Any]]:
    return {
        str(family["id"]): dict(family)
        for family in approach_family_config()["families"]
    }


def campaign_lanes(profile_name: str) -> tuple[dict[str, Any], ...]:
    if profile_name not in PROFILE_NAMES:
        raise SystemExit(f"unknown campaign profile: {profile_name}")
    profile = read_json(PROFILES / f"{profile_name}.json")
    approach_config = approach_family_config()
    profile_mapping = approach_config["profileMappings"].get(profile_name)
    if not isinstance(profile_mapping, dict):
        raise SystemExit(f"profile has no approach-family mapping: {profile_name}")
    lanes = profile.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        raise SystemExit(f"profile has no lanes: {profile_name}")
    required = {"wave", "id", "title", "objective", "deliverables"}
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lane in lanes:
        if not isinstance(lane, dict) or not required.issubset(lane):
            raise SystemExit(f"invalid lane in profile: {profile_name}")
        lane_id = str(lane["id"])
        if lane_id in seen:
            raise SystemExit(f"duplicate lane in profile {profile_name}: {lane_id}")
        seen.add(lane_id)
        item = dict(lane)
        item["deliverables"] = tuple(str(value) for value in lane["deliverables"])
        item["dependsOn"] = [str(value) for value in lane.get("dependsOn", [])]
        item["priority"] = int(lane.get("priority", 0))
        family_ids = profile_mapping.get(lane_id)
        if not isinstance(family_ids, list) or not family_ids:
            raise SystemExit(
                f"profile lane has no explicit semantic approach family: "
                f"{profile_name}/{lane_id}"
            )
        item["approachFamilies"] = [str(value) for value in family_ids]
        normalized.append(item)
    for lane in normalized:
        unknown = set(lane["dependsOn"]).difference(seen)
        if unknown:
            raise SystemExit(
                f"profile {profile_name} lane {lane['id']} has unknown dependencies: "
                + ", ".join(sorted(unknown))
            )
    return tuple(normalized)


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
    initialize_orchestration_schema(connection)
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
          excluded_agents_json TEXT NOT NULL DEFAULT '[]',
          finding_id TEXT,
          unblocks_task_id TEXT,
          research_round INTEGER NOT NULL DEFAULT 0,
          route_id TEXT,
          task_kind TEXT NOT NULL DEFAULT 'ordinary',
          reviews_task_id TEXT,
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
        CREATE TABLE IF NOT EXISTS approach_families (
          family_id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          boundary TEXT NOT NULL,
          mechanism TEXT NOT NULL,
          invariant_text TEXT NOT NULL,
          exploration INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_approach_families (
          task_id TEXT NOT NULL,
          family_id TEXT NOT NULL,
          PRIMARY KEY(task_id, family_id),
          FOREIGN KEY(task_id) REFERENCES tasks(task_id),
          FOREIGN KEY(family_id) REFERENCES approach_families(family_id)
        );
        CREATE TABLE IF NOT EXISTS research_leads (
          lead_id TEXT PRIMARY KEY,
          semantic_identity TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL,
          evidence_grade TEXT NOT NULL,
          state TEXT NOT NULL,
          title TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          first_task_id TEXT,
          first_worker_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_research_leads (
          task_id TEXT NOT NULL,
          lead_id TEXT NOT NULL,
          relationship TEXT NOT NULL,
          PRIMARY KEY(task_id, lead_id, relationship),
          FOREIGN KEY(task_id) REFERENCES tasks(task_id),
          FOREIGN KEY(lead_id) REFERENCES research_leads(lead_id)
        );
        CREATE INDEX IF NOT EXISTS tasks_state_wave_idx ON tasks(state, wave, priority);
        CREATE INDEX IF NOT EXISTS task_approach_family_idx
          ON task_approach_families(family_id, task_id);
        CREATE UNIQUE INDEX IF NOT EXISTS tasks_one_running_per_worker
          ON tasks(lease_owner)
          WHERE state = 'running' AND lease_owner IS NOT NULL;
        CREATE INDEX IF NOT EXISTS events_task_idx ON events(task_id, event_id);
        CREATE INDEX IF NOT EXISTS research_leads_grade_idx
          ON research_leads(state, evidence_grade, updated_at);
        """
    )
    task_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
    }
    if "unblocks_task_id" not in task_columns:
        connection.execute("ALTER TABLE tasks ADD COLUMN unblocks_task_id TEXT")
    if "excluded_agents_json" not in task_columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN excluded_agents_json TEXT NOT NULL DEFAULT '[]'"
        )
    if "research_round" not in task_columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN research_round INTEGER NOT NULL DEFAULT 0"
        )
    if "route_id" not in task_columns:
        connection.execute("ALTER TABLE tasks ADD COLUMN route_id TEXT")
    if "task_kind" not in task_columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN task_kind TEXT NOT NULL DEFAULT 'ordinary'"
        )
    if "reviews_task_id" not in task_columns:
        connection.execute("ALTER TABLE tasks ADD COLUMN reviews_task_id TEXT")
    if "lead_id" not in task_columns:
        connection.execute("ALTER TABLE tasks ADD COLUMN lead_id TEXT")
    connection.commit()


def set_metadata(connection: sqlite3.Connection, key: str, value: Any) -> None:
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def get_metadata(connection: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return default if row is None else json.loads(row["value"])


def sync_approach_family_registry(
    connection: sqlite3.Connection, selected: list[dict[str, Any]] | None = None
) -> None:
    now = utc_now()
    families = selected if selected is not None else approach_family_config()["families"]
    for family in families:
        connection.execute(
            "INSERT INTO approach_families(family_id,title,boundary,mechanism,invariant_text,"
            "exploration,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(family_id) DO UPDATE SET title=excluded.title,boundary=excluded.boundary,"
            "mechanism=excluded.mechanism,invariant_text=excluded.invariant_text,"
            "exploration=excluded.exploration,updated_at=excluded.updated_at",
            (
                family["id"],
                family["title"],
                family["boundary"],
                family["mechanism"],
                family["invariant"],
                1 if family["exploration"] else 0,
                now,
                now,
            ),
        )


def set_task_approach_families(
    connection: sqlite3.Connection, task_id: str, family_ids: list[str]
) -> None:
    normalized = list(dict.fromkeys(str(value).strip() for value in family_ids if str(value).strip()))
    if not normalized:
        raise SystemExit(f"task has no explicit approach family: {task_id}")
    known = {
        row["family_id"]
        for row in connection.execute(
            "SELECT family_id FROM approach_families WHERE family_id IN ("
            + ",".join("?" for _ in normalized)
            + ")",
            normalized,
        ).fetchall()
    }
    unknown = set(normalized).difference(known)
    if unknown:
        raise SystemExit(
            f"task {task_id} uses unknown approach families: {', '.join(sorted(unknown))}"
        )
    connection.execute("DELETE FROM task_approach_families WHERE task_id=?", (task_id,))
    connection.executemany(
        "INSERT INTO task_approach_families(task_id,family_id) VALUES(?,?)",
        [(task_id, family_id) for family_id in normalized],
    )


def task_approach_families(connection: sqlite3.Connection, task_id: str) -> list[str]:
    return [
        row["family_id"]
        for row in connection.execute(
            "SELECT family_id FROM task_approach_families WHERE task_id=? ORDER BY family_id",
            (task_id,),
        ).fetchall()
    ]


def approach_family_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    families: list[dict[str, Any]] = []
    for family in connection.execute(
        "SELECT * FROM approach_families ORDER BY family_id"
    ).fetchall():
        state_counts = {
            row["state"]: int(row["count"])
            for row in connection.execute(
                "SELECT tasks.state,COUNT(DISTINCT tasks.task_id) AS count "
                "FROM task_approach_families JOIN tasks USING(task_id) "
                "WHERE family_id=? GROUP BY tasks.state",
                (family["family_id"],),
            ).fetchall()
        }
        active_agents = int(
            connection.execute(
                "SELECT COUNT(DISTINCT workers.agent) AS count "
                "FROM task_approach_families JOIN tasks USING(task_id) "
                "JOIN workers ON workers.worker_id=tasks.lease_owner "
                "WHERE family_id=? AND tasks.state='running'",
                (family["family_id"],),
            ).fetchone()["count"]
        )
        explored = sum(
            state_counts.get(state, 0)
            for state in ("completed", "failed", "blocked", "timed-out", "cancelled")
        )
        families.append(
            {
                "id": family["family_id"],
                "title": family["title"],
                "boundary": family["boundary"],
                "mechanism": family["mechanism"],
                "invariant": family["invariant_text"],
                "exploration": bool(family["exploration"]),
                "taskStates": state_counts,
                "activeAgents": active_agents,
                "exploredTasks": explored,
                "coverageLoad": explored + state_counts.get("running", 0),
            }
        )
    exploration = [family for family in families if family["exploration"]]
    active_exploration_agents = int(
        connection.execute(
            "SELECT COUNT(DISTINCT workers.agent) AS count "
            "FROM task_approach_families JOIN approach_families USING(family_id) "
            "JOIN tasks USING(task_id) JOIN workers ON workers.worker_id=tasks.lease_owner "
            "WHERE tasks.state='running' AND approach_families.exploration=1"
        ).fetchone()["count"]
    )
    convergence_threshold = max(2, (active_exploration_agents + 1) // 2)
    minimum_load = min((family["coverageLoad"] for family in exploration), default=0)
    underexplored = [
        family["id"] for family in exploration if family["coverageLoad"] == minimum_load
    ]
    converged = [
        family["id"]
        for family in exploration
        if family["activeAgents"] >= convergence_threshold
    ]
    return {
        "schemaVersion": 1,
        "generatedAt": utc_now(),
        "policy": {
            "identityBasis": "registered boundary + mechanism + invariant, never task wording",
            "convergenceThreshold": convergence_threshold,
            "activeExplorationAgents": active_exploration_agents,
            "redirectBeforeDominance": True,
            "selectionOrder": [
                "lowest-active-agent-load",
                "lowest-prior-coverage",
                "task-priority",
            ],
            "promisingOrSuspiciousDoesNotOverrideDiversity": True,
        },
        "underexploredFamilies": underexplored,
        "convergedFamilies": converged,
        "families": families,
    }


def write_approach_family_snapshot(root: Path, connection: sqlite3.Connection) -> None:
    write_json(root / "approach-registry.json", approach_family_snapshot(connection))


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


def parse_max_concurrency(value: Any) -> str | int:
    text = str(value).strip().lower()
    if text == "auto":
        return "auto"
    try:
        parsed = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "max concurrency must be 'auto' or a positive integer"
        ) from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError(
            "max concurrency must be 'auto' or a positive integer"
        )
    return parsed


def active_agent_count(connection: sqlite3.Connection) -> int:
    return int(
        connection.execute(
            "SELECT COUNT(DISTINCT agent) AS count FROM workers WHERE status='active'"
        ).fetchone()["count"]
    )


def resolve_concurrency_limit(connection: sqlite3.Connection) -> tuple[str | int, int]:
    configured = get_metadata(connection, "maxConcurrency", "auto")
    active = active_agent_count(connection)
    if configured == "auto":
        return configured, active
    limit = int(configured)
    return limit, min(limit, active)


def validate_task_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{1,127}", value):
        raise argparse.ArgumentTypeError(
            "task ID must start with a letter and use letters, digits, dot, underscore, or dash"
        )
    return value


def require_string(value: Any, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise SystemExit(f"result must include non-empty {label}")
    return result


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise SystemExit(f"result must include {label} as a non-empty list")
    result = [str(item).strip() for item in value if str(item).strip()]
    if not result:
        raise SystemExit(f"result must include {label} as a non-empty list")
    return result


def validate_blocker_result(result: dict[str, Any]) -> dict[str, Any]:
    blocker = result.get("blocker")
    if not isinstance(blocker, dict):
        raise SystemExit("blocked outcome requires a blocker object")
    require_string(blocker.get("category"), "blocker.category")
    require_string(blocker.get("reason"), "blocker.reason")
    require_string(blocker.get("blockedLink"), "blocker.blockedLink")
    require_string(blocker.get("guardOrFailure"), "blocker.guardOrFailure")
    require_string(blocker.get("mechanismFingerprint"), "blocker.mechanismFingerprint")
    require_string(blocker.get("whyBlocked"), "blocker.whyBlocked")
    require_string(blocker.get("cheapestDiscriminator"), "blocker.cheapestDiscriminator")
    require_string(blocker.get("authorityRequired"), "blocker.authorityRequired")
    require_string_list(blocker.get("evidence"), "blocker.evidence")
    require_string_list(blocker.get("attempts"), "blocker.attempts")
    require_string_list(blocker.get("nextExperiments"), "blocker.nextExperiments")
    require_string_list(blocker.get("bypassHypotheses"), "blocker.bypassHypotheses")
    require_string_list(blocker.get("alternativeRoutes"), "blocker.alternativeRoutes")
    if not isinstance(blocker.get("canSelfResolve"), bool):
        raise SystemExit("blocker.canSelfResolve must be true or false")
    validate_analysis_provenance(blocker)
    return blocker


def validate_unblock_result(
    root: Path,
    connection: sqlite3.Connection,
    result: dict[str, Any],
    blocked_task_id: str,
) -> dict[str, Any]:
    unblock = result.get("unblock")
    if not isinstance(unblock, dict):
        raise SystemExit("unblock task requires an unblock object")
    if unblock.get("blockedTaskId") != blocked_task_id:
        raise SystemExit("unblock.blockedTaskId does not match the scheduled parent task")
    if unblock.get("blockerAddressed") is not True:
        raise SystemExit("unblock.blockerAddressed must be true before completing the task")
    require_string_list(unblock.get("evidence"), "unblock.evidence")
    require_string(unblock.get("resumeStrategy"), "unblock.resumeStrategy")
    new_mechanism = unblock.get("newMechanism")
    if not isinstance(new_mechanism, dict):
        raise SystemExit("unblock.newMechanism must describe a genuinely new mechanism")
    fingerprint = require_string(
        new_mechanism.get("fingerprint"), "unblock.newMechanism.fingerprint"
    )
    differs_from = require_string(
        new_mechanism.get("differsFrom"), "unblock.newMechanism.differsFrom"
    )
    require_string(new_mechanism.get("mechanism"), "unblock.newMechanism.mechanism")
    require_string(
        new_mechanism.get("difference"), "unblock.newMechanism.difference"
    )
    require_string_list(
        new_mechanism.get("evidence"), "unblock.newMechanism.evidence"
    )
    submission = latest_task_submission(connection, blocked_task_id)
    if submission is None:
        raise SystemExit("blocked task has no retained blocker result")
    previous_result = read_json(root / str(submission["result_path"]))
    previous_blocker = previous_result.get("blocker")
    if isinstance(previous_blocker, dict):
        previous_fingerprint = require_string(
            previous_blocker.get("mechanismFingerprint"),
            "previous blocker.mechanismFingerprint",
        )
    else:
        failure = previous_result.get("failure")
        if not isinstance(failure, dict):
            raise SystemExit("blocked task result has no retained mechanism")
        previous_fingerprint = "failure:" + require_string(
            failure.get("category"), "previous failure.category"
        )
    if differs_from != previous_fingerprint or fingerprint == previous_fingerprint:
        raise SystemExit(
            "blocked approach may reopen only with a different mechanism fingerprint"
        )
    return unblock


PROHIBITED_PROVENANCE_FLAGS = (
    "changelogUsed",
    "gitHistoryUsed",
    "advisoryMiningUsed",
    "patchedVersionDiffUsed",
    "internetPatchDiffUsed",
)

LEAD_KINDS = ("minimized-stack", "invariant-break", "verified-primitive")
LEAD_GRADE_ORDER = {
    "verified-primitive": 0,
    "runtime-invariant": 1,
    "minimized-stack": 2,
    "source-invariant": 3,
}


def validate_analysis_provenance(container: dict[str, Any]) -> dict[str, Any]:
    provenance = container.get("analysisProvenance")
    if not isinstance(provenance, dict):
        raise SystemExit("completed result requires an analysisProvenance object")
    if provenance.get("firstPrinciplesOnly") is not True:
        raise SystemExit("analysisProvenance.firstPrinciplesOnly must be true")
    for field in PROHIBITED_PROVENANCE_FLAGS:
        if provenance.get(field) is not False:
            raise SystemExit(f"analysisProvenance.{field} must be false")
    return provenance


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_lead_evidence_paths(root: Path, lead: dict[str, Any]) -> list[str]:
    evidence = require_string_list(lead.get("evidence"), "researchLead.evidence")
    retained: list[str] = []
    for value in evidence:
        try:
            path = safe_campaign_path(root, value)
        except ValueError as error:
            raise SystemExit(f"researchLead.evidence:{error}") from error
        if not path.is_file():
            raise SystemExit(f"researchLead.evidence does not exist: {value}")
        retained.append(path.relative_to(root).as_posix())
    return retained


def validate_lead_source_artifacts(root: Path, lead: dict[str, Any]) -> list[dict[str, Any]]:
    campaign = read_json(root / "campaign.json")
    checkout_value = str(campaign.get("localCheckout") or "").strip()
    if not checkout_value:
        raise SystemExit("invariant-break lead requires campaign.localCheckout")
    checkout = Path(checkout_value).expanduser().resolve()
    raw = lead.get("sourceArtifacts")
    if not isinstance(raw, list) or not raw:
        raise SystemExit("invariant-break lead requires sourceArtifacts")
    normalized = []
    for index, artifact in enumerate(raw):
        if not isinstance(artifact, dict):
            raise SystemExit(f"researchLead.sourceArtifacts[{index}] must be an object")
        target_path = require_string(
            artifact.get("targetPath"), f"sourceArtifacts[{index}].targetPath"
        )
        candidate = Path(target_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise SystemExit("sourceArtifacts.targetPath must be checkout-relative")
        source = (checkout / candidate).resolve()
        try:
            source.relative_to(checkout)
        except ValueError as error:
            raise SystemExit("sourceArtifacts.targetPath escapes the checkout") from error
        if not source.is_file():
            raise SystemExit(f"source artifact does not exist: {target_path}")
        observed_sha = sha256(source)
        if artifact.get("sha256") != observed_sha:
            raise SystemExit(f"source artifact hash mismatch: {target_path}")
        line_start = artifact.get("lineStart")
        line_end = artifact.get("lineEnd")
        line_count = len(source.read_text(encoding="utf-8", errors="replace").splitlines())
        if (
            not isinstance(line_start, int)
            or not isinstance(line_end, int)
            or line_start < 1
            or line_end < line_start
            or line_end > line_count
        ):
            raise SystemExit(f"invalid source line range: {target_path}")
        normalized.append(
            {
                "targetPath": candidate.as_posix(),
                "sha256": observed_sha,
                "lineStart": line_start,
                "lineEnd": line_end,
            }
        )
    return normalized


def validate_research_lead(root: Path, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SystemExit("taskResult.researchLeads entries must be objects")
    kind = require_string(raw.get("kind"), "researchLead.kind")
    if kind not in LEAD_KINDS:
        raise SystemExit("researchLead.kind must identify a retained stack, invariant, or primitive")
    title = require_string(raw.get("title"), "researchLead.title")
    next_experiment = require_string(
        raw.get("nextExperiment"), "researchLead.nextExperiment"
    )
    source_references = require_string_list(
        raw.get("sourceReferences"), "researchLead.sourceReferences"
    )
    approach_families = require_string_list(
        raw.get("approachFamilies"), "researchLead.approachFamilies"
    )
    evidence = validate_lead_evidence_paths(root, raw)
    status = str(raw.get("status") or "active")
    if status not in {"active", "disproved"}:
        raise SystemExit("researchLead.status must be active or disproved")

    normalized = {
        "kind": kind,
        "title": title,
        "status": status,
        "nextExperiment": next_experiment,
        "sourceReferences": source_references,
        "approachFamilies": approach_families,
        "evidence": evidence,
    }
    if kind == "minimized-stack":
        stack = raw.get("minimizedStack")
        if not isinstance(stack, dict):
            raise SystemExit("minimized-stack lead requires minimizedStack")
        crash_id = require_string(stack.get("crashId"), "minimizedStack.crashId")
        cluster_id = require_string(stack.get("clusterId"), "minimizedStack.clusterId")
        if not re.fullmatch(r"[0-9a-f]{64}", crash_id):
            raise SystemExit("minimizedStack.crashId must be a full crash fingerprint")
        crash_dir = root / "dynamic" / "crashes" / crash_id
        triage_path = crash_dir / "triage.json"
        minimized_path = crash_dir / "minimized.bin"
        if not triage_path.is_file() or not minimized_path.is_file():
            raise SystemExit("minimized-stack lead requires retained triage and minimized.bin")
        triage = read_json(triage_path)
        observed_cluster = str((triage.get("stack") or {}).get("clusterId") or "")
        if observed_cluster != cluster_id:
            raise SystemExit("minimizedStack.clusterId does not match retained triage")
        minimized_sha = sha256(minimized_path)
        supplied_sha = str(stack.get("minimizedSha256") or "")
        if supplied_sha and supplied_sha != minimized_sha:
            raise SystemExit("minimizedStack.minimizedSha256 does not match retained input")
        normalized["minimizedStack"] = {
            "crashId": crash_id,
            "clusterId": cluster_id,
            "minimizedSha256": minimized_sha,
            "faultClass": str((triage.get("firstFault") or {}).get("class") or ""),
        }
        normalized["semanticIdentity"] = f"stack:{cluster_id}"
        normalized["evidenceGrade"] = "minimized-stack"
    elif kind == "invariant-break":
        invariant = raw.get("invariantBreak")
        if not isinstance(invariant, dict):
            raise SystemExit("invariant-break lead requires invariantBreak")
        boundary = require_string(invariant.get("boundary"), "invariantBreak.boundary")
        invariant_text = require_string(
            invariant.get("invariant"), "invariantBreak.invariant"
        )
        expected = require_string(invariant.get("expected"), "invariantBreak.expected")
        observed = require_string(invariant.get("observed"), "invariantBreak.observed")
        restored = require_string(
            invariant.get("restoredControl"), "invariantBreak.restoredControl"
        )
        runtime_reproduced = invariant.get("runtimeReproduced") is True
        source_artifacts = validate_lead_source_artifacts(root, raw)
        attestation_summary: dict[str, Any] | None = None
        if runtime_reproduced:
            reference = invariant.get("attestation")
            if not isinstance(reference, dict):
                raise SystemExit("runtime invariant lead requires a machine attestation")
            try:
                attestation_path = safe_campaign_path(root, reference.get("path"))
            except ValueError as error:
                raise SystemExit(f"invariantBreak.attestation:{error}") from error
            result = validate_attestation(root, attestation_path)
            if not result["passed"]:
                raise SystemExit(
                    "runtime invariant attestation failed: " + ", ".join(result["errors"])
                )
            if reference.get("sha256") != result["attestationSha256"]:
                raise SystemExit("runtime invariant attestation hash mismatch")
            attestation_summary = {
                "path": attestation_path.relative_to(root).as_posix(),
                "sha256": result["attestationSha256"],
                "runId": result["record"]["runId"],
            }
        identity_material = {
            "boundary": boundary,
            "invariant": invariant_text,
            "sourceArtifacts": source_artifacts,
        }
        normalized["sourceArtifacts"] = source_artifacts
        normalized["invariantBreak"] = {
            "boundary": boundary,
            "invariant": invariant_text,
            "expected": expected,
            "observed": observed,
            "restoredControl": restored,
            "runtimeReproduced": runtime_reproduced,
            "attestation": attestation_summary,
        }
        normalized["semanticIdentity"] = "invariant:" + canonical_digest(identity_material)
        normalized["evidenceGrade"] = (
            "runtime-invariant" if runtime_reproduced else "source-invariant"
        )
    else:
        primitive = raw.get("verifiedPrimitive")
        if not isinstance(primitive, dict):
            raise SystemExit("verified-primitive lead requires verifiedPrimitive")
        crash_id = require_string(primitive.get("crashId"), "verifiedPrimitive.crashId")
        claim = require_string(primitive.get("claim"), "verifiedPrimitive.claim")
        try:
            verification_path = safe_campaign_path(root, primitive.get("verificationPath"))
        except ValueError as error:
            raise SystemExit(f"verifiedPrimitive.verificationPath:{error}") from error
        if not verification_path.is_file():
            raise SystemExit("verifiedPrimitive.verificationPath does not exist")
        verification = read_json(verification_path)
        if (
            verification.get("producer") != "krineon-primitive-verifier"
            or verification.get("status") != "verified"
            or verification.get("crashId") != crash_id
            or verification.get("claim") != claim
        ):
            raise SystemExit("verifiedPrimitive does not match its retained verifier record")
        normalized["verifiedPrimitive"] = {
            "crashId": crash_id,
            "claim": claim,
            "verificationPath": verification_path.relative_to(root).as_posix(),
            "verificationSha256": sha256(verification_path),
        }
        normalized["semanticIdentity"] = f"primitive:{crash_id}:{claim}"
        normalized["evidenceGrade"] = "verified-primitive"
    return normalized


def validate_research_leads(root: Path, task_result: dict[str, Any]) -> list[dict[str, Any]]:
    raw = task_result.get("researchLeads", [])
    if not isinstance(raw, list):
        raise SystemExit("taskResult.researchLeads must be a list")
    return [validate_research_lead(root, item) for item in raw]


def validate_completed_result(
    root: Path, result: dict[str, Any], task_id: str
) -> list[dict[str, Any]]:
    task_result = result.get("taskResult")
    if not isinstance(task_result, dict):
        raise SystemExit("completed result requires a taskResult object")
    if task_result.get("taskId") != task_id:
        raise SystemExit("taskResult.taskId must match the leased task")
    require_string(task_result.get("summary"), "taskResult.summary")
    require_string(task_result.get("conclusion"), "taskResult.conclusion")
    require_string_list(task_result.get("searchedSurface"), "taskResult.searchedSurface")
    require_string_list(task_result.get("sourceReferences"), "taskResult.sourceReferences")
    require_string_list(task_result.get("evidence"), "taskResult.evidence")
    dependencies = task_result.get("dependenciesAnalyzed", [])
    if not isinstance(dependencies, list):
        raise SystemExit("taskResult.dependenciesAnalyzed must be a list")
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise SystemExit(f"taskResult.dependenciesAnalyzed[{index}] must be an object")
        require_string(
            dependency.get("name"), f"taskResult.dependenciesAnalyzed[{index}].name"
        )
        resolved = require_string(
            dependency.get("resolvedCommit"),
            f"taskResult.dependenciesAnalyzed[{index}].resolvedCommit",
        )
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", resolved):
            raise SystemExit(
                f"taskResult.dependenciesAnalyzed[{index}].resolvedCommit must be a full object ID"
            )
        require_string(
            dependency.get("targetLockEvidence"),
            f"taskResult.dependenciesAnalyzed[{index}].targetLockEvidence",
        )
        require_string(
            dependency.get("boundary"),
            f"taskResult.dependenciesAnalyzed[{index}].boundary",
        )
    for field in ("hypotheses", "nextTasks"):
        if not isinstance(task_result.get(field), list):
            raise SystemExit(f"taskResult.{field} must be a list")
    validate_analysis_provenance(task_result)
    return validate_research_leads(root, task_result)


def coordinator_reexecute_result(
    root: Path,
    result: dict[str, Any],
    task_id: str,
    validated_leads: list[dict[str, Any]],
) -> dict[str, Any] | None:
    runtime_grades = {"runtime-invariant", "minimized-stack", "verified-primitive"}
    runtime_claim = any(
        str(lead.get("evidenceGrade") or "") in runtime_grades
        for lead in validated_leads
    )
    task_result = result.get("taskResult")
    replay = task_result.get("coordinatorReplay") if isinstance(task_result, dict) else None
    if not runtime_claim and replay is None:
        return None
    if not isinstance(replay, dict):
        raise SystemExit(
            "runtime evidence cannot enter the queue without taskResult.coordinatorReplay"
        )
    try:
        recipe_path = safe_campaign_path(root, replay.get("recipe"))
    except ValueError as error:
        raise SystemExit(f"coordinatorReplay.recipe:{error}") from error
    if not recipe_path.is_file():
        raise SystemExit("coordinator replay recipe does not exist")
    recipe = read_json(recipe_path)
    if recipe.get("findingId") != task_id:
        raise SystemExit("coordinator replay recipe findingId must equal the task ID")
    cases = recipe.get("cases")
    if not isinstance(cases, list):
        raise SystemExit("coordinator replay recipe requires cases")
    by_name = {
        str(case.get("name")): case for case in cases if isinstance(case, dict)
    }
    if set(by_name) != {"baseline", "negative", "positive"}:
        raise SystemExit("coordinator replay requires baseline, negative, and positive")
    control_kinds = {"stdout-not-contains-challenge", "no-memory-write"}
    positive_kinds = {
        "stdout-contains-challenge",
        "controlled-write",
        "controlled-pc",
    }
    for name in ("baseline", "negative"):
        assertions = by_name[name].get("assertions")
        kinds = {
            str(value.get("kind") or "")
            for value in assertions or []
            if isinstance(value, dict)
        }
        if not kinds.intersection(control_kinds):
            raise SystemExit(
                f"coordinator replay {name} lacks a machine-checkable absence control"
            )
    positive_assertions = by_name["positive"].get("assertions")
    positive_observations = {
        str(value.get("kind") or "")
        for value in positive_assertions or []
        if isinstance(value, dict)
    }
    if not positive_observations.intersection(positive_kinds):
        raise SystemExit("coordinator replay positive case lacks a concrete observation")

    campaign = read_json(root / "campaign.json")
    frozen = campaign.get("frozenTargetArtifacts")
    frozen_by_path = {
        str(value.get("path")): str(value.get("sha256"))
        for value in frozen or []
        if isinstance(value, dict)
    }
    targets = recipe.get("targetArtifacts")
    if not isinstance(targets, list) or not targets:
        raise SystemExit("coordinator replay recipe requires frozen target artifacts")
    for target_value in targets:
        target_path = safe_campaign_path(root, target_value)
        relative = target_path.relative_to(root).as_posix()
        if frozen_by_path.get(relative) != sha256(target_path):
            raise SystemExit(
                f"coordinator replay target is not coordinator-frozen: {relative}"
            )

    repetitions = int(replay.get("repetitions") or 1)
    if repetitions < 1 or repetitions > 10:
        raise SystemExit("coordinatorReplay.repetitions must be between 1 and 10")
    command = [
        sys.executable,
        str(REALITY_RUNNER),
        str(root),
        task_id,
        "--recipe",
        recipe_path.relative_to(root).as_posix(),
        "--worker-id",
        "coordinator",
        "--role",
        "coordinator",
        "--repetitions",
        str(repetitions),
    ]
    completed = subprocess.run(
        command, check=False, capture_output=True, text=True, timeout=120
    )
    if completed.returncode != 0:
        raise SystemExit(
            "coordinator re-execution rejected the worker claim: "
            + completed.stderr[-4000:]
        )
    try:
        output = json.loads(completed.stdout)
        attestation_path = safe_campaign_path(root, output.get("attestation"))
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"coordinator replay emitted invalid evidence: {error}") from error
    validation = validate_attestation(
        root,
        attestation_path,
        expected_finding_id=task_id,
        expected_worker_id="coordinator",
        expected_role="coordinator",
    )
    if not validation["passed"]:
        raise SystemExit(
            "coordinator replay attestation failed: " + ", ".join(validation["errors"])
        )
    return {
        "recipe": recipe_path.relative_to(root).as_posix(),
        "recipeSha256": sha256(recipe_path),
        "attestation": attestation_path.relative_to(root).as_posix(),
        "attestationSha256": validation["attestationSha256"],
        "runId": validation["record"]["runId"],
        "repetitions": repetitions,
    }


def validate_route_development_result(
    result: dict[str, Any], route_id: str, research_round: int
) -> None:
    development = result.get("routeDevelopment")
    if not isinstance(development, dict):
        raise SystemExit("route-development task requires routeDevelopment")
    if development.get("routeId") != route_id:
        raise SystemExit("routeDevelopment.routeId must match the leased route")
    if int(development.get("round", -1)) != research_round:
        raise SystemExit("routeDevelopment.round must match the leased research round")
    require_string_list(development.get("strengths"), "routeDevelopment.strengths")
    require_string_list(development.get("gaps"), "routeDevelopment.gaps")
    require_string_list(development.get("evidence"), "routeDevelopment.evidence")
    require_string(development.get("nextExperiment"), "routeDevelopment.nextExperiment")
    fresh_ideas = require_string_list(
        development.get("freshIdeas"), "routeDevelopment.freshIdeas"
    )
    intermediate_bugs = development.get("intermediateBugs")
    if not isinstance(intermediate_bugs, list):
        raise SystemExit("routeDevelopment.intermediateBugs must be a list")
    for index, bug in enumerate(intermediate_bugs):
        if not isinstance(bug, dict):
            raise SystemExit(f"routeDevelopment.intermediateBugs[{index}] must be an object")
        require_string(bug.get("id"), f"routeDevelopment.intermediateBugs[{index}].id")
        require_string(
            bug.get("rootCause"),
            f"routeDevelopment.intermediateBugs[{index}].rootCause",
        )
        require_string(bug.get("primitive"), f"routeDevelopment.intermediateBugs[{index}].primitive")
        require_string_list(
            bug.get("evidence"), f"routeDevelopment.intermediateBugs[{index}].evidence"
        )
    chain_hypotheses = development.get("chainHypotheses")
    if not isinstance(chain_hypotheses, list):
        raise SystemExit("routeDevelopment.chainHypotheses must be a list")
    if intermediate_bugs and not [item for item in chain_hypotheses if str(item).strip()]:
        raise SystemExit("intermediate bugs require non-empty chainHypotheses")
    if not fresh_ideas:
        raise SystemExit("a route may not end merely because the current approach found nothing")


def validate_adversarial_route_result(
    result: dict[str, Any], reviewed_task_id: str, route_id: str, research_round: int
) -> None:
    review = result.get("adversarialReview")
    if not isinstance(review, dict):
        raise SystemExit("adversarial route task requires adversarialReview")
    if review.get("reviewedTaskId") != reviewed_task_id:
        raise SystemExit("adversarialReview.reviewedTaskId does not match the route task")
    if review.get("routeId") != route_id or int(review.get("round", -1)) != research_round:
        raise SystemExit("adversarialReview route or round does not match the leased task")
    if not isinstance(review.get("sanityPassed"), bool):
        raise SystemExit("adversarialReview.sanityPassed must be true or false")
    require_string(
        review.get("strongestCounterargument"),
        "adversarialReview.strongestCounterargument",
    )
    require_string_list(review.get("evidence"), "adversarialReview.evidence")
    if not isinstance(review.get("unresolvedGaps"), list):
        raise SystemExit("adversarialReview.unresolvedGaps must be a list")


def validate_round_synthesis_result(
    result: dict[str, Any],
    research_round: int,
    connection: sqlite3.Connection | None = None,
) -> None:
    synthesis = result.get("roundSynthesis")
    if not isinstance(synthesis, dict):
        raise SystemExit("root-round-synthesis task requires roundSynthesis")
    if int(synthesis.get("round", -1)) != research_round:
        raise SystemExit("roundSynthesis.round must match the leased research round")
    routes = synthesis.get("routes")
    if not isinstance(routes, list) or len(routes) < 3:
        raise SystemExit("roundSynthesis.routes must contain at least three routes")
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            raise SystemExit(f"roundSynthesis.routes[{index}] must be an object")
        require_string(route.get("routeId"), f"roundSynthesis.routes[{index}].routeId")
        require_string_list(route.get("strengths"), f"roundSynthesis.routes[{index}].strengths")
        require_string_list(route.get("gaps"), f"roundSynthesis.routes[{index}].gaps")
        require_string(route.get("decision"), f"roundSynthesis.routes[{index}].decision")
        require_string(
            route.get("nextExperiment"),
            f"roundSynthesis.routes[{index}].nextExperiment",
        )
    require_string_list(synthesis.get("challenges"), "roundSynthesis.challenges")
    if not isinstance(synthesis.get("redirects"), list):
        raise SystemExit("roundSynthesis.redirects must be a list")
    fresh_ideas = require_string_list(synthesis.get("freshIdeas"), "roundSynthesis.freshIdeas")
    if len(fresh_ideas) < 3:
        raise SystemExit("roundSynthesis.freshIdeas must contain at least three new directions")
    intermediate_chains = synthesis.get("intermediateChains")
    if not isinstance(intermediate_chains, list):
        raise SystemExit("roundSynthesis.intermediateChains must be a list")
    for index, chain in enumerate(intermediate_chains):
        if not isinstance(chain, dict):
            raise SystemExit(f"roundSynthesis.intermediateChains[{index}] must be an object")
        require_string_list(
            chain.get("sourceIntermediateBugs"),
            f"roundSynthesis.intermediateChains[{index}].sourceIntermediateBugs",
        )
        require_string(chain.get("outcome"), f"roundSynthesis.intermediateChains[{index}].outcome")
        require_string(
            chain.get("nextExperiment"),
            f"roundSynthesis.intermediateChains[{index}].nextExperiment",
        )
    if connection is not None:
        completed_chain_count = int(
            connection.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE research_round=? "
                "AND task_kind='intermediate-chain-composition' AND state='completed'",
                (research_round,),
            ).fetchone()["count"]
        )
        if completed_chain_count and not intermediate_chains:
            raise SystemExit(
                "roundSynthesis must incorporate completed intermediate-bug chain tasks"
            )
    if not isinstance(synthesis.get("launchNextRound"), bool):
        raise SystemExit("roundSynthesis.launchNextRound must be true or false")
    if synthesis["launchNextRound"] is True:
        require_string_list(
            synthesis.get("nextRoundDirections"), "roundSynthesis.nextRoundDirections"
        )
    else:
        hard_stop = synthesis.get("hardStop")
        if not isinstance(hard_stop, dict):
            raise SystemExit(
                "no findings or failed approaches cannot stop the campaign; record a hardStop"
            )
        category = require_string(hard_stop.get("category"), "roundSynthesis.hardStop.category")
        if category not in {
            "explicit-user-stop",
            "authorization-required",
            "campaign-budget-exhausted",
            "unsafe-or-out-of-scope",
        }:
            raise SystemExit("roundSynthesis hardStop category is not an allowed terminal condition")
        require_string(hard_stop.get("reason"), "roundSynthesis.hardStop.reason")
        require_string_list(hard_stop.get("evidence"), "roundSynthesis.hardStop.evidence")


def validate_intermediate_chain_result(result: dict[str, Any]) -> None:
    chain = result.get("chainComposition")
    if not isinstance(chain, dict):
        raise SystemExit("intermediate chain task requires chainComposition")
    require_string_list(
        chain.get("sourceIntermediateBugs"), "chainComposition.sourceIntermediateBugs"
    )
    require_string_list(chain.get("attemptedChains"), "chainComposition.attemptedChains")
    require_string(chain.get("outcome"), "chainComposition.outcome")
    require_string_list(chain.get("freshIdeas"), "chainComposition.freshIdeas")
    require_string_list(chain.get("evidence"), "chainComposition.evidence")


def validate_next_round_planning_result(
    connection: sqlite3.Connection, result: dict[str, Any], from_round: int
) -> None:
    planning = result.get("nextRoundPlanning")
    if not isinstance(planning, dict):
        raise SystemExit("next-round planning task requires nextRoundPlanning")
    if int(planning.get("fromRound", -1)) != from_round:
        raise SystemExit("nextRoundPlanning.fromRound does not match the synthesis round")
    target_round = from_round + 1
    if int(planning.get("launchedRound", -1)) != target_round:
        raise SystemExit("nextRoundPlanning.launchedRound must be the immediate next round")
    require_string(planning.get("planPath"), "nextRoundPlanning.planPath")
    require_string_list(planning.get("launchedTaskIds"), "nextRoundPlanning.launchedTaskIds")
    if int(get_metadata(connection, "lastResearchRound", 0)) < target_round:
        raise SystemExit("launch the next round with round-plan before completing this task")
    synthesis_id = f"round-{target_round}-root-synthesis"
    if connection.execute(
        "SELECT 1 FROM tasks WHERE task_id=? AND research_round=?",
        (synthesis_id, target_round),
    ).fetchone() is None:
        raise SystemExit("nextRoundPlanning does not correspond to a launched round")


def validate_failed_result(result: dict[str, Any]) -> dict[str, Any]:
    failure = result.get("failure")
    if not isinstance(failure, dict):
        raise SystemExit("failed outcome requires a failure object")
    require_string(failure.get("category"), "failure.category")
    require_string(failure.get("reason"), "failure.reason")
    require_string_list(failure.get("evidence"), "failure.evidence")
    validate_analysis_provenance(failure)
    return failure


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


def revive_dependency_blocks(connection: sqlite3.Connection) -> int:
    revived = 0
    for row in connection.execute(
        "SELECT * FROM tasks WHERE state='blocked' AND last_error='dependency ended unsuccessfully'"
    ).fetchall():
        if dependency_state(connection, row) != "blocked":
            connection.execute(
                "UPDATE tasks SET state='queued',last_error=NULL,updated_at=? WHERE task_id=?",
                (utc_now(), row["task_id"]),
            )
            record_event(connection, "dependency-block-revived", task_id=row["task_id"])
            revived += 1
    return revived


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
    for source_name, target_name in (
        ("campaign.json", "KRINEON_CAMPAIGN.json"),
        ("AUTHORIZATION.md", "AUTHORIZATION.md"),
        ("PROGRAM_GUIDELINES.md", "PROGRAM_GUIDELINES.md"),
        ("PROGRAM_SCOPE.md", "PROGRAM_SCOPE.md"),
        ("approach-registry.json", "KRINEON_APPROACH_REGISTRY.json"),
    ):
        source = root / source_name
        if source.is_file():
            shutil.copy2(source, workspace / target_name)
    result_template = ASSETS / "task-result.template.json"
    if result_template.is_file():
        shutil.copy2(result_template, workspace / "KRINEON_TASK_RESULT.template.json")
    reference_root = workspace / "KRINEON_REFERENCES"
    reference_root.mkdir(exist_ok=True)
    reference_names = [
        "critical-rce.md",
        "approach-families.md",
        "dependencies.md",
        "rediscovery-benchmark.md",
    ]
    if campaign.get("profile") == "chrome-v8":
        reference_names.extend(("chrome-v8.md", "chrome-v8-agent.md"))
    for reference_name in reference_names:
        source = (
            PROJECT_ROOT / "agents" / reference_name
            if reference_name.endswith("-agent.md")
            else PROJECT_ROOT / "references" / reference_name
        )
        if source.is_file():
            shutil.copy2(source, reference_root / reference_name)
    if campaign.get("profile") == "chrome-v8":
        chrome_result_template = ASSETS / "chrome-v8-result.template.json"
        if chrome_result_template.is_file():
            shutil.copy2(
                chrome_result_template,
                reference_root / "chrome-v8-result.template.json",
            )
    dependency_mounts: list[dict[str, str]] = []
    manifest_path = root / "third_party" / "manifest.json"
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        shutil.copy2(manifest_path, workspace / "KRINEON_DEPENDENCIES.json")
        dependencies = manifest.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise RuntimeError("invalid third_party dependency manifest")
        dependency_root = workspace / "KRINEON_THIRD_PARTY"
        dependency_root.mkdir(exist_ok=True)
        campaign_dependency_root = (root / "third_party").resolve()
        for item in dependencies:
            if not isinstance(item, dict):
                raise RuntimeError("invalid dependency manifest entry")
            try:
                name = validate_dependency_name(str(item.get("name") or ""))
            except argparse.ArgumentTypeError as exc:
                raise RuntimeError(str(exc)) from exc
            source = (root / str(item.get("path") or "")).resolve()
            try:
                source.relative_to(campaign_dependency_root)
            except ValueError as exc:
                raise RuntimeError(f"dependency path escapes third_party: {source}") from exc
            revision = str(item.get("resolvedCommit") or "")
            destination = dependency_root / name
            completed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "worktree",
                    "add",
                    "--detach",
                    str(destination),
                    revision,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode:
                raise RuntimeError(
                    f"dependency worktree failed for {name}: {completed.stderr.strip()}"
                )
            dependency_mounts.append(
                {
                    "name": name,
                    "path": destination.relative_to(workspace).as_posix(),
                    "resolvedCommit": revision,
                }
            )
    write_json(
        workspace / "KRINEON_ASSIGNMENT.json",
        {
            "schemaVersion": 1,
            "campaign": str(root),
            "workerId": worker_id,
            "taskId": task_id,
            "attempt": attempt,
            "workspaceMode": mode,
            "dependencyWorktrees": dependency_mounts,
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
    campaign_path = root / "campaign.json"
    campaign = read_json(campaign_path)
    third_party = root / "third_party"
    third_party.mkdir(exist_ok=True)
    manifest_path = third_party / "manifest.json"
    if not manifest_path.is_file():
        write_json(
            manifest_path,
            {
                "schemaVersion": 1,
                "createdAt": utc_now(),
                "updatedAt": utc_now(),
                "dependencies": [],
            },
        )
    if campaign.get("dependencyManifest") != "third_party/manifest.json":
        campaign["dependencyManifest"] = "third_party/manifest.json"
        write_json(campaign_path, campaign)
    return campaign


def registry_path(root: Path) -> Path:
    return root / "registry.json"


def load_registry(root: Path) -> dict[str, Any]:
    return read_json(registry_path(root))


def save_registry(root: Path, registry: dict[str, Any]) -> None:
    registry["updatedAt"] = utc_now()
    write_json(registry_path(root), registry)


def rediscovery_measurement(root: Path) -> dict[str, Any]:
    measured: list[dict[str, Any]] = []
    benchmark_root = root / "benchmarks"
    if benchmark_root.is_dir():
        for status_path in sorted(benchmark_root.glob("*/status.json")):
            try:
                status = read_json(status_path)
            except (OSError, json.JSONDecodeError):
                continue
            hours = status.get("hoursToFirstRediscovery")
            if status.get("status") == "measured" and isinstance(hours, (int, float)):
                measured.append(
                    {
                        "name": status.get("name") or status_path.parent.name,
                        "hoursToFirstRediscovery": float(hours),
                        "recall": status.get("recall"),
                        "status": str(status_path.relative_to(root)),
                    }
                )
    if not measured:
        return {
            "status": "unmeasured",
            "profileLaneClaims": "documentation-only",
            "hoursToFirstRediscovery": None,
            "benchmarks": [],
        }
    best = min(measured, key=lambda item: item["hoursToFirstRediscovery"])
    return {
        "status": "measured",
        "profileLaneClaims": "empirically-measured-on-frozen-local-corpus",
        "hoursToFirstRediscovery": best["hoursToFirstRediscovery"],
        "recall": best["recall"],
        "benchmarks": measured,
    }


def task_markdown(lane: dict[str, Any], campaign: dict[str, Any]) -> str:
    deliverables = "\n".join(f"- {item}" for item in lane["deliverables"])
    definitions = approach_family_definitions()
    approach_lines = []
    for family_id in lane["approachFamilies"]:
        family = definitions[family_id]
        approach_lines.append(
            f"- `{family_id}`: boundary={family['boundary']}; "
            f"mechanism={family['mechanism']}; invariant={family['invariant']}"
        )
    approaches = "\n".join(approach_lines)
    return f"""# Task: {lane['title']}

## Campaign

- Target: {campaign['target']}
- Repository: {campaign['repository']}
- Exact revision: {campaign['commit']}
- Mode: {campaign['mode']}
- Profile: {campaign.get('profile', 'critical-rce')}
- Wave: {lane['wave']}

## Search-efficacy status

- Status: `{campaign.get('_rediscoveryMeasurement', {}).get('status', 'unmeasured')}`
- Profile-lane claim: `{campaign.get('_rediscoveryMeasurement', {}).get('profileLaneClaims', 'documentation-only')}`
- Hours to first rediscovery: `{campaign.get('_rediscoveryMeasurement', {}).get('hoursToFirstRediscovery')}`

An unmeasured lane is an experiment, not evidence that the methodology works.
Measure it with `scripts/rediscovery_benchmark.py` against target-owned tests or
invariants on a frozen local corpus before making efficacy claims.

Read `AUTHORIZATION.md` and `KRINEON_CAMPAIGN.json` before taking any dynamic action.
Stay within the recorded environment and stop conditions.
Read `KRINEON_REFERENCES/critical-rce.md` before discovery or chain construction.
Read `KRINEON_REFERENCES/dependencies.md` and `KRINEON_DEPENDENCIES.json` before
assuming a library boundary ends the chain. Pinned dependency worktrees, when
present, are under `KRINEON_THIRD_PARTY/`.
{"Read `KRINEON_REFERENCES/chrome-v8.md` and `KRINEON_REFERENCES/chrome-v8-agent.md` before starting." if campaign.get('profile') == 'chrome-v8' else ""}

## Critical/RCE mission and internal search objective

Search for and retain unique minimized stacks, target-invariant breaks, and
verified primitives from first-principles analysis of the pinned source and
its exact-revision runtime behavior. Advance each retained lead with the
smallest useful next experiment. A complete Critical/RCE chain is required for
filing, not for completing this research task. Do not invent missing links.
Do not use changelogs,
advisories, git history or blame, historical commits, patched-version
comparisons, or an internet-based patch diff to locate vulnerabilities. Work
from public ingress toward a privileged sink, and from execution/native sinks
back toward attacker-controlled input. A crash, assertion, denial of service,
isolated primitive, or lower-severity issue is a research lead, not a fileable
finding. Read checked-in tests, assertions, fuzz targets, fixtures, and
invariant comments from the pinned target as local oracles.
Development servers, development builds, hot-reload paths, test or fixture
servers, preview-only runtimes, and debug-only paths are also lead-generation
environments, not findings. The primary terminal must survive a supported
production-equivalent or release entrypoint before promotion.

## Primary objective

{lane['objective']}

## Registered approach families

{approaches}

These identities are semantic. Classify work by the security boundary,
mechanism, and invariant above, not by similar task titles or prose. Record the
families actually exercised in the task result. If this family is already
converged, expect the scheduler to redirect free agents toward less-explored
families.

## Required deliverables

{deliverables}

## Evidence contract

- Pin source references to the tested revision.
- Separate runtime proof, source confirmation, and inference.
- Register blocked and disproved paths as well as candidates.
- State the falsification condition for each hypothesis.
- Do not use a static-tool result as exploit evidence.
- Do not access third-party data, degrade services, or broaden authorization.
- Submit completed work using `KRINEON_TASK_RESULT.template.json`; the scheduler
  rejects missing evidence, searched surfaces, pinned source references, or
  prohibited discovery provenance.

## Exploration and blocker contract

This lane is a starting search direction, not a fixed testcase list. Follow
adjacent call paths, state transitions, representations, platforms, sibling
implementations, and cross-lane compositions while they remain inside the
recorded authorization. Add focused tasks with `task-add` when new evidence
opens a material branch.

Do not end with only "blocked." Record the exact missing chain link, guard or
failure mechanism, why it blocks the current assumptions, evidence, attempts,
bypass hypotheses, alternative routes, cheapest discriminator, authority
requirements, and next experiments. A self-resolvable technical blocker
automatically creates a high-priority fresh-agent breakout task. If an exact
route is falsified, preserve that result and pursue a different source-derived
route rather than forcing an exploit claim or ending the campaign.

## Handoff

Use `assets/agent-handoff.template.md` as the structure. Return exact commands,
artifact paths, controls, blockers, and cleanup state.
"""


def validate_dependency_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise argparse.ArgumentTypeError(
            "dependency name must use letters, digits, dot, underscore, or hyphen"
        )
    return value


def dependency_manifest(root: Path) -> dict[str, Any]:
    manifest = read_json(root / "third_party" / "manifest.json")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list):
        raise SystemExit("invalid third_party dependency manifest")
    return manifest


def run_git_checked(arguments: list[str], description: str) -> str:
    completed = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if completed.returncode:
        raise SystemExit(f"{description} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def cmd_dependency_add(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    manifest = dependency_manifest(root)
    if any(item.get("name") == args.name for item in manifest["dependencies"]):
        raise SystemExit(f"dependency already registered: {args.name}")
    parsed = urlsplit(args.repo)
    if parsed.scheme in {"http", "https"} and (parsed.username or parsed.password):
        raise SystemExit("dependency repository URLs must not embed credentials")
    destination = root / "third_party" / args.name
    if destination.exists():
        raise SystemExit(f"dependency destination already exists: {destination}")
    try:
        run_git_checked(
            ["git", "clone", "--no-checkout", "--", args.repo, str(destination)],
            "dependency clone",
        )
        run_git_checked(
            ["git", "-C", str(destination), "checkout", "--detach", args.commit],
            "dependency revision checkout",
        )
        resolved = run_git_checked(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            "dependency revision resolution",
        )
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", resolved):
            raise SystemExit("dependency revision did not resolve to a full object ID")
        dirty = run_git_checked(
            ["git", "-C", str(destination), "status", "--porcelain"],
            "dependency worktree check",
        )
        if dirty:
            raise SystemExit("new dependency checkout is unexpectedly dirty")
    except BaseException:
        if destination.exists():
            shutil.rmtree(destination)
        raise
    now = utc_now()
    manifest["updatedAt"] = now
    manifest["dependencies"].append(
        {
            "name": args.name,
            "repository": args.repo,
            "requestedRevision": args.commit,
            "resolvedCommit": resolved,
            "path": f"third_party/{args.name}",
            "relationship": args.relationship,
            "scopeStatus": args.scope_status,
            "lockEvidence": list(args.lock_evidence),
            "reason": args.reason,
            "addedAt": now,
            "discoveryBoundary": "exact pinned dependency; no history or patched-version diff",
        }
    )
    write_json(root / "third_party" / "manifest.json", manifest)
    print(f"added dependency {args.name} at {resolved}")
    print(f"manifest: {root / 'third_party' / 'manifest.json'}")
    return 0


def cmd_dependency_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    manifest = dependency_manifest(root)
    if args.json:
        print(json.dumps(manifest, indent=2))
        return 0
    dependencies = manifest["dependencies"]
    if not dependencies:
        print("no pinned third-party dependencies")
        return 0
    print(f"{'NAME':<24} {'RELATIONSHIP':<14} {'SCOPE':<20} COMMIT")
    print("-" * 100)
    for item in dependencies:
        print(
            f"{str(item['name']):<24} {str(item['relationship']):<14} "
            f"{str(item['scopeStatus']):<20} {item['resolvedCommit']}"
        )
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"refusing to initialize non-empty directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in CAMPAIGN_DIRS:
        (root / name).mkdir(exist_ok=True)

    lanes = campaign_lanes(args.profile)
    data = template("campaign.template.json")
    data.update(
        {
            "profile": args.profile,
            "target": args.target,
            "repository": args.repo,
            "localCheckout": str(Path(args.checkout).expanduser().resolve()) if args.checkout else "",
            "commit": args.commit,
            "mode": args.mode,
            "programUrl": args.program_url or "",
            "createdAt": utc_now(),
            "lanes": [lane["id"] for lane in lanes],
            "dependencyManifest": "third_party/manifest.json",
        }
    )
    write_json(root / "campaign.json", data)
    write_json(
        root / "third_party" / "manifest.json",
        {
            "schemaVersion": 1,
            "createdAt": utc_now(),
            "updatedAt": utc_now(),
            "dependencies": [],
        },
    )
    if args.profile == "chrome-v8":
        chrome_root = root / "chrome-v8"
        chrome_root.mkdir(exist_ok=True)
        builds = template("chrome-v8-builds.template.json")
        builds["createdAt"] = utc_now()
        write_json(chrome_root / "builds.json", builds)
        write_json(
            chrome_root / "result.template.json",
            template("chrome-v8-result.template.json"),
        )
    write_json(
        registry_path(root),
        {"schemaVersion": 1, "createdAt": utc_now(), "updatedAt": utc_now(), "findings": []},
    )
    definitions = approach_family_definitions()
    selected_family_ids = sorted(
        {family_id for lane in lanes for family_id in lane["approachFamilies"]}
    )
    write_json(
        root / "approach-registry.json",
        {
            "schemaVersion": 1,
            "generatedAt": utc_now(),
            "policy": {
                "identityBasis": "registered boundary + mechanism + invariant, never task wording",
                "redirectBeforeDominance": True,
            },
            "underexploredFamilies": selected_family_ids,
            "convergedFamilies": [],
            "families": [definitions[family_id] for family_id in selected_family_ids],
        },
    )

    authorization = f"""# Authorization record

- Target: {args.target}
- Repository or asset: {args.repo}
- Exact revision: {args.commit}
- Campaign profile: {args.profile}
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
    profile_name = str(campaign.get("profile") or "critical-rce")
    profile = read_json(PROFILES / f"{profile_name}.json")
    lanes = campaign_lanes(profile_name)
    selected = set(args.lane or ())
    unknown = selected.difference(lane["id"] for lane in lanes)
    if unknown:
        raise SystemExit(f"unknown lanes: {', '.join(sorted(unknown))}")

    included = [lane for lane in lanes if not selected or lane["id"] in selected]
    measurement = rediscovery_measurement(root)
    task_campaign = dict(campaign)
    task_campaign["_rediscoveryMeasurement"] = measurement
    included_ids = {lane["id"] for lane in included}
    planned: list[dict[str, Any]] = []
    for lane in included:
        path = root / "tasks" / f"wave-{lane['wave']}-{lane['id']}.md"
        path.write_text(task_markdown(lane, task_campaign), encoding="utf-8")
        planned.append(
            {
                "taskId": lane["id"],
                "wave": lane["wave"],
                "lane": lane["id"],
                "title": lane["title"],
                "task": str(path.relative_to(root)),
                "priority": lane["priority"],
                "approachFamilies": lane["approachFamilies"],
                "dependsOn": (
                    [value for value in lane.get("dependsOn", []) if value in included_ids]
                    if "dependsOn" in lane
                    else (
                        []
                        if lane["wave"] == 0
                        else [
                            earlier["id"]
                            for earlier in included
                            if earlier["wave"] == lane["wave"] - 1
                        ]
                    )
                ),
            }
        )
    definitions = approach_family_definitions()
    selected_family_ids = sorted(
        {family_id for task in planned for family_id in task["approachFamilies"]}
        | {"blocker-alternative-route", "chain-composition", "validation-replay"}
    )
    write_json(
        root / "launch-plan.json",
        {
            "schemaVersion": 2,
            "profile": profile_name,
            "mission": "critical-rce-chain",
            "discoveryPolicy": campaign.get("discoveryPolicy", {}),
            "schedulingPolicy": profile.get("schedulingPolicy", {}),
            "rediscoveryMeasurement": measurement,
            "generatedAt": utc_now(),
            "maxConcurrency": args.max_concurrency,
            "defaultLeaseSeconds": args.lease_seconds,
            "defaultTaskTimeoutSeconds": args.task_timeout_seconds,
            "defaultMaxAttempts": args.max_attempts,
            "campaignBudgetSeconds": args.budget_seconds,
            "validationRule": "a candidate must be replayed by an agent that did not originate it",
            "approachFamilies": [definitions[family_id] for family_id in selected_family_ids],
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
            sync_approach_family_registry(
                connection, list(plan.get("approachFamilies", []))
            )
            set_metadata(connection, "schemaVersion", 1)
            set_metadata(connection, "createdAt", get_metadata(connection, "createdAt", now))
            configured_concurrency = parse_max_concurrency(
                plan.get("maxConcurrency", "auto")
            )
            set_metadata(connection, "maxConcurrency", configured_concurrency)
            set_metadata(
                connection, "schedulingPolicy", plan.get("schedulingPolicy", {})
            )
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
                    int(task.get("priority", 0)),
                    json.dumps(task.get("dependsOn", [])),
                    int(plan.get("defaultMaxAttempts", 2)),
                    int(plan.get("defaultTaskTimeoutSeconds", 7200)),
                    now,
                    now,
                )
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO tasks("
                    "task_id,wave,lane,title,packet,state,priority,depends_json,max_attempts,"
                    "timeout_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
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
                            "UPDATE tasks SET wave=?,lane=?,title=?,packet=?,priority=?,depends_json=?,"
                            "max_attempts=?,timeout_seconds=?,updated_at=? WHERE task_id=?",
                            (
                                int(task["wave"]),
                                str(task["lane"]),
                                str(task["title"]),
                                str(task["task"]),
                                int(task.get("priority", 0)),
                                json.dumps(task.get("dependsOn", [])),
                                int(plan.get("defaultMaxAttempts", 2)),
                                int(plan.get("defaultTaskTimeoutSeconds", 7200)),
                                now,
                                task_id,
                            ),
                        )
                        refreshed += 1
                set_task_approach_families(
                    connection, task_id, list(task.get("approachFamilies", []))
                )
            record_event(
                connection,
                "queue-reconciled",
                payload={"inserted": inserted, "refreshed": refreshed},
            )
            write_approach_family_snapshot(root, connection)
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
            existing = connection.execute(
                "SELECT agent FROM workers WHERE worker_id=?", (args.worker_id,)
            ).fetchone()
            active = connection.execute(
                "SELECT COUNT(*) AS count FROM workers WHERE status='active'"
            ).fetchone()["count"]
            gate_path = root / "evidence" / "coordinator-gate.json"
            gate = read_json(gate_path) if gate_path.is_file() else {}
            if (
                existing is None
                and int(active) >= 1
                and not (
                    gate.get("producer") == "krineon-coordinator-gate"
                    and gate.get("status") == "passed"
                    and gate.get("lyingWorkerRejected") is True
                )
            ):
                raise SystemExit(
                    "additional workers are disabled until gate-self-test proves that "
                    "coordinator re-execution rejects a lying worker"
                )
            if existing is not None and existing["agent"] != args.agent:
                raise SystemExit(
                    "worker agent identity is immutable; register a new worker ID instead"
                )
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


def cmd_gate_self_test(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    authorization = campaign.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise SystemExit("gate-self-test requires confirmed local authorization")
    directory = root / "evidence" / "coordinator-gate"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "always-negative.py"
    target.write_text(
        "#!/usr/bin/env python3\nprint('negative-only')\n", encoding="utf-8"
    )
    target_relative = target.relative_to(root).as_posix()
    frozen = campaign.get("frozenTargetArtifacts")
    if not isinstance(frozen, list):
        frozen = []
    frozen = [
        value
        for value in frozen
        if not isinstance(value, dict) or value.get("path") != target_relative
    ]
    frozen.append(
        {
            "path": target_relative,
            "sha256": sha256(target),
            "producer": "krineon-gate-self-test",
        }
    )
    campaign["frozenTargetArtifacts"] = frozen
    write_json(root / "campaign.json", campaign)
    task_id = "coordinator-gate-self-test"
    recipe = directory / "lying-worker-recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "findingId": task_id,
                "targetArtifacts": [target_relative],
                "cases": [
                    {
                        "name": "baseline",
                        "command": [sys.executable, target_relative],
                        "assertions": [
                            {"id": "baseline", "kind": "stdout-not-contains-challenge"}
                        ],
                    },
                    {
                        "name": "negative",
                        "command": [sys.executable, target_relative],
                        "assertions": [
                            {"id": "negative", "kind": "stdout-not-contains-challenge"}
                        ],
                    },
                    {
                        "name": "positive",
                        "command": [sys.executable, target_relative],
                        "assertions": [
                            {"id": "claimed-positive", "kind": "stdout-contains-challenge"}
                        ],
                    },
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    fake_result = {
        "taskResult": {
            "coordinatorReplay": {
                "recipe": recipe.relative_to(root).as_posix(),
                "repetitions": 1,
            }
        }
    }
    rejected = False
    diagnostic = ""
    try:
        coordinator_reexecute_result(root, fake_result, task_id, [])
    except SystemExit as error:
        diagnostic = str(error)
        rejected = "coordinator re-execution rejected" in diagnostic
    if not rejected:
        raise SystemExit(
            "coordinator gate self-test failed to reject the false positive claim: "
            + diagnostic
        )
    record = {
        "schemaVersion": 1,
        "producer": "krineon-coordinator-gate",
        "status": "passed",
        "testedAt": utc_now(),
        "lyingWorkerRejected": True,
        "target": {"path": target_relative, "sha256": sha256(target)},
        "recipe": {
            "path": recipe.relative_to(root).as_posix(),
            "sha256": sha256(recipe),
        },
        "diagnostic": diagnostic,
    }
    write_json(root / "evidence" / "coordinator-gate.json", record)
    print("coordinator gate: passed; false worker claim was rejected by re-execution")
    return 0


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
            write_approach_family_snapshot(root, connection)
        print(f"stopped worker {args.worker_id}; requeued {len(running)} tasks")
        return 0
    finally:
        connection.close()


def diversity_rank_ready_tasks(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> tuple[list[sqlite3.Row], dict[str, Any] | None]:
    if len(rows) < 2:
        return rows, None
    snapshot = approach_family_snapshot(connection)
    family_stats = {family["id"]: family for family in snapshot["families"]}
    task_families: dict[str, list[str]] = {}
    for row in rows:
        task_families[str(row["task_id"])] = [
            family_id
            for family_id in task_approach_families(connection, str(row["task_id"]))
            if family_stats.get(family_id, {}).get("exploration")
        ]
    baseline_families = task_families[str(rows[0]["task_id"])]
    if not baseline_families:
        return rows, None
    ready_families = {
        family_id for family_ids in task_families.values() for family_id in family_ids
    }
    if len(ready_families) < 2:
        return rows, None

    def load_key(row: sqlite3.Row) -> tuple[int, int]:
        families = task_families[str(row["task_id"])]
        if not families:
            return (sys.maxsize, sys.maxsize)
        # A multi-family task must account for its most-loaded family. Otherwise
        # attaching one unused label could disguise continued concentration.
        return (
            max(int(family_stats[family_id]["activeAgents"]) for family_id in families),
            max(int(family_stats[family_id]["coverageLoad"]) for family_id in families),
        )

    exploration_rows = [row for row in rows if task_families[str(row["task_id"])]]
    best_load = min(load_key(row) for row in exploration_rows)
    baseline_load = load_key(rows[0])
    if baseline_load == best_load:
        return rows, None
    preferred: list[sqlite3.Row] = []
    remainder: list[sqlite3.Row] = []
    for row in rows:
        if load_key(row) == best_load:
            preferred.append(row)
        else:
            remainder.append(row)
    ranked = preferred + remainder
    minimum_active = min(family_stats[family_id]["activeAgents"] for family_id in ready_families)
    underexplored = sorted(
        family_id
        for family_id in ready_families
        if family_stats[family_id]["activeAgents"] == minimum_active
        and family_stats[family_id]["coverageLoad"]
        == min(
            family_stats[candidate]["coverageLoad"]
            for candidate in ready_families
            if family_stats[candidate]["activeAgents"] == minimum_active
        )
    )
    dominated = sorted(
        family_id
        for family_id in ready_families
        if family_stats[family_id]["activeAgents"] > minimum_active
        or family_stats[family_id]["coverageLoad"] > best_load[1]
    )
    return ranked, {
        "fromTaskId": rows[0]["task_id"],
        "toTaskId": ranked[0]["task_id"],
        "dominatedFamilies": dominated,
        "underexploredFamilies": underexplored,
        "baselineLoad": {"activeAgents": baseline_load[0], "coverageLoad": baseline_load[1]},
        "selectedLoad": {"activeAgents": best_load[0], "coverageLoad": best_load[1]},
        "reason": "approach diversity outranks suspicion, promise, and raw task priority",
        "identityBasis": "registered boundary + mechanism + invariant",
    }


def worker_is_eligible_for_round_task(
    connection: sqlite3.Connection, worker: sqlite3.Row, task: sqlite3.Row
) -> bool:
    task_kind = str(task["task_kind"] or "ordinary")
    research_round = int(task["research_round"] or 0)
    if task_kind in {"root-round-synthesis", "next-round-planning"} and worker[
        "role"
    ] != "coordinator":
        return False
    if worker["role"] == "coordinator" and task_kind in {
        "route-development",
        "adversarial-route-review",
        "mature-cross-pollination",
    }:
        return False
    if task_kind == "route-development" and research_round > 0:
        used_agents = {
            row["agent"]
            for row in connection.execute(
                "SELECT DISTINCT workers.agent FROM tasks "
                "JOIN workers ON workers.worker_id=tasks.lease_owner "
                "WHERE tasks.research_round=? AND tasks.task_kind='route-development' "
                "AND tasks.route_id<>? AND tasks.state IN ('running','completed','blocked','failed')",
                (research_round, task["route_id"] or ""),
            ).fetchall()
        }
        if worker["agent"] in used_agents:
            return False
    if task_kind == "adversarial-route-review" and task["reviews_task_id"]:
        developer = connection.execute(
            "SELECT workers.agent FROM tasks "
            "JOIN workers ON workers.worker_id=tasks.lease_owner "
            "WHERE tasks.task_id=?",
            (task["reviews_task_id"],),
        ).fetchone()
        if developer is not None and developer["agent"] == worker["agent"]:
            return False
    return True


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
        active_for_agent = connection.execute(
            "SELECT tasks.task_id FROM tasks JOIN workers ON workers.worker_id=tasks.lease_owner "
            "WHERE tasks.state='running' AND workers.agent=? LIMIT 1",
            (worker["agent"],),
        ).fetchone()
        if active_for_agent is not None:
            connection.commit()
            payload = {
                "claimed": False,
                "reason": "agent-already-holds-running-task",
                "taskId": active_for_agent["task_id"],
                "recovery": recovery,
            }
            if args.json:
                print(json.dumps(payload, indent=2))
            else:
                print(
                    f"agent identity already owns running task: {active_for_agent['task_id']}",
                    file=sys.stderr,
                )
            return 3
        _, max_concurrency = resolve_concurrency_limit(connection)
        running = connection.execute(
            "SELECT COUNT(*) AS count FROM tasks WHERE state='running'"
        ).fetchone()["count"]
        if running >= max_concurrency:
            connection.commit()
            print("concurrency limit reached", file=sys.stderr)
            return 3
        chosen = None
        eligible: list[sqlite3.Row] = []
        for row in connection.execute(
            "SELECT * FROM tasks WHERE state='queued' ORDER BY priority DESC,wave,created_at,task_id"
        ).fetchall():
            excluded = json.loads(row["excluded_workers_json"])
            excluded_agents = json.loads(row["excluded_agents_json"])
            if args.worker_id in excluded or worker["agent"] in excluded_agents:
                continue
            if not worker_is_eligible_for_round_task(connection, worker, row):
                continue
            if dependency_state(connection, row) == "ready":
                eligible.append(row)
        ranked, redirect = diversity_rank_ready_tasks(connection, eligible)
        if ranked:
            chosen = ranked[0]
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
        # Prefix the capability so argparse never mistakes a leading '-' from
        # token_urlsafe() for a new command-line option.
        token = "lease_" + secrets.token_urlsafe(24)
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
                "approachFamilies": task_approach_families(
                    connection, str(chosen["task_id"])
                ),
            },
        )
        if redirect is not None:
            record_event(
                connection,
                "approach-family-redirect",
                task_id=chosen["task_id"],
                worker_id=args.worker_id,
                payload=redirect,
            )
        write_approach_family_snapshot(root, connection)
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
            "researchRound": chosen["research_round"],
            "routeId": chosen["route_id"],
            "taskKind": chosen["task_kind"],
            "reviewsTaskId": chosen["reviews_task_id"],
            "approachFamilies": task_approach_families(
                connection, str(chosen["task_id"])
            ),
            "approachRedirect": redirect,
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


def validate_dependencies(connection: sqlite3.Connection, dependencies: list[str]) -> None:
    for dependency in dependencies:
        if connection.execute(
            "SELECT 1 FROM tasks WHERE task_id=?", (dependency,)
        ).fetchone() is None:
            raise SystemExit(f"unknown task dependency: {dependency}")


def insert_dynamic_task(
    connection: sqlite3.Connection,
    *,
    task_id: str,
    wave: int,
    lane: str,
    title: str,
    packet: str,
    priority: int,
    dependencies: list[str],
    excluded_workers: list[str],
    max_attempts: int,
    timeout_seconds: int,
    approach_families: list[str],
    unblocks_task_id: str | None = None,
    research_round: int = 0,
    route_id: str | None = None,
    task_kind: str = "ordinary",
    reviews_task_id: str | None = None,
    excluded_agents: list[str] | None = None,
) -> None:
    validate_dependencies(connection, dependencies)
    if connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone():
        raise SystemExit(f"task already exists: {task_id}")
    now = utc_now()
    connection.execute(
        "INSERT INTO tasks(task_id,wave,lane,title,packet,state,priority,depends_json,"
        "excluded_workers_json,excluded_agents_json,unblocks_task_id,research_round,route_id,"
        "task_kind,reviews_task_id,max_attempts,timeout_seconds,created_at,updated_at) "
        "VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            task_id,
            wave,
            lane,
            title,
            packet,
            priority,
            json.dumps(dependencies),
            json.dumps(excluded_workers),
            json.dumps(sorted(set(excluded_agents or []))),
            unblocks_task_id,
            research_round,
            route_id,
            task_kind,
            reviews_task_id,
            max_attempts,
            timeout_seconds,
            now,
            now,
        ),
    )
    set_task_approach_families(connection, task_id, approach_families)


def lead_rank_key(row: sqlite3.Row) -> tuple[int, int, str]:
    state_rank = 1 if str(row["state"]) == "disproved" else 0
    grade_rank = LEAD_GRADE_ORDER.get(str(row["evidence_grade"]), 99)
    return (state_rank, grade_rank, str(row["lead_id"]))


def ingest_research_leads(
    root: Path,
    connection: sqlite3.Connection,
    *,
    task: sqlite3.Row,
    worker_id: str,
    leads: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    for lead in leads:
        identity = str(lead["semanticIdentity"])
        deterministic_id = "L" + hashlib.sha256(identity.encode()).hexdigest()[:15]
        now = utc_now()
        prior = connection.execute(
            "SELECT * FROM research_leads WHERE semantic_identity=?", (identity,)
        ).fetchone()
        if prior is None:
            payload = dict(lead)
            payload["originTasks"] = [str(task["task_id"])]
            payload["originWorkers"] = [worker_id]
            payload["scheduledExperimentDigests"] = []
            connection.execute(
                "INSERT INTO research_leads(lead_id,semantic_identity,kind,evidence_grade,state,"
                "title,payload_json,first_task_id,first_worker_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    deterministic_id,
                    identity,
                    lead["kind"],
                    lead["evidenceGrade"],
                    lead["status"],
                    lead["title"],
                    json.dumps(payload, sort_keys=True),
                    str(task["task_id"]),
                    worker_id,
                    now,
                    now,
                ),
            )
            lead_id = deterministic_id
            created = True
        else:
            lead_id = str(prior["lead_id"])
            payload = json.loads(prior["payload_json"])
            payload["originTasks"] = sorted(
                set(payload.get("originTasks", [])) | {str(task["task_id"])}
            )
            payload["originWorkers"] = sorted(
                set(payload.get("originWorkers", [])) | {worker_id}
            )
            payload["evidence"] = sorted(
                set(payload.get("evidence", [])) | set(lead.get("evidence", []))
            )
            payload["sourceReferences"] = sorted(
                set(payload.get("sourceReferences", []))
                | set(lead.get("sourceReferences", []))
            )
            prior_grade = str(prior["evidence_grade"])
            new_grade = str(lead["evidenceGrade"])
            if LEAD_GRADE_ORDER.get(new_grade, 99) < LEAD_GRADE_ORDER.get(prior_grade, 99):
                payload.update(lead)
                grade = new_grade
            else:
                grade = prior_grade
                payload["nextExperiment"] = lead["nextExperiment"]
                payload["status"] = lead["status"]
            connection.execute(
                "UPDATE research_leads SET evidence_grade=?,state=?,title=?,payload_json=?,"
                "updated_at=? WHERE lead_id=?",
                (
                    grade,
                    lead["status"],
                    lead["title"],
                    json.dumps(payload, sort_keys=True),
                    now,
                    lead_id,
                ),
            )
            created = False
        connection.execute(
            "INSERT OR IGNORE INTO task_research_leads(task_id,lead_id,relationship) "
            "VALUES(?,?,'observed')",
            (str(task["task_id"]), lead_id),
        )

        scheduled_task: str | None = None
        experiment_digest = canonical_digest(
            {
                "lead": lead_id,
                "experiment": lead["nextExperiment"],
                "grade": lead["evidenceGrade"],
            }
        )
        row = connection.execute(
            "SELECT payload_json,state FROM research_leads WHERE lead_id=?", (lead_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        scheduled = list(payload.get("scheduledExperimentDigests", []))
        if row["state"] != "disproved" and experiment_digest not in scheduled:
            suffix = len(scheduled) + 1
            scheduled_task = f"lead-{lead_id.lower()}-{suffix}"
            packet = root / "tasks" / f"dynamic-{scheduled_task}.md"
            packet.write_text(
                f"""# Research-lead experiment: {lead_id}

## Retained observation

- Kind: `{lead['kind']}`
- Evidence grade: `{lead['evidenceGrade']}`
- Semantic identity: `{identity}`
- Title: {lead['title']}

## Next experiment

{lead['nextExperiment']}

## Success contract

Confirm or falsify this one observation, minimize it further, improve its
evidence grade, or connect one adjacent predecessor/successor link. A complete
RCE chain is **not** required to complete this task. Never invent missing chain
links to unlock later work. Return another `taskResult.researchLeads` entry when
the observation survives or materially changes; mark it disproved when a
control falsifies it.

Checked-in tests, assertions, comments that state invariants, and test fixtures
from the pinned target revision are valid local oracles. Do not inspect patch
history, security commits, advisories, or other revisions to locate a bug.
""",
                encoding="utf-8",
            )
            insert_dynamic_task(
                connection,
                task_id=scheduled_task,
                wave=max(1, int(task["wave"])),
                lane="research-lead-validation",
                title=f"Validate {lead_id}: {lead['title']}",
                packet=packet.relative_to(root).as_posix(),
                priority=1600 - LEAD_GRADE_ORDER.get(str(lead["evidenceGrade"]), 99),
                dependencies=[],
                excluded_workers=[],
                max_attempts=2,
                timeout_seconds=int(task["timeout_seconds"]),
                approach_families=list(lead["approachFamilies"]),
                task_kind="research-lead-validation",
            )
            connection.execute(
                "UPDATE tasks SET lead_id=? WHERE task_id=?", (lead_id, scheduled_task)
            )
            connection.execute(
                "INSERT OR IGNORE INTO task_research_leads(task_id,lead_id,relationship) "
                "VALUES(?,?,'validates')",
                (scheduled_task, lead_id),
            )
            scheduled.append(experiment_digest)
            payload["scheduledExperimentDigests"] = scheduled
            connection.execute(
                "UPDATE research_leads SET payload_json=?,updated_at=? WHERE lead_id=?",
                (json.dumps(payload, sort_keys=True), now, lead_id),
            )
        record_event(
            connection,
            "research-lead-ingested",
            task_id=str(task["task_id"]),
            worker_id=worker_id,
            payload={
                "leadId": lead_id,
                "semanticIdentity": identity,
                "kind": lead["kind"],
                "evidenceGrade": lead["evidenceGrade"],
                "created": created,
                "scheduledTask": scheduled_task,
            },
        )
        retained.append(
            {
                "leadId": lead_id,
                "created": created,
                "evidenceGrade": lead["evidenceGrade"],
                "scheduledTask": scheduled_task,
            }
        )
    return retained


def cmd_lead_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        rows = sorted(
            connection.execute("SELECT * FROM research_leads").fetchall(),
            key=lead_rank_key,
        )
        leads = []
        for rank, row in enumerate(rows, start=1):
            payload = json.loads(row["payload_json"])
            leads.append(
                {
                    "rank": rank,
                    "leadId": row["lead_id"],
                    "kind": row["kind"],
                    "evidenceGrade": row["evidence_grade"],
                    "state": row["state"],
                    "title": row["title"],
                    "semanticIdentity": row["semantic_identity"],
                    "nextExperiment": payload.get("nextExperiment"),
                    "originTasks": payload.get("originTasks", []),
                }
            )
        result = {
            "rankingBasis": [
                "active before disproved",
                "verified primitive",
                "runtime-reproduced invariant break",
                "unique minimized stack cluster",
                "source-confirmed invariant break",
                "stable semantic identity breaks equal-grade ties",
            ],
            "impactClaimed": False,
            "leads": leads,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        elif not leads:
            print("no retained research leads")
        else:
            print(f"{'RANK':>4} {'LEAD':<18} {'GRADE':<20} {'STATE':<10} TITLE")
            print("-" * 100)
            for lead in leads:
                print(
                    f"{lead['rank']:>4} {lead['leadId']:<18} "
                    f"{lead['evidenceGrade']:<20} {lead['state']:<10} {lead['title']}"
                )
        return 0
    finally:
        connection.close()


def cmd_task_add(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    if args.wave < 0 or args.max_attempts < 1 or args.timeout_seconds < 1:
        raise SystemExit("wave must be nonnegative; attempts and timeout must be positive")
    connection = connect_orchestration(root)
    packet = root / "tasks" / f"dynamic-{args.task_id}.md"
    success = "\n".join(f"- {item}" for item in args.success_criterion)
    packet.write_text(
        f"""# Dynamic exploration task: {args.title}

## Objective

{args.objective}

## Registered approach families

{chr(10).join(f'- `{family_id}`' for family_id in args.approach_family)}

Use these stable semantic family identities. Do not relabel the same mechanism
with different prose to make it look like new coverage.

## Success criteria

{success}

## Expansion mandate

Treat the objective as a starting direction, not an exhaustive testcase list.
Follow adjacent source paths, state transitions, platform variants, and
producer/consumer boundaries while they remain inside `AUTHORIZATION.md`. If a
path blocks, identify the missing link, blocking mechanism, bypass hypotheses,
alternative routes, and cheapest discriminator. Submit structured evidence;
do not stop at a prose statement that the lane is blocked. Self-resolvable
technical blockers automatically become fresh-agent breakout tasks.

## Search and filing policy

Preserve unique stack clusters, invariant violations, and verified primitives
even before they compose into Critical/RCE. Analyze the pinned source and
exact-revision runtime from first principles. A complete chain is the report
bar, not the queue-admission bar. Do not use changelogs,
advisories, Git history or blame, historical commits, patched-version
comparisons, or internet-derived patch diffs. Do not promote crash-only, DoS,
or lower-severity outcomes as reports. Target-owned tests and invariants in the
pinned revision are permitted and encouraged local oracles.

## Evidence contract

- Preserve exact revisions, commands, controls, and artifact paths.
- Separate confirmed runtime behavior from source inference.
- Register promising, blocked, and disproved variants.
- Do not broaden authorization or test third-party systems.
""",
        encoding="utf-8",
    )
    try:
        with connection:
            insert_dynamic_task(
                connection,
                task_id=args.task_id,
                wave=args.wave,
                lane=args.lane,
                title=args.title,
                packet=packet.relative_to(root).as_posix(),
                priority=args.priority,
                dependencies=args.depends_on or [],
                excluded_workers=args.exclude_worker or [],
                max_attempts=args.max_attempts,
                timeout_seconds=args.timeout_seconds,
                approach_families=args.approach_family,
            )
            record_event(
                connection,
                "dynamic-task-added",
                task_id=args.task_id,
                payload={
                    "lane": args.lane,
                    "objective": args.objective,
                    "dependencies": args.depends_on or [],
                    "approachFamilies": args.approach_family,
                },
            )
        print(f"added exploration task {args.task_id}")
        return 0
    finally:
        connection.close()


def route_maturity(
    root: Path, connection: sqlite3.Connection, route_id: str, before_round: int
) -> dict[str, int]:
    development = int(
        connection.execute(
            "SELECT COUNT(DISTINCT research_round) AS count FROM tasks "
            "WHERE route_id=? AND task_kind='route-development' AND state='completed' "
            "AND research_round<?",
            (route_id, before_round),
        ).fetchone()["count"]
    )
    passed_rounds: set[int] = set()
    for row in connection.execute(
        "SELECT tasks.research_round,submissions.result_path FROM tasks "
        "JOIN submissions ON submissions.task_id=tasks.task_id "
        "WHERE tasks.route_id=? AND tasks.task_kind='adversarial-route-review' "
        "AND tasks.state='completed' AND tasks.research_round<? "
        "AND submissions.outcome='completed'",
        (route_id, before_round),
    ).fetchall():
        result_path = root / str(row["result_path"])
        if not result_path.is_file():
            continue
        review = read_json(result_path).get("adversarialReview")
        if isinstance(review, dict) and review.get("sanityPassed") is True:
            passed_rounds.add(int(row["research_round"]))
    adversarial = len(passed_rounds)
    return {"developmentRounds": development, "adversarialRounds": adversarial}


def cmd_round_plan(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    plan = read_json(Path(args.plan).expanduser().resolve())
    research_round = int(plan.get("round", 0))
    routes = plan.get("routes")
    if research_round < 1 or not isinstance(routes, list) or len(routes) < 3:
        raise SystemExit("round plan requires a positive round and at least three routes")
    connection = connect_orchestration(root)
    try:
        with connection:
            coordinator = connection.execute(
                "SELECT * FROM workers WHERE worker_id=?", (args.worker_id,)
            ).fetchone()
            if coordinator is None or coordinator["status"] != "active":
                raise SystemExit("round coordinator must be a registered active worker")
            if coordinator["role"] != "coordinator":
                raise SystemExit("round-plan may be launched only by a coordinator worker")
            expected_round = int(get_metadata(connection, "lastResearchRound", 0)) + 1
            if research_round != expected_round:
                raise SystemExit(f"next research round must be {expected_round}")
            if research_round > 1:
                previous_synthesis_id = f"round-{research_round - 1}-root-synthesis"
                previous = connection.execute(
                    "SELECT tasks.state,submissions.result_path FROM tasks "
                    "LEFT JOIN submissions ON submissions.task_id=tasks.task_id "
                    "AND submissions.outcome='completed' "
                    "WHERE tasks.task_id=? ORDER BY submissions.submitted_at DESC LIMIT 1",
                    (previous_synthesis_id,),
                ).fetchone()
                if previous is None or previous["state"] != "completed" or not previous["result_path"]:
                    raise SystemExit(
                        "the previous coordinator synthesis must complete before another round"
                    )
                previous_result = read_json(root / str(previous["result_path"]))
                previous_synthesis = previous_result.get("roundSynthesis")
                if (
                    not isinstance(previous_synthesis, dict)
                    or previous_synthesis.get("launchNextRound") is not True
                ):
                    raise SystemExit(
                        "the previous root synthesis did not authorize another research round"
                    )
            definitions = {
                row["family_id"]: row
                for row in connection.execute("SELECT * FROM approach_families").fetchall()
            }
            route_by_id: dict[str, dict[str, Any]] = {}
            family_ids: set[str] = set()
            for index, route in enumerate(routes):
                if not isinstance(route, dict):
                    raise SystemExit(f"routes[{index}] must be an object")
                route_id = validate_task_id(require_string(route.get("id"), f"routes[{index}].id"))
                family_id = require_string(route.get("family"), f"routes[{index}].family")
                if route_id in route_by_id:
                    raise SystemExit(f"duplicate route ID: {route_id}")
                if family_id in family_ids:
                    raise SystemExit(
                        "independent routes in one round must use distinct semantic families"
                    )
                family = definitions.get(family_id)
                if family is None or not family["exploration"]:
                    raise SystemExit(f"route must use a registered exploration family: {family_id}")
                previous_family = connection.execute(
                    "SELECT task_approach_families.family_id FROM tasks "
                    "JOIN task_approach_families USING(task_id) "
                    "WHERE tasks.route_id=? AND tasks.task_kind='route-development' "
                    "ORDER BY tasks.research_round DESC LIMIT 1",
                    (route_id,),
                ).fetchone()
                if previous_family is not None and previous_family["family_id"] != family_id:
                    raise SystemExit(
                        f"route {route_id} cannot change semantic family across rounds"
                    )
                require_string(route.get("title"), f"routes[{index}].title")
                require_string(route.get("objective"), f"routes[{index}].objective")
                require_string_list(route.get("successCriteria"), f"routes[{index}].successCriteria")
                incompatible = require_string_list(
                    route.get("incompatibleWith"), f"routes[{index}].incompatibleWith"
                )
                if route_id in incompatible:
                    raise SystemExit("a route cannot be incompatible with itself")
                route_by_id[route_id] = route
                family_ids.add(family_id)
            route_ids = set(route_by_id)
            for route_id, route in route_by_id.items():
                incompatible = set(str(value) for value in route["incompatibleWith"])
                unknown = incompatible.difference(route_ids)
                if unknown:
                    raise SystemExit(
                        f"route {route_id} references unknown incompatible routes: "
                        + ", ".join(sorted(unknown))
                    )
                if not any(
                    route_id in set(str(value) for value in route_by_id[other]["incompatibleWith"])
                    for other in incompatible
                ):
                    raise SystemExit(
                        f"route {route_id} needs at least one reciprocal incompatibility"
                    )

            adversarial_task_ids: dict[str, str] = {}
            for route_id, route in route_by_id.items():
                family_id = str(route["family"])
                development_id = f"round-{research_round}-{route_id}-develop"
                adversarial_id = f"round-{research_round}-{route_id}-adversary"
                criteria = "\n".join(f"- {item}" for item in route["successCriteria"])
                incompatibility = ", ".join(f"`{item}`" for item in route["incompatibleWith"])
                development_packet = root / "tasks" / f"dynamic-{development_id}.md"
                development_packet.write_text(
                    f"""# Independent route development: {route['title']}

Research round: {research_round}
Route ID: `{route_id}`
Semantic family: `{family_id}`
Incompatible routes kept alive this round: {incompatibility}

## Objective

{route['objective']}

## Success criteria

{criteria}

Develop this route independently. Do not consume another route's unpublished
ideas or combine mechanisms during this task. Record real strengths, gaps,
evidence, intermediate bugs, chain hypotheses, fresh ideas, and the next
experiment in `routeDevelopment`. A result of "no finding" is not a terminal
outcome. Independence exists to expose what this route can and cannot do before
synthesis.
""",
                    encoding="utf-8",
                )
                insert_dynamic_task(
                    connection,
                    task_id=development_id,
                    wave=100 + research_round,
                    lane="independent-route-development",
                    title=f"Round {research_round}: {route['title']}",
                    packet=development_packet.relative_to(root).as_posix(),
                    priority=3000,
                    dependencies=[],
                    excluded_workers=[],
                    max_attempts=int(plan.get("maxAttempts", 2)),
                    timeout_seconds=int(plan.get("timeoutSeconds", 7200)),
                    approach_families=[family_id],
                    research_round=research_round,
                    route_id=route_id,
                    task_kind="route-development",
                )
                adversarial_packet = root / "tasks" / f"dynamic-{adversarial_id}.md"
                adversarial_packet.write_text(
                    f"""# Adversarial route review: {route['title']}

Research round: {research_round}
Route ID: `{route_id}`
Review task: `{development_id}`

Attack the route's assumptions, attacker control, reachability, invariants,
evidence, and terminal. Reproduce the decisive observation where safe. Do not
help the developer repair the route until the strongest counterargument and
unresolved gaps are recorded. Submit `adversarialReview`; the scheduler rejects
the same runtime-agent identity that developed the route.
""",
                    encoding="utf-8",
                )
                insert_dynamic_task(
                    connection,
                    task_id=adversarial_id,
                    wave=100 + research_round,
                    lane="adversarial-route-review",
                    title=f"Adversarial review of {route['title']}",
                    packet=adversarial_packet.relative_to(root).as_posix(),
                    priority=2900,
                    dependencies=[development_id],
                    excluded_workers=[],
                    max_attempts=int(plan.get("maxAttempts", 2)),
                    timeout_seconds=int(plan.get("timeoutSeconds", 7200)),
                    approach_families=[family_id],
                    research_round=research_round,
                    route_id=route_id,
                    task_kind="adversarial-route-review",
                    reviews_task_id=development_id,
                )
                adversarial_task_ids[route_id] = adversarial_id

            cross_task_ids: list[str] = []
            cross_pollinations = plan.get("crossPollinations", [])
            if not isinstance(cross_pollinations, list):
                raise SystemExit("crossPollinations must be a list")
            for index, cross in enumerate(cross_pollinations):
                if not isinstance(cross, dict):
                    raise SystemExit(f"crossPollinations[{index}] must be an object")
                cross_id = validate_task_id(
                    require_string(cross.get("id"), f"crossPollinations[{index}].id")
                )
                left = require_string(cross.get("leftRoute"), "crossPollination.leftRoute")
                right = require_string(cross.get("rightRoute"), "crossPollination.rightRoute")
                if left == right or left not in route_by_id or right not in route_by_id:
                    raise SystemExit("cross-pollination requires two current, distinct routes")
                for route_id in (left, right):
                    maturity = route_maturity(root, connection, route_id, research_round)
                    if maturity["developmentRounds"] < 2 or maturity["adversarialRounds"] < 2:
                        raise SystemExit(
                            f"cross-pollination is premature for {route_id}; "
                            "require two completed development and adversarial rounds"
                        )
                title = require_string(cross.get("title"), "crossPollination.title")
                objective = require_string(cross.get("objective"), "crossPollination.objective")
                success = require_string_list(
                    cross.get("successCriteria"), "crossPollination.successCriteria"
                )
                task_id = f"round-{research_round}-cross-{cross_id}"
                packet = root / "tasks" / f"dynamic-{task_id}.md"
                packet.write_text(
                    f"""# Mature-route cross-pollination: {title}

Source routes: `{left}` and `{right}`
Research round: {research_round}

Both routes completed at least two independent development and adversarial
rounds. Combine only their retained strengths and explicitly account for both
sets of gaps.

## Objective

{objective}

## Success criteria

{chr(10).join(f'- {item}' for item in success)}
""",
                    encoding="utf-8",
                )
                insert_dynamic_task(
                    connection,
                    task_id=task_id,
                    wave=100 + research_round,
                    lane="mature-route-cross-pollination",
                    title=title,
                    packet=packet.relative_to(root).as_posix(),
                    priority=2950,
                    dependencies=[adversarial_task_ids[left], adversarial_task_ids[right]],
                    excluded_workers=[],
                    max_attempts=int(plan.get("maxAttempts", 2)),
                    timeout_seconds=int(plan.get("timeoutSeconds", 7200)),
                    approach_families=list(
                        dict.fromkeys(
                            [
                                str(route_by_id[left]["family"]),
                                str(route_by_id[right]["family"]),
                                "chain-composition",
                            ]
                        )
                    ),
                    research_round=research_round,
                    route_id=f"{left}+{right}",
                    task_kind="mature-cross-pollination",
                )
                cross_task_ids.append(task_id)

            synthesis_id = f"round-{research_round}-root-synthesis"
            synthesis_packet = root / "tasks" / f"dynamic-{synthesis_id}.md"
            synthesis_packet.write_text(
                f"""# Root synthesis for research round {research_round}

Read every route-development result and adversarial review. Compare strengths,
gaps, falsifications, and missing links without collapsing the campaign onto
the most exciting route. Redirect weak routes to their cheapest discriminators,
challenge strong routes with their best counterarguments, and decide which
incompatible routes remain alive. Generate at least three fresh directions and
chain all sanity-checked intermediate bugs before synthesis can finish. Launch
the next round with `round-plan` when `roundSynthesis.launchNextRound` is true.
"No findings" and failed current approaches are not hard stops. Cross-pollinate
only routes that have already satisfied the two-round maturity gate.
""",
                encoding="utf-8",
            )
            insert_dynamic_task(
                connection,
                task_id=synthesis_id,
                wave=100 + research_round,
                lane="root-round-synthesis",
                title=f"Root synthesis for round {research_round}",
                packet=synthesis_packet.relative_to(root).as_posix(),
                priority=2800,
                dependencies=list(adversarial_task_ids.values()) + cross_task_ids,
                excluded_workers=[],
                max_attempts=2,
                timeout_seconds=int(plan.get("timeoutSeconds", 7200)),
                approach_families=["chain-composition"],
                research_round=research_round,
                task_kind="root-round-synthesis",
            )
            set_metadata(connection, "lastResearchRound", research_round)
            record_event(
                connection,
                "research-round-launched",
                task_id=synthesis_id,
                worker_id=args.worker_id,
                payload={
                    "round": research_round,
                    "routes": sorted(route_by_id),
                    "crossPollinations": cross_task_ids,
                },
            )
            write_approach_family_snapshot(root, connection)
        print(
            f"launched round {research_round}: {len(route_by_id)} independent routes, "
            f"{len(route_by_id)} adversarial reviews, {len(cross_task_ids)} cross-pollinations"
        )
        return 0
    finally:
        connection.close()


def latest_task_submission(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM submissions WHERE task_id=? ORDER BY submitted_at DESC LIMIT 1",
        (task_id,),
    ).fetchone()


def schedule_intermediate_chain_task(
    root: Path,
    connection: sqlite3.Connection,
    review_task: sqlite3.Row,
    review_result: dict[str, Any],
    reviewer_worker: str,
) -> str | None:
    review = review_result.get("adversarialReview")
    if not isinstance(review, dict) or review.get("sanityPassed") is not True:
        return None
    development_id = str(review_task["reviews_task_id"] or "")
    submission = latest_task_submission(connection, development_id)
    if submission is None:
        return None
    development_result = read_json(root / str(submission["result_path"]))
    development = development_result.get("routeDevelopment")
    if not isinstance(development, dict):
        return None
    intermediate_bugs = development.get("intermediateBugs")
    if not isinstance(intermediate_bugs, list) or not intermediate_bugs:
        return None
    route_id = str(review_task["route_id"])
    research_round = int(review_task["research_round"])
    existing = int(
        connection.execute(
            "SELECT COUNT(*) AS count FROM tasks WHERE research_round=? AND route_id=? "
            "AND task_kind='intermediate-chain-composition'",
            (research_round, route_id),
        ).fetchone()["count"]
    )
    task_id = f"round-{research_round}-{route_id}-chain-{existing + 1}"
    bug_lines = "\n".join(
        f"- `{bug['id']}`: root cause={bug['rootCause']}; primitive={bug['primitive']}"
        for bug in intermediate_bugs
        if isinstance(bug, dict)
    )
    hypotheses = "\n".join(
        f"- {item}"
        for item in development.get("chainHypotheses", [])
        if str(item).strip()
    )
    packet = root / "tasks" / f"dynamic-{task_id}.md"
    packet.write_text(
        f"""# Intermediate-bug chain composition

Research round: {research_round}
Route: `{route_id}`
Source development: `{development_id}`
Sanity review: `{review_task['task_id']}`

## Sanity-checked intermediate bugs

{bug_lines}

## Source route's chain hypotheses

{hypotheses}

Do not discard these bugs because none is Critical alone. Attempt compositions
with other retained primitives, acquisition paths, authority transitions, and
stock sinks. Record attempted chains, evidence, the strongest surviving or
falsified composition, and fresh ideas. A failed composition is not permission
to end the route or campaign.
""",
        encoding="utf-8",
    )
    excluded_agents: set[str] = set()
    for worker_id in (str(submission["worker_id"]), reviewer_worker):
        worker = connection.execute(
            "SELECT agent FROM workers WHERE worker_id=?", (worker_id,)
        ).fetchone()
        if worker is not None:
            excluded_agents.add(str(worker["agent"]))
    excluded_workers = [
        row["worker_id"]
        for agent in sorted(excluded_agents)
        for row in connection.execute(
            "SELECT worker_id FROM workers WHERE agent=?", (agent,)
        ).fetchall()
    ]
    insert_dynamic_task(
        connection,
        task_id=task_id,
        wave=int(review_task["wave"]),
        lane="intermediate-bug-chain-composition",
        title=f"Chain sanity-checked intermediate bugs from {route_id}",
        packet=packet.relative_to(root).as_posix(),
        priority=2975,
        dependencies=[str(review_task["task_id"])],
        excluded_workers=sorted(set(excluded_workers)),
        excluded_agents=sorted(excluded_agents),
        max_attempts=max(2, int(review_task["max_attempts"])),
        timeout_seconds=int(review_task["timeout_seconds"]),
        approach_families=list(
            dict.fromkeys(
                task_approach_families(connection, development_id)
                + ["chain-composition"]
            )
        ),
        research_round=research_round,
        route_id=route_id,
        task_kind="intermediate-chain-composition",
    )
    synthesis = connection.execute(
        "SELECT * FROM tasks WHERE research_round=? AND task_kind='root-round-synthesis'",
        (research_round,),
    ).fetchone()
    if synthesis is not None and synthesis["state"] == "queued":
        dependencies = task_dependencies(synthesis)
        if task_id not in dependencies:
            dependencies.append(task_id)
            connection.execute(
                "UPDATE tasks SET depends_json=?,updated_at=? WHERE task_id=?",
                (json.dumps(dependencies), utc_now(), synthesis["task_id"]),
            )
    record_event(
        connection,
        "intermediate-chain-task-scheduled",
        task_id=task_id,
        worker_id=reviewer_worker,
        payload={
            "routeId": route_id,
            "round": research_round,
            "sourceTaskId": development_id,
            "reviewTaskId": review_task["task_id"],
            "intermediateBugIds": [
                str(bug.get("id")) for bug in intermediate_bugs if isinstance(bug, dict)
            ],
        },
    )
    return task_id


def schedule_next_round_planning_task(
    root: Path,
    connection: sqlite3.Connection,
    synthesis_task: sqlite3.Row,
    synthesis_result: dict[str, Any],
    coordinator_worker: str,
) -> str | None:
    synthesis = synthesis_result.get("roundSynthesis")
    if not isinstance(synthesis, dict) or synthesis.get("launchNextRound") is not True:
        return None
    from_round = int(synthesis_task["research_round"])
    target_round = from_round + 1
    task_id = f"round-{target_round}-planning"
    if connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone():
        return task_id
    directions = "\n".join(
        f"- {item}" for item in synthesis.get("nextRoundDirections", []) if str(item).strip()
    )
    fresh_ideas = "\n".join(
        f"- {item}" for item in synthesis.get("freshIdeas", []) if str(item).strip()
    )
    packet = root / "tasks" / f"dynamic-{task_id}.md"
    packet.write_text(
        f"""# Plan and launch research round {target_round}

Previous synthesis: `{synthesis_task['task_id']}`
Coordinator: `{coordinator_worker}`

## Required next-round directions

{directions}

## Fresh ideas retained by synthesis

{fresh_ideas}

Build a new round plan with at least three genuinely incompatible semantic
families. Preserve viable routes, redirect falsified mechanisms only when a new
mechanism exists, and allocate fresh routes to underexplored boundaries. Do not
complete this task merely by writing a plan: invoke `round-plan` and verify that
round {target_round}'s development, adversarial, and root-synthesis tasks exist.
Submit `nextRoundPlanning` with the retained plan path and launched task IDs.
"No findings" is not permission to return without launching this round.
""",
        encoding="utf-8",
    )
    insert_dynamic_task(
        connection,
        task_id=task_id,
        wave=int(synthesis_task["wave"]) + 1,
        lane="root-next-round-planning",
        title=f"Plan and launch research round {target_round}",
        packet=packet.relative_to(root).as_posix(),
        priority=3100,
        dependencies=[str(synthesis_task["task_id"])],
        excluded_workers=[],
        max_attempts=max(2, int(synthesis_task["max_attempts"])),
        timeout_seconds=int(synthesis_task["timeout_seconds"]),
        approach_families=["chain-composition"],
        research_round=from_round,
        task_kind="next-round-planning",
    )
    record_event(
        connection,
        "next-round-planning-scheduled",
        task_id=task_id,
        worker_id=coordinator_worker,
        payload={
            "fromRound": from_round,
            "targetRound": target_round,
            "directions": synthesis.get("nextRoundDirections", []),
        },
    )
    return task_id


def root_blocking_dependencies(
    connection: sqlite3.Connection, row: sqlite3.Row, seen: set[str] | None = None
) -> set[str]:
    seen = set() if seen is None else seen
    task_id = str(row["task_id"])
    if task_id in seen:
        return {task_id}
    seen.add(task_id)
    if row["state"] in ("failed", "timed-out", "cancelled"):
        return {task_id}
    if row["state"] == "blocked" and row["last_error"] != "dependency ended unsuccessfully":
        return {task_id}
    roots: set[str] = set()
    for dependency in task_dependencies(row):
        dependency_row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (dependency,)
        ).fetchone()
        if dependency_row is None or dependency_row["state"] == "completed":
            continue
        roots.update(root_blocking_dependencies(connection, dependency_row, seen))
    return roots or {task_id}


def schedule_automatic_unblock(
    connection: sqlite3.Connection,
    root: Path,
    blocked: sqlite3.Row,
    blocker: dict[str, Any],
    originator_worker: str,
) -> str | None:
    authority = str(blocker.get("authorityRequired") or "").strip().lower()
    if blocker.get("canSelfResolve") is not True or authority not in {
        "none",
        "no",
        "not required",
    }:
        return None
    existing = connection.execute(
        "SELECT COUNT(*) AS count FROM tasks WHERE unblocks_task_id=?",
        (blocked["task_id"],),
    ).fetchone()["count"]
    task_id = f"unblock-{blocked['task_id']}-{existing + 1}"
    experiments: list[str] = []
    for field in ("bypassHypotheses", "alternativeRoutes", "nextExperiments"):
        for value in blocker.get(field, []):
            text = str(value).strip()
            if text and text not in experiments:
                experiments.append(text)
    experiment_list = "\n".join(f"- {item}" for item in experiments)
    evidence_list = "\n".join(f"- `{item}`" for item in blocker.get("evidence", []))
    packet = root / "tasks" / f"dynamic-{task_id}.md"
    packet.write_text(
        f"""# Automatic blocker breakout: {blocked['task_id']}

Blocked task: `{blocked['task_id']}`
Blocked chain link: {blocker['blockedLink']}
Guard or failure mechanism: {blocker['guardOrFailure']}
Why the current path is blocked: {blocker['whyBlocked']}
Cheapest discriminator: {blocker['cheapestDiscriminator']}

## Retained evidence

{evidence_list}

## Source-derived bypass and alternate-route hypotheses

{experiment_list}

Do not merely replay the failed input. Explain which assumption or guard blocks
the chain, derive the smallest safe experiment that can distinguish the listed
hypotheses, and pursue an alternative route to the same Critical/RCE boundary
when the original path is genuinely closed. Add new focused tasks when the
evidence branches. Return to the pinned, unmodified supported build for the
security claim after diagnostic instrumentation.

Completion requires the normal `taskResult` plus an `unblock` object for
`{blocked['task_id']}`. `unblock.newMechanism` must provide a fingerprint that
differs from `{blocker['mechanismFingerprint']}`, explain the semantic change,
and retain enabling evidence. New wording or another input for the same
mechanism does not reopen the route. If this experiment exposes another
technical blocker, submit a new structured blocker; Krineon will continue the
breakout loop.

Never bypass authorization, access third-party data, disable an essential
production security boundary merely to manufacture impact, or evade campaign
budgets and safety stop conditions. Resolve only technical chain blockers in
the authorized source tree and disposable environment. Do not use changelogs,
advisories, Git history, patched versions, or internet patch diffs.
""",
        encoding="utf-8",
    )
    dependencies: list[str] = []
    for dependency in task_dependencies(blocked):
        state = connection.execute(
            "SELECT state FROM tasks WHERE task_id=?", (dependency,)
        ).fetchone()
        if state is not None and state["state"] == "completed":
            dependencies.append(dependency)
    insert_dynamic_task(
        connection,
        task_id=task_id,
        wave=int(blocked["wave"]),
        lane="automatic-blocker-breakout",
        title=f"Break out of blocker in {blocked['task_id']}",
        packet=packet.relative_to(root).as_posix(),
        priority=max(2000, int(blocked["priority"]) + 1),
        dependencies=dependencies,
        excluded_workers=[originator_worker],
        max_attempts=max(2, int(blocked["max_attempts"])),
        timeout_seconds=int(blocked["timeout_seconds"]),
        approach_families=list(
            dict.fromkeys(
                task_approach_families(connection, str(blocked["task_id"]))
                + ["blocker-alternative-route"]
            )
        ),
        unblocks_task_id=str(blocked["task_id"]),
    )
    record_event(
        connection,
        "automatic-unblock-scheduled",
        task_id=task_id,
        payload={
            "blockedTaskId": blocked["task_id"],
            "blockedLink": blocker["blockedLink"],
            "guardOrFailure": blocker["guardOrFailure"],
            "originatingWorkerExcluded": originator_worker,
        },
    )
    return task_id


def cmd_schedule_unblock(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    if args.max_attempts < 1 or args.timeout_seconds < 1:
        raise SystemExit("attempts and timeout must be positive")
    connection = connect_orchestration(root)
    try:
        with connection:
            blocked = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (args.blocked_task_id,)
            ).fetchone()
            if blocked is None:
                raise SystemExit(f"unknown blocked task: {args.blocked_task_id}")
            if blocked["state"] not in ("blocked", "failed", "timed-out"):
                raise SystemExit(
                    f"task must be blocked, failed, or timed-out; current state is {blocked['state']}"
                )
            if (
                blocked["state"] == "blocked"
                and blocked["last_error"] == "dependency ended unsuccessfully"
            ):
                roots = sorted(root_blocking_dependencies(connection, blocked))
                raise SystemExit(
                    "task is only transitively blocked; schedule one unblock task for each "
                    f"root blocker instead: {', '.join(roots)}"
                )
            existing = connection.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE unblocks_task_id=?",
                (args.blocked_task_id,),
            ).fetchone()["count"]
            task_id = args.task_id or f"unblock-{args.blocked_task_id}-{existing + 1}"
            submission = latest_task_submission(connection, args.blocked_task_id)
            blocker_result = submission["result_path"] if submission else "not recorded"
            packet = root / "tasks" / f"dynamic-{task_id}.md"
            packet.write_text(
                f"""# Unblock task: {args.blocked_task_id}

Blocked task: `{args.blocked_task_id}`
Recorded blocker result: `{blocker_result}`

## Working hypothesis

{args.strategy}

## Success criterion

{args.success_criterion}

Inspect the recorded blocker evidence first. Determine whether the stop came
from a missing tool, build artifact, unsupported assumption, nondeterminism,
coverage gap, inaccessible state transition, environment mismatch, or a real
falsification. Test the smallest safe experiment that distinguishes those
possibilities. Explore alternative routes to the same security boundary when
the original mechanism is disproved.

Completion requires a JSON `unblock` object containing the original
`blockedTaskId`, `blockerAddressed: true`, retained `evidence`, and a concrete
`resumeStrategy`, plus `newMechanism` with a new fingerprint, semantic
difference, and enabling evidence. A renamed or lightly varied copy of the
blocked mechanism cannot resume it. If the blocker survives, submit this task
as blocked with a new structured blocker object, first-principles provenance,
and next experiments.

Stay within the Critical/RCE chain mission. Resolve the blocker from the pinned
source and exact-revision runtime only; do not use changelogs, advisories, Git
history, patched-version comparisons, or internet-derived patch diffs.
""",
                encoding="utf-8",
            )
            dependencies = []
            for dependency in task_dependencies(blocked):
                state = connection.execute(
                    "SELECT state FROM tasks WHERE task_id=?", (dependency,)
                ).fetchone()
                if state is not None and state["state"] == "completed":
                    dependencies.append(dependency)
            insert_dynamic_task(
                connection,
                task_id=task_id,
                wave=int(blocked["wave"]),
                lane="unblock",
                title=f"Unblock {args.blocked_task_id}: {args.title}",
                packet=packet.relative_to(root).as_posix(),
                priority=args.priority,
                dependencies=dependencies,
                excluded_workers=args.exclude_worker or [],
                max_attempts=args.max_attempts,
                timeout_seconds=args.timeout_seconds,
                approach_families=list(
                    dict.fromkeys(
                        task_approach_families(connection, args.blocked_task_id)
                        + ["blocker-alternative-route"]
                    )
                ),
                unblocks_task_id=args.blocked_task_id,
            )
            record_event(
                connection,
                "unblock-task-scheduled",
                task_id=task_id,
                payload={
                    "blockedTaskId": args.blocked_task_id,
                    "strategy": args.strategy,
                    "successCriterion": args.success_criterion,
                },
            )
        print(f"scheduled {task_id} to unblock {args.blocked_task_id}")
        return 0
    finally:
        connection.close()


def update_finding_from_submission(
    root: Path,
    connection: sqlite3.Connection,
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
        originator_worker = connection.execute(
            "SELECT agent FROM workers WHERE worker_id=?", (originator,)
        ).fetchone()
        reviewer_worker = connection.execute(
            "SELECT agent FROM workers WHERE worker_id=?", (worker_id,)
        ).fetchone()
        if originator_worker is None or reviewer_worker is None:
            raise SystemExit("originator and reviewer must be registered workers")
        if originator_worker["agent"] == reviewer_worker["agent"]:
            raise SystemExit("independent replay requires a different agent identity")
        prior_reviewer_agents = {
            str(item.get("reviewerAgent") or "").strip()
            for item in finding.get("independentReplays", [])
            if isinstance(item, dict) and item.get("passed") is True
        }
        if reviewer_worker["agent"] in prior_reviewer_agents:
            raise SystemExit(
                "double sanity replay requires a reviewer agent not used by an earlier replay"
            )
        replay_record = result.get("independentReplay")
        if not isinstance(replay_record, dict) or replay_record.get("passed") is not True:
            raise SystemExit("replay result must contain independentReplay.passed=true")
        if replay_record.get("findingId") != finding_id:
            raise SystemExit("replay result findingId does not match --replay-of")
        if replay_record.get("originator") != originator:
            raise SystemExit("replay result originator does not match finding record")
        if replay_record.get("reviewer") != worker_id:
            raise SystemExit("replay result reviewer does not match submitting worker")
        attestation_reference = replay_record.get("attestation")
        if not isinstance(attestation_reference, dict):
            raise SystemExit("independent replay requires a machine attestation")
        try:
            attestation_path = safe_campaign_path(root, attestation_reference.get("path"))
        except ValueError as error:
            raise SystemExit(f"independent replay attestation path is invalid: {error}") from error
        attestation_result = validate_attestation(
            root,
            attestation_path,
            expected_finding_id=finding_id,
            expected_worker_id=worker_id,
            expected_role="reviewer",
        )
        if attestation_reference.get("sha256") != attestation_result.get(
            "attestationSha256"
        ):
            attestation_result["errors"].append("attestation reference hash mismatch")
            attestation_result["passed"] = False
        if not attestation_result["passed"]:
            raise SystemExit(
                "independent replay machine attestation failed: "
                + ", ".join(attestation_result["errors"])
            )
        proof_contract = finding_origin_attestation_contract(root, finding)
        if proof_contract is None:
            raise SystemExit(
                "independent replay requires a passing originator attestation in the path proof"
            )
        if (
            attestation_result["record"]["recipe"]["sha256"]
            != proof_contract["recipeSha256"]
        ):
            raise SystemExit("independent replay recipe differs from the path proof")
        if attestation_result["targetHashes"] != proof_contract["targetHashes"]:
            raise SystemExit("independent replay targets differ from the path proof")
        if set(attestation_result["challengeHashes"]) & set(
            proof_contract["challengeHashes"]
        ):
            raise SystemExit("independent replay reused the originator's challenge")
        if set(attestation_result["processIds"]) & set(proof_contract["processIds"]):
            raise SystemExit("independent replay reused the originator's process identity")
        for prior in finding.get("independentReplays", []):
            if not isinstance(prior, dict) or prior.get("passed") is not True:
                continue
            if set(prior.get("challengeHashes", [])) & set(
                attestation_result["challengeHashes"]
            ):
                raise SystemExit("independent replay reused an earlier challenge")
            if set(prior.get("processIds", [])) & set(attestation_result["processIds"]):
                raise SystemExit("independent replay reused an earlier process identity")
            if prior.get("recipeSha256") != attestation_result["record"]["recipe"]["sha256"]:
                raise SystemExit("independent replay did not execute the same recipe")
            if prior.get("targetHashes") != attestation_result["targetHashes"]:
                raise SystemExit("independent replay did not execute the same target artifacts")
        record = {
            "taskId": task_id,
            "originator": originator,
            "originatorAgent": originator_worker["agent"],
            "reviewer": worker_id,
            "reviewerAgent": reviewer_worker["agent"],
            "result": result_path,
            "sha256": digest,
            "submittedAt": utc_now(),
            "passed": True,
            "attestation": attestation_path.relative_to(root).as_posix(),
            "attestationSha256": attestation_result["attestationSha256"],
            "attestationRunId": attestation_result["record"]["runId"],
            "recipeSha256": attestation_result["record"]["recipe"]["sha256"],
            "targetHashes": attestation_result["targetHashes"],
            "challengeHashes": attestation_result["challengeHashes"],
            "processIds": attestation_result["processIds"],
        }
        replays = finding.setdefault("independentReplays", [])
        if not any(item.get("sha256") == digest for item in replays):
            replays.append(record)
        reviewers = finding.setdefault("reviewers", [])
        if worker_id not in reviewers:
            reviewers.append(worker_id)
        distinct_reviewer_agents = {
            str(item.get("reviewerAgent") or "").strip()
            for item in replays
            if isinstance(item, dict) and item.get("passed") is True
        }
        distinct_reviewer_agents.discard("")
        finding.setdefault("gates", {})["independent_replay"] = (
            len(distinct_reviewer_agents) >= 2
        )
    else:
        originator = str(finding.get("originator") or "").strip()
        if originator and originator != worker_id:
            reviewers = finding.setdefault("reviewers", [])
            if worker_id not in reviewers:
                reviewers.append(worker_id)
        else:
            finding["originator"] = worker_id
    write_json(path, finding)


def validate_replay_scheduler_result(root: Path, result: dict[str, Any]) -> None:
    task_result = result.get("taskResult")
    findings = task_result.get("replayFindings") if isinstance(task_result, dict) else None
    if not isinstance(findings, list) or not findings:
        raise SystemExit(
            "replay-scheduler completion requires taskResult.replayFindings"
        )
    for finding_id in findings:
        value = str(finding_id).strip()
        if not value:
            raise SystemExit("taskResult.replayFindings contains an empty finding ID")
        finding = read_json(finding_path(root, value))
        if not replay_is_machine_verified(root, finding):
            raise SystemExit(
                f"finding {value} has no accepted machine-verifiable independent replay"
            )


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
        blocker = validate_blocker_result(result) if args.outcome == "blocked" else None
        failure = validate_failed_result(result) if args.outcome == "failed" else None
        replay_of = args.replay_of or (
            task["finding_id"] if task["lane"] == "independent-replay" else None
        )
        if args.replay_of and task["lane"] != "independent-replay":
            raise SystemExit("--replay-of is valid only for an independent-replay task")
        if replay_of and task["finding_id"] != replay_of:
            raise SystemExit("replay finding must match the leased replay task")
        if args.finding_id and replay_of and args.finding_id != replay_of:
            raise SystemExit("--finding-id and --replay-of must not conflict")
        finding_id = replay_of or args.finding_id
        validated_leads: list[dict[str, Any]] = []
        coordinator_replay: dict[str, Any] | None = None
        if args.outcome == "completed":
            validated_leads = validate_completed_result(
                root, result, str(task["task_id"])
            )
            if task["task_kind"] == "route-development":
                validate_route_development_result(
                    result, str(task["route_id"]), int(task["research_round"])
                )
            elif task["task_kind"] == "adversarial-route-review":
                validate_adversarial_route_result(
                    result,
                    str(task["reviews_task_id"]),
                    str(task["route_id"]),
                    int(task["research_round"]),
                )
            elif task["task_kind"] == "root-round-synthesis":
                validate_round_synthesis_result(
                    result, int(task["research_round"]), connection
                )
            elif task["task_kind"] == "intermediate-chain-composition":
                validate_intermediate_chain_result(result)
            elif task["task_kind"] == "next-round-planning":
                validate_next_round_planning_result(
                    connection, result, int(task["research_round"])
                )
            if task["unblocks_task_id"]:
                validate_unblock_result(
                    root,
                    connection,
                    result,
                    str(task["unblocks_task_id"]),
                )
            if task["lane"] in {
                "finding-scoped-replay-scheduler",
                "v8-finding-scoped-replay-scheduler",
            }:
                validate_replay_scheduler_result(root, result)
            coordinator_replay = coordinator_reexecute_result(
                root, result, str(task["task_id"]), validated_leads
            )
        result_dir = root / "results" / task["task_id"]
        result_dir.mkdir(parents=True, exist_ok=True)
        result_name = f"attempt-{task['attempt']}-{digest[:16]}.json"
        result_target = result_dir / result_name
        if result_target.exists() and sha256(result_target) != digest:
            raise SystemExit(f"result path collision: {result_target}")
        if not result_target.exists():
            shutil.copy2(result_source, result_target)
        relative_result = result_target.relative_to(root).as_posix()
        if finding_id and args.outcome == "completed":
            update_finding_from_submission(
                root,
                connection,
                finding_id,
                args.worker_id,
                args.task_id,
                digest,
                relative_result,
                result,
                replay=bool(replay_of),
            )
        ingested_leads = (
            ingest_research_leads(
                root,
                connection,
                task=task,
                worker_id=args.worker_id,
                leads=validated_leads,
            )
            if args.outcome == "completed" and validated_leads
            else []
        )
        next_state = {
            "completed": "completed",
            "failed": "failed",
            "blocked": "blocked",
        }[args.outcome]
        last_error = (
            str(blocker["reason"])
            if blocker is not None
            else (str(failure["reason"]) if failure is not None else None)
        )
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
            "UPDATE tasks SET state=?,completed_at=?,result_digest=?,lease_token=NULL,"
            "lease_expires_at=NULL,last_error=?,updated_at=? WHERE task_id=?",
            (next_state, utc_now(), digest, last_error, utc_now(), args.task_id),
        )
        automatic_unblock = None
        if blocker is not None:
            automatic_unblock = schedule_automatic_unblock(
                connection, root, task, blocker, args.worker_id
            )
        intermediate_chain_task = None
        if (
            args.outcome == "completed"
            and task["task_kind"] == "adversarial-route-review"
        ):
            intermediate_chain_task = schedule_intermediate_chain_task(
                root, connection, task, result, args.worker_id
            )
        next_round_planning_task = None
        if args.outcome == "completed" and task["task_kind"] == "root-round-synthesis":
            next_round_planning_task = schedule_next_round_planning_task(
                root, connection, task, result, args.worker_id
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
                "automaticUnblockTask": automatic_unblock,
                "intermediateChainTask": intermediate_chain_task,
                "nextRoundPlanningTask": next_round_planning_task,
                "researchLeads": ingested_leads,
                "coordinatorReplay": coordinator_replay,
            },
        )
        if task["unblocks_task_id"] and args.outcome == "completed":
            blocked_task_id = str(task["unblocks_task_id"])
            blocked_task = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (blocked_task_id,)
            ).fetchone()
            if blocked_task and blocked_task["state"] in ("blocked", "failed", "timed-out"):
                max_attempts = max(
                    int(blocked_task["max_attempts"]), int(blocked_task["attempt"]) + 1
                )
                connection.execute(
                    "UPDATE tasks SET state='queued',max_attempts=?,lease_owner=NULL,"
                    "lease_token=NULL,lease_expires_at=NULL,completed_at=NULL,last_error=NULL,"
                    "result_digest=NULL,updated_at=? WHERE task_id=?",
                    (max_attempts, utc_now(), blocked_task_id),
                )
                record_event(
                    connection,
                    "task-unblocked",
                    task_id=blocked_task_id,
                    worker_id=args.worker_id,
                    payload={"unblockTaskId": args.task_id, "result": relative_result},
                )
                revive_dependency_blocks(connection)
        write_approach_family_snapshot(root, connection)
        connection.commit()
        print(f"accepted {args.outcome} result: {relative_result}")
        if automatic_unblock:
            print(f"scheduled automatic blocker breakout: {automatic_unblock}")
        if intermediate_chain_task:
            print(f"scheduled intermediate-bug chain task: {intermediate_chain_task}")
        if next_round_planning_task:
            print(f"scheduled next-round planning task: {next_round_planning_task}")
        for lead in ingested_leads:
            print(
                f"retained research lead {lead['leadId']} ({lead['evidenceGrade']}); "
                f"next task: {lead['scheduledTask'] or 'none'}"
            )
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
            originator_worker = connection.execute(
                "SELECT agent FROM workers WHERE worker_id=?", (originator,)
            ).fetchone()
            if originator_worker is None:
                raise SystemExit("finding originator must be a registered worker")
            aliases = [
                row["worker_id"]
                for row in connection.execute(
                    "SELECT worker_id FROM workers WHERE agent=?",
                    (originator_worker["agent"],),
                ).fetchall()
            ]
            prior_reviewer_agents = {
                str(item.get("reviewerAgent") or "").strip()
                for item in finding.get("independentReplays", [])
                if isinstance(item, dict) and item.get("passed") is True
            }
            prior_reviewer_agents.discard("")
            prior_reviewer_aliases = [
                row["worker_id"]
                for agent in sorted(prior_reviewer_agents)
                for row in connection.execute(
                    "SELECT worker_id FROM workers WHERE agent=?", (agent,)
                ).fetchall()
            ]
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
Assigned reviewer must be a different registered agent identity, not an alias
of the originating runtime.

Reproduce from the pinned campaign revision without using private originator
state. Run the retained recipe through `scripts/reality_runner.py` as this
reviewer so baseline, negative, and positive controls execute in distinct fresh
processes with new harness-generated challenges. Submit a JSON result whose
`independentReplay` object contains `findingId`, `originator`, `reviewer`,
`passed: true`, and the machine attestation path plus SHA-256. Prose, copied
originator output, screenshots, or `passed: true` without a recomputable
attestation are rejected.

Replay the source-derived Critical/RCE chain as submitted. Do not mine
changelogs, advisories, Git history, patched versions, or internet patch diffs
for missing links.
""",
                encoding="utf-8",
            )
            now = utc_now()
            connection.execute(
                "INSERT INTO tasks(task_id,wave,lane,title,packet,state,priority,depends_json,"
                "excluded_workers_json,excluded_agents_json,finding_id,max_attempts,"
                "timeout_seconds,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?,?,?)",
                (
                    task_id,
                    3,
                    "independent-replay",
                    f"Independent replay for {args.finding_id}",
                    packet.relative_to(root).as_posix(),
                    2000,
                    json.dumps(args.depends_on or []),
                    json.dumps(sorted(set(aliases + prior_reviewer_aliases))),
                    json.dumps(
                        sorted({originator_worker["agent"], *prior_reviewer_agents})
                    ),
                    args.finding_id,
                    args.max_attempts,
                    args.timeout_seconds,
                    now,
                    now,
                ),
            )
            set_task_approach_families(
                connection, task_id, ["validation-replay"]
            )
            record_event(
                connection,
                "replay-scheduled",
                task_id=task_id,
                payload={
                    "findingId": args.finding_id,
                    "excludedOriginator": originator,
                    "excludedAgent": originator_worker["agent"],
                    "excludedWorkerAliases": sorted(set(aliases)),
                    "excludedPriorReviewerAgents": sorted(prior_reviewer_agents),
                },
            )
        print(
            f"scheduled {task_id}; excluded originator agent "
            f"{originator_worker['agent']} ({', '.join(sorted(set(aliases)))})"
        )
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
            write_approach_family_snapshot(root, connection)
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
            if row["state"] == "blocked":
                raise SystemExit(
                    "blocked tasks cannot be retried directly; use schedule-unblock and "
                    "submit evidence for a genuinely new mechanism fingerprint"
                )
            if row["state"] not in ("failed", "timed-out", "cancelled"):
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
            write_approach_family_snapshot(root, connection)
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
            write_approach_family_snapshot(root, connection)
        print(json.dumps(result, indent=2) if args.json else ", ".join(f"{k}={v}" for k, v in result.items()))
        return 0
    finally:
        connection.close()


def orchestration_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    task_rows = connection.execute("SELECT * FROM tasks ORDER BY wave,task_id").fetchall()
    tasks = [dict(row) for row in task_rows]
    workers = [dict(row) for row in connection.execute("SELECT * FROM workers ORDER BY worker_id")]
    counts: dict[str, int] = {}
    for task in tasks:
        counts[task["state"]] = counts.get(task["state"], 0) + 1
        task["dependsOn"] = json.loads(task.pop("depends_json"))
        task["excludedWorkers"] = json.loads(task.pop("excluded_workers_json"))
        task["excludedAgents"] = json.loads(task.pop("excluded_agents_json"))
        task["approachFamilies"] = task_approach_families(
            connection, str(task["task_id"])
        )
        task.pop("lease_token", None)
    configured, resolved = resolve_concurrency_limit(connection)
    running = counts.get("running", 0)
    ready_rows = [
        row
        for row in task_rows
        if row["state"] == "queued" and dependency_state(connection, row) == "ready"
    ]
    active_workers_by_agent: dict[str, set[str]] = {}
    for worker in workers:
        if worker["status"] == "active":
            active_workers_by_agent.setdefault(worker["agent"], set()).add(
                worker["worker_id"]
            )
    running_agents = {
        row["agent"]
        for row in connection.execute(
            "SELECT DISTINCT workers.agent FROM tasks "
            "JOIN workers ON workers.worker_id=tasks.lease_owner "
            "WHERE tasks.state='running'"
        ).fetchall()
    }
    idle_agents = sorted(set(active_workers_by_agent).difference(running_agents))

    def agent_can_claim(agent: str, row: sqlite3.Row) -> bool:
        if agent in set(json.loads(row["excluded_agents_json"])):
            return False
        excluded_workers = set(json.loads(row["excluded_workers_json"]))
        for worker_id in active_workers_by_agent[agent].difference(excluded_workers):
            worker_row = connection.execute(
                "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
            ).fetchone()
            if worker_row is not None and worker_is_eligible_for_round_task(
                connection, worker_row, row
            ):
                return True
        return False

    matched_task_to_agent: dict[int, str] = {}

    def match_agent(agent: str, seen_tasks: set[int]) -> bool:
        for index, row in enumerate(ready_rows):
            if index in seen_tasks or not agent_can_claim(agent, row):
                continue
            seen_tasks.add(index)
            current = matched_task_to_agent.get(index)
            if current is None or match_agent(current, seen_tasks):
                matched_task_to_agent[index] = agent
                return True
        return False

    for agent in idle_agents:
        match_agent(agent, set())
    claimable_by_active = len(matched_task_to_agent)
    available_slots = max(0, resolved - running)
    recommended_claims = min(available_slots, claimable_by_active)
    unmatched_ready = max(0, len(ready_rows) - claimable_by_active)
    can_expand = configured == "auto" or running + recommended_claims < int(configured)
    return {
        "metadata": {
            row["key"]: json.loads(row["value"])
            for row in connection.execute("SELECT key,value FROM metadata ORDER BY key")
        },
        "taskCounts": counts,
        "schedulerDemand": {
            "configuredConcurrency": configured,
            "resolvedConcurrency": resolved,
            "activeAgentIdentities": active_agent_count(connection),
            "running": running,
            "availableSlots": available_slots,
            "runnableTasks": len(ready_rows),
            "claimableByActiveAgents": claimable_by_active,
            "recommendedClaims": recommended_claims,
            "scaleOutOpportunity": unmatched_ready > 0 and can_expand,
            "hardCapReached": configured != "auto" and running >= int(configured),
        },
        "workers": workers,
        "tasks": tasks,
        "approachRegistry": approach_family_snapshot(connection),
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
        demand = snapshot["schedulerDemand"]
        print(
            "scheduler: "
            f"configured={demand['configuredConcurrency']} "
            f"resolved={demand['resolvedConcurrency']} "
            f"running={demand['running']} runnable={demand['runnableTasks']} "
            f"recommended-claims={demand['recommendedClaims']}"
        )
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


def cmd_approach_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    connection = connect_orchestration(root)
    try:
        snapshot = approach_family_snapshot(connection)
        write_approach_family_snapshot(root, connection)
        if args.json:
            print(json.dumps(snapshot, indent=2))
            return 0
        print(
            "converged: "
            + (", ".join(snapshot["convergedFamilies"]) or "none")
        )
        print(
            "underexplored: "
            + (", ".join(snapshot["underexploredFamilies"]) or "none")
        )
        print()
        print(f"{'FAMILY':<32} {'ACTIVE':>6} {'EXPLORED':>8} {'LOAD':>5}  MECHANISM")
        print("-" * 110)
        for family in snapshot["families"]:
            print(
                f"{family['id']:<32} {family['activeAgents']:>6} "
                f"{family['exploredTasks']:>8} {family['coverageLoad']:>5}  "
                f"{family['mechanism']}"
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


def finding_origin_attestation_contract(
    root: Path, finding: dict[str, Any]
) -> dict[str, Any] | None:
    finding_id = str(finding.get("id") or "").strip()
    originator = str(finding.get("originator") or "").strip()
    path_proof = finding.get("pathProof")
    if not finding_id or not originator or not isinstance(path_proof, dict):
        return None
    expected = f"evidence/path-proofs/{finding_id}.json"
    if path_proof.get("path") != expected:
        return None
    proof_path = root / expected
    if not proof_path.is_file():
        return None
    try:
        proof = read_json(proof_path)
        review = proof.get("review") if isinstance(proof.get("review"), dict) else {}
        reference = review.get("originatorAttestation")
        if not isinstance(reference, dict):
            return None
        attestation_path = safe_campaign_path(root, reference.get("path"))
        result = validate_attestation(
            root,
            attestation_path,
            expected_finding_id=finding_id,
            expected_worker_id=originator,
            expected_role="originator",
        )
        if (
            not result["passed"]
            or reference.get("sha256") != result.get("attestationSha256")
        ):
            return None
        return {
            "recipeSha256": result["record"]["recipe"]["sha256"],
            "targetHashes": result["targetHashes"],
            "challengeHashes": result["challengeHashes"],
            "processIds": result["processIds"],
        }
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def replay_is_machine_verified(root: Path, finding: dict[str, Any]) -> bool:
    originator = str(finding.get("originator") or "").strip()
    finding_id = str(finding.get("id") or "").strip()
    replays = finding.get("independentReplays")
    if not originator or not finding_id or not isinstance(replays, list):
        return False
    proof_contract = finding_origin_attestation_contract(root, finding)
    if proof_contract is None:
        return False
    database = orchestration_path(root)
    if not database.is_file():
        return False
    connection = connect_orchestration(root)
    try:
        originator_worker = connection.execute(
            "SELECT * FROM workers WHERE worker_id=?", (originator,)
        ).fetchone()
        if originator_worker is None:
            return False
        verified_reviewer_agents: set[str] = set()
        seen_challenges = set(proof_contract["challengeHashes"])
        seen_processes = set(proof_contract["processIds"])
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
            attestation_name = str(replay.get("attestation") or "").strip()
            if not attestation_name:
                continue
            try:
                attestation_path = safe_campaign_path(root, attestation_name)
            except ValueError:
                continue
            attestation_result = validate_attestation(
                root,
                attestation_path,
                expected_finding_id=finding_id,
                expected_worker_id=reviewer,
                expected_role="reviewer",
            )
            if (
                not attestation_result["passed"]
                or replay.get("attestationSha256")
                != attestation_result.get("attestationSha256")
                or replay.get("recipeSha256")
                != attestation_result["record"].get("recipe", {}).get("sha256")
                or replay.get("targetHashes") != attestation_result.get("targetHashes")
                or replay.get("challengeHashes") != attestation_result.get("challengeHashes")
                or replay.get("processIds") != attestation_result.get("processIds")
                or replay.get("recipeSha256") != proof_contract["recipeSha256"]
                or replay.get("targetHashes") != proof_contract["targetHashes"]
            ):
                continue
            if seen_challenges & set(attestation_result["challengeHashes"]):
                continue
            if seen_processes & set(attestation_result["processIds"]):
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
            if worker["agent"] == originator_worker["agent"]:
                continue
            if (
                task["state"] != "completed"
                or task["lane"] != "independent-replay"
                or task["finding_id"] != finding_id
                or originator not in set(json.loads(task["excluded_workers_json"]))
                or originator_worker["agent"]
                not in set(json.loads(task["excluded_agents_json"]))
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
                and isinstance(payload.get("attestation"), dict)
                and payload["attestation"].get("path") == attestation_name
                and payload["attestation"].get("sha256")
                == attestation_result.get("attestationSha256")
            ):
                verified_reviewer_agents.add(str(worker["agent"]))
                seen_challenges.update(attestation_result["challengeHashes"])
                seen_processes.update(attestation_result["processIds"])
        return len(verified_reviewer_agents) >= 2
    finally:
        connection.close()


def gate_result(
    finding: dict[str, Any],
    level: str,
    *,
    replay_verified: bool = False,
    campaign_root_path: Path | None = None,
) -> dict[str, Any]:
    required_gates = CANDIDATE_GATES if level == "candidate" else REPORTABLE_GATES
    gates = finding.get("gates", {})
    missing_gates = [name for name in required_gates if gates.get(name) is not True]
    missing_fields: list[str] = []
    for field in ("rootCause", "impact"):
        if not str(finding.get(field, "")).strip():
            missing_fields.append(field)
    impact_class = str(finding.get("impactClass") or "").strip()
    if impact_class not in {"rce", "program-defined-critical"}:
        missing_fields.append("impactClass:rce-or-program-defined-critical")
    if impact_class == "program-defined-critical" and not str(
        finding.get("criticalScopeRule") or ""
    ).strip():
        missing_fields.append("criticalScopeRule")
    for field in ("preconditions", "evidence"):
        value = finding.get(field)
        if not isinstance(value, list) or not value:
            missing_fields.append(field)
    chain = finding.get("chain")
    if not isinstance(chain, dict):
        missing_fields.append("chain")
    else:
        for field in (
            "attacker",
            "ingress",
            "attackerControl",
            "brokenInvariant",
            "primitive",
            "executionOrCriticalSink",
            "terminal",
            "remoteAcquisition",
            "deployment",
        ):
            if not str(chain.get(field) or "").strip():
                missing_fields.append(f"chain.{field}")
        transformations = chain.get("transformations")
        if not isinstance(transformations, list) or not any(
            str(item).strip() for item in transformations
        ):
            missing_fields.append("chain.transformations")
        if chain.get("applicationAuthoredSink") is not False:
            missing_fields.append("chain.applicationAuthoredSink:false")
    terminal_evidence = finding.get("terminalEvidence")
    if not isinstance(terminal_evidence, dict):
        missing_fields.append("terminalEvidence")
    else:
        if str(terminal_evidence.get("type") or "") not in {
            "bounded-command-execution",
            "program-defined-critical-effect",
        }:
            missing_fields.append("terminalEvidence.type")
        if not str(terminal_evidence.get("commandOrEffect") or "").strip():
            missing_fields.append("terminalEvidence.commandOrEffect")
        if terminal_evidence.get("synthetic") is not False:
            missing_fields.append("terminalEvidence.synthetic:false")
    environment = finding.get("executionEnvironment")
    if not isinstance(environment, dict):
        missing_fields.append("executionEnvironment")
    else:
        environment_class = str(environment.get("environmentClass") or "").strip()
        if environment_class not in {
            "production-equivalent",
            "release-build",
            "supported-production",
        }:
            missing_fields.append(
                "executionEnvironment.environmentClass:production-or-release-equivalent"
            )
        if environment.get("developmentServer") is not False:
            missing_fields.append("executionEnvironment.developmentServer:false")
        if environment.get("developmentBuild") is not False:
            missing_fields.append("executionEnvironment.developmentBuild:false")
        if environment.get("supportedConfiguration") is not True:
            missing_fields.append("executionEnvironment.supportedConfiguration:true")
        if environment.get("primaryTerminalObserved") is not True:
            missing_fields.append("executionEnvironment.primaryTerminalObserved:true")
        if not str(environment.get("commandOrEntrypoint") or "").strip():
            missing_fields.append("executionEnvironment.commandOrEntrypoint")
        environment_evidence = environment.get("evidence")
        if not isinstance(environment_evidence, list) or not any(
            str(item).strip() for item in environment_evidence
        ):
            missing_fields.append("executionEnvironment.evidence")
    provenance = finding.get("analysisProvenance")
    if not isinstance(provenance, dict):
        missing_fields.append("analysisProvenance")
    else:
        if provenance.get("firstPrinciplesOnly") is not True:
            missing_fields.append("analysisProvenance.firstPrinciplesOnly:true")
        for field in (
            "changelogUsed",
            "gitHistoryUsed",
            "advisoryMiningUsed",
            "patchedVersionDiffUsed",
            "internetPatchDiffUsed",
        ):
            if provenance.get(field) is not False:
                missing_fields.append(f"analysisProvenance.{field}:false")
    controls = finding.get("controls", {})
    for control in ("baseline", "negative", "positive"):
        if not str(controls.get(control, "")).strip():
            missing_fields.append(f"controls.{control}")
    path_proof_summary: dict[str, Any] = {
        "required": True,
        "passed": False,
        "errors": [],
        "summary": {},
    }
    finding_id = str(finding.get("id") or "")
    expected_path_proof = f"evidence/path-proofs/{finding_id}.json"
    path_proof = finding.get("pathProof")
    if not isinstance(path_proof, dict):
        missing_fields.append("pathProof")
    else:
        if path_proof.get("required") is not True:
            missing_fields.append("pathProof.required:true")
        if path_proof.get("path") != expected_path_proof:
            missing_fields.append("pathProof.path:canonical")
    if campaign_root_path is None:
        missing_fields.append("pathProof.campaignRoot")
    elif isinstance(path_proof, dict) and path_proof.get("path") == expected_path_proof:
        proof_path = campaign_root_path / expected_path_proof
        if not proof_path.is_file():
            missing_fields.append("pathProof.missing")
        else:
            proof_record: dict[str, Any] = {}
            try:
                proof_record = read_json(proof_path)
                proof_audit = validate_path_proof(
                    proof_record,
                    expected_finding_id=finding_id,
                    expected_originator=str(finding.get("originator") or ""),
                    campaign_root=campaign_root_path,
                )
            except (OSError, json.JSONDecodeError, SystemExit) as error:
                proof_audit = {
                    "passed": False,
                    "errors": [f"unreadable:{error}"],
                    "summary": {},
                }
            path_proof_summary.update(proof_audit)
            for error in proof_audit["errors"]:
                missing_fields.append(f"pathProof.{error}")
            if proof_record:
                identity_errors: list[str] = []
                review = proof_record.get("review")
                review = review if isinstance(review, dict) else {}
                originator_id = str(review.get("originator") or "")
                reviewer_id = str(review.get("reviewer") or "")
                database = orchestration_path(campaign_root_path)
                if not database.is_file():
                    identity_errors.append("review.identityRegistry")
                else:
                    connection = connect_orchestration(campaign_root_path)
                    try:
                        originator_worker = connection.execute(
                            "SELECT agent FROM workers WHERE worker_id=?",
                            (originator_id,),
                        ).fetchone()
                        reviewer_worker = connection.execute(
                            "SELECT agent FROM workers WHERE worker_id=?",
                            (reviewer_id,),
                        ).fetchone()
                    finally:
                        connection.close()
                    if originator_worker is None:
                        identity_errors.append("review.originator:unregistered")
                    if reviewer_worker is None:
                        identity_errors.append("review.reviewer:unregistered")
                    if (
                        originator_worker is not None
                        and reviewer_worker is not None
                        and originator_worker["agent"] == reviewer_worker["agent"]
                    ):
                        identity_errors.append("review.agent:must-be-independent")
                if identity_errors:
                    path_proof_summary["passed"] = False
                    path_proof_summary.setdefault("errors", []).extend(identity_errors)
                    for error in identity_errors:
                        missing_fields.append(f"pathProof.{error}")
    triage_summary: dict[str, Any] = {"required": False, "verdicts": []}
    dynamic_triage = finding.get("dynamicTriage")
    if isinstance(dynamic_triage, dict) and (
        dynamic_triage.get("required") is True or dynamic_triage.get("crashIds")
    ):
        triage_summary["required"] = True
        crash_ids = dynamic_triage.get("crashIds")
        if not isinstance(crash_ids, list) or not crash_ids:
            missing_fields.append("dynamicTriage.crashIds")
            crash_ids = []
        if dynamic_triage.get("reviewed") is not True:
            missing_fields.append("dynamicTriage.reviewed:true")
        if not str(dynamic_triage.get("reviewedBy") or "").strip():
            missing_fields.append("dynamicTriage.reviewedBy")
        if not str(dynamic_triage.get("reviewNotes") or "").strip():
            missing_fields.append("dynamicTriage.reviewNotes")
        if dynamic_triage.get("index") != "dynamic/triage/index.json":
            missing_fields.append("dynamicTriage.index:dynamic/triage/index.json")
        accepted_clusters = dynamic_triage.get("acceptedClusterIds")
        if not isinstance(accepted_clusters, list):
            accepted_clusters = []
            missing_fields.append("dynamicTriage.acceptedClusterIds")
        machine_verdicts = dynamic_triage.get("machineVerdicts")
        if not isinstance(machine_verdicts, dict):
            machine_verdicts = {}
            missing_fields.append("dynamicTriage.machineVerdicts")
        if campaign_root_path is None:
            missing_fields.append("dynamicTriage.campaignRoot")
        else:
            index_path = campaign_root_path / "dynamic" / "triage" / "index.json"
            indexed_crashes: dict[str, dict[str, Any]] = {}
            if not index_path.is_file():
                missing_fields.append("dynamicTriage.index:missing")
            else:
                index_record = read_json(index_path)
                index_rows = index_record.get("crashes")
                if isinstance(index_rows, list):
                    indexed_crashes = {
                        str(row.get("crashId")): row
                        for row in index_rows
                        if isinstance(row, dict) and row.get("crashId")
                    }
                else:
                    missing_fields.append("dynamicTriage.index:invalid")
            for crash_id_value in crash_ids:
                crash_id = str(crash_id_value)
                if not re.fullmatch(r"[0-9a-f]{64}", crash_id):
                    missing_fields.append(f"dynamicTriage.crashId:{crash_id}")
                    continue
                triage_path = (
                    campaign_root_path / "dynamic" / "crashes" / crash_id / "triage.json"
                )
                if not triage_path.is_file():
                    missing_fields.append(f"dynamicTriage.missing:{crash_id}")
                    continue
                triage = read_json(triage_path)
                stack = triage.get("stack") if isinstance(triage.get("stack"), dict) else {}
                assessment = (
                    triage.get("automatedExploitability")
                    if isinstance(triage.get("automatedExploitability"), dict)
                    else {}
                )
                verdict_name = str(assessment.get("verdict") or "")
                cluster_id = str(stack.get("clusterId") or "")
                recommendation = str(assessment.get("gateRecommendation") or "")
                triage_summary["verdicts"].append(
                    {
                        "crashId": crash_id,
                        "clusterId": cluster_id,
                        "verdict": verdict_name,
                        "gateRecommendation": recommendation,
                    }
                )
                if triage.get("crashId") != crash_id:
                    missing_fields.append(f"dynamicTriage.identityMismatch:{crash_id}")
                if cluster_id not in set(str(value) for value in accepted_clusters):
                    missing_fields.append(f"dynamicTriage.unacceptedCluster:{cluster_id}")
                if machine_verdicts.get(crash_id) != verdict_name:
                    missing_fields.append(f"dynamicTriage.verdictMismatch:{crash_id}")
                indexed = indexed_crashes.get(crash_id)
                if not indexed:
                    missing_fields.append(f"dynamicTriage.indexMissingCrash:{crash_id}")
                elif (
                    indexed.get("clusterId") != cluster_id
                    or indexed.get("verdict") != verdict_name
                ):
                    missing_fields.append(f"dynamicTriage.indexMismatch:{crash_id}")
                if assessment.get("machinePromotionEligible") is not False:
                    missing_fields.append(f"dynamicTriage.unsafeMachinePromotion:{crash_id}")
                if recommendation == "requires-primitive-verification":
                    missing_fields.append(
                        f"dynamicTriage.unverifiedPrimitive:{crash_id}"
                    )
                if recommendation == "reject-crash-only" and not str(
                    dynamic_triage.get("overrideReason") or ""
                ).strip():
                    missing_fields.append("dynamicTriage.overrideReason:crash-only")
    browser_replay_summary: dict[str, Any] = {"required": False, "replays": []}
    browser_replay = finding.get("browserReplay")
    if isinstance(browser_replay, dict) and (
        browser_replay.get("required") is True or browser_replay.get("replayIds")
    ):
        browser_replay_summary["required"] = True
        replay_ids = browser_replay.get("replayIds")
        if not isinstance(replay_ids, list) or not replay_ids:
            missing_fields.append("browserReplay.replayIds")
            replay_ids = []
        if browser_replay.get("reviewed") is not True:
            missing_fields.append("browserReplay.reviewed:true")
        if not str(browser_replay.get("reviewedBy") or "").strip():
            missing_fields.append("browserReplay.reviewedBy")
        if not str(browser_replay.get("reviewNotes") or "").strip():
            missing_fields.append("browserReplay.reviewNotes")
        if campaign_root_path is None:
            missing_fields.append("browserReplay.campaignRoot")
        else:
            for replay_id_value in replay_ids:
                replay_id = str(replay_id_value)
                if not re.fullmatch(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{10}", replay_id):
                    missing_fields.append(f"browserReplay.replayId:{replay_id}")
                    continue
                replay_path = (
                    campaign_root_path
                    / "chrome-v8"
                    / "browser-replays"
                    / replay_id
                    / "replay.json"
                )
                if not replay_path.is_file():
                    missing_fields.append(f"browserReplay.missing:{replay_id}")
                    continue
                replay = read_json(replay_path)
                summary = replay.get("summary") if isinstance(replay.get("summary"), dict) else {}
                build = replay.get("build") if isinstance(replay.get("build"), dict) else {}
                cases = replay.get("cases") if isinstance(replay.get("cases"), dict) else {}
                positive = cases.get("positive") if isinstance(cases.get("positive"), dict) else {}
                control = cases.get("control") if isinstance(cases.get("control"), dict) else {}
                browser_replay_summary["replays"].append(
                    {
                        "replayId": replay_id,
                        "promotionReady": summary.get("promotionReady"),
                        "sandboxVerified": summary.get("sandboxVerified"),
                        "positiveMatched": summary.get("positiveMatched"),
                        "controlMatched": summary.get("controlMatched"),
                    }
                )
                if replay.get("replayId") != replay_id:
                    missing_fields.append(f"browserReplay.identityMismatch:{replay_id}")
                if replay.get("driver") != "direct-cdp":
                    missing_fields.append(f"browserReplay.driver:{replay_id}")
                if replay.get("status") != "completed":
                    missing_fields.append(f"browserReplay.status:{replay_id}")
                if replay.get("ownedLocalOrigin") is not True:
                    missing_fields.append(f"browserReplay.ownedOrigin:{replay_id}")
                if build.get("kind") != "chrome" or build.get("role") != "sandboxed-chrome":
                    missing_fields.append(f"browserReplay.build:{replay_id}")
                site = replay.get("site") if isinstance(replay.get("site"), dict) else {}
                if not isinstance(site.get("files"), list) or not site.get("files"):
                    missing_fields.append(f"browserReplay.siteManifest:{replay_id}")
                for case_name, case in (("positive", positive), ("control", control)):
                    prefix = f"browserReplay.{case_name}:{replay_id}"
                    if not case:
                        missing_fields.append(prefix)
                        continue
                    if case.get("status") != "completed":
                        missing_fields.append(prefix + ":status")
                    if case.get("freshProcess") is not True:
                        missing_fields.append(prefix + ":freshProcess")
                    if case.get("profileDisposable") is not True:
                        missing_fields.append(prefix + ":disposableProfile")
                    if case.get("finalUrlOwned") is not True:
                        missing_fields.append(prefix + ":finalUrlOwned")
                    if case.get("expressionMatched") is not True:
                        missing_fields.append(prefix + ":expressionMatched")
                    sandbox = case.get("sandbox") if isinstance(case.get("sandbox"), dict) else {}
                    if sandbox.get("verified") is not True:
                        missing_fields.append(prefix + ":sandboxVerified")
                    if case.get("blockedExternalRequests"):
                        missing_fields.append(prefix + ":externalRequestAttempt")
                    if case.get("targetCrashed") is not False:
                        missing_fields.append(prefix + ":targetCrashed")
                if summary.get("promotionReady") is not True:
                    missing_fields.append(f"browserReplay.notPromotionReady:{replay_id}")
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
        "dynamicTriage": triage_summary,
        "browserReplay": browser_replay_summary,
        "pathProof": path_proof_summary,
    }


def cmd_gate(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    finding = read_json(finding_path(root, args.finding_id))
    result = gate_result(
        finding,
        args.level,
        campaign_root_path=root,
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
    for dirname in (
        "evidence",
        "findings",
        "reports",
        "results",
        "dynamic",
        "chrome-v8",
        "benchmarks",
    ):
        base = root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS":
                yield path
    for filename in (
        "campaign.json",
        "registry.json",
        "approach-registry.json",
        "launch-plan.json",
        "AUTHORIZATION.md",
        "PROGRAM_GUIDELINES.md",
        "PROGRAM_SCOPE.md",
        "onboarding.json",
        "third_party/manifest.json",
    ):
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
        relative_parts = path.relative_to(root).parts
        if any(part in excluded for part in relative_parts):
            continue
        if relative_parts[:1] == ("third_party",) and relative_parts != (
            "third_party",
            "manifest.json",
        ):
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
    init.add_argument(
        "--profile",
        choices=PROFILE_NAMES,
        default="critical-rce",
        help="campaign lane and evidence profile",
    )
    init.add_argument("--mode", choices=("source", "local-lab", "testnet", "authorized-live"), default="source")
    init.add_argument("--program-url")
    init.set_defaults(func=cmd_init)

    dependency_add = sub.add_parser(
        "dependency-add",
        help="clone and pin an exact target-used dependency under campaign third_party",
    )
    dependency_add.add_argument("campaign_dir")
    dependency_add.add_argument("name", type=validate_dependency_name)
    dependency_add.add_argument("--repo", required=True)
    dependency_add.add_argument(
        "--commit",
        required=True,
        help="exact dependency tag, object ID, or lock-resolved revision to pin",
    )
    dependency_add.add_argument(
        "--relationship",
        required=True,
        choices=("runtime", "bundled", "native", "build", "optional", "transitive"),
    )
    dependency_add.add_argument(
        "--scope-status",
        choices=("target-in-scope", "dependency-in-scope", "supporting-context"),
        default="supporting-context",
        help="classification only; does not expand program authorization",
    )
    dependency_add.add_argument(
        "--lock-evidence",
        action="append",
        required=True,
        help="pinned-target file/symbol proving this exact dependency is used; repeatable",
    )
    dependency_add.add_argument("--reason", required=True)
    dependency_add.set_defaults(func=cmd_dependency_add)

    dependency_status = sub.add_parser(
        "dependency-status", help="show pinned campaign dependencies and scope classification"
    )
    dependency_status.add_argument("campaign_dir")
    dependency_status.add_argument("--json", action="store_true")
    dependency_status.set_defaults(func=cmd_dependency_status)

    plan = sub.add_parser("plan", help="write wave-based agent task packets")
    plan.add_argument("campaign_dir")
    plan.add_argument("--lane", action="append", help="limit to a lane ID; repeatable")
    plan.add_argument("--max-concurrency", type=parse_max_concurrency, default="auto")
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

    gate_self_test = sub.add_parser(
        "gate-self-test",
        help="prove coordinator re-execution rejects a false worker claim before scale-out",
    )
    gate_self_test.add_argument("campaign_dir")
    gate_self_test.set_defaults(func=cmd_gate_self_test)

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
    submit.add_argument(
        "--outcome",
        choices=("completed", "failed", "blocked"),
        default="completed",
    )
    submit.add_argument("--finding-id", type=validate_finding_id)
    submit.add_argument("--replay-of", type=validate_finding_id)
    submit.set_defaults(func=cmd_submit)

    task_add = sub.add_parser(
        "task-add", help="add a new evidence-driven exploration task at runtime"
    )
    task_add.add_argument("campaign_dir")
    task_add.add_argument("task_id", type=validate_task_id)
    task_add.add_argument("--title", required=True)
    task_add.add_argument("--lane", required=True)
    task_add.add_argument("--objective", required=True)
    task_add.add_argument(
        "--approach-family",
        action="append",
        required=True,
        help="stable semantic family ID from approach-registry.json; repeatable",
    )
    task_add.add_argument("--success-criterion", action="append", required=True)
    task_add.add_argument("--depends-on", action="append")
    task_add.add_argument("--exclude-worker", action="append", type=validate_identity)
    task_add.add_argument("--wave", type=int, default=2)
    task_add.add_argument("--priority", type=int, default=50)
    task_add.add_argument("--max-attempts", type=int, default=2)
    task_add.add_argument("--timeout-seconds", type=int, default=7200)
    task_add.set_defaults(func=cmd_task_add)

    round_plan = sub.add_parser(
        "round-plan",
        help="launch independent route development, adversarial review, and root synthesis",
    )
    round_plan.add_argument("campaign_dir")
    round_plan.add_argument("worker_id", type=validate_identity)
    round_plan.add_argument("--plan", required=True, help="round plan JSON")
    round_plan.set_defaults(func=cmd_round_plan)

    schedule_unblock = sub.add_parser(
        "schedule-unblock", help="schedule a focused task to resolve a recorded blocker"
    )
    schedule_unblock.add_argument("campaign_dir")
    schedule_unblock.add_argument("blocked_task_id", type=validate_task_id)
    schedule_unblock.add_argument("--task-id", type=validate_task_id)
    schedule_unblock.add_argument("--title", required=True)
    schedule_unblock.add_argument("--strategy", required=True)
    schedule_unblock.add_argument("--success-criterion", required=True)
    schedule_unblock.add_argument("--exclude-worker", action="append", type=validate_identity)
    schedule_unblock.add_argument("--priority", type=int, default=2000)
    schedule_unblock.add_argument("--max-attempts", type=int, default=2)
    schedule_unblock.add_argument("--timeout-seconds", type=int, default=7200)
    schedule_unblock.set_defaults(func=cmd_schedule_unblock)

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

    retry = sub.add_parser("retry", help="requeue a failed, timed-out, or cancelled task")
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

    approach_status = sub.add_parser(
        "approach-status",
        help="show semantic approach-family coverage, convergence, and underexplored areas",
    )
    approach_status.add_argument("campaign_dir")
    approach_status.add_argument("--json", action="store_true")
    approach_status.set_defaults(func=cmd_approach_status)

    lead_status = sub.add_parser(
        "lead-status",
        help="rank unique minimized stacks, invariant breaks, and verified primitives",
    )
    lead_status.add_argument("campaign_dir")
    lead_status.add_argument("--json", action="store_true")
    lead_status.set_defaults(func=cmd_lead_status)

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

    hash_cmd = sub.add_parser("hash", help="hash retained findings, evidence, dynamic results, reports, and metadata")
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
