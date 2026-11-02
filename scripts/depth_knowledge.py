#!/usr/bin/env python3
"""Durable discovery-depth knowledge plane for Krineon campaigns.

This module stores searchable worker observations, typed serial attack-chain
plans, worker continuation checkpoints, global semantic assets, coverage, and
lossless cold-graph digests.  It never executes a target or promotes a finding.
The coordinator remains responsible for experiment execution and evidence
gates.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from .chain_reasoning import (
        capability_match,
        context_match,
        normalize_capability,
        normalize_context,
    )
except ImportError:
    from chain_reasoning import (
        capability_match,
        context_match,
        normalize_capability,
        normalize_context,
    )


ORCHESTRATION_DB = "orchestration.db"
OBSERVATION_STATES = {"active", "promoted", "refuted", "superseded", "compacted"}
CHAIN_STATES = {"active", "completed", "refuted", "paused"}
STEP_STATES = {"pending", "ready", "running", "satisfied", "refuted", "blocked"}
COVERAGE_STATES = {"untested", "hypothesized", "tested", "refuted", "verified"}
CONFIDENCE_RANK = {
    "hypothesized": 0,
    "source-supported": 1,
    "observed": 2,
    "runtime-observed": 3,
    "coordinator-replayed": 4,
    "independently-replayed": 5,
}
CONNECTION_STAGE_RANK = {
    "incompatible": -1,
    "hypothetical": 0,
    "compatible": 1,
    "runtime-observed": 2,
    "independently-verified": 3,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(prefix: str, *values: Any) -> str:
    digest = hashlib.sha256(canonical(values).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"{field} is required")
    return result


def string_list(value: Any, field: str, *, empty: bool = True) -> list[str]:
    if value is None and empty:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result = [str(item).strip() for item in value if str(item).strip()]
    if not empty and not result:
        raise ValueError(f"{field} must be non-empty")
    return list(dict.fromkeys(result))


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS depth_observations (
          observation_id TEXT PRIMARY KEY,
          semantic_identity TEXT NOT NULL UNIQUE,
          task_id TEXT NOT NULL,
          worker_id TEXT NOT NULL,
          experiment_id TEXT,
          kind TEXT NOT NULL,
          mechanism TEXT NOT NULL,
          summary TEXT NOT NULL,
          confidence TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN (
            'active','promoted','refuted','superseded','compacted'
          )),
          produces_json TEXT NOT NULL,
          requires_json TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          source_refs_json TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          result_path TEXT NOT NULL,
          digest_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depth_chain_plans (
          chain_id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          terminal_capability TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('active','completed','refuted','paused')),
          priority INTEGER NOT NULL,
          origin_task_id TEXT NOT NULL,
          context_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depth_chain_steps (
          chain_id TEXT NOT NULL,
          step_id TEXT NOT NULL,
          ordinal INTEGER NOT NULL,
          title TEXT NOT NULL,
          capability TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN (
            'pending','ready','running','satisfied','refuted','blocked'
          )),
          requires_json TEXT NOT NULL,
          produces_json TEXT NOT NULL,
          objective TEXT NOT NULL,
          success_json TEXT NOT NULL,
          approach_families_json TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          resolution_json TEXT NOT NULL DEFAULT '{}',
          scheduled_task_id TEXT,
          revision INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY(chain_id, step_id),
          FOREIGN KEY(chain_id) REFERENCES depth_chain_plans(chain_id)
        );
        CREATE TABLE IF NOT EXISTS depth_planner_feedback (
          feedback_id TEXT PRIMARY KEY,
          observation_id TEXT,
          chain_id TEXT,
          step_id TEXT,
          action TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('pending','scheduled','processed','suppressed')),
          reason TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          scheduled_task_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depth_worker_continuations (
          task_id TEXT PRIMARY KEY,
          worker_id TEXT NOT NULL,
          session_id TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('active','blocked','exhausted','completed')),
          hypothesis TEXT NOT NULL,
          competing_json TEXT NOT NULL,
          eliminated_json TEXT NOT NULL,
          blocker TEXT NOT NULL,
          next_experiment TEXT NOT NULL,
          artifacts_json TEXT NOT NULL,
          steer_revision INTEGER NOT NULL DEFAULT 0,
          steer_message TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depth_assets (
          asset_id TEXT PRIMARY KEY,
          semantic_key TEXT NOT NULL UNIQUE,
          asset_type TEXT NOT NULL,
          name TEXT NOT NULL,
          context_json TEXT NOT NULL,
          first_task_id TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depth_asset_edges (
          source_asset_id TEXT NOT NULL,
          relation TEXT NOT NULL,
          target_asset_id TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(source_asset_id, relation, target_asset_id)
        );
        CREATE TABLE IF NOT EXISTS depth_observation_assets (
          observation_id TEXT NOT NULL,
          asset_id TEXT NOT NULL,
          role TEXT NOT NULL,
          PRIMARY KEY(observation_id, asset_id, role)
        );
        CREATE TABLE IF NOT EXISTS depth_asset_coverage (
          asset_id TEXT NOT NULL,
          boundary TEXT NOT NULL,
          consumer TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN (
            'untested','hypothesized','tested','refuted','verified'
          )),
          task_id TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY(asset_id, boundary, consumer)
        );
        CREATE TABLE IF NOT EXISTS depth_graph_digests (
          digest_id TEXT PRIMARY KEY,
          mechanism TEXT NOT NULL,
          signature TEXT NOT NULL UNIQUE,
          member_ids_json TEXT NOT NULL,
          asset_ids_json TEXT NOT NULL,
          summary_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS depth_observation_search_idx
          ON depth_observations(state, mechanism, confidence, updated_at);
        CREATE INDEX IF NOT EXISTS depth_chain_step_state_idx
          ON depth_chain_steps(state, ordinal, updated_at);
        CREATE INDEX IF NOT EXISTS depth_feedback_state_idx
          ON depth_planner_feedback(state, created_at);
        CREATE INDEX IF NOT EXISTS depth_asset_type_idx
          ON depth_assets(asset_type, name);
        CREATE INDEX IF NOT EXISTS depth_coverage_state_idx
          ON depth_asset_coverage(state, boundary, consumer);
        """
    )
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(depth_chain_steps)").fetchall()
    }
    if "resolution_json" not in columns:
        connection.execute(
            "ALTER TABLE depth_chain_steps ADD COLUMN resolution_json TEXT NOT NULL DEFAULT '{}'"
        )


def _safe_evidence(root: Path, values: list[str]) -> list[str]:
    result: list[str] = []
    for raw in values:
        candidate = (root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
        try:
            relative = candidate.relative_to(root)
        except ValueError as error:
            raise ValueError(f"evidence path escapes campaign: {raw}") from error
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"evidence file is missing or unsafe: {raw}")
        result.append(relative.as_posix())
    return list(dict.fromkeys(result))


def _normalize_capabilities(value: Any, field: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    rows: list[Any] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            rows.append(text(item, f"{field}[{index}]"))
            continue
        if not isinstance(item, dict):
            raise ValueError(f"{field}[{index}] must be text or a typed capability")
        try:
            rows.append(
                normalize_capability(
                    item,
                    f"{field}[{index}]",
                    require_binding=True,
                )
            )
        except RuntimeError as exc:
            raise ValueError(str(exc)) from exc
    unique = {canonical(item): item for item in rows}
    return [unique[key] for key in sorted(unique)]


def normalize_observation(
    root: Path,
    raw: dict[str, Any],
    *,
    task_id: str,
    worker_id: str,
    result_path: str,
    maximum_confidence: str = "runtime-observed",
) -> dict[str, Any]:
    kind = text(raw.get("kind") or "observation", "observation.kind")
    mechanism = text(
        raw.get("mechanism") or raw.get("mechanismFingerprint") or kind,
        "observation.mechanism",
    )
    summary = text(raw.get("summary") or raw.get("title"), "observation.summary")
    confidence = str(raw.get("confidence") or "hypothesized").strip()
    if confidence not in CONFIDENCE_RANK:
        raise ValueError(f"unsupported observation confidence: {confidence}")
    if maximum_confidence not in CONFIDENCE_RANK:
        raise ValueError(f"unsupported maximum observation confidence: {maximum_confidence}")
    if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[maximum_confidence]:
        confidence = maximum_confidence
    state = str(raw.get("state") or "active").strip()
    if state not in OBSERVATION_STATES:
        raise ValueError(f"unsupported observation state: {state}")
    evidence = _safe_evidence(
        root, string_list(raw.get("evidence", []), "observation.evidence")
    )
    source_refs = string_list(
        raw.get("sourceReferences", []), "observation.sourceReferences"
    )
    produces = _normalize_capabilities(
        raw.get("producesCapabilities", []), "observation.producesCapabilities"
    )
    requires = _normalize_capabilities(
        raw.get("requiresCapabilities", []), "observation.requiresCapabilities"
    )
    experiment_id = str(raw.get("experimentId") or "").strip()
    semantic = str(raw.get("semanticIdentity") or "").strip() or stable_id(
        "OBS-S",
        mechanism,
        summary,
        produces,
        requires,
        source_refs,
    )
    observation_id = str(raw.get("id") or "").strip() or stable_id(
        "OBS", semantic, task_id, experiment_id
    )
    return {
        "id": observation_id,
        "semanticIdentity": semantic,
        "taskId": task_id,
        "workerId": worker_id,
        "experimentId": experiment_id,
        "kind": kind,
        "mechanism": mechanism,
        "summary": summary,
        "confidence": confidence,
        "state": state,
        "producesCapabilities": produces,
        "requiresCapabilities": requires,
        "evidence": evidence,
        "sourceReferences": source_refs,
        "assetRefs": raw.get("assetRefs", []),
        "coverage": raw.get("coverage", []),
        "context": raw.get("context") if isinstance(raw.get("context"), dict) else {},
        "payload": raw,
        "resultPath": result_path,
    }


def lead_observation(lead: dict[str, Any]) -> dict[str, Any]:
    capability = lead.get("capabilityModel") if isinstance(lead.get("capabilityModel"), dict) else {}
    produces = []
    for value in capability.get("produces", []):
        if isinstance(value, dict) and value.get("type"):
            produces.append(str(value["type"]))
    requires = []
    for value in capability.get("requires", []):
        if isinstance(value, dict) and value.get("type"):
            requires.append(str(value["type"]))
    grade = str(lead.get("evidenceGrade") or lead.get("chainMaturity") or "")
    confidence = (
        "coordinator-replayed"
        if grade in {"verified-primitive", "minimized-stack"}
        else "runtime-observed"
        if grade in {"runtime-observation", "runtime-invariant"}
        else "source-supported"
    )
    return {
        "kind": str(lead.get("kind") or "research-lead"),
        "mechanism": str(lead.get("mechanismFingerprint") or lead.get("kind") or "lead"),
        "summary": str(lead.get("title") or "retained research lead"),
        "confidence": confidence,
        "state": "refuted" if lead.get("status") in {"refuted", "disproved"} else "active",
        "producesCapabilities": produces,
        "requiresCapabilities": requires,
        "sourceReferences": list(lead.get("sourceReferences") or []),
        "evidence": list(lead.get("evidence") or []),
        "semanticIdentity": lead.get("semanticIdentity"),
        "payload": lead,
    }


def upsert_asset(
    connection: sqlite3.Connection,
    *,
    task_id: str,
    asset_type: str,
    name: str,
    context: dict[str, Any] | None = None,
) -> str:
    semantic_key = stable_id("ASSET-S", asset_type, name, context or {})
    asset_id = stable_id("ASSET", semantic_key)
    now = utc_now()
    connection.execute(
        "INSERT INTO depth_assets(asset_id,semantic_key,asset_type,name,context_json,"
        "first_task_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(semantic_key) DO UPDATE SET updated_at=excluded.updated_at",
        (asset_id, semantic_key, asset_type, name, canonical(context or {}), task_id, now, now),
    )
    row = connection.execute(
        "SELECT asset_id FROM depth_assets WHERE semantic_key=?", (semantic_key,)
    ).fetchone()
    return str(row["asset_id"] if isinstance(row, sqlite3.Row) else row[0])


def _ingest_asset_refs(
    connection: sqlite3.Connection,
    observation: dict[str, Any],
) -> list[str]:
    asset_ids: list[str] = []
    for raw in observation.get("assetRefs", []):
        if not isinstance(raw, dict):
            continue
        asset_type = str(raw.get("type") or "unknown").strip()
        name = str(raw.get("name") or raw.get("symbol") or "").strip()
        if not name:
            continue
        asset_id = upsert_asset(
            connection,
            task_id=observation["taskId"],
            asset_type=asset_type,
            name=name,
            context=raw.get("context") if isinstance(raw.get("context"), dict) else {},
        )
        asset_ids.append(asset_id)
        connection.execute(
            "INSERT OR IGNORE INTO depth_observation_assets(observation_id,asset_id,role) "
            "VALUES(?,?,?)",
            (observation["id"], asset_id, str(raw.get("role") or "examined")),
        )
        parent = raw.get("parent")
        if isinstance(parent, dict) and parent.get("name"):
            parent_id = upsert_asset(
                connection,
                task_id=observation["taskId"],
                asset_type=str(parent.get("type") or "unknown"),
                name=str(parent["name"]),
                context=parent.get("context") if isinstance(parent.get("context"), dict) else {},
            )
            connection.execute(
                "INSERT OR IGNORE INTO depth_asset_edges(source_asset_id,relation,target_asset_id,"
                "evidence_json,created_at) VALUES(?,?,?,?,?)",
                (parent_id, str(raw.get("relation") or "contains"), asset_id, canonical(observation["evidence"]), utc_now()),
            )
    for raw in observation.get("coverage", []):
        if not isinstance(raw, dict):
            continue
        asset_id = str(raw.get("assetId") or (asset_ids[0] if len(asset_ids) == 1 else ""))
        if not asset_id:
            continue
        state = str(raw.get("state") or "hypothesized")
        if state not in COVERAGE_STATES:
            raise ValueError(f"unsupported coverage state: {state}")
        connection.execute(
            "INSERT INTO depth_asset_coverage(asset_id,boundary,consumer,state,task_id,evidence_json,updated_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(asset_id,boundary,consumer) DO UPDATE SET "
            "state=excluded.state,task_id=excluded.task_id,evidence_json=excluded.evidence_json,updated_at=excluded.updated_at",
            (
                asset_id,
                text(raw.get("boundary"), "coverage.boundary"),
                text(raw.get("consumer"), "coverage.consumer"),
                state,
                observation["taskId"],
                canonical(observation["evidence"]),
                utc_now(),
            ),
        )
    return asset_ids


def ingest_observation(connection: sqlite3.Connection, observation: dict[str, Any]) -> str:
    now = utc_now()
    existing = connection.execute(
        "SELECT observation_id,confidence,state FROM depth_observations WHERE semantic_identity=?",
        (observation["semanticIdentity"],),
    ).fetchone()
    if existing is not None:
        current_confidence = str(existing["confidence"])
        selected_confidence = (
            observation["confidence"]
            if CONFIDENCE_RANK[observation["confidence"]] >= CONFIDENCE_RANK.get(current_confidence, -1)
            else current_confidence
        )
        selected_state = observation["state"] if observation["state"] != "active" else str(existing["state"])
        observation_id = str(existing["observation_id"])
        connection.execute(
            "UPDATE depth_observations SET task_id=?,worker_id=?,experiment_id=?,kind=?,mechanism=?,summary=?,"
            "confidence=?,state=?,produces_json=?,requires_json=?,evidence_json=?,source_refs_json=?,payload_json=?,"
            "result_path=?,updated_at=? WHERE observation_id=?",
            (
                observation["taskId"], observation["workerId"], observation["experimentId"],
                observation["kind"], observation["mechanism"], observation["summary"],
                selected_confidence, selected_state, canonical(observation["producesCapabilities"]),
                canonical(observation["requiresCapabilities"]), canonical(observation["evidence"]),
                canonical(observation["sourceReferences"]), canonical(observation["payload"]),
                observation["resultPath"], now, observation_id,
            ),
        )
        observation["id"] = observation_id
    else:
        connection.execute(
            "INSERT INTO depth_observations(observation_id,semantic_identity,task_id,worker_id,experiment_id,"
            "kind,mechanism,summary,confidence,state,produces_json,requires_json,evidence_json,source_refs_json,"
            "payload_json,result_path,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation["id"], observation["semanticIdentity"], observation["taskId"],
                observation["workerId"], observation["experimentId"], observation["kind"],
                observation["mechanism"], observation["summary"], observation["confidence"],
                observation["state"], canonical(observation["producesCapabilities"]),
                canonical(observation["requiresCapabilities"]), canonical(observation["evidence"]),
                canonical(observation["sourceReferences"]), canonical(observation["payload"]),
                observation["resultPath"], now, now,
            ),
        )
    _ingest_asset_refs(connection, observation)
    return observation["id"]


def _normalize_chain(root: Path, raw: dict[str, Any], origin_task_id: str) -> dict[str, Any]:
    title = text(raw.get("title"), "attackChainTodo.title")
    terminal = text(raw.get("terminalCapability"), "attackChainTodo.terminalCapability")
    chain_id = str(raw.get("id") or "").strip() or stable_id("CHAIN", title, terminal)
    state = str(raw.get("state") or "active")
    if state not in CHAIN_STATES:
        raise ValueError(f"unsupported chain state: {state}")
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("attackChainTodo.steps must be non-empty")
    normalized_steps = []
    step_contexts: dict[str, dict[str, Any]] = {}
    for ordinal, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ValueError("attackChainTodo steps must be objects")
        capability = text(step.get("capability"), "attackChainTodo.step.capability")
        step_id = str(step.get("id") or "").strip() or stable_id("STEP", chain_id, ordinal, capability)
        step_state = str(step.get("state") or "pending")
        if step_state not in STEP_STATES:
            raise ValueError(f"unsupported chain step state: {step_state}")
        if step_state in {"ready", "running", "satisfied"}:
            raise ValueError(
                "worker submissions cannot assert ready, running, or satisfied chain steps"
            )
        normalized_steps.append(
            {
                "id": step_id,
                "ordinal": ordinal,
                "title": text(step.get("title") or capability, "attackChainTodo.step.title"),
                "capability": capability,
                "state": step_state,
                "requires": _normalize_capabilities(step.get("requires", []), "attackChainTodo.step.requires"),
                "produces": _normalize_capabilities(step.get("produces", [capability]), "attackChainTodo.step.produces"),
                "objective": text(step.get("objective") or f"Establish {capability}", "attackChainTodo.step.objective"),
                "successCriteria": string_list(step.get("successCriteria", []), "attackChainTodo.step.successCriteria", empty=False),
                "approachFamilies": string_list(step.get("approachFamilies", ["chain-composition"]), "attackChainTodo.step.approachFamilies", empty=False),
                "evidence": _safe_evidence(
                    root,
                    string_list(step.get("evidence", []), "attackChainTodo.step.evidence"),
                ),
            }
        )
        step_contexts[step_id] = (
            step.get("context") if isinstance(step.get("context"), dict) else {}
        )
    chain_context = raw.get("context") if isinstance(raw.get("context"), dict) else {}
    chain_context = {**chain_context, "stepContexts": step_contexts}
    return {
        "id": chain_id,
        "title": title,
        "terminalCapability": terminal,
        "state": state,
        "priority": int(raw.get("priority") or 1000),
        "originTaskId": origin_task_id,
        "context": chain_context,
        "steps": normalized_steps,
    }


def upsert_chain(connection: sqlite3.Connection, chain: dict[str, Any]) -> None:
    now = utc_now()
    connection.execute(
        "INSERT INTO depth_chain_plans(chain_id,title,terminal_capability,state,priority,origin_task_id,"
        "context_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id) DO UPDATE SET "
        "title=excluded.title,terminal_capability=excluded.terminal_capability,state=excluded.state,"
        "priority=excluded.priority,context_json=excluded.context_json,updated_at=excluded.updated_at",
        (
            chain["id"], chain["title"], chain["terminalCapability"], chain["state"],
            chain["priority"], chain["originTaskId"], canonical(chain["context"]), now, now,
        ),
    )
    for step in chain["steps"]:
        connection.execute(
            "INSERT INTO depth_chain_steps(chain_id,step_id,ordinal,title,capability,state,requires_json,"
            "produces_json,objective,success_json,approach_families_json,evidence_json,resolution_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id,step_id) DO UPDATE SET "
            "ordinal=excluded.ordinal,title=excluded.title,capability=excluded.capability,"
            "requires_json=excluded.requires_json,produces_json=excluded.produces_json,objective=excluded.objective,"
            "success_json=excluded.success_json,approach_families_json=excluded.approach_families_json,"
            "evidence_json=excluded.evidence_json,resolution_json=excluded.resolution_json,"
            "revision=depth_chain_steps.revision+1,updated_at=excluded.updated_at",
            (
                chain["id"], step["id"], step["ordinal"], step["title"], step["capability"],
                step["state"], canonical(step["requires"]), canonical(step["produces"]),
                step["objective"], canonical(step["successCriteria"]),
                canonical(step["approachFamilies"]), canonical(step["evidence"]),
                canonical({"status": "hypothetical", "connections": []}), now, now,
            ),
        )


def _all_produced(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    produced: list[dict[str, Any]] = []
    rows = connection.execute(
        "SELECT observation_id,produces_json,evidence_json,payload_json,confidence "
        "FROM depth_observations WHERE state IN ('active','promoted')"
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
        for capability in json.loads(row["produces_json"]):
            produced.append(
                {
                    "observationId": str(row["observation_id"]),
                    "capability": capability,
                    "confidence": str(row["confidence"]),
                    "context": context,
                    "evidence": json.loads(row["evidence_json"]),
                }
            )
    return produced


def _capability_type(value: Any) -> str:
    return str(value.get("type") or "") if isinstance(value, dict) else str(value)


def _confidence_stage(confidence: str) -> str:
    if confidence == "independently-replayed":
        return "independently-verified"
    if confidence in {"observed", "runtime-observed", "coordinator-replayed"}:
        return "runtime-observed"
    if confidence == "source-supported":
        return "compatible"
    return "hypothetical"


def _context_resolution(
    produced: dict[str, Any], required: dict[str, Any]
) -> tuple[str, list[str]]:
    meaningful = {
        key: value
        for key, value in required.items()
        if key != "stepContexts"
        and not isinstance(value, (dict, list))
        and value not in {None, "", "any", "unknown"}
    }
    mismatches: list[str] = []
    missing: list[str] = []
    for key, expected in meaningful.items():
        actual = produced.get(key)
        if actual in {None, "", "any", "unknown"}:
            missing.append(key)
        elif str(actual) != str(expected):
            mismatches.append(f"{key}:{actual!s}!={expected!s}")
    if mismatches:
        return "incompatible", mismatches
    if missing:
        return "hypothetical", [f"missing-context:{key}" for key in missing]

    # Use the main chain engine's context contract for its canonical fields.
    canonical_fields = (
        "principal", "actorSession", "tenant", "process", "namespace",
        "runtime", "origin", "cacheLayer", "observationEpoch",
    )
    if any(key in produced or key in required for key in canonical_fields):
        producer_context = {key: str(produced.get(key) or "any") for key in canonical_fields}
        consumer_context = {key: str(required.get(key) or "any") for key in canonical_fields}
        try:
            status, reasons = context_match(
                {"context": normalize_context(producer_context, "producer")},
                {"context": normalize_context(consumer_context, "consumer")},
            )
        except RuntimeError as exc:
            return "hypothetical", [str(exc)]
        if status == "impossible":
            return "incompatible", reasons
        if status == "unknown":
            return "hypothetical", reasons
    return "compatible", []


def _resolve_capability(
    requirement: Any,
    produced: list[dict[str, Any]],
    required_context: dict[str, Any],
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in produced:
        capability = row["capability"]
        if _capability_type(capability) != _capability_type(requirement):
            continue
        match_status = "compatible"
        reasons: list[str] = []
        if isinstance(requirement, dict) and isinstance(capability, dict):
            matched, reason = capability_match(capability, requirement)
            if not matched:
                match_status = "incompatible"
                reasons.append(reason)
        elif isinstance(requirement, dict) != isinstance(capability, dict):
            match_status = "hypothetical"
            reasons.append("typed-capability-binding-missing")
        context_status, context_reasons = _context_resolution(
            row.get("context", {}), required_context
        )
        if "incompatible" in {match_status, context_status}:
            stage = "incompatible"
        elif "hypothetical" in {match_status, context_status}:
            stage = "hypothetical"
        else:
            stage = _confidence_stage(row["confidence"])
        candidates.append(
            {
                "status": stage,
                "observationId": row["observationId"],
                "confidence": row["confidence"],
                "evidence": row["evidence"],
                "reasons": [*reasons, *context_reasons],
            }
        )
    if not candidates:
        return {
            "capability": _capability_type(requirement),
            "status": "hypothetical",
            "observationId": None,
            "evidence": [],
            "reasons": ["no-producer"],
        }
    best = max(
        candidates,
        key=lambda item: (
            CONNECTION_STAGE_RANK[item["status"]],
            CONFIDENCE_RANK.get(item["confidence"], -1),
        ),
    )
    return {"capability": _capability_type(requirement), **best}


def _resolve_set(
    requirements: list[Any],
    produced: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        _resolve_capability(requirement, produced, context)
        for requirement in requirements
    ]


def evaluate_chains(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    produced = _all_produced(connection)
    actions: list[dict[str, Any]] = []
    chains = connection.execute(
        "SELECT * FROM depth_chain_plans WHERE state='active' ORDER BY priority DESC,created_at"
    ).fetchall()
    now = utc_now()
    for chain in chains:
        chain_context = json.loads(chain["context_json"])
        step_contexts = chain_context.get("stepContexts", {})
        base_context = {
            key: value for key, value in chain_context.items() if key != "stepContexts"
        }
        steps = connection.execute(
            "SELECT * FROM depth_chain_steps WHERE chain_id=? ORDER BY ordinal,step_id",
            (chain["chain_id"],),
        ).fetchall()
        for step in steps:
            state = str(step["state"])
            if state == "refuted":
                continue
            requirements = json.loads(step["requires_json"])
            outputs = json.loads(step["produces_json"])
            required_context = {
                **base_context,
                **(
                    step_contexts.get(str(step["step_id"]), {})
                    if isinstance(step_contexts, dict)
                    and isinstance(step_contexts.get(str(step["step_id"]), {}), dict)
                    else {}
                ),
            }
            output_resolution = _resolve_set(outputs, produced, required_context)
            requirement_resolution = _resolve_set(
                requirements, produced, required_context
            )
            resolution = {
                "status": min(
                    (
                        item["status"]
                        for item in [*requirement_resolution, *output_resolution]
                    ),
                    key=lambda value: CONNECTION_STAGE_RANK[value],
                    default="hypothetical",
                ),
                "requirements": requirement_resolution,
                "outputs": output_resolution,
                "context": required_context,
            }
            connection.execute(
                "UPDATE depth_chain_steps SET resolution_json=?,updated_at=? "
                "WHERE chain_id=? AND step_id=?",
                (canonical(resolution), now, chain["chain_id"], step["step_id"]),
            )
            outputs_observed = bool(output_resolution) and all(
                CONNECTION_STAGE_RANK[item["status"]]
                >= CONNECTION_STAGE_RANK["runtime-observed"]
                for item in output_resolution
            )
            requirements_observed = all(
                CONNECTION_STAGE_RANK[item["status"]]
                >= CONNECTION_STAGE_RANK["runtime-observed"]
                for item in requirement_resolution
            )
            if outputs_observed:
                ev = sorted(
                    {
                        evidence
                        for item in output_resolution
                        for evidence in item.get("evidence", [])
                    }
                )
                connection.execute(
                    "UPDATE depth_chain_steps SET state='satisfied',evidence_json=?,resolution_json=?,updated_at=? "
                    "WHERE chain_id=? AND step_id=?",
                    (canonical(ev), canonical(resolution), now, chain["chain_id"], step["step_id"]),
                )
                continue
            if requirements_observed:
                next_state = "running" if step["scheduled_task_id"] else "ready"
                connection.execute(
                    "UPDATE depth_chain_steps SET state=?,updated_at=? WHERE chain_id=? AND step_id=?",
                    (next_state, now, chain["chain_id"], step["step_id"]),
                )
                if not step["scheduled_task_id"]:
                    feedback_id = stable_id("FDBK", chain["chain_id"], step["step_id"], int(step["revision"]))
                    action = {
                        "feedbackId": feedback_id,
                        "chainId": str(chain["chain_id"]),
                        "stepId": str(step["step_id"]),
                        "title": str(step["title"]),
                        "objective": str(step["objective"]),
                        "successCriteria": json.loads(step["success_json"]),
                        "approachFamilies": json.loads(step["approach_families_json"]),
                        "requires": sorted(_capability_type(item) for item in requirements),
                        "produces": sorted(_capability_type(item) for item in outputs),
                        "capabilityResolution": resolution,
                        "priority": int(chain["priority"]) + max(0, 100 - int(step["ordinal"])),
                    }
                    connection.execute(
                        "INSERT OR IGNORE INTO depth_planner_feedback(feedback_id,chain_id,step_id,action,state,"
                        "reason,payload_json,created_at,updated_at) VALUES(?,?,?,'schedule-experiment','pending',?,?,?,?)",
                        (
                            feedback_id, chain["chain_id"], step["step_id"],
                            "all context-compatible typed prerequisites are runtime-observed; execute the next missing edge",
                            canonical(action), now, now,
                        ),
                    )
                    actions.append(action)
                break
            connection.execute(
                "UPDATE depth_chain_steps SET state='pending',updated_at=? WHERE chain_id=? AND step_id=?",
                (now, chain["chain_id"], step["step_id"]),
            )
            break
        remaining = connection.execute(
            "SELECT COUNT(*) AS n FROM depth_chain_steps WHERE chain_id=? AND state<>'satisfied'",
            (chain["chain_id"],),
        ).fetchone()["n"]
        if int(remaining) == 0:
            connection.execute(
                "UPDATE depth_chain_plans SET state='completed',updated_at=? WHERE chain_id=?",
                (now, chain["chain_id"]),
            )
    return actions


def mark_feedback_scheduled(
    connection: sqlite3.Connection, *, feedback_id: str, task_id: str
) -> None:
    row = connection.execute(
        "SELECT chain_id,step_id FROM depth_planner_feedback WHERE feedback_id=? AND state='pending'",
        (feedback_id,),
    ).fetchone()
    if row is None:
        raise ValueError("planner feedback is not pending")
    now = utc_now()
    connection.execute(
        "UPDATE depth_planner_feedback SET state='scheduled',scheduled_task_id=?,updated_at=? WHERE feedback_id=?",
        (task_id, now, feedback_id),
    )
    connection.execute(
        "UPDATE depth_chain_steps SET state='running',scheduled_task_id=?,updated_at=? "
        "WHERE chain_id=? AND step_id=?",
        (task_id, now, row["chain_id"], row["step_id"]),
    )


def upsert_continuation(
    root: Path,
    connection: sqlite3.Connection,
    *,
    task_id: str,
    worker_id: str,
    raw: dict[str, Any],
) -> None:
    state = str(raw.get("state") or "active")
    if state not in {"active", "blocked", "exhausted", "completed"}:
        raise ValueError(f"unsupported continuation state: {state}")
    connection.execute(
        "INSERT INTO depth_worker_continuations(task_id,worker_id,session_id,state,hypothesis,competing_json,"
        "eliminated_json,blocker,next_experiment,artifacts_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,session_id=excluded.session_id,"
        "state=excluded.state,hypothesis=excluded.hypothesis,competing_json=excluded.competing_json,"
        "eliminated_json=excluded.eliminated_json,blocker=excluded.blocker,next_experiment=excluded.next_experiment,"
        "artifacts_json=excluded.artifacts_json,updated_at=excluded.updated_at",
        (
            task_id, worker_id, str(raw.get("sessionId") or task_id), state,
            str(raw.get("hypothesis") or ""), canonical(string_list(raw.get("competingExplanations", []), "continuation.competingExplanations")),
            canonical(string_list(raw.get("eliminatedMechanisms", []), "continuation.eliminatedMechanisms")),
            str(raw.get("blocker") or ""), str(raw.get("nextExperiment") or ""),
            canonical(
                _safe_evidence(
                    root,
                    string_list(raw.get("artifacts", []), "continuation.artifacts"),
                )
            ),
            utc_now(),
        ),
    )


def continuation_for_task(connection: sqlite3.Connection, task_id: str) -> dict[str, Any] | None:
    ensure_schema(connection)
    row = connection.execute(
        "SELECT * FROM depth_worker_continuations WHERE task_id=?", (task_id,)
    ).fetchone()
    if row is None:
        return None
    return {
        "taskId": row["task_id"], "workerId": row["worker_id"], "sessionId": row["session_id"],
        "state": row["state"], "hypothesis": row["hypothesis"],
        "competingExplanations": json.loads(row["competing_json"]),
        "eliminatedMechanisms": json.loads(row["eliminated_json"]),
        "blocker": row["blocker"], "nextExperiment": row["next_experiment"],
        "artifacts": json.loads(row["artifacts_json"]), "steerRevision": row["steer_revision"],
        "steerMessage": row["steer_message"], "updatedAt": row["updated_at"],
    }


def steer_worker(connection: sqlite3.Connection, task_id: str, message: str) -> int:
    ensure_schema(connection)
    update = connection.execute(
        "UPDATE depth_worker_continuations SET steer_revision=steer_revision+1,steer_message=?,updated_at=? "
        "WHERE task_id=?",
        (text(message, "steer message"), utc_now(), task_id),
    )
    if update.rowcount != 1:
        raise ValueError("task has no continuation checkpoint")
    return int(connection.execute(
        "SELECT steer_revision FROM depth_worker_continuations WHERE task_id=?", (task_id,)
    ).fetchone()["steer_revision"])


def ingest_submission(
    root: Path,
    connection: sqlite3.Connection,
    *,
    task_id: str,
    worker_id: str,
    result_path: str,
    result: dict[str, Any],
    validated_leads: list[dict[str, Any]],
    maximum_confidence: str = "runtime-observed",
) -> dict[str, Any]:
    ensure_schema(connection)
    task_result = result.get("taskResult") if isinstance(result.get("taskResult"), dict) else {}
    raw_observations = list(task_result.get("observations") or [])
    raw_observations.extend(lead_observation(lead) for lead in validated_leads)
    observation_ids: list[str] = []
    for raw in raw_observations:
        if not isinstance(raw, dict):
            raise ValueError("taskResult.observations must contain objects")
        observation = normalize_observation(
            root,
            raw,
            task_id=task_id,
            worker_id=worker_id,
            result_path=result_path,
            maximum_confidence=maximum_confidence,
        )
        observation_ids.append(ingest_observation(connection, observation))
    chain_ids: list[str] = []
    for raw in task_result.get("attackChainTodos") or []:
        if not isinstance(raw, dict):
            raise ValueError("taskResult.attackChainTodos must contain objects")
        chain = _normalize_chain(root, raw, task_id)
        upsert_chain(connection, chain)
        chain_ids.append(chain["id"])
    continuation = task_result.get("workerContinuation")
    if isinstance(continuation, dict):
        upsert_continuation(
            root,
            connection,
            task_id=task_id,
            worker_id=worker_id,
            raw=continuation,
        )
    actions = evaluate_chains(connection)
    return {
        "observations": observation_ids,
        "chains": chain_ids,
        "plannerActions": actions,
    }


def search_observations(
    connection: sqlite3.Connection, query: str, *, limit: int = 50
) -> list[dict[str, Any]]:
    ensure_schema(connection)
    terms = [term.lower() for term in re.findall(r"[A-Za-z0-9_.:/-]+", query) if term]
    where = "state<>'compacted'"
    args: list[Any] = []
    for term in terms:
        where += " AND lower(mechanism||' '||summary||' '||payload_json) LIKE ?"
        args.append(f"%{term}%")
    args.append(max(1, min(limit, 200)))
    rows = connection.execute(
        f"SELECT * FROM depth_observations WHERE {where} ORDER BY "
        "CASE confidence WHEN 'independently-replayed' THEN 5 WHEN 'coordinator-replayed' THEN 4 "
        "WHEN 'runtime-observed' THEN 3 WHEN 'observed' THEN 2 WHEN 'source-supported' THEN 1 ELSE 0 END DESC,"
        "updated_at DESC LIMIT ?",
        args,
    ).fetchall()
    results = [
        {
            "id": row["observation_id"], "taskId": row["task_id"], "workerId": row["worker_id"],
            "kind": row["kind"], "mechanism": row["mechanism"], "summary": row["summary"],
            "confidence": row["confidence"], "state": row["state"],
            "producesCapabilities": json.loads(row["produces_json"]),
            "requiresCapabilities": json.loads(row["requires_json"]),
            "evidence": json.loads(row["evidence_json"]), "updatedAt": row["updated_at"],
        }
        for row in rows
    ]
    remaining = max(0, max(1, min(limit, 200)) - len(results))
    if remaining:
        digest_where = "1=1"
        digest_args: list[Any] = []
        for term in terms:
            digest_where += " AND lower(mechanism||' '||summary_json) LIKE ?"
            digest_args.append(f"%{term}%")
        digest_args.append(remaining)
        for row in connection.execute(
            f"SELECT * FROM depth_graph_digests WHERE {digest_where} "
            "ORDER BY created_at DESC LIMIT ?",
            digest_args,
        ).fetchall():
            summary = json.loads(row["summary_json"])
            results.append(
                {
                    "id": row["digest_id"],
                    "kind": "compacted-observation-digest",
                    "mechanism": row["mechanism"],
                    "summary": f"{summary.get('memberCount', 0)} settled observations",
                    "state": "compacted",
                    "memberCount": summary.get("memberCount", 0),
                    "producesCapabilities": summary.get("capabilities", []),
                    "evidence": summary.get("evidence", []),
                    "losslessExpansion": True,
                    "createdAt": row["created_at"],
                }
            )
    return results


def expand_digest(connection: sqlite3.Connection, digest_id: str) -> dict[str, Any]:
    ensure_schema(connection)
    digest = connection.execute(
        "SELECT * FROM depth_graph_digests WHERE digest_id=?", (digest_id,)
    ).fetchone()
    if digest is None:
        raise ValueError("depth graph digest does not exist")
    member_ids = json.loads(digest["member_ids_json"])
    members: list[dict[str, Any]] = []
    for observation_id in member_ids:
        row = connection.execute(
            "SELECT * FROM depth_observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"depth graph digest member is missing: {observation_id}")
        members.append(
            {
                "id": row["observation_id"],
                "semanticIdentity": row["semantic_identity"],
                "taskId": row["task_id"],
                "workerId": row["worker_id"],
                "kind": row["kind"],
                "mechanism": row["mechanism"],
                "summary": row["summary"],
                "confidence": row["confidence"],
                "state": row["state"],
                "producesCapabilities": json.loads(row["produces_json"]),
                "requiresCapabilities": json.loads(row["requires_json"]),
                "evidence": json.loads(row["evidence_json"]),
                "sourceReferences": json.loads(row["source_refs_json"]),
                "resultPath": row["result_path"],
            }
        )
    return {
        "digestId": digest["digest_id"],
        "mechanism": digest["mechanism"],
        "signature": digest["signature"],
        "assets": json.loads(digest["asset_ids_json"]),
        "summary": json.loads(digest["summary_json"]),
        "members": members,
    }


def compact_graph(connection: sqlite3.Connection, *, minimum: int = 8) -> list[str]:
    """Losslessly fold settled observations into expandable deterministic digests."""

    ensure_schema(connection)
    rows = connection.execute(
        "SELECT * FROM depth_observations WHERE state IN ('refuted','superseded') AND digest_id IS NULL "
        "ORDER BY mechanism,updated_at"
    ).fetchall()
    groups: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(str(row["mechanism"]), []).append(row)
    created: list[str] = []
    for mechanism, members in groups.items():
        if len(members) < minimum:
            continue
        member_ids = [str(row["observation_id"]) for row in members]
        asset_ids = sorted({
            str(asset["asset_id"])
            for member_id in member_ids
            for asset in connection.execute(
                "SELECT asset_id FROM depth_observation_assets WHERE observation_id=?", (member_id,)
            ).fetchall()
        })
        signature = hashlib.sha256(canonical([
            {"id": row["observation_id"], "state": row["state"], "updated": row["updated_at"]}
            for row in members
        ]).encode()).hexdigest()
        digest_id = stable_id("DIGEST", mechanism, signature)
        summary = {
            "mechanism": mechanism,
            "memberCount": len(members),
            "states": sorted({str(row["state"]) for row in members}),
            "capabilities": sorted({cap for row in members for cap in json.loads(row["produces_json"])}),
            "evidence": sorted({path for row in members for path in json.loads(row["evidence_json"])}),
            "losslessExpansion": True,
        }
        connection.execute(
            "INSERT OR IGNORE INTO depth_graph_digests(digest_id,mechanism,signature,member_ids_json,asset_ids_json,"
            "summary_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (digest_id, mechanism, signature, canonical(member_ids), canonical(asset_ids), canonical(summary), utc_now()),
        )
        connection.executemany(
            "UPDATE depth_observations SET state='compacted',digest_id=?,updated_at=? WHERE observation_id=?",
            [(digest_id, utc_now(), member_id) for member_id in member_ids],
        )
        created.append(digest_id)
    return created


def status(connection: sqlite3.Connection) -> dict[str, Any]:
    ensure_schema(connection)
    def counts(table: str, column: str) -> dict[str, int]:
        return {
            str(row[column]): int(row["n"])
            for row in connection.execute(
                f"SELECT {column},COUNT(*) AS n FROM {table} GROUP BY {column}"
            ).fetchall()
        }
    gaps = connection.execute(
        "SELECT a.asset_id,a.asset_type,a.name,c.boundary,c.consumer,c.state FROM depth_assets a "
        "LEFT JOIN depth_asset_coverage c ON c.asset_id=a.asset_id "
        "WHERE c.state IS NULL OR c.state IN ('untested','hypothesized') ORDER BY a.asset_type,a.name LIMIT 100"
    ).fetchall()
    return {
        "observations": counts("depth_observations", "state"),
        "chains": counts("depth_chain_plans", "state"),
        "chainSteps": counts("depth_chain_steps", "state"),
        "plannerFeedback": counts("depth_planner_feedback", "state"),
        "assets": counts("depth_assets", "asset_type"),
        "coverage": counts("depth_asset_coverage", "state"),
        "coverageGaps": [dict(row) for row in gaps],
    }


def connect(campaign: Path) -> sqlite3.Connection:
    path = campaign.resolve() / ORCHESTRATION_DB
    if not path.is_file():
        raise ValueError(f"campaign orchestration database is missing: {path}")
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    ensure_schema(connection)
    return connection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("status")
    show.add_argument("campaign")
    search = sub.add_parser("search")
    search.add_argument("campaign")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)
    compact = sub.add_parser("compact")
    compact.add_argument("campaign")
    compact.add_argument("--minimum", type=int, default=8)
    steer = sub.add_parser("steer")
    steer.add_argument("campaign")
    steer.add_argument("task_id")
    steer.add_argument("message")
    continuation = sub.add_parser("continuation")
    continuation.add_argument("campaign")
    continuation.add_argument("task_id")
    expand = sub.add_parser("expand")
    expand.add_argument("campaign")
    expand.add_argument("digest_id")
    args = parser.parse_args(argv)
    try:
        connection = connect(Path(args.campaign))
        if args.command == "status":
            result: Any = status(connection)
        elif args.command == "search":
            result = search_observations(connection, args.query, limit=args.limit)
        elif args.command == "compact":
            connection.execute("BEGIN IMMEDIATE")
            result = {"digests": compact_graph(connection, minimum=max(2, args.minimum))}
            connection.commit()
        elif args.command == "steer":
            connection.execute("BEGIN IMMEDIATE")
            result = {"steerRevision": steer_worker(connection, args.task_id, args.message)}
            connection.commit()
        elif args.command == "continuation":
            result = continuation_for_task(connection, args.task_id)
        else:
            result = expand_digest(connection, args.digest_id)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        connection.close()
        return 0
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as error:
        print(f"depth knowledge error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
