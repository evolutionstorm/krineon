#!/usr/bin/env python3
"""Bind target traffic to durable web research tasks and diversity policy.

This module deliberately sits below individual HTTP, browser, and MCP
adapters.  A caller cannot avoid the research-family limits by bypassing the
task scheduler and calling an adapter directly.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping


AUTHORIZATION_FAMILY = "web-authorization-isolation"
WEB_RUNTIME_FAMILIES = frozenset(
    {
        AUTHORIZATION_FAMILY,
        "web-workflow-business-logic",
        "web-cache-partition",
        "web-browser-api",
        "web-capability-sharing",
        "web-integration-callback",
        "web-upload-storage-processing",
        "web-async-job-lifecycle",
        "web-protocol-differential",
        "representation-parser",
        "capability-code-loading",
        "ingress-authority",
    }
)
NOVEL_ZERO_DAY_FAMILIES = frozenset(
    {
        "web-workflow-business-logic",
        "web-cache-partition",
        "web-capability-sharing",
        "web-integration-callback",
        "web-upload-storage-processing",
        "web-async-job-lifecycle",
        "web-protocol-differential",
        "representation-parser",
        "capability-code-loading",
    }
)

EXECUTION_PHASES = frozenset({"baseline", "novel", "followup", "replay"})

DEFAULT_RESEARCH_DIVERSITY = {
    "enforceOperationBinding": True,
    "warmupOperations": 4,
    "maximumAuthorizationRequestShare": 0.20,
    "minimumRuntimeFamiliesBeforeClosure": 4,
    "minimumNonAuthorizationFamiliesBeforeClosure": 3,
    "minimumNovelMechanismFamiliesBeforeClosure": 3,
    # Shares apply to the non-cleanup request budget. They prevent initial
    # inventory work from consuming the capacity needed to test, minimize, and
    # independently replay a surviving mechanism.
    "runtimeBudgetAllocation": {
        "baseline": 0.20,
        "novel": 0.55,
        "followup": 0.15,
        "replay": 0.10,
    },
}

SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")


class WebResearchGovernanceError(ValueError):
    """Raised when target traffic is detached from the research frontier."""


def infer_execution_phase(*values: Any) -> str:
    """Derive the budget phase from durable task identity, never worker claims."""

    text = " ".join(str(value or "").lower() for value in values)
    if any(
        token in text
        for token in ("discovery", "inventory", "normal-workflow", "contract", "baseline")
    ):
        return "baseline"
    if any(
        token in text
        for token in ("independent-replay", "replay-", "evidence-finding", "verification")
    ):
        return "replay"
    if any(
        token in text
        for token in ("lead-", "campaign-chain", "controlled-execution", "followup")
    ):
        return "followup"
    return "novel"


def owned_full_testing(contract: Mapping[str, Any]) -> bool:
    authorization = contract.get("authorization")
    return bool(
        isinstance(authorization, Mapping)
        and isinstance(authorization.get("ownedFullTesting"), Mapping)
        and authorization["ownedFullTesting"].get("enabled") is True
    )


def diversity_policy(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return the effective target-operation diversity policy.

    Owned full-testing campaigns fail closed even when they predate the
    explicit ``researchDiversity`` field.  Read-only/offline compatibility
    campaigns remain unaffected unless they opt in.
    """

    configured = contract.get("researchDiversity")
    policy = dict(DEFAULT_RESEARCH_DIVERSITY)
    if isinstance(configured, Mapping):
        policy.update(configured)
    if owned_full_testing(contract):
        policy["enforceOperationBinding"] = True
    elif not isinstance(configured, Mapping):
        policy["enforceOperationBinding"] = False
    return policy


def validate_diversity_policy(contract: Mapping[str, Any]) -> None:
    configured = contract.get("researchDiversity")
    if configured is None:
        return
    if not isinstance(configured, Mapping):
        raise WebResearchGovernanceError("researchDiversity must be an object")
    policy = diversity_policy(contract)
    if not isinstance(policy.get("enforceOperationBinding"), bool):
        raise WebResearchGovernanceError(
            "researchDiversity.enforceOperationBinding must be Boolean"
        )
    for field in (
        "warmupOperations",
        "minimumRuntimeFamiliesBeforeClosure",
        "minimumNonAuthorizationFamiliesBeforeClosure",
        "minimumNovelMechanismFamiliesBeforeClosure",
    ):
        value = policy.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WebResearchGovernanceError(
                f"researchDiversity.{field} must be a non-negative integer"
            )
    share = policy.get("maximumAuthorizationRequestShare")
    if (
        isinstance(share, bool)
        or not isinstance(share, (int, float))
        or not 0 < float(share) < 1
    ):
        raise WebResearchGovernanceError(
            "researchDiversity.maximumAuthorizationRequestShare must be between 0 and 1"
        )
    allocation = policy.get("runtimeBudgetAllocation")
    if not isinstance(allocation, Mapping) or set(allocation) != set(EXECUTION_PHASES):
        raise WebResearchGovernanceError(
            "researchDiversity.runtimeBudgetAllocation must define baseline, novel, followup, and replay"
        )
    total = 0.0
    for phase in sorted(EXECUTION_PHASES):
        value = allocation.get(phase)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise WebResearchGovernanceError(
                f"researchDiversity.runtimeBudgetAllocation.{phase} must be positive"
            )
        total += float(value)
    if abs(total - 1.0) > 0.000001:
        raise WebResearchGovernanceError(
            "researchDiversity.runtimeBudgetAllocation shares must sum to 1"
        )


def normalize_research_binding(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise WebResearchGovernanceError(
            "owned full-testing operations require a researchBinding object"
        )
    normalized: dict[str, str] = {}
    for field in (
        "taskId",
        "sourceTaskId",
        "experimentId",
        "approachFamily",
        "mechanismFingerprint",
    ):
        content = str(value.get(field) or "").strip()
        if not content or SAFE_IDENTIFIER.fullmatch(content) is None:
            raise WebResearchGovernanceError(
                f"researchBinding.{field} requires a safe non-empty identifier"
            )
        normalized[field] = content
    if normalized["approachFamily"] not in WEB_RUNTIME_FAMILIES:
        raise WebResearchGovernanceError(
            "researchBinding.approachFamily is not a registered web runtime family"
        )
    supplied_phase = str(value.get("executionPhase") or "").strip()
    inferred_phase = infer_execution_phase(normalized["sourceTaskId"])
    if supplied_phase:
        phase = supplied_phase
    else:
        phase = inferred_phase
    if phase not in EXECUTION_PHASES:
        raise WebResearchGovernanceError(
            "researchBinding.executionPhase must be baseline, novel, followup, or replay"
        )
    normalized["executionPhase"] = phase
    return normalized


def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM tasks WHERE task_id=?", (task_id,)
    ).fetchone()
    if row is None:
        raise WebResearchGovernanceError(
            f"researchBinding references missing orchestration task: {task_id}"
        )
    return row


def validate_binding_against_campaign(
    campaign_root: Path, binding: Mapping[str, str]
) -> dict[str, str]:
    """Verify execution ownership and topical provenance in orchestration.db."""

    database = campaign_root / "orchestration.db"
    if not database.is_file():
        raise WebResearchGovernanceError(
            "owned full-testing requires orchestration.db before target dispatch"
        )
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        execution = _task_row(connection, binding["taskId"])
        if execution["state"] not in {"running", "verifying"}:
            raise WebResearchGovernanceError(
                "researchBinding.taskId must be a running or verifying task; "
                f"observed {execution['state']}"
            )
        source = _task_row(connection, binding["sourceTaskId"])
        if source["state"] in {"cancelled", "blocked", "failed"}:
            raise WebResearchGovernanceError(
                "researchBinding.sourceTaskId cannot use a terminal unsuccessful task"
            )
        matched = connection.execute(
            "SELECT 1 FROM task_approach_families WHERE task_id=? AND family_id=?",
            (binding["sourceTaskId"], binding["approachFamily"]),
        ).fetchone()
        if matched is None:
            raise WebResearchGovernanceError(
                "researchBinding approach family is not assigned to sourceTaskId"
            )
        fields = set(source.keys())
        expected_phase = infer_execution_phase(
            source["task_id"],
            source["title"],
            source["lane"] if "lane" in fields else "",
            source["task_kind"] if "task_kind" in fields else "",
        )
        if binding["executionPhase"] != expected_phase:
            raise WebResearchGovernanceError(
                "researchBinding.executionPhase does not match the durable source task; "
                f"expected {expected_phase}"
            )
    except sqlite3.Error as exc:
        raise WebResearchGovernanceError(
            f"orchestration database cannot validate researchBinding: {exc}"
        ) from exc
    finally:
        connection.close()
    return dict(binding)


def record_orchestration_event(
    campaign_root: Path,
    *,
    event_type: str,
    binding: Mapping[str, str],
    operation_id: str,
    status: str,
) -> None:
    """Attach operation lifecycle to the durable scheduler event stream."""

    database = campaign_root / "orchestration.db"
    connection = sqlite3.connect(database, timeout=15)
    try:
        connection.execute(
            "INSERT INTO events(created_at,event_type,task_id,worker_id,payload_json) "
            "VALUES(strftime('%Y-%m-%dT%H:%M:%fZ','now'),?,?,NULL,?)",
            (
                event_type,
                binding["taskId"],
                json.dumps(
                    {
                        "operationId": operation_id,
                        "status": status,
                        "sourceTaskId": binding["sourceTaskId"],
                        "experimentId": binding["experimentId"],
                        "approachFamily": binding["approachFamily"],
                        "mechanismFingerprint": binding["mechanismFingerprint"],
                        "executionPhase": binding["executionPhase"],
                    },
                    sort_keys=True,
                ),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def binding_from(workflow: Mapping[str, Any], step: Mapping[str, Any]) -> Any:
    """Use a step-specific binding when present, otherwise the workflow binding."""

    return step.get("researchBinding", workflow.get("researchBinding"))
