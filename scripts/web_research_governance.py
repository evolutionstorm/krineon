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

DEFAULT_RESEARCH_DIVERSITY = {
    "enforceOperationBinding": True,
    "warmupOperations": 4,
    "maximumAuthorizationRequestShare": 0.20,
    "minimumRuntimeFamiliesBeforeClosure": 4,
    "minimumNonAuthorizationFamiliesBeforeClosure": 3,
    "minimumNovelMechanismFamiliesBeforeClosure": 3,
}

SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")


class WebResearchGovernanceError(ValueError):
    """Raised when target traffic is detached from the research frontier."""


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
    return normalized


def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT task_id,state,title FROM tasks WHERE task_id=?", (task_id,)
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
