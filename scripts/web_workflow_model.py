#!/usr/bin/env python3
"""Connect a web surface map into lifecycle, trust, and coverage models."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


def load_map(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("kind") != "krineon-web-surface-map":
        raise WebContractError("input is not a Krineon web surface map")
    return value


def build_workflow_model(surface: dict[str, Any], source: Path) -> dict[str, Any]:
    identities = {str(item["id"]): item for item in surface.get("identityModel", [])}
    resources = {str(item["id"]): item for item in surface.get("resourceModel", [])}
    operations = [item for item in surface.get("operationModel", []) if isinstance(item, dict)]
    operation_ids = {str(item.get("id") or "") for item in operations}
    workflows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for operation in operations:
        workflows[str(operation.get("workflowId") or "unknown")].append(operation)

    lifecycle_models = []
    for workflow_id, rows in sorted(workflows.items()):
        unresolved = sorted(
            {
                dependency
                for row in rows
                for dependency in row.get("prerequisites", [])
                if dependency not in operation_ids
            }
        )
        lifecycle_models.append(
            {
                "id": workflow_id,
                "operationIds": [str(row.get("id") or "") for row in rows],
                "transitions": [
                    {
                        "operationId": str(row.get("id") or ""),
                        "actor": str(row.get("actor") or "anonymous"),
                        "resourceId": str(row.get("resourceId") or ""),
                        "action": str(row.get("action") or "unknown"),
                        "prerequisites": list(row.get("prerequisites") or []),
                        "preState": str(row.get("preState") or "unknown"),
                        "postState": str(row.get("postState") or "unknown"),
                        "effect": str(row.get("effect") or "unknown"),
                        "confidence": str(row.get("confidence") or "hypothesized"),
                    }
                    for row in rows
                ],
                "multiStep": len(rows) > 1 and any(row.get("prerequisites") for row in rows),
                "unresolvedPrerequisites": unresolved,
            }
        )

    attempted = []
    attempted_keys: set[tuple[str, str, str, str]] = set()
    for row in operations:
        key = (
            str(row.get("actor") or "anonymous"),
            str(row.get("resourceId") or ""),
            str(row.get("action") or "unknown"),
            str(row.get("preState") or "unknown"),
        )
        attempted_keys.add(key)
        attempted.append(
            {
                "actor": key[0],
                "resourceId": key[1],
                "action": key[2],
                "state": key[3],
                "operationId": str(row.get("id") or ""),
                "result": "attempt-observed",
                "confidence": "observed",
            }
        )

    meaningful_actions = sorted(
        {
            str(row.get("action"))
            for row in operations
            if row.get("action") not in {None, "", "unknown"}
            and not str(row.get("action")).startswith("http:")
        }
    )
    if "read" not in meaningful_actions:
        meaningful_actions.append("read")
    unattempted = []
    for identity_id in sorted(identities):
        for resource_id, resource in sorted(resources.items()):
            owner = str(resource.get("owner") or "unknown")
            for action in meaningful_actions:
                state = "active"
                key = (identity_id, resource_id, action, state)
                if key in attempted_keys:
                    continue
                unattempted.append(
                    {
                        "actor": identity_id,
                        "resourceId": resource_id,
                        "resourceOwner": owner,
                        "action": action,
                        "state": state,
                        "status": "unattempted",
                        "permission": "requires-coordinator-approved-experiment",
                    }
                )

    questions = []
    for item in unattempted:
        if item["resourceOwner"] not in {"", "unknown", "public", item["actor"]} and item["action"] == "read":
            questions.append(
                {
                    "priority": 100,
                    "kind": "cross-identity-authorization",
                    "question": (
                        f"Can actor {item['actor']} read active resource {item['resourceId']} "
                        f"owned by {item['resourceOwner']}?"
                    ),
                    "coverageCell": item,
                    "status": "unresolved",
                    "requiredEvidence": [
                        "owner baseline read",
                        "non-owner read with a separate session",
                        "authoritative resource state before and after",
                    ],
                }
            )
    for workflow in lifecycle_models:
        if workflow["multiStep"] and any(
            row["postState"] == "invalidated" for row in workflow["transitions"]
        ):
            questions.append(
                {
                    "priority": 90,
                    "kind": "post-invalidation-lifecycle",
                    "question": f"Does workflow {workflow['id']} reject use after invalidation?",
                    "workflowId": workflow["id"],
                    "status": "unresolved",
                    "requiredEvidence": [
                        "authoritative invalidated state",
                        "bounded post-invalidation operation",
                        "independent state read",
                    ],
                }
            )
    questions.sort(key=lambda item: (-int(item["priority"]), item["question"]))
    next_question = questions[0] if questions else {
        "priority": 0,
        "kind": "policy-clarification",
        "question": "Which owner-specified business invariant should be tested next?",
        "status": "inconclusive",
        "requiredEvidence": ["owner-specified rule or source-supported invariant"],
    }

    trust = []
    for item in surface.get("trustRepresentationModel", []):
        trust.append(
            {
                "operationId": item.get("operationId"),
                "boundary": "request-representation-to-application",
                "protocol": item.get("protocol"),
                "signed": item.get("signed"),
                "authenticationBoundFields": item.get("authenticationBoundFields", []),
                "question": "Do authorization and execution consume the same representation?",
                "confidence": "observed",
            }
        )
    for item in surface.get("browserModel", []):
        for worker in item.get("serviceWorkers", []):
            trust.append(
                {
                    "operationId": item.get("stepId"),
                    "boundary": "browser-to-service-worker-cache",
                    "resource": worker,
                    "question": "Which identity and cache partition own this persistent state?",
                    "confidence": "observed",
                }
            )

    return {
        "schemaVersion": 1,
        "kind": "krineon-web-workflow-model",
        "sourceSurfaceMap": {
            "path": str(source),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "identityModel": list(identities.values()),
        "resourceModel": list(resources.values()),
        "workflowModel": lifecycle_models,
        "trustRepresentationModel": trust,
        "coverageLedger": {
            "unit": "actor x resource x action x state",
            "attempted": attempted,
            "unattempted": unattempted,
            "requestCountIsCoverage": False,
            "pageCountIsCoverage": False,
        },
        "unresolvedQuestions": questions,
        "nextUnresolvedSecurityQuestion": next_question,
        "policy": {
            "uiVisibilityDefinesAuthorization": False,
            "httpMethodDefinesEffect": False,
            "ambiguousRulesRemainInconclusive": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("surface_map")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    source = Path(args.surface_map).expanduser().resolve()
    try:
        result = build_workflow_model(load_map(source), source)
        output = Path(args.output).expanduser().resolve()
        atomic_json(output, result, mode=0o600)
        print(json.dumps({"workflows": len(result["workflowModel"]), "attemptedCoverageCells": len(result["coverageLedger"]["attempted"]), "nextQuestion": result["nextUnresolvedSecurityQuestion"]["question"]}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
