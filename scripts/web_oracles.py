#!/usr/bin/env python3
"""Admit and evaluate executable web experiment contracts.

This module is the typed adapter between web experiments and Krineon's
existing oracle evaluator.  It deliberately contains no generic command or
executable-path hook.  Target actions remain owned by a registered broker and
an approved, signed workflow.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError
    from .web_oracle import evaluate as evaluate_oracle
    from .web_oracle import validate_oracle
except ImportError:
    from web_contract import WebContractError
    from web_oracle import evaluate as evaluate_oracle
    from web_oracle import validate_oracle


CONTRACT_TYPES = {
    "http-differential": "krineon-http-broker-v1",
    "browser-differential": "krineon-chrome-cdp-v1",
    "workflow-sequence": "krineon-http-broker-v1",
    "cache-serialization-differential": "krineon-http-broker-v1",
}
CASE_ROLES = {"baseline", "enforcing-negative", "positive"}
OUTCOMES = {
    "confirmed-disagreement",
    "observed-preservation",
    "inconclusive",
}
INCONCLUSIVE_STATES = {
    "auth-inconclusive": "authentication-expiry-or-state",
    "environment-blocked": "challenge-or-environment-blocked",
    "deployment-drift": "deployment-drift",
    "cleanup-failed": "cleanup-failure",
    "execution-failed": "execution-failure",
}


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def _string_list(value: Any, field: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise WebContractError(f"{field} must be a{' non-empty' if nonempty else ''} list")
    result = [_text(item, field) for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} must not contain duplicates")
    return result


def _safe_file(root: Path, value: Any, field: str) -> Path:
    relative = Path(_text(value, field))
    if relative.is_absolute() or ".." in relative.parts:
        raise WebContractError(f"{field} must be campaign-relative")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise WebContractError(f"{field} escapes the campaign") from exc
    if not resolved.is_file():
        raise WebContractError(f"{field} does not exist: {relative.as_posix()}")
    return resolved


def _validate_scope(scope: Any, prerequisite_version: str) -> dict[str, Any]:
    if not isinstance(scope, dict):
        raise WebContractError("experimentalScope must be an object")
    required = {
        "mechanism",
        "relevantInputs",
        "configuration",
        "state",
        "prerequisiteVersion",
    }
    if not required.issubset(scope):
        raise WebContractError("experimentalScope is missing exact negative-scope fields")
    if str(scope.get("prerequisiteVersion")) != prerequisite_version:
        raise WebContractError("experimentalScope prerequisiteVersion does not match")
    return {
        "mechanism": _text(scope.get("mechanism"), "experimentalScope.mechanism"),
        "relevantInputs": _string_list(
            scope.get("relevantInputs"), "experimentalScope.relevantInputs"
        ),
        "configuration": _string_list(
            scope.get("configuration"), "experimentalScope.configuration"
        ),
        "state": _string_list(scope.get("state"), "experimentalScope.state"),
        "prerequisiteVersion": prerequisite_version,
    }


def _validate_causal_model(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError("causalModel must be an object")
    kind = str(value.get("kind") or "")
    if kind == "isolated-variable":
        return {
            "kind": kind,
            "variable": _text(value.get("variable"), "causalModel.variable"),
        }
    if kind == "enumerated-interaction":
        conditions = _string_list(
            value.get("conditions"), "causalModel.conditions"
        )
        histories = value.get("counterfactualHistories")
        if not isinstance(histories, list) or len(histories) < 2:
            raise WebContractError(
                "enumerated interactions require at least two counterfactual histories"
            )
        normalized_histories = []
        for index, history in enumerate(histories):
            if not isinstance(history, dict):
                raise WebContractError("counterfactual history must be an object")
            normalized_histories.append(
                {
                    "id": _text(history.get("id"), f"counterfactualHistories[{index}].id"),
                    "sequence": _string_list(
                        history.get("sequence"),
                        f"counterfactualHistories[{index}].sequence",
                    ),
                    "expectedDifference": _text(
                        history.get("expectedDifference"),
                        f"counterfactualHistories[{index}].expectedDifference",
                    ),
                }
            )
        return {
            "kind": kind,
            "conditions": conditions,
            "counterfactualHistories": normalized_histories,
        }
    raise WebContractError(
        "causalModel.kind must be isolated-variable or enumerated-interaction"
    )


def _validate_budgets(value: Any, sequence_length: int) -> dict[str, int]:
    if not isinstance(value, dict):
        raise WebContractError("budgets must be an object")
    required = (
        "maxOperations",
        "maxRequests",
        "maxEffects",
        "maxWallSeconds",
        "cleanupReservedRequests",
    )
    normalized: dict[str, int] = {}
    for field in required:
        raw = value.get(field)
        if not isinstance(raw, int) or raw < 0:
            raise WebContractError(f"budgets.{field} must be a non-negative integer")
        normalized[field] = raw
    if normalized["maxOperations"] < sequence_length:
        raise WebContractError("maxOperations does not cover the approved sequence")
    if normalized["maxRequests"] < sequence_length:
        raise WebContractError("maxRequests does not charge every sequence step")
    if normalized["maxWallSeconds"] <= 0:
        raise WebContractError("maxWallSeconds must be positive")
    return normalized


def admit_contract(root: Path, raw: Any) -> dict[str, Any]:
    """Validate a web oracle contract without accepting worker code paths."""

    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("web oracle contract schemaVersion must be 1")
    contract_type = str(raw.get("contractType") or "")
    registered_runner = str(raw.get("registeredRunner") or "")
    if CONTRACT_TYPES.get(contract_type) != registered_runner:
        raise WebContractError("contractType must use its registered Krineon runner")
    if raw.get("executablePath") is not None or raw.get("command") is not None:
        raise WebContractError("web oracle contracts cannot select executable paths")
    contract_id = _text(raw.get("id"), "id")
    prerequisite_version = _text(
        raw.get("prerequisiteVersion"), "prerequisiteVersion"
    )
    if prerequisite_version in {"unknown", "unspecified-prerequisite-version"}:
        raise WebContractError("web experiments require a stable prerequisiteVersion")

    binding = raw.get("workflowBinding")
    if not isinstance(binding, dict):
        raise WebContractError("workflowBinding must be an object")
    workflow_path = _safe_file(root, binding.get("workflow"), "workflowBinding.workflow")
    signature_path = _safe_file(
        root, binding.get("signature"), "workflowBinding.signature"
    )
    campaign_contract_path = _safe_file(
        root, binding.get("campaignContract"), "workflowBinding.campaignContract"
    )
    workflow_sha = file_sha256(workflow_path)
    if binding.get("workflowSha256") != workflow_sha:
        raise WebContractError("workflowBinding.workflowSha256 does not match")
    workflow = json.loads(workflow_path.read_text(encoding="utf-8"))
    if not isinstance(workflow, dict):
        raise WebContractError("bound workflow must be a JSON object")
    if str(workflow.get("prerequisiteVersion") or "") != prerequisite_version:
        raise WebContractError("bound workflow prerequisiteVersion does not match")
    runner_binding: dict[str, Any] = {}
    if contract_type == "browser-differential":
        scenario_path = _safe_file(
            root, binding.get("scenario"), "workflowBinding.scenario"
        )
        if binding.get("scenarioSha256") != file_sha256(scenario_path):
            raise WebContractError("workflowBinding.scenarioSha256 does not match")
        runner_binding = {
            "scenario": scenario_path.relative_to(root).as_posix(),
            "scenarioSha256": file_sha256(scenario_path),
        }

    sequence = _string_list(raw.get("approvedActionSequence"), "approvedActionSequence")
    workflow_steps = [
        str(step.get("id") or "")
        for step in [*workflow.get("steps", []), *workflow.get("cleanupSteps", [])]
        if isinstance(step, dict)
    ]
    if any(step not in workflow_steps for step in sequence):
        raise WebContractError("approvedActionSequence contains an unknown workflow step")
    selected_steps = {
        str(step.get("id") or ""): str(step.get("type") or "http")
        for step in [*workflow.get("steps", []), *workflow.get("cleanupSteps", [])]
        if isinstance(step, dict)
    }
    expected_step_type = "browser" if contract_type == "browser-differential" else "http"
    if any(selected_steps.get(step) != expected_step_type for step in sequence):
        raise WebContractError(
            f"{contract_type} may select only {expected_step_type} workflow steps"
        )

    actor_fixtures = _string_list(raw.get("actorFixtures"), "actorFixtures")
    resource_fixtures = _string_list(raw.get("resourceFixtures"), "resourceFixtures")
    secret_references = _string_list(
        raw.get("secretReferences", []), "secretReferences", nonempty=False
    )
    if any(not value.startswith("secret://") for value in secret_references):
        raise WebContractError("secretReferences must use secret:// identifiers")
    cases = raw.get("cases")
    if not isinstance(cases, list) or {
        str(case.get("role") or "") for case in cases if isinstance(case, dict)
    } != CASE_ROLES:
        raise WebContractError("cases require baseline, enforcing-negative, and positive roles")
    normalized_cases = []
    case_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise WebContractError("case must be an object")
        case_id = _text(case.get("id"), "case.id")
        if case_id in case_ids:
            raise WebContractError("case ids must be unique")
        case_ids.add(case_id)
        case_steps = _string_list(case.get("steps"), "case.steps")
        if any(step not in sequence for step in case_steps):
            raise WebContractError("case steps must belong to approvedActionSequence")
        normalized_cases.append(
            {
                "id": case_id,
                "role": str(case.get("role")),
                "steps": case_steps,
            }
        )
    workflow_by_id = {
        str(step.get("id") or ""): step
        for step in [*workflow.get("steps", []), *workflow.get("cleanupSteps", [])]
        if isinstance(step, dict)
    }
    effect_count = 0
    for step_id in sequence:
        step = workflow_by_id[step_id]
        actor = str(step.get("identityId") or "anonymous")
        resource = step.get("resource") if isinstance(step.get("resource"), dict) else {}
        resource_id = str(resource.get("id") or "")
        if actor not in actor_fixtures:
            raise WebContractError(
                f"workflow step {step_id} actor is not an actor fixture"
            )
        if resource_id not in resource_fixtures:
            raise WebContractError(
                f"workflow step {step_id} resource is not a resource fixture"
            )
        if str(step.get("effectClass") or "unknown") != "read-only":
            effect_count += 1
    assertion = raw.get("assertion")
    if not isinstance(assertion, dict) or assertion.get("engine") != "krineon-web-oracle-v1":
        raise WebContractError("assertion must use krineon-web-oracle-v1")
    oracle_id = _text(assertion.get("oracleId"), "assertion.oracleId")
    matching = [
        value
        for value in workflow.get("oracles", [])
        if isinstance(value, dict) and value.get("id") == oracle_id
    ]
    if len(matching) != 1:
        raise WebContractError("assertion.oracleId must select one bound workflow oracle")
    validate_oracle(matching[0])
    cleanup = raw.get("cleanup")
    if not isinstance(cleanup, dict):
        raise WebContractError("cleanup must be an object")
    cleanup_steps = _string_list(
        cleanup.get("steps", []), "cleanup.steps", nonempty=False
    )
    if any(step not in workflow_steps for step in cleanup_steps):
        raise WebContractError("cleanup references an unknown workflow step")
    replay = raw.get("independentReplay")
    if not isinstance(replay, dict):
        raise WebContractError("independentReplay must be an object")
    evidence_outputs = _string_list(raw.get("evidenceOutputs"), "evidenceOutputs")
    scope = _validate_scope(raw.get("experimentalScope"), prerequisite_version)
    causal_model = _validate_causal_model(raw.get("causalModel"))
    budgets = _validate_budgets(raw.get("budgets"), len(sequence))
    if budgets["maxEffects"] < effect_count:
        raise WebContractError("maxEffects does not charge every non-read operation")

    return {
        "schemaVersion": 1,
        "id": contract_id,
        "kind": "web-typed",
        "contractType": contract_type,
        "registeredRunner": registered_runner,
        "prerequisiteVersion": prerequisite_version,
        "experimentalScope": scope,
        "causalModel": causal_model,
        "workflowBinding": {
            "workflow": workflow_path.relative_to(root).as_posix(),
            "signature": signature_path.relative_to(root).as_posix(),
            "campaignContract": campaign_contract_path.relative_to(root).as_posix(),
            "workflowSha256": workflow_sha,
            "signatureSha256": file_sha256(signature_path),
            "campaignContractSha256": file_sha256(campaign_contract_path),
            "workflowId": str(workflow.get("id") or ""),
            **runner_binding,
        },
        "approvedActionSequence": sequence,
        "actorFixtures": actor_fixtures,
        "resourceFixtures": resource_fixtures,
        "secretReferences": secret_references,
        "budgets": budgets,
        "cases": normalized_cases,
        "assertion": {
            "engine": "krineon-web-oracle-v1",
            "oracleId": oracle_id,
            "oracle": matching[0],
        },
        "cleanup": {
            "required": bool(cleanup.get("required")),
            "steps": cleanup_steps,
            "successPredicate": _text(
                cleanup.get("successPredicate"), "cleanup.successPredicate"
            ),
        },
        "independentReplay": {
            "freshIdentityRequired": bool(replay.get("freshIdentityRequired", True)),
            "freshResourceRequired": bool(replay.get("freshResourceRequired", True)),
            "prerequisites": _string_list(
                replay.get("prerequisites"), "independentReplay.prerequisites"
            ),
        },
        "evidenceOutputs": evidence_outputs,
    }


def evaluate_contract(
    contract: dict[str, Any],
    observation: dict[str, Any],
    *,
    observed_prerequisite_version: str | None = None,
) -> dict[str, Any]:
    """Normalize broker/CDP observations into a three-valued web outcome."""

    expected_version = str(contract.get("prerequisiteVersion") or "")
    actual_version = str(
        observed_prerequisite_version
        or observation.get("prerequisiteVersion")
        or ""
    )
    run_state = str(observation.get("runState") or "completed")
    cleanup_errors = observation.get("cleanupErrors")
    reason = "oracle-evaluated"
    evaluation: dict[str, Any] | None = None
    outcome = "inconclusive"
    if actual_version != expected_version:
        reason = "deployment-drift"
    elif cleanup_errors:
        reason = "cleanup-failure"
    elif run_state != "completed":
        reason = INCONCLUSIVE_STATES.get(run_state, "execution-inconclusive")
    elif observation.get("failure"):
        reason = "execution-failure"
    else:
        evaluation = evaluate_oracle(contract["assertion"]["oracle"], observation)
        raw_outcome = str(evaluation.get("outcome") or "")
        if raw_outcome == "confirmed-invariant-disagreement":
            outcome = "confirmed-disagreement"
        elif raw_outcome == "observed-invariant-preservation":
            outcome = "observed-preservation"
        else:
            reason = raw_outcome or "missing-telemetry"
    result = {
        "schemaVersion": 1,
        "producer": "krineon-web-oracles",
        "contractId": contract.get("id"),
        "workflowId": contract.get("workflowBinding", {}).get("workflowId"),
        "prerequisiteVersion": expected_version,
        "outcome": outcome,
        "reason": reason,
        "promotionEligible": outcome == "confirmed-disagreement",
        "securityViolationConfirmed": outcome == "confirmed-disagreement",
        "experimentalScope": contract.get("experimentalScope"),
        "evidenceReferences": [
            value
            for value in observation.get("evidenceReferences", [])
            if isinstance(value, str)
        ],
        "cleanupComplete": not bool(cleanup_errors),
        "evaluation": evaluation,
    }
    if outcome == "observed-preservation":
        result["scopedNegativeKnowledge"] = {
            "consumer": contract.get("id"),
            "experimentalScope": contract.get("experimentalScope"),
            "reopeningConditions": [
                "prerequisite version changes",
                "a relevant input, configuration, or state element changes",
                "new telemetry contradicts the preserved invariant",
            ],
            "evidence": result["evidenceReferences"],
        }
    return result
