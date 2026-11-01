#!/usr/bin/env python3
"""Search signed web operations for one explicit forbidden composition.

This planner does not permute captured requests. It starts from a reviewed
normal workflow and concrete attacker authority, works backward from one
forbidden terminal consumer, and advances a resumable semantic frontier only
through operations that can contribute to that terminal.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
    from .web_sequence_planner import (
        requirement_refs,
        stable_id,
        sum_cost,
        validate_operation,
    )
    from .web_state_oracles import validate_oracle
except ImportError:
    from web_contract import WebContractError, atomic_json
    from web_sequence_planner import (
        requirement_refs,
        stable_id,
        sum_cost,
        validate_operation,
    )
    from web_state_oracles import validate_oracle


COMPOSITION_FAMILIES = {
    "approval-then-mutation": "Does approval remain bound after a protected object or property changes?",
    "request-then-async-consumption": "Does a worker recheck authority and job ownership at consumption?",
    "grant-then-revocation": "Does a later consumer retain authority after bounded revocation propagation?",
    "parent-tenant-transition-then-use": "Does a resource retain stale owner authority after a parent or tenant transition?",
    "delegated-request-then-deputy": "Can attacker-controlled state redirect a privileged deputy's resource or action?",
    "prepare-preview-then-commit": "Does commit use the same object, totals, identity, and version as preparation?",
    "invitation-share-then-lifecycle-change": "Does consumption enforce current recipient, tenant, expiry, and cancellation?",
    "one-time-operation-then-alternate-consumer": "Can another channel consume an already used capability?",
    "independent-weak-primitives": "Do compatible partial capabilities combine into a new authority violation?",
    "paired-concurrent-steps": "Can one approved pair violate an invariant that holds sequentially?",
}

HISTORY_CHANGES = {
    "omitted-prerequisite",
    "actor-transition",
    "repeated-operation",
    "changed-relationship",
    "delayed-consumption",
    "alternate-consumer",
    "paired-concurrent-steps",
}

LIMIT_FIELDS = {
    "maxPathLength",
    "maxExecutionsPerOperation",
    "maxRequests",
    "maxPolling",
    "maxWallSeconds",
    "maxStateChangingEffects",
    "maxFrontierStates",
}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise WebContractError(f"{field} is required")
    return text


def string_list(value: Any, field: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise WebContractError(f"{field} must contain at least {minimum} values")
    result = [require_text(item, field) for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} must not contain duplicates")
    return result


def validate_limits(raw: Any) -> dict[str, int | bool]:
    if not isinstance(raw, dict):
        raise WebContractError("approvedLimits must be an object")
    limits: dict[str, int | bool] = {}
    for field in LIMIT_FIELDS:
        value = raw.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise WebContractError(f"approvedLimits.{field} must be non-negative")
        limits[field] = value
    concurrency = raw.get("allowConcurrency")
    if not isinstance(concurrency, bool):
        raise WebContractError("approvedLimits.allowConcurrency must be Boolean")
    limits["allowConcurrency"] = concurrency
    if int(limits["maxPathLength"]) < 1 or int(limits["maxFrontierStates"]) < 1:
        raise WebContractError("path length and frontier bounds must be positive")
    if int(limits["maxExecutionsPerOperation"]) < 1:
        raise WebContractError("each operation must permit at least one execution")
    return limits


def validate_history_change(raw: dict[str, Any]) -> dict[str, Any]:
    kind = str(raw.get("kind") or "")
    required_by_kind = {
        "omitted-prerequisite": ("operationId", "reference"),
        "actor-transition": ("fromActor", "toActor"),
        "repeated-operation": ("operationId",),
        "changed-relationship": ("reference",),
        "delayed-consumption": ("producerOperationId", "consumerOperationId"),
        "alternate-consumer": ("consumerOperationId", "reference"),
        "paired-concurrent-steps": (),
    }
    if kind not in required_by_kind:
        raise WebContractError("historyChange.kind is unsupported")
    result = dict(raw)
    for field in required_by_kind[kind]:
        result[field] = require_text(raw.get(field), f"historyChange.{field}")
    if kind == "paired-concurrent-steps":
        members = string_list(
            raw.get("interactionOperationIds"),
            "historyChange.interactionOperationIds",
            minimum=2,
        )
        if len(members) != 2:
            raise WebContractError("paired history change requires exactly two operations")
        result["interactionOperationIds"] = members
    return result


def validate_prior_outcomes(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise WebContractError("priorOutcomes must be an array")
    outcomes = []
    for index, value in enumerate(raw):
        if not isinstance(value, dict) or value.get("outcome") not in {
            "confirmed",
            "refuted",
            "inconclusive",
        }:
            raise WebContractError(f"priorOutcomes[{index}] has an unsupported outcome")
        outcomes.append(
            {
                "outcome": value["outcome"],
                "stateKey": require_text(value.get("stateKey"), "prior outcome stateKey"),
                "mechanism": require_text(value.get("mechanism"), "prior outcome mechanism"),
                "input": require_text(value.get("input"), "prior outcome input"),
                "configuration": require_text(
                    value.get("configuration"), "prior outcome configuration"
                ),
                "state": require_text(value.get("state"), "prior outcome state"),
                "prerequisiteVersion": require_text(
                    value.get("prerequisiteVersion"),
                    "prior outcome prerequisiteVersion",
                ),
                "evidence": string_list(
                    value.get("evidence"), "prior outcome evidence", minimum=1
                ),
            }
        )
    return outcomes


def validate_goal(raw: Any, graph: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("forbidden composition goal schemaVersion must be 1")
    if raw.get("prerequisiteVersion") != graph.get("prerequisiteVersion"):
        raise WebContractError("goal and sequence graph prerequisite versions differ")
    family = str(raw.get("compositionFamily") or "")
    if family not in COMPOSITION_FAMILIES:
        raise WebContractError("compositionFamily is unsupported")
    change = raw.get("historyChange")
    if not isinstance(change, dict):
        raise WebContractError("historyChange must be an object")
    change = validate_history_change(change)
    terminal = raw.get("forbiddenTerminal")
    if not isinstance(terminal, dict):
        raise WebContractError("forbiddenTerminal must be an object")
    for field in (
        "consumerOperationId",
        "observerOperationId",
        "prohibitedEffect",
        "policyBasis",
        "attackerActorRef",
        "observerActorRef",
        "resourceId",
        "tenant",
        "owner",
        "version",
        "generation",
        "action",
        "observationEpoch",
    ):
        require_text(terminal.get(field), f"forbiddenTerminal.{field}")
    operations = {
        item["id"]: item
        for item in (
            validate_operation(value) for value in graph.get("operations", [])
        )
    }
    if len(operations) != len(graph.get("operations", [])):
        raise WebContractError("operation ids must be unique")
    consumer_id = str(terminal["consumerOperationId"])
    if consumer_id not in operations:
        raise WebContractError("forbidden terminal consumer is not a signed operation")
    consumer = operations[consumer_id]
    observer_id = str(terminal["observerOperationId"])
    if observer_id not in operations or observer_id == consumer_id:
        raise WebContractError("forbidden terminal requires a separate signed observer operation")
    observer_operation = operations[observer_id]
    matching_resources = [
        value
        for value in consumer["resourceBindings"]
        if value["id"] == terminal["resourceId"]
        and all(
            str(value[field]) == str(terminal[field])
            for field in ("tenant", "owner", "version", "generation")
        )
    ]
    if len(matching_resources) != 1:
        raise WebContractError("terminal resource binding does not match the consumer")
    if consumer["authorityBinding"]["action"] != terminal["action"]:
        raise WebContractError("terminal action does not match the consumer authority binding")
    if observer_operation["actorRef"]["id"] != terminal["observerActorRef"]:
        raise WebContractError("observer operation does not use the approved observer identity")
    if not any(
        value["id"] == terminal["resourceId"]
        and all(
            str(value[field]) == str(terminal[field])
            for field in ("tenant", "owner", "version", "generation")
        )
        for value in observer_operation["resourceBindings"]
    ):
        raise WebContractError("observer operation does not read the terminal resource binding")
    authority = raw.get("startingAuthority")
    if not isinstance(authority, dict):
        raise WebContractError("startingAuthority must be an object")
    actor_refs = string_list(authority.get("actorRefs"), "startingAuthority.actorRefs", minimum=1)
    observer_refs = string_list(
        authority.get("observerActorRefs"),
        "startingAuthority.observerActorRefs",
        minimum=1,
    )
    if terminal["attackerActorRef"] not in actor_refs:
        raise WebContractError("terminal attacker is not in starting attacker authority")
    if terminal["observerActorRef"] not in observer_refs:
        raise WebContractError("terminal observer is not an approved owned observer")
    if terminal["observerActorRef"] == terminal["attackerActorRef"]:
        raise WebContractError("terminal readback requires an identity independent of the attacker")
    resources = authority.get("resources")
    if not isinstance(resources, list) or not resources:
        raise WebContractError("startingAuthority.resources must contain owned fixtures")
    normalized_resources = {}
    for value in resources:
        if not isinstance(value, dict) or value.get("owned") is not True:
            raise WebContractError("starting resources must be explicitly owned")
        resource_id = require_text(value.get("id"), "starting resource id")
        normalized_resources[resource_id] = {
            field: require_text(value.get(field), f"starting resource {field}")
            for field in ("id", "tenant", "owner", "version", "generation", "relationship")
        }
        normalized_resources[resource_id]["observationEpoch"] = require_text(
            value.get("observationEpoch"), "starting resource observationEpoch"
        )
        if normalized_resources[resource_id]["observationEpoch"] != terminal["observationEpoch"]:
            raise WebContractError("starting resources must share the terminal observation epoch")
        normalized_resources[resource_id]["owned"] = True
    if terminal["resourceId"] not in normalized_resources:
        raise WebContractError("terminal resource is not an owned starting fixture")
    raw_consumption_counts = authority.get("consumptionCounts", {})
    if not isinstance(raw_consumption_counts, dict):
        raise WebContractError("startingAuthority.consumptionCounts must be an object")
    consumption_counts = {}
    for reference, count in raw_consumption_counts.items():
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise WebContractError("starting consumption counts must be non-negative integers")
        consumption_counts[require_text(reference, "consumed value reference")] = count
    semantics = raw.get("operationSemantics")
    if not isinstance(semantics, dict):
        raise WebContractError("operationSemantics must be an object")
    normalized_semantics = {}
    for operation_id, value in semantics.items():
        if operation_id not in operations or not isinstance(value, dict):
            raise WebContractError("operationSemantics references an unknown operation")
        if not isinstance(value.get("attackerCanAttempt"), bool):
            raise WebContractError("operationSemantics.attackerCanAttempt must be Boolean")
        policy = str(value.get("referencePolicy") or "")
        if policy not in {"allowed", "forbidden", "conditional"}:
            raise WebContractError("operation referencePolicy is unsupported")
        evidence = string_list(value.get("evidence"), "operationSemantics.evidence", minimum=1)
        observation_epoch = require_text(
            value.get("observationEpoch"),
            f"operationSemantics.{operation_id}.observationEpoch",
        )
        if observation_epoch != terminal["observationEpoch"]:
            raise WebContractError("operation semantics cannot cross observation epochs")
        resource_transitions = []
        for index, transition in enumerate(value.get("resourceTransitions", [])):
            if not isinstance(transition, dict):
                raise WebContractError("resourceTransitions entries must be objects")
            before = transition.get("from")
            after = transition.get("to")
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise WebContractError("resource transition requires from and to states")
            resource_id = require_text(
                transition.get("resourceId"),
                f"operationSemantics.{operation_id}.resourceTransitions[{index}].resourceId",
            )
            normalized_before = {
                field: require_text(before.get(field), f"resource transition from {field}")
                for field in ("tenant", "owner", "version", "generation", "relationship")
            }
            normalized_after = {
                field: require_text(after.get(field), f"resource transition to {field}")
                for field in ("tenant", "owner", "version", "generation", "relationship")
            }
            resource_transitions.append(
                {
                    "resourceId": resource_id,
                    "from": normalized_before,
                    "to": normalized_after,
                    "evidence": string_list(
                        transition.get("evidence"), "resource transition evidence", minimum=1
                    ),
                }
            )
        permission_transitions = []
        for index, transition in enumerate(value.get("permissionTransitions", [])):
            if not isinstance(transition, dict):
                raise WebContractError("permissionTransitions entries must be objects")
            permission_transitions.append(
                {
                    "actorRef": require_text(
                        transition.get("actorRef"),
                        f"operationSemantics.{operation_id}.permissionTransitions[{index}].actorRef",
                    ),
                    "from": require_text(transition.get("from"), "permission transition from"),
                    "to": require_text(transition.get("to"), "permission transition to"),
                    "evidence": string_list(
                        transition.get("evidence"), "permission transition evidence", minimum=1
                    ),
                }
            )
        normalized_semantics[operation_id] = {
            "attackerCanAttempt": value["attackerCanAttempt"],
            "referencePolicy": policy,
            "evidence": evidence,
            "observationEpoch": observation_epoch,
            "resourceTransitions": resource_transitions,
            "permissionTransitions": permission_transitions,
        }
    candidate_ids = string_list(
        raw.get("candidateOperationIds", []), "candidateOperationIds"
    )
    unknown = set(candidate_ids).difference(operations)
    if unknown:
        raise WebContractError("candidateOperationIds contains unknown operations")
    normal_plan_id = require_text(raw.get("normalPlanId"), "normalPlanId")
    normal_plans = [value for value in graph.get("plans", []) if value.get("id") == normal_plan_id]
    if len(normal_plans) != 1:
        raise WebContractError("normalPlanId must select one sequence plan")
    normal_history = list(map(str, normal_plans[0]["histories"]["normal"]))
    if not normal_history:
        raise WebContractError("the legitimate normal workflow must be non-empty")
    if any(operation_id not in operations for operation_id in normal_history):
        raise WebContractError("the legitimate normal workflow references an unknown operation")
    if observer_id in normal_history or observer_id in candidate_ids:
        raise WebContractError("the terminal observer must be a distinct post-effect operation")
    controls_raw = raw.get("controlHistories")
    if not isinstance(controls_raw, list) or not controls_raw:
        raise WebContractError("at least one specific authority or state-binding control is required")
    control_histories = []
    control_ids: set[str] = set()
    for index, control in enumerate(controls_raw):
        if not isinstance(control, dict):
            raise WebContractError("control histories must be objects")
        control_id = require_text(control.get("id"), f"controlHistories[{index}].id")
        if control_id in control_ids:
            raise WebContractError("control history ids must be unique")
        control_ids.add(control_id)
        purpose = str(control.get("purpose") or "")
        if purpose not in {"remove-disputed-binding", "restore-disputed-binding"}:
            raise WebContractError("control history must remove or restore the disputed binding")
        operation_ids = string_list(
            control.get("operationIds"),
            f"controlHistories[{index}].operationIds",
            minimum=1,
        )
        if operation_ids[: len(normal_history)] != normal_history:
            raise WebContractError("every control history must include the legitimate sequence first")
        if any(operation_id not in operations for operation_id in operation_ids):
            raise WebContractError("control history references an unknown operation")
        control_histories.append(
            {
                "id": control_id,
                "purpose": purpose,
                "disputedBinding": require_text(
                    control.get("disputedBinding"),
                    f"controlHistories[{index}].disputedBinding",
                ),
                "operationIds": operation_ids,
                "expectedObservation": require_text(
                    control.get("expectedObservation"),
                    f"controlHistories[{index}].expectedObservation",
                ),
            }
        )
    explanations_raw = raw.get("competingExplanations")
    if not isinstance(explanations_raw, list) or len(explanations_raw) < 2:
        raise WebContractError("forbidden composition requires at least two competing explanations")
    competing_explanations = []
    explanation_ids: set[str] = set()
    for index, value in enumerate(explanations_raw):
        if not isinstance(value, dict):
            raise WebContractError("competing explanations must be objects")
        explanation_id = require_text(value.get("id"), f"competingExplanations[{index}].id")
        if explanation_id in explanation_ids:
            raise WebContractError("competing explanation ids must be unique")
        explanation_ids.add(explanation_id)
        competing_explanations.append(
            {
                "id": explanation_id,
                "statement": require_text(
                    value.get("statement"), f"competingExplanations[{index}].statement"
                ),
                "expectedObservations": string_list(
                    value.get("expectedObservations"),
                    f"competingExplanations[{index}].expectedObservations",
                    minimum=1,
                ),
            }
        )
    state_oracle = raw.get("stateOracle")
    state_oracle = validate_oracle(state_oracle)
    if state_oracle["prerequisiteVersion"] != raw["prerequisiteVersion"]:
        raise WebContractError("state oracle and forbidden goal prerequisite versions differ")
    legitimate_replay = raw.get("legitimateReplay")
    if not isinstance(legitimate_replay, dict) or legitimate_replay.get("status") != "confirmed":
        raise WebContractError("the legitimate normal workflow requires a confirmed replay")
    for field in ("beforeStateEvidence", "afterStateEvidence", "policyEvidence"):
        string_list(
            legitimate_replay.get(field),
            f"legitimateReplay.{field}",
            minimum=1,
        )
    if legitimate_replay.get("observationEpoch") != terminal["observationEpoch"]:
        raise WebContractError("legitimate replay and forbidden goal must share an observation epoch")
    exceptions = raw.get("counterfactualExceptions", {})
    if not isinstance(exceptions, dict):
        raise WebContractError("counterfactualExceptions must be an object")
    normalized_exceptions = {
        field: string_list(exceptions.get(field, []), f"counterfactualExceptions.{field}")
        for field in (
            "unsatisfiedRequirementRefs",
            "invalidatedValueRefs",
            "replayedValueRefs",
        )
    }
    raw_permission_versions = authority.get("permissionVersions", {})
    if not isinstance(raw_permission_versions, dict):
        raise WebContractError("startingAuthority.permissionVersions must be an object")
    raw_session_versions = authority.get("sessionRefreshVersions", {})
    if not isinstance(raw_session_versions, dict):
        raise WebContractError("startingAuthority.sessionRefreshVersions must be an object")
    replay_raw = raw.get("independentReplayRequirements")
    if not isinstance(replay_raw, dict):
        raise WebContractError("independentReplayRequirements must be an object")
    for field in (
        "rebuildDisposableFixtures",
        "freshCredentialBindings",
        "replayEntireMinimalSequence",
        "rejectCopiedTerminalResponse",
        "rejectPrepopulatedState",
        "rejectStaleApproval",
        "rejectPrivateEvaluatorResource",
    ):
        if replay_raw.get(field) is not True:
            raise WebContractError(f"independentReplayRequirements.{field} must be true")
    independent_replay = {
        **{field: True for field in (
            "rebuildDisposableFixtures",
            "freshCredentialBindings",
            "replayEntireMinimalSequence",
            "rejectCopiedTerminalResponse",
            "rejectPrepopulatedState",
            "rejectStaleApproval",
            "rejectPrivateEvaluatorResource",
        )},
        "minimumIndependentReviewers": int(replay_raw.get("minimumIndependentReviewers", 1)),
        "legitimateOtherActorActions": string_list(
            replay_raw.get("legitimateOtherActorActions", []),
            "independentReplayRequirements.legitimateOtherActorActions",
        ),
        "victimInteraction": require_text(
            replay_raw.get("victimInteraction"),
            "independentReplayRequirements.victimInteraction",
        ),
    }
    if independent_replay["minimumIndependentReviewers"] < 1:
        raise WebContractError("independent replay requires at least one fresh reviewer")
    primitive_raw = raw.get("primitiveContributions", [])
    if not isinstance(primitive_raw, list):
        raise WebContractError("primitiveContributions must be an array")
    primitive_contributions = []
    for index, value in enumerate(primitive_raw):
        if not isinstance(value, dict):
            raise WebContractError("primitive contributions must be objects")
        operation_ids = string_list(
            value.get("operationIds"),
            f"primitiveContributions[{index}].operationIds",
            minimum=1,
        )
        if any(operation_id not in operations for operation_id in operation_ids):
            raise WebContractError("primitive contribution references an unknown operation")
        primitive_contributions.append(
            {
                "id": require_text(value.get("id"), f"primitiveContributions[{index}].id"),
                "operationIds": operation_ids,
                "contribution": require_text(
                    value.get("contribution"),
                    f"primitiveContributions[{index}].contribution",
                ),
                "aloneReachesTerminal": value.get("aloneReachesTerminal") is True,
                "separateIssue": value.get("separateIssue") is True,
            }
        )
    if family == "independent-weak-primitives" and len(primitive_contributions) < 2:
        raise WebContractError("multi-primitive composition requires at least two contributions")
    goal = {
        "id": require_text(raw.get("id"), "goal.id"),
        "title": require_text(raw.get("title"), "goal.title"),
        "prerequisiteVersion": raw["prerequisiteVersion"],
        "compositionFamily": family,
        "historyChange": dict(change),
        "forbiddenTerminal": dict(terminal),
        "startingAuthority": {
            "actorRefs": actor_refs,
            "observerActorRefs": observer_refs,
            "resources": normalized_resources,
            "serverValueRefs": string_list(
                authority.get("serverValueRefs", []),
                "startingAuthority.serverValueRefs",
            ),
            "capabilityRefs": string_list(
                authority.get("capabilityRefs", []),
                "startingAuthority.capabilityRefs",
            ),
            "invalidatedValueRefs": string_list(
                authority.get("invalidatedValueRefs", []),
                "startingAuthority.invalidatedValueRefs",
            ),
            "consumptionCounts": consumption_counts,
            "permissionVersions": dict(raw_permission_versions),
            "sessionRefreshVersions": dict(raw_session_versions),
        },
        "operationSemantics": normalized_semantics,
        "candidateOperationIds": candidate_ids,
        "normalPlanId": normal_plan_id,
        "normalHistory": normal_history,
        "controlHistories": control_histories,
        "competingExplanations": competing_explanations,
        "primitiveContributions": primitive_contributions,
        "independentReplayRequirements": independent_replay,
        "stateOracle": state_oracle,
        "legitimateReplay": dict(legitimate_replay),
        "counterfactualExceptions": normalized_exceptions,
        "approvedLimits": validate_limits(raw.get("approvedLimits")),
        "reviewedBudgetExtension": raw.get("reviewedBudgetExtension"),
        "priorOutcomes": validate_prior_outcomes(raw.get("priorOutcomes", [])),
    }
    permission_versions = goal["startingAuthority"]["permissionVersions"]
    goal["startingAuthority"]["permissionVersions"] = {
        require_text(actor, "permission version actor"): require_text(
            version, "permission version"
        )
        for actor, version in permission_versions.items()
    }
    goal["startingAuthority"]["sessionRefreshVersions"] = {
        require_text(actor, "session refresh actor"): require_text(
            version, "session refresh version"
        )
        for actor, version in goal["startingAuthority"]["sessionRefreshVersions"].items()
    }
    for actor in actor_refs:
        if actor not in goal["startingAuthority"]["permissionVersions"] or actor not in goal["startingAuthority"]["sessionRefreshVersions"]:
            raise WebContractError(
                "every attacker actor requires distinct permission and session refresh versions"
            )
    if family == "paired-concurrent-steps" and goal["approvedLimits"]["allowConcurrency"] is not True:
        raise WebContractError("paired concurrency requires an explicit concurrency budget")
    if family != "paired-concurrent-steps" and goal["approvedLimits"]["allowConcurrency"] is True:
        raise WebContractError("concurrency must remain disabled outside its explicit family")
    return goal


def producer_map(operations: dict[str, dict[str, Any]]) -> dict[str, str]:
    result = {}
    for operation in operations.values():
        for value in operation["produces"]:
            result[value["id"]] = operation["id"]
    return result


def history_change_operation_ids(change: dict[str, Any]) -> set[str]:
    values = []
    for field in ("operationId", "producerOperationId", "consumerOperationId"):
        if change.get(field):
            values.append(str(change[field]))
    values.extend(map(str, change.get("interactionOperationIds", [])))
    return set(values)


def backward_relevant_operations(
    operations: dict[str, dict[str, Any]], goal: dict[str, Any]
) -> set[str]:
    produced_by = producer_map(operations)
    relevant = {
        str(goal["forbiddenTerminal"]["consumerOperationId"]),
        *goal["candidateOperationIds"],
        *history_change_operation_ids(goal["historyChange"]),
    }
    queue = list(relevant)
    while queue:
        operation_id = queue.pop()
        operation = operations.get(operation_id)
        if operation is None:
            raise WebContractError(f"goal references unknown operation: {operation_id}")
        dependencies = set(operation["ordering"]["after"])
        dependencies.update(
            producer_map(operations).get(value["id"], "")
            for value in operation["consumes"]
        )
        dependencies.update(
            ref
            for ref in requirement_refs(operation["requires"])
            if ref in operations
        )
        for dependency in dependencies.difference({""}):
            if dependency not in relevant:
                relevant.add(dependency)
                queue.append(dependency)
    return relevant


def initial_state(goal: dict[str, Any]) -> dict[str, Any]:
    limits = goal["approvedLimits"]
    reserved = goal.get(
        "fixedExecutionCost",
        {
            "pathLength": 0,
            "requests": 0,
            "polling": 0,
            "wallSeconds": 0,
            "stateChangingEffects": 0,
        },
    )
    return {
        "sequence": [],
        "actors": list(goal["startingAuthority"]["actorRefs"]),
        "resources": goal["startingAuthority"]["resources"],
        "serverValues": list(goal["startingAuthority"]["serverValueRefs"]),
        "invalidatedValues": list(goal["startingAuthority"]["invalidatedValueRefs"]),
        "consumptionCounts": dict(goal["startingAuthority"]["consumptionCounts"]),
        "capabilities": list(goal["startingAuthority"]["capabilityRefs"]),
        "permissionVersions": goal["startingAuthority"]["permissionVersions"],
        "sessionRefreshVersions": goal["startingAuthority"]["sessionRefreshVersions"],
        "relationships": {
            key: value["relationship"]
            for key, value in goal["startingAuthority"]["resources"].items()
        },
        "completedOperations": sorted(set(goal.get("normalOperationIds", []))),
        "executionCounts": dict(goal.get("normalOperationCounts", {})),
        "lastActor": goal.get("normalLastActor"),
        "orderingTrace": list(goal.get("normalOrderingTrace", [])),
        "historyChangeUsed": False,
        "historyChangeEvidence": [],
        "observationEpoch": goal["forbiddenTerminal"]["observationEpoch"],
        "remaining": {
            "pathLength": int(limits["maxPathLength"]) - int(reserved["pathLength"]),
            "requests": int(limits["maxRequests"]) - int(reserved["requests"]),
            "polling": int(limits["maxPolling"]) - int(reserved["polling"]),
            "wallSeconds": int(limits["maxWallSeconds"]) - int(reserved["wallSeconds"]),
            "stateChangingEffects": int(limits["maxStateChangingEffects"])
            - int(reserved["stateChangingEffects"]),
        },
    }


def resource_compatible(operation: dict[str, Any], state: dict[str, Any]) -> bool:
    for binding in operation["resourceBindings"]:
        actual = state["resources"].get(binding["id"])
        if actual is None:
            return False
        if any(
            str(actual[field]) != str(binding[field])
            for field in ("tenant", "owner", "version", "generation")
        ):
            return False
    return True


def requirement_status(requirement: dict[str, Any], state: dict[str, Any]) -> tuple[bool, set[str]]:
    if requirement["operator"] == "fact":
        ref = str(requirement["ref"])
        fact_type = requirement["type"]
        if fact_type == "operation":
            observed = ref in state["completedOperations"]
        elif fact_type == "server-value":
            observed = ref in state["serverValues"] and ref not in state["invalidatedValues"]
        elif fact_type == "approval":
            observed = ref in state["capabilities"]
        elif fact_type == "relationship":
            observed = ref in state["relationships"].values()
        elif fact_type in {"capability", "authority"}:
            observed = ref in state["capabilities"]
        else:
            observed = ref in state["capabilities"]
        satisfied = observed == requirement.get("expected", True)
        return satisfied, set() if satisfied else {ref}
    rows = [requirement_status(value, state) for value in requirement["clauses"]]
    if requirement["operator"] == "and":
        return all(value[0] for value in rows), set().union(*(value[1] for value in rows))
    if any(value[0] for value in rows):
        return True, set()
    return False, set().union(*(value[1] for value in rows))


def independent(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_resources = {value["id"] for value in left["resourceBindings"]}
    right_resources = {value["id"] for value in right["resourceBindings"]}
    if left_resources.intersection(right_resources):
        return False
    left_values = {value["id"] for value in [*left["produces"], *left["consumes"], *left["invalidates"]]}
    right_values = {value["id"] for value in [*right["produces"], *right["consumes"], *right["invalidates"]]}
    if left_values.intersection(right_values):
        return False
    if right["id"] in left["ordering"]["after"] or left["id"] in right["ordering"]["after"]:
        return False
    return True


def history_change_after(
    change: dict[str, Any],
    operation: dict[str, Any],
    state: dict[str, Any],
    missing: set[str],
    semantics: dict[str, Any],
) -> tuple[bool, list[str]]:
    kind = change["kind"]
    evidence: list[str] = []
    used = bool(state["historyChangeUsed"])
    sequence = state["sequence"]
    if kind == "omitted-prerequisite":
        reference = str(change.get("reference") or "")
        if reference and reference in missing and operation["id"] == change.get("operationId"):
            used = True
            evidence.append(f"omitted:{reference}")
    elif kind == "repeated-operation":
        if operation["id"] == change.get("operationId") and state["executionCounts"].get(operation["id"], 0) >= 1:
            used = True
            evidence.append(f"repeated:{operation['id']}")
    elif kind == "actor-transition":
        if state["lastActor"] == change.get("fromActor") and operation["actorRef"]["id"] == change.get("toActor"):
            used = True
            evidence.append(f"actor:{state['lastActor']}->{operation['actorRef']['id']}")
    elif kind == "changed-relationship":
        reference = str(change.get("reference") or "")
        transition_ids = {
            value["resourceId"] for value in semantics.get("resourceTransitions", [])
        }
        if reference and (
            reference in transition_ids
            or any(
                value["id"] == reference
                for value in [*operation["produces"], *operation["invalidates"]]
            )
        ):
            used = True
            evidence.append(f"relationship:{reference}")
    elif kind == "delayed-consumption":
        producer = str(change.get("producerOperationId") or "")
        consumer = str(change.get("consumerOperationId") or "")
        if operation["id"] == consumer and producer in sequence:
            producer_index = sequence.index(producer)
            if len(sequence) - producer_index > 1:
                used = True
                evidence.append(f"delayed:{producer}->{consumer}")
    elif kind == "alternate-consumer":
        reference = str(change.get("reference") or "")
        if reference and any(value["id"] == reference for value in operation["consumes"]):
            prior = int(state["consumptionCounts"].get(reference, 0))
            if prior >= 1 and operation["id"] == change.get("consumerOperationId"):
                used = True
                evidence.append(f"alternate-consumer:{reference}")
    elif kind == "paired-concurrent-steps":
        pair = list(map(str, change.get("interactionOperationIds", [])))
        if len(pair) == 2 and [*sequence[-1:], operation["id"]] == pair:
            used = True
            evidence.append("paired:" + "+".join(pair))
    return used, evidence


def operation_cost(operation: dict[str, Any]) -> dict[str, int]:
    return {
        "pathLength": 1,
        "requests": int(operation["cost"]["maxRequests"]),
        "polling": int(operation["cost"]["maxPolling"]),
        "wallSeconds": int(operation["consistencyWindow"]["maximumSeconds"]),
        "stateChangingEffects": int(operation["cost"]["maxEffects"]),
    }


def apply_operation(
    state: dict[str, Any], operation: dict[str, Any], goal: dict[str, Any]
) -> dict[str, Any] | None:
    semantics = goal["operationSemantics"].get(operation["id"])
    if not semantics or semantics["attackerCanAttempt"] is not True:
        return None
    if operation["actorRef"]["id"] not in state["actors"]:
        return None
    actor_id = operation["actorRef"]["id"]
    identity_transition = operation.get("identityTransition")
    if identity_transition:
        if (
            state["sessionRefreshVersions"].get(actor_id)
            != identity_transition["fromSessionRefreshVersion"]
            or state["permissionVersions"].get(actor_id)
            != identity_transition["permissionVersionBefore"]
            or operation["actorRef"]["sessionRefreshVersion"]
            != identity_transition["fromSessionRefreshVersion"]
        ):
            return None
    elif (
        state["sessionRefreshVersions"].get(actor_id)
        != operation["actorRef"]["sessionRefreshVersion"]
        or state["permissionVersions"].get(actor_id)
        != operation["actorRef"]["permissionVersion"]
    ):
        return None
    if not resource_compatible(operation, state):
        return None
    for transition in semantics["resourceTransitions"]:
        actual = state["resources"].get(transition["resourceId"])
        if actual is None or any(
            str(actual[field]) != str(transition["from"][field])
            for field in ("tenant", "owner", "version", "generation", "relationship")
        ):
            return None
    for transition in semantics["permissionTransitions"]:
        if str(state["permissionVersions"].get(transition["actorRef"], "")) != transition["from"]:
            return None
    cost = operation_cost(operation)
    if any(state["remaining"][field] < value for field, value in cost.items()):
        return None
    count = int(state["executionCounts"].get(operation["id"], 0))
    if count >= int(goal["approvedLimits"]["maxExecutionsPerOperation"]):
        return None
    satisfied, missing = requirement_status(operation["requires"], state)
    allowed_missing = set(goal["counterfactualExceptions"]["unsatisfiedRequirementRefs"])
    if not satisfied and not missing.issubset(allowed_missing):
        return None
    produced_values = {value["id"]: value for value in operation["produces"]}
    for value in operation["consumes"]:
        reference = value["id"]
        if reference not in state["serverValues"]:
            return None
        if reference in state["invalidatedValues"] and reference not in set(
            goal["counterfactualExceptions"]["invalidatedValueRefs"]
        ):
            return None
        if int(state["consumptionCounts"].get(reference, 0)) >= 1 and reference not in set(
            goal["counterfactualExceptions"]["replayedValueRefs"]
        ):
            return None
    updated = json.loads(json.dumps(state))
    updated["sequence"].append(operation["id"])
    updated["completedOperations"].append(operation["id"])
    updated["executionCounts"][operation["id"]] = count + 1
    updated["lastActor"] = operation["actorRef"]["id"]
    if operation["id"] in goal["orderingOperationIds"]:
        updated["orderingTrace"].append(operation["id"])
    for field, value in cost.items():
        updated["remaining"][field] -= value
    for reference in produced_values:
        if reference not in updated["serverValues"]:
            updated["serverValues"].append(reference)
    for value in operation["produces"]:
        if value["kind"] in {"approval", "capability"} and value["id"] not in updated["capabilities"]:
            updated["capabilities"].append(value["id"])
        if value["kind"] == "relationship":
            updated["relationships"][value["resourceBinding"]] = value["id"]
    for value in operation["consumes"]:
        updated["consumptionCounts"][value["id"]] = int(
            updated["consumptionCounts"].get(value["id"], 0)
        ) + 1
    for value in operation["invalidates"]:
        if value["id"] not in updated["invalidatedValues"]:
            updated["invalidatedValues"].append(value["id"])
    for transition in semantics["resourceTransitions"]:
        resource_id = transition["resourceId"]
        updated["resources"][resource_id].update(transition["to"])
        updated["relationships"][resource_id] = transition["to"]["relationship"]
    for transition in semantics["permissionTransitions"]:
        updated["permissionVersions"][transition["actorRef"]] = transition["to"]
    if identity_transition:
        updated["sessionRefreshVersions"][actor_id] = identity_transition[
            "toSessionRefreshVersion"
        ]
    changed, evidence = history_change_after(
        goal["historyChange"], operation, state, missing, semantics
    )
    updated["historyChangeUsed"] = changed
    updated["historyChangeEvidence"].extend(evidence)
    for field in ("serverValues", "invalidatedValues", "capabilities", "completedOperations"):
        updated[field] = sorted(set(updated[field]))
    return updated


def semantic_core(state: dict[str, Any]) -> str:
    return canonical(
        {
            "actors": state["actors"],
            "resources": state["resources"],
            "serverValues": state["serverValues"],
            "invalidatedValues": state["invalidatedValues"],
            "consumptionCounts": state["consumptionCounts"],
            "capabilities": state["capabilities"],
            "permissionVersions": state["permissionVersions"],
            "sessionRefreshVersions": state["sessionRefreshVersions"],
            "relationships": state["relationships"],
            "completedOperations": state["completedOperations"],
            "executionCounts": state["executionCounts"],
            "lastActor": state["lastActor"],
            "orderingTrace": state.get("orderingTrace", []),
            "historyChangeUsed": state["historyChangeUsed"],
            "observationEpoch": state["observationEpoch"],
        }
    )


def state_key(state: dict[str, Any]) -> str:
    return digest({"semantic": semantic_core(state), "remaining": state["remaining"]})


def dominates(left: dict[str, int], right: dict[str, int]) -> bool:
    return all(int(left[field]) >= int(right[field]) for field in left)


def terminal_reached(state: dict[str, Any], goal: dict[str, Any]) -> bool:
    terminal = goal["forbiddenTerminal"]
    resource = state["resources"].get(terminal["resourceId"])
    exact_resource = resource is not None and all(
        str(resource[field]) == str(terminal[field])
        for field in ("tenant", "owner", "version", "generation")
    )
    return bool(
        state["sequence"]
        and state["sequence"][-1] == terminal["consumerOperationId"]
        and state["historyChangeUsed"]
        and exact_resource
    )


def causal_minimization(
    sequence: list[str], operations: dict[str, dict[str, Any]], goal: dict[str, Any]
) -> list[dict[str, Any]]:
    required = {
        str(goal["forbiddenTerminal"]["consumerOperationId"]),
        *history_change_operation_ids(goal["historyChange"]),
    }
    produced_by = producer_map(operations)
    for operation_id in sequence:
        operation = operations[operation_id]
        for value in operation["consumes"]:
            if value["id"] in produced_by:
                required.add(produced_by[value["id"]])
    return [
        {
            "operationId": value,
            "status": "requires-fresh-counterfactual-replay",
            "preserve": [
                "forbidden terminal effect",
                "authenticated starting authority",
                "resource owner, tenant, version, and generation",
                "single-use consumption counts",
                "permission versions and observation epoch",
                "relevant ordering and timing",
            ],
        }
        for value in sequence
        if value not in required
    ]


def verify_resume_budget(
    goal: dict[str, Any], resume: dict[str, Any], resume_path: Path
) -> None:
    if resume.get("goalId") != goal["id"] or resume.get("prerequisiteVersion") != goal["prerequisiteVersion"]:
        raise WebContractError("resume checkpoint belongs to a different goal or deployment")
    previous = resume.get("approvedLimits")
    if previous == goal["approvedLimits"]:
        return
    extension = goal.get("reviewedBudgetExtension")
    if not isinstance(extension, dict) or extension.get("approved") is not True:
        raise WebContractError("changed search limits require a reviewed budget extension")
    expected = hashlib.sha256(resume_path.read_bytes()).hexdigest()
    if extension.get("previousCheckpointSha256") != expected:
        raise WebContractError("budget extension does not bind the previous checkpoint")
    for field in ("approvedBy", "reason"):
        require_text(extension.get(field), f"reviewedBudgetExtension.{field}")


def build_sequence_specification(
    sequence_id: str,
    attack_sequence: list[str],
    counterfactual_sequence: list[str],
    histories: dict[str, list[str]],
    operations: dict[str, dict[str, Any]],
    goal: dict[str, Any],
) -> dict[str, Any]:
    selected_ids = list(dict.fromkeys(
        operation_id
        for history in histories.values()
        for operation_id in history
    ))
    selected = [operations[operation_id] for operation_id in selected_ids]
    actors = {}
    fixtures = {}
    for operation in selected:
        actor = operation["actorRef"]
        if actor.get("authorityVersionsExplicit") is not True:
            raise WebContractError(
                "forbidden-composition evidence requires explicit session refresh and permission versions"
            )
        actors[actor["id"]] = {
            "id": actor["id"],
            "role": actor["role"],
            "tenant": actor["tenant"],
            "session": actor["session"],
            "effectiveActor": actor["effectiveActor"],
            "sessionRefreshVersion": actor["sessionRefreshVersion"],
            "permissionVersion": actor["permissionVersion"],
            "verified": True,
        }
        for resource in operation["resourceBindings"]:
            fixtures[resource["id"]] = dict(resource)
    producer_by_value = {
        value["id"]: (operation, value)
        for operation in selected
        for value in operation["produces"]
    }
    value_edges = []
    for value_id, (producer, value) in sorted(producer_by_value.items()):
        if value.get("lifecycleExplicit") is not True:
            raise WebContractError(
                f"server value {value_id} lacks issuer, consumer, expiry, or single-use evidence"
            )
        consumers = [
            operation["id"]
            for operation in selected
            if any(consumed["id"] == value_id for consumed in operation["consumes"])
        ]
        value_edges.append(
            {
                "valueId": value_id,
                "kind": value["kind"],
                "producerOperationId": producer["id"],
                "consumerOperationIds": consumers,
                "issuer": value["issuer"],
                "intendedConsumer": value["intendedConsumer"],
                "resourceBinding": value["resourceBinding"],
                "version": value["version"],
                "expiryPolicy": value["expiryPolicy"],
                "expiryValue": value["expiryValue"],
                "singleUse": value["singleUse"],
                "transferPolicy": value["transferPolicy"],
                "invalidationOperationIds": [
                    operation["id"]
                    for operation in selected
                    if any(item["id"] == value_id for item in operation["invalidates"])
                ],
            }
        )
    steps = []
    for operation in selected:
        semantics = goal["operationSemantics"].get(operation["id"])
        steps.append(
            {
                "operationId": operation["id"],
                "actor": operation["actorRef"],
                "action": operation["actionRef"],
                "resources": operation["resourceBindings"],
                "guards": operation["requires"],
                "authorityBinding": operation["authorityBinding"],
                "effectBudget": operation["cost"],
                "ordering": operation["ordering"],
                "asyncWait": operation.get("asyncWait"),
                "identityTransition": operation.get("identityTransition"),
                "applicationPermissionTransitions": (
                    semantics["permissionTransitions"] if semantics else []
                ),
                "resourceTransitions": semantics["resourceTransitions"] if semantics else [],
                "observations": operation["observations"],
                "referenceExpectation": (
                    {
                        "policy": semantics["referencePolicy"],
                        "evidence": semantics["evidence"],
                    }
                    if semantics
                    else {
                        "policy": "allowed-control",
                        "evidence": goal["legitimateReplay"]["policyEvidence"],
                    }
                ),
                "implementationObservation": "runtime-required",
            }
        )
    partial_order = [
        {
            "before": predecessor,
            "after": operation["id"],
            "confidence": operation["ordering"]["dependencyConfidence"],
            "evidence": operation["ordering"]["evidence"],
        }
        for operation in selected
        for predecessor in operation["ordering"]["after"]
        if predecessor in selected_ids
    ]
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-sequence-specification",
        "sequenceId": sequence_id,
        "mechanismId": goal["id"],
        "prerequisiteVersion": goal["prerequisiteVersion"],
        "observationEpoch": goal["forbiddenTerminal"]["observationEpoch"],
        "verifiedContext": {
            "actors": list(actors.values()),
            "tenants": sorted({value["tenant"] for value in actors.values()}),
            "fixtures": list(fixtures.values()),
            "initialAuthority": {
                **goal["startingAuthority"],
                "permissionVersions": {
                    actor_id: actor["permissionVersion"]
                    for actor_id, actor in actors.items()
                },
                "sessionRefreshVersions": {
                    actor_id: actor["sessionRefreshVersion"]
                    for actor_id, actor in actors.items()
                },
            },
        },
        "invariant": {
            "legitimateBaseline": goal["normalHistory"],
            "legitimateReplayEvidence": goal["legitimateReplay"],
            "basis": goal["forbiddenTerminal"]["policyBasis"],
            "goalPredicate": {
                "prohibitedEffect": goal["forbiddenTerminal"]["prohibitedEffect"],
                "stateOracleId": goal["stateOracle"]["id"],
                "observerOperationId": goal["forbiddenTerminal"]["observerOperationId"],
                "resourceId": goal["forbiddenTerminal"]["resourceId"],
            },
        },
        "histories": {
            "legitimate": goal["normalHistory"],
            "disputed": counterfactual_sequence,
            "controls": [
                {
                    **control,
                    "historyKey": f"control-{control['id']}",
                }
                for control in goal["controlHistories"]
            ],
        },
        "partialOrder": partial_order,
        "steps": steps,
        "valueExtractionEdges": value_edges,
        "transitionObservationRequirements": [
            {
                "operationId": operation["id"],
                "beforeEvidenceRefs": goal["legitimateReplay"]["beforeStateEvidence"],
                "afterObservationIds": [value["id"] for value in operation["observations"]],
            }
            for operation in selected
            if operation["actionRef"]["effectClass"] == "disposable-write"
            or operation["produces"]
            or operation["invalidates"]
            or operation["id"] in attack_sequence
        ],
        "competingExplanations": goal["competingExplanations"],
        "primitiveContributions": goal["primitiveContributions"],
        "minimalSuccessfulWitness": {
            "operationIds": attack_sequence,
            "status": "search-minimal; runtime and independent causal replay required",
            "prefixMayContainSeparateIssue": True,
        },
        "cleanup": [
            {
                "operationId": operation["id"],
                "hookRef": operation["cleanup"].get("hookRef"),
                "irreversible": operation["cleanup"].get("irreversible", False),
            }
            for operation in selected
            if operation["actionRef"]["effectClass"] == "disposable-write"
        ],
        "independentReplayRequirements": goal["independentReplayRequirements"],
        "approvedLimits": goal["approvedLimits"],
    }


def build_plan(
    sequence: list[str],
    operations: dict[str, dict[str, Any]],
    graph: dict[str, Any],
    goal: dict[str, Any],
) -> dict[str, Any]:
    normal = next(
        value for value in graph["plans"] if value["id"] == goal["normalPlanId"]
    )
    counterfactual_sequence = [
        *goal["normalHistory"],
        *sequence,
        goal["forbiddenTerminal"]["observerOperationId"],
    ]
    selected = [operations[value] for value in counterfactual_sequence]
    required_observations = set(goal["stateOracle"]["requiredObservations"])
    available_observations = {
        observation["id"]
        for operation in selected
        for observation in operation["observations"]
    }
    missing_observations = required_observations.difference(available_observations)
    if missing_observations:
        raise WebContractError(
            "generated history does not execute required oracle observations: "
            + ", ".join(sorted(missing_observations))
        )
    plan_id = stable_id("WFC", [goal["id"], sequence, goal["prerequisiteVersion"]])
    histories = {
        "normal": goal["normalHistory"],
        "counterfactual": counterfactual_sequence,
        **{
            f"control-{control['id']}": control["operationIds"]
            for control in goal["controlHistories"]
        },
    }
    specification = build_sequence_specification(
        plan_id,
        sequence,
        counterfactual_sequence,
        histories,
        operations,
        goal,
    )
    return {
        "id": plan_id,
        "hypothesisId": goal["id"],
        "family": (
            "bounded-concurrency"
            if goal["compositionFamily"] == "paired-concurrent-steps"
            else goal["compositionFamily"]
        ),
        "prerequisiteVersion": goal["prerequisiteVersion"],
        "executionState": normal["executionState"],
        "histories": histories,
        "cost": {
            "normal": normal["cost"]["normal"],
            "counterfactual": sum_cost(selected),
        },
        "stateOracle": goal["stateOracle"],
        "executable": True,
        "blockedReason": None,
        "counterfactualExceptions": goal["counterfactualExceptions"],
        "requiredEvidence": [
            "legitimate workflow replay",
            "forbidden terminal independent readback",
            "same fixture epoch and concrete bindings",
        ],
        "cleanupRequired": any(
            value["actionRef"]["effectClass"] == "disposable-write"
            for value in selected
        ),
        "approvedLimits": goal["approvedLimits"],
        "minimizationCandidates": {
            "normal": [],
            "counterfactual": causal_minimization(sequence, operations, goal),
        },
        "mechanismScope": "single-step" if len(sequence) == 1 else "composition",
        "attackerSequence": sequence,
        "observerOperationId": goal["forbiddenTerminal"]["observerOperationId"],
        "sequenceSpecification": specification,
        "sequenceSpecificationSha256": digest(specification),
    }


def search(
    graph: dict[str, Any],
    raw_goal: dict[str, Any],
    *,
    resume: dict[str, Any] | None = None,
    resume_path: Path | None = None,
) -> dict[str, Any]:
    if graph.get("kind") != "krineon-web-sequence-graph":
        raise WebContractError("input is not a Krineon web sequence graph")
    goal = validate_goal(raw_goal, graph)
    operations = {
        value["id"]: validate_operation(value) for value in graph.get("operations", [])
    }
    relevant = backward_relevant_operations(operations, goal)
    explicitly_ordered = {
        operation_id
        for operation_id in relevant
        if operations[operation_id]["ordering"]["after"]
        or operations[operation_id]["ordering"]["before"]
    }
    for operation_id in relevant:
        explicitly_ordered.update(operations[operation_id]["ordering"]["after"])
        explicitly_ordered.update(operations[operation_id]["ordering"]["before"])
    explicitly_ordered.update(history_change_operation_ids(goal["historyChange"]))
    goal["orderingOperationIds"] = sorted(explicitly_ordered.intersection(operations))
    fixed_operation_ids = [
        *goal["normalHistory"],
        goal["forbiddenTerminal"]["observerOperationId"],
    ]
    fixed_operations = [operations[operation_id] for operation_id in fixed_operation_ids]
    goal["fixedExecutionCost"] = {
        "pathLength": len(fixed_operations),
        "requests": sum(int(value["cost"]["maxRequests"]) for value in fixed_operations),
        "polling": sum(int(value["cost"]["maxPolling"]) for value in fixed_operations),
        "wallSeconds": sum(
            int(value["consistencyWindow"]["maximumSeconds"])
            for value in fixed_operations
        ),
        "stateChangingEffects": sum(
            int(value["cost"]["maxEffects"]) for value in fixed_operations
        ),
    }
    complete_limits = {
        "pathLength": int(goal["approvedLimits"]["maxPathLength"]),
        "requests": int(goal["approvedLimits"]["maxRequests"]),
        "polling": int(goal["approvedLimits"]["maxPolling"]),
        "wallSeconds": int(goal["approvedLimits"]["maxWallSeconds"]),
        "stateChangingEffects": int(goal["approvedLimits"]["maxStateChangingEffects"]),
    }
    exceeded = [
        field
        for field, value in goal["fixedExecutionCost"].items()
        if value > complete_limits[field]
    ]
    if exceeded:
        raise WebContractError(
            "normal controls and terminal observer exceed approved experiment limits: "
            + ", ".join(sorted(exceeded))
        )
    normal_counts: dict[str, int] = {}
    for operation_id in goal["normalHistory"]:
        normal_counts[operation_id] = normal_counts.get(operation_id, 0) + 1
    if any(
        count > int(goal["approvedLimits"]["maxExecutionsPerOperation"])
        for count in normal_counts.values()
    ):
        raise WebContractError("the legitimate control exceeds the per-operation execution limit")
    goal["normalOperationIds"] = list(goal["normalHistory"])
    goal["normalOperationCounts"] = normal_counts
    goal["normalLastActor"] = operations[goal["normalHistory"][-1]]["actorRef"]["id"]
    goal["normalOrderingTrace"] = [
        operation_id
        for operation_id in goal["normalHistory"]
        if operation_id in goal["orderingOperationIds"]
    ]
    allowed = [operations[value] for value in sorted(relevant)]
    if resume is not None:
        if resume_path is None:
            raise WebContractError("resume path is required")
        verify_resume_budget(goal, resume, resume_path)
        frontier_states = resume.get("frontier", [])
        if not isinstance(frontier_states, list):
            raise WebContractError("resume frontier must be an array")
        prior_outcomes = validate_prior_outcomes(resume.get("outcomes", []))
    else:
        frontier_states = [initial_state(goal)]
        prior_outcomes = list(goal.get("priorOutcomes", []))
    queue: list[tuple[int, str, int, dict[str, Any]]] = []
    serial = 0
    for state in frontier_states:
        state.setdefault("orderingTrace", [])
        heapq.heappush(queue, (len(state["sequence"]), state_key(state), serial, state))
        serial += 1
    budget_frontiers: dict[str, list[dict[str, int]]] = {}
    explored: set[str] = set()
    candidates: list[dict[str, Any]] = []
    refuted_state_keys = {
        value["stateKey"]
        for value in prior_outcomes
        if value.get("outcome") == "refuted"
        and value.get("prerequisiteVersion") == goal["prerequisiteVersion"]
    }
    suppressed_refutations: list[str] = []
    truncated = False
    max_states = int(goal["approvedLimits"]["maxFrontierStates"])
    while queue and len(explored) < max_states:
        _, key, _, state = heapq.heappop(queue)
        if key in explored:
            continue
        explored.add(key)
        core = semantic_core(state)
        budgets = budget_frontiers.setdefault(core, [])
        if any(dominates(value, state["remaining"]) for value in budgets):
            continue
        budgets[:] = [
            value for value in budgets if not dominates(state["remaining"], value)
        ]
        budgets.append(dict(state["remaining"]))
        if terminal_reached(state, goal):
            if key in refuted_state_keys:
                suppressed_refutations.append(key)
                continue
            candidates.append(
                {
                    "sequence": state["sequence"],
                    "historyChangeEvidence": state["historyChangeEvidence"],
                    "stateKey": key,
                    "remaining": state["remaining"],
                }
            )
            continue
        for operation in allowed:
            if state["sequence"]:
                previous = operations[state["sequence"][-1]]
                if (
                    independent(previous, operation)
                    and operation["id"] < previous["id"]
                    and previous["id"] not in goal["orderingOperationIds"]
                    and operation["id"] not in goal["orderingOperationIds"]
                ):
                    continue
            updated = apply_operation(state, operation, goal)
            if updated is None:
                continue
            heapq.heappush(
                queue,
                (len(updated["sequence"]), state_key(updated), serial, updated),
            )
            serial += 1
    if queue:
        truncated = True
    retained_frontier = [item[3] for item in sorted(queue)[:max_states]]
    unique_candidates = {}
    for value in candidates:
        unique_candidates[tuple(value["sequence"])] = value
    candidates = sorted(
        unique_candidates.values(), key=lambda value: (len(value["sequence"]), value["sequence"])
    )
    plans = [
        build_plan(value["sequence"], operations, graph, goal)
        for value in candidates
    ]
    for plan, candidate in zip(plans, candidates, strict=True):
        plan["searchStateKey"] = candidate["stateKey"]
        plan["historyChangeEvidence"] = candidate["historyChangeEvidence"]
    next_experiment = None
    if plans:
        next_experiment = {
            "planId": plans[0]["id"],
            "question": COMPOSITION_FAMILIES[goal["compositionFamily"]],
            "changedHistory": goal["historyChange"],
            "terminal": goal["forbiddenTerminal"],
            "approvedLimits": goal["approvedLimits"],
        }
    elif retained_frontier:
        next_experiment = {
            "kind": "checkpoint-continuation",
            "question": "Continue the highest-value backward-relevant semantic frontier",
            "frontierStateKey": state_key(retained_frontier[0]),
            "requiresReviewedBudgetExtension": truncated,
        }
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-forbidden-composition-frontier",
        "profile": "web-app",
        "web": {"forbiddenComposition": True},
        "goalId": goal["id"],
        "goalHash": digest(goal),
        "prerequisiteVersion": goal["prerequisiteVersion"],
        "compositionFamily": goal["compositionFamily"],
        "forbiddenTerminal": goal["forbiddenTerminal"],
        "legitimateNormalHistory": goal["normalHistory"],
        "legitimateReplay": goal["legitimateReplay"],
        "approvedLimits": goal["approvedLimits"],
        "fixedExecutionCost": goal["fixedExecutionCost"],
        "operations": list(operations.values()),
        "backwardRelevantOperationIds": sorted(relevant),
        "plans": plans,
        "frontier": retained_frontier,
        "outcomes": prior_outcomes,
        "knowledge": {
            "confirmed": sum(value["outcome"] == "confirmed" for value in prior_outcomes),
            "refuted": sum(value["outcome"] == "refuted" for value in prior_outcomes),
            "inconclusive": sum(value["outcome"] == "inconclusive" for value in prior_outcomes),
            "exactRefutationsSuppressed": sorted(set(suppressed_refutations)),
        },
        "nextExperiment": next_experiment,
        "experimentCandidates": [
            {
                "id": plan["id"],
                "kind": "forbidden-composition",
                "question": COMPOSITION_FAMILIES[goal["compositionFamily"]],
                "executableOracle": goal["stateOracle"]["id"],
                "approvedLimits": goal["approvedLimits"],
                "forbiddenTerminal": goal["forbiddenTerminal"],
            }
            for plan in plans
        ],
        "semanticIRAdapter": {
            "facts": [
                {
                    "kind": "forbidden-terminal",
                    "goalId": goal["id"],
                    "consumerOperationId": goal["forbiddenTerminal"]["consumerOperationId"],
                    "resourceId": goal["forbiddenTerminal"]["resourceId"],
                    "observationEpoch": goal["forbiddenTerminal"]["observationEpoch"],
                }
            ],
            "relations": [
                {
                    "kind": "backward-relevant-operation",
                    "from": goal["id"],
                    "to": operation_id,
                }
                for operation_id in sorted(relevant)
            ],
            "hypotheses": [
                {
                    "id": goal["id"],
                    "status": "runtime-experiment-required",
                    "stateOracleId": goal["stateOracle"]["id"],
                }
            ],
        },
        "search": {
            "algorithm": "backward-relevance+forward-authority+semantic-dominance+partial-order-reduction",
            "exploredStates": len(explored),
            "candidateHistories": len(plans),
            "truncated": truncated,
            "resumable": bool(retained_frontier),
            "arbitraryPermutationSearch": False,
        },
        "policy": {
            "sameConcreteBindingsRequired": True,
            "sameObservationEpochRequired": True,
            "implementationDecidesAttemptOutcome": True,
            "independentTerminalReadbackRequired": True,
            "partialCapabilitiesRetained": True,
            "causalMinimizationOnly": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument("goal", type=Path)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = search(
            load_object(args.graph),
            load_object(args.goal),
            resume=load_object(args.resume) if args.resume else None,
            resume_path=args.resume,
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(
            json.dumps(
                {
                    "goalId": result["goalId"],
                    "candidateHistories": result["search"]["candidateHistories"],
                    "truncated": result["search"]["truncated"],
                },
                indent=2,
            )
        )
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
