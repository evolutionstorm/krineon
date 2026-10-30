#!/usr/bin/env python3
"""Build a typed capability graph and emit concrete missing-link experiments."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import heapq
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


BOUNDARY_OPERATIONS = {
    "data-to-executable-behavior",
    "privileged-function-or-module-selection",
    "managed-native-ownership-crossing",
    "lower-trust-to-higher-trust-execution",
    "program-defined-critical-authority",
}

PROGRESS_MILESTONES = {
    "invariant-violation-reproduced",
    "attacker-capability-controlled",
    "new-consumer-reached",
    "acquisition-prerequisite-resolved",
    "compatible-primitives-connected",
    "chain-precondition-confirmed",
    "chain-precondition-falsified",
}

CONTEXT_FIELDS = ("principal", "process", "namespace", "runtime")


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{field} must be non-empty text")
    return value.strip()


def require_text_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise RuntimeError(f"{field} must be a{' possibly empty' if allow_empty else ' non-empty'} list")
    rows = [require_text(item, f"{field}[]") for item in value]
    return list(dict.fromkeys(rows))


def normalize_capability(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    return {
        "type": require_text(value.get("type"), f"{field}.type"),
        "properties": require_text_list(
            value.get("properties", []), f"{field}.properties", allow_empty=True
        ),
        "limitations": require_text_list(
            value.get("limitations", []), f"{field}.limitations", allow_empty=True
        ),
        "forbiddenLimitations": require_text_list(
            value.get("forbiddenLimitations", []),
            f"{field}.forbiddenLimitations",
            allow_empty=True,
        ),
    }


def normalize_state_sequence(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    initial = require_text(value.get("initialState"), f"{field}.initialState")
    transitions = value.get("transitions")
    if not isinstance(transitions, list):
        raise RuntimeError(f"{field}.transitions must be a list")
    normalized: list[dict[str, Any]] = []
    prior = initial
    identifiers: set[str] = set()
    for index, transition in enumerate(transitions):
        prefix = f"{field}.transitions[{index}]"
        if not isinstance(transition, dict):
            raise RuntimeError(f"{prefix} must be an object")
        identifier = require_text(transition.get("id"), f"{prefix}.id")
        if identifier in identifiers:
            raise RuntimeError(f"{prefix}.id is duplicated")
        before = require_text(transition.get("from"), f"{prefix}.from")
        after = require_text(transition.get("to"), f"{prefix}.to")
        if before != prior:
            raise RuntimeError(
                f"{prefix}.from must continue the preceding state {prior!r}"
            )
        normalized.append(
            {
                "id": identifier,
                "operation": require_text(
                    transition.get("operation"), f"{prefix}.operation"
                ),
                "from": before,
                "to": after,
                "authorityBefore": require_text(
                    transition.get("authorityBefore"),
                    f"{prefix}.authorityBefore",
                ),
                "authorityAfter": require_text(
                    transition.get("authorityAfter"), f"{prefix}.authorityAfter"
                ),
                "ownershipBefore": require_text(
                    transition.get("ownershipBefore"),
                    f"{prefix}.ownershipBefore",
                ),
                "ownershipAfter": require_text(
                    transition.get("ownershipAfter"),
                    f"{prefix}.ownershipAfter",
                ),
                "evidence": require_text_list(
                    transition.get("evidence"), f"{prefix}.evidence"
                ),
            }
        )
        identifiers.add(identifier)
        prior = after
    preserve = require_text_list(
        value.get("reductionMustPreserve", []),
        f"{field}.reductionMustPreserve",
        allow_empty=not normalized,
    )
    return {
        "initialState": initial,
        "transitions": normalized,
        "reductionMustPreserve": preserve,
    }


def normalize_context(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    return {
        name: require_text(value.get(name), f"{field}.{name}")
        for name in CONTEXT_FIELDS
    }


def normalize_context_transition(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    preserves = value.get("preservesCapabilities", "all")
    if preserves != "all":
        preserves = require_text_list(
            preserves, f"{field}.preservesCapabilities", allow_empty=True
        )
    return {
        "from": normalize_context(value.get("from"), f"{field}.from"),
        "to": normalize_context(value.get("to"), f"{field}.to"),
        "transport": require_text(value.get("transport"), f"{field}.transport"),
        "authorityChange": require_text(
            value.get("authorityChange"), f"{field}.authorityChange"
        ),
        "preservesCapabilities": preserves,
    }


def normalize_attempt_model(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {
            "attackerCanAttempt": True,
            "referenceExpected": "allow",
            "observedOutcome": "allowed",
        }
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    expected = require_text(value.get("referenceExpected"), f"{field}.referenceExpected")
    observed = require_text(value.get("observedOutcome"), f"{field}.observedOutcome")
    if expected not in {"allow", "reject"}:
        raise RuntimeError(f"{field}.referenceExpected must be allow or reject")
    if observed not in {"unknown", "allowed", "rejected"}:
        raise RuntimeError(
            f"{field}.observedOutcome must be unknown, allowed, or rejected"
        )
    return {
        "attackerCanAttempt": bool(value.get("attackerCanAttempt", True)),
        "referenceExpected": expected,
        "observedOutcome": observed,
    }


def normalize_constraints(value: Any, field: str) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    return {
        name: require_text_list(value.get(name, []), f"{field}.{name}", allow_empty=True)
        for name in (
            "lifetime",
            "ordering",
            "deployment",
            "acquisition",
            "requiredState",
            "providedState",
            "invalidatedState",
        )
    }


def normalize_object_ref(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    generation = value.get("generation", "any")
    if not isinstance(generation, (str, int)) or generation == "":
        raise RuntimeError(f"{field}.generation must be an integer or non-empty text")
    return {
        "identity": require_text(value.get("identity"), f"{field}.identity"),
        "generation": generation,
        "state": require_text(value.get("state", "valid"), f"{field}.state"),
    }


def normalize_objects(value: Any, field: str) -> dict[str, list[dict[str, Any]]]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    result: dict[str, list[dict[str, Any]]] = {}
    for name in ("requires", "produces", "invalidates"):
        raw = value.get(name, [])
        if not isinstance(raw, list):
            raise RuntimeError(f"{field}.{name} must be a list")
        result[name] = [
            normalize_object_ref(item, f"{field}.{name}[{index}]")
            for index, item in enumerate(raw)
        ]
    return result


def normalize_progress(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    milestones = require_text_list(
        value.get("milestones", []), f"{field}.milestones", allow_empty=True
    )
    unknown = set(milestones).difference(PROGRESS_MILESTONES)
    if unknown:
        raise RuntimeError(f"{field}.milestones contains unknown values: {sorted(unknown)}")
    return {
        "milestones": milestones,
        "resolvedPreconditions": require_text_list(
            value.get("resolvedPreconditions", []),
            f"{field}.resolvedPreconditions",
            allow_empty=True,
        ),
        "falsifiedPreconditions": require_text_list(
            value.get("falsifiedPreconditions", []),
            f"{field}.falsifiedPreconditions",
            allow_empty=True,
        ),
        "connectedPrimitives": require_text_list(
            value.get("connectedPrimitives", []),
            f"{field}.connectedPrimitives",
            allow_empty=True,
        ),
        "uncertaintiesResolved": require_text_list(
            value.get("uncertaintiesResolved", []),
            f"{field}.uncertaintiesResolved",
            allow_empty=True,
        ),
    }


def normalize_measured_cost(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    wall_seconds = value.get("wallSeconds")
    executions = value.get("executions")
    if not isinstance(wall_seconds, (int, float)) or wall_seconds < 0:
        raise RuntimeError(f"{field}.wallSeconds must be non-negative")
    if not isinstance(executions, int) or executions < 1:
        raise RuntimeError(f"{field}.executions must be a positive integer")
    return {
        "wallSeconds": float(wall_seconds),
        "executions": executions,
        "evidence": require_text_list(value.get("evidence"), f"{field}.evidence"),
    }


def progress_score(progress: dict[str, Any]) -> int:
    weights = {
        "invariant-violation-reproduced": 2,
        "attacker-capability-controlled": 3,
        "new-consumer-reached": 4,
        "acquisition-prerequisite-resolved": 4,
        "compatible-primitives-connected": 6,
        "chain-precondition-confirmed": 3,
        "chain-precondition-falsified": 2,
    }
    return (
        sum(weights[value] for value in progress.get("milestones", []))
        + len(progress.get("resolvedPreconditions", []))
        + len(progress.get("falsifiedPreconditions", []))
        + 2 * len(progress.get("connectedPrimitives", []))
        + len(progress.get("uncertaintiesResolved", []))
    )


def normalize_negative_knowledge(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RuntimeError(f"{field} must be a list")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        prefix = f"{field}[{index}]"
        if not isinstance(item, dict):
            raise RuntimeError(f"{prefix} must be an object")
        rows.append(
            {
                "mechanism": require_text(item.get("mechanism"), f"{prefix}.mechanism"),
                "inputs": require_text_list(item.get("inputs"), f"{prefix}.inputs"),
                "conditions": require_text_list(
                    item.get("conditions"), f"{prefix}.conditions"
                ),
                "guard": require_text(item.get("guard"), f"{prefix}.guard"),
                "consumer": require_text(item.get("consumer"), f"{prefix}.consumer"),
                "observation": require_text(
                    item.get("observation"), f"{prefix}.observation"
                ),
                "evidence": require_text_list(
                    item.get("evidence"), f"{prefix}.evidence"
                ),
                "reopeningConditions": require_text_list(
                    item.get("reopeningConditions"),
                    f"{prefix}.reopeningConditions",
                ),
            }
        )
    return rows


def normalize_boundary(value: Any, field: str = "criticalBoundary") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    operation = require_text(value.get("operation"), f"{field}.operation")
    if operation not in BOUNDARY_OPERATIONS:
        raise RuntimeError(f"{field}.operation is not a Critical authority boundary")
    required = value.get("requiredCapabilities")
    if not isinstance(required, list) or not required:
        raise RuntimeError(f"{field}.requiredCapabilities must be a non-empty list")
    return {
        "id": require_text(value.get("id", operation), f"{field}.id"),
        "operation": operation,
        "eventualImpact": require_text(
            value.get("eventualImpact"), f"{field}.eventualImpact"
        ),
        "intermediateCapability": require_text(
            value.get("intermediateCapability"),
            f"{field}.intermediateCapability",
        ),
        "requiredCapabilities": [
            normalize_capability(item, f"{field}.requiredCapabilities[{index}]")
            for index, item in enumerate(required)
        ],
        "context": normalize_context(value.get("context"), f"{field}.context"),
        "constraints": normalize_constraints(
            value.get("constraints"), f"{field}.constraints"
        ),
        "objects": normalize_objects(value.get("objects"), f"{field}.objects"),
        "sourceEvidence": require_text_list(
            value.get("sourceEvidence"), f"{field}.sourceEvidence"
        ),
    }


def normalize_primitive(value: Any, field: str = "primitive") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    produces = value.get("produces")
    requires = value.get("requires")
    if not isinstance(produces, list) or not produces:
        raise RuntimeError(f"{field}.produces must be a non-empty list")
    if not isinstance(requires, list):
        raise RuntimeError(f"{field}.requires must be a list")
    maximum_executions = int(value.get("maxExecutions", 1))
    if not 1 <= maximum_executions <= 16:
        raise RuntimeError(f"{field}.maxExecutions must be between 1 and 16")
    return {
        "id": require_text(value.get("id"), f"{field}.id"),
        "attackerControlledInputs": require_text_list(
            value.get("attackerControlledInputs", []),
            f"{field}.attackerControlledInputs",
            allow_empty=True,
        ),
        "produces": [
            normalize_capability(item, f"{field}.produces[{index}]")
            for index, item in enumerate(produces)
        ],
        "requires": [
            normalize_capability(item, f"{field}.requires[{index}]")
            for index, item in enumerate(requires)
        ],
        "context": normalize_context(value.get("context"), f"{field}.context"),
        "contextTransition": normalize_context_transition(
            value.get("contextTransition"), f"{field}.contextTransition"
        ),
        "attemptModel": normalize_attempt_model(
            value.get("attemptModel"), f"{field}.attemptModel"
        ),
        "maxExecutions": maximum_executions,
        "constraints": normalize_constraints(
            value.get("constraints"), f"{field}.constraints"
        ),
        "objects": normalize_objects(value.get("objects"), f"{field}.objects"),
        "invalidatesCapabilities": require_text_list(
            value.get("invalidatesCapabilities", []),
            f"{field}.invalidatesCapabilities",
            allow_empty=True,
        ),
        "stateSequence": normalize_state_sequence(
            value.get("stateSequence"), f"{field}.stateSequence"
        ),
        "sourceEvidence": require_text_list(
            value.get("sourceEvidence"), f"{field}.sourceEvidence"
        ),
        "runtimeEvidence": require_text_list(
            value.get("runtimeEvidence", []),
            f"{field}.runtimeEvidence",
            allow_empty=True,
        ),
        "progress": normalize_progress(value.get("progress"), f"{field}.progress"),
        "negativeKnowledge": normalize_negative_knowledge(
            value.get("negativeKnowledge", []), f"{field}.negativeKnowledge"
        ),
        "measuredCost": normalize_measured_cost(
            value.get("measuredCost"), f"{field}.measuredCost"
        ),
    }


def capability_match(produced: dict[str, Any], required: dict[str, Any]) -> tuple[bool, str]:
    if produced["type"] != required["type"]:
        return False, "capability-type"
    if not set(required["properties"]).issubset(produced["properties"]):
        return False, "missing-properties"
    if set(produced["limitations"]).intersection(required["forbiddenLimitations"]):
        return False, "forbidden-limitation"
    return True, "matched"


def context_match(
    producer: dict[str, Any], consumer: dict[str, Any]
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    unknown: list[str] = []
    attempt = consumer.get("attemptModel")
    if isinstance(attempt, dict):
        if not attempt["attackerCanAttempt"]:
            reasons.append("operation-not-attacker-attemptable")
        elif attempt["observedOutcome"] == "rejected":
            reasons.append("implementation-rejected-operation")
        elif attempt["observedOutcome"] == "unknown":
            unknown.append("implementation-outcome-unobserved")
    for field in CONTEXT_FIELDS:
        supplied = producer["context"][field]
        required = consumer["context"][field]
        if "any" in {supplied, required}:
            unknown.append(field)
        elif supplied != required:
            reasons.append(field)
    if reasons:
        return "impossible", reasons
    if unknown:
        return "unknown", unknown
    return "feasible", []


def condition_atom(scope: str, value: str) -> tuple[str, str, str]:
    if value.startswith("not:"):
        return (f"{scope}:{value[4:]}", "!=", "true")
    if "!=" in value:
        key, content = value.split("!=", 1)
        return (f"{scope}:{key.strip()}", "!=", content.strip())
    if "=" in value:
        key, content = value.split("=", 1)
        return (f"{scope}:{key.strip()}", "=", content.strip())
    return (f"{scope}:{value}", "=", "true")


def condition_atoms(constraints: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    return [
        condition_atom(scope, value)
        for scope in ("lifetime", "deployment", "acquisition")
        for value in constraints[scope]
    ]


def condition_conflicts(
    left: list[tuple[str, str, str]], right: list[tuple[str, str, str]]
) -> list[str]:
    conflicts: set[str] = set()
    combined = [*left, *right]
    for index, (key, operator, value) in enumerate(combined):
        for other_key, other_operator, other_value in combined[index + 1 :]:
            if key != other_key:
                continue
            if operator == other_operator == "=" and value != other_value:
                conflicts.add(f"{key} cannot be both {value!r} and {other_value!r}")
            elif operator != other_operator and value == other_value:
                conflicts.add(f"{key} cannot satisfy {operator}{value!r} and {other_operator}{other_value!r}")
    return sorted(conflicts)


def object_matches(actual: dict[str, Any], required: dict[str, Any]) -> bool:
    generation = required["generation"]
    if actual["identity"] != required["identity"]:
        return False
    if actual["state"] != required["state"]:
        return False
    return generation in {"any", "current"} or actual["generation"] == generation


def connection_assessment(
    producer: dict[str, Any], consumer: dict[str, Any]
) -> dict[str, Any]:
    consumer_id = consumer["id"]
    matches: list[dict[str, Any]] = []
    for produced in producer["produces"]:
        for required in consumer["requires"]:
            matched, _ = capability_match(produced, required)
            if matched:
                matches.append(
                    {
                        "capability": produced["type"],
                        "properties": required["properties"],
                    }
                )
    reasons: list[str] = []
    unknown: list[str] = []
    producer_context = (
        producer.get("contextTransition", {}).get("to")
        if producer.get("contextTransition")
        else producer["context"]
    )
    consumer_context = (
        consumer.get("contextTransition", {}).get("from")
        if consumer.get("contextTransition")
        else consumer["context"]
    )
    context_status, context_reasons = context_match(
        {"context": producer_context}, {"context": consumer_context}
    )
    if context_status == "impossible":
        reasons.extend(f"context:{value}" for value in context_reasons)
    elif context_status == "unknown":
        unknown.extend(f"context-unresolved:{value}" for value in context_reasons)
    conflicts = condition_conflicts(
        condition_atoms(producer["constraints"]),
        condition_atoms(consumer["constraints"]),
    )
    reasons.extend(f"condition:{value}" for value in conflicts)
    if not matches:
        reasons.append("no-compatible-capability")
    missing_state = set(consumer["constraints"]["requiredState"]).difference(
        producer["constraints"]["providedState"]
    )
    if missing_state:
        unknown.append("state-needs-earlier-producer:" + ",".join(sorted(missing_state)))
    for required in consumer.get("objects", {}).get("requires", []):
        if any(
            object_matches(produced, required)
            for produced in producer.get("objects", {}).get("produces", [])
        ):
            continue
        if any(
            invalidated["identity"] == required["identity"]
            for invalidated in producer.get("objects", {}).get("invalidates", [])
        ):
            reasons.append(f"object-invalidated:{required['identity']}")
        else:
            unknown.append(f"object-needs-earlier-producer:{required['identity']}")
    for requirement in consumer["constraints"]["ordering"]:
        if requirement.startswith("after:") and requirement[6:] != producer["id"]:
            unknown.append(f"ordering-needs:{requirement}")
    status = "impossible" if reasons else "unknown" if unknown else "feasible"
    return {
        "producer": producer["id"],
        "consumer": consumer_id,
        "status": status,
        "matches": matches,
        "reasons": reasons,
        "unknowns": unknown,
        "contextChecks": {
            field: producer_context[field] for field in CONTEXT_FIELDS
        },
        "stateChecks": consumer["constraints"]["requiredState"],
    }


def primitive_edge(producer: dict[str, Any], consumer: dict[str, Any]) -> dict[str, Any] | None:
    assessment = connection_assessment(producer, consumer)
    if assessment["status"] != "feasible":
        return None
    return assessment


def boundary_consumer(boundary: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "boundary:" + boundary["id"],
        "requires": boundary["requiredCapabilities"],
        "produces": [],
        "context": boundary["context"],
        "constraints": boundary["constraints"],
        "objects": boundary["objects"],
        "sourceEvidence": boundary["sourceEvidence"],
    }


def boundary_edge(producer: dict[str, Any], boundary: dict[str, Any]) -> dict[str, Any] | None:
    return primitive_edge(producer, boundary_consumer(boundary))


def capability_available(
    available: list[dict[str, Any]], required: dict[str, Any]
) -> bool:
    return any(capability_match(value, required)[0] for value in available)


def execution_check(
    configuration: dict[str, Any], consumer: dict[str, Any]
) -> tuple[str, list[str]]:
    impossible: list[str] = []
    unknown: list[str] = []
    attempt = consumer.get("attemptModel")
    if isinstance(attempt, dict):
        if not attempt["attackerCanAttempt"]:
            impossible.append("operation-not-attacker-attemptable")
        elif attempt["observedOutcome"] == "rejected":
            impossible.append("implementation-rejected-operation")
        elif attempt["observedOutcome"] == "unknown":
            unknown.append("implementation-outcome-unobserved")
    chain_context = configuration.get("context")
    if chain_context is not None:
        transition = consumer.get("contextTransition")
        required_context = transition["from"] if transition else consumer["context"]
        for field in CONTEXT_FIELDS:
            supplied = chain_context[field]
            required = required_context[field]
            if "any" in {supplied, required}:
                unknown.append(f"context-unresolved:{field}")
            elif supplied != required:
                impossible.append(f"context:{field}")
    conflicts = condition_conflicts(
        configuration["conditions"], condition_atoms(consumer["constraints"])
    )
    impossible.extend(f"condition:{value}" for value in conflicts)
    for required in consumer["requires"]:
        if not capability_available(configuration["capabilities"], required):
            unknown.append(f"capability:{required['type']}")
    missing_state = set(consumer["constraints"]["requiredState"]).difference(
        configuration["state"]
    )
    unknown.extend(f"state:{value}" for value in sorted(missing_state))
    for required in consumer.get("objects", {}).get("requires", []):
        actual = configuration["objects"].get(required["identity"])
        if actual is None:
            unknown.append(f"object:{required['identity']}:absent")
        elif not object_matches(actual, required):
            impossible.append(
                f"object:{required['identity']}:generation-or-state-mismatch"
            )
    used = set(configuration.get("executed", configuration["sequence"]))
    for ordering in consumer["constraints"]["ordering"]:
        if ordering.startswith("after:") and ordering[6:] not in used:
            unknown.append(f"ordering:{ordering}")
        if ordering.startswith("before:") and ordering[7:] in used:
            impossible.append(f"ordering:{ordering}")
    if impossible:
        return "impossible", impossible
    if unknown:
        return "unknown", unknown
    return "feasible", []


def apply_primitive(
    configuration: dict[str, Any], primitive: dict[str, Any]
) -> dict[str, Any]:
    transition = primitive.get("contextTransition")
    preserved = transition.get("preservesCapabilities") if transition else "all"
    capabilities = [
        value
        for value in configuration["capabilities"]
        if value["type"] not in primitive["invalidatesCapabilities"]
        and (preserved == "all" or value["type"] in preserved)
    ]
    capabilities.extend(primitive["produces"])
    capabilities = list(
        {
            json.dumps(value, sort_keys=True, separators=(",", ":")): value
            for value in capabilities
        }.values()
    )
    capabilities.sort(
        key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    )
    state = set(configuration["state"])
    state.difference_update(primitive["constraints"]["invalidatedState"])
    state.update(primitive["constraints"]["providedState"])
    objects = {key: dict(value) for key, value in configuration["objects"].items()}
    for invalidated in primitive["objects"]["invalidates"]:
        actual = objects.get(invalidated["identity"])
        if actual is not None and (
            invalidated["generation"] in {"any", "current", actual["generation"]}
        ):
            actual["state"] = "invalidated"
    for produced in primitive["objects"]["produces"]:
        previous = objects.get(produced["identity"])
        generation = produced["generation"]
        if generation == "next":
            generation = int(previous["generation"]) + 1 if previous and isinstance(previous["generation"], int) else 1
        elif generation in {"same", "current", "any"}:
            generation = previous["generation"] if previous else 1
        objects[produced["identity"]] = {
            **produced,
            "generation": generation,
        }
    prior_context = configuration["context"]
    if transition is not None:
        merged_context = dict(transition["to"])
    elif prior_context is None:
        merged_context = dict(primitive["context"])
    else:
        merged_context = dict(prior_context)
    counts = dict(configuration.get("counts", {}))
    counts[primitive["id"]] = int(counts.get(primitive["id"], 0)) + 1
    return {
        "sequence": [*configuration["sequence"], primitive["id"]],
        "executed": sorted(
            set(configuration.get("executed", configuration["sequence"]))
            | {primitive["id"]}
        ),
        "counts": counts,
        "capabilities": capabilities,
        "state": sorted(state),
        "objects": objects,
        "conditions": sorted(
            set(
                [
                    *[tuple(value) for value in configuration["conditions"]],
                    *condition_atoms(primitive["constraints"]),
                ]
            )
        ),
        "context": merged_context,
    }


def configuration_key(
    configuration: dict[str, Any], ordering_sensitive: set[str] | None = None
) -> str:
    """Return a semantic state key, excluding irrelevant execution history."""

    ordering_sensitive = ordering_sensitive or set()
    semantic = {
        "capabilities": sorted(
            configuration["capabilities"],
            key=lambda value: json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ),
        ),
        "state": configuration["state"],
        "objects": configuration["objects"],
        "conditions": configuration["conditions"],
        "context": configuration["context"],
        "orderingProgress": sorted(
            set(configuration.get("executed", configuration["sequence"]))
            & ordering_sensitive
        ),
    }
    return json.dumps(semantic, sort_keys=True, separators=(",", ":"))


def backward_relevant_primitives(
    primitives: list[dict[str, Any]], boundaries: list[dict[str, Any]]
) -> set[str]:
    """Find primitives that can satisfy a Critical boundary or its prerequisites."""

    needed_capabilities = {
        capability["type"]
        for boundary in boundaries
        for capability in boundary["requiredCapabilities"]
    }
    relevant: set[str] = set()
    changed = True
    while changed:
        changed = False
        for primitive in primitives:
            if primitive["id"] in relevant:
                continue
            produced = {value["type"] for value in primitive["produces"]}
            if not produced.intersection(needed_capabilities):
                continue
            relevant.add(primitive["id"])
            needed_capabilities.update(value["type"] for value in primitive["requires"])
            changed = True
    # Attacker-controlled roots remain relevant if they feed any required type.
    return relevant


def analyze_chain(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schemaVersion") != 1:
        raise RuntimeError("chain specification requires schemaVersion 1")
    primitives = [
        normalize_primitive(item, f"primitives[{index}]")
        for index, item in enumerate(document.get("primitives", []))
    ]
    boundaries = [
        normalize_boundary(item, f"boundaries[{index}]")
        for index, item in enumerate(document.get("boundaries", []))
    ]
    if not primitives or not boundaries:
        raise RuntimeError("chain specification requires primitives and boundaries")
    by_id = {row["id"]: row for row in primitives}
    if len(by_id) != len(primitives):
        raise RuntimeError("primitive IDs must be unique")
    assessments: list[dict[str, Any]] = []
    for producer in primitives:
        for consumer in primitives:
            if producer["id"] == consumer["id"]:
                continue
            assessments.append(connection_assessment(producer, consumer))
        for boundary in boundaries:
            assessments.append(
                connection_assessment(producer, boundary_consumer(boundary))
            )
    edges = [row for row in assessments if row["status"] == "feasible"]
    unknown_connections = [row for row in assessments if row["status"] == "unknown"]
    impossible_connections = [
        row for row in assessments if row["status"] == "impossible"
    ]

    ordering_sensitive = {
        value.split(":", 1)[1]
        for consumer in [*primitives, *[boundary_consumer(row) for row in boundaries]]
        for value in consumer["constraints"]["ordering"]
        if value.startswith(("after:", "before:")) and ":" in value
    }
    relevant_primitives = backward_relevant_primitives(primitives, boundaries)
    empty = {
        "sequence": [],
        "executed": [],
        "counts": {},
        "capabilities": [],
        "state": [],
        "objects": {},
        "conditions": [],
        "context": None,
    }
    configurations: list[dict[str, Any]] = []
    queue: list[tuple[int, int, int, dict[str, Any]]] = []
    seen: set[str] = set()
    partial_order_reductions = 0
    serial = 0

    def enqueue(configuration: dict[str, Any]) -> None:
        nonlocal serial, partial_order_reductions
        key = configuration_key(configuration, ordering_sensitive)
        if key in seen:
            partial_order_reductions += 1
            return
        seen.add(key)
        serial += 1
        relevant_count = sum(
            1 for value in configuration["sequence"] if value in relevant_primitives
        )
        heapq.heappush(
            queue,
            (-relevant_count, len(configuration["sequence"]), serial, configuration),
        )

    normalized_specification = {
        "primitives": primitives,
        "boundaries": boundaries,
        "orderingSensitive": sorted(ordering_sensitive),
    }
    search_digest = hashlib.sha256(
        json.dumps(
            normalized_specification, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    checkpoint = document.get("resumeCheckpoint")
    if checkpoint is not None:
        if not isinstance(checkpoint, dict) or checkpoint.get("specificationSha256") != search_digest:
            raise RuntimeError("resumeCheckpoint does not match this normalized chain specification")
        prior_states = checkpoint.get("exploredStates", [])
        frontier = checkpoint.get("frontier", [])
        if not isinstance(prior_states, list) or not isinstance(frontier, list):
            raise RuntimeError("resumeCheckpoint states and frontier must be lists")
        configurations.extend(prior_states)
        for configuration in [*prior_states, *frontier]:
            seen.add(configuration_key(configuration, ordering_sensitive))
        # Frontier states need to be reinserted after seeding the visited set.
        for configuration in frontier:
            serial += 1
            relevant_count = sum(
                1
                for value in configuration["sequence"]
                if value in relevant_primitives
            )
            heapq.heappush(
                queue,
                (-relevant_count, len(configuration["sequence"]), serial, configuration),
            )
    else:
        for primitive in sorted(
            primitives,
            key=lambda row: (row["id"] not in relevant_primitives, row["id"]),
        ):
            if not primitive["attackerControlledInputs"]:
                continue
            status, _ = execution_check(empty, primitive)
            if status == "feasible":
                enqueue(apply_primitive(empty, primitive))
    maximum_configurations = int(document.get("maximumConfigurations", 10000))
    explored_this_run = 0
    while queue and explored_this_run < maximum_configurations:
        _, _, _, configuration = heapq.heappop(queue)
        configurations.append(configuration)
        explored_this_run += 1
        counts = configuration.get("counts", {})
        for primitive in sorted(
            primitives,
            key=lambda row: (row["id"] not in relevant_primitives, row["id"]),
        ):
            if int(counts.get(primitive["id"], 0)) >= primitive["maxExecutions"]:
                continue
            status, _ = execution_check(configuration, primitive)
            if status != "feasible":
                continue
            enqueue(apply_primitive(configuration, primitive))

    reachable = {
        primitive_id
        for configuration in configurations
        for primitive_id in configuration["sequence"]
    }
    paths: list[list[str]] = []
    boundary_suppliers: dict[str, dict[str, list[str]]] = {}
    for boundary in boundaries:
        boundary_id = "boundary:" + boundary["id"]
        consumer = boundary_consumer(boundary)
        completed = [
            configuration
            for configuration in configurations
            if execution_check(configuration, consumer)[0] == "feasible"
        ]
        suppliers: dict[str, list[str]] = {}
        for index, requirement in enumerate(boundary["requiredCapabilities"]):
            suppliers[f"{index}:{requirement['type']}"] = sorted(
                {
                    primitive_id
                    for configuration in completed
                    for primitive_id in configuration["sequence"]
                    if any(
                        capability_match(produced, requirement)[0]
                        for produced in by_id[primitive_id]["produces"]
                    )
                }
            )
        boundary_suppliers[boundary_id] = suppliers
        paths.extend([*configuration["sequence"], boundary_id] for configuration in completed)

    experiments: list[dict[str, Any]] = []
    consumers = [*primitives, *[boundary_consumer(value) for value in boundaries]]
    capability_use_count: dict[str, int] = {}
    experiment_keys: set[tuple[str, str]] = set()
    for consumer in consumers:
        for requirement in consumer["requires"]:
            capability_use_count[requirement["type"]] = (
                capability_use_count.get(requirement["type"], 0) + 1
            )
    for consumer in consumers:
        consumer_reached = consumer["id"] in reachable or consumer["id"].startswith("boundary:") and any(
            path[-1] == consumer["id"] for path in paths
        )
        if consumer_reached:
            continue
        missing_requirements = [
            requirement
            for requirement in consumer["requires"]
            if not any(
                capability_available(configuration["capabilities"], requirement)
                for configuration in configurations
            )
        ]
        for requirement in missing_requirements:
            candidates = [
                producer
                for producer in primitives
                if any(
                    item["type"] == requirement["type"]
                    for item in producer["produces"]
                )
            ]
            candidate = max(
                candidates,
                key=lambda row: progress_score(row["progress"]),
                default=None,
            )
            related = [
                row
                for row in assessments
                if row["consumer"] == consumer["id"]
                and (candidate is None or row["producer"] == candidate["id"])
            ]
            uncertainty = sorted(
                {
                    value
                    for row in related
                    for value in [*row["unknowns"], *row["reasons"]]
                }
            )
            boundary_relevance = 100 if consumer["id"].startswith("boundary:") else 40
            reachable_bonus = 30 if candidate and candidate["id"] in reachable else 0
            shared_usefulness = 10 * capability_use_count[requirement["type"]]
            measured_cost = candidate.get("measuredCost") if candidate else None
            estimated_cost = (
                max(
                    1,
                    int(measured_cost["wallSeconds"] / 60)
                    + int(measured_cost["executions"]),
                )
                if measured_cost
                else 1
                + (len(candidate["stateSequence"]["transitions"]) if candidate else 2)
            )
            priority_score = (
                boundary_relevance
                + reachable_bonus
                + shared_usefulness
                + min(25, 5 * len(uncertainty))
                - estimated_cost
            )
            experiments.append(
                {
                    "id": "CE-" + hashlib.sha256(
                        f"{candidate['id'] if candidate else 'missing'}:{consumer['id']}:{requirement['type']}".encode()
                    ).hexdigest()[:16],
                    "producer": candidate["id"] if candidate else None,
                    "consumer": consumer["id"],
                    "missingCapability": requirement,
                    "question": (
                        f"Can {candidate['id']} deliver {requirement['type']} to {consumer['id']}"
                        if candidate
                        else f"Which source-reachable producer can create {requirement['type']} for {consumer['id']}"
                    ),
                    "setupSequence": (
                        candidate["stateSequence"]["transitions"] if candidate else []
                    ),
                    "oracle": "the consumer is reached with the required capability and matching principal/process/namespace/runtime state",
                    "falsifier": "the retained guard or context mismatch prevents the consumer from observing that capability",
                    "uncertainty": uncertainty,
                    "estimatedCost": estimated_cost,
                    "costBasis": "measured" if measured_cost else "state-sequence-estimate",
                    "measuredCost": measured_cost,
                    "ranking": {
                        "criticalBoundaryRelevance": boundary_relevance,
                        "reachableProducer": reachable_bonus,
                        "sharedUsefulness": shared_usefulness,
                        "uncertaintyResolved": min(25, 5 * len(uncertainty)),
                        "estimatedCostPenalty": estimated_cost,
                        "score": priority_score,
                    },
                    "sourceEvidence": sorted(
                        set(
                            (candidate["sourceEvidence"] if candidate else [])
                            + consumer.get("sourceEvidence", [])
                        )
                    ),
                }
            )
            experiment_keys.add((consumer["id"], requirement["type"]))

        # A capability can exist somewhere in the graph while no single feasible
        # execution also satisfies the required state, object generation,
        # ordering, lifetime, deployment, and acquisition constraints. Preserve
        # that missing link instead of incorrectly treating the consumer as
        # connected merely because a label exists.
        if not missing_requirements:
            evaluated = [
                (configuration, *execution_check(configuration, consumer))
                for configuration in (configurations or [empty])
            ]
            unresolved = [row for row in evaluated if row[1] != "feasible"]
            if unresolved:
                best_configuration, status, blockers = min(
                    unresolved,
                    key=lambda row: (
                        1 if row[1] == "impossible" else 0,
                        len(row[2]),
                        len(row[0]["sequence"]),
                    ),
                )
                key = (consumer["id"], "execution-prerequisite")
                if key not in experiment_keys:
                    candidate_id = (
                        best_configuration["sequence"][-1]
                        if best_configuration["sequence"]
                        else None
                    )
                    candidate = by_id.get(candidate_id or "")
                    boundary_relevance = (
                        100 if consumer["id"].startswith("boundary:") else 40
                    )
                    measured_cost = candidate.get("measuredCost") if candidate else None
                    estimated_cost = (
                        max(
                            1,
                            int(measured_cost["wallSeconds"] / 60)
                            + int(measured_cost["executions"]),
                        )
                        if measured_cost
                        else 1 + len(blockers)
                    )
                    priority_score = (
                        boundary_relevance
                        + 25
                        + min(30, 6 * len(blockers))
                        - estimated_cost
                    )
                    experiments.append(
                        {
                            "id": "CE-"
                            + hashlib.sha256(
                                f"{candidate_id or 'state'}:{consumer['id']}:execution-prerequisite".encode()
                            ).hexdigest()[:16],
                            "producer": candidate_id,
                            "consumer": consumer["id"],
                            "missingCapability": {
                                "type": "execution-prerequisite",
                                "properties": blockers,
                                "limitations": [],
                                "forbiddenLimitations": [],
                            },
                            "question": (
                                f"Can one execution satisfy all prerequisites for {consumer['id']}: "
                                + ", ".join(blockers)
                            ),
                            "setupSequence": list(best_configuration["sequence"]),
                            "oracle": "one retained execution reaches the consumer with all capabilities, state, object generations, ordering, and deployment conditions jointly satisfied",
                            "falsifier": "a specific retained contradiction proves that the prerequisite set cannot be satisfied in one execution",
                            "uncertainty": blockers,
                            "connectionStatus": status,
                            "estimatedCost": estimated_cost,
                            "costBasis": (
                                "measured" if measured_cost else "blocker-count-estimate"
                            ),
                            "measuredCost": measured_cost,
                            "ranking": {
                                "criticalBoundaryRelevance": boundary_relevance,
                                "reachableProducer": 25,
                                "sharedUsefulness": 0,
                                "uncertaintyResolved": min(30, 6 * len(blockers)),
                                "estimatedCostPenalty": estimated_cost,
                                "score": priority_score,
                            },
                            "sourceEvidence": sorted(
                                set(
                                    (candidate["sourceEvidence"] if candidate else [])
                                    + consumer.get("sourceEvidence", [])
                                )
                            ),
                        }
                    )
                    experiment_keys.add(key)
    search_truncated = bool(queue)
    continuation_strategy: dict[str, Any] | None = None
    search_checkpoint: dict[str, Any] | None = None
    if search_truncated:
        frontier_states = [item[3] for item in sorted(queue)]
        search_checkpoint = {
            "schemaVersion": 1,
            "specificationSha256": search_digest,
            "exploredStates": configurations,
            "frontier": frontier_states,
        }
        continuation_id = "CE-" + hashlib.sha256(
            f"search-continuation:{search_digest}:{len(configurations)}".encode()
        ).hexdigest()[:16]
        continuation_experiment = {
            "id": continuation_id,
            "kind": "search-continuation",
            "producer": None,
            "consumer": "critical-boundary-search",
            "missingCapability": {
                "type": "search-continuation",
                "properties": ["retained-semantic-frontier"],
                "limitations": [],
                "forbiddenLimitations": [],
            },
            "question": "Continue the retained semantic frontier instead of restarting or abandoning a truncated chain search",
            "setupSequence": [],
            "oracle": "the resumed search explores retained frontier states and either reaches a boundary or produces narrower missing links",
            "falsifier": "the resumed semantic frontier is exhausted without a Critical boundary path",
            "uncertainty": ["search-budget-exhausted"],
            "estimatedCost": maximum_configurations,
            "costBasis": "retained-frontier-size",
            "measuredCost": None,
            "ranking": {
                "criticalBoundaryRelevance": 100,
                "reachableProducer": 30,
                "sharedUsefulness": 20,
                "uncertaintyResolved": 25,
                "estimatedCostPenalty": 1,
                "score": 174,
            },
            "sourceEvidence": sorted(
                {
                    evidence
                    for row in [*primitives, *boundaries]
                    for evidence in row["sourceEvidence"]
                }
            ),
        }
        experiments.append(continuation_experiment)
        continuation_strategy = {
            "required": True,
            "experimentId": continuation_id,
            "reason": "configuration budget exhausted with an eligible semantic frontier remaining",
            "resumeInput": "searchCheckpoint",
            "frontierStates": len(frontier_states),
            "exploredThisRun": explored_this_run,
        }
    experiments.sort(key=lambda row: (-int(row["ranking"]["score"]), row["id"]))
    progress = sum(progress_score(row["progress"]) for row in primitives)
    focus_eligible = bool(experiments) and (
        search_truncated
        or progress >= 6
        or any(
            edge["producer"] in reachable
            and edge["status"] in {"feasible", "unknown"}
            and bool(edge["matches"])
            for edge in assessments
        )
    )
    negative = [
        {"primitive": row["id"], **item}
        for row in primitives
        for item in row["negativeKnowledge"]
    ]
    return {
        "schemaVersion": 1,
        "producer": "krineon-chain-reasoner",
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "primitives": primitives,
        "boundaries": boundaries,
        "connectionAssessments": assessments,
        "compatibleEdges": edges,
        "unknownConnections": unknown_connections,
        "impossibleConnections": impossible_connections,
        "reachableFromAttacker": sorted(reachable),
        "completeBoundaryPaths": paths,
        "executionStates": configurations,
        "searchTruncated": search_truncated,
        "searchStrategy": {
            "semanticStateDeduplication": True,
            "partialOrderReductions": partial_order_reductions,
            "backwardRelevantPrimitives": sorted(relevant_primitives),
            "historyRetainedOnlyForWitnessesAndOrdering": True,
        },
        "continuationStrategy": continuation_strategy,
        "searchCheckpoint": search_checkpoint,
        "boundaryRequirementSuppliers": boundary_suppliers,
        "missingLinkExperiments": experiments,
        "scopedNegativeKnowledge": negative,
        "chainProgressScore": progress,
        "focusEligible": focus_eligible,
        "findingClaimed": False,
    }


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def schedule_focus(campaign: Path, analysis_path: Path, analysis: dict[str, Any]) -> str | None:
    if not analysis.get("focusEligible") or not analysis.get("missingLinkExperiments"):
        return None
    experiment = analysis["missingLinkExperiments"][0]
    digest = hashlib.sha256(
        json.dumps(experiment, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    task_id = "chain-focus-" + digest
    command = [
        sys.executable,
        str(Path(__file__).with_name("research_harness.py")),
        "task-add",
        str(campaign),
        task_id,
        "--title",
        f"Resolve chain link: {experiment['missingCapability']['type']}",
        "--lane",
        "focused-chain-investigation",
        "--task-kind",
        "focused-chain-investigation",
        "--approach-family",
        "chain-composition",
        "--objective",
        experiment["question"],
        "--success-criterion",
        experiment["oracle"] + "; falsify with: " + experiment["falsifier"],
        "--priority",
        "2400",
        "--max-attempts",
        "2",
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0 and "already" not in completed.stderr.lower():
        raise RuntimeError(f"cannot schedule focused chain task: {completed.stderr.strip()}")
    packet = campaign / "tasks" / f"dynamic-{task_id}.md"
    if packet.is_file():
        packet.write_text(
            packet.read_text(encoding="utf-8")
            + "\n## Typed chain evidence\n\n"
            + f"Analysis: `{analysis_path.relative_to(campaign).as_posix()}`\n\n"
            + "The coordinator unlocked bounded focus because retained evidence improved the chain graph. "
            + "Test only the named producer-consumer compatibility and retain a scoped negative if it fails.\n",
            encoding="utf-8",
        )
    return task_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ingest", action="store_true")
    parser.add_argument(
        "--resume-from",
        type=Path,
        help="prior chain analysis containing a searchCheckpoint",
    )
    args = parser.parse_args(argv)
    try:
        campaign = args.campaign.expanduser().resolve()
        if not (campaign / "campaign.json").is_file():
            raise RuntimeError("not a Krineon campaign")
        output = args.output.expanduser().resolve()
        output.relative_to(campaign)
        specification = read_json(args.spec.expanduser().resolve())
        if args.resume_from:
            prior = read_json(args.resume_from.expanduser().resolve())
            checkpoint = prior.get("searchCheckpoint")
            if not isinstance(checkpoint, dict):
                raise RuntimeError("resume analysis has no searchCheckpoint")
            specification["resumeCheckpoint"] = checkpoint
        analysis = analyze_chain(specification)
        write_json(output, analysis)
        task = schedule_focus(campaign, output, analysis) if args.ingest else None
        print(json.dumps({"analysis": str(output), "focusedTask": task}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
