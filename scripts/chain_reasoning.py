#!/usr/bin/env python3
"""Build a typed capability graph and emit concrete missing-link experiments."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from collections import deque
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
        )
    }


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
        "constraints": normalize_constraints(
            value.get("constraints"), f"{field}.constraints"
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
    }


def capability_match(produced: dict[str, Any], required: dict[str, Any]) -> tuple[bool, str]:
    if produced["type"] != required["type"]:
        return False, "capability-type"
    if not set(required["properties"]).issubset(produced["properties"]):
        return False, "missing-properties"
    if set(produced["limitations"]).intersection(required["forbiddenLimitations"]):
        return False, "forbidden-limitation"
    return True, "matched"


def context_match(producer: dict[str, Any], consumer: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for field in CONTEXT_FIELDS:
        supplied = producer["context"][field]
        required = consumer["context"][field]
        if supplied not in {required, "any"} and required != "any":
            reasons.append(field)
    supplied_state = set(producer["constraints"]["providedState"])
    required_state = set(consumer["constraints"]["requiredState"])
    if not required_state.issubset(supplied_state):
        reasons.append("runtime-state")
    return not reasons, reasons


def primitive_edge(producer: dict[str, Any], consumer: dict[str, Any]) -> dict[str, Any] | None:
    compatible_context, context_reasons = context_match(producer, consumer)
    if not compatible_context:
        return None
    matches: list[dict[str, Any]] = []
    for produced in producer["produces"]:
        for required in consumer["requires"]:
            matched, reason = capability_match(produced, required)
            if matched:
                matches.append({"capability": produced["type"], "properties": required["properties"]})
    if not matches:
        return None
    return {
        "producer": producer["id"],
        "consumer": consumer["id"],
        "matches": matches,
        "contextChecks": {field: producer["context"][field] for field in CONTEXT_FIELDS},
        "stateChecks": consumer["constraints"]["requiredState"],
    }


def boundary_edge(producer: dict[str, Any], boundary: dict[str, Any]) -> dict[str, Any] | None:
    consumer = {
        "id": "boundary:" + boundary["id"],
        "requires": boundary["requiredCapabilities"],
        "context": boundary["context"],
        "constraints": boundary["constraints"],
    }
    return primitive_edge(producer, consumer)


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
    edges: list[dict[str, Any]] = []
    adjacency: dict[str, list[str]] = {row["id"]: [] for row in primitives}
    for producer in primitives:
        for consumer in primitives:
            if producer["id"] == consumer["id"]:
                continue
            edge = primitive_edge(producer, consumer)
            if edge:
                edges.append(edge)
                adjacency[producer["id"]].append(consumer["id"])
        for boundary in boundaries:
            edge = boundary_edge(producer, boundary)
            if edge:
                edges.append(edge)
                adjacency[producer["id"]].append("boundary:" + boundary["id"])
    roots = [
        row["id"]
        for row in primitives
        if row["attackerControlledInputs"] and not row["requires"]
    ]
    reachable: set[str] = set(roots)

    def requirement_suppliers(consumer_id: str, requirements: list[dict[str, Any]]) -> dict[str, list[str]]:
        supplied: dict[str, list[str]] = {}
        for index, requirement in enumerate(requirements):
            key = f"{index}:{requirement['type']}"
            supplied[key] = sorted(
                {
                    str(edge["producer"])
                    for edge in edges
                    if edge["consumer"] == consumer_id
                    and edge["producer"] in reachable
                    and any(
                        match["capability"] == requirement["type"]
                        and set(requirement["properties"]).issubset(match["properties"])
                        for match in edge["matches"]
                    )
                }
            )
        return supplied

    changed = True
    while changed:
        changed = False
        for primitive in primitives:
            if primitive["id"] in reachable:
                continue
            suppliers = requirement_suppliers(primitive["id"], primitive["requires"])
            if primitive["requires"] and all(suppliers.values()):
                reachable.add(primitive["id"])
                changed = True

    paths: list[list[str]] = []
    boundary_suppliers: dict[str, dict[str, list[str]]] = {}
    for boundary in boundaries:
        boundary_id = "boundary:" + boundary["id"]
        suppliers = requirement_suppliers(boundary_id, boundary["requiredCapabilities"])
        boundary_suppliers[boundary_id] = suppliers
        if all(suppliers.values()):
            ordered = sorted({item for values in suppliers.values() for item in values})
            paths.append([*ordered, boundary_id])
    experiments: list[dict[str, Any]] = []
    for consumer in [*primitives, *[
        {
            "id": "boundary:" + value["id"],
            "requires": value["requiredCapabilities"],
            "context": value["context"],
            "constraints": value["constraints"],
            "sourceEvidence": value["sourceEvidence"],
        }
        for value in boundaries
    ]]:
        incoming = [edge for edge in edges if edge["consumer"] == consumer["id"]]
        for requirement in consumer["requires"]:
            if any(
                edge["producer"] in reachable
                and match["capability"] == requirement["type"]
                and set(requirement["properties"]).issubset(match["properties"])
                for edge in incoming
                for match in edge["matches"]
            ):
                continue
            candidate = next(
                (
                    producer
                    for producer in primitives
                    if any(item["type"] == requirement["type"] for item in producer["produces"])
                ),
                None,
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
                    "sourceEvidence": sorted(
                        set(
                            (candidate["sourceEvidence"] if candidate else [])
                            + consumer.get("sourceEvidence", [])
                        )
                    ),
                }
            )
    progress = sum(progress_score(row["progress"]) for row in primitives)
    focus_eligible = bool(experiments) and (
        progress >= 6
        or any(edge["producer"] in reachable for edge in edges)
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
        "compatibleEdges": edges,
        "reachableFromAttacker": sorted(reachable),
        "completeBoundaryPaths": paths,
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
    args = parser.parse_args(argv)
    try:
        campaign = args.campaign.expanduser().resolve()
        if not (campaign / "campaign.json").is_file():
            raise RuntimeError("not a Krineon campaign")
        output = args.output.expanduser().resolve()
        output.relative_to(campaign)
        analysis = analyze_chain(read_json(args.spec.expanduser().resolve()))
        write_json(output, analysis)
        task = schedule_focus(campaign, output, analysis) if args.ingest else None
        print(json.dumps({"analysis": str(output), "focusedTask": task}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
