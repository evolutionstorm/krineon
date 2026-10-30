#!/usr/bin/env python3
"""Generate history-preserving operation sequences from an explicit state graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{field} must be non-empty text")
    return value.strip()


def generate(document: dict[str, Any], maximum_length: int) -> dict[str, Any]:
    if document.get("schemaVersion") != 1:
        raise RuntimeError("state graph requires schemaVersion 1")
    initial = require_text(document.get("initialState"), "initialState")
    raw = document.get("operations")
    if not isinstance(raw, list) or not raw:
        raise RuntimeError("operations must be a non-empty list")
    default_repetitions = int(document.get("maxRepetitionsPerOperation", 2))
    if not 1 <= default_repetitions <= maximum_length:
        raise RuntimeError("maxRepetitionsPerOperation must be within the sequence bound")
    operations: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RuntimeError(f"operations[{index}] must be an object")
        operation: dict[str, Any] = {
            name: require_text(item.get(name), f"operations[{index}].{name}")
            for name in ("id", "from", "to", "authority", "ownership", "invariant")
        }
        operation["maxRepetitions"] = int(
            item.get("maxRepetitions", default_repetitions)
        )
        if not 1 <= operation["maxRepetitions"] <= maximum_length:
            raise RuntimeError(
                f"operations[{index}].maxRepetitions must be within the sequence bound"
            )
        operation["thread"] = require_text(
            item.get("thread", "main"), f"operations[{index}].thread"
        )
        operation["attackerCanAttempt"] = bool(
            item.get("attackerCanAttempt", True)
        )
        observed = str(item.get("observedOutcome", "unknown"))
        if observed not in {"unknown", "allowed", "rejected"}:
            raise RuntimeError(
                f"operations[{index}].observedOutcome must be unknown, allowed, or rejected"
            )
        operation["observedOutcome"] = observed
        happens_after = item.get("happensAfter", [])
        if not isinstance(happens_after, list) or not all(
            isinstance(value, str) and value.strip() for value in happens_after
        ):
            raise RuntimeError(f"operations[{index}].happensAfter must be text")
        operation["happensAfter"] = list(dict.fromkeys(happens_after))
        instance = item.get("instance")
        if instance is not None:
            if not isinstance(instance, dict):
                raise RuntimeError(f"operations[{index}].instance must be an object")
            action = require_text(instance.get("action"), f"operations[{index}].instance.action")
            if action not in {"allocate", "release", "use", "invalidate"}:
                raise RuntimeError(f"operations[{index}].instance.action is unsupported")
            operation["instance"] = {
                "identity": require_text(
                    instance.get("identity"), f"operations[{index}].instance.identity"
                ),
                "action": action,
            }
        operations.append(operation)
    if len({item["id"] for item in operations}) != len(operations):
        raise RuntimeError("operation IDs must be unique")
    by_state: dict[str, list[dict[str, Any]]] = {}
    for operation in operations:
        by_state.setdefault(operation["from"], []).append(operation)
    sequences: list[dict[str, Any]] = []

    def apply_instance(
        operation: dict[str, Any], instances: dict[str, dict[str, Any]]
    ) -> tuple[dict[str, dict[str, Any]], bool, str | None]:
        result = {key: dict(value) for key, value in instances.items()}
        model = operation.get("instance")
        if not isinstance(model, dict):
            return result, True, None
        identity = model["identity"]
        action = model["action"]
        current = result.get(identity)
        if action == "allocate":
            generation = int(current["generation"]) + 1 if current else 1
            result[identity] = {"generation": generation, "state": "allocated"}
        elif current is None or current.get("state") != "allocated":
            stale_state = str(current.get("state")) if current else "absent"
            return result, False, f"{identity} is {stale_state}, not allocated"
        elif action == "use":
            pass
        elif action == "release":
            current["state"] = "released"
        elif action == "invalidate":
            current["state"] = "invalidated"
        return result, True, None

    def walk(
        state: str,
        path: list[dict[str, Any]],
        instances: dict[str, dict[str, Any]],
        instance_history: list[dict[str, Any]],
    ) -> None:
        if path:
            sequences.append(
                {
                    "operationIds": [item["id"] for item in path],
                    "states": [initial, *[item["actualTo"] for item in path]],
                    "transitionPairs": [
                        [item["actualFrom"], item["actualTo"]] for item in path
                    ],
                    "declaredTransitionPairs": [
                        [item["from"], item["to"]] for item in path
                    ],
                    "invariants": [item["invariant"] for item in path],
                    "threads": [item["thread"] for item in path],
                    "instanceHistory": instance_history,
                    "finalInstances": instances,
                    "partialOrder": [
                        {
                            "operation": item["id"],
                            "thread": item["thread"],
                            "happensAfter": item["happensAfter"],
                        }
                        for item in path
                    ],
                    "historyPreserved": True,
                }
            )
        if len(path) >= maximum_length:
            return
        candidates = list(by_state.get(state, []))
        for operation in operations:
            model = operation.get("instance")
            if (
                operation not in candidates
                and operation["attackerCanAttempt"]
                and isinstance(model, dict)
                and model["action"] == "use"
                and model["identity"] in instances
                and instances[model["identity"]].get("state") != "allocated"
            ):
                # Deliberately attempt a stale reference. The reference model
                # expects rejection; only a real observation may say otherwise.
                candidates.append(operation)
        for operation in candidates:
            if (
                sum(item["id"] == operation["id"] for item in path)
                >= operation["maxRepetitions"]
            ):
                continue
            if not set(operation["happensAfter"]).issubset(
                {item["id"] for item in path}
            ):
                continue
            next_instances, instance_valid, instance_reason = apply_instance(
                operation, instances
            )
            state_valid = operation["from"] == state
            reference_expected = "allow" if state_valid and instance_valid else "reject"
            observed = operation["observedOutcome"]
            implementation_allowed = observed == "allowed" or (
                observed == "unknown" and reference_expected == "allow"
            )
            next_state = operation["to"] if implementation_allowed else state
            if reference_expected == "reject" and observed != "allowed":
                next_instances = {key: dict(value) for key, value in instances.items()}
            walk(
                next_state,
                [
                    *path,
                    {**operation, "actualFrom": state, "actualTo": next_state},
                ],
                next_instances,
                [
                    *instance_history,
                    {
                        "operation": operation["id"],
                        "before": instances,
                        "after": next_instances,
                        "changed": instances != next_instances,
                        "attempted": True,
                        "referenceExpected": reference_expected,
                        "observedOutcome": observed,
                        "referenceReason": (
                            instance_reason
                            if instance_reason
                            else (
                                f"operation requires state {operation['from']}"
                                if not state_valid
                                else None
                            )
                        ),
                        "staleReferenceAttempt": bool(
                            isinstance(operation.get("instance"), dict)
                            and operation["instance"]["action"] == "use"
                            and not instance_valid
                        ),
                        "securityInvariantDisagreement": (
                            reference_expected == "reject" and observed == "allowed"
                        ),
                    },
                ],
            )

    walk(initial, [], {}, [])
    required = document.get("requiredTransitionPairs", [])
    if not isinstance(required, list):
        raise RuntimeError("requiredTransitionPairs must be a list")
    required_pairs = {
        tuple(pair)
        for pair in required
        if isinstance(pair, list) and len(pair) == 2 and all(isinstance(v, str) for v in pair)
    }
    for sequence in sequences:
        observed = {tuple(pair) for pair in sequence["transitionPairs"]}
        sequence["coversRequiredPairs"] = sorted([list(pair) for pair in required_pairs & observed])
        sequence["missingRequiredPairs"] = sorted([list(pair) for pair in required_pairs - observed])
    return {
        "schemaVersion": 1,
        "producer": "krineon-state-sequence-generator",
        "initialState": initial,
        "maximumLength": maximum_length,
        "sequences": sequences,
        "mutationPolicy": {
            "attackerAttemptsSeparatedFromReferenceExpectations": True,
            "implementationObservationsNeverInferredFromTheReferenceModel": True,
            "staleReferenceAttemptsRetained": True,
            "historyIsNeverReordered": True,
            "reductionsMustRetainRequiredTransitionPairs": True,
            "boundedOperationRepetition": default_repetitions,
            "instanceGenerationsTracked": True,
            "controlledInterleavingsRespectHappensAfter": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--maximum-length", type=int, default=6)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.maximum_length <= 32:
            raise RuntimeError("--maximum-length must be between 1 and 32")
        document = json.loads(args.spec.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise RuntimeError("state graph must be a JSON object")
        result = generate(document, args.maximum_length)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(args.output)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
