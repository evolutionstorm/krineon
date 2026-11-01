#!/usr/bin/env python3
"""Evaluate authoritative state transitions for web business workflows."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


FAMILIES = {
    "object-authorization",
    "function-authorization",
    "tenant-parent-binding",
    "workflow-prerequisites",
    "replay-idempotency",
    "state-invalidation",
    "server-client-trust",
    "async-workflow",
    "transaction-integrity",
    "bounded-concurrency",
}
ROLES = {"baseline-control", "enforcing-negative", "positive-invariant"}
AUTHORITATIVE_ORIGINS = {
    "server-response",
    "server-persisted-readback",
    "signed-browser-network-response",
    "owner-control-plane-readback",
}
INCONCLUSIVE_STATES = {
    "auth-inconclusive",
    "environment-blocked",
    "deployment-drift",
    "cleanup-failed",
    "inaccessible-business-state",
    "missing-telemetry",
}
OPERATORS = {
    "equals",
    "not-equals",
    "contains",
    "not-contains",
    "exists",
    "not-exists",
    "less-than",
    "greater-than",
}


class MissingState(Exception):
    pass


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def parse_time(value: Any) -> dt.datetime:
    text = str(value or "")
    if not text:
        raise MissingState("observedAt")
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def nested(value: Any, path: str) -> Any:
    current = value
    for part in path.split(".") if path else []:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise MissingState(path)
    return current


def compare(operator: str, left: Any, right: Any | None) -> bool:
    if operator == "equals":
        return left == right
    if operator == "not-equals":
        return left != right
    if operator == "contains":
        return isinstance(left, (str, list, dict)) and right in left
    if operator == "not-contains":
        return not isinstance(left, (str, list, dict)) or right not in left
    if operator == "exists":
        return left is not None
    if operator == "not-exists":
        return left is None
    if operator == "less-than":
        return float(left) < float(right)
    if operator == "greater-than":
        return float(left) > float(right)
    raise WebContractError(f"unsupported state assertion operator: {operator}")


def validate_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError("state observation must be an object")
    required = (
        "id",
        "kind",
        "authenticatedActor",
        "effectiveActor",
        "resourceId",
        "ownerId",
        "tenantId",
        "generation",
        "evidenceOrigin",
        "observedAt",
        "state",
    )
    missing = [
        field
        for field in required
        if value.get(field) is None or value.get(field) == ""
    ]
    if missing:
        raise WebContractError(
            "state observation is missing: " + ", ".join(sorted(missing))
        )
    if value.get("evidenceOrigin") not in AUTHORITATIVE_ORIGINS:
        raise WebContractError(
            "state observations require authoritative server-visible evidence"
        )
    if value.get("authoritative") is not True:
        raise WebContractError("state observation must be marked authoritative")
    if value.get("localPlannerState") is not None or value.get("domOnly") is True:
        raise WebContractError("local planner or DOM-only state is not authoritative")
    parse_time(value["observedAt"])
    if not isinstance(value.get("state"), dict):
        raise WebContractError("state observation state must be an object")
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise WebContractError("state observation requires evidence references")
    return dict(value)


def validate_oracle(spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict) or spec.get("schemaVersion") != 1:
        raise WebContractError("business state oracle schemaVersion must be 1")
    if spec.get("family") not in FAMILIES:
        raise WebContractError("business state oracle family is unsupported")
    for field in ("id", "claim", "ruleBasis", "prerequisiteVersion"):
        if not str(spec.get(field) or "").strip():
            raise WebContractError(f"business state oracle requires {field}")
    if spec.get("ruleBasisConfidence") not in {
        "owner-specified",
        "source-supported",
        "observed-normal-workflow",
    }:
        raise WebContractError("business rule requires an explicit evidence basis")
    window = spec.get("consistencyWindowSeconds")
    if not isinstance(window, (int, float)) or window < 0:
        raise WebContractError("consistencyWindowSeconds must be non-negative")
    if float(window) > 0 and (
        not str(spec.get("consistencyStartObservation") or "").strip()
        or not isinstance(spec.get("terminalObservations"), list)
        or not spec.get("terminalObservations")
    ):
        raise WebContractError(
            "a non-zero consistency window requires its start and terminal observations"
        )
    assertions = spec.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise WebContractError("business state oracle requires assertions")
    roles: set[str] = set()
    ids: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise WebContractError("state assertion must be an object")
        assertion_id = str(assertion.get("id") or "")
        if not assertion_id or assertion_id in ids:
            raise WebContractError("state assertion ids must be unique")
        ids.add(assertion_id)
        role = str(assertion.get("role") or "")
        if role not in ROLES:
            raise WebContractError("state assertion has an unsupported role")
        roles.add(role)
        if assertion.get("operator") not in OPERATORS:
            raise WebContractError("state assertion operator is unsupported")
        if not isinstance(assertion.get("left"), dict):
            raise WebContractError("state assertion requires a left selector")
        if assertion["operator"] not in {"exists", "not-exists"} and not isinstance(
            assertion.get("right"), dict
        ):
            raise WebContractError("binary state assertion requires a right operand")
        if not isinstance(assertion.get("expected"), bool):
            raise WebContractError("state assertion expected must be Boolean")
    if roles != ROLES:
        raise WebContractError("state oracle requires all three control roles")
    required = spec.get("requiredObservations")
    if not isinstance(required, list) or not required:
        raise WebContractError("state oracle requires requiredObservations")
    return dict(spec)


def resolve(selector: dict[str, Any], observations: dict[str, dict[str, Any]]) -> Any:
    if "literal" in selector:
        return selector["literal"]
    observation_id = str(selector.get("observation") or "")
    if observation_id not in observations:
        raise MissingState(f"observation:{observation_id}")
    return nested(observations[observation_id], str(selector.get("field") or ""))


def evaluate(
    spec: dict[str, Any],
    observation_document: dict[str, Any],
    *,
    evaluation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    oracle = validate_oracle(spec)
    if observation_document.get("prerequisiteVersion") != oracle["prerequisiteVersion"]:
        return inconclusive(oracle, "deployment-drift")
    run_state = str(observation_document.get("runState") or "completed")
    if run_state in INCONCLUSIVE_STATES:
        return inconclusive(oracle, run_state)
    if observation_document.get("cleanupComplete") is False:
        return inconclusive(oracle, "cleanup-failed")
    observations: dict[str, dict[str, Any]] = {}
    invalid: list[str] = []
    for raw in observation_document.get("observations", []):
        try:
            item = validate_observation(raw)
        except WebContractError as error:
            invalid.append(str(error))
            continue
        if item["id"] in observations:
            invalid.append(f"duplicate observation:{item['id']}")
            continue
        observations[item["id"]] = item
    missing = [
        str(value)
        for value in oracle["requiredObservations"]
        if str(value) not in observations
    ]
    if invalid or missing:
        result = inconclusive(oracle, "missing-telemetry")
        result["missingObservations"] = missing
        result["invalidObservations"] = invalid
        return result
    terminal_ids = set(map(str, oracle.get("terminalObservations", [])))
    pending = []
    if float(oracle["consistencyWindowSeconds"]) > 0:
        start_id = str(oracle["consistencyStartObservation"])
        start = observations.get(start_id)
        if start is None:
            result = inconclusive(oracle, "missing-telemetry")
            result["missingObservations"] = [start_id]
            return result
        started_at = parse_time(start["observedAt"])
        for observation_id in terminal_ids:
            observed = observations.get(observation_id)
            if observed is None:
                continue
            elapsed = (parse_time(observed["observedAt"]) - started_at).total_seconds()
            if elapsed < float(oracle["consistencyWindowSeconds"]):
                pending.append(
                    {
                        "observation": observation_id,
                        "elapsedSeconds": elapsed,
                        "requiredSeconds": float(oracle["consistencyWindowSeconds"]),
                    }
                )
    if pending:
        result = inconclusive(oracle, "consistency-window-unresolved")
        result["pendingObservations"] = pending
        return result

    results = []
    missing_fields = []
    for assertion in oracle["assertions"]:
        row = {
            "id": assertion["id"],
            "role": assertion["role"],
            "passed": False,
            "observed": None,
        }
        try:
            left = resolve(assertion["left"], observations)
            right = (
                None
                if assertion["operator"] in {"exists", "not-exists"}
                else resolve(assertion["right"], observations)
            )
            observed = compare(assertion["operator"], left, right)
            row["observed"] = observed
            row["passed"] = observed == assertion["expected"]
        except (MissingState, TypeError, ValueError) as error:
            missing_fields.append(f"{assertion['id']}:{error}")
        results.append(row)
    if missing_fields:
        result = inconclusive(oracle, "missing-telemetry")
        result["missingFields"] = missing_fields
        result["assertions"] = results
        return result
    controls = [row for row in results if row["role"] != "positive-invariant"]
    positive = [row for row in results if row["role"] == "positive-invariant"]
    if not all(row["passed"] for row in controls):
        outcome, reason = "inconclusive", "control-failure"
    elif any(not row["passed"] for row in positive):
        outcome, reason = "confirmed-disagreement", "business-invariant-disagreed"
    else:
        outcome, reason = "observed-preservation", "business-invariant-preserved"
    return {
        "schemaVersion": 1,
        "producer": "krineon-web-state-oracles",
        "oracleId": oracle["id"],
        "family": oracle["family"],
        "outcome": outcome,
        "reason": reason,
        "promotionEligible": outcome == "confirmed-disagreement",
        "assertions": results,
        "prerequisiteVersion": oracle["prerequisiteVersion"],
        "ruleBasis": oracle["ruleBasis"],
    }


def inconclusive(oracle: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "producer": "krineon-web-state-oracles",
        "oracleId": oracle["id"],
        "family": oracle["family"],
        "outcome": "inconclusive",
        "reason": reason,
        "promotionEligible": False,
        "prerequisiteVersion": oracle["prerequisiteVersion"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oracle", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = evaluate(load_object(args.oracle), load_object(args.observations))
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps(result, indent=2))
        return 0 if result["outcome"] != "inconclusive" else 1
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
