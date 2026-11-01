#!/usr/bin/env python3
"""Evaluate typed web security invariants from broker observations.

Oracles use three roles. Baseline and enforcing-negative assertions must pass.
The positive assertion describes expected secure behavior. A positive mismatch
with both controls passing is a confirmed invariant disagreement. Missing
telemetry or failed controls produce an inconclusive result.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


ORACLE_KINDS = {
    "authorization-isolation",
    "tenant-isolation",
    "resource-resolution",
    "session-binding",
    "cache-partition",
    "parser-agreement",
    "state-transition",
    "capability-acquisition",
    "business-invariant",
    "independent-state-read",
    "canary-context",
    "callback-correlation",
    "browser-security-context",
}
ROLES = {"baseline-control", "enforcing-negative", "positive-invariant"}
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


class MissingObservation(Exception):
    pass


def load_object(path: Path | str) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected a JSON object in {resolved}")
    return value


def step_map(observation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    steps = observation.get("steps")
    if not isinstance(steps, list):
        raise WebContractError("observation.steps must be an array")
    result: dict[str, dict[str, Any]] = {}
    for item in steps:
        if not isinstance(item, dict) or not str(item.get("id") or ""):
            raise WebContractError("every observation step requires an id")
        step_id = str(item["id"])
        if step_id in result:
            raise WebContractError(f"duplicate observation step: {step_id}")
        result[step_id] = item
    return result


def nested(value: Any, path: str) -> Any:
    current = value
    if not path:
        return current
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        raise MissingObservation(path)
    return current


def resolve_operand(
    operand: Any, steps: dict[str, dict[str, Any]], *, literal_allowed: bool = True
) -> Any:
    if isinstance(operand, dict) and "step" in operand:
        step_id = str(operand.get("step") or "")
        if step_id not in steps:
            raise MissingObservation(f"step:{step_id}")
        return nested(steps[step_id], str(operand.get("field") or ""))
    if literal_allowed and isinstance(operand, dict) and "literal" in operand:
        return operand["literal"]
    raise WebContractError("oracle operand must select a step field or literal")


def compare(operator: str, left: Any, right: Any | None) -> bool:
    if operator == "equals":
        return left == right
    if operator == "not-equals":
        return left != right
    if operator == "contains":
        if isinstance(left, (str, list, dict)):
            return right in left
        return False
    if operator == "not-contains":
        if isinstance(left, (str, list, dict)):
            return right not in left
        return True
    if operator == "exists":
        return left is not None
    if operator == "not-exists":
        return left is None
    if operator == "less-than":
        return float(left) < float(right)
    if operator == "greater-than":
        return float(left) > float(right)
    raise WebContractError(f"unsupported oracle operator: {operator}")


def validate_oracle(oracle: dict[str, Any]) -> None:
    if oracle.get("schemaVersion") != 1:
        raise WebContractError("oracle schemaVersion must be 1")
    if oracle.get("kind") not in ORACLE_KINDS:
        raise WebContractError("oracle kind is unsupported")
    if not str(oracle.get("id") or "").strip() or not str(oracle.get("claim") or "").strip():
        raise WebContractError("oracle requires id and claim")
    assertions = oracle.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise WebContractError("oracle requires assertions")
    required = oracle.get("requiredObservations")
    if not isinstance(required, list) or not required:
        raise WebContractError("oracle requires explicit requiredObservations")
    for selector in required:
        if not isinstance(selector, dict) or "step" not in selector:
            raise WebContractError("requiredObservations must be step selectors")
    seen_roles: set[str] = set()
    seen_ids: set[str] = set()
    for item in assertions:
        if not isinstance(item, dict):
            raise WebContractError("oracle assertion must be an object")
        assertion_id = str(item.get("id") or "")
        if not assertion_id or assertion_id in seen_ids:
            raise WebContractError("oracle assertion ids must be nonempty and unique")
        seen_ids.add(assertion_id)
        role = str(item.get("role") or "")
        if role not in ROLES:
            raise WebContractError("oracle assertion has an unsupported role")
        seen_roles.add(role)
        operator = str(item.get("operator") or "")
        if operator not in OPERATORS:
            raise WebContractError("oracle assertion has an unsupported operator")
        if not isinstance(item.get("expected"), bool):
            raise WebContractError("oracle assertion requires a Boolean expected value")
        if not isinstance(item.get("left"), dict):
            raise WebContractError("oracle assertion requires a left selector")
        if operator not in {"exists", "not-exists"} and not isinstance(
            item.get("right"), dict
        ):
            raise WebContractError("binary oracle assertion requires a right operand")
    if seen_roles != ROLES:
        raise WebContractError("oracle needs baseline, enforcing-negative, and positive roles")
    requirements = oracle.get("evidenceRequirements", [])
    if not isinstance(requirements, list):
        raise WebContractError("oracle evidenceRequirements must be an array")
    for item in requirements:
        if not isinstance(item, dict) or not str(item.get("purpose") or ""):
            raise WebContractError("each evidence requirement needs a purpose")
        selectors = item.get("selectors")
        if not isinstance(selectors, list) or not selectors:
            raise WebContractError("each evidence requirement needs selectors")
        if any(not isinstance(selector, dict) or "step" not in selector for selector in selectors):
            raise WebContractError("evidence requirement selectors must select step fields")


def evaluate(oracle: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    validate_oracle(oracle)
    steps = step_map(observation)
    results: list[dict[str, Any]] = []
    missing: list[str] = []
    for selector in oracle.get("requiredObservations", []):
        try:
            resolve_operand(selector, steps, literal_allowed=False)
        except MissingObservation as exc:
            missing.append(str(exc))
    evidence_requirements: list[dict[str, Any]] = []
    for requirement in oracle.get("evidenceRequirements", []):
        requirement_missing: list[str] = []
        for selector in requirement["selectors"]:
            try:
                resolve_operand(selector, steps, literal_allowed=False)
            except MissingObservation as exc:
                requirement_missing.append(str(exc))
                missing.append(str(exc))
        evidence_requirements.append(
            {
                "purpose": requirement["purpose"],
                "satisfied": not requirement_missing,
                "missing": requirement_missing,
            }
        )
    for assertion in oracle["assertions"]:
        row = {
            "id": assertion["id"],
            "role": assertion["role"],
            "operator": assertion["operator"],
            "expected": assertion["expected"],
            "observed": None,
            "passed": False,
            "missing": [],
        }
        try:
            left = resolve_operand(assertion["left"], steps)
            right = (
                None
                if assertion["operator"] in {"exists", "not-exists"}
                else resolve_operand(assertion["right"], steps)
            )
            observed = compare(assertion["operator"], left, right)
            row["observed"] = observed
            row["passed"] = observed == assertion["expected"]
        except MissingObservation as exc:
            row["missing"].append(str(exc))
            missing.append(str(exc))
        except (TypeError, ValueError) as exc:
            row["missing"].append(f"comparison:{exc}")
            missing.append(f"comparison:{assertion['id']}")
        results.append(row)
    controls = [
        row
        for row in results
        if row["role"] in {"baseline-control", "enforcing-negative"}
    ]
    positives = [row for row in results if row["role"] == "positive-invariant"]
    positive_security_fields = []
    for assertion in oracle["assertions"]:
        if assertion["role"] != "positive-invariant":
            continue
        for side in ("left", "right"):
            selector = assertion.get(side)
            if isinstance(selector, dict) and "step" in selector:
                positive_security_fields.append(str(selector.get("field") or ""))
    status_only = bool(positive_security_fields) and all(
        field == "response.status" for field in positive_security_fields
    )
    if missing:
        outcome = "inconclusive-missing-telemetry"
    elif not all(row["passed"] for row in controls):
        outcome = "inconclusive-control-failure"
    elif status_only:
        outcome = "inconclusive-insufficient-security-evidence"
    elif any(not row["passed"] for row in positives):
        outcome = "confirmed-invariant-disagreement"
    else:
        outcome = "observed-invariant-preservation"
    return {
        "schemaVersion": 1,
        "oracleId": oracle["id"],
        "oracleKind": oracle["kind"],
        "claim": oracle["claim"],
        "workflowId": observation.get("workflowId"),
        "outcome": outcome,
        "securityViolationConfirmed": outcome == "confirmed-invariant-disagreement",
        "missingTelemetry": sorted(set(missing)),
        "assertions": results,
        "evidenceRequirements": evidence_requirements,
        "statusOnlyEvidenceRejected": status_only,
        "limitations": observation.get("limitations", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oracle")
    parser.add_argument("observation")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = evaluate(load_object(args.oracle), load_object(args.observation))
        if args.output:
            atomic_json(Path(args.output).expanduser().resolve(), result)
        else:
            print(json.dumps(result, indent=2))
        return 0 if not result["outcome"].startswith("inconclusive") else 1
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
