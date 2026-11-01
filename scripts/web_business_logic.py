#!/usr/bin/env python3
"""Compile explicit business rules into evidence-bound research hypotheses."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

try:
    from .web_contract import WebContractError, atomic_json
    from .web_state_oracles import FAMILIES, validate_oracle
except ImportError:
    from web_contract import WebContractError, atomic_json
    from web_state_oracles import FAMILIES, validate_oracle


DISCOVERY_DIMENSIONS = {
    "object-authorization": {
        "question": "Can B read or change A's private owned record?",
        "minimumEvidence": [
            "owner positive control",
            "non-owner own-resource control",
            "non-owner against owner resource",
            "independent owner and state readback",
        ],
        "variedDimension": "actor-resource binding",
    },
    "function-authorization": {
        "question": "Can a lower-role actor perform a privileged operation?",
        "minimumEvidence": [
            "verified roles",
            "owner-specified or source-supported policy",
            "authoritative protected effect readback",
        ],
        "variedDimension": "actor role",
    },
    "tenant-parent-binding": {
        "question": "Can a resource reference escape its owning tenant or parent?",
        "minimumEvidence": [
            "two owned tenants",
            "correct binding control",
            "mismatched binding case",
            "authoritative resulting owner and tenant",
        ],
        "variedDimension": "parent or tenant binding",
    },
    "workflow-prerequisites": {
        "question": "Can an operation run without its required prerequisite?",
        "minimumEvidence": [
            "normal workflow",
            "omitted or reordered prerequisite",
            "authoritative terminal state",
        ],
        "variedDimension": "sequence prerequisite",
    },
    "replay-idempotency": {
        "question": "Can a one-time entitlement or transition be reused?",
        "minimumEvidence": [
            "disposable bounded resource",
            "explicit once-only rule",
            "first-use state",
            "second-use authoritative state",
        ],
        "variedDimension": "use generation",
    },
    "state-invalidation": {
        "question": "Does revoked or changed authority persist through another consumer?",
        "minimumEvidence": [
            "before authority check",
            "authoritative invalidation",
            "bounded consistency window",
            "after authority check",
        ],
        "variedDimension": "authority generation",
    },
    "server-client-trust": {
        "question": "Does the server trust a client-authored protected property?",
        "minimumEvidence": [
            "protected-property rule",
            "client-authored field",
            "authoritative forbidden server-state change",
        ],
        "variedDimension": "protected property provenance",
    },
    "async-workflow": {
        "question": "Can job ownership or completion cross principals?",
        "minimumEvidence": [
            "producer job identity",
            "independent consumer identity",
            "bounded polling",
            "authoritative result ownership",
        ],
        "variedDimension": "job consumer identity",
    },
    "transaction-integrity": {
        "question": "Can authoritative totals or entitlements disagree across steps?",
        "minimumEvidence": [
            "program-approved synthetic transaction",
            "before authoritative totals",
            "after authoritative totals",
            "no real funds or inventory effect",
        ],
        "variedDimension": "transaction sequence",
    },
    "bounded-concurrency": {
        "question": "Can a staged pair violate a once-only invariant?",
        "minimumEvidence": [
            "explicit concurrency approval",
            "two-operation maximum",
            "isolated disposable fixture",
            "before and after invariant readback",
        ],
        "variedDimension": "approved paired ordering",
    },
}


@dataclass(frozen=True)
class DomainOraclePlugin:
    name: str
    family: str
    builder: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


DOMAIN_ORACLES: dict[str, DomainOraclePlugin] = {}


def register_domain_oracle(
    name: str,
    family: str,
    builder: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
) -> None:
    if family not in FAMILIES:
        raise WebContractError(f"unsupported domain oracle family: {family}")
    if name in DOMAIN_ORACLES:
        raise WebContractError(f"duplicate domain oracle plugin: {name}")
    DOMAIN_ORACLES[name] = DomainOraclePlugin(name, family, builder)


def stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"{prefix}-{digest[:20]}"


def require_text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def require_list(value: Any, field: str, minimum: int = 1) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise WebContractError(f"{field} requires at least {minimum} values")
    return value


def validate_fixture(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError("business rule requires an owned fixture contract")
    if value.get("owned") is not True or not str(value.get("namespace") or ""):
        raise WebContractError("business fixture must be owned and namespaced")
    if value.get("irreversible") is True:
        raise WebContractError("irreversible business fixtures remain blocked")
    for field in ("factoryRef", "readbackRef", "cleanupRef", "version"):
        require_text(value.get(field), f"fixture.{field}")
    if value.get("factoryRef") == "generic-endpoint-mutation":
        raise WebContractError("generic endpoint mutation is not a fixture factory")
    return dict(value)


def default_rule_builder(rule: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    family = str(rule["family"])
    dimension = DISCOVERY_DIMENSIONS[family]
    oracle = rule.get("stateOracle")
    admitted_oracle = validate_oracle(oracle) if isinstance(oracle, dict) else None
    return {
        "id": stable_id("BLH", [rule["id"], context.get("prerequisiteVersion")]),
        "family": family,
        "title": rule["title"],
        "question": str(rule.get("question") or dimension["question"]),
        "rule": {
            "statement": rule["statement"],
            "basis": rule["basis"],
            "confidence": rule["basisConfidence"],
        },
        "attackerStartingAuthority": rule["attackerStartingAuthority"],
        "fixture": rule["fixture"],
        "actors": rule["actors"],
        "resources": rule["resources"],
        "normalWorkflow": rule["normalWorkflow"],
        "counterfactual": rule["counterfactual"],
        "variedDimension": dimension["variedDimension"],
        "minimumEvidence": dimension["minimumEvidence"],
        "stateOracle": admitted_oracle,
        "planningOnly": admitted_oracle is None,
        "promotionStage": "mechanism-supported"
        if admitted_oracle is not None
        else "observation",
        "sourceSupport": rule.get("sourceSupport"),
        "pairedConcurrencyApproved": bool(rule.get("pairedConcurrencyApproved")),
        "counterfactualExceptions": rule["counterfactualExceptions"],
        "blackboxReplayRequired": True,
    }


for _family in sorted(FAMILIES):
    register_domain_oracle(f"rule-bound:{_family}", _family, default_rule_builder)


def validate_rule(raw: Any, prerequisite_version: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WebContractError("business rule must be an object")
    family = str(raw.get("family") or "")
    if family not in FAMILIES:
        raise WebContractError("business rule family is unsupported")
    basis_confidence = str(raw.get("basisConfidence") or "")
    if basis_confidence not in {
        "owner-specified",
        "source-supported",
        "observed-normal-workflow",
    }:
        raise WebContractError("business rule needs an explicit trusted basis")
    normal = require_list(raw.get("normalWorkflow"), "normalWorkflow")
    counterfactual = require_list(raw.get("counterfactual"), "counterfactual")
    if normal == counterfactual:
        raise WebContractError("counterfactual must differ from the normal workflow")
    plugin = str(raw.get("oraclePlugin") or f"rule-bound:{family}")
    if plugin not in DOMAIN_ORACLES or DOMAIN_ORACLES[plugin].family != family:
        raise WebContractError("oraclePlugin is not registered for this family")
    exceptions = raw.get("counterfactualExceptions", {})
    if not isinstance(exceptions, dict):
        raise WebContractError("counterfactualExceptions must be an object")
    normalized_exceptions = {}
    for field in (
        "unsatisfiedRequirementRefs",
        "invalidatedValueRefs",
        "replayedValueRefs",
    ):
        values = exceptions.get(field, [])
        if not isinstance(values, list) or any(
            not str(value or "").strip() for value in values
        ):
            raise WebContractError(f"counterfactualExceptions.{field} must be a string list")
        normalized = list(map(str, values))
        if len(normalized) != len(set(normalized)):
            raise WebContractError(f"counterfactualExceptions.{field} has duplicates")
        normalized_exceptions[field] = normalized
    result = {
        "id": require_text(raw.get("id"), "rule.id"),
        "title": require_text(raw.get("title"), "rule.title"),
        "family": family,
        "statement": require_text(raw.get("statement"), "rule.statement"),
        "basis": require_text(raw.get("basis"), "rule.basis"),
        "basisConfidence": basis_confidence,
        "attackerStartingAuthority": require_text(
            raw.get("attackerStartingAuthority"), "rule.attackerStartingAuthority"
        ),
        "actors": require_list(raw.get("actors"), "rule.actors", 2),
        "resources": require_list(raw.get("resources"), "rule.resources"),
        "normalWorkflow": normal,
        "counterfactual": counterfactual,
        "fixture": validate_fixture(raw.get("fixture")),
        "stateOracle": raw.get("stateOracle"),
        "sourceSupport": raw.get("sourceSupport"),
        "oraclePlugin": plugin,
        "prerequisiteVersion": prerequisite_version,
        "pairedConcurrencyApproved": bool(raw.get("pairedConcurrencyApproved")),
        "counterfactualExceptions": normalized_exceptions,
    }
    if family == "bounded-concurrency" and raw.get("pairedConcurrencyApproved") is not True:
        raise WebContractError("bounded concurrency requires explicit paired approval")
    if family == "workflow-prerequisites" and not normalized_exceptions[
        "unsatisfiedRequirementRefs"
    ]:
        raise WebContractError(
            "workflow prerequisite testing must name the intentionally omitted prerequisite"
        )
    if family == "replay-idempotency" and not normalized_exceptions[
        "replayedValueRefs"
    ]:
        raise WebContractError("replay testing must name the intentionally replayed value")
    if family == "state-invalidation" and not normalized_exceptions[
        "invalidatedValueRefs"
    ]:
        raise WebContractError(
            "state invalidation testing must name the intentionally stale value"
        )
    if family == "transaction-integrity" and (
        result["fixture"].get("synthetic") is not True
        or result["fixture"].get("realFundsOrInventory") is not False
    ):
        raise WebContractError(
            "transaction integrity requires a program-approved synthetic fixture with no real funds or inventory"
        )
    if family == "replay-idempotency" and result["fixture"].get("disposable") is not True:
        raise WebContractError("replay testing requires a disposable bounded fixture")
    return result


def compile_business_logic(
    workflow_model: dict[str, Any], rule_document: dict[str, Any]
) -> dict[str, Any]:
    if workflow_model.get("kind") != "krineon-web-workflow-model":
        raise WebContractError("input is not a Krineon workflow model")
    if rule_document.get("schemaVersion") != 1:
        raise WebContractError("business rule document schemaVersion must be 1")
    prerequisite_version = require_text(
        rule_document.get("prerequisiteVersion"), "prerequisiteVersion"
    )
    context = {
        "prerequisiteVersion": prerequisite_version,
        "identityModel": workflow_model.get("identityModel", []),
        "resourceModel": workflow_model.get("resourceModel", []),
        "workflowModel": workflow_model.get("workflowModel", []),
    }
    rules = [
        validate_rule(value, prerequisite_version)
        for value in require_list(rule_document.get("rules"), "rules")
    ]
    hypotheses = [
        DOMAIN_ORACLES[rule["oraclePlugin"]].builder(rule, context) for rule in rules
    ]
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-business-logic",
        "prerequisiteVersion": prerequisite_version,
        "hypotheses": hypotheses,
        "discoveryDimensions": DISCOVERY_DIMENSIONS,
        "policy": {
            "unusualBehaviorIsUnsafe": False,
            "explicitRuleRequired": True,
            "ownedFixtureRequired": True,
            "authoritativeReadbackRequired": True,
            "nucleiReplacesWorkflowDiscovery": False,
            "identitySubstitutionReplacesWorkflowDiscovery": False,
            "recordUsefulPrimitiveWithoutInventingTerminal": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow_model", type=Path)
    parser.add_argument("rules", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        workflow_model = json.loads(args.workflow_model.read_text(encoding="utf-8"))
        rules = json.loads(args.rules.read_text(encoding="utf-8"))
        result = compile_business_logic(workflow_model, rules)
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"hypotheses": len(result["hypotheses"])}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
