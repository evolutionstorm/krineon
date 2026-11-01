#!/usr/bin/env python3
"""Validate and evaluate bounded web cache poisoning and deception experiments.

This module performs no target traffic. The controlled web broker or Chrome CDP
runner executes the referenced workflows. This module decides whether retained
observations prove a shared-cache invariant break rather than reflection, local
browser state, content negotiation, or stale deployment output.
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


CACHE_LAYERS = {
    "browser-memory",
    "browser-disk",
    "service-worker-cache-api",
    "application-cache",
    "reverse-proxy",
    "cdn",
    "unknown",
}
SHARED_LAYERS = {"application-cache", "reverse-proxy", "cdn"}
DIMENSIONS = {
    "query",
    "path",
    "selected-header",
    "host-authority",
    "content-negotiation",
    "identity",
}
MODES = {"poisoning", "deception"}
ROLES = {
    "clean-baseline",
    "attacker-prime",
    "victim-fetch",
    "canonical-authenticated",
    "canonical-anonymous-control",
    "enforcing-control",
    "cleanup-verify",
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def string_list(value: Any, field: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise WebContractError(f"{field} requires at least {minimum} entries")
    result = [text(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} contains duplicates")
    return result


def validate_experiment(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("cache experiment schemaVersion must be 1")
    if raw.get("kind") != "krineon-web-cache-experiment":
        raise WebContractError("input is not a Krineon cache experiment")
    for field in ("id", "prerequisiteVersion", "title"):
        text(raw.get(field), field)
    mode = str(raw.get("mode") or "")
    if mode not in MODES:
        raise WebContractError("cache experiment mode must be poisoning or deception")
    layer = str(raw.get("observedCacheLayer") or "")
    if layer not in CACHE_LAYERS:
        raise WebContractError("observedCacheLayer is unsupported")
    identities = raw.get("identities")
    if not isinstance(identities, dict):
        raise WebContractError("cache experiment requires identities")
    required_identities = {"attacker", "victim"}
    if mode == "deception":
        required_identities.add("privateOwner")
    for role in required_identities:
        identity = identities.get(role)
        if not isinstance(identity, dict):
            raise WebContractError(f"cache experiment requires {role} identity")
        for field in ("actorRef", "profileRef", "credentialBindingVersion"):
            text(identity.get(field), f"identities.{role}.{field}")
    if identities["attacker"]["profileRef"] == identities["victim"]["profileRef"]:
        raise WebContractError("attacker and victim require independent profiles")
    dimension = raw.get("disputedDimension")
    if not isinstance(dimension, dict) or dimension.get("kind") not in DIMENSIONS:
        raise WebContractError("cache experiment requires one supported disputed dimension")
    for field in ("baseline", "attackerRepresentation", "victimRepresentation", "hypothesis"):
        text(dimension.get(field), f"disputedDimension.{field}")
    isolation = raw.get("isolation")
    if not isinstance(isolation, dict):
        raise WebContractError("cache experiment requires an isolation contract")
    live_mutation = isolation.get("liveSharedCacheMutation") is True
    if live_mutation:
        if isolation.get("established") is not True:
            raise WebContractError("live cache mutation requires proven isolation")
        if isolation.get("basis") not in {
            "owner-provided-staging",
            "cache-key-proof",
            "isolated-owned-cache-fixture",
        }:
            raise WebContractError("live cache mutation lacks an accepted isolation basis")
        if isolation.get("randomMarkerIsSoleBasis") is not False:
            raise WebContractError("a random query or path marker does not prove cache isolation")
        string_list(isolation.get("evidence"), "isolation.evidence")
        if isolation.get("exactSharedEffectApproved") is not True:
            raise WebContractError("live shared-cache mutation requires exact owner approval")
        string_list(isolation.get("approvalEvidence"), "isolation.approvalEvidence")
    elif isolation.get("established") is True:
        if isolation.get("basis") not in {
            "owner-provided-staging",
            "isolated-owned-cache-fixture",
        }:
            raise WebContractError("non-live mutation must use an owned fixture or staging environment")
        if isolation.get("randomMarkerIsSoleBasis") is not False:
            raise WebContractError("a random query or path marker does not prove cache isolation")
        string_list(isolation.get("evidence"), "isolation.evidence")
    elif isolation.get("planningOnly") is not True:
        raise WebContractError("unisolated cache experiments must remain planning-only")
    safety = raw.get("safety")
    if not isinstance(safety, dict):
        raise WebContractError("cache experiment requires safety limits")
    if any(
        safety.get(field) is not False
        for field in (
            "broadPurge",
            "commonRoutePoisoning",
            "evictionResearch",
            "fiveXXCaching",
            "availabilityImpact",
            "cacheControlNoCacheAssumedPurge",
        )
    ):
        raise WebContractError("cache experiment permits a prohibited shared-cache effect")
    for field in ("approvedTtlSeconds", "maxRequests", "maxStateChangingEffects"):
        value = safety.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WebContractError(f"safety.{field} must be a non-negative integer")
    text(safety.get("cleanupBehavior"), "safety.cleanupBehavior")
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WebContractError("cache experiment requires bounded workflow steps")
    roles: dict[str, dict[str, Any]] = {}
    for step in steps:
        if not isinstance(step, dict):
            raise WebContractError("cache steps must be objects")
        role = str(step.get("role") or "")
        if role not in ROLES or role in roles:
            raise WebContractError("cache step roles must be supported and unique")
        roles[role] = step
        for field in ("id", "workflowRef", "actorRef", "resourceRef"):
            text(step.get(field), f"cache step {role}.{field}")
        if step.get("ordinaryRepresentation") not in {True, False}:
            raise WebContractError("cache step ordinaryRepresentation must be Boolean")
    required_roles = {
        "clean-baseline",
        "attacker-prime",
        "victim-fetch",
        "enforcing-control",
        "cleanup-verify",
    }
    if mode == "deception":
        required_roles.update({"canonical-authenticated", "canonical-anonymous-control"})
    if not required_roles.issubset(roles):
        raise WebContractError("cache experiment lacks required baseline, victim, control, or cleanup steps")
    canary = raw.get("canary")
    if not isinstance(canary, dict):
        raise WebContractError("cache experiment requires a synthetic canary")
    text(canary.get("sha256"), "canary.sha256")
    if canary.get("owned") is not True or canary.get("synthetic") is not True:
        raise WebContractError("cache canary must be synthetic and researcher-owned")
    if mode == "deception" and canary.get("privateToActorRef") != identities["privateOwner"]["actorRef"]:
        raise WebContractError("deception canary must be private to the owned source actor")
    explanations = raw.get("competingExplanations")
    if not isinstance(explanations, list) or len(explanations) < 3:
        raise WebContractError("cache experiment requires at least three competing explanations")
    for explanation in explanations:
        text(explanation.get("id") if isinstance(explanation, dict) else None, "explanation.id")
        text(explanation.get("statement") if isinstance(explanation, dict) else None, "explanation.statement")
    return dict(raw)


def validate_cache_metadata(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError(f"{field} must be an object")
    required = (
        "age",
        "via",
        "vary",
        "etag",
        "timestamp",
        "cookiesPresent",
        "cachePartitionSignals",
    )
    if any(item not in value for item in required):
        raise WebContractError(f"{field} must retain Age, Via, Vary, ETag, timestamp, cookies, and partition signals")
    text(value.get("timestamp"), f"{field}.timestamp")
    if not isinstance(value.get("cookiesPresent"), bool):
        raise WebContractError(f"{field}.cookiesPresent must be Boolean")
    if not isinstance(value.get("cachePartitionSignals"), list):
        raise WebContractError(f"{field}.cachePartitionSignals must be a list")
    return dict(value)


def validate_observation(value: Any, step_ids: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError("cache observation must be an object")
    for field in ("id", "stepId", "actorRef", "profileRef", "method", "resourceIdentity"):
        text(value.get(field), f"observation.{field}")
    if value["stepId"] not in step_ids:
        raise WebContractError("cache observation references an unknown step")
    if str(value["method"]).upper() not in {"GET", "HEAD", "POST"}:
        raise WebContractError("cache observation method is unsupported")
    if not isinstance(value.get("ordinaryRequest"), bool) or not isinstance(
        value.get("disputedInputPresent"), bool
    ):
        raise WebContractError("cache observation must classify ordinary and disputed input")
    response = value.get("response")
    if not isinstance(response, dict):
        raise WebContractError("cache observation requires a response")
    for field in ("status", "bodySha256", "canarySha256"):
        if field not in response:
            raise WebContractError(f"cache response requires {field}")
    for field in (
        "syntheticCanarySeen",
        "privateCanarySeen",
        "genericShell",
        "redirect",
        "publicContent",
        "requestSpecificReflection",
    ):
        if not isinstance(response.get(field), bool):
            raise WebContractError(f"cache response {field} must be Boolean")
    provenance = response.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("layer") not in CACHE_LAYERS:
        raise WebContractError("cache response requires classified provenance")
    if not isinstance(provenance.get("sharedReuseProved"), bool):
        raise WebContractError("cache provenance must state whether shared reuse was proved")
    string_list(provenance.get("evidence"), "response.provenance.evidence")
    validate_cache_metadata(value.get("cacheMetadata"), "observation.cacheMetadata")
    return dict(value)


def evaluate(spec_raw: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    spec = validate_experiment(spec_raw)
    if spec["isolation"].get("established") is not True:
        return {"outcome": "inconclusive", "reason": "cache-isolation-not-established"}
    if document.get("schemaVersion") != 1 or document.get("kind") != "krineon-web-cache-observations":
        raise WebContractError("input is not a cache observation document")
    if document.get("prerequisiteVersion") != spec["prerequisiteVersion"]:
        return {"outcome": "inconclusive", "reason": "deployment-drift"}
    steps = {value["id"]: value for value in spec["steps"]}
    by_role: dict[str, dict[str, Any]] = {}
    for raw in document.get("observations", []):
        observation = validate_observation(raw, set(steps))
        role = steps[observation["stepId"]]["role"]
        if role in by_role:
            raise WebContractError(f"duplicate cache observation for role {role}")
        if observation["actorRef"] != steps[observation["stepId"]]["actorRef"]:
            raise WebContractError("cache observation actor differs from the signed step")
        by_role[role] = observation
    required = {value["role"] for value in spec["steps"]}
    missing = sorted(required.difference(by_role))
    if missing:
        return {"outcome": "inconclusive", "reason": "missing-telemetry", "missingRoles": missing}
    cleanup = document.get("cleanup")
    if not isinstance(cleanup, dict):
        return {"outcome": "inconclusive", "reason": "cleanup-missing"}
    if cleanup.get("broaderEffectObserved") is True:
        return {"outcome": "inconclusive", "reason": "broader-cache-effect-stop"}
    if cleanup.get("ownedEntryExpiredOrRemoved") is not True or not cleanup.get("evidence"):
        return {"outcome": "inconclusive", "reason": "cleanup-unverified"}
    attacker = by_role["attacker-prime"]
    victim = by_role["victim-fetch"]
    control = by_role["enforcing-control"]
    expected_profiles = {
        "attacker-prime": spec["identities"]["attacker"]["profileRef"],
        "victim-fetch": spec["identities"]["victim"]["profileRef"],
    }
    if spec["mode"] == "deception":
        expected_profiles["canonical-authenticated"] = spec["identities"][
            "privateOwner"
        ]["profileRef"]
    for role, profile in expected_profiles.items():
        if by_role[role]["profileRef"] != profile:
            return {"outcome": "inconclusive", "reason": f"{role}-profile-binding-mismatch"}
    if attacker["profileRef"] == victim["profileRef"]:
        return {"outcome": "inconclusive", "reason": "victim-profile-not-independent"}
    victim_response = victim["response"]
    provenance = victim_response["provenance"]
    shared = provenance["layer"] in SHARED_LAYERS and provenance["sharedReuseProved"] is True
    if spec["observedCacheLayer"] != "unknown" and provenance["layer"] != spec["observedCacheLayer"]:
        return {"outcome": "inconclusive", "reason": "cache-layer-classification-drift"}
    confounder = any(
        victim_response[field]
        for field in (
            "genericShell",
            "redirect",
            "publicContent",
            "requestSpecificReflection",
        )
    )
    control_enforces = not control["response"][
        "syntheticCanarySeen" if spec["mode"] == "poisoning" else "privateCanarySeen"
    ]
    if spec["mode"] == "poisoning":
        proved = (
            attacker["response"]["syntheticCanarySeen"]
            and victim_response["syntheticCanarySeen"]
            and victim_response["canarySha256"] == spec["canary"]["sha256"]
            and victim_response["bodySha256"] == attacker["response"]["bodySha256"]
            and victim["resourceIdentity"] == attacker["resourceIdentity"]
            and victim["ordinaryRequest"]
            and not victim["disputedInputPresent"]
            and shared
            and not confounder
            and control_enforces
        )
        return {
            "outcome": "confirmed-cache-poisoning-primitive" if proved else "invariant-preserved",
            "reportableImpact": "primitive-only" if proved else "none",
            "cacheLayer": provenance["layer"],
            "sharedReuseProved": shared,
            "independentVictim": True,
            "confounderObserved": confounder,
            "note": "RCE, XSS, account compromise, or cross-tenant impact requires separate proof.",
        }
    canonical = by_role["canonical-authenticated"]
    anonymous = by_role["canonical-anonymous-control"]
    proved = (
        canonical["response"]["privateCanarySeen"]
        and canonical["response"]["canarySha256"] == spec["canary"]["sha256"]
        and not anonymous["response"]["privateCanarySeen"]
        and attacker["response"]["privateCanarySeen"]
        and victim_response["privateCanarySeen"]
        and victim_response["canarySha256"] == spec["canary"]["sha256"]
        and victim_response["bodySha256"] == attacker["response"]["bodySha256"]
        and victim["resourceIdentity"] == attacker["resourceIdentity"]
        and victim["ordinaryRequest"]
        and not victim["disputedInputPresent"]
        and shared
        and not confounder
        and control_enforces
    )
    return {
        "outcome": "confirmed-cache-deception-disclosure" if proved else "invariant-preserved",
        "reportableImpact": "owned-private-canary-disclosure" if proved else "none",
        "cacheLayer": provenance["layer"],
        "sharedReuseProved": shared,
        "independentVictim": True,
        "confounderObserved": confounder,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("experiment", type=Path)
    run = sub.add_parser("evaluate")
    run.add_argument("experiment", type=Path)
    run.add_argument("observations", type=Path)
    run.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        spec = validate_experiment(load_object(args.experiment))
        if args.command == "validate":
            print(json.dumps({"valid": True, "id": spec["id"]}, indent=2))
            return 0
        result = evaluate(spec, load_object(args.observations))
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not str(result["outcome"]).startswith("inconclusive") else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
