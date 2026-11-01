#!/usr/bin/env python3
"""Compile bounded ffuf-style candidates and import them as endpoint observations.

The adapter does not send target traffic. Candidate requests must be executed by
Krineon's broker so aggregate budgets, identity scope, and bot-protection stops
remain authoritative. Imported results are discovery observations, never
findings.
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


SOURCES = {
    "observed-client-path",
    "route-convention",
    "api-schema",
    "sibling-operation",
    "unresolved-symbolic-segment",
}
CONFOUNDERS = {
    "soft-404",
    "wildcard-route",
    "login-shell",
    "waf-page",
    "content-negotiation",
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


def validate_profile(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("ffuf profile schemaVersion must be 1")
    if raw.get("kind") != "krineon-ffuf-profile":
        raise WebContractError("input is not a Krineon ffuf profile")
    for field in ("id", "prerequisiteVersion", "identityRef", "originRef"):
        text(raw.get(field), field)
    if raw.get("browserFingerprintImpersonation") is not False or raw.get("botEvasion") is not False:
        raise WebContractError("ffuf adapter cannot impersonate browsers or evade bot protection")
    if raw.get("recursion") is not False:
        raise WebContractError("ffuf recursion is disabled")
    calibration = raw.get("calibration")
    if not isinstance(calibration, dict) or not isinstance(calibration.get("automatic"), bool):
        raise WebContractError("ffuf profile requires an explicit calibration policy")
    if calibration["automatic"]:
        if calibration.get("approved") is not True:
            raise WebContractError("automatic calibration requires exact approval")
        probes = calibration.get("maxProbes")
        if isinstance(probes, bool) or not isinstance(probes, int) or not 1 <= probes <= 4:
            raise WebContractError("approved calibration permits at most four probes")
    elif calibration.get("maxProbes") != 0:
        raise WebContractError("disabled calibration must send zero probes")
    limits = raw.get("limits")
    if not isinstance(limits, dict):
        raise WebContractError("ffuf profile requires preflight limits")
    for field, ceiling in (
        ("maxCandidates", 128),
        ("maxCombinations", 256),
        ("maxRedirects", 4),
        ("maxRetries", 2),
        ("maxRequests", 256),
    ):
        value = limits.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ceiling:
            raise WebContractError(f"ffuf limits.{field} exceeds the bounded ceiling")
    candidates = raw.get("candidates")
    if not isinstance(candidates, list) or not candidates or len(candidates) > limits["maxCandidates"]:
        raise WebContractError("ffuf candidate list is empty or exceeds its bound")
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, dict) or candidate.get("source") not in SOURCES:
            raise WebContractError("ffuf candidates require an approved derivation source")
        candidate_id = text(candidate.get("id"), "candidate.id")
        if candidate_id in seen:
            raise WebContractError("ffuf candidate ids must be unique")
        seen.add(candidate_id)
        path = text(candidate.get("path"), f"candidate {candidate_id}.path")
        if not path.startswith("/") or "FUZZ" in path or "*" in path:
            raise WebContractError("ffuf candidates must be concrete bounded paths")
        text(candidate.get("rationale"), f"candidate {candidate_id}.rationale")
        evidence = candidate.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise WebContractError("ffuf candidates require provenance evidence")
    return dict(raw)


def compile_plan(profile_raw: dict[str, Any]) -> dict[str, Any]:
    profile = validate_profile(profile_raw)
    calibration = profile["calibration"]["maxProbes"]
    retries = profile["limits"]["maxRetries"]
    redirects = profile["limits"]["maxRedirects"]
    candidate_count = len(profile["candidates"])
    combinations = candidate_count * (1 + retries) * (1 + redirects) + calibration
    if combinations > profile["limits"]["maxCombinations"] or combinations > profile["limits"]["maxRequests"]:
        raise WebContractError("ffuf preflight work product exceeds the approved request bound")
    return {
        "schemaVersion": 1,
        "kind": "krineon-ffuf-candidate-plan",
        "profileId": profile["id"],
        "prerequisiteVersion": profile["prerequisiteVersion"],
        "identityRef": profile["identityRef"],
        "originRef": profile["originRef"],
        "candidates": profile["candidates"],
        "preflight": {
            "candidateCount": candidate_count,
            "calibrationProbes": calibration,
            "redirectAllowancePerCandidate": redirects,
            "retryAllowancePerCandidate": retries,
            "maximumRequests": combinations,
            "recursion": False,
        },
        "executionAdapter": "krineon-web-broker",
        "ffufDirectTargetTraffic": False,
        "semanticReplayRequired": True,
    }


def import_results(plan: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    if plan.get("kind") != "krineon-ffuf-candidate-plan":
        raise WebContractError("input is not an ffuf candidate plan")
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-ffuf-broker-results":
        raise WebContractError("input is not an ffuf broker result")
    if raw.get("prerequisiteVersion") != plan["prerequisiteVersion"]:
        return {"outcome": "inconclusive", "reason": "deployment-drift"}
    if raw.get("executedBy") != "krineon-web-broker":
        raise WebContractError("ffuf candidate traffic must be executed by the broker")
    observations = raw.get("observations")
    if not isinstance(observations, list):
        raise WebContractError("ffuf results require observations")
    candidates = {value["id"]: value for value in plan["candidates"]}
    if len(observations) > plan["preflight"]["maximumRequests"]:
        raise WebContractError("ffuf results exceed the preflight request bound")
    accepted = []
    blocked = []
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("candidateId") not in candidates:
            raise WebContractError("ffuf result references an unknown candidate")
        state = observation.get("accessState")
        if state in {"environment-blocked", "auth-inconclusive", "rate-limited"}:
            blocked.append(observation["candidateId"])
            continue
        confounders = set(observation.get("confounders", []))
        if not confounders.issubset(CONFOUNDERS):
            raise WebContractError("ffuf result contains an unsupported confounder")
        accepted.append(
            {
                "candidateId": observation["candidateId"],
                "path": candidates[observation["candidateId"]]["path"],
                "status": observation.get("status"),
                "bodySha256": observation.get("bodySha256"),
                "confounders": sorted(confounders),
                "classification": "endpoint-observation",
                "finding": False,
                "semanticReplayRequired": True,
            }
        )
    before = int(raw.get("workflowCoverageBefore") or 0)
    after = int(raw.get("workflowCoverageAfter") or 0)
    return {
        "schemaVersion": 1,
        "kind": "krineon-ffuf-endpoint-observations",
        "outcome": "environment-blocked" if blocked else "observations-imported",
        "observations": accepted,
        "blockedCandidateIds": blocked,
        "stopExpansion": bool(blocked or after <= before),
        "coverageImprovement": max(0, after - before),
        "findings": [],
        "semanticReplayRequired": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("profile", type=Path)
    plan.add_argument("--output", required=True, type=Path)
    imported = sub.add_parser("import")
    imported.add_argument("plan", type=Path)
    imported.add_argument("results", type=Path)
    imported.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = (
            compile_plan(load_object(args.profile))
            if args.command == "plan"
            else import_results(load_object(args.plan), load_object(args.results))
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"kind": result["kind"], "accepted": True}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
