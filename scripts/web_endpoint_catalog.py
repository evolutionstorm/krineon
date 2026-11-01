#!/usr/bin/env python3
"""Merge JavaScript/API extraction records into a measured endpoint catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from .semantic_ir import stable_id
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from semantic_ir import stable_id
    from web_contract import WebContractError, atomic_json


CONFIDENCE_RANK = {
    "literal-hint": 0,
    "ast-resolved": 1,
    "runtime-observed": 2,
    "independently-replayed": 3,
}
AUTHORITY_HINTS = re.compile(
    r"(?i)(?:invit|grant|member|approv|final|import|export|job|share|redeem|token|serializ|private|admin|permission|role)"
)


def read_extraction(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("kind") != "krineon-web-js-api-extraction":
        raise WebContractError(f"not a Krineon JS/API extraction: {path}")
    return value


def semantic_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("canonicalOrigin", ""),
        row.get("semanticPathTemplate", ""),
        tuple(sorted(map(str, row.get("candidateMethods", [])))),
        row.get("operationKind", ""),
        row.get("graphqlOperation", ""),
        row.get("persistedQueryHash", ""),
        row.get("rpcAction", ""),
        row.get("requestContentType", ""),
        row.get("identityBehaviorKey", ""),
        row.get("securityVersion", ""),
        row.get("deploymentEpoch", ""),
    )


def correlation_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Correlate static and runtime evidence without collapsing operation variants."""

    return (
        row.get("canonicalOrigin", ""),
        row.get("semanticPathTemplate", ""),
        tuple(sorted(map(str, row.get("candidateMethods", [])))),
        row.get("operationKind", ""),
        row.get("graphqlOperation", ""),
        row.get("rpcAction", ""),
        row.get("actor", "anonymous"),
        row.get("tenant", ""),
        row.get("deploymentEpoch", ""),
    )


def endpoint_record(rows: list[dict[str, Any]]) -> dict[str, Any]:
    best = max(rows, key=lambda row: CONFIDENCE_RANK.get(str(row.get("confidence")), -1))
    confidence = str(best.get("confidence") or "literal-hint")
    variants = []
    actors = set()
    tenants = set()
    prerequisites = set()
    provenance = []
    for row in rows:
        actors.add(str(row.get("actor") or "anonymous"))
        if row.get("tenant"):
            tenants.add(str(row["tenant"]))
        prerequisites.update(map(str, row.get("workflowPrerequisites", [])))
        provenance.append(row.get("provenance") or {})
        variants.append(
            {
                "rawPathTemplate": row.get("rawPathTemplate"),
                "queryFields": row.get("symbolicQueryFields", []),
                "bodyFields": row.get("symbolicBodyFields", []),
                "actor": row.get("actor", "anonymous"),
                "tenant": row.get("tenant", ""),
                "confidence": row.get("confidence"),
                "sourceLocation": row.get("sourceLocation", {}),
                "sourceMapMapping": row.get("sourceMapMapping", {}),
            }
        )
    sensitive_text = " ".join(
        str(best.get(field) or "")
        for field in (
            "semanticPathTemplate", "graphqlOperation", "rpcAction", "callee"
        )
    )
    hints = sorted(set(AUTHORITY_HINTS.findall(sensitive_text)))
    return {
        **best,
        "endpointId": stable_id("WEB-CAT", semantic_key(best)),
        "confidence": confidence,
        "observedAtRuntime": any(row.get("confidence") == "runtime-observed" for row in rows),
        "independentlyReplayed": any(row.get("confidence") == "independently-replayed" for row in rows),
        "actors": sorted(actors),
        "tenants": sorted(tenants),
        "workflowPrerequisites": sorted(prerequisites),
        "variants": variants,
        "provenance": provenance,
        "authorityOrStateTransitionNameHints": hints,
        "nameHintsAreVulnerabilityEvidence": False,
        "effectClassification": str(best.get("effectClassification") or "unknown"),
        "scopeApprovalStatus": str(best.get("scopeApprovalStatus") or "candidate-not-authorized"),
        "safeValidationEligible": (
            str(best.get("effectClassification") or "unknown") != "unknown"
            and str(best.get("scopeApprovalStatus") or "").startswith("approved")
        ),
    }


def build_catalog(paths: list[Path]) -> dict[str, Any]:
    values = [read_extraction(path) for path in paths]
    epochs = sorted({str(value.get("deploymentEpoch") or "") for value in values})
    if len(epochs) != 1:
        raise WebContractError(
            "endpoint catalogs cannot mix incompatible deployment epochs"
        )
    all_rows = [
        row
        for value in values
        for collection in ("endpointCandidates", "runtimeOperations")
        for row in value.get(collection, [])
        if isinstance(row, dict)
    ]
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        grouped[semantic_key(row)].append(row)
    endpoints = [endpoint_record(rows) for _, rows in sorted(grouped.items(), key=lambda item: str(item[0]))]
    static_by_correlation: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    runtime_by_correlation: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        destination = (
            runtime_by_correlation
            if row.get("confidence") == "runtime-observed"
            else static_by_correlation
        )
        destination[correlation_key(row)].append(row)
    static_runtime_correlations = [
        {
            "correlationId": stable_id("WEB-CORR", key),
            "staticEndpointIds": sorted({str(row.get("endpointId")) for row in static_by_correlation[key]}),
            "runtimeEndpointIds": sorted({str(row.get("endpointId")) for row in runtime_by_correlation[key]}),
            "confidence": "runtime-observed",
            "interpretation": "same actor, operation, path, and deployment; content-type variants remain separate catalog entries",
        }
        for key in sorted(set(static_by_correlation) & set(runtime_by_correlation), key=str)
    ]

    hints = [item for value in values for item in value.get("literalHints", [])]
    hint_keys = {
        (
            item.get("canonicalOrigin", ""),
            item.get("semanticPathTemplate", ""),
            item.get("originatingScriptSha256", ""),
            (item.get("sourceLocation") or {}).get("line"),
        ): item
        for item in hints
    }
    runtime_keys = {
        (row.get("canonicalOrigin", ""), row.get("semanticPathTemplate", ""))
        for row in all_rows
        if row.get("confidence") == "runtime-observed"
    }
    static_unobserved = [
        endpoint for endpoint in endpoints if not endpoint["observedAtRuntime"]
    ]
    role_surfaces: dict[str, set[str]] = defaultdict(set)
    for row in all_rows:
        if row.get("confidence") != "runtime-observed":
            continue
        role_surfaces[str(row.get("actor") or "anonymous")].add(
            stable_id("WEB-CAT", semantic_key(row))
        )
    actors = sorted(role_surfaces)
    role_differences = []
    for left in actors:
        for right in actors:
            if left >= right:
                continue
            role_differences.append(
                {
                    "leftActor": left,
                    "rightActor": right,
                    "leftOnly": sorted(role_surfaces[left] - role_surfaces[right]),
                    "rightOnly": sorted(role_surfaces[right] - role_surfaces[left]),
                    "interpretation": "observed-surface-difference-not-authorization-proof",
                }
            )

    hypotheses = []
    for endpoint in static_unobserved:
        if not endpoint["authorityOrStateTransitionNameHints"]:
            continue
        hypotheses.append(
            {
                "id": stable_id("WEB-WF-H", endpoint["endpointId"], "activation"),
                "endpointId": endpoint["endpointId"],
                "statement": (
                    "A legitimate role-specific journey may activate this static "
                    "authority or state-transition candidate."
                ),
                "confidence": "hypothesized",
                "notAVulnerabilityVerdict": True,
                "cheapestExperiment": (
                    "Use the owning disposable fixture and legitimate UI journey, "
                    "then require a CDP runtime request with an independently read state change."
                ),
                "blockedUntil": [
                    "effect is reviewed",
                    "scope and actor are approved",
                    "dynamic identifiers come from owned fixture state",
                ],
            }
        )
        if len(hypotheses) >= 25:
            break

    review_queue = [
        {
            "endpointId": hypothesis["endpointId"],
            "reason": "unobserved static candidate is connected to an authority or state-transition name hint",
            "nameHintIsEvidence": False,
            "dispatchAuthorized": False,
            "requiredReview": [
                "classify effect",
                "confirm exact scope and actor",
                "obtain dynamic values from an owned legitimate journey",
                "define an enforcing negative control",
            ],
        }
        for hypothesis in hypotheses[:10]
    ]

    unavailable = [item for value in values for item in value.get("unavailableArtifacts", [])]
    unresolved = [item for value in values for item in value.get("unresolvedExpressions", [])]
    gaps = sorted(
        set(
            str(item)
            for value in values
            for item in value.get("coverageGaps", [])
        )
    )
    next_action: dict[str, Any]
    if unavailable:
        next_action = {
            "kind": "legitimate-journey-artifact-collection",
            "action": "Run the cheapest approved journey that loads the first unavailable observed chunk.",
            "artifact": unavailable[0],
        }
    elif hypotheses:
        next_action = {
            "kind": "workflow-activation",
            "action": hypotheses[0]["cheapestExperiment"],
            "endpointId": hypotheses[0]["endpointId"],
        }
    elif unresolved:
        next_action = {
            "kind": "resolve-expression",
            "action": "Capture the owning journey and runtime initiator for the first unresolved expression.",
            "expression": unresolved[0],
        }
    else:
        next_action = {
            "kind": "coverage-question",
            "action": "Obtain another approved role or owner-specified workflow prerequisite.",
        }

    artifacts = [item for value in values for item in value.get("artifactLedger", [])]
    map_available = sum(1 for item in artifacts if (item.get("sourceMap") or {}).get("available"))
    observed = sum(1 for item in endpoints if item["observedAtRuntime"])
    blocked = sum(1 for item in endpoints if not item["safeValidationEligible"])
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-endpoint-catalog",
        "deploymentEpoch": epochs[0],
        "inputs": [
            {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in paths
        ],
        "coverageClaim": "measured-partial-never-all-apis",
        "endpoints": endpoints,
        "literalHints": list(hint_keys.values()),
        "runtimeMatchedHintCount": sum(
            1
            for item in hint_keys.values()
            if (item.get("canonicalOrigin", ""), item.get("semanticPathTemplate", ""))
            in runtime_keys
        ),
        "roleSurfaceDifferences": role_differences,
        "staticRuntimeCorrelations": static_runtime_correlations,
        "workflowHypotheses": hypotheses,
        "reviewQueue": review_queue,
        "ledger": {
            "artifactsFetched": len(artifacts),
            "artifactsUnavailable": unavailable,
            "sourceMapsAvailable": map_available,
            "journeys": [item for value in values for item in value.get("journeys", [])],
            "unresolvedExpressions": unresolved,
            "observedOperations": observed,
            "blockedEffectsOrApproval": blocked,
            "coverageGaps": gaps,
            "nextCheapestLegitimateAction": next_action,
        },
        "policy": {
            "stringsAuthorizeDispatch": False,
            "safeMethodsAssumedHarmless": False,
            "thirdPartyHostsAutoScoped": False,
            "suspectedSecretsValidatedExternally": False,
            "namesAreRiskScores": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extraction", nargs="+")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        paths = [Path(item).expanduser().resolve() for item in args.extraction]
        result = build_catalog(paths)
        atomic_json(Path(args.output).expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"endpoints": len(result["endpoints"]), "literalHints": len(result["literalHints"]), "workflowHypotheses": len(result["workflowHypotheses"]), "coverageClaim": result["coverageClaim"]}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
