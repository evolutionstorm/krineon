#!/usr/bin/env python3
"""Build Krineon's evidence-linked semantic intermediate representation.

The IR does not decide that a vulnerability exists. It records scoped data
flow, aliases, mutations, control candidates, cross-module edges, authority and
ownership changes, generated-bundle mappings, and runtime observations. Any
missing semantic fact becomes an explicit experiment requirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def stable_id(prefix: str, *parts: Any) -> str:
    encoded = json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def runtime_index(observations: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        fact_id = str(observation.get("factId") or "")
        if fact_id:
            result.setdefault(fact_id, []).append(observation)
    return result


def operation_nodes(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kinds = {
        "authentication-signal",
        "call-operation",
        "assignment",
        "property-assignment",
        "cache-operation",
        "dynamic-import",
        "environment-read",
        "http-handler",
    }
    nodes: list[dict[str, Any]] = []
    for fact in facts:
        if fact.get("kind") not in kinds:
            continue
        nodes.append(
            {
                "id": fact.get("id"),
                "kind": fact.get("kind"),
                "module": fact.get("source"),
                "scope": fact.get("scopeId", "module"),
                "position": {
                    "line": fact.get("line"),
                    "column": fact.get("column"),
                    "tokenIndex": fact.get("tokenIndex"),
                },
                "controlPath": fact.get("controlPath", []),
                "callee": fact.get("callee"),
                "defines": [fact["targetSymbol"]]
                if fact.get("targetSymbol")
                else ([fact["resultSymbol"]] if fact.get("resultSymbol") else []),
                "uses": sorted(
                    set(map(str, fact.get("sourceIdentifiers", [])))
                    | set(map(str, fact.get("argumentIdentifiers", [])))
                    | set(map(str, fact.get("receiverSymbols", [])))
                ),
                "propertyPath": fact.get("propertyPath", []),
                "sourceFact": fact.get("id"),
            }
        )
    return nodes


def data_edges(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for fact in facts:
        if fact.get("kind") not in {"assignment", "property-assignment"}:
            continue
        target = str(fact.get("targetSymbol") or "")
        sources = list(map(str, fact.get("sourceIdentifiers", []))) or ["<constant>"]
        for source in sources:
            edges.append(
                {
                    "id": stable_id("IR-E", fact.get("id"), source, target),
                    "kind": "alias" if fact.get("kind") == "assignment" else "mutation",
                    "sourceValue": source,
                    "targetValue": target,
                    "baseObject": fact.get("baseSymbol"),
                    "scope": fact.get("scopeId", "module"),
                    "controlPath": fact.get("controlPath", []),
                    "sourceFact": fact.get("id"),
                    "confidence": "structural-candidate",
                }
            )
    return edges


def control_flow_graphs(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build conservative function-scoped CFG candidates.

    These graphs preserve lexical scopes and branch paths. They are useful for
    scheduling runtime dominance probes, but are never labelled exact unless a
    target-specific runtime observer supplies that proof.
    """

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for operation in operations:
        grouped.setdefault(
            (str(operation.get("module") or ""), str(operation.get("scope") or "module")),
            [],
        ).append(operation)
    graphs: list[dict[str, Any]] = []
    for (module, scope), rows in sorted(grouped.items()):
        ordered = sorted(
            rows,
            key=lambda row: (
                int((row.get("position") or {}).get("tokenIndex") or -1),
                str(row.get("id") or ""),
            ),
        )
        edges = []
        for left, right in zip(ordered, ordered[1:]):
            left_path = list(left.get("controlPath") or [])
            right_path = list(right.get("controlPath") or [])
            edges.append(
                {
                    "from": left.get("id"),
                    "to": right.get("id"),
                    "kind": "lexical-successor",
                    "branchTransition": {
                        "from": left_path,
                        "to": right_path,
                    },
                }
            )
        graphs.append(
            {
                "id": stable_id("IR-CFG", module, scope),
                "module": module,
                "scope": scope,
                "nodes": [row.get("id") for row in ordered],
                "edges": edges,
                "dominanceConfidence": "structural-candidate-runtime-proof-required",
            }
        )
    return graphs


def module_edges(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": relation.get("id"),
            "sourceModule": relation.get("sourceModule"),
            "targetModule": relation.get("targetModule"),
            "specifier": relation.get("specifier"),
            "dynamic": relation.get("dynamic", False),
            "crossesDirectiveBoundary": relation.get("crossesDirectiveBoundary", False),
            "sourceFact": relation.get("sourceFact"),
            "bindings": relation.get("bindings", []),
        }
        for relation in relations
        if relation.get("kind") == "module-edge"
    ]


def cross_module_calls(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": relation.get("id"),
            "importFact": relation.get("importFact"),
            "callFact": relation.get("callFact"),
            "sourceModule": relation.get("sourceModule"),
            "targetModule": relation.get("targetModule"),
            "localBinding": relation.get("localBinding"),
            "importedSymbol": relation.get("importedSymbol"),
            "resolvedExport": relation.get("resolvedExport"),
            "targetExportObserved": relation.get("targetExportObserved", False),
            "status": relation.get("status"),
        }
        for relation in relations
        if relation.get("kind") == "cross-module-call"
    ]


def representation_edges(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relation in relations:
        if relation.get("kind") != "validated-transformation-consumer":
            continue
        previous = relation.get("validatedFact")
        for transformation in relation.get("transformations", []):
            current = transformation.get("fact")
            rows.append(
                {
                    "id": stable_id("IR-R", relation.get("id"), previous, current),
                    "fromFact": previous,
                    "toFact": current,
                    "callee": transformation.get("callee"),
                    "inputSymbol": transformation.get("inputSymbol"),
                    "outputSymbol": transformation.get("resultSymbol"),
                    "semanticEffect": "unknown-until-runtime-value-trace",
                }
            )
            previous = current
        rows.append(
            {
                "id": stable_id(
                    "IR-R", relation.get("id"), previous, relation.get("consumerFact")
                ),
                "fromFact": previous,
                "toFact": relation.get("consumerFact"),
                "callee": relation.get("consumerCallee"),
                "inputSymbol": relation.get("resultSymbol"),
                "outputSymbol": "consumer-selected-resource",
                "semanticEffect": "resource-selection-runtime-identity-required",
            }
        )
    return rows


def bundle_edges(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": relation.get("id"),
            "source": relation.get("source"),
            "generated": relation.get("generated"),
            "sourceLine": relation.get("sourceLine"),
            "generatedLine": relation.get("generatedLine"),
            "generatedColumn": relation.get("generatedColumn"),
        }
        for relation in relations
        if relation.get("kind") == "source-to-bundle"
    ]


def authority_transitions(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for fact in facts:
        kind = str(fact.get("kind") or "")
        if kind == "authentication-signal":
            before, after, transition = "untrusted-request", "authenticated-or-rejected", "authority-check"
        elif kind == "dynamic-import":
            before, after, transition = "data-specifier", "module-loading-authority", "code-loading"
        elif kind == "cache-operation":
            before, after, transition = "request-state", "shared-cache-state", "state-ownership"
        else:
            continue
        rows.append(
            {
                "id": stable_id("IR-A", fact.get("id"), transition),
                "kind": transition,
                "from": before,
                "to": after,
                "scope": fact.get("scopeId", "module"),
                "sourceFact": fact.get("id"),
                "runtimeVerificationRequired": True,
            }
        )
    return rows


def runtime_continuity(
    fact_ids: list[str], observations: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    rows = [row for fact_id in fact_ids for row in observations.get(fact_id, [])]
    required = ("objectIdentity", "generation", "principal", "process", "runtime")
    if not rows or any(any(row.get(field) in {None, ""} for field in required) for row in rows):
        return {
            "status": "unknown",
            "reason": "runtime identity, generation, principal, process, and runtime telemetry is incomplete",
            "observations": rows,
        }
    continuity = {
        field: len({str(row[field]) for row in rows}) == 1 for field in required
    }
    return {
        "status": "preserved" if all(continuity.values()) else "changed",
        "dimensions": continuity,
        "observations": rows,
    }


def build_security_paths(
    facts: list[dict[str, Any]],
    relations: list[dict[str, Any]],
    observations: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    by_id = {str(row.get("id")): row for row in facts}
    assignments = [
        row
        for row in facts
        if row.get("kind") in {"assignment", "property-assignment"}
    ]
    paths: list[dict[str, Any]] = []
    for relation in relations:
        if relation.get("kind") != "validated-transformation-consumer":
            continue
        check_id = str(relation.get("validatedFact") or "")
        consumer_id = str(relation.get("consumerFact") or "")
        transform_ids = list(map(str, relation.get("transformationFacts", [])))
        fact_ids = [check_id, *transform_ids, consumer_id]
        check = by_id.get(check_id, {})
        consumer = by_id.get(consumer_id, {})
        validated = set(map(str, relation.get("validatedSymbols", [])))
        mutations = [
            row
            for row in assignments
            if row.get("source") == relation.get("source")
            and row.get("scopeId", "module") == relation.get("scopeId", "module")
            and (
                str(row.get("targetSymbol") or "") in validated
                or str(row.get("baseSymbol") or "") in validated
            )
            and int(row.get("tokenIndex", -1)) > int(check.get("tokenIndex", -1))
            and int(row.get("tokenIndex", -1)) < int(consumer.get("tokenIndex", 1 << 30))
        ]
        dominant = str(
            (relation.get("defUseChecks") or {}).get("controlFlowDominance") or "unknown"
        )
        runtime_rows = [row for fact_id in fact_ids for row in observations.get(fact_id, [])]
        checked_resources = {
            str(row.get("resourceIdentity"))
            for row in observations.get(check_id, [])
            if row.get("resourceIdentity") is not None
        }
        consumed_resources = {
            str(row.get("resourceIdentity"))
            for row in observations.get(consumer_id, [])
            if row.get("resourceIdentity") is not None
        }
        agreement = (
            "agreed"
            if checked_resources and checked_resources == consumed_resources
            else "disagreed"
            if checked_resources and consumed_resources
            else "unknown"
        )
        unknowns: list[str] = []
        if "runtime" in dominant or dominant == "unknown":
            unknowns.append("control-flow dominance is not runtime-confirmed")
        if mutations:
            unknowns.append("a validated alias or object property mutates before consumption")
        if agreement == "unknown":
            unknowns.append("checker and consumer resource identities were not both observed")
        continuity = runtime_continuity(fact_ids, observations)
        if continuity["status"] == "unknown":
            unknowns.append("end-to-end identity and authority continuity is unobserved")
        path_id = stable_id("IR-P", relation.get("id"), fact_ids)
        paths.append(
            {
                "id": path_id,
                "status": "runtime-verified" if not unknowns and agreement == "agreed" else "experiment-required",
                "attackerControlledValue": {
                    "symbols": sorted(validated),
                    "ingress": "request or route input validated by the recorded check",
                    "evidenceFact": check_id,
                },
                "transformations": [
                    {
                        "factId": value,
                        "callee": by_id.get(value, {}).get("callee"),
                        "resultSymbol": by_id.get(value, {}).get("resultSymbol"),
                    }
                    for value in transform_ids
                ],
                "dominatingChecks": [
                    {
                        "factId": check_id,
                        "candidateDominance": dominant,
                        "controlPath": check.get("controlPath", []),
                    }
                ],
                "aliasMutationRisk": {
                    "canInvalidate": bool(mutations),
                    "mutationFacts": [str(row.get("id")) for row in mutations],
                },
                "resourceAgreement": {
                    "status": agreement,
                    "checked": sorted(checked_resources),
                    "consumed": sorted(consumed_resources),
                },
                "continuity": continuity,
                "consumer": {"factId": consumer_id, "callee": consumer.get("callee")},
                "unknowns": unknowns,
                "runtimeObservations": runtime_rows,
                "sourceFacts": fact_ids,
            }
        )
    return paths


def build_experiment_candidates(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for path in paths:
        if path.get("status") != "experiment-required":
            continue
        candidates.append(
            {
                "id": stable_id("IR-X", path.get("id"), path.get("unknowns")),
                "pathId": path.get("id"),
                "question": "Do authorization and execution consume the same resource under the same object and authority history?",
                "competingExplanations": [
                    {"id": "H1", "claim": "checker and consumer transform or resolve the input differently"},
                    {"id": "H2", "claim": "the selected resource is intentionally public"},
                    {"id": "H3", "claim": "the observation is an error or fallback artifact"},
                    {"id": "H4", "claim": "a proxy or earlier component performed the transformation"},
                ],
                "oneVariable": "input representation",
                "requiredObservations": [
                    "raw request and response",
                    "check and consumer resource identities",
                    "object identity and generation",
                    "principal, process, and runtime",
                ],
                "expectedObservations": {
                    "H1": "same authorization result but different checked and consumed resource identities",
                    "H2": "the baseline reaches the same resource without protected authority",
                    "H3": "the attack response lacks the protected consumer identity",
                    "H4": "the representation changes before the recorded checker fact",
                },
                "executableOracle": False,
                "blockedReason": "a target adapter must bind these fact IDs to a production request and telemetry recipe",
                "uncertaintyRemoved": len(path.get("unknowns", [])),
                "estimatedExecutions": 3,
            }
        )
    return candidates


def build_semantic_ir(
    analysis: dict[str, Any],
    runtime_observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    facts = [row for row in analysis.get("facts", []) if isinstance(row, dict)]
    relations = [row for row in analysis.get("relations", []) if isinstance(row, dict)]
    observations = runtime_index(runtime_observations or [])
    operations = operation_nodes(facts)
    paths = build_security_paths(facts, relations, observations)
    return {
        "schemaVersion": 1,
        "producer": "krineon-semantic-ir",
        "framework": analysis.get("framework"),
        "sourceAnalysisRunId": analysis.get("runId"),
        "operations": operations,
        "dataEdges": data_edges(facts),
        "controlFlowGraphs": control_flow_graphs(operations),
        "moduleEdges": module_edges(relations),
        "crossModuleCalls": cross_module_calls(relations),
        "requestRepresentationEdges": representation_edges(relations),
        "authorityAndOwnershipTransitions": authority_transitions(facts),
        "sourceBundleMappings": bundle_edges(relations),
        "securityPaths": paths,
        "experimentCandidates": build_experiment_candidates(paths),
        "contract": {
            "vulnerabilityVerdictsProduced": False,
            "unknownTransformationsBecomeExperiments": True,
            "runtimeIdentityRequiredForContinuity": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runtime-observations", type=Path)
    args = parser.parse_args(argv)
    try:
        analysis = read_object(args.analysis.expanduser().resolve())
        observations: list[dict[str, Any]] = []
        if args.runtime_observations:
            raw = json.loads(args.runtime_observations.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise RuntimeError("runtime observations must be a JSON list")
            observations = [row for row in raw if isinstance(row, dict)]
        write_json(args.output.expanduser().resolve(), build_semantic_ir(analysis, observations))
        print(args.output.expanduser().resolve())
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
