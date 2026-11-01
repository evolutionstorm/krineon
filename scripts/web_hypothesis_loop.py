#!/usr/bin/env python3
"""Drive adaptive web hypotheses through Krineon's shared durable frontier."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

try:
    from .research_harness import (
        complete_profile_experiment_frontier,
        connect_orchestration,
        experiment_frontier_identity,
        get_metadata,
        schedule_experiment_frontier,
        set_metadata,
        sync_approach_family_registry,
        verified_web_observation,
    )
    from .semantic_ir import build_semantic_ir
    from .web_contract import WebContractError
    from .web_oracles import admit_contract, evaluate_contract
    from .web_execution_broker import main as run_http_broker
except ImportError:
    from research_harness import (
        complete_profile_experiment_frontier,
        connect_orchestration,
        experiment_frontier_identity,
        get_metadata,
        schedule_experiment_frontier,
        set_metadata,
        sync_approach_family_registry,
        verified_web_observation,
    )
    from semantic_ir import build_semantic_ir
    from web_contract import WebContractError
    from web_oracles import admit_contract, evaluate_contract
    from web_execution_broker import main as run_http_broker


CONFIDENCE = {"observed", "owner-specified", "source-supported", "hypothesized"}
SENSITIVE_KEY_PARTS = {
    "token",
    "secret",
    "password",
    "cookie",
    "authorization",
    "credential",
    "apikey",
    "api_key",
}
RANK_FIELDS = {
    "meaningfulImpact",
    "constraintsRemoved",
    "primitiveCompatibility",
    "discrimination",
    "attackerAcquisition",
    "cost",
    "cleanupRisk",
}


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


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


def string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise WebContractError(f"{field} must be a non-empty list")
    result = [text(item, field) for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} must not contain duplicates")
    return result


def reject_sensitive_version_material(value: Any, path: str = "version") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower().replace("-", "").replace("_", "")
            if any(part.replace("_", "") in lowered for part in SENSITIVE_KEY_PARTS):
                raise WebContractError(
                    f"{path}.{key} may not contribute token or credential material"
                )
            reject_sensitive_version_material(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_sensitive_version_material(item, f"{path}[{index}]")


def selected_mapping(value: Any, fields: tuple[str, ...], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError(f"{name} must be an object")
    selected = {
        field: value[field]
        for field in fields
        if value.get(field) is not None and value.get(field) != ""
    }
    if not selected:
        raise WebContractError(f"{name} has no stable version fields")
    return selected


def derive_prerequisite_version(document: dict[str, Any]) -> dict[str, Any]:
    """Hash stable, non-secret deployment and fixture identity components."""

    components = {
        "deployment": selected_mapping(
            document.get("deploymentObservations"),
            ("deploymentId", "release", "buildDigest", "observationEpoch"),
            "deploymentObservations",
        ),
        "workflow": selected_mapping(
            document.get("workflowContract"),
            ("schemaVersion", "contractSha256", "workflowVersion"),
            "workflowContract",
        ),
        "transport": selected_mapping(
            document.get("transportConfiguration"),
            ("protocol", "proxyChain", "tlsMode", "cacheLayer", "browserEngine"),
            "transportConfiguration",
        ),
        "identityCapability": document.get("identityCapabilityVersion"),
        "resourceFixture": document.get("resourceFixtureVersion"),
    }
    if components["identityCapability"] is None or components["identityCapability"] == "":
        raise WebContractError("identityCapabilityVersion is required")
    if components["resourceFixture"] is None or components["resourceFixture"] == "":
        raise WebContractError("resourceFixtureVersion is required")
    reject_sensitive_version_material(components)
    return {
        "schemaVersion": 1,
        "id": "web-prereq-v1-" + canonical_digest(components)[:24],
        "components": components,
    }


def ranking(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != RANK_FIELDS:
        raise WebContractError(
            "ranking must contain impact, constraint, compatibility, discrimination, "
            "acquisition, cost, and cleanup-risk fields only"
        )
    values: dict[str, int] = {}
    for field in RANK_FIELDS:
        value = raw.get(field)
        if not isinstance(value, int) or not 0 <= value <= 5:
            raise WebContractError(f"ranking.{field} must be an integer from 0 to 5")
        values[field] = value
    score = (
        6 * values["meaningfulImpact"]
        + 5 * values["constraintsRemoved"]
        + 4 * values["primitiveCompatibility"]
        + 5 * values["discrimination"]
        + 4 * values["attackerAcquisition"]
        - 3 * values["cost"]
        - 5 * values["cleanupRisk"]
    )
    return {**values, "score": score, "predictedSeverityRewarded": False}


def validate_explanations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 2:
        raise WebContractError("competingExplanations requires at least two entries")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise WebContractError("competing explanation must be an object")
        result.append(
            {
                "id": text(item.get("id"), f"competingExplanations[{index}].id"),
                "statement": text(
                    item.get("statement"), f"competingExplanations[{index}].statement"
                ),
                "expectedObservations": string_list(
                    item.get("expectedObservations"),
                    f"competingExplanations[{index}].expectedObservations",
                ),
            }
        )
    return result


def mechanism_fingerprint(hypothesis: dict[str, Any], scope: dict[str, Any]) -> str:
    # Titles and mechanism labels are deliberately excluded so renaming cannot
    # reset experiment history or budgets.
    identity = {
        "boundary": hypothesis["securityInvariant"]["statement"],
        "basis": hypothesis["securityInvariant"]["basis"],
        "scopeInputs": scope["relevantInputs"],
        "scopeConfiguration": scope["configuration"],
        "scopeState": scope["state"],
        "prerequisiteVersion": scope["prerequisiteVersion"],
    }
    return "WM-" + canonical_digest(identity)[:20]


def normalized_prior_negatives(connection: Any) -> list[dict[str, Any]]:
    values = []
    for row in connection.execute(
        "SELECT outcome_json FROM experiment_frontier WHERE state='refuted'"
    ).fetchall():
        try:
            outcome = json.loads(row["outcome_json"] or "{}")
        except json.JSONDecodeError:
            continue
        negative = outcome.get("scopedNegativeKnowledge")
        if isinstance(negative, dict):
            values.append(negative)
        elif isinstance(outcome.get("negativeKnowledge"), dict):
            values.append(outcome["negativeKnowledge"])
    return values


def validate_hypothesis(
    root: Path, raw: dict[str, Any], prerequisite_version: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    observed = raw.get("observedBehavior")
    if not isinstance(observed, dict):
        raise WebContractError("hypothesis observedBehavior must be an object")
    confidence = str(observed.get("confidence") or "")
    if confidence not in CONFIDENCE:
        raise WebContractError("observedBehavior.confidence is unsupported")
    invariant = raw.get("securityInvariant")
    if not isinstance(invariant, dict):
        raise WebContractError("securityInvariant must be an object")
    setup = raw.get("setup")
    if not isinstance(setup, dict):
        raise WebContractError("setup must be an object")
    experiment = raw.get("experiment")
    if not isinstance(experiment, dict):
        raise WebContractError("experiment must be an object")
    scope = experiment.get("experimentalScope")
    if not isinstance(scope, dict):
        raise WebContractError("experiment.experimentalScope must be an object")
    scope = dict(scope)
    scope["prerequisiteVersion"] = prerequisite_version
    for field in ("relevantInputs", "configuration", "state"):
        scope[field] = string_list(scope.get(field), f"experimentalScope.{field}")
    scope["mechanism"] = text(scope.get("mechanism"), "experimentalScope.mechanism")
    operation_sequence = experiment.get("operationSequence")
    if not isinstance(operation_sequence, list) or not operation_sequence:
        raise WebContractError("operationSequence must be a non-empty list")
    normalized_sequence = []
    request_count = 0
    effect_count = 0
    for index, operation in enumerate(operation_sequence):
        if not isinstance(operation, dict):
            raise WebContractError("operationSequence entry must be an object")
        operation_type = text(operation.get("type"), f"operationSequence[{index}].type")
        normalized_sequence.append(
            {
                "id": text(operation.get("id"), f"operationSequence[{index}].id"),
                "type": operation_type,
                "actor": text(operation.get("actor"), f"operationSequence[{index}].actor"),
                "resource": text(
                    operation.get("resource"), f"operationSequence[{index}].resource"
                ),
                "effectClass": text(
                    operation.get("effectClass"),
                    f"operationSequence[{index}].effectClass",
                ),
            }
        )
        if operation_type in {"http", "browser", "cache", "workflow"}:
            request_count += 1
        if operation.get("effectClass") != "read-only":
            effect_count += 1
    effect_budget = experiment.get("effectBudget")
    if not isinstance(effect_budget, dict):
        raise WebContractError("effectBudget must be an object")
    max_operations = int(effect_budget.get("maxOperations", -1))
    max_requests = int(effect_budget.get("maxRequests", -1))
    max_effects = int(effect_budget.get("maxEffects", -1))
    if (
        max_operations < len(normalized_sequence)
        or max_requests < request_count
        or max_effects < effect_count
    ):
        raise WebContractError("effectBudget does not charge every operation/request/effect")
    cases = experiment.get("cases")
    if not isinstance(cases, dict) or set(cases) != {
        "baseline",
        "enforcingNegative",
        "positive",
    }:
        raise WebContractError("cases require baseline, enforcingNegative, and positive")
    for name, case in cases.items():
        if not isinstance(case, dict):
            raise WebContractError(f"cases.{name} must be an object")
        text(case.get("purpose"), f"cases.{name}.purpose")
        string_list(case.get("steps"), f"cases.{name}.steps")
    oracle_raw = experiment.get("executableOracle")
    admitted_oracle = admit_contract(root, oracle_raw) if oracle_raw else None
    if admitted_oracle and admitted_oracle["prerequisiteVersion"] != prerequisite_version:
        raise WebContractError("oracle prerequisite version does not match campaign")
    cleanup = experiment.get("cleanup")
    replay = experiment.get("independentReplay")
    if not isinstance(cleanup, dict) or not isinstance(replay, dict):
        raise WebContractError("cleanup and independentReplay are required")
    hypothesis = {
        "id": text(raw.get("id"), "hypothesis.id"),
        "title": text(raw.get("title"), "hypothesis.title"),
        "profile": "web-app",
        "observedBehavior": {
            "summary": text(observed.get("summary"), "observedBehavior.summary"),
            "confidence": confidence,
            "evidence": string_list(observed.get("evidence"), "observedBehavior.evidence"),
        },
        "securityInvariant": {
            "statement": text(invariant.get("statement"), "securityInvariant.statement"),
            "basis": text(invariant.get("basis"), "securityInvariant.basis"),
        },
        "attackerStartingAuthority": text(
            raw.get("attackerStartingAuthority"), "attackerStartingAuthority"
        ),
        "setup": {
            "ownedActors": string_list(setup.get("ownedActors"), "setup.ownedActors"),
            "ownedResources": string_list(
                setup.get("ownedResources"), "setup.ownedResources"
            ),
            "exactState": string_list(setup.get("exactState"), "setup.exactState"),
        },
        "competingExplanations": validate_explanations(
            raw.get("competingExplanations")
        ),
        "sourceSupport": raw.get("sourceSupport"),
        "blackboxReplayRequired": True,
    }
    fingerprint = mechanism_fingerprint(hypothesis, scope)
    rank = ranking(raw.get("ranking"))
    frontier_experiment = {
        "id": "WX-" + canonical_digest([hypothesis["id"], scope, normalized_sequence])[:20],
        "kind": "web-hypothesis-experiment",
        "producer": hypothesis["id"],
        "consumer": fingerprint,
        "mechanismFingerprint": fingerprint,
        "missingCapability": {
            "type": "web-invariant-discriminator",
            "properties": [hypothesis["securityInvariant"]["statement"]],
            "limitations": [],
            "forbiddenLimitations": ["availability-only", "third-party-data"],
        },
        "experimentalScope": scope,
        "question": text(experiment.get("question"), "experiment.question"),
        "setupSequence": [row["id"] for row in normalized_sequence],
        "operationSequence": normalized_sequence,
        "effectBudget": {
            "maxOperations": max_operations,
            "maxRequests": max_requests,
            "maxEffects": max_effects,
        },
        "oracle": text(experiment.get("oracle"), "experiment.oracle"),
        "falsifier": text(experiment.get("falsifier"), "experiment.falsifier"),
        "uncertainty": string_list(
            experiment.get("uncertainty"), "experiment.uncertainty"
        ),
        "competingExplanations": hypothesis["competingExplanations"],
        "cases": cases,
        "observations": string_list(
            experiment.get("observations"), "experiment.observations"
        ),
        "cleanup": cleanup,
        "independentReplay": replay,
        "reopeningConditions": string_list(
            experiment.get("reopeningConditions"), "experiment.reopeningConditions"
        ),
        "ranking": rank,
        "sourceEvidence": raw.get("sourceSupport", {}).get("evidence", [])
        if isinstance(raw.get("sourceSupport"), dict)
        else [],
        "executableOracle": admitted_oracle,
        "planningOnly": admitted_oracle is None,
        "promotionStage": "mechanism-supported"
        if confidence == "observed"
        else "observation",
    }
    return hypothesis, frontier_experiment


def enforce_mechanism_budgets(
    connection: Any, experiments: list[dict[str, Any]], extensions: list[dict[str, Any]]
) -> None:
    approved = {
        str(value.get("mechanismFingerprint"))
        for value in extensions
        if isinstance(value, dict)
        and value.get("approved") is True
        and value.get("reviewedBy")
    }
    historical: dict[str, int] = {}
    running: dict[str, int] = {}
    proposed_frontier_ids = {experiment_frontier_identity(value) for value in experiments}
    for row in connection.execute(
        "SELECT frontier_id,state,payload_json FROM experiment_frontier"
    ).fetchall():
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            continue
        fingerprint = str(payload.get("mechanismFingerprint") or "")
        if not fingerprint:
            continue
        if row["frontier_id"] not in proposed_frontier_ids:
            historical[fingerprint] = historical.get(fingerprint, 0) + 1
        if row["state"] == "running":
            running[fingerprint] = running.get(fingerprint, 0) + 1
    proposed: dict[str, int] = {}
    for experiment in experiments:
        fingerprint = experiment["mechanismFingerprint"]
        proposed[fingerprint] = proposed.get(fingerprint, 0) + 1
    for fingerprint, count in proposed.items():
        if count > 3 and fingerprint not in approved:
            raise WebContractError(
                f"mechanism {fingerprint} exceeds three active experiments without a reviewed extension"
            )
        if historical.get(fingerprint, 0) >= 3 and fingerprint not in approved:
            raise WebContractError(
                f"mechanism {fingerprint} exhausted its inherited experiment budget"
            )
        if running.get(fingerprint, 0) > 1:
            raise WebContractError(
                f"mechanism {fingerprint} has more than one running experiment"
            )


def build_graph(
    root: Path, document: dict[str, Any], connection: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    prerequisite = derive_prerequisite_version(document)
    hypotheses = []
    experiments = []
    for raw in document.get("hypotheses", []):
        if not isinstance(raw, dict):
            raise WebContractError("hypotheses must contain objects")
        hypothesis, experiment = validate_hypothesis(root, raw, prerequisite["id"])
        hypotheses.append(hypothesis)
        experiments.append(experiment)
    if not hypotheses:
        raise WebContractError("at least one hypothesis is required")
    enforce_mechanism_budgets(
        connection, experiments, document.get("reviewedBudgetExtensions", [])
    )
    facts = [value for value in document.get("webFacts", []) if isinstance(value, dict)]
    relations = [
        value for value in document.get("webRelations", []) if isinstance(value, dict)
    ]
    semantic_ir = build_semantic_ir(
        {
            "framework": "web-app",
            "profile": "web-app",
            "runId": document.get("runId"),
            "facts": facts,
            "relations": relations,
        }
    )
    # Frontier candidates are shared with the semantic IR. Planning-only items
    # remain visible but cannot be scheduled until a replay adapter is admitted.
    semantic_ir["experimentCandidates"] = experiments
    semantic_ir["prerequisiteVersion"] = prerequisite["id"]
    negatives = normalized_prior_negatives(connection)
    negatives.extend(
        value
        for value in document.get("scopedNegativeKnowledge", [])
        if isinstance(value, dict)
    )
    graph = {
        "schemaVersion": 1,
        "producer": "krineon-web-hypothesis-loop",
        "profile": "web-app",
        "createdAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "prerequisiteVersion": prerequisite["id"],
        "prerequisiteVersionRecord": prerequisite,
        "hypotheses": hypotheses,
        "semanticIR": semantic_ir,
        "missingLinkExperiments": experiments,
        "scopedNegativeKnowledge": negatives,
        "focusEligible": any(not value["planningOnly"] for value in experiments),
        "findingClaimed": False,
        "profilePolicy": {
            "maxActiveLeads": 25,
            "maxActivePerMechanism": 3,
            "maxExperimentsPerMechanism": 3,
            "maxRunningPerMechanism": 1,
            "proseExpirationDays": 7,
            "stalenessTriggersLiveTraffic": False,
            "sourceSupportOptional": True,
            "blackboxReplayRequired": True,
        },
    }
    return graph, semantic_ir


def plan(campaign: Path, input_path: Path, output: Path | None) -> dict[str, Any]:
    document = load_object(input_path)
    connection = connect_orchestration(campaign, required=False)
    try:
        sync_approach_family_registry(connection)
        graph, semantic_ir = build_graph(campaign, document, connection)
        digest = canonical_digest(
            {
                "prerequisiteVersion": graph["prerequisiteVersion"],
                "hypotheses": graph["hypotheses"],
                "experiments": graph["missingLinkExperiments"],
            }
        )
        prior_digest = str(get_metadata(connection, "webHypothesisGraphDigest", ""))
        version = int(get_metadata(connection, "webHypothesisGraphVersion", 0))
        unchanged = digest == prior_digest and version > 0
        if not unchanged:
            version += 1
        graph["graphVersion"] = version
        graph["specificationSha256"] = digest
        graph_dir = campaign / "evidence" / "chain-graphs"
        path = graph_dir / f"web-hypothesis-v{version}.json"
        latest = graph_dir / "web-hypothesis-latest.json"
        atomic_json(path, graph)
        atomic_json(latest, graph)
        atomic_json(
            campaign / "evidence" / "semantic-ir" / "web-latest.json", semantic_ir
        )
        relative = path.relative_to(campaign).as_posix()
        set_metadata(connection, "webHypothesisGraphDigest", digest)
        set_metadata(connection, "webHypothesisGraphVersion", version)
        set_metadata(connection, "webHypothesisGraphLatest", relative)
        set_metadata(
            connection, "webPrerequisiteVersion", graph["prerequisiteVersion"]
        )
        scheduled = schedule_experiment_frontier(
            campaign,
            connection,
            graph,
            version=version,
            graph_path=relative,
        )
        connection.commit()
        result = {
            "graph": relative,
            "graphVersion": version,
            "prerequisiteVersion": graph["prerequisiteVersion"],
            "unchanged": unchanged,
            "scheduledTask": scheduled,
            "frontier": frontier_status(connection),
        }
        if output:
            atomic_json(output, result)
        return result
    finally:
        connection.close()


def frontier_status(connection: Any) -> list[dict[str, Any]]:
    return [
        {
            "frontierId": row["frontier_id"],
            "experimentId": row["experiment_id"],
            "state": row["state"],
            "score": row["score"],
            "taskId": row["task_id"],
        }
        for row in connection.execute(
            "SELECT * FROM experiment_frontier ORDER BY score DESC,created_at,frontier_id"
        ).fetchall()
    ]


def record(
    campaign: Path,
    frontier_id: str,
    observation_path: Path,
    signature_path: Path,
) -> dict[str, Any]:
    connection = connect_orchestration(campaign)
    try:
        row = connection.execute(
            "SELECT payload_json,graph_version FROM experiment_frontier WHERE frontier_id=?",
            (frontier_id,),
        ).fetchone()
        if row is None:
            raise WebContractError(f"unknown frontier item: {frontier_id}")
        experiment = json.loads(row["payload_json"])
        contract = experiment.get("executableOracle")
        if not isinstance(contract, dict) or contract.get("kind") != "web-typed":
            raise WebContractError("frontier item has no admitted typed web oracle")
        binding = contract["workflowBinding"]
        budget_path = observation_path.parent / "budget-ledger.json"
        broker_verified, verification_errors, _ = verified_web_observation(
            campaign,
            contract_path=campaign / binding["campaignContract"],
            workflow_path=campaign / binding["workflow"],
            workflow_signature=campaign / binding["signature"],
            observation_path=observation_path,
            observation_signature=signature_path,
            budget_ledger_path=budget_path,
        )
        if not broker_verified:
            raise WebContractError(
                "broker observation verification failed: "
                + ", ".join(verification_errors)
            )
        observation = load_object(observation_path)
        observation["evidenceReferences"] = [
            observation_path.relative_to(campaign).as_posix(),
            signature_path.relative_to(campaign).as_posix(),
            budget_path.relative_to(campaign).as_posix(),
        ]
        normalized = evaluate_contract(contract, observation)
        if isinstance(normalized.get("scopedNegativeKnowledge"), dict):
            normalized["scopedNegativeKnowledge"]["consumer"] = experiment.get(
                "consumer"
            )
        state = complete_profile_experiment_frontier(
            connection,
            frontier_id=frontier_id,
            normalized_outcome=normalized,
            broker_evidence_verified=broker_verified,
        )
        latest = str(get_metadata(connection, "webHypothesisGraphLatest", ""))
        if not latest or not (campaign / latest).is_file():
            raise WebContractError("latest web hypothesis graph is unavailable")
        graph = load_object(campaign / latest)
        if isinstance(normalized.get("scopedNegativeKnowledge"), dict):
            graph.setdefault("scopedNegativeKnowledge", []).append(
                normalized["scopedNegativeKnowledge"]
            )
        scheduled = schedule_experiment_frontier(
            campaign,
            connection,
            graph,
            version=int(graph["graphVersion"]),
            graph_path=latest,
        )
        connection.commit()
        return {
            "frontierId": frontier_id,
            "state": state,
            "outcome": normalized,
            "scheduledTask": scheduled,
            "frontier": frontier_status(connection),
        }
    finally:
        connection.close()


def execute(
    campaign: Path,
    frontier_id: str,
    output: Path,
    *,
    secret_store: Path | None = None,
) -> dict[str, Any]:
    """Execute an admitted experiment through a fixed registered adapter."""

    connection = connect_orchestration(campaign)
    try:
        row = connection.execute(
            "SELECT payload_json,state FROM experiment_frontier WHERE frontier_id=?",
            (frontier_id,),
        ).fetchone()
        if row is None or row["state"] != "running":
            raise WebContractError("only a running frontier experiment can execute")
        experiment = json.loads(row["payload_json"])
        contract = experiment.get("executableOracle")
        if not isinstance(contract, dict) or contract.get("kind") != "web-typed":
            raise WebContractError("frontier item lacks a typed web oracle")
        if contract.get("registeredRunner") != "krineon-http-broker-v1":
            raise WebContractError(
                "this command cannot dispatch the selected registered adapter"
            )
        binding = contract["workflowBinding"]
    finally:
        connection.close()
    arguments = [
        str(campaign),
        str(campaign / binding["campaignContract"]),
        str(campaign / binding["workflow"]),
        "--signature",
        str(campaign / binding["signature"]),
        "--output",
        str(output),
    ]
    if secret_store is not None:
        arguments.extend(["--secret-store", str(secret_store)])
    if run_http_broker(arguments) != 0:
        raise WebContractError("registered HTTP broker execution failed")
    return record(
        campaign,
        frontier_id,
        output / "observation.json",
        output / "observation.json.sig",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("campaign", type=Path)
    plan_parser.add_argument("input", type=Path)
    plan_parser.add_argument("--output", type=Path)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("campaign", type=Path)
    record_parser.add_argument("frontier_id")
    record_parser.add_argument("observation", type=Path)
    record_parser.add_argument("signature", type=Path)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("campaign", type=Path)
    execute_parser.add_argument("frontier_id")
    execute_parser.add_argument("output", type=Path)
    execute_parser.add_argument("--secret-store", type=Path)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("campaign", type=Path)
    version_parser = subparsers.add_parser("derive-version")
    version_parser.add_argument("campaign", type=Path)
    version_parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        campaign = args.campaign.expanduser().resolve()
        if args.command == "plan":
            result = plan(
                campaign,
                args.input.expanduser().resolve(),
                args.output.expanduser().resolve() if args.output else None,
            )
        elif args.command == "record":
            result = record(
                campaign,
                args.frontier_id,
                args.observation.expanduser().resolve(),
                args.signature.expanduser().resolve(),
            )
        elif args.command == "execute":
            result = execute(
                campaign,
                args.frontier_id,
                args.output.expanduser().resolve(),
                secret_store=args.secret_store.expanduser().resolve()
                if args.secret_store
                else None,
            )
        elif args.command == "status":
            connection = connect_orchestration(campaign)
            try:
                result = {"frontier": frontier_status(connection)}
            finally:
                connection.close()
        else:
            result = derive_prerequisite_version(
                load_object(args.input.expanduser().resolve())
            )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
