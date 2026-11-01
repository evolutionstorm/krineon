#!/usr/bin/env python3
"""Validate retained sequence specifications and independent web replays."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def require_text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def validate_specification(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("sequence specification schemaVersion must be 1")
    if raw.get("kind") != "krineon-web-sequence-specification":
        raise WebContractError("input is not a Krineon sequence specification")
    for field in ("sequenceId", "mechanismId", "prerequisiteVersion", "observationEpoch"):
        require_text(raw.get(field), field)
    context = raw.get("verifiedContext")
    if not isinstance(context, dict):
        raise WebContractError("sequence specification requires verifiedContext")
    actors = context.get("actors")
    tenants = context.get("tenants")
    fixtures = context.get("fixtures")
    initial_authority = context.get("initialAuthority")
    if (
        not isinstance(actors, list)
        or not actors
        or not isinstance(tenants, list)
        or not tenants
        or not isinstance(fixtures, list)
        or not fixtures
        or not isinstance(initial_authority, dict)
    ):
        raise WebContractError("sequence specification requires actors and disposable fixtures")
    for actor in actors:
        if not isinstance(actor, dict) or actor.get("verified") is not True:
            raise WebContractError("sequence actors must be verified")
        for field in (
            "id",
            "tenant",
            "session",
            "sessionRefreshVersion",
            "permissionVersion",
        ):
            require_text(actor.get(field), f"actor.{field}")
    for fixture in fixtures:
        if (
            not isinstance(fixture, dict)
            or fixture.get("owned") is not True
            or fixture.get("disposable") is not True
        ):
            raise WebContractError("sequence fixtures must be owned and disposable")
        for field in ("id", "tenant", "owner", "generation", "fixtureNamespace"):
            require_text(fixture.get(field), f"fixture.{field}")
    actor_ids = {value["id"] for value in actors}
    actor_tenants = {value["tenant"] for value in actors}
    if set(map(str, tenants)) != actor_tenants:
        raise WebContractError("verified tenant inventory differs from the actor bindings")
    for field in ("permissionVersions", "sessionRefreshVersions"):
        versions = initial_authority.get(field)
        if not isinstance(versions, dict) or set(versions) != actor_ids:
            raise WebContractError(f"initialAuthority.{field} must bind every actor")
    for actor in actors:
        actor_id = actor["id"]
        if initial_authority["permissionVersions"][actor_id] != actor["permissionVersion"]:
            raise WebContractError("initial authority changes an actor permission version")
        if initial_authority["sessionRefreshVersions"][actor_id] != actor["sessionRefreshVersion"]:
            raise WebContractError("initial authority changes an actor session-refresh version")
    invariant = raw.get("invariant")
    if not isinstance(invariant, dict) or not isinstance(invariant.get("goalPredicate"), dict):
        raise WebContractError("sequence specification requires a goal predicate")
    require_text(invariant.get("basis"), "invariant.basis")
    baseline = invariant.get("legitimateBaseline")
    replay_evidence = invariant.get("legitimateReplayEvidence")
    if not isinstance(baseline, list) or not baseline or not isinstance(replay_evidence, dict):
        raise WebContractError("sequence invariant requires a legitimate baseline and replay evidence")
    goal_predicate = invariant["goalPredicate"]
    for field in ("prohibitedEffect", "stateOracleId", "observerOperationId", "resourceId"):
        require_text(goal_predicate.get(field), f"invariant.goalPredicate.{field}")
    histories = raw.get("histories")
    if not isinstance(histories, dict):
        raise WebContractError("sequence specification requires histories")
    if not isinstance(histories.get("legitimate"), list) or not histories["legitimate"]:
        raise WebContractError("sequence specification requires a legitimate history")
    if not isinstance(histories.get("disputed"), list) or not histories["disputed"]:
        raise WebContractError("sequence specification requires a disputed history")
    if histories["legitimate"] != baseline:
        raise WebContractError("legitimate history differs from the invariant baseline")
    controls = histories.get("controls")
    if not isinstance(controls, list) or not controls:
        raise WebContractError("sequence specification requires a binding control history")
    for control in controls:
        if control.get("purpose") not in {
            "remove-disputed-binding",
            "restore-disputed-binding",
        } or not control.get("operationIds") or not require_text(
            control.get("disputedBinding"), "control.disputedBinding"
        ):
            raise WebContractError("control history does not isolate the disputed binding")
        if control["operationIds"][: len(baseline)] != baseline:
            raise WebContractError("control history does not begin with the legitimate baseline")
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WebContractError("sequence specification requires step contracts")
    actor_bindings = {value["id"]: value for value in actors}
    fixture_bindings = {value["id"]: value for value in fixtures}
    step_ids = set()
    for value in steps:
        operation_id = require_text(value.get("operationId"), "step.operationId")
        step_ids.add(operation_id)
        actor = value.get("actor")
        if not isinstance(actor, dict) or actor.get("id") not in actor_bindings:
            raise WebContractError("step actor is not in verifiedContext")
        verified_actor = actor_bindings[actor["id"]]
        if any(
            actor.get(field) != verified_actor.get(field)
            for field in ("sessionRefreshVersion", "permissionVersion")
        ):
            raise WebContractError("step actor authority versions differ from verifiedContext")
        for resource in value.get("resources", []):
            fixture = fixture_bindings.get(resource.get("id"))
            if fixture is None or any(
                resource.get(field) != fixture.get(field)
                for field in ("tenant", "owner", "generation", "fixtureNamespace")
            ):
                raise WebContractError("step resource differs from the verified fixture binding")
        for field in (
            "action",
            "guards",
            "authorityBinding",
            "effectBudget",
            "ordering",
            "observations",
            "referenceExpectation",
        ):
            if not isinstance(value.get(field), (dict, list)):
                raise WebContractError(f"step {operation_id} lacks {field}")
        if not value["observations"]:
            raise WebContractError(f"step {operation_id} lacks authoritative observations")
    for history in [histories["legitimate"], histories["disputed"]]:
        if not set(history).issubset(step_ids):
            raise WebContractError("sequence history references an unknown step")
    for control in controls:
        if not set(control["operationIds"]).issubset(step_ids):
            raise WebContractError("control history references an unknown step")
    if goal_predicate["observerOperationId"] not in step_ids:
        raise WebContractError("goal predicate observer is not a retained step")
    partial_order = raw.get("partialOrder")
    if not isinstance(partial_order, list):
        raise WebContractError("sequence specification requires partial-order evidence")
    for relation in partial_order:
        if not isinstance(relation, dict) or not {
            relation.get("before"), relation.get("after")
        }.issubset(step_ids):
            raise WebContractError("partial-order relation references an unknown step")
    for edge in raw.get("valueExtractionEdges", []):
        if not isinstance(edge, dict):
            raise WebContractError("value extraction edges must be objects")
        for field in (
            "valueId",
            "issuer",
            "intendedConsumer",
            "expiryPolicy",
        ):
            require_text(edge.get(field), f"value edge {field}")
        if not isinstance(edge.get("singleUse"), bool):
            raise WebContractError("value edges require explicit single-use status")
    explanations = raw.get("competingExplanations")
    if not isinstance(explanations, list) or len(explanations) < 2:
        raise WebContractError("sequence specification requires competing explanations")
    witness = raw.get("minimalSuccessfulWitness")
    if not isinstance(witness, dict) or not isinstance(witness.get("operationIds"), list) or not witness["operationIds"]:
        raise WebContractError("sequence specification requires a causal witness")
    if not set(witness["operationIds"]).issubset(set(histories["disputed"])):
        raise WebContractError("causal witness is not contained in the disputed history")
    transition_requirements = raw.get("transitionObservationRequirements")
    if not isinstance(transition_requirements, list) or not transition_requirements:
        raise WebContractError("sequence specification requires transition observations")
    for requirement in transition_requirements:
        if requirement.get("operationId") not in step_ids:
            raise WebContractError("transition observation references an unknown step")
        if not requirement.get("beforeEvidenceRefs") or not requirement.get("afterObservationIds"):
            raise WebContractError("transition observation lacks before or after evidence")
    replay = raw.get("independentReplayRequirements")
    if not isinstance(replay, dict):
        raise WebContractError("sequence specification requires independent replay policy")
    for field in (
        "rebuildDisposableFixtures",
        "freshCredentialBindings",
        "replayEntireMinimalSequence",
        "rejectCopiedTerminalResponse",
        "rejectPrepopulatedState",
        "rejectStaleApproval",
        "rejectPrivateEvaluatorResource",
    ):
        if replay.get(field) is not True:
            raise WebContractError(f"independent replay policy does not enforce {field}")
    return dict(raw)


def validate_execution_result(
    result: dict[str, Any], specification: dict[str, Any], *, label: str
) -> None:
    if result.get("kind") != "krineon-web-sequence-execution":
        raise WebContractError(f"{label} is not a sequence execution result")
    if result.get("history") != "disputed":
        raise WebContractError(f"{label} did not execute the disputed history")
    expected = specification["histories"]["disputed"]
    if result.get("executedOperationIds") != expected:
        raise WebContractError(f"{label} did not execute its entire disputed history")
    timeline = result.get("transitionTimeline")
    if not isinstance(timeline, list) or len(timeline) != len(expected):
        raise WebContractError(f"{label} lacks a complete transition timeline")
    requirements = {
        value["operationId"]: value
        for value in specification["transitionObservationRequirements"]
    }
    for operation_id, transition in zip(expected, timeline, strict=True):
        if transition.get("operationId") != operation_id:
            raise WebContractError(f"{label} transition order differs from the history")
        require_text(transition.get("beforeStateSha256"), f"{label}.beforeStateSha256")
        require_text(transition.get("afterStateSha256"), f"{label}.afterStateSha256")
        if not isinstance(transition.get("observationIds"), list) or not transition["observationIds"]:
            raise WebContractError(f"{label} transition lacks authoritative observations")
        expectation = transition.get("referenceExpectation")
        if not isinstance(expectation, dict) or not require_text(
            expectation.get("policy"), f"{label}.referenceExpectation.policy"
        ):
            raise WebContractError(f"{label} transition lacks a reference expectation")
        require_text(
            transition.get("implementationObservation"),
            f"{label}.implementationObservation",
        )
        requirement = requirements.get(operation_id)
        if requirement and not set(requirement["afterObservationIds"]).issubset(
            set(transition["observationIds"])
        ):
            raise WebContractError(f"{label} transition omits required after-state evidence")


def evidence_hashes(base: Path, references: Any, field: str) -> set[str]:
    if not isinstance(references, list) or not references:
        raise WebContractError(f"{field} requires retained evidence files")
    hashes = set()
    for index, reference in enumerate(references):
        if not isinstance(reference, dict):
            raise WebContractError(f"{field}[{index}] must bind a file and sha256")
        relative = Path(require_text(reference.get("path"), f"{field}[{index}].path"))
        if relative.is_absolute() or ".." in relative.parts:
            raise WebContractError(f"{field} evidence path escapes its root")
        path = (base / relative).resolve()
        try:
            path.relative_to(base.resolve())
        except ValueError as error:
            raise WebContractError(f"{field} evidence path escapes its root") from error
        if not path.is_file():
            raise WebContractError(f"{field} evidence file is missing: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != reference.get("sha256"):
            raise WebContractError(f"{field} evidence hash mismatch: {relative}")
        hashes.add(actual)
    return hashes


def actor_map(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {value["id"]: value for value in spec["verifiedContext"]["actors"]}


def fixture_map(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {value["id"]: value for value in spec["verifiedContext"]["fixtures"]}


def verify_replay(
    original_spec_raw: dict[str, Any],
    original_result: dict[str, Any],
    replay_spec_raw: dict[str, Any],
    replay_result: dict[str, Any],
    attestation: dict[str, Any],
    *,
    evidence_root: Path,
) -> dict[str, Any]:
    original_spec = validate_specification(original_spec_raw)
    replay_spec = validate_specification(replay_spec_raw)
    if original_result.get("sequenceSpecificationSha256") != digest(original_spec):
        raise WebContractError("original result is not bound to its sequence specification")
    if replay_result.get("sequenceSpecificationSha256") != digest(replay_spec):
        raise WebContractError("replay result is not bound to its sequence specification")
    validate_execution_result(original_result, original_spec, label="original result")
    validate_execution_result(replay_result, replay_spec, label="replay result")
    if original_spec["mechanismId"] != replay_spec["mechanismId"]:
        raise WebContractError("independent replay changed the mechanism")
    if original_spec["prerequisiteVersion"] != replay_spec["prerequisiteVersion"]:
        raise WebContractError("independent replay changed the prerequisite version")
    original_witness = original_spec["minimalSuccessfulWitness"]["operationIds"]
    replay_witness = replay_spec["minimalSuccessfulWitness"]["operationIds"]
    if original_witness != replay_witness:
        raise WebContractError("independent replay did not execute the same minimal witness")
    if original_result.get("oracleResult", {}).get("outcome") != "confirmed-disagreement":
        raise WebContractError("original sequence is not a confirmed invariant disagreement")
    if replay_result.get("oracleResult", {}).get("outcome") != "confirmed-disagreement":
        raise WebContractError("independent replay did not reproduce the invariant disagreement")
    if original_result.get("cleanupComplete") is not True or replay_result.get("cleanupComplete") is not True:
        raise WebContractError("both sequence runs require complete cleanup")
    if original_result.get("runId") == replay_result.get("runId"):
        raise WebContractError("independent replay reused the original run identity")
    original_actors = actor_map(original_spec)
    replay_actors = actor_map(replay_spec)
    if set(original_actors) != set(replay_actors):
        raise WebContractError("independent replay changed the actor set")
    for actor_id in original_actors:
        if original_actors[actor_id]["sessionRefreshVersion"] == replay_actors[actor_id]["sessionRefreshVersion"]:
            raise WebContractError("independent replay reused a credential binding")
        if original_actors[actor_id]["permissionVersion"] != replay_actors[actor_id]["permissionVersion"]:
            raise WebContractError("independent replay changed the application permission version")
    original_fixtures = fixture_map(original_spec)
    replay_fixtures = fixture_map(replay_spec)
    if set(original_fixtures) != set(replay_fixtures):
        raise WebContractError("independent replay changed the fixture topology")
    for fixture_id in original_fixtures:
        original = original_fixtures[fixture_id]
        replay = replay_fixtures[fixture_id]
        if original["fixtureNamespace"] != replay["fixtureNamespace"]:
            raise WebContractError("independent replay changed the fixture namespace")
        if original["generation"] == replay["generation"]:
            raise WebContractError("independent replay reused a pre-populated fixture generation")
    if attestation.get("schemaVersion") != 1:
        raise WebContractError("independent replay attestation schemaVersion must be 1")
    reviewer = require_text(attestation.get("reviewerIdentity"), "reviewerIdentity")
    originator = require_text(attestation.get("originatorIdentity"), "originatorIdentity")
    if reviewer == originator:
        raise WebContractError("independent replay requires a fresh reviewer identity")
    for field in (
        "copiedTerminalResponse",
        "prepopulatedServerState",
        "staleApprovalUsed",
        "privateEvaluatorResourceUsed",
    ):
        if attestation.get(field) is not False:
            raise WebContractError(f"independent replay attestation must reject {field}")
    required_actions = original_spec["independentReplayRequirements"].get(
        "legitimateOtherActorActions", []
    )
    if attestation.get("legitimateOtherActorActions") != required_actions:
        raise WebContractError(
            "independent replay does not document the required legitimate owned-actor actions"
        )
    if attestation.get("victimInteraction") != original_spec[
        "independentReplayRequirements"
    ].get("victimInteraction"):
        raise WebContractError("independent replay changed or omitted victim interaction requirements")
    fixture_evidence = evidence_hashes(
        evidence_root,
        attestation.get("fixtureRebuildEvidence"),
        "fixtureRebuildEvidence",
    )
    credential_evidence = evidence_hashes(
        evidence_root,
        attestation.get("freshCredentialBindingEvidence"),
        "freshCredentialBindingEvidence",
    )
    original_hashes = set(map(str, original_result.get("runnerEvidenceHashes", [])))
    replay_hashes = set(map(str, replay_result.get("runnerEvidenceHashes", [])))
    if not original_hashes or not replay_hashes or original_hashes.intersection(replay_hashes):
        raise WebContractError("independent replay requires fresh machine evidence")
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-sequence-independent-replay",
        "accepted": True,
        "mechanismId": original_spec["mechanismId"],
        "prerequisiteVersion": original_spec["prerequisiteVersion"],
        "originatorIdentity": originator,
        "reviewerIdentity": reviewer,
        "originalRunId": original_result["runId"],
        "replayRunId": replay_result["runId"],
        "fixtureEvidenceHashes": sorted(fixture_evidence),
        "credentialEvidenceHashes": sorted(credential_evidence),
        "originalEvidenceHashes": sorted(original_hashes),
        "replayEvidenceHashes": sorted(replay_hashes),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_spec", type=Path)
    parser.add_argument("original_result", type=Path)
    parser.add_argument("replay_spec", type=Path)
    parser.add_argument("replay_result", type=Path)
    parser.add_argument("attestation", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_replay(
            load_object(args.original_spec),
            load_object(args.original_result),
            load_object(args.replay_spec),
            load_object(args.replay_result),
            load_object(args.attestation),
            evidence_root=args.evidence_root.expanduser().resolve(),
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"accepted": True, "replayRunId": result["replayRunId"]}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
