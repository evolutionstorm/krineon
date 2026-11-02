#!/usr/bin/env python3
"""Evaluate prepared oracles and autonomous discovery on held-out web fixtures."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .experiment_control import (
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )
    from .research_harness import verified_web_observation
    from .web_contract import WebCampaignContract, WebContractError, atomic_json
except ImportError:
    from experiment_control import (
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )
    from research_harness import verified_web_observation
    from web_contract import WebCampaignContract, WebContractError, atomic_json


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected a JSON object in {path}")
    return value


def campaign_path(campaign: Path, value: Any) -> Path:
    relative = Path(str(value or ""))
    if relative.is_absolute() or ".." in relative.parts or not str(relative):
        raise WebContractError("evaluation manifest contains an unsafe path")
    resolved = (campaign / relative).resolve()
    resolved.relative_to(campaign.resolve())
    return resolved


def validate_heldout(value: dict[str, Any], contract_digest: str) -> None:
    if value.get("schemaVersion") != 1:
        raise WebContractError("held-out evaluation schemaVersion must be 1")
    if not str(value.get("evaluationId") or ""):
        raise WebContractError("held-out evaluation requires evaluationId")
    if value.get("contractSha256") != contract_digest:
        raise WebContractError("held-out evaluation targets a different contract")
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise WebContractError("held-out evaluation requires cases")
    evaluation_mode = str(value.get("evaluationMode") or "prepared-oracle")
    if evaluation_mode not in {"prepared-oracle", "autonomous-discovery"}:
        raise WebContractError("held-out evaluationMode is unsupported")
    seen: set[tuple[str, str]] = set()
    for item in cases:
        if not isinstance(item, dict):
            raise WebContractError("held-out case must be an object")
        key = (
            (str(item.get("workflowId") or ""), str(item.get("oracleId") or ""))
            if evaluation_mode == "prepared-oracle"
            else (str(item.get("mechanismFingerprint") or ""), "autonomous-discovery")
        )
        if not all(key) or key in seen:
            raise WebContractError("held-out workflow/oracle pairs must be unique")
        seen.add(key)
        if item.get("expectedOutcome") not in {
            "confirmed-invariant-disagreement",
            "observed-invariant-preservation",
        }:
            raise WebContractError("held-out case has an invalid expectedOutcome")
    for field in ("minimumPrecision", "minimumRecall"):
        try:
            score = float(value.get(field))
        except (TypeError, ValueError) as exc:
            raise WebContractError(f"{field} must be a number") from exc
        if not 0 <= score <= 1:
            raise WebContractError(f"{field} must be between zero and one")


def validate_discovery_input(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value.get("schemaVersion") != 1 or value.get("kind") != "krineon-web-blind-observations":
        raise WebContractError("autonomous discovery input has an invalid schema")
    prerequisite = str(value.get("prerequisiteVersion") or "")
    if not prerequisite or prerequisite in {"unknown", "unspecified"}:
        raise WebContractError("autonomous discovery requires a stable prerequisiteVersion")
    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) < 3:
        raise WebContractError("autonomous discovery requires at least three observations")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in observations:
        if not isinstance(raw, dict):
            raise WebContractError("autonomous discovery observation must be an object")
        required = (
            "id",
            "actorRef",
            "actorTenant",
            "resourceRef",
            "resourceOwnerRef",
            "resourceTenant",
            "action",
            "outcome",
            "securityRelevantSha256",
            "resourceVisibility",
            "evidenceRef",
        )
        if any(not str(raw.get(field) or "").strip() for field in required):
            raise WebContractError("autonomous discovery observation lacks typed ownership evidence")
        observation_id = str(raw["id"])
        if observation_id in seen:
            raise WebContractError("autonomous discovery observation ids must be unique")
        seen.add(observation_id)
        if raw["outcome"] not in {"allowed", "denied"}:
            raise WebContractError("autonomous discovery outcome must be allowed or denied")
        if raw["resourceVisibility"] not in {"private", "public"}:
            raise WebContractError("resourceVisibility must be private or public")
        if raw.get("authoritative") is not True or raw.get("ownedFixture") is not True:
            raise WebContractError("autonomous discovery accepts only authoritative owned-fixture observations")
        normalized.append(dict(raw))
    return normalized


def mechanism_fingerprint(family: str, action: str) -> str:
    material = f"{family}\0{action}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def discover(
    campaign: Path,
    contract_path: Path,
    observations_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Derive candidates without accepting a supplied hypothesis, workflow, or oracle."""

    contract = WebCampaignContract.load(contract_path)
    source = load_object(observations_path)
    observations = validate_discovery_input(source)
    own_allowed = [
        item
        for item in observations
        if item["outcome"] == "allowed"
        and item["actorRef"] == item["resourceOwnerRef"]
        and item["actorTenant"] == item["resourceTenant"]
    ]
    own_by_resource = {str(item["resourceRef"]): item for item in own_allowed}
    actor_controls = {
        (str(item["actorRef"]), str(item["action"]))
        for item in own_allowed
    }
    candidates: list[dict[str, Any]] = []
    for item in observations:
        if (
            item["outcome"] != "allowed"
            or item["resourceVisibility"] != "private"
            or item["actorRef"] == item["resourceOwnerRef"]
        ):
            continue
        owner_baseline = own_by_resource.get(str(item["resourceRef"]))
        if owner_baseline is None:
            continue
        if (str(item["actorRef"]), str(item["action"])) not in actor_controls:
            continue
        if item["securityRelevantSha256"] != owner_baseline["securityRelevantSha256"]:
            continue
        family = "object-authorization"
        candidates.append(
            {
                "family": family,
                "mechanismFingerprint": mechanism_fingerprint(family, str(item["action"])),
                "stage": "runtime-differential",
                "generatedHypothesis": (
                    "The resource consumer may authorize the operation without binding "
                    "the selected resource to its current owner and tenant."
                ),
                "generatedOracle": {
                    "expected": "an actor cannot consume another owner's private resource",
                    "observed": "the cross-owner response matched the authoritative owner baseline",
                },
                "minimalObservationIds": [
                    str(owner_baseline["id"]),
                    next(
                        str(control["id"])
                        for control in own_allowed
                        if control["actorRef"] == item["actorRef"]
                        and control["action"] == item["action"]
                    ),
                    str(item["id"]),
                ],
                "actorRef": item["actorRef"],
                "resourceOwnerRef": item["resourceOwnerRef"],
                "actorTenant": item["actorTenant"],
                "resourceTenant": item["resourceTenant"],
                "resourceRef": item["resourceRef"],
                "securityRelevantSha256": item["securityRelevantSha256"],
            }
        )
    authority = record_authority(campaign)
    record = {
        "schemaVersion": 1,
        "kind": "krineon-autonomous-web-discovery",
        "contractSha256": contract.digest,
        "observationsSha256": sha256(observations_path),
        "prerequisiteVersion": source["prerequisiteVersion"],
        "preparedHypothesisUsed": False,
        "preparedWorkflowUsed": False,
        "preparedOracleUsed": False,
        "candidateCount": len(candidates),
        "candidates": candidates,
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    atomic_json(output, record)
    sign_file(Path(authority["privateKey"]), output, output.with_suffix(output.suffix + ".sig"))
    return record


def score_discovery(
    campaign: Path,
    contract_path: Path,
    heldout: Path,
    enrollment_path: Path,
    discovery_path: Path,
    output: Path,
) -> dict[str, Any]:
    contract = WebCampaignContract.load(contract_path)
    heldout_value = load_object(heldout)
    validate_heldout(heldout_value, contract.digest)
    if heldout_value.get("evaluationMode") != "autonomous-discovery":
        raise WebContractError("held-out evaluation is not autonomous-discovery mode")
    enrollment = load_object(enrollment_path)
    public = control_public_key(campaign)
    if not verify_file(public, enrollment_path, enrollment_path.with_suffix(enrollment_path.suffix + ".sig")):
        raise WebContractError("evaluation enrollment signature is invalid")
    if enrollment.get("heldoutSha256") != sha256(heldout):
        raise WebContractError("held-out specification changed after enrollment")
    if not verify_file(public, discovery_path, discovery_path.with_suffix(discovery_path.suffix + ".sig")):
        raise WebContractError("autonomous discovery signature is invalid")
    discovery = load_object(discovery_path)
    if discovery.get("contractSha256") != contract.digest:
        raise WebContractError("autonomous discovery targets a different contract")
    if any(
        discovery.get(field) is not False
        for field in ("preparedHypothesisUsed", "preparedWorkflowUsed", "preparedOracleUsed")
    ):
        raise WebContractError("autonomous discovery used prepared research material")
    actual = {
        str(item.get("mechanismFingerprint"))
        for item in discovery.get("candidates", [])
        if isinstance(item, dict) and item.get("stage") == "runtime-differential"
    }
    results = []
    tp = fp = fn = tn = 0
    expected_fingerprints = {
        str(item["mechanismFingerprint"]) for item in heldout_value["cases"]
    }
    for case in heldout_value["cases"]:
        fingerprint = str(case["mechanismFingerprint"])
        expected_positive = case["expectedOutcome"] == "confirmed-invariant-disagreement"
        actual_positive = fingerprint in actual
        if expected_positive and actual_positive:
            tp += 1
        elif expected_positive:
            fn += 1
        elif actual_positive:
            fp += 1
        else:
            tn += 1
        results.append(
            {
                "mechanismFingerprint": fingerprint,
                "expectedOutcome": case["expectedOutcome"],
                "observedOutcome": (
                    "confirmed-invariant-disagreement"
                    if actual_positive
                    else "observed-invariant-preservation"
                ),
                "matched": expected_positive == actual_positive,
            }
        )
    fp += len(actual.difference(expected_fingerprints))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    passed = (
        all(item["matched"] for item in results)
        and precision >= float(heldout_value["minimumPrecision"])
        and recall >= float(heldout_value["minimumRecall"])
    )
    record = {
        "schemaVersion": 1,
        "evaluationId": heldout_value["evaluationId"],
        "mode": "autonomous-discovery",
        "counts": {"truePositive": tp, "falsePositive": fp, "falseNegative": fn, "trueNegative": tn},
        "precision": precision,
        "recall": recall,
        "results": results,
        "passed": passed,
    }
    atomic_json(output, record)
    private, _ = authority_paths(campaign)
    sign_file(private, output, output.with_suffix(output.suffix + ".sig"))
    return record


def record_authority(campaign: Path) -> dict[str, str]:
    authority = ensure_authority(campaign)
    campaign_record = load_object(campaign / "campaign.json")
    campaign_record["experimentAuthority"] = {
        key: value for key, value in authority.items() if key != "privateKey"
    }
    atomic_json(campaign / "campaign.json", campaign_record)
    return authority


def enroll(campaign: Path, contract_path: Path, heldout: Path, output: Path) -> dict[str, Any]:
    try:
        heldout.resolve().relative_to(campaign.resolve())
    except ValueError:
        pass
    else:
        raise WebContractError("held-out oracle material must remain outside the campaign")
    contract = WebCampaignContract.load(contract_path)
    heldout_value = load_object(heldout)
    validate_heldout(heldout_value, contract.digest)
    authority = record_authority(campaign)
    record = {
        "schemaVersion": 1,
        "evaluationId": heldout_value["evaluationId"],
        "contractSha256": contract.digest,
        "heldoutSha256": sha256(heldout),
        "caseCount": len(heldout_value["cases"]),
        "enrolledAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "note": "The held-out specification remains evaluator-controlled and outside the campaign.",
    }
    atomic_json(output, record)
    sign_file(Path(authority["privateKey"]), output, output.with_suffix(output.suffix + ".sig"))
    return record


def score(
    campaign: Path,
    contract_path: Path,
    heldout: Path,
    enrollment_path: Path,
    manifest_path: Path,
    output: Path,
) -> dict[str, Any]:
    contract = WebCampaignContract.load(contract_path)
    heldout_value = load_object(heldout)
    validate_heldout(heldout_value, contract.digest)
    enrollment = load_object(enrollment_path)
    public = control_public_key(campaign)
    if not verify_file(
        public,
        enrollment_path,
        enrollment_path.with_suffix(enrollment_path.suffix + ".sig"),
    ):
        raise WebContractError("evaluation enrollment signature is invalid")
    if enrollment.get("heldoutSha256") != sha256(heldout):
        raise WebContractError("held-out specification changed after enrollment")
    manifest = load_object(manifest_path)
    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("runs"), list):
        raise WebContractError("evaluation manifest must contain a runs array")

    observed: dict[tuple[str, str], str] = {}
    rejected_runs: list[dict[str, Any]] = []
    for index, run in enumerate(manifest["runs"]):
        if not isinstance(run, dict):
            rejected_runs.append({"index": index, "errors": ["run:not-object"]})
            continue
        try:
            paths = {
                key: campaign_path(campaign, run.get(key))
                for key in (
                    "contract",
                    "workflow",
                    "workflowSignature",
                    "observation",
                    "observationSignature",
                    "budgetLedger",
                )
            }
            passed, errors, details = verified_web_observation(
                campaign,
                contract_path=paths["contract"],
                workflow_path=paths["workflow"],
                workflow_signature=paths["workflowSignature"],
                observation_path=paths["observation"],
                observation_signature=paths["observationSignature"],
                budget_ledger_path=paths["budgetLedger"],
                require_disagreement=False,
            )
            if not passed:
                rejected_runs.append({"index": index, "errors": errors})
                continue
            if details.get("contractSha256") != contract.digest:
                rejected_runs.append(
                    {"index": index, "errors": ["run:contract-hash-mismatch"]}
                )
                continue
            workflow_id = str(details["observation"].get("workflowId") or "")
            for oracle in details["oracleResults"]:
                key = (workflow_id, str(oracle.get("oracleId") or ""))
                outcome = str(oracle.get("outcome") or "")
                previous = observed.get(key)
                if previous is not None and previous != outcome:
                    raise WebContractError(
                        "signed runs disagree for one held-out workflow/oracle pair"
                    )
                observed[key] = outcome
        except (OSError, ValueError, WebContractError) as exc:
            rejected_runs.append({"index": index, "errors": [str(exc)]})

    results: list[dict[str, Any]] = []
    true_positive = false_positive = false_negative = true_negative = 0
    for case in heldout_value["cases"]:
        key = (str(case["workflowId"]), str(case["oracleId"]))
        expected = str(case["expectedOutcome"])
        actual = observed.get(key, "missing")
        expected_positive = expected == "confirmed-invariant-disagreement"
        actual_positive = actual == "confirmed-invariant-disagreement"
        if expected_positive and actual_positive:
            true_positive += 1
        elif expected_positive:
            false_negative += 1
        elif actual_positive:
            false_positive += 1
        elif actual == "observed-invariant-preservation":
            true_negative += 1
        results.append(
            {
                "workflowId": key[0],
                "oracleId": key[1],
                "expectedOutcome": expected,
                "observedOutcome": actual,
                "matched": actual == expected,
            }
        )
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    passed = (
        not rejected_runs
        and all(item["matched"] for item in results)
        and precision >= float(heldout_value["minimumPrecision"])
        and recall >= float(heldout_value["minimumRecall"])
    )
    record = {
        "schemaVersion": 1,
        "evaluationId": heldout_value["evaluationId"],
        "contractSha256": contract.digest,
        "enrollmentSha256": sha256(enrollment_path),
        "scoredAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "counts": {
            "truePositive": true_positive,
            "falsePositive": false_positive,
            "falseNegative": false_negative,
            "trueNegative": true_negative,
        },
        "precision": precision,
        "recall": recall,
        "results": results,
        "rejectedRuns": rejected_runs,
        "passed": passed,
    }
    atomic_json(output, record)
    private, _ = authority_paths(campaign)
    sign_file(private, output, output.with_suffix(output.suffix + ".sig"))
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    enroll_parser = sub.add_parser("enroll")
    enroll_parser.add_argument("campaign")
    enroll_parser.add_argument("contract")
    enroll_parser.add_argument("heldout")
    enroll_parser.add_argument("--output", required=True)
    score_parser = sub.add_parser("score")
    score_parser.add_argument("campaign")
    score_parser.add_argument("contract")
    score_parser.add_argument("heldout")
    score_parser.add_argument("enrollment")
    score_parser.add_argument("manifest")
    score_parser.add_argument("--output", required=True)
    discover_parser = sub.add_parser("discover")
    discover_parser.add_argument("campaign")
    discover_parser.add_argument("contract")
    discover_parser.add_argument("observations")
    discover_parser.add_argument("--output", required=True)
    score_discovery_parser = sub.add_parser("score-discovery")
    score_discovery_parser.add_argument("campaign")
    score_discovery_parser.add_argument("contract")
    score_discovery_parser.add_argument("heldout")
    score_discovery_parser.add_argument("enrollment")
    score_discovery_parser.add_argument("discovery")
    score_discovery_parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        campaign = Path(args.campaign).expanduser().resolve()
        contract = Path(args.contract).expanduser().resolve()
        heldout = Path(args.heldout).expanduser().resolve() if hasattr(args, "heldout") else None
        output = Path(args.output).expanduser().resolve()
        if args.command == "enroll":
            assert heldout is not None
            result = enroll(campaign, contract, heldout, output)
        elif args.command == "score":
            assert heldout is not None
            result = score(
                campaign,
                contract,
                heldout,
                Path(args.enrollment).expanduser().resolve(),
                Path(args.manifest).expanduser().resolve(),
                output,
            )
        elif args.command == "discover":
            result = discover(
                campaign,
                contract,
                Path(args.observations).expanduser().resolve(),
                output,
            )
        else:
            assert heldout is not None
            result = score_discovery(
                campaign,
                contract,
                heldout,
                Path(args.enrollment).expanduser().resolve(),
                Path(args.discovery).expanduser().resolve(),
                output,
            )
        print(json.dumps(result, indent=2))
        return 0 if result.get("passed", True) else 1
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
