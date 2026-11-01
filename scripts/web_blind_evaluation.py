#!/usr/bin/env python3
"""Commit to evaluator-held web oracles, then score signed broker observations."""

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
    seen: set[tuple[str, str]] = set()
    for item in cases:
        if not isinstance(item, dict):
            raise WebContractError("held-out case must be an object")
        key = (str(item.get("workflowId") or ""), str(item.get("oracleId") or ""))
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
    args = parser.parse_args(argv)
    try:
        campaign = Path(args.campaign).expanduser().resolve()
        contract = Path(args.contract).expanduser().resolve()
        heldout = Path(args.heldout).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        if args.command == "enroll":
            result = enroll(campaign, contract, heldout, output)
        else:
            result = score(
                campaign,
                contract,
                heldout,
                Path(args.enrollment).expanduser().resolve(),
                Path(args.manifest).expanduser().resolve(),
                output,
            )
        print(json.dumps(result, indent=2))
        return 0 if result.get("passed", True) else 1
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
