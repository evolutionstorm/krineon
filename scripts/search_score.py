#!/usr/bin/env python3
"""Score search evidence and retain ablation decisions for Krineon subsystems."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

try:
    from .experiment_control import (
        verify_controlled_observation,
        verify_signed_record,
    )
    from .path_proof import validate_path_proof
except ImportError:  # Direct script execution.
    from experiment_control import verify_controlled_observation, verify_signed_record
    from path_proof import validate_path_proof


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def campaign(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    return root


def latest_coverage(root: Path, profile_name: str) -> dict[str, Any] | None:
    profile_path = root / "dynamic" / "fuzzers" / profile_name / "profile.json"
    if profile_path.is_file():
        rows = read_json(profile_path).get("coverageRebuilds")
        if isinstance(rows, list) and rows:
            record_path = root / str(rows[-1].get("record") or "")
            if record_path.is_file():
                return read_json(record_path)
    campaign_path = root / "campaign.json"
    if campaign_path.is_file():
        rows = read_json(campaign_path).get("jsCoverageRuns")
        matches = (
            [
                row
                for row in rows
                if isinstance(row, dict) and row.get("profile") == profile_name
            ]
            if isinstance(rows, list)
            else []
        )
        if matches:
            record_path = root / str(matches[-1].get("record") or "")
            if record_path.is_file():
                record = read_json(record_path)
                coverage = record.get("coverage")
                return {"metrics": coverage if isinstance(coverage, dict) else {}}
    return None


def unique_stack_count(root: Path) -> int:
    path = root / "dynamic" / "triage" / "index.json"
    if not path.is_file():
        return 0
    record = read_json(path)
    clusters = record.get("clusters")
    return len(clusters) if isinstance(clusters, list) else int(record.get("clusterCount") or 0)


def rediscovery_hours(root: Path, benchmark: str) -> float | None:
    path = root / "benchmarks" / benchmark / "status.json"
    if not path.is_file():
        return None
    value = read_json(path).get("hoursToFirstRediscovery")
    return float(value) if isinstance(value, (int, float)) else None


def validated_root_cause_metrics(root: Path) -> dict[str, Any]:
    identities: set[str] = set()
    process_seconds = 0.0
    findings_root = root / "findings"
    for path in findings_root.glob("*.json") if findings_root.is_dir() else []:
        try:
            finding = read_json(path)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            continue
        root_cause = " ".join(str(finding.get("rootCause") or "").split()).lower()
        controlled_passed = False
        for experiment in finding.get("controlledExperiments", []):
            if not isinstance(experiment, dict):
                continue
            observation_value = experiment.get("controlledObservation")
            signature_value = experiment.get("controlledObservationSignature")
            if not isinstance(observation_value, str) or not isinstance(
                signature_value, str
            ):
                continue
            observation_path = root / observation_value
            signature_path = root / signature_value
            if not observation_path.is_file() or not signature_path.is_file():
                continue
            try:
                verification = verify_controlled_observation(
                    root, observation_path, signature_path
                )
                if verification.get("passed") is not True:
                    continue
                controlled_passed = True
                observation = verification["record"]
                attestation_value = observation.get("attestation", {}).get("path")
                attestation = read_json(root / str(attestation_value))
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                continue
            for runs in attestation.get("cases", {}).values():
                for run in runs if isinstance(runs, list) else []:
                    if not isinstance(run, dict):
                        continue
                    started = run.get("startedNs")
                    finished = run.get("finishedNs")
                    if isinstance(started, int) and isinstance(finished, int) and finished >= started:
                        process_seconds += (finished - started) / 1_000_000_000
        proof_reference = finding.get("pathProof")
        proof_passed = False
        if isinstance(proof_reference, dict):
            proof_value = proof_reference.get("path")
            if isinstance(proof_value, str):
                proof_path = root / proof_value
                try:
                    proof = read_json(proof_path)
                    proof_passed = validate_path_proof(
                        proof,
                        expected_finding_id=str(finding.get("id") or ""),
                        expected_originator=str(finding.get("originator") or ""),
                        campaign_root=root,
                    )["passed"]
                except (OSError, ValueError, RuntimeError, json.JSONDecodeError, SystemExit):
                    proof_passed = False
        if root_cause and controlled_passed and proof_passed:
            identities.add(hashlib.sha256(root_cause.encode()).hexdigest())
    hours = process_seconds / 3600
    return {
        "validatedRootCauses": len(identities),
        "controlledProcessHours": hours,
        "validatedRootCausesPerCpuHour": (
            len(identities) / hours if identities and hours > 0 else None
        ),
    }


def semantic_information_metrics(root: Path) -> dict[str, Any]:
    information_gain = 0
    wall_seconds = 0.0
    observations = 0
    for path in root.rglob("*.json"):
        if any(part in {"worktrees", "third_party"} for part in path.parts):
            continue
        try:
            record = read_json(path)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            continue
        if record.get("producer") != "krineon-semantic-observation":
            continue
        signature_path = path.with_suffix(path.suffix + ".sig")
        signed, _, _ = verify_signed_record(
            root,
            path,
            signature_path,
            producer="krineon-semantic-observation",
        )
        if not signed:
            continue
        observations += 1
        cost = record.get("cost") if isinstance(record.get("cost"), dict) else {}
        if isinstance(cost.get("wallSeconds"), (int, float)):
            wall_seconds += float(cost["wallSeconds"])
        for result in record.get("results", []):
            evaluation = result.get("evaluation") if isinstance(result, dict) else None
            if isinstance(evaluation, dict) and isinstance(evaluation.get("informationGain"), int):
                information_gain += int(evaluation["informationGain"])
    return {
        "semanticObservations": observations,
        "securityInformationGain": information_gain,
        "informationGainPerHour": (
            information_gain / (wall_seconds / 3600)
            if information_gain and wall_seconds > 0
            else None
        ),
    }


def chain_progress_metrics(root: Path) -> dict[str, Any]:
    database = root / "orchestration.db"
    if not database.is_file():
        return {
            "invariantViolations": 0,
            "controlledCapabilities": 0,
            "newConsumersReached": 0,
            "acquisitionPrerequisitesResolved": 0,
            "compatiblePrimitiveEdges": 0,
            "confirmedChainPreconditions": 0,
            "falsifiedChainPreconditions": 0,
            "chainUncertaintiesResolved": 0,
            "chainProgressScore": 0,
        }
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT payload_json FROM research_leads WHERE state<>'disproved'"
        ).fetchall()
    except sqlite3.DatabaseError:
        rows = []
    finally:
        connection.close()
    milestone_counts: dict[str, int] = {}
    connected: set[tuple[str, str]] = set()
    resolved: set[str] = set()
    falsified: set[str] = set()
    uncertainties: set[str] = set()
    score = 0
    for (payload_json,) in rows:
        try:
            payload = json.loads(payload_json)
        except (TypeError, json.JSONDecodeError):
            continue
        progress = payload.get("chainProgress")
        if not isinstance(progress, dict):
            continue
        for milestone in progress.get("milestones", []):
            milestone_counts[str(milestone)] = milestone_counts.get(str(milestone), 0) + 1
        primitive_id = str((payload.get("capabilityModel") or {}).get("id") or "unknown")
        connected.update(
            (primitive_id, str(value)) for value in progress.get("connectedPrimitives", [])
        )
        resolved.update(map(str, progress.get("resolvedPreconditions", [])))
        falsified.update(map(str, progress.get("falsifiedPreconditions", [])))
        uncertainties.update(map(str, progress.get("uncertaintiesResolved", [])))
        score += int(payload.get("chainProgressScore", 0))
    return {
        "invariantViolations": milestone_counts.get("invariant-violation-reproduced", 0),
        "controlledCapabilities": milestone_counts.get("attacker-capability-controlled", 0),
        "newConsumersReached": milestone_counts.get("new-consumer-reached", 0),
        "acquisitionPrerequisitesResolved": milestone_counts.get("acquisition-prerequisite-resolved", 0),
        "compatiblePrimitiveEdges": len(connected),
        "confirmedChainPreconditions": len(resolved),
        "falsifiedChainPreconditions": len(falsified),
        "chainUncertaintiesResolved": len(uncertainties),
        "chainProgressScore": score,
    }


def score_vector(root: Path, profile: str, benchmark: str) -> dict[str, Any]:
    coverage = latest_coverage(root, profile)
    metrics = coverage.get("metrics") if isinstance(coverage, dict) else {}
    return {
        "newEdgesPerHour": (
            float(metrics["newEdgesPerHour"])
            if isinstance(metrics, dict)
            and isinstance(metrics.get("newEdgesPerHour"), (int, float))
            else None
        ),
        "uniqueStackClusters": unique_stack_count(root),
        "hoursToFirstRediscovery": rediscovery_hours(root, benchmark),
        **validated_root_cause_metrics(root),
        **semantic_information_metrics(root),
        **chain_progress_metrics(root),
    }


def cmd_snapshot(args: argparse.Namespace) -> int:
    root = campaign(args.campaign_dir)
    value = {
        "schemaVersion": 1,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": args.profile,
        "benchmark": args.benchmark,
        "score": score_vector(root, args.profile, args.benchmark),
        "direction": {
            "newEdgesPerHour": "higher-is-better",
            "uniqueStackClusters": "higher-is-better",
            "hoursToFirstRediscovery": "lower-is-better",
            "validatedRootCauses": "higher-is-better",
            "validatedRootCausesPerCpuHour": "higher-is-better-primary",
            "securityInformationGain": "higher-is-better",
            "informationGainPerHour": "higher-is-better",
            "chainProgressScore": "higher-is-better",
            "compatiblePrimitiveEdges": "higher-is-better",
            "chainUncertaintiesResolved": "higher-is-better",
        },
    }
    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else root
        / "metrics"
        / "scores"
        / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    )
    atomic_json(output, value)
    print(output)
    return 0


def improved(before: Any, after: Any, *, lower: bool = False) -> bool:
    if after is None:
        return False
    if before is None:
        return True
    return after < before if lower else after > before


def cmd_compare(args: argparse.Namespace) -> int:
    root = campaign(args.campaign_dir)
    before = read_json(Path(args.before).expanduser().resolve()).get("score", {})
    after = read_json(Path(args.after).expanduser().resolve()).get("score", {})
    deltas = {
        "newEdgesPerHour": improved(
            before.get("newEdgesPerHour"), after.get("newEdgesPerHour")
        ),
        "uniqueStackClusters": improved(
            before.get("uniqueStackClusters"), after.get("uniqueStackClusters")
        ),
        "hoursToFirstRediscovery": improved(
            before.get("hoursToFirstRediscovery"),
            after.get("hoursToFirstRediscovery"),
            lower=True,
        ),
        "validatedRootCauses": improved(
            before.get("validatedRootCauses"), after.get("validatedRootCauses")
        ),
        "validatedRootCausesPerCpuHour": improved(
            before.get("validatedRootCausesPerCpuHour"),
            after.get("validatedRootCausesPerCpuHour"),
        ),
        "securityInformationGain": improved(
            before.get("securityInformationGain"), after.get("securityInformationGain")
        ),
        "informationGainPerHour": improved(
            before.get("informationGainPerHour"), after.get("informationGainPerHour")
        ),
        "chainProgressScore": improved(
            before.get("chainProgressScore"), after.get("chainProgressScore")
        ),
        "compatiblePrimitiveEdges": improved(
            before.get("compatiblePrimitiveEdges"),
            after.get("compatiblePrimitiveEdges"),
        ),
        "chainUncertaintiesResolved": improved(
            before.get("chainUncertaintiesResolved"),
            after.get("chainUncertaintiesResolved"),
        ),
    }
    primary_moved = deltas["validatedRootCausesPerCpuHour"] or deltas["validatedRootCauses"]
    proxy_moved = any(
        value for key, value in deltas.items()
        if key not in {"validatedRootCausesPerCpuHour", "validatedRootCauses"}
    )
    moved = primary_moved or proxy_moved
    decision = {
        "schemaVersion": 1,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "subsystem": args.subsystem,
        "before": before,
        "after": after,
        "improvements": deltas,
        "verdict": (
            "keep" if primary_moved else "provisional-keep" if proxy_moved else "delete"
        ),
        "reason": (
            "improved validated root causes per measured cost"
            if primary_moved
            else "improved a search proxy but has not yet improved validated root causes per cost"
            if proxy_moved
            else "moved neither validated root causes per cost nor a retained search proxy"
        ),
    }
    output = root / "metrics" / "ablations" / f"{args.subsystem}.json"
    atomic_json(output, decision)
    print(json.dumps(decision, indent=2))
    return 0 if moved or not args.enforce else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("campaign_dir")
    snapshot.add_argument("--profile", required=True)
    snapshot.add_argument("--benchmark", required=True)
    snapshot.add_argument("--output")
    snapshot.set_defaults(func=cmd_snapshot)
    compare = commands.add_parser("compare")
    compare.add_argument("campaign_dir")
    compare.add_argument("--subsystem", required=True)
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--enforce", action="store_true")
    compare.set_defaults(func=cmd_compare)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
