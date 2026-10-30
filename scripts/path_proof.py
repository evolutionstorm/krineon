#!/usr/bin/env python3
"""Create and audit a contradiction-free source-to-sink path proof.

The proof is deliberately separate from a finding's prose. Candidate promotion
must be backed by an ordered code path, an exhaustive inventory of branch
conditions, concrete attacker control for every required outcome, falsification
evidence, and review by someone other than the originator.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from .reality_evidence import (
        evidence_reference,
        safe_campaign_path,
        sha256_file,
        validate_attestation,
    )
except ImportError:  # Direct script execution.
    from reality_evidence import (
        evidence_reference,
        safe_campaign_path,
        sha256_file,
        validate_attestation,
    )


FINDING_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,63}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CONDITION_ID_RE = re.compile(r"C[1-9][0-9]*")
PLACEHOLDER_RE = re.compile(
    r"^\s*(?:todo|tbd|fixme|replace[- _]me|example(?: value| text)?)\s*$", re.I
)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not PLACEHOLDER_RE.search(value)


def _text_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_text(item) for item in value)


def _relative_evidence(value: Any) -> bool:
    if not _text_list(value):
        return False
    for item in value:
        candidate = str(item).split(":", 1)[0]
        if candidate.startswith(("/", "~")) or re.match(r"[A-Za-z]:[\\/]", candidate):
            return False
        if ".." in Path(candidate).parts:
            return False
    return True


def proof_template(finding_id: str, originator: str = "") -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "findingId": finding_id,
        "complete": False,
        "entryPoint": {
            "source": "",
            "symbol": "",
            "interface": "",
            "attackerInput": "",
            "evidence": [],
        },
        "sink": {
            "source": "",
            "symbol": "",
            "effect": "",
            "evidence": [],
        },
        "steps": [
            {
                "ordinal": 1,
                "source": "",
                "symbol": "",
                "operation": "",
                "attackerControlledValue": "",
                "transitionToNext": "",
                "conditionIds": [],
                "sourceEvidence": [],
                "runtimeEvidence": [],
                "machineEvidence": [],
            },
            {
                "ordinal": 2,
                "source": "",
                "symbol": "",
                "operation": "",
                "attackerControlledValue": "",
                "transitionToNext": "terminal sink",
                "conditionIds": [],
                "sourceEvidence": [],
                "runtimeEvidence": [],
                "machineEvidence": [],
            },
        ],
        "conditions": [
            {
                "id": "C1",
                "source": "",
                "symbol": "",
                "expression": "",
                "requiredOutcome": "",
                "attackerMechanism": "",
                "concreteInputOrState": "",
                "sourceEvidence": [],
                "runtimeEvidence": [],
                "machineEvidence": [],
                "observed": False,
            }
        ],
        "conditionCoverage": {
            "method": "",
            "functionsReviewed": [
                {
                    "source": "",
                    "symbol": "",
                    "range": "",
                    "sourceSha256": "",
                    "sourceArtifact": "",
                    "lineStart": 0,
                    "lineEnd": 0,
                    "conditionIds": [],
                }
            ],
            "allPathConditionsEnumerated": False,
            "noConditionsReason": "",
        },
        "assumptions": [],
        "contradictionChecks": [
            {
                "challenge": "",
                "challenger": "",
                "result": "",
                "resolution": "",
                "evidence": [],
            }
        ],
        "falsification": {
            "negativeControls": [],
            "disprovingObservationsChecked": [],
        },
        "review": {
            "originator": originator,
            "reviewer": "",
            "reviewedAt": "",
            "notes": "",
            "originatorAttestation": {"path": "", "sha256": ""},
            "reviewerAttestation": {"path": "", "sha256": ""},
        },
    }


def validate_path_proof(
    proof: dict[str, Any],
    *,
    expected_finding_id: str | None = None,
    expected_originator: str | None = None,
    campaign_root: Path | None = None,
) -> dict[str, Any]:
    """Return a machine-readable audit without trusting a boolean gate."""

    errors: list[str] = []

    def require(condition: bool, field: str) -> None:
        if not condition:
            errors.append(field)

    evidence_artifacts: set[str] = set()
    machine_observations = 0

    def retain_evidence(value: Any, field: str) -> None:
        require(_relative_evidence(value), field)
        if not isinstance(value, list):
            return
        for item in value:
            if not isinstance(item, str):
                continue
            evidence_artifacts.add(item)
            artifact = Path(item)
            require(
                bool(artifact.parts) and artifact.parts[0] == "evidence",
                f"{field}:must-be-retained-under-evidence:{item}",
            )
            if campaign_root is not None:
                require(
                    (campaign_root / artifact).is_file(),
                    f"{field}:missing-artifact:{item}",
                )

    def retain_machine_evidence(value: Any, field: str) -> None:
        nonlocal machine_observations
        require(isinstance(value, list) and bool(value), field)
        if not isinstance(value, list) or campaign_root is None:
            return
        for index, reference in enumerate(value):
            passed, reference_errors, summary = evidence_reference(
                campaign_root,
                reference,
                expected_finding_id=str(proof.get("findingId") or ""),
            )
            require(passed, f"{field}[{index}]:machine-verified")
            for error in reference_errors:
                errors.append(f"{field}[{index}]:{error}")
            if passed:
                require(
                    summary.get("challengeBound") is True,
                    f"{field}[{index}]:challenge-bound-observation",
                )
                machine_observations += int(summary.get("observations") or 0)
                evidence_artifacts.add(str(summary.get("attestation") or ""))

    require(proof.get("schemaVersion") == 2, "schemaVersion:2")
    finding_id = proof.get("findingId")
    require(isinstance(finding_id, str) and bool(FINDING_ID_RE.fullmatch(finding_id)), "findingId")
    if expected_finding_id is not None:
        require(finding_id == expected_finding_id, "findingId:mismatch")
    require(proof.get("complete") is True, "complete:true")

    entry = proof.get("entryPoint")
    if not isinstance(entry, dict):
        errors.append("entryPoint")
        entry = {}
    for field in ("source", "symbol", "interface", "attackerInput"):
        require(_text(entry.get(field)), f"entryPoint.{field}")
    retain_evidence(entry.get("evidence"), "entryPoint.evidence")

    sink = proof.get("sink")
    if not isinstance(sink, dict):
        errors.append("sink")
        sink = {}
    for field in ("source", "symbol", "effect"):
        require(_text(sink.get(field)), f"sink.{field}")
    retain_evidence(sink.get("evidence"), "sink.evidence")

    steps = proof.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        errors.append("steps:min-2")
        steps = []
    referenced_conditions: set[str] = set()
    for index, step in enumerate(steps, start=1):
        prefix = f"steps[{index}]"
        if not isinstance(step, dict):
            errors.append(prefix)
            continue
        require(step.get("ordinal") == index, f"{prefix}.ordinal:{index}")
        for field in ("source", "symbol", "operation", "attackerControlledValue"):
            require(_text(step.get(field)), f"{prefix}.{field}")
        require(_text(step.get("transitionToNext")), f"{prefix}.transitionToNext")
        retain_evidence(step.get("sourceEvidence"), f"{prefix}.sourceEvidence")
        retain_evidence(step.get("runtimeEvidence"), f"{prefix}.runtimeEvidence")
        retain_machine_evidence(step.get("machineEvidence"), f"{prefix}.machineEvidence")
        condition_ids = step.get("conditionIds")
        require(isinstance(condition_ids, list), f"{prefix}.conditionIds")
        if isinstance(condition_ids, list):
            for condition_id in condition_ids:
                require(
                    isinstance(condition_id, str)
                    and bool(CONDITION_ID_RE.fullmatch(condition_id)),
                    f"{prefix}.conditionId:{condition_id}",
                )
                if isinstance(condition_id, str):
                    referenced_conditions.add(condition_id)
    if steps:
        first = steps[0] if isinstance(steps[0], dict) else {}
        last = steps[-1] if isinstance(steps[-1], dict) else {}
        require(
            entry.get("source") == first.get("source")
            and entry.get("symbol") == first.get("symbol"),
            "entryPoint:first-step-mismatch",
        )
        require(
            sink.get("source") == last.get("source")
            and sink.get("symbol") == last.get("symbol"),
            "sink:last-step-mismatch",
        )

    conditions = proof.get("conditions")
    if not isinstance(conditions, list):
        errors.append("conditions")
        conditions = []
    condition_ids: set[str] = set()
    for index, condition in enumerate(conditions, start=1):
        prefix = f"conditions[{index}]"
        if not isinstance(condition, dict):
            errors.append(prefix)
            continue
        condition_id = condition.get("id")
        require(
            isinstance(condition_id, str) and bool(CONDITION_ID_RE.fullmatch(condition_id)),
            f"{prefix}.id",
        )
        if isinstance(condition_id, str):
            require(condition_id not in condition_ids, f"{prefix}.id:duplicate")
            condition_ids.add(condition_id)
        for field in (
            "source",
            "symbol",
            "expression",
            "requiredOutcome",
            "attackerMechanism",
            "concreteInputOrState",
        ):
            require(_text(condition.get(field)), f"{prefix}.{field}")
        retain_evidence(condition.get("sourceEvidence"), f"{prefix}.sourceEvidence")
        retain_evidence(condition.get("runtimeEvidence"), f"{prefix}.runtimeEvidence")
        retain_machine_evidence(
            condition.get("machineEvidence"), f"{prefix}.machineEvidence"
        )
        require(condition.get("observed") is True, f"{prefix}.observed:true")
    require(referenced_conditions == condition_ids, "conditions:step-coverage-exact")

    coverage = proof.get("conditionCoverage")
    if not isinstance(coverage, dict):
        errors.append("conditionCoverage")
        coverage = {}
    require(_text(coverage.get("method")), "conditionCoverage.method")
    require(
        coverage.get("allPathConditionsEnumerated") is True,
        "conditionCoverage.allPathConditionsEnumerated:true",
    )
    functions = coverage.get("functionsReviewed")
    if not isinstance(functions, list) or not functions:
        errors.append("conditionCoverage.functionsReviewed")
        functions = []
    function_condition_ids: set[str] = set()
    for index, function in enumerate(functions, start=1):
        prefix = f"conditionCoverage.functionsReviewed[{index}]"
        if not isinstance(function, dict):
            errors.append(prefix)
            continue
        for field in ("source", "symbol", "range"):
            require(_text(function.get(field)), f"{prefix}.{field}")
        require(
            isinstance(function.get("sourceSha256"), str)
            and bool(SHA256_RE.fullmatch(function["sourceSha256"])),
            f"{prefix}.sourceSha256",
        )
        source_artifact = function.get("sourceArtifact")
        require(_text(source_artifact), f"{prefix}.sourceArtifact")
        line_start = function.get("lineStart")
        line_end = function.get("lineEnd")
        require(isinstance(line_start, int) and line_start >= 1, f"{prefix}.lineStart")
        require(
            isinstance(line_end, int)
            and isinstance(line_start, int)
            and line_end >= line_start,
            f"{prefix}.lineEnd",
        )
        if campaign_root is not None and _text(source_artifact):
            try:
                source_path = safe_campaign_path(campaign_root, source_artifact)
                source_lines = source_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                require(
                    sha256_file(source_path) == function.get("sourceSha256"),
                    f"{prefix}.sourceSha256:mismatch",
                )
                require(
                    isinstance(line_end, int) and line_end <= len(source_lines),
                    f"{prefix}.lineRange:outside-artifact",
                )
                evidence_artifacts.add(str(source_artifact))
            except (OSError, ValueError):
                errors.append(f"{prefix}.sourceArtifact:missing-or-unsafe")
        function_ids = function.get("conditionIds")
        require(isinstance(function_ids, list), f"{prefix}.conditionIds")
        if isinstance(function_ids, list):
            for condition_id in function_ids:
                if isinstance(condition_id, str):
                    function_condition_ids.add(condition_id)
    if conditions:
        require(not _text(coverage.get("noConditionsReason")), "conditionCoverage.noConditionsReason:empty")
    else:
        require(_text(coverage.get("noConditionsReason")), "conditionCoverage.noConditionsReason")
    require(function_condition_ids == condition_ids, "conditions:function-coverage-exact")

    assumptions = proof.get("assumptions")
    require(isinstance(assumptions, list), "assumptions:list")
    require(assumptions == [], "assumptions:must-be-empty")

    contradiction_checks = proof.get("contradictionChecks")
    if not isinstance(contradiction_checks, list) or not contradiction_checks:
        errors.append("contradictionChecks")
        contradiction_checks = []
    for index, check in enumerate(contradiction_checks, start=1):
        prefix = f"contradictionChecks[{index}]"
        if not isinstance(check, dict):
            errors.append(prefix)
            continue
        for field in ("challenge", "challenger", "resolution"):
            require(_text(check.get(field)), f"{prefix}.{field}")
        require(
            check.get("result") == "resolved-no-contradiction",
            f"{prefix}.result:resolved-no-contradiction",
        )
        retain_evidence(check.get("evidence"), f"{prefix}.evidence")

    falsification = proof.get("falsification")
    if not isinstance(falsification, dict):
        errors.append("falsification")
        falsification = {}
    retain_evidence(falsification.get("negativeControls"), "falsification.negativeControls")
    retain_evidence(
        falsification.get("disprovingObservationsChecked"),
        "falsification.disprovingObservationsChecked",
    )

    review = proof.get("review")
    if not isinstance(review, dict):
        errors.append("review")
        review = {}
    originator = review.get("originator")
    reviewer = review.get("reviewer")
    require(_text(originator), "review.originator")
    require(_text(reviewer), "review.reviewer")
    require(originator != reviewer, "review.reviewer:must-be-independent")
    if expected_originator is not None:
        require(originator == expected_originator, "review.originator:mismatch")
    require(
        _text(review.get("reviewedAt"))
        and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", review["reviewedAt"])),
        "review.reviewedAt:UTC",
    )
    require(_text(review.get("notes")), "review.notes")

    origin_attestation = review.get("originatorAttestation")
    reviewer_attestation = review.get("reviewerAttestation")
    origin_result: dict[str, Any] = {"passed": False, "errors": ["not-checked"]}
    reviewer_result: dict[str, Any] = {"passed": False, "errors": ["not-checked"]}
    if campaign_root is None:
        errors.append("review.attestations:campaign-root-required")
    else:
        for label, value, worker, role in (
            ("originatorAttestation", origin_attestation, originator, "originator"),
            ("reviewerAttestation", reviewer_attestation, reviewer, "reviewer"),
        ):
            if not isinstance(value, dict):
                errors.append(f"review.{label}")
                continue
            try:
                attestation_path = safe_campaign_path(campaign_root, value.get("path"))
                result = validate_attestation(
                    campaign_root,
                    attestation_path,
                    expected_finding_id=str(finding_id or ""),
                    expected_worker_id=str(worker or ""),
                    expected_role=role,
                )
                if value.get("sha256") != result.get("attestationSha256"):
                    result["errors"].append("review:attestation-hash")
                    result["passed"] = False
                for error in result["errors"]:
                    errors.append(f"review.{label}:{error}")
                evidence_artifacts.add(str(value.get("path") or ""))
                if label == "originatorAttestation":
                    origin_result = result
                else:
                    reviewer_result = result
            except (OSError, ValueError):
                errors.append(f"review.{label}:missing-or-unsafe")
        if origin_result.get("passed") and reviewer_result.get("passed"):
            origin_record = origin_result["record"]
            reviewer_record = reviewer_result["record"]
            require(
                origin_record.get("runId") != reviewer_record.get("runId"),
                "review.attestations:distinct-run-id",
            )
            require(
                origin_record.get("recipe", {}).get("sha256")
                == reviewer_record.get("recipe", {}).get("sha256"),
                "review.attestations:same-recipe",
            )
            require(
                origin_result.get("targetHashes") == reviewer_result.get("targetHashes"),
                "review.attestations:same-targets",
            )
            require(
                not set(origin_result.get("challengeHashes", []))
                & set(reviewer_result.get("challengeHashes", [])),
                "review.attestations:fresh-independent-challenges",
            )
            require(
                not set(origin_result.get("processIds", []))
                & set(reviewer_result.get("processIds", [])),
                "review.attestations:fresh-independent-processes",
            )

    errors = list(dict.fromkeys(errors))
    return {
        "passed": not errors,
        "errors": errors,
        "summary": {
            "steps": len(steps),
            "conditions": len(conditions),
            "functionsReviewed": len(functions),
            "assumptions": len(assumptions) if isinstance(assumptions, list) else None,
            "contradictionChecks": len(contradiction_checks),
            "independentReviewer": bool(_text(reviewer) and originator != reviewer),
            "evidenceArtifacts": len(evidence_artifacts),
            "machineObservations": machine_observations,
            "machineIndependentReview": bool(
                origin_result.get("passed") and reviewer_result.get("passed")
            ),
        },
    }


def campaign_root(value: str) -> Path:
    root = Path(value).resolve()
    if not (root / "campaign.json").is_file():
        raise SystemExit(f"not a Krineon campaign: {root}")
    return root


def finding_path(root: Path, finding_id: str) -> Path:
    path = root / "findings" / f"{finding_id}.json"
    if not path.is_file():
        raise SystemExit(f"unknown finding: {finding_id}")
    return path


def cmd_init(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    finding_file = finding_path(root, args.finding_id)
    finding = read_json(finding_file)
    relative = f"evidence/path-proofs/{args.finding_id}.json"
    proof_file = root / relative
    if proof_file.exists() and not args.force:
        raise SystemExit(f"path proof already exists: {proof_file}")
    proof = proof_template(args.finding_id, str(finding.get("originator") or ""))
    write_json(proof_file, proof)
    finding["pathProof"] = {"required": True, "path": relative}
    gates = finding.setdefault("gates", {})
    gates["path_proof_complete"] = False
    write_json(finding_file, finding)
    print(f"initialized path proof: {proof_file}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    finding_file = finding_path(root, args.finding_id)
    finding = read_json(finding_file)
    expected_relative = f"evidence/path-proofs/{args.finding_id}.json"
    path_proof = finding.get("pathProof")
    if not isinstance(path_proof, dict) or path_proof.get("path") != expected_relative:
        result = {
            "passed": False,
            "errors": ["finding.pathProof:path-missing-or-noncanonical"],
            "summary": {},
        }
    else:
        proof_file = root / expected_relative
        if not proof_file.is_file():
            result = {"passed": False, "errors": ["proof:missing"], "summary": {}}
        else:
            proof_record = read_json(proof_file)
            result = validate_path_proof(
                proof_record,
                expected_finding_id=args.finding_id,
                expected_originator=str(finding.get("originator") or ""),
                campaign_root=root,
            )
            review = proof_record.get("review")
            review = review if isinstance(review, dict) else {}
            originator_id = str(review.get("originator") or "")
            reviewer_id = str(review.get("reviewer") or "")
            identity_errors: list[str] = []
            database = root / "orchestration.db"
            if not database.is_file():
                identity_errors.append("review.identityRegistry")
            else:
                connection = sqlite3.connect(database)
                connection.row_factory = sqlite3.Row
                try:
                    originator_worker = connection.execute(
                        "SELECT agent FROM workers WHERE worker_id=?", (originator_id,)
                    ).fetchone()
                    reviewer_worker = connection.execute(
                        "SELECT agent FROM workers WHERE worker_id=?", (reviewer_id,)
                    ).fetchone()
                except sqlite3.Error:
                    originator_worker = None
                    reviewer_worker = None
                    identity_errors.append("review.identityRegistry")
                finally:
                    connection.close()
                if originator_worker is None:
                    identity_errors.append("review.originator:unregistered")
                if reviewer_worker is None:
                    identity_errors.append("review.reviewer:unregistered")
                if (
                    originator_worker is not None
                    and reviewer_worker is not None
                    and originator_worker["agent"] == reviewer_worker["agent"]
                ):
                    identity_errors.append("review.agent:must-be-independent")
            if identity_errors:
                result["passed"] = False
                result["errors"].extend(identity_errors)
            result["summary"]["registeredIndependentReviewer"] = not identity_errors
    if args.update_gate:
        finding.setdefault("gates", {})["path_proof_complete"] = result["passed"]
        write_json(finding_file, finding)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(("PASS" if result["passed"] else "FAIL") + f": {args.finding_id} path proof")
        for error in result["errors"]:
            print(f"  - {error}")
    return 0 if result["passed"] else 1


def validate_finding_id(value: str) -> str:
    if not FINDING_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "finding ID must start with a letter and use letters, digits, _ or -"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create and link an incomplete path-proof template")
    init.add_argument("campaign_dir")
    init.add_argument("finding_id", type=validate_finding_id)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)
    audit = sub.add_parser("audit", help="audit a linked path proof")
    audit.add_argument("campaign_dir")
    audit.add_argument("finding_id", type=validate_finding_id)
    audit.add_argument("--update-gate", action="store_true")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
