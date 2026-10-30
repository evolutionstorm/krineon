from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
REALITY_RUNNER = PROJECT / "scripts" / "reality_runner.py"
REALITY_TARGET = PROJECT / "tests" / "fixtures" / "reality_target.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_machine_path_evidence(
    campaign: Path,
    finding_id: str,
    originator: str,
    reviewer: str,
) -> dict[str, object]:
    campaign_record = json.loads((campaign / "campaign.json").read_text())
    campaign_record["authorization"]["confirmed"] = True
    campaign_record["authorization"]["basis"] = "owned executable test fixture"
    (campaign / "campaign.json").write_text(json.dumps(campaign_record, indent=2) + "\n")

    target = campaign / "evidence" / "bin" / "reality_target.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(REALITY_TARGET.read_bytes())
    source = campaign / "evidence" / "source-snapshots" / "path.cc"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "int parse_request(int encoded_length) {\n"
        "  if (encoded_length <= 4096) return encoded_length;\n"
        "  return 0;\n"
        "}\n"
        "int copy_decoded(int encoded_length) { return encoded_length; }\n",
        encoding="utf-8",
    )
    trace = campaign / "evidence" / "path-proof" / "trace.json"
    trace.parent.mkdir(parents=True, exist_ok=True)
    trace.write_text('{"sourceSnapshot":"evidence/source-snapshots/path.cc"}\n')
    recipe = campaign / "evidence" / "recipes" / f"{finding_id}.json"
    recipe.parent.mkdir(parents=True, exist_ok=True)
    recipe.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "findingId": finding_id,
                "targetArtifacts": ["evidence/bin/reality_target.py"],
                "subjectArtifact": "evidence/bin/reality_target.py",
                "subjectArgvIndex": 1,
                "cases": [
                    {
                        "name": "baseline",
                        "command": [sys.executable, "evidence/bin/reality_target.py"],
                        "assertions": [
                            {"id": "baseline-ok", "kind": "stdout-contains", "value": "baseline-ok"},
                            {"id": "baseline-exit", "kind": "exit-code", "equals": 0},
                        ],
                    },
                    {
                        "name": "negative",
                        "command": [sys.executable, "evidence/bin/reality_target.py"],
                        "assertions": [
                            {"id": "negative-blocked", "kind": "stdout-contains", "value": "negative-blocked"},
                            {"id": "negative-no-terminal", "kind": "stdout-not-contains", "value": "terminal:"},
                        ],
                    },
                    {
                        "name": "positive",
                        "command": [sys.executable, "evidence/bin/reality_target.py"],
                        "assertions": [
                            {"id": "positive-challenge", "kind": "stdout-contains-challenge"},
                            {"id": "positive-terminal", "kind": "stdout-contains", "value": "terminal:"},
                        ],
                    },
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    attestations: dict[str, dict[str, str]] = {}
    for role, worker in (("originator", originator), ("reviewer", reviewer)):
        completed = subprocess.run(
            [
                sys.executable,
                str(REALITY_RUNNER),
                str(campaign),
                finding_id,
                "--recipe",
                recipe.relative_to(campaign).as_posix(),
                "--worker-id",
                worker,
                "--role",
                role,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr or completed.stdout)
        output = json.loads(completed.stdout)
        attestations[role] = {
            "path": output["attestation"],
            "sha256": output["sha256"],
        }
    origin_reference = {
        "attestation": attestations["originator"]["path"],
        "sha256": attestations["originator"]["sha256"],
        "case": "positive",
        "assertionId": "positive-challenge",
    }
    terminal_reference = dict(origin_reference)
    return complete_path_proof(
        finding_id=finding_id,
        originator=originator,
        reviewer=reviewer,
        source_sha256=sha256(source),
        originator_attestation=attestations["originator"],
        reviewer_attestation=attestations["reviewer"],
        transition_reference=origin_reference,
        terminal_reference=terminal_reference,
    )


def complete_path_proof(
    *,
    finding_id: str = "FPATH",
    originator: str = "worker-originator",
    reviewer: str = "worker-reviewer",
    source_sha256: str = "",
    originator_attestation: dict[str, str] | None = None,
    reviewer_attestation: dict[str, str] | None = None,
    transition_reference: dict[str, object] | None = None,
    terminal_reference: dict[str, object] | None = None,
) -> dict[str, object]:
    evidence = "evidence/path-proof/trace.json"
    transition_reference = transition_reference or {}
    terminal_reference = terminal_reference or {}
    return {
        "schemaVersion": 2,
        "findingId": finding_id,
        "complete": True,
        "entryPoint": {
            "source": "src/request.cc:40-58",
            "symbol": "parse_request",
            "interface": "unauthenticated HTTP body",
            "attackerInput": "the declared and encoded body lengths",
            "evidence": [evidence],
        },
        "sink": {
            "source": "src/copy.cc:91-104",
            "symbol": "copy_decoded",
            "effect": "attacker-sized copy into a fixed-size destination",
            "evidence": [evidence],
        },
        "steps": [
            {
                "ordinal": 1,
                "source": "src/request.cc:40-58",
                "symbol": "parse_request",
                "operation": "parses the request-controlled encoded length",
                "attackerControlledValue": "encoded_length = 257",
                "transitionToNext": "passes encoded_length to decode_record",
                "conditionIds": ["C1"],
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
                "machineEvidence": [transition_reference],
            },
            {
                "ordinal": 2,
                "source": "src/copy.cc:91-104",
                "symbol": "copy_decoded",
                "operation": "copies decoded bytes using encoded_length",
                "attackerControlledValue": "encoded_length remains 257",
                "transitionToNext": "terminal sink",
                "conditionIds": [],
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
                "machineEvidence": [terminal_reference],
            },
        ],
        "conditions": [
            {
                "id": "C1",
                "source": "src/request.cc:48",
                "symbol": "parse_request",
                "expression": "encoded_length <= protocol_max",
                "requiredOutcome": "true",
                "attackerMechanism": "choose 257, below protocol_max 4096",
                "concreteInputOrState": "encoded_length=257; protocol_max=4096",
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
                "machineEvidence": [transition_reference],
                "observed": True,
            }
        ],
        "conditionCoverage": {
            "method": "line-by-line exact source walk from ingress to sink",
            "functionsReviewed": [
                {
                    "source": "src/request.cc",
                    "symbol": "parse_request and copy_decoded",
                    "range": "1-5",
                    "sourceSha256": source_sha256,
                    "sourceArtifact": "evidence/source-snapshots/path.cc",
                    "lineStart": 1,
                    "lineEnd": 5,
                    "conditionIds": ["C1"],
                }
            ],
            "allPathConditionsEnumerated": True,
            "noConditionsReason": "",
        },
        "assumptions": [],
        "contradictionChecks": [
            {
                "challenge": "the destination may be resized before the copy",
                "challenger": "worker-reviewer",
                "result": "resolved-no-contradiction",
                "resolution": "the retained trace and source show a fixed 256-byte destination",
                "evidence": [evidence],
            }
        ],
        "falsification": {
            "negativeControls": [evidence],
            "disprovingObservationsChecked": [evidence],
        },
        "review": {
            "originator": originator,
            "reviewer": reviewer,
            "reviewedAt": "2026-10-29T12:00:00Z",
            "notes": "Re-derived every transition and branch from the retained source and trace.",
            "originatorAttestation": originator_attestation or {},
            "reviewerAttestation": reviewer_attestation or {},
        },
    }
