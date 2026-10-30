from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.chain_reasoning import analyze_chain, normalize_negative_knowledge


def capability(name: str, *properties: str) -> dict[str, object]:
    return {
        "type": name,
        "properties": list(properties),
        "limitations": [],
        "forbiddenLimitations": [],
    }


def context(runtime: str = "production") -> dict[str, str]:
    return {
        "principal": "attacker",
        "process": "server",
        "namespace": "application",
        "runtime": runtime,
    }


def constraints() -> dict[str, list[str]]:
    return {
        "lifetime": [],
        "ordering": [],
        "deployment": ["production"],
        "acquisition": ["network"],
        "requiredState": [],
        "providedState": ["reachable"],
    }


def progress(*milestones: str) -> dict[str, object]:
    return {
        "milestones": list(milestones),
        "resolvedPreconditions": [],
        "falsifiedPreconditions": [],
        "connectedPrimitives": [],
        "uncertaintiesResolved": [],
    }


def primitive(
    identifier: str,
    produces: list[dict[str, object]],
    requires: list[dict[str, object]],
    *,
    inputs: bool = False,
    runtime: str = "production",
    milestones: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "id": identifier,
        "attackerControlledInputs": ["HTTP body"] if inputs else [],
        "produces": produces,
        "requires": requires,
        "context": context(runtime),
        "constraints": constraints(),
        "stateSequence": {
            "initialState": "fresh",
            "transitions": [],
            "reductionMustPreserve": [],
        },
        "sourceEvidence": [f"src/{identifier}.cc:1"],
        "runtimeEvidence": [],
        "progress": progress(*milestones),
        "negativeKnowledge": [],
    }


def boundary(requirement: dict[str, object]) -> dict[str, object]:
    return {
        "id": "critical-exec",
        "operation": "data-to-executable-behavior",
        "eventualImpact": "code execution",
        "intermediateCapability": "select a manifest-valid executable module",
        "requiredCapabilities": [requirement],
        "context": context(),
        "constraints": constraints(),
        "sourceEvidence": ["src/consumer.cc:10"],
    }


class ChainReasoningTests(unittest.TestCase):
    def test_compatible_primitives_reach_boundary(self) -> None:
        raw = capability("attacker-bytes", "controlled")
        executable = capability("module-selection", "manifest-valid")
        result = analyze_chain(
            {
                "schemaVersion": 1,
                "primitives": [
                    primitive("ingress", [raw], [], inputs=True),
                    primitive("decoder", [executable], [raw]),
                ],
                "boundaries": [boundary(executable)],
            }
        )
        self.assertIn("decoder", result["reachableFromAttacker"])
        self.assertEqual(result["completeBoundaryPaths"][0][-1], "boundary:critical-exec")
        self.assertFalse(result["findingClaimed"])

    def test_context_mismatch_does_not_form_chain(self) -> None:
        raw = capability("attacker-bytes", "controlled")
        executable = capability("module-selection", "manifest-valid")
        result = analyze_chain(
            {
                "schemaVersion": 1,
                "primitives": [
                    primitive("ingress", [raw], [], inputs=True),
                    primitive("decoder", [executable], [raw], runtime="development"),
                ],
                "boundaries": [boundary(executable)],
            }
        )
        self.assertNotIn("decoder", result["reachableFromAttacker"])
        self.assertEqual(result["completeBoundaryPaths"], [])

    def test_missing_link_generates_falsifiable_experiment_and_unlocks_focus(self) -> None:
        raw = capability("attacker-bytes", "controlled")
        executable = capability("module-selection", "manifest-valid")
        result = analyze_chain(
            {
                "schemaVersion": 1,
                "primitives": [
                    primitive(
                        "ingress",
                        [raw],
                        [],
                        inputs=True,
                        milestones=("attacker-capability-controlled", "chain-precondition-confirmed"),
                    )
                ],
                "boundaries": [boundary(executable)],
            }
        )
        self.assertTrue(result["focusEligible"])
        self.assertEqual(
            result["missingLinkExperiments"][0]["missingCapability"]["type"],
            "module-selection",
        )
        self.assertIn("falsifier", result["missingLinkExperiments"][0])

    def test_negative_knowledge_requires_reopening_criteria(self) -> None:
        with self.assertRaises(RuntimeError):
            normalize_negative_knowledge(
                [
                    {
                        "mechanism": "case-fold",
                        "inputs": ["/ADMIN"],
                        "conditions": ["production"],
                        "guard": "matcher blocked",
                        "consumer": "route resolver",
                        "observation": "403",
                        "evidence": ["evidence/run.json"],
                        "reopeningConditions": [],
                    }
                ],
                "negativeKnowledge",
            )

    def test_cli_ingest_creates_evidence_unlocked_focused_task(self) -> None:
        project = Path(__file__).resolve().parents[1]
        harness = project / "scripts" / "research_harness.py"
        reasoner = project / "scripts" / "chain_reasoning.py"
        with tempfile.TemporaryDirectory() as temporary:
            campaign = Path(temporary) / "campaign"
            for command in (
                [
                    sys.executable,
                    str(harness),
                    "init",
                    str(campaign),
                    "--target",
                    "chain-fixture",
                    "--repo",
                    "https://example.invalid/chain",
                    "--commit",
                    "a" * 40,
                ],
                [sys.executable, str(harness), "plan", str(campaign)],
                [sys.executable, str(harness), "queue", str(campaign)],
            ):
                completed = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            raw = capability("attacker-bytes", "controlled")
            executable = capability("module-selection", "manifest-valid")
            spec = Path(temporary) / "chain.json"
            spec.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "primitives": [
                            primitive(
                                "ingress",
                                [raw],
                                [],
                                inputs=True,
                                milestones=(
                                    "attacker-capability-controlled",
                                    "chain-precondition-confirmed",
                                ),
                            )
                        ],
                        "boundaries": [boundary(executable)],
                    }
                )
                + "\n"
            )
            output = campaign / "evidence" / "chain-graphs" / "fixture.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(reasoner),
                    str(campaign),
                    str(spec),
                    str(output),
                    "--ingest",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                row = connection.execute(
                    "SELECT task_kind FROM tasks WHERE task_id LIKE 'chain-focus-%'"
                ).fetchone()
            self.assertEqual(row, ("focused-chain-investigation",))


if __name__ == "__main__":
    unittest.main()
