from __future__ import annotations

import json
import hashlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.static_analysis_pipeline import (
    parse_z3_spec,
    select_normalized_leads,
    source_language_inventory,
)


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PIPELINE = PROJECT / "scripts" / "static_analysis_pipeline.py"
Z3_SOLVER = PROJECT / "scripts" / "z3_boundary_solver.py"


class StaticAnalysisPipelineTests(unittest.TestCase):
    def run_command(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def test_language_inventory_drives_mandatory_analyzer_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "server.cc").write_text("int main() { return 0; }\n")
            (root / "src" / "server.h").write_text("int main();\n")
            (root / "tool.ts").write_text("export const value = 1;\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.ts").write_text("ignored\n")
            inventory = source_language_inventory(root)
            self.assertEqual(inventory["trailmarkLanguage"], "cpp")
            self.assertEqual(inventory["joernLanguage"], "c")
            self.assertTrue(inventory["cppcheckCompatible"])
            self.assertNotIn("ignored.ts", json.dumps(inventory))

    @unittest.skipUnless(shutil.which("z3"), "Z3 binary is unavailable")
    def test_z3_solver_emits_concrete_wrap_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            payloads = Path(tmp) / "payloads"
            self.run_command(
                sys.executable,
                str(Z3_SOLVER),
                "--kind",
                "truncate",
                "--bits",
                "32",
                "--target",
                "0",
                "--min-x",
                "1",
                "--max-x",
                "4294967296",
                "--output",
                str(output),
                "--emit-dir",
                str(payloads),
            )
            result = json.loads(output.read_text())
            self.assertEqual(result["model"]["x"]["integer"], 2**32)
            self.assertEqual(result["model"]["x"]["consumerUnsigned"], 0)
            self.assertEqual((payloads / "x.hex.txt").read_text().strip(), "100000000")
            self.assertEqual((payloads / "x.big-endian.bin").read_bytes(), b"\x01\x00\x00\x00\x00")

    @unittest.skipUnless(shutil.which("z3"), "Z3 binary is unavailable")
    def test_z3_source_binding_reads_target_but_does_not_overclaim_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "decoder.cc"
            source.write_text(
                "void step() {\n  rowLength = (rowLength << 4) | nibble;\n}\n",
                encoding="utf-8",
            )
            spec = root / "spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "kind": "custom-smt",
                        "consumerBits": 32,
                        "variables": [
                            {"name": "rowLength", "sort": "Int", "min": 1, "max": 2**32}
                        ],
                        "assertions": [
                            "(assert (= ((_ int2bv 32) rowLength) (_ bv0 32)))"
                        ],
                        "implementationBinding": {
                            "sourceFile": "decoder.cc",
                            "startLine": 2,
                            "endLine": 2,
                            "expression": "rowLength = (rowLength << 4) | nibble;",
                            "constraintExtraction": "manual-transcription",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "result.json"
            self.run_command(
                sys.executable,
                str(Z3_SOLVER),
                "--spec",
                str(spec),
                "--source-root",
                str(root),
                "--output",
                str(output),
            )
            result = json.loads(output.read_text())
            binding = result["implementationBinding"]
            self.assertTrue(binding["sourceBound"])
            self.assertTrue(binding["sourceFragmentMatched"])
            self.assertFalse(binding["implementationMatched"])
            self.assertEqual(binding["constraintExtraction"], "manual-transcription")
            self.assertEqual(binding["sourceSha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(result["model"]["rowLength"]["integer"], 2**32)

    @unittest.skipUnless(shutil.which("z3"), "Z3 binary is unavailable")
    def test_z3_refuses_unimplemented_tool_extraction_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "decoder.cc").write_text("int x = x + 1;\n", encoding="utf-8")
            spec = root / "spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "kind": "truncate",
                        "bits": 32,
                        "target": 0,
                        "maxX": 2**32,
                        "implementationBinding": {
                            "sourceFile": "decoder.cc",
                            "startLine": 1,
                            "endLine": 1,
                            "expression": "x = x + 1",
                            "constraintExtraction": "tool-extracted",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Z3_SOLVER),
                    "--spec",
                    str(spec),
                    "--source-root",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("does not implement source-to-SMT extraction", completed.stderr)

    def test_ingest_creates_idempotent_provenance_validation_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            self.run_command(
                sys.executable,
                str(HARNESS),
                "init",
                str(campaign),
                "--target",
                "fixture",
                "--repo",
                "https://example.invalid/fixture",
                "--commit",
                "a" * 40,
            )
            self.run_command(sys.executable, str(HARNESS), "plan", str(campaign))
            self.run_command(sys.executable, str(HARNESS), "queue", str(campaign))
            run_dir = campaign / "tools" / "static" / "fixture-run"
            run_dir.mkdir(parents=True)
            run_path = run_dir / "run.json"
            run_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "runId": "fixture-run",
                        "campaignCommit": "a" * 40,
                        "source": "/fixture",
                        "leads": [
                            {
                                "id": "SL-0123456789abcdef",
                                "tool": "differential-witness",
                                "kind": "consumer-disagreement",
                                "title": "Two consumers disagree",
                                "location": "src/server.c:42",
                                "approachFamily": "execution-sink-backtrace",
                                "evidence": ["tools/static/fixture-run/differential.json"],
                                "provenance": {
                                    "runId": "fixture-run",
                                    "runRecord": "tools/static/fixture-run/run.json",
                                    "campaignCommit": "a" * 40,
                                    "staticOnly": True,
                                    "runtimeValidated": False,
                                },
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            for _ in range(2):
                self.run_command(
                    sys.executable,
                    str(PIPELINE),
                    "ingest",
                    str(campaign),
                    "--run",
                    str(run_path),
                )
            registry = json.loads((campaign / "tools" / "static-leads.json").read_text())
            self.assertEqual(len(registry["leads"]), 1)
            self.assertEqual(registry["leads"][0]["taskId"], "static-0123456789abcdef")
            self.assertTrue(registry["leads"][0]["provenance"]["staticOnly"])
            self.assertFalse(registry["leads"][0]["provenance"]["runtimeValidated"])
            self.assertEqual(len(registry["leads"][0]["observations"]), 1)
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                rows = connection.execute(
                    "SELECT task_id,lane,state FROM tasks WHERE task_id=?",
                    ("static-0123456789abcdef",),
                ).fetchall()
            self.assertEqual(rows, [("static-0123456789abcdef", "evidence-lead-validation", "queued")])
            findings = json.loads((campaign / "registry.json").read_text())
            self.assertEqual(findings["findings"], [])

    def test_semantic_lead_outranks_earlier_inventory_with_bounded_queue(self) -> None:
        inventory = {
            "tool": "trailmark",
            "kind": "public-ingress",
            "title": "Inventory entry point",
            "location": "src/public.cc:1",
            "approachFamily": "ingress-authority",
            "priorityScore": 10,
        }
        semantic = {
            "tool": "differential-witness",
            "kind": "lifetime-escape-boundary",
            "title": "Lifetime transfer",
            "location": "src/core.cc:90",
            "approachFamily": "memory-lifetime",
            "priorityScore": 92,
        }
        selected, total = select_normalized_leads(
            [(inventory, ["inventory.json"]), (semantic, ["semantic.json"])],
            run_id="run",
            run_path="tools/static/run/run.json",
            commit="a" * 40,
            max_leads=1,
        )
        self.assertEqual(total, 2)
        self.assertEqual(selected[0]["kind"], "lifetime-escape-boundary")

    def test_pipeline_rejects_unbound_z3_as_target_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "generic.json"
            spec.write_text(
                json.dumps(
                    {
                        "kind": "truncate",
                        "bits": 32,
                        "target": 0,
                        "maxX": 2**32,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                parse_z3_spec(spec, allow_unbound=False)
            parsed = parse_z3_spec(spec, allow_unbound=True)
            self.assertNotIn("implementationBinding", parsed)

if __name__ == "__main__":
    unittest.main()
