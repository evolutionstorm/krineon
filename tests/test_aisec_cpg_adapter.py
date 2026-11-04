from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.aisec_cpg_adapter import normalize_graph, source_manifest
from scripts.static_analysis_pipeline import source_language_inventory


PROJECT = Path(__file__).resolve().parents[1]
ADAPTER = PROJECT / "scripts" / "aisec_cpg_adapter.py"
PIPELINE = PROJECT / "scripts" / "static_analysis_pipeline.py"


def fixture_graph() -> dict[str, object]:
    return {
        "nodes": [
            {
                "@id": "1",
                "@label": ["CallExpression"],
                "properties": {
                    "location": "src/app.ts:4",
                    "resolved": False,
                    "isInferred": True,
                },
            },
            {
                "@id": "2",
                "@label": ["FunctionDeclaration"],
                "properties": {"location": "src/app.ts:1"},
            },
        ],
        "edges": [
            {"@out": "1", "@in": "2", "@label": "DFG"},
            {"@out": "2", "@in": "1", "@label": "EOG"},
            {"@out": "1", "@in": "2", "@label": "CALLS"},
        ],
    }


class AisecCpgAdapterTests(unittest.TestCase):
    def test_normalizer_labels_inference_and_experimental_frontend(self) -> None:
        result = normalize_graph(
            fixture_graph(), language="typescript", maturity="experimental"
        )
        self.assertEqual(result["graph"]["nodeCount"], 2)
        self.assertEqual(result["graph"]["edgeCount"], 3)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["dfg"], 1)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["eog"], 1)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["call"], 1)
        self.assertEqual(result["graph"]["inferredNodeCount"], 1)
        self.assertFalse(result["frontend"]["authoritativeForPromotion"])
        self.assertFalse(result["promotion"]["createsQueueLead"])

    def test_source_manifest_uses_source_relative_ignore_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "campaign" / "worktrees" / "source"
            root.mkdir(parents=True)
            (root / "app.go").write_text("package main\n", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.go").write_text("ignored\n")
            manifest = source_manifest(root)
            inventory = source_language_inventory(root)
            self.assertEqual(manifest["fileCount"], 1)
            self.assertEqual(inventory["aisecCpgLanguage"], "go")
            self.assertEqual(inventory["aisecCpgMaturity"], "maintained")

    def test_normalizer_recovers_nested_ogm_relationship_fields(self) -> None:
        result = normalize_graph(
            {
                "translationUnits": [
                    {
                        "id": "tu-1",
                        "type": "TranslationUnitDeclaration",
                        "nextEOG": [{"id": "call-1", "type": "CallExpression"}],
                        "nextDFG": [{"id": "value-1", "type": "Literal"}],
                        "invokes": [{"id": "fn-1", "type": "FunctionDeclaration"}],
                    }
                ]
            },
            language="java",
            maturity="maintained",
        )
        self.assertEqual(result["graph"]["nodeCount"], 4)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["eog"], 1)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["dfg"], 1)
        self.assertEqual(result["graph"]["semanticEdgeFamilies"]["call"], 1)
        self.assertTrue(result["frontend"]["eligibleAsSourceSupport"])
        self.assertFalse(result["frontend"]["authoritativeForPromotion"])

    def test_static_pipeline_executes_available_cpg_and_retains_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            source = campaign / "worktrees" / "source"
            source.mkdir(parents=True)
            (source / "app.ts").write_text(
                "export function run(value: string) { return value; }\n",
                encoding="utf-8",
            )
            (campaign / "campaign.json").write_text(
                json.dumps({"schemaVersion": 1, "commit": "a" * 40}) + "\n",
                encoding="utf-8",
            )
            tools = root / "bin"
            tools.mkdir()
            exporter = tools / "cpg-neo4j"
            exporter.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "if '--help' in sys.argv:\n"
                "    print('Fraunhofer AISEC cpg-neo4j fixture')\n"
                "    raise SystemExit(0)\n"
                "out = pathlib.Path(sys.argv[sys.argv.index('--export-json') + 1])\n"
                f"out.write_text(json.dumps({fixture_graph()!r}) + '\\n')\n",
                encoding="utf-8",
            )
            exporter.chmod(0o700)
            environment = dict(os.environ)
            environment["PATH"] = str(tools) + os.pathsep + "/usr/bin:/bin"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PIPELINE),
                    "run",
                    str(campaign),
                    "--source",
                    str(source),
                    "--timeout",
                    "10",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            run_path = Path(completed.stdout.strip().splitlines()[-1])
            run = json.loads(run_path.read_text(encoding="utf-8"))
            records = [item for item in run["tools"] if item["name"] == "aisec-cpg"]
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record["status"], "completed")
            self.assertEqual(record["frontend"]["maturity"], "experimental")
            self.assertFalse(record["frontend"]["authoritativeForPromotion"])
            self.assertEqual(len(record["evidence"]), 3)
            for relative in record["evidence"]:
                self.assertTrue((campaign / relative).is_file())
            self.assertEqual(len(run["semanticGraphArtifacts"]), 1)
            self.assertEqual(
                run["semanticGraphArtifacts"][0]["provider"],
                "fraunhofer-aisec-cpg",
            )
            self.assertEqual(run["leads"], [])


if __name__ == "__main__":
    unittest.main()
