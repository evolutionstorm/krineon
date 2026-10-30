from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
GENERATOR = PROJECT / "scripts" / "structured_input_generator.py"
JS_COVERAGE = PROJECT / "scripts" / "js_coverage_harness.py"
SEARCH_SCORE = PROJECT / "scripts" / "search_score.py"


MODELS = {
    "json": {"message": "héllo", "nested": {"a": 1, "b": [True, None]}},
    "manifest": {"serverActions": {"a": {"workers": {"app/page": "1"}}}},
    "url": {"scheme": "https", "host": "Example.COM", "pathSegments": ["api", "a b"], "query": [["x", "1"], ["x", "2"]]},
    "headers": [["X-Test", "one"], ["X-Test", "two"], ["Content-Type", "application/json"]],
    "multipart": {"parts": [{"headers": [["Content-Disposition", "form-data; name=x"]], "bodyText": "alpha"}]},
    "rsc": {"rows": [{"id": 16, "tag": "J", "payload": {"value": "alpha"}}]},
    "server-action": {"fields": [["$ACTION_ID_test", ""], ["argument", "alpha"]]},
}


class StructuredGeneratorTests(unittest.TestCase):
    def test_all_framework_generators_emit_distinct_semantic_equivalent_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind, model in MODELS.items():
                spec = root / f"{kind}.json"
                spec.write_text(json.dumps({"schemaVersion": 1, "kind": kind, "model": model}) + "\n")
                output = root / f"out-{kind}"
                run = subprocess.run(
                    [sys.executable, str(GENERATOR), str(spec), str(output), "--count", "6", "--seed", "7"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(run.returncode, 0, f"{kind}: {run.stderr}")
                manifest = json.loads((output / "generation.json").read_text())
                self.assertEqual(manifest["kind"], kind)
                self.assertEqual(len(manifest["outputs"]), 6)
                self.assertTrue(manifest["allSemanticRoundTripsVerified"])
                self.assertEqual(len({row["sha256"] for row in manifest["outputs"]}), 6)
                self.assertEqual(len({row["semanticGroupSha256"] for row in manifest["outputs"]}), 1)
                for row in manifest["outputs"]:
                    self.assertTrue(row["semanticRoundTripVerified"])
                    body = (output / row["path"]).read_bytes()
                    self.assertEqual(hashlib.sha256(body).hexdigest(), row["sha256"])


@unittest.skipUnless(shutil.which("node"), "Node is unavailable")
class JavaScriptCoverageTests(unittest.TestCase):
    def test_persistent_workers_merge_v8_istanbul_and_browser_coverage_with_source_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps(
                    {
                        "commit": "c" * 40,
                        "mode": "local-lab",
                        "authorization": {"confirmed": True, "allowedEnvironment": "owned temporary fixture"},
                    }
                )
                + "\n"
            )
            project = root / "project"
            server_dir = project / ".next" / "server"
            client_dir = project / ".next" / "static" / "chunks"
            corpus = project / "corpus"
            server_dir.mkdir(parents=True)
            client_dir.mkdir(parents=True)
            corpus.mkdir()
            for index, value in enumerate((b"A", b"B", b"AA", b"BB")):
                (corpus / f"{index}.bin").write_bytes(value)

            original = project / "target.ts"
            original.write_text(
                "export function fuzz(data: Uint8Array): string {\n"
                "  if (data[0] === 65) return 'A';\n"
                "  return 'other';\n"
                "}\n"
            )
            bundle = server_dir / "bundle.mjs"
            bundle.write_text(
                "import {fileURLToPath} from 'node:url';\n"
                "const p=fileURLToPath(import.meta.url);\n"
                "globalThis.__coverage__={[p]:{path:p,statementMap:{0:{start:{line:4,column:0},end:{line:4,column:50}}},s:{0:0},fnMap:{},f:{},branchMap:{},b:{}}};\n"
                "export function fuzz(data){globalThis.__coverage__[p].s[0]++;if(data[0]===65)return 'A';return 'other';}\n"
                "//# sourceMappingURL=bundle.mjs.map\n"
            )
            (server_dir / "bundle.mjs.map").write_text(
                json.dumps({"version": 3, "file": "bundle.mjs", "sources": ["../../target.ts"], "names": [], "mappings": "AAAA;AACA;AACA;AACA;AACA", "sourcesContent": [original.read_text()]})
            )

            client_source = project / "client.ts"
            client_source.write_text("export const client = () => 1;\n")
            client = client_dir / "client.js"
            client.write_text("function client(){return 1}\n//# sourceMappingURL=client.js.map\n")
            (client_dir / "client.js.map").write_text(
                json.dumps({"version": 3, "file": "client.js", "sources": ["../../../client.ts"], "names": [], "mappings": "AAAA", "sourcesContent": [client_source.read_text()]})
            )
            browser_coverage = project / "browser-v8.json"
            browser_coverage.write_text(
                json.dumps(
                    {
                        "result": [
                            {
                                "scriptId": "1",
                                "url": client.as_uri(),
                                "functions": [
                                    {
                                        "functionName": "client",
                                        "ranges": [{"startOffset": 0, "endOffset": len(client.read_text()), "count": 1}],
                                        "isBlockCoverage": True,
                                    }
                                ],
                            }
                        ]
                    }
                )
                + "\n"
            )
            spec = root / "coverage-spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "profile": "web-stack",
                        "projectRoot": str(project),
                        "runtime": shutil.which("node"),
                        "module": ".next/server/bundle.mjs",
                        "export": "fuzz",
                        "inputMode": "buffer",
                        "inputs": ["corpus/*.bin"],
                        "workers": 2,
                        "additionalV8CoverageFiles": ["browser-v8.json"],
                    }
                )
                + "\n"
            )
            universe = root / "universe.json"
            universe.write_text(json.dumps({"edges": [{"id": "uncovered-fixture-edge", "label": "unreached branch", "source": "target.ts"}]}) + "\n")
            output = campaign / "js-coverage"
            run = subprocess.run(
                [sys.executable, str(JS_COVERAGE), str(campaign), str(spec), str(output), "--edge-universe", str(universe)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            retained = (output / "js-coverage-run.json").read_text() if (output / "js-coverage-run.json").is_file() else ""
            self.assertEqual(run.returncode, 0, f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}\nrun:\n{retained}")
            record = json.loads(retained)
            self.assertEqual(record["status"], "passed")
            self.assertEqual(record["inputCount"], 4)
            self.assertEqual(record["workerCount"], 2)
            self.assertEqual(sum(worker["processed"] for worker in record["workers"]), 4)
            self.assertTrue(all(worker["processed"] == 2 for worker in record["workers"]))
            self.assertTrue(all(worker["nativeEdges"] for worker in record["workers"]))
            self.assertTrue(all(worker["nativeTimeline"] for worker in record["workers"]))
            self.assertTrue(all("newNativeEdges" in row["response"] for row in record["cases"]))
            self.assertGreater(record["coverage"]["uniqueEdges"], 0)
            self.assertGreater(record["coverage"]["mappedEdges"], 0)
            self.assertGreater(record["coverage"]["byBoundary"].get("server", 0), 0)
            self.assertGreater(record["coverage"]["byBoundary"].get("client", 0), 0)
            self.assertGreater(record["coverage"]["newEdgesPerHour"], 0)
            self.assertEqual(record["coverage"]["coverageHoles"], 1)
            native = record["coverage"]["nativePreciseCoverage"]
            self.assertGreater(native["uniqueEdges"], 0)
            self.assertGreaterEqual(native["eventCount"], 4)
            self.assertEqual(native["timeline"][-1]["globalEdgesSeen"], native["uniqueEdges"])
            self.assertFalse(native["plateauReached"])
            coverage = json.loads((output / "coverage.json").read_text())
            self.assertIn("v8-range", {edge["kind"] for edge in coverage["edges"]})
            self.assertIn("istanbul-statement", {edge["kind"] for edge in coverage["edges"]})
            original_sources = {edge["originalStart"]["source"] for edge in coverage["edges"] if edge["originalStart"]["mapped"]}
            self.assertTrue(any(source.endswith("target.ts") for source in original_sources))
            self.assertTrue(any(source.endswith("client.ts") for source in original_sources))
            snapshot = root / "score.json"
            scored = subprocess.run(
                [sys.executable, str(SEARCH_SCORE), "snapshot", str(campaign), "--profile", "web-stack", "--benchmark", "none", "--output", str(snapshot)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(scored.returncode, 0, scored.stderr)
            self.assertEqual(json.loads(snapshot.read_text())["score"]["newEdgesPerHour"], record["coverage"]["newEdgesPerHour"])


if __name__ == "__main__":
    unittest.main()
