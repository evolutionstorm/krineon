from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
PIPELINE = PROJECT / "scripts" / "framework_analysis_pipeline.py"


class FrameworkAnalysisPipelineTests(unittest.TestCase):
    def test_ingest_is_idempotent_and_schedules_runtime_validation_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            initialized = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT / "scripts" / "research_harness.py"),
                    "init",
                    str(campaign),
                    "--target",
                    "framework-analysis-fixture",
                    "--repo",
                    "https://example.invalid/framework-analysis-fixture",
                    "--commit",
                    "f" * 40,
                    "--mode",
                    "source",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            planned = subprocess.run(
                [sys.executable, str(PROJECT / "scripts" / "research_harness.py"), "plan", str(campaign)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            queued = subprocess.run(
                [sys.executable, str(PROJECT / "scripts" / "research_harness.py"), "queue", str(campaign)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(queued.returncode, 0, queued.stderr)
            project = root / "project"
            (project / "src").mkdir(parents=True)
            (project / "package.json").write_text("{}\n")
            (project / "src" / "main.js").write_text("export const mode = process.env.RUNTIME_MODE;\n")
            spec = root / "spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "framework": "node",
                        "projectRoot": str(project),
                        "sourceGlobs": ["src/**/*.js"],
                        "generatedGlobs": [],
                        "vendoredGlobs": [],
                        "manifestGlobs": [],
                        "sourceMapGlobs": [],
                    }
                )
                + "\n"
            )
            for index in range(2):
                completed = subprocess.run(
                    [sys.executable, str(PIPELINE), str(campaign), str(spec), str(campaign / f"analysis-{index}"), "--ingest"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                rows = connection.execute(
                    "SELECT task_id, lane, packet FROM tasks WHERE lane = ?",
                    ("framework-runtime-hypothesis",),
                ).fetchall()
            self.assertEqual(len(rows), 1)
            packet = (campaign / rows[0][2]).read_text()
            self.assertIn("not a vulnerability verdict", packet)
            self.assertIn("production adapter", packet)

    def run_pipeline(self, root: Path, framework: str, project: Path, source_globs: list[str]) -> dict:
        campaign = root / f"campaign-{framework}"
        campaign.mkdir()
        (campaign / "campaign.json").write_text(
            json.dumps({"commit": framework * 8, "mode": "source", "authorization": {"confirmed": False}}) + "\n"
        )
        spec = root / f"{framework}-analysis.json"
        spec.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "framework": framework,
                    "projectRoot": str(project),
                    "sourceGlobs": source_globs,
                    "generatedGlobs": [],
                    "vendoredGlobs": [],
                    "manifestGlobs": [],
                    "sourceMapGlobs": [],
                }
            )
            + "\n"
        )
        output = campaign / "analysis"
        completed = subprocess.run(
            [sys.executable, str(PIPELINE), str(campaign), str(spec), str(output)],
            check=False,
            capture_output=True,
            text=True,
        )
        retained = (output / "framework-analysis.json").read_text() if (output / "framework-analysis.json").is_file() else ""
        self.assertEqual(completed.returncode, 0, f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n{retained}")
        return json.loads(retained)

    def test_react_and_node_entrypoints_produce_runtime_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            react = root / "react-project"
            (react / "src").mkdir(parents=True)
            (react / "package.json").write_text(json.dumps({"dependencies": {"react": "19.3.1", "react-dom": "19.3.1"}}) + "\n")
            (react / "src" / "server.tsx").write_text("'use server';\nimport {Client} from './client';\nexport const render = () => Client();\n")
            (react / "src" / "client.tsx").write_text("'use client';\nexport const Client = () => 'ok';\n")
            react_record = self.run_pipeline(root, "react", react, ["src/**/*.tsx"])
            self.assertTrue(any(row.get("crossesDirectiveBoundary") for row in react_record["relations"]))
            self.assertIn("directive-boundary", {row["kind"] for row in react_record["hypotheses"]})

            node = root / "node-project"
            (node / "src").mkdir(parents=True)
            (node / "package.json").write_text(json.dumps({"dependencies": {"express": "5.1.0"}}) + "\n")
            (node / "src" / "server.js").write_text(
                "app.post('/owned/action', async (req, res) => { await requireAuth(req); return res.send(process.env.MODE); });\n"
            )
            node_record = self.run_pipeline(root, "node", node, ["src/**/*.js"])
            handlers = [row for row in node_record["facts"] if row["kind"] == "http-handler"]
            self.assertEqual([(row["method"], row["route"]) for row in handlers], [("POST", "/owned/action")])
            node_hypotheses = {row["kind"] for row in node_record["hypotheses"]}
            self.assertTrue({"route-runtime-alignment", "middleware-handler-order", "environment-runtime-branch"}.issubset(node_hypotheses))

    def test_next_pipeline_links_manifests_boundaries_runtime_branches_and_source_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps({"commit": "a" * 40, "mode": "source", "authorization": {"confirmed": False}}) + "\n"
            )
            project = root / "project"
            (project / "app" / "admin").mkdir(parents=True)
            (project / "app" / "api" / "items").mkdir(parents=True)
            (project / ".next" / "server" / "app" / "admin").mkdir(parents=True)
            (project / ".next" / "static" / "chunks").mkdir(parents=True)
            (project / "node_modules" / "next" / "dist" / "server").mkdir(parents=True)
            (project / "package.json").write_text(json.dumps({"dependencies": {"next": "16.4.3", "react": "19.3.1"}}) + "\n")

            page = project / "app" / "admin" / "page.tsx"
            page.write_text(
                "'use server';\n"
                "import {Widget} from './widget';\n"
                "const mode = process.env.NEXT_RUNTIME === 'edge' ? 'edge' : 'node';\n"
                "const load = () => import('./worker');\n"
                "const value = unstable_cache(async () => mode, ['admin']);\n"
                "export default async function Page(){ await auth(); return Widget(value); }\n"
            )
            (project / "app" / "admin" / "widget.tsx").write_text("'use client';\nexport const Widget = (x) => x;\n")
            (project / "app" / "admin" / "worker.ts").write_text("export const worker = 1;\n")
            (project / "app" / "api" / "items" / "route.ts").write_text(
                "export async function GET(){ revalidatePath('/admin'); return new Response('ok'); }\n"
            )
            (project / "middleware.ts").write_text(
                "// auth() in a comment must not become a fact\n"
                "export async function middleware(request){ return requireAuth(request); }\n"
            )

            server = project / ".next" / "server"
            (server / "app-paths-manifest.json").write_text(
                json.dumps({"/admin": "app/admin/page.js", "/api/items/route": "app/api/items/route.js"}) + "\n"
            )
            (server / "middleware-manifest.json").write_text(
                json.dumps(
                    {
                        "middleware": {
                            "/": {
                                "files": ["server/middleware.js"],
                                "matchers": [{"regexp": "^/(?:admin|api/items)(?:/.*)?$"}],
                            }
                        }
                    }
                )
                + "\n"
            )
            (server / "server-reference-manifest.json").write_text(
                json.dumps({"node": {"ref-admin": {"workers": {"app/admin/page": "77"}, "layer": {"app/admin/page": "rsc"}}}, "edge": {}}) + "\n"
            )
            (project / ".next" / "routes-manifest.json").write_text(
                json.dumps({"staticRoutes": [{"page": "/admin", "regex": "^/admin$"}], "dynamicRoutes": [], "rewrites": []}) + "\n"
            )
            (project / ".next" / "prerender-manifest.json").write_text(
                json.dumps({"routes": {"/admin": {"initialRevalidateSeconds": 60, "dataRoute": "/_next/data/build/admin.json"}}}) + "\n"
            )
            bundle = server / "app" / "admin" / "page.js"
            bundle.write_text(
                "'use strict';\n"
                "const Widget=require(100);\n"
                "const mode=process.env.NEXT_RUNTIME;\n"
                "const load=()=>Promise.resolve().then(()=>require(101));\n"
                "const value=cache(()=>mode);\n"
                "exports.default=async function(){return Widget(value)};\n"
                "//# sourceMappingURL=page.js.map\n"
            )
            (bundle.parent / "page.js.map").write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "page.js",
                        "sources": ["../../../../app/admin/page.tsx"],
                        "names": [],
                        "mappings": "AAAA;AACA;AACA;AACA;AACA;AACA",
                        "sourcesContent": [page.read_text()],
                    }
                )
                + "\n"
            )
            (project / ".next" / "static" / "chunks" / "client.js").write_text("self.webpackChunk_N_E=[];\n")
            (project / "node_modules" / "next" / "dist" / "server" / "runtime.js").write_text(
                "export async function load(name){ return import(name); }\n"
            )

            spec = root / "analysis.json"
            spec.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "framework": "nextjs",
                        "projectRoot": str(project),
                        "sourceGlobs": ["app/**/*.ts", "app/**/*.tsx", "middleware.ts"],
                        "generatedGlobs": [".next/server/**/*.js", ".next/static/**/*.js"],
                        "vendoredGlobs": ["node_modules/next/dist/server/**/*.js"],
                        "manifestGlobs": [".next/**/*manifest*.json"],
                        "sourceMapGlobs": [".next/**/*.map"],
                        "maxHypotheses": 100,
                    }
                )
                + "\n"
            )
            output = campaign / "analysis"
            completed = subprocess.run(
                [sys.executable, str(PIPELINE), str(campaign), str(spec), str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            retained = (output / "framework-analysis.json").read_text() if (output / "framework-analysis.json").is_file() else ""
            self.assertEqual(completed.returncode, 0, f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n{retained}")
            record = json.loads(retained)
            self.assertEqual(record["producer"], "krineon-framework-analysis")
            self.assertFalse(record["analysisContract"]["vulnerabilityVerdictsProduced"])
            self.assertTrue(record["analysisContract"]["runtimeValidationRequired"])
            self.assertEqual(record["parser"]["kind"], "structural-javascript-tokenizer")
            kinds = {row["kind"] for row in record["facts"]}
            self.assertTrue(
                {
                    "manifest-route",
                    "source-route",
                    "middleware-entry",
                    "directive",
                    "dynamic-import",
                    "module-identity-use",
                    "server-reference-identity",
                    "cache-operation",
                    "environment-read",
                    "authentication-signal",
                    "call-operation",
                    "prerender-cache",
                }.issubset(kinds)
            )
            auth_facts = [row for row in record["facts"] if row["kind"] == "authentication-signal"]
            self.assertEqual({row["callee"] for row in auth_facts}, {"auth", "requireAuth"})
            operation_facts = [
                row for row in record["facts"] if row["kind"] == "call-operation"
            ]
            self.assertIn("requireAuth", {row["callee"] for row in operation_facts})
            relation_kinds = {row["kind"] for row in record["relations"]}
            self.assertTrue(
                {
                    "module-edge",
                    "route-source-manifest",
                    "middleware-route",
                    "route-runtime-dependencies",
                    "cache-revalidation-path",
                    "source-to-bundle",
                }.issubset(relation_kinds)
            )
            self.assertTrue(any(row.get("crossesDirectiveBoundary") for row in record["relations"]))
            self.assertTrue(
                any(
                    row["kind"] == "middleware-route" and row.get("operationFacts")
                    for row in record["relations"]
                )
            )
            self.assertTrue(any(row["kind"] == "source-to-bundle" and row["source"].endswith("page.tsx") for row in record["relations"]))
            cache_facts = [row for row in record["facts"] if row["kind"] == "cache-operation" and row.get("operation") == "unstable_cache"]
            self.assertEqual(cache_facts[0]["literalArguments"], ["admin"])
            environment_facts = [row for row in record["facts"] if row["kind"] == "environment-read" and row.get("source") == "app/admin/page.tsx"]
            self.assertTrue(environment_facts[0]["branchCandidate"])
            self.assertEqual({row["classification"] for row in record["runtimeFiles"]}, {"source", "generated", "vendored"})
            hypothesis_kinds = {row["kind"] for row in record["hypotheses"]}
            self.assertTrue(
                {
                    "route-runtime-alignment",
                    "middleware-handler-order",
                    "directive-boundary",
                    "dynamic-module-identity",
                    "cache-revalidation-isolation",
                    "environment-runtime-branch",
                }.issubset(hypothesis_kinds)
            )
            for hypothesis in record["hypotheses"]:
                self.assertEqual(hypothesis["classification"], "runtime-hypothesis")
                self.assertEqual(hypothesis["state"], "not-executed")
                self.assertEqual(hypothesis["conclusion"], "none-until-runtime-discriminator")
                self.assertNotIn("severity", hypothesis)
                self.assertNotIn("cwe", hypothesis)
                self.assertNotIn("cvss", hypothesis)
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            self.assertEqual(campaign_record["frameworkAnalysisRuns"][0]["hypotheses"], len(record["hypotheses"]))


if __name__ == "__main__":
    unittest.main()
