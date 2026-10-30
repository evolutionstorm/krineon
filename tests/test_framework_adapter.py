from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.framework_adapter import SURFACES, validate_framework


PROJECT = Path(__file__).resolve().parents[1]
ADAPTER = PROJECT / "scripts" / "framework_adapter.py"


def can_bind_loopback() -> bool:
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


def lockfile(root: Path, name: str) -> None:
    (root / "package-lock.json").write_text(
        json.dumps({"name": name, "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {"": {"name": name, "version": "1.0.0"}}}) + "\n"
    )


class FrameworkAdapterTests(unittest.TestCase):
    def test_framework_surface_catalogs_cover_requested_production_modes(self) -> None:
        self.assertTrue({"app-router", "pages-router", "middleware", "server-actions", "rsc", "route-handlers", "rewrites", "image-optimization", "node-runtime", "edge-runtime", "standalone"}.issubset(SURFACES["nextjs"]))
        self.assertTrue({"react-dom", "hydration", "server-rendering", "rsc", "browser-bundle", "source-maps", "client-server-boundary"}.issubset(SURFACES["react"]))
        self.assertTrue({"raw-http", "express", "fastify", "koa", "cli-parser", "native-addon", "worker-threads"}.issubset(SURFACES["node"]))

    def test_next_and_react_configs_require_declared_surface_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lockfile(root, "fixture")
            base_case = {
                "name": "production",
                "environment": {"NODE_ENV": "production"},
                "buildCommand": ["node", "build.js"],
                "launch": {"command": ["node", "server.js"]},
                "deploymentArtifacts": ["server.js"],
                "compilerProbes": [{"name": "node", "command": ["node", "--version"]}],
            }
            for framework, dependencies, surface in (
                ("nextjs", {"next": "16.4.3", "react": "19.3.1", "react-dom": "19.3.1"}, "app-router"),
                ("react", {"react": "19.3.1", "react-dom": "19.3.1"}, "hydration"),
            ):
                (root / "package.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0", "dependencies": dependencies}) + "\n")
                spec = {
                    "framework": framework,
                    "surfaces": [surface],
                    "lockfile": "package-lock.json",
                    "cases": [base_case],
                }
                with self.assertRaisesRegex(RuntimeError, "hashed evidence globs"):
                    validate_framework(spec, root)
                spec["surfaceEvidence"] = {surface: ["package.json"]}
                validate_framework(spec, root)

    def test_hidden_development_package_script_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lockfile(root, "fixture")
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "version": "1.0.0",
                        "dependencies": {"next": "16.4.3"},
                        "scripts": {"build": "next dev", "start": "next start"},
                    }
                )
                + "\n"
            )
            spec = {
                "framework": "nextjs",
                "surfaces": ["app-router"],
                "surfaceEvidence": {"app-router": ["package.json"]},
                "lockfile": "package-lock.json",
                "environment": {"NODE_ENV": "production"},
                "buildCommand": ["npm", "run", "build"],
                "launch": {"command": ["npm", "run", "start"]},
                "deploymentArtifacts": ["package.json"],
                "compilerProbes": [{"name": "node", "command": ["node", "--version"]}],
                "cases": [{"name": "production"}],
            }
            with self.assertRaisesRegex(RuntimeError, "development command"):
                validate_framework(spec, root)

    @unittest.skipUnless(shutil.which("node"), "Node is unavailable")
    @unittest.skipUnless(can_bind_loopback(), "loopback sockets are unavailable")
    def test_node_adapter_builds_launches_exercises_and_hashes_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(json.dumps({"commit": "b" * 40, "authorization": {"confirmed": True}}) + "\n")
            project = root / "project"
            project.mkdir()
            (project / "package.json").write_text(json.dumps({"name": "adapter-fixture", "version": "1.0.0", "scripts": {"build": "node build.js"}}) + "\n")
            lockfile(project, "adapter-fixture")
            (project / "server.js").write_text(
                "const http=require('node:http');\n"
                "const server=http.createServer((req,res)=>{res.statusCode=200;res.end(req.url==='/health'?'ok':'production');});\n"
                "server.listen(Number(process.env.PORT),'127.0.0.1');\n"
            )
            (project / "build.js").write_text(
                "const fs=require('node:fs');fs.mkdirSync('dist',{recursive:true});fs.copyFileSync('server.js','dist/server.js');\n"
            )
            exercise = root / "exercise.json"
            exercise.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "targets": {"node": {"host": "127.0.0.1", "port": "${PORT}"}},
                        "steps": [
                            {
                                "id": "production-route",
                                "target": "node",
                                "request": {"path": "/production", "headers": []},
                                "assertions": [{"kind": "body-contains", "value": "production"}],
                            }
                        ],
                    }
                )
                + "\n"
            )
            spec = root / "adapter.json"
            spec.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "framework": "node",
                        "projectRoot": str(project),
                        "lockfile": "package-lock.json",
                        "surfaces": ["raw-http"],
                        "surfaceEvidence": {"raw-http": ["server.js", "dist/server.js"]},
                        "environment": {"NODE_ENV": "production"},
                        "buildCommand": ["{runtime}", "build.js"],
                        "generatedArtifacts": ["dist/**"],
                        "deploymentArtifacts": ["dist/server.js"],
                        "compilerProbes": [{"name": "node-runtime", "command": ["{runtime}", "--version"]}],
                        "launch": {
                            "command": ["{runtime}", "dist/server.js"],
                            "environment": {"PORT": "{port}"},
                            "readyPath": "/health",
                        },
                        "exerciseSpec": "exercise.json",
                        "cases": [{"name": "current-node", "runtime": shutil.which("node")}],
                    }
                )
                + "\n"
            )
            output = campaign / "adapter-output"
            run = subprocess.run(
                [sys.executable, str(ADAPTER), str(campaign), str(spec), str(output)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            retained = (output / "framework-adapter-run.json").read_text() if (output / "framework-adapter-run.json").is_file() else ""
            self.assertEqual(run.returncode, 0, f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}\nmanifest:\n{retained}")
            manifest = json.loads(retained)
            self.assertEqual(manifest["status"], "passed")
            case = manifest["cases"][0]
            self.assertEqual(case["status"], "passed")
            self.assertEqual(case["surfaces"], ["raw-http"])
            self.assertTrue(case["surfaceEvidence"]["raw-http"])
            self.assertEqual(case["deploymentArtifacts"][0]["path"], "dist/server.js")
            self.assertTrue(case["runtime"]["sha256"])
            self.assertTrue(case["compilerProbes"][0]["executable"]["sha256"])
            protocol = Path(case["exercise"]["path"])
            self.assertEqual(json.loads(protocol.read_text())["status"], "passed")
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            self.assertEqual(campaign_record["frameworkAdapterRuns"][0]["framework"], "node")


if __name__ == "__main__":
    unittest.main()
