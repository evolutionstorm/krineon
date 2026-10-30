from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts" / "semantic_hypothesis_loop.py"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        authorized = self.headers.get("Authorization") == "Bearer owned"
        if self.path == "/admin" and not authorized:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"blocked")
            return
        if self.path in {"/admin", "/ADMIN"} and (authorized or self.path == "/ADMIN"):
            body = b'<script id="__NEXT_DATA__">{"page":"/admin"}</script>'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class SemanticHypothesisLoopTests(unittest.TestCase):
    def run_cli(self, *args: str, expected: int = 0, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(completed.returncode, expected, completed.stderr or completed.stdout)
        return completed

    def test_derives_and_executes_authorization_route_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps({"authorization": {"confirmed": True, "basis": "owned fixture"}}) + "\n"
            )
            analysis = root / "analysis.json"
            analysis.write_text(
                json.dumps(
                    {
                        "producer": "krineon-framework-analysis",
                        "framework": "nextjs",
                        "facts": [
                            {"id": "route-admin", "kind": "manifest-route", "route": "/admin"},
                            {"id": "auth-call", "kind": "authentication-signal", "callee": "requireAuth"},
                            {"id": "case-normalizer", "kind": "call-operation", "callee": "pathname.toLowerCase"},
                            {"id": "middleware", "kind": "middleware-entry"},
                        ],
                        "relations": [
                            {
                                "kind": "middleware-route",
                                "routeFact": "route-admin",
                                "route": "/admin",
                                "concretePath": "/admin",
                                "matchedMiddleware": ["middleware"],
                                "handlerAuthSignals": [],
                                "middlewareAuthSignals": ["auth-call"],
                                "operationFacts": ["case-normalizer"],
                            }
                        ],
                    }
                )
                + "\n"
            )
            proposal = campaign / "proposal.json"
            self.run_cli("derive", str(campaign), "--analysis", str(analysis), "--output", str(proposal))
            value = json.loads(proposal.read_text())
            self.assertEqual(len(value["models"]), 1)
            self.assertEqual(value["models"][0]["boundary"], "authorization-to-route-execution")
            self.assertTrue(value["models"][0]["checks"])
            case_variant = next(
                row
                for row in value["models"][0]["experiment"]["variants"]
                if row["family"] == "case-fold"
            )
            self.assertEqual(case_variant["origin"], "source-transformation")
            self.assertEqual(case_variant["sourceFact"], "case-normalizer")
            self.assertTrue(
                value["models"][0]["assumptionFlow"]["sourceDerivedWitnessAvailable"]
            )
            approved = json.loads(
                self.run_cli("approve", str(campaign), "--proposal", str(proposal)).stdout
            )

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                output = campaign / "observation.json"
                environment = dict(os.environ)
                environment["KRINEON_AUTH_HEADER"] = "Authorization: Bearer owned"
                self.run_cli(
                    "run",
                    str(campaign),
                    "--proposal",
                    str(proposal),
                    "--signature",
                    approved["signature"],
                    "--base-url",
                    f"http://127.0.0.1:{server.server_port}",
                    "--output",
                    str(output),
                    env=environment,
                )
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()
            observation = json.loads(output.read_text())
            evaluation = observation["results"][0]["evaluation"]
            self.assertEqual(evaluation["verdict"], "oracle-violated")
            self.assertEqual(evaluation["violations"][0]["family"], "case-fold")
            self.assertGreater(evaluation["informationGain"], 0)

            value["models"][0]["route"] = "/changed"
            proposal.write_text(json.dumps(value) + "\n")
            rejected = campaign / "rejected.json"
            self.run_cli(
                "run",
                str(campaign),
                "--proposal",
                str(proposal),
                "--signature",
                approved["signature"],
                "--base-url",
                "http://127.0.0.1:1",
                "--output",
                str(rejected),
                expected=2,
                env=environment,
            )


if __name__ == "__main__":
    unittest.main()
