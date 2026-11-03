from __future__ import annotations

import json
import hashlib
import sqlite3
import tempfile
import threading
import unittest
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scripts.web_browser_harness import validate_scenario
from scripts.web_budget import SharedWebBudget
from scripts.web_contract import WebCampaignContract, WebContractError
from scripts.web_policy import WebPolicyEngine, normalize_scope_path, validate_step_envelope
from scripts.http_protocol_harness import BrokeredProtocolTransport
from tests.test_web_app_profile import OwnedFixtureHandler, contract_value, workflow_value


PROJECT = Path(__file__).resolve().parents[1]
REAL_BROWSER_FIXTURE = PROJECT / "tests" / "fixtures" / "web_browser_fixture.py"


def chromium_binary() -> str | None:
    configured = os.environ.get("KRINEON_TEST_CHROMIUM")
    if configured and Path(configured).is_file():
        return configured
    for name in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def can_bind() -> bool:
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


class SlowHandler(BaseHTTPRequestHandler):
    entered = threading.Event()

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        type(self).entered.set()
        time.sleep(10)


def resolver_for(*addresses: str):
    return lambda _host, port: [
        (2 if ":" not in address else 10, 1, 6, "", (address, port))
        for address in addresses
    ]


class WebPolicyBudgetTests(unittest.TestCase):
    def contract(self, root: Path, *, concurrent: int = 2) -> WebCampaignContract:
        value = contract_value("http://owned.test:8080", confirmed=False)
        value["origins"][0]["allowedPathPrefixes"] = ["/"]
        value["origins"][0]["excludedPaths"] = ["/billing"]
        value["origins"][0]["maxConcurrentRequests"] = concurrent
        value["budget"]["maxConcurrentRequests"] = concurrent
        value["budget"]["totalRequests"] = 6
        value["budget"]["cleanupReservedRequests"] = 1
        path = root / "contract.json"
        path.write_text(json.dumps(value, indent=2) + "\n")
        return WebCampaignContract.load(path)

    def governed_contract(self, root: Path) -> WebCampaignContract:
        value = contract_value("http://owned.test:8080", confirmed=True)
        manifest = root / "owned-accounts.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "accounts": [{"id": "user-a"}, {"id": "user-b"}],
                }
            )
            + "\n"
        )
        value["authorization"]["ownedFullTesting"] = {
            "enabled": True,
            "ownedAccountsOnly": True,
            "autoApproveBoundedWorkflows": True,
            "accountManifest": manifest.name,
            "accountManifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "accountIds": ["user-a", "user-b"],
        }
        value["researchDiversity"] = {
            "enforceOperationBinding": True,
            "warmupOperations": 2,
            "maximumAuthorizationRequestShare": 0.5,
            "minimumRuntimeFamiliesBeforeClosure": 2,
            "minimumNonAuthorizationFamiliesBeforeClosure": 1,
            "minimumNovelMechanismFamiliesBeforeClosure": 1,
        }
        path = root / "web-campaign.json"
        path.write_text(json.dumps(value, indent=2) + "\n")
        database = sqlite3.connect(root / "orchestration.db")
        database.executescript(
            """
            CREATE TABLE tasks(task_id TEXT PRIMARY KEY,state TEXT,title TEXT);
            CREATE TABLE task_approach_families(task_id TEXT,family_id TEXT);
            CREATE TABLE approach_families(family_id TEXT PRIMARY KEY,exploration INTEGER);
            CREATE TABLE events(
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT,
              event_type TEXT,task_id TEXT,worker_id TEXT,payload_json TEXT
            );
            """
        )
        tasks = [
            ("execution-task", "running", "Controlled execution"),
            ("auth-source", "completed", "Authorization mechanism"),
            ("capability-source", "completed", "Capability mechanism"),
            ("web-root-synthesis", "running", "Synthesis"),
        ]
        database.executemany("INSERT INTO tasks VALUES(?,?,?)", tasks)
        database.executemany(
            "INSERT INTO approach_families VALUES(?,1)",
            [
                ("web-authorization-isolation",),
                ("web-capability-sharing",),
            ],
        )
        database.executemany(
            "INSERT INTO task_approach_families VALUES(?,?)",
            [
                ("auth-source", "web-authorization-isolation"),
                ("capability-source", "web-capability-sharing"),
            ],
        )
        database.commit()
        database.close()
        return WebCampaignContract.load(path)

    @staticmethod
    def research_binding(family: str, source: str, experiment: str) -> dict[str, str]:
        return {
            "taskId": "execution-task",
            "sourceTaskId": source,
            "experimentId": experiment,
            "approachFamily": family,
            "mechanismFingerprint": f"mechanism-{experiment}",
        }

    def test_owned_full_testing_binds_operations_and_caps_one_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self.governed_contract(root)
            budget = SharedWebBudget(contract, root / "budget.sqlite3")
            with self.assertRaisesRegex(WebContractError, "researchBinding"):
                budget.reserve(
                    operation_id="unbound",
                    request_bytes=1,
                    estimated_response_bytes=1,
                    cleanup=False,
                    adapter="test",
                )
            for index in range(2):
                operation_id = f"auth-{index}"
                budget.reserve(
                    operation_id=operation_id,
                    request_bytes=1,
                    estimated_response_bytes=1,
                    cleanup=False,
                    adapter="test",
                    research_binding=self.research_binding(
                        "web-authorization-isolation", "auth-source", operation_id
                    ),
                )
                budget.reconcile_response(operation_id, 1)
            with self.assertRaisesRegex(WebContractError, "request-share cap"):
                budget.reserve(
                    operation_id="auth-capped",
                    request_bytes=1,
                    estimated_response_bytes=1,
                    cleanup=False,
                    adapter="test",
                    research_binding=self.research_binding(
                        "web-authorization-isolation", "auth-source", "auth-capped"
                    ),
                )
            budget.reserve(
                operation_id="capability-1",
                request_bytes=1,
                estimated_response_bytes=1,
                cleanup=False,
                adapter="test",
                research_binding=self.research_binding(
                    "web-capability-sharing", "capability-source", "capability-1"
                ),
            )
            budget.reconcile_response("capability-1", 1)
            ledger = budget.read()
            self.assertEqual(ledger["familyUsage"]["web-authorization-isolation"], 2)
            self.assertEqual(ledger["familyUsage"]["web-capability-sharing"], 1)
            database = sqlite3.connect(root / "orchestration.db")
            event_types = {
                row[0] for row in database.execute("SELECT event_type FROM events")
            }
            database.close()
            self.assertIn("web-operation-reserved", event_types)
            self.assertIn("web-operation-completed", event_types)

    def test_depth_gate_rejects_narrow_or_unfinished_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self.governed_contract(root)
            budget = SharedWebBudget(contract, root / "budget.sqlite3")
            for operation_id, family, source in (
                ("auth-one", "web-authorization-isolation", "auth-source"),
                ("cap-one", "web-capability-sharing", "capability-source"),
            ):
                budget.reserve(
                    operation_id=operation_id,
                    request_bytes=1,
                    estimated_response_bytes=1,
                    cleanup=False,
                    adapter="test",
                    research_binding=self.research_binding(family, source, operation_id),
                )
                budget.reconcile_response(operation_id, 1)
            blocked = budget.depth_gate()
            self.assertFalse(blocked["eligibleForCompletedCampaignClaim"])
            self.assertIn("web-root-synthesis is not complete", blocked["blockers"])
            database = sqlite3.connect(root / "orchestration.db")
            database.execute(
                "UPDATE tasks SET state='completed' WHERE task_id IN "
                "('execution-task','web-root-synthesis')"
            )
            database.commit()
            database.close()
            passed = budget.depth_gate()
            self.assertTrue(passed["eligibleForCompletedCampaignClaim"], passed)

    def test_canonicalization_checks_raw_and_normalized_paths(self) -> None:
        self.assertEqual(normalize_scope_path("/a/%7euser/../b"), "/a/b")
        with tempfile.TemporaryDirectory() as temporary:
            contract = self.contract(Path(temporary))
            policy = WebPolicyEngine(contract, resolver=resolver_for("127.0.0.1"))
            with self.assertRaisesRegex(WebContractError, "excluded scope"):
                policy.admit(
                    origin_id="app",
                    url="http://owned.test:8080/safe/%2e%2e/billing",
                    method="GET",
                    effect_class="read-only",
                    operation_class="ordinary-http",
                    intent="authorization-invariant",
                )
            with self.assertRaisesRegex(WebContractError, "ambiguous separator"):
                normalize_scope_path("/safe\\billing")

    def test_dns_rotation_is_allowed_only_inside_reviewed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = self.contract(Path(temporary))
            addresses = ["127.0.0.1"]

            def resolver(_host: str, port: int):
                return [(2, 1, 6, "", (value, port)) for value in addresses]

            policy = WebPolicyEngine(contract, resolver=resolver)
            decision = policy.admit(
                origin_id="app",
                url="http://owned.test:8080/health",
                method="GET",
                effect_class="read-only",
                operation_class="ordinary-http",
                intent="authorization-invariant",
            )
            addresses[:] = ["127.0.0.2"]
            policy.verify_connected(decision, "127.0.0.2")
            addresses[:] = ["169.254.169.254"]
            with self.assertRaisesRegex(WebContractError, "unauthorized destination"):
                policy.verify_connected(decision, "169.254.169.254")

    def test_redirect_is_a_candidate_not_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = self.contract(Path(temporary))
            contract.raw["authorization"]["allowRedirects"] = True
            policy = WebPolicyEngine(contract, resolver=resolver_for("127.0.0.1"))
            decision = policy.admit(
                origin_id="app",
                url="http://owned.test:8080/start",
                method="GET",
                effect_class="read-only",
                operation_class="ordinary-http",
                intent="authorization-invariant",
            )
            with self.assertRaisesRegex(WebContractError, "scope candidate"):
                policy.admit_redirect(
                    source=decision,
                    location="https://discovered.example/new",
                    method="GET",
                    effect_class="read-only",
                    operation_class="ordinary-http",
                    intent="authorization-invariant",
                )

    def test_concurrent_budget_and_cancellation_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self.contract(root, concurrent=2)
            budget = SharedWebBudget(contract, root / "budget.sqlite3")
            barrier = threading.Barrier(3)
            outcomes: list[str] = []

            def reserve(index: int) -> None:
                barrier.wait()
                try:
                    budget.reserve(
                        operation_id=f"op-thread-{index}",
                        request_bytes=1,
                        estimated_response_bytes=1,
                        cleanup=False,
                        adapter="test",
                        origin_id="app",
                    )
                    outcomes.append("reserved")
                except WebContractError:
                    outcomes.append("blocked")

            threads = [threading.Thread(target=reserve, args=(index,)) for index in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["blocked", "reserved", "reserved"])
            budget.cancel("operator stop")
            self.assertTrue(budget.is_cancelled())
            with self.assertRaisesRegex(WebContractError, "cancelled"):
                budget.reserve(
                    operation_id="op-after-cancel",
                    request_bytes=1,
                    estimated_response_bytes=1,
                    cleanup=False,
                    adapter="test",
                )

    @unittest.skipUnless(can_bind(), "loopback sockets unavailable")
    def test_cancellation_stops_an_outstanding_raw_http_job(self) -> None:
        SlowHandler.entered.clear()
        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                origin = f"http://127.0.0.1:{server.server_port}"
                value = contract_value(origin, confirmed=False)
                contract_path = root / "contract.json"
                contract_path.write_text(json.dumps(value, indent=2) + "\n")
                contract = WebCampaignContract.load(contract_path)
                budget = SharedWebBudget(contract, root / "budget.sqlite3")
                transport = BrokeredProtocolTransport(contract, budget)
                wire = (
                    f"GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                definition = {
                    "effectClass": "read-only",
                    "operationClass": "ordinary-http",
                    "intent": "authorization-invariant",
                    "timeout": 20,
                    "limits": {
                        "maximumEffect": "read one owned slow response",
                        "maxActions": 1,
                        "maxInputBytes": 4096,
                        "timeoutSeconds": 20,
                        "cleanupPlan": "none required",
                        "retryPolicy": "never",
                        "idempotent": True,
                    },
                }
                errors: list[Exception] = []

                def run() -> None:
                    try:
                        transport.exchange(
                            operation_id="op-cancel-live-job",
                            target={
                                "host": "127.0.0.1",
                                "port": server.server_port,
                                "originId": "app",
                            },
                            wire=wire,
                            definition=definition,
                        )
                    except Exception as exc:
                        errors.append(exc)

                worker = threading.Thread(target=run)
                worker.start()
                self.assertTrue(SlowHandler.entered.wait(2))
                budget.cancel("operator stop")
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertTrue(errors)
                self.assertTrue(budget.is_cancelled())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_effect_envelope_blocks_expensive_and_prohibited_templates(self) -> None:
        step = {
            "intent": "regex-backtracking",
            "limits": {
                "maximumEffect": "read one record",
                "maxActions": 1,
                "maxInputBytes": 10,
                "timeoutSeconds": 1,
                "cleanupPlan": "none required",
                "retryPolicy": "never",
                "idempotent": True,
            },
        }
        with self.assertRaisesRegex(WebContractError, "prohibited"):
            validate_step_envelope(step)
        step["intent"] = "authorization-invariant"
        step["limits"]["retryPolicy"] = "automatic"
        with self.assertRaisesRegex(WebContractError, "retry"):
            validate_step_envelope(step)
        with tempfile.TemporaryDirectory() as temporary:
            contract = self.contract(Path(temporary))
            policy = WebPolicyEngine(contract, resolver=resolver_for("127.0.0.1"))
            with self.assertRaisesRegex(WebContractError, "not permitted"):
                policy.admit(
                    origin_id="app",
                    url="http://owned.test:8080/search?q=small",
                    method="GET",
                    effect_class="unknown",
                    operation_class="ordinary-http",
                    intent="ordinary-security-observation",
                )

    def test_subprocess_policy_rejects_unowned_link_local_egress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = contract_value("http://169.254.169.254", confirmed=False)
            value["networkContainment"]["ownedInternalLabCidrs"] = []
            contract_path = root / "contract.json"
            contract_path.write_text(json.dumps(value, indent=2) + "\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT / "scripts" / "web_policy.py"),
                    str(contract_path),
                    "app",
                    "http://169.254.169.254/latest/meta-data",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("unauthorized destination", completed.stdout)

    @unittest.skipUnless(can_bind(), "loopback sockets unavailable")
    def test_raw_http1_harness_uses_broker_policy_and_shared_budget(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedFixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                campaign = root / "campaign"
                campaign.mkdir()
                (campaign / "campaign.json").write_text(
                    json.dumps({"commit": "owned", "authorization": {"confirmed": True}}) + "\n"
                )
                origin = f"http://127.0.0.1:{server.server_port}"
                value = contract_value(origin, confirmed=True)
                contract_path = root / "contract.json"
                contract_path.write_text(json.dumps(value, indent=2) + "\n")
                spec = {
                    "schemaVersion": 1,
                    "targets": {
                        "app": {
                            "host": "127.0.0.1",
                            "port": server.server_port,
                            "originId": "app",
                        }
                    },
                    "sessions": {
                        "anonymous": {
                            "role": "anonymous",
                            "tenant": None,
                            "cookies": {},
                            "variables": {},
                        }
                    },
                    "steps": [
                        {
                            "id": "negative-control",
                            "type": "request",
                            "target": "app",
                            "session": "anonymous",
                            "effectClass": "read-only",
                            "operationClass": "ordinary-http",
                            "intent": "parser-agreement",
                            "limits": {
                                "maximumEffect": "read one owned fixture response",
                                "maxActions": 1,
                                "maxInputBytes": 4096,
                                "timeoutSeconds": 5,
                                "cleanupPlan": "none required",
                                "retryPolicy": "never",
                                "idempotent": True,
                            },
                            "request": {"method": "GET", "path": "/missing", "headers": []},
                            "assertions": [{"kind": "status", "equals": 403}],
                        }
                    ],
                }
                spec_path = root / "protocol.json"
                spec_path.write_text(json.dumps(spec, indent=2) + "\n")
                output = root / "output"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PROJECT / "scripts" / "http_protocol_harness.py"),
                        str(campaign),
                        str(spec_path),
                        str(output),
                        "--web-contract",
                        str(contract_path),
                        "--ledger",
                        str(root / "budget.sqlite3"),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads((output / "protocol-run.json").read_text())
                self.assertEqual(result["transport"], "brokered-byte-exact-http/1.1")
                exchange = result["steps"][0]["redirectChain"][0]
                self.assertEqual(exchange["transport"]["transport"], "byte-exact-http/1.1")
                self.assertEqual(exchange["transport"]["connectedAddress"], "127.0.0.1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_browser_scenario_requires_explicit_supported_capabilities(self) -> None:
        workflow = workflow_value()
        workflow["steps"][0]["type"] = "browser"
        scenario = {
            "schemaVersion": 1,
            "id": "local-browser",
            "requiredCapabilities": ["fresh-process-per-run", "sandbox-enabled"],
            "runs": [
                {
                    "id": "victim",
                    "role": "victim",
                    "mode": "headless",
                    "workflowStep": workflow["steps"][0]["id"],
                    "timeoutSeconds": 10,
                }
            ],
        }
        self.assertEqual(validate_scenario(scenario, workflow)["runs"], 1)
        scenario["requiredCapabilities"].append("fake-unsupported-capability")
        with self.assertRaisesRegex(WebContractError, "unsupported"):
            validate_scenario(scenario, workflow)

    @unittest.skipUnless(chromium_binary() and can_bind(), "real Chromium or loopback sockets unavailable")
    def test_real_chromium_owned_fixture_exercises_browser_surfaces(self) -> None:
        from scripts.web_cdp_runner import discover
        from scripts.web_endpoint_catalog import build_catalog
        from scripts.web_js_api_extract import extract
        from scripts.experiment_control import ensure_authority

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ensure_authority(root)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = int(listener.getsockname()[1])
            process = subprocess.Popen(
                [sys.executable, str(REAL_BROWSER_FIXTURE), "--port", str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), 0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                value = contract_value(f"http://127.0.0.1:{port}", confirmed=True)
                value["authorization"]["allowBrowserNavigation"] = True
                value["origins"][0]["maxConcurrentRequests"] = 32
                value["budget"]["maxConcurrentRequests"] = 32
                contract_path = root / "contract.json"
                contract_path.write_text(json.dumps(value, indent=2) + "\n")
                contract = WebCampaignContract.load(contract_path)
                workflow = workflow_value()
                step = workflow["steps"][0]
                step.update({"type": "browser", "path": "/fixture", "identityId": "anonymous"})
                result = discover(
                    campaign=root,
                    binary=Path(str(chromium_binary())),
                    contract=contract,
                    workflow=workflow,
                    step=step,
                    ledger=SharedWebBudget(contract, root / "budget.sqlite3"),
                    output=root / "browser",
                    timeout=20,
                )
                resources = json.dumps(result["discovery"])
                events = (root / "browser" / "cdp-events.redacted.json").read_text()
                self.assertIn("/login", resources)
                self.assertIn("/frame", resources)
                self.assertIn("/csrf", events)
                self.assertIn("/popup", events)
                self.assertIn("/ws", events)
                self.assertIn("/app.min.js", events)
                self.assertIn("/lazy.js", events)
                self.assertIn("/api/projects/owned", events)
                self.assertIn("/graphql?query=OwnedProject", events)
                self.assertIn("/api/lazy-observed", events)
                self.assertIn("Target.attachedToTarget", events)
                self.assertTrue(result["discovery"]["serviceWorkers"])
                self.assertTrue(result["freshProfile"])
                self.assertTrue(result["sandbox"]["verified"])
                self.assertTrue(result["browserRequestContext"]["generatedByChrome"])
                self.assertFalse(result["browserRequestContext"]["copiedUserAgent"])
                self.assertEqual(result["accessState"]["state"], "application-response")
                manifest = json.loads(
                    (root / "browser" / "client-artifact-manifest.json").read_text()
                )
                urls = {item["url"] for item in manifest["artifacts"]}
                self.assertTrue(any(url.endswith("/app.min.js") for url in urls), manifest)
                self.assertTrue(any(url.endswith("/lazy.js") for url in urls), manifest)
                self.assertTrue(manifest["unavailableArtifacts"])
                self.assertFalse(manifest["automaticSourceMapProbing"])
                self.assertEqual(result["clientArtifactCount"], len(manifest["artifacts"]))
                extraction = extract(
                    root / "browser" / "client-artifact-manifest.json",
                    root / "browser",
                )
                extraction_path = root / "browser" / "api-extraction.json"
                extraction_path.write_text(json.dumps(extraction, indent=2) + "\n")
                catalog = build_catalog([extraction_path])
                self.assertTrue(
                    any(
                        row["semanticPathTemplate"] == "/api/projects/owned"
                        and row["confidence"] == "runtime-observed"
                        for row in extraction["runtimeOperations"]
                    )
                )
                self.assertTrue(catalog["staticRuntimeCorrelations"])
                self.assertTrue(catalog["workflowHypotheses"])
            finally:
                process.terminate()
                process.wait(timeout=3)
                if process.stderr is not None:
                    process.stderr.close()


if __name__ == "__main__":
    unittest.main()
