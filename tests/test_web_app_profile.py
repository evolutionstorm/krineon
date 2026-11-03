from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scripts.research_harness import (
    WEB_CANDIDATE_GATES,
    WEB_REPORTABLE_GATES,
    verified_web_observation,
    web_gate_result,
)
from scripts.web_blind_evaluation import (
    discover as blind_discover,
    enroll,
    mechanism_fingerprint,
    score,
    score_discovery,
)
from scripts.web_business_logic import compile_business_logic
from scripts.web_cdp_runner import browser_network_flags, discover
from scripts.web_contract import (
    BudgetLedger,
    ExecutionLease,
    WebCampaignContract,
    WebContractError,
)
from scripts.web_execution_broker import WebExecutionBroker
from scripts.web_markdown_requests import convert
from scripts.web_nuclei_adapter import admitted_template
from scripts.web_workflow import approve, load_object, validate_workflow, verify
from scripts.web_oracles import admit_contract, evaluate_contract
from scripts.web_sequence_executor import execute_plan
from scripts.web_sequence_planner import build_graph


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
BOOTSTRAP = PROJECT / "scripts" / "campaign_bootstrap.py"
WEB_BROKER = PROJECT / "scripts" / "web_execution_broker.py"
TEMPLATE = PROJECT / "assets" / "web-campaign.template.json"


class OwnedFixtureHandler(BaseHTTPRequestHandler):
    requests_seen = 0
    race_lock = threading.Lock()
    race_active = 0
    race_max_active = 0
    race_overlap_observed = False

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        type(self).requests_seen += 1
        authorization = self.headers.get("Authorization", "")
        if self.path == "/tenant-a" and authorization == "Bearer token-a":
            self.respond(200, {"tenant": "tenant-a", "secret": "owned-a"})
            return
        if self.path == "/tenant-b" and authorization == "Bearer token-b":
            self.respond(200, {"tenant": "tenant-b", "secret": "owned-b"})
            return
        if self.path == "/tenant-b" and authorization == "Bearer token-a":
            # Deliberate owned-fixture defect used to test the oracle itself.
            self.respond(200, {"tenant": "tenant-b", "secret": "owned-b"})
            return
        self.respond(403, {"error": "forbidden"})

    def do_POST(self) -> None:
        type(self).requests_seen += 1
        authorization = self.headers.get("Authorization", "")
        if self.path == "/race/reset" and authorization in {
            "Bearer token-a",
            "Bearer token-b",
        }:
            with type(self).race_lock:
                type(self).race_active = 0
                type(self).race_max_active = 0
            self.respond(200, {"reset": "true"})
            return
        if self.path == "/race" and authorization in {
            "Bearer token-a",
            "Bearer token-b",
        }:
            with type(self).race_lock:
                type(self).race_active += 1
                type(self).race_max_active = max(
                    type(self).race_max_active, type(self).race_active
                )
                if type(self).race_active == 2:
                    type(self).race_overlap_observed = True
            time.sleep(0.1)
            with type(self).race_lock:
                overlap = type(self).race_max_active
                type(self).race_active -= 1
            self.respond(209 if overlap == 2 else 200, {"overlap": str(overlap)})
            return
        self.respond(403, {"error": "forbidden"})

    def respond(self, status: int, value: dict[str, str]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def contract_value(origin: str, *, confirmed: bool) -> dict[str, object]:
    value = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    value["environmentOwner"] = "krineon-test"
    value["origins"] = [
        {
            "id": "app",
            "url": origin,
            "purpose": "owned-application-fixture",
            "allowedPathPrefixes": ["/"],
            "excludedPaths": ["/billing"],
            "allowedMethods": ["GET", "HEAD"],
            "maxRequestsPerSecond": 100,
            "maxConcurrentRequests": 1,
        }
    ]
    value["authorization"].update(
        {
            "confirmed": confirmed,
            "rulesFile": "PROGRAM_RULES.md",
            "confirmedBy": "test-coordinator" if confirmed else "",
            "confirmedAt": now.isoformat() if confirmed else None,
            "validUntil": (now + dt.timedelta(days=1)).isoformat() if confirmed else None,
            "ownedFixtureNamespace": "krineon-web-test",
        }
    )
    value["identities"] = [
        {
            "id": "user-a",
            "credentialRef": "secret://user-a",
            "secretVersion": "sv-test-user-a",
            "credentialType": "bearer",
            "expectedTenant": "tenant-a",
            "roles": ["member"],
            "session": "session-a",
            "allowedOriginIds": ["app"],
            "allowedPathPrefixes": ["/"],
            "allowedTransports": ["http", "browser"],
            "expiresAt": (now + dt.timedelta(days=1)).isoformat(),
            "verification": {
                "status": "verified",
                "method": "owner-assertion",
                "evidence": "owned test identity user-a",
            },
        },
        {
            "id": "user-b",
            "credentialRef": "secret://user-b",
            "secretVersion": "sv-test-user-b",
            "credentialType": "bearer",
            "expectedTenant": "tenant-b",
            "roles": ["member"],
            "session": "session-b",
            "allowedOriginIds": ["app"],
            "allowedPathPrefixes": ["/"],
            "allowedTransports": ["http", "browser"],
            "expiresAt": (now + dt.timedelta(days=1)).isoformat(),
            "verification": {
                "status": "verified",
                "method": "owner-assertion",
                "evidence": "owned test identity user-b",
            },
        },
    ]
    value["actionPolicies"] = [
        {
            "id": "owned-read",
            "originId": "app",
            "pathPrefix": "/",
            "methods": ["GET", "HEAD"],
            "effectClasses": ["read-only"],
            "maxRequestBodyBytes": 4096,
            "maxResponseBodyBytes": 16384,
        }
    ]
    value["budget"].update(
        {
            "totalRequests": 40,
            "cleanupReservedRequests": 2,
            "totalRequestBytes": 1024 * 1024,
            "totalResponseBytes": 2 * 1024 * 1024,
            "maxRequestsPerSecond": 100,
            "maxConcurrentRequests": 1,
            "maxRequestBodyBytes": 4096,
            "maxResponseBodyBytes": 16384,
            "maxWallSeconds": 120,
        }
    )
    value["networkContainment"]["ownedInternalLabCidrs"] = [
        "127.0.0.0/8",
        "::1/128",
    ]
    value["program"] = {
        "url": "https://example.invalid/program",
        "rulesDate": now.date().isoformat(),
        "researcherHeaders": {"X-Researcher": "krineon-test"},
    }
    return value


def workflow_value() -> dict[str, object]:
    def step(step_id: str, path: str, identity: str, owner: str) -> dict[str, object]:
        return {
            "id": step_id,
            "type": "http",
            "originId": "app",
            "identityId": identity,
            "method": "GET",
            "path": path,
            "headers": [],
            "effectClass": "read-only",
            "resource": {
                "id": path.removeprefix("/"),
                "kind": "tenant-record",
                "expectedOwner": owner,
                "selectedResource": path,
                "permittedAction": "read",
            },
            "intent": "authorization-invariant",
            "observationContext": {
                "evidenceOrigin": "owned fixture response",
                "cacheLayer": "not-applicable",
                "executionContext": "independent HTTP request",
            },
            "limits": {
                "maximumEffect": "read one owned fixture record",
                "maxActions": 1,
                "maxInputBytes": 4096,
                "timeoutSeconds": 5,
                "cleanupPlan": "none required for read-only step",
                "retryPolicy": "never",
                "idempotent": True,
            },
            "extract": [{"id": "secret", "pointer": "/secret"}],
        }

    oracle = {
        "schemaVersion": 1,
        "id": "tenant-isolation",
        "kind": "tenant-isolation",
        "claim": "A tenant A identity cannot read tenant B's owned record.",
        "requiredObservations": [
            {"step": "baseline-a", "field": "response.status"},
            {"step": "baseline-b", "field": "response.extractions.secret.sha256"},
            {"step": "negative-b", "field": "response.status"},
            {"step": "attack-b", "field": "response.extractions.secret.sha256"},
        ],
        "assertions": [
            {
                "id": "baseline-a-works",
                "role": "baseline-control",
                "operator": "equals",
                "left": {"step": "baseline-a", "field": "response.status"},
                "right": {"literal": 200},
                "expected": True,
            },
            {
                "id": "anonymous-is-blocked",
                "role": "enforcing-negative",
                "operator": "equals",
                "left": {"step": "negative-b", "field": "response.status"},
                "right": {"literal": 403},
                "expected": True,
            },
            {
                "id": "cross-tenant-read-is-blocked",
                "role": "positive-invariant",
                "operator": "equals",
                "left": {"step": "attack-b", "field": "response.status"},
                "right": {"literal": 403},
                "expected": True,
            },
            {
                "id": "cross-tenant-body-differs",
                "role": "positive-invariant",
                "operator": "not-equals",
                "left": {
                    "step": "attack-b",
                    "field": "response.extractions.secret.sha256",
                },
                "right": {
                    "step": "baseline-b",
                    "field": "response.extractions.secret.sha256",
                },
                "expected": True,
            },
        ],
        "inconclusiveWhenMissing": True,
    }
    steps = [
        step("baseline-a", "/tenant-a", "user-a", "tenant-a"),
        step("baseline-b", "/tenant-b", "user-b", "tenant-b"),
        step("negative-b", "/tenant-b", "anonymous", "tenant-b"),
        step("attack-b", "/tenant-b", "user-a", "tenant-b"),
    ]
    steps[2]["extract"] = []

    def operation_contract(
        step_value: dict[str, object], after: list[str], observation_id: str
    ) -> dict[str, object]:
        actor_id = str(step_value["identityId"])
        resource = dict(step_value["resource"])
        owner = str(resource["expectedOwner"])
        identity = {
            "user-a": ("member", "tenant-a", "session-a"),
            "user-b": ("member", "tenant-b", "session-b"),
            "anonymous": ("anonymous", "public", "anonymous"),
        }[actor_id]
        step_id = str(step_value["id"])
        return {
            "id": step_id,
            "actorRef": {
                "id": actor_id,
                "role": identity[0],
                "tenant": identity[1],
                "session": identity[2],
                "verified": True,
                "effectiveActor": actor_id,
                "capabilityVersion": "owned-identities-v1",
            },
            "actionRef": {
                "runner": "krineon-http-broker-v1",
                "workflow": "web/tenant-workflow.json",
                "signature": "web/tenant-workflow.json.sig",
                "campaignContract": "web-campaign.json",
                "workflowId": "owned-tenant-isolation",
                "stepId": step_id,
                "effectClass": "read-only",
            },
            "resourceBindings": [
                {
                    "id": str(resource["id"]),
                    "kind": "tenant-record",
                    "parent": "owned-root",
                    "tenant": owner,
                    "owner": owner,
                    "version": "v1",
                    "generation": "g1",
                    "fixtureNamespace": "krineon-web-test",
                    "owned": True,
                    "disposable": True,
                }
            ],
            "requires": {
                "operator": "fact",
                "type": "operation" if after else "state",
                "ref": after[-1] if after else "fixture-not-ready",
                "expected": True if after else False,
                "evidence": [],
            },
            "produces": [],
            "consumes": [],
            "invalidates": [],
            "authorityBinding": {
                "actor": actor_id,
                "resource": str(resource["id"]),
                "action": "read",
                "version": "v1",
            },
            "ordering": {
                "after": after,
                "before": [],
                "asyncBoundary": False,
                "sequencingHintOnly": False,
                "dependencyConfidence": "replay-confirmed",
                "evidence": ["owned normal-workflow replay"],
            },
            "observations": [
                {
                    "id": observation_id,
                    "kind": "authoritative-readback",
                    "authoritative": True,
                    "evidenceOrigin": "server-response",
                    "resourceBindingRef": str(resource["id"]),
                    "stateSelectors": {
                        "status": "response.status",
                        "bodySha256": "response.bodySha256",
                    },
                }
            ],
            "consistencyWindow": {
                "basis": "synchronous owned fixture",
                "maximumSeconds": 0,
            },
            "cleanup": {"hookRef": "none-read-only", "irreversible": False},
            "cost": {
                "maxRequests": 1,
                "maxSteps": 1,
                "maxBytes": 16384,
                "maxPolling": 0,
                "maxEffects": 0,
                "maxConcurrencyParticipants": 1,
            },
        }

    operation_contracts = []
    observation_ids = [
        "owner-readback",
        "other-owner-readback",
        "anonymous-negative-readback",
        "cross-owner-readback",
    ]
    for index, step_value in enumerate(steps):
        operation_contracts.append(
            operation_contract(
                step_value,
                [str(steps[index - 1]["id"])] if index else [],
                observation_ids[index],
            )
        )
    return {
        "schemaVersion": 1,
        "prerequisiteVersion": "owned-fixture-prerequisite-v1",
        "id": "owned-tenant-isolation",
        "title": "Owned cross-tenant authorization discriminator",
        "hypothesis": "The application resolves tenant B's record under tenant A's identity.",
        "competingExplanations": [
            {
                "id": "H1",
                "statement": "Tenant isolation is violated.",
                "expectedObservations": ["attack-b returns the tenant-b record"],
            },
            {
                "id": "H2",
                "statement": "The route is protected and the response is an error artifact.",
                "expectedObservations": ["attack-b is denied like negative-b"],
            },
        ],
        "changedVariable": "identityId",
        "steps": steps,
        "operationContracts": operation_contracts,
        "oracles": [oracle],
        "cleanupSteps": [],
        "coordinatorApproval": {
            "approved": False,
            "approvedBy": "",
            "approvedAt": None,
            "contractSha256": "",
        },
    }


class WebAppProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        OwnedFixtureHandler.requests_seen = 0
        OwnedFixtureHandler.race_active = 0
        OwnedFixtureHandler.race_max_active = 0
        OwnedFixtureHandler.race_overlap_observed = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedFixtureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def initialize_campaign(self, root: Path) -> Path:
        campaign = root / "campaign"
        completed = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "init",
                str(campaign),
                "--target",
                "owned-web-fixture",
                "--repo",
                "web-application-no-source",
                "--commit",
                "deployed-artifact-test",
                "--profile",
                "web-app",
                "--mode",
                "local-lab",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        (campaign / "PROGRAM_RULES.md").write_text("Owned fixture only.\n", encoding="utf-8")
        return campaign

    def test_bootstrap_url_creates_offline_plan_without_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "web-campaign"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BOOTSTRAP),
                    str(campaign),
                    "--app-url",
                    self.origin + "/tenant-a",
                    "--profile",
                    "web-app",
                    "--no-queue",
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual(output["profile"], "web-app")
            self.assertFalse(output["authorizationConfirmed"])
            launch = json.loads((campaign / "launch-plan.json").read_text())
            contract = WebCampaignContract.load(campaign / "web-campaign.json")
            self.assertEqual(len(launch["tasks"]), 26)
            self.assertTrue(
                {
                    "web-cache-semantic-research",
                    "web-deserialization-semantic-research",
                    "web-bounded-boundary-adapters",
                }.issubset({value["taskId"] for value in launch["tasks"]})
            )
            self.assertFalse(contract.offline_plan()["trafficPermitted"])
            self.assertEqual(OwnedFixtureHandler.requests_seen, 0)

    def test_bot_protection_access_requires_owner_approval_and_revalidated_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value = contract_value(self.origin, confirmed=False)
            approval = value["authorization"]["botProtectionApproval"]
            approval.update(
                {
                    "enabled": True,
                    "kind": "source-ip-allowlist",
                    "approvedBy": "fixture-owner",
                    "evidence": "owned fixture policy record",
                    "baselineRevalidated": False,
                    "environmentDifferences": ["WAF challenge bypassed for test source"],
                }
            )
            path = root / "contract.json"
            path.write_text(json.dumps(value, indent=2) + "\n")
            with self.assertRaisesRegex(WebContractError, "revalidated"):
                WebCampaignContract.load(path)
            approval["baselineRevalidated"] = True
            path.write_text(json.dumps(value, indent=2) + "\n")
            self.assertTrue(
                WebCampaignContract.load(path).raw["authorization"]
                ["botProtectionApproval"]["enabled"]
            )

    def test_dos_is_rejected_at_planning_and_unconfirmed_dispatch_is_zero_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contract_path = root / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=False), indent=2) + "\n"
            )
            contract = WebCampaignContract.load(contract_path)
            workflow = workflow_value()
            workflow["steps"][0]["effectClass"] = "dos"
            with self.assertRaisesRegex(WebContractError, "effect class"):
                validate_workflow(workflow, contract, dynamic=False)

            cache_workflow = workflow_value()
            cache_workflow["steps"][0]["operationClass"] = "cache-experiment"
            with self.assertRaisesRegex(WebContractError, "allowCacheMutation"):
                validate_workflow(cache_workflow, contract, dynamic=False)

            safe_workflow = workflow_value()
            output = root / "blocked-output"
            broker = WebExecutionBroker(
                root,
                contract,
                safe_workflow,
                BudgetLedger(contract, root / "ledger.json"),
                output,
            )
            with self.assertRaisesRegex(WebContractError, "authorization.confirmed"):
                broker.run()
            self.assertEqual(OwnedFixtureHandler.requests_seen, 0)
            self.assertFalse(output.exists())

            campaign = self.initialize_campaign(root)
            confirmed_path = campaign / "web-campaign.json"
            confirmed_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=True), indent=2) + "\n"
            )
            workflow_path = campaign / "web" / "approved-safe-workflow.json"
            workflow_path.write_text(
                json.dumps(workflow_value(), indent=2) + "\n", encoding="utf-8"
            )
            approve(
                campaign,
                confirmed_path,
                workflow_path,
                workflow_path.with_suffix(".json.sig"),
            )
            malicious = load_object(workflow_path)
            malicious["steps"][0]["effectClass"] = "dos"
            confirmed = WebCampaignContract.load(confirmed_path)
            dispatch_output = campaign / "evidence" / "web" / "dos-dispatch"
            result = WebExecutionBroker(
                campaign,
                confirmed,
                malicious,
                BudgetLedger(confirmed, campaign / "evidence" / "web" / "dos-ledger.json"),
                dispatch_output,
            ).run()
            self.assertIn("dos", result["failure"])
            self.assertEqual(OwnedFixtureHandler.requests_seen, 0)
            self.assertEqual(
                json.loads((dispatch_output / "budget-ledger.json").read_text())[
                    "requests"
                ],
                0,
            )

    def test_markdown_rejects_literal_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            contract_path = Path(tmp) / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=False), indent=2) + "\n"
            )
            contract = WebCampaignContract.load(contract_path)
            capture = """<!-- krineon: id=read origin=app identity=user-a effect=read-only -->
```http
GET /tenant-a HTTP/1.1
Cookie: session=plaintext

```
"""
            with self.assertRaisesRegex(WebContractError, "credential header"):
                convert(capture, contract, "requests.md")

    def test_nuclei_templates_are_hash_pinned_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe = root / "safe.yaml"
            safe.write_text(
                """id: owned-read
info:
  name: Owned read
  author: krineon
  severity: info
http:
  - method: GET
    path:
      - \"{{BaseURL}}\"
""",
                encoding="utf-8",
            )
            value = contract_value(self.origin, confirmed=False)
            value["authorization"]["allowNuclei"] = True
            value["nuclei"] = {
                "enabled": True,
                "maxTemplates": 1,
                "admittedTemplates": [
                    {
                        "id": "owned-read",
                        "path": "safe.yaml",
                        "sha256": hashlib.sha256(safe.read_bytes()).hexdigest(),
                        "maxRequests": 1,
                    }
                ],
            }
            contract_path = root / "web-campaign.json"
            contract_path.write_text(json.dumps(value, indent=2) + "\n")
            contract = WebCampaignContract.load(contract_path)
            selected, count = admitted_template(contract, "owned-read")
            self.assertEqual(selected, safe)
            self.assertEqual(count, 1)

            safe.write_text(safe.read_text() + "    unsafe: true\n", encoding="utf-8")
            value["nuclei"]["admittedTemplates"][0]["sha256"] = hashlib.sha256(
                safe.read_bytes()
            ).hexdigest()
            contract_path.write_text(json.dumps(value, indent=2) + "\n")
            contract = WebCampaignContract.load(contract_path)
            with self.assertRaisesRegex(WebContractError, "forbidden execution feature"):
                admitted_template(contract, "owned-read")

    def test_signed_workflow_replays_and_evidence_is_machine_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = self.initialize_campaign(root)
            contract_path = campaign / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=True), indent=2) + "\n"
            )
            workflow_path = campaign / "web" / "tenant-workflow.json"
            workflow_path.write_text(json.dumps(workflow_value(), indent=2) + "\n")
            heldout_path = root / "evaluator-heldout.json"
            heldout_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "evaluationId": "owned-web-oracle-evaluation",
                        "contractSha256": WebCampaignContract.load(contract_path).digest,
                        "minimumPrecision": 1.0,
                        "minimumRecall": 1.0,
                        "cases": [
                            {
                                "workflowId": "owned-tenant-isolation",
                                "oracleId": "tenant-isolation",
                                "expectedOutcome": "confirmed-invariant-disagreement",
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            enrollment_path = (
                campaign / "evidence" / "web" / "blind" / "enrollment.json"
            )
            enrollment = enroll(
                campaign, contract_path, heldout_path, enrollment_path
            )
            self.assertEqual(enrollment["caseCount"], 1)
            signature = workflow_path.with_suffix(".json.sig")
            approval = approve(campaign, contract_path, workflow_path, signature)
            self.assertTrue(approval["approved"])
            verification = verify(campaign, contract_path, workflow_path, signature)
            self.assertTrue(verification["passed"], verification)

            environment = dict(os.environ)
            environment["KRINEON_SECRET_USER_A"] = "token-a"
            environment["KRINEON_SECRET_USER_B"] = "token-b"
            outputs: list[Path] = []
            for index in range(2):
                output = campaign / "evidence" / "web" / f"run-{index + 1}"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(WEB_BROKER),
                        str(campaign),
                        str(contract_path),
                        str(workflow_path),
                        "--signature",
                        str(signature),
                        "--output",
                        str(output),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                )
                outputs.append(output)

            self.assertEqual(OwnedFixtureHandler.requests_seen, 8)
            observations = [
                json.loads((output / "observation.json").read_text()) for output in outputs
            ]
            self.assertNotEqual(observations[0]["runId"], observations[1]["runId"])
            self.assertTrue(observations[0]["securityInvariantDisagreement"])
            self.assertEqual(
                observations[0]["oracleResults"][0]["outcome"],
                "confirmed-invariant-disagreement",
            )
            typed_contract = admit_contract(
                campaign,
                {
                    "schemaVersion": 1,
                    "kind": "web-typed",
                    "id": "owned-tenant-typed-oracle",
                    "contractType": "workflow-sequence",
                    "registeredRunner": "krineon-http-broker-v1",
                    "prerequisiteVersion": "owned-fixture-prerequisite-v1",
                    "workflowBinding": {
                        "workflow": workflow_path.relative_to(campaign).as_posix(),
                        "signature": signature.relative_to(campaign).as_posix(),
                        "campaignContract": contract_path.relative_to(campaign).as_posix(),
                        "workflowSha256": hashlib.sha256(
                            workflow_path.read_bytes()
                        ).hexdigest(),
                    },
                    "approvedActionSequence": [
                        "baseline-a",
                        "baseline-b",
                        "negative-b",
                        "attack-b",
                    ],
                    "actorFixtures": ["user-a", "user-b", "anonymous"],
                    "resourceFixtures": ["tenant-a", "tenant-b"],
                    "secretReferences": ["secret://user-a", "secret://user-b"],
                    "budgets": {
                        "maxOperations": 4,
                        "maxRequests": 4,
                        "maxEffects": 0,
                        "maxWallSeconds": 60,
                        "cleanupReservedRequests": 0,
                    },
                    "cases": [
                        {
                            "id": "owner-baseline",
                            "role": "baseline",
                            "steps": ["baseline-a", "baseline-b"],
                        },
                        {
                            "id": "anonymous-negative",
                            "role": "enforcing-negative",
                            "steps": ["negative-b"],
                        },
                        {
                            "id": "cross-tenant-positive",
                            "role": "positive",
                            "steps": ["attack-b"],
                        },
                    ],
                    "assertion": {
                        "engine": "krineon-web-oracle-v1",
                        "oracleId": "tenant-isolation",
                    },
                    "cleanup": {
                        "required": False,
                        "steps": [],
                        "successPredicate": "read-only workflow leaves no state",
                    },
                    "independentReplay": {
                        "freshIdentityRequired": True,
                        "freshResourceRequired": True,
                        "prerequisites": ["fresh owned fixture process"],
                    },
                    "evidenceOutputs": [
                        "observation.json",
                        "budget-ledger.json",
                    ],
                    "causalModel": {
                        "kind": "isolated-variable",
                        "variable": "request identity",
                    },
                    "experimentalScope": {
                        "mechanism": "tenant-route-resource-selection",
                        "relevantInputs": ["identity", "tenant route"],
                        "configuration": ["owned HTTP fixture"],
                        "state": ["tenant-b record owned by user-b"],
                        "prerequisiteVersion": "owned-fixture-prerequisite-v1",
                    },
                },
            )
            typed_result = evaluate_contract(typed_contract, observations[0])
            self.assertEqual(typed_result["outcome"], "confirmed-disagreement")
            self.assertTrue(typed_result["promotionEligible"])
            private = json.loads((outputs[0] / "private-evidence.json").read_text())
            private_text = json.dumps(private)
            self.assertNotIn("token-a", private_text)
            self.assertNotIn("token-b", private_text)
            self.assertIn("<redacted>", private_text)

            for output in outputs:
                passed, errors, _ = verified_web_observation(
                    campaign,
                    contract_path=contract_path,
                    workflow_path=workflow_path,
                    workflow_signature=signature,
                    observation_path=output / "observation.json",
                    observation_signature=output / "observation.json.sig",
                    budget_ledger_path=output / "budget-ledger.json",
                )
                self.assertTrue(passed, errors)

            manifest_path = campaign / "evidence" / "web" / "blind" / "runs.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "runs": [
                            {
                                "contract": "web-campaign.json",
                                "workflow": "web/tenant-workflow.json",
                                "workflowSignature": "web/tenant-workflow.json.sig",
                                "observation": "evidence/web/run-1/observation.json",
                                "observationSignature": "evidence/web/run-1/observation.json.sig",
                                "budgetLedger": "evidence/web/run-1/budget-ledger.json",
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            score_path = campaign / "evidence" / "web" / "blind" / "score.json"
            evaluation = score(
                campaign,
                contract_path,
                heldout_path,
                enrollment_path,
                manifest_path,
                score_path,
            )
            self.assertTrue(evaluation["passed"], evaluation)
            self.assertEqual(evaluation["precision"], 1.0)
            self.assertEqual(evaluation["recall"], 1.0)
            self.assertTrue(score_path.with_suffix(".json.sig").is_file())

            finding = {
                "id": "FWEB",
                "rootCause": "The owned fixture authorizes by route but not resource tenant.",
                "impact": "An owned tenant A identity reads an owned tenant B record.",
                "impactClass": "cross-tenant-access",
                "availabilityOnly": False,
                "preconditions": ["two owned tenant identities"],
                "evidence": ["signed broker observation"],
                "securityInvariant": {
                    "expected": "tenant A cannot read tenant B",
                    "observed": "tenant A received tenant B's record",
                    "actor": "owned user-a",
                    "resource": "owned tenant-b record",
                    "identityBoundary": "tenant-a to tenant-b",
                    "unauthorizedEffect": "protected record read",
                },
                "chain": {
                    "attacker": "authenticated low-privilege user",
                    "ingress": "GET /tenant-b",
                    "attackerControl": "owned bearer identity",
                    "transformations": ["route to tenant record"],
                    "brokenInvariant": "tenant isolation",
                    "primitive": "cross-tenant read",
                    "terminal": "protected data disclosure",
                    "deployment": "owned supported fixture",
                    "applicationAuthoredSink": True,
                },
                "controls": {
                    "baseline": "user-a reads tenant-a",
                    "negative": "anonymous request is denied",
                    "positive": "user-a reads tenant-b",
                },
                "webEvidence": {
                    "contract": "web-campaign.json",
                    "workflow": "web/tenant-workflow.json",
                    "workflowSignature": "web/tenant-workflow.json.sig",
                    "observation": "evidence/web/run-1/observation.json",
                    "observationSignature": "evidence/web/run-1/observation.json.sig",
                    "budgetLedger": "evidence/web/run-1/budget-ledger.json",
                },
                "gates": {name: True for name in WEB_CANDIDATE_GATES},
            }
            gate = web_gate_result(
                finding,
                "candidate",
                replay_verified=False,
                campaign_root_path=campaign,
            )
            self.assertTrue(gate["passed"], gate)
            finding["gates"] = {name: True for name in WEB_REPORTABLE_GATES}
            finding["originator"] = "agent-web-originator"
            finding["severityAssessment"] = {
                "band": "High",
                "justification": "verified cross-tenant protected-data disclosure",
                "programMinimum": "High",
                "programRule": "program accepts High and Critical web findings",
            }
            reportable = web_gate_result(
                finding,
                "reportable",
                replay_verified=True,
                campaign_root_path=campaign,
            )
            self.assertTrue(reportable["passed"], reportable)
            finding["severityAssessment"]["band"] = "Medium"
            medium = web_gate_result(
                finding,
                "reportable",
                replay_verified=True,
                campaign_root_path=campaign,
            )
            self.assertFalse(medium["passed"])
            self.assertIn(
                "severityAssessment.band:High-or-Critical", medium["missingFields"]
            )
            finding["severityAssessment"]["band"] = "High"
            finding["availabilityOnly"] = True
            rejected = web_gate_result(
                finding,
                "candidate",
                replay_verified=False,
                campaign_root_path=campaign,
            )
            self.assertFalse(rejected["passed"])
            self.assertIn("availabilityOnly:false", rejected["missingFields"])

            tampered = json.loads((outputs[0] / "budget-ledger.json").read_text())
            tampered["requests"] += 1
            (outputs[0] / "budget-ledger.json").write_text(
                json.dumps(tampered, indent=2) + "\n"
            )
            passed, errors, _ = verified_web_observation(
                campaign,
                contract_path=contract_path,
                workflow_path=workflow_path,
                workflow_signature=signature,
                observation_path=outputs[0] / "observation.json",
                observation_signature=outputs[0] / "observation.json.sig",
                budget_ledger_path=outputs[0] / "budget-ledger.json",
            )
            self.assertFalse(passed)
            self.assertIn("observation:budget-ledger-hash", errors)

    def test_execution_lease_and_remote_browser_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lease_path = root / "execution.lock"
            first = ExecutionLease(lease_path, "one")
            second = ExecutionLease(lease_path, "two")
            first.acquire()
            try:
                with self.assertRaisesRegex(WebContractError, "execution lease"):
                    second.acquire()
            finally:
                first.release()

            remote = contract_value("https://example.test", confirmed=True)
            remote["authorization"]["allowBrowserNavigation"] = True
            contract_path = root / "remote.json"
            contract_path.write_text(json.dumps(remote, indent=2) + "\n")
            contract = WebCampaignContract.load(contract_path)
            workflow = workflow_value()
            step = workflow["steps"][0]
            step["type"] = "browser"
            step["path"] = "/"
            with self.assertRaisesRegex(WebContractError, "remote CDP navigation is blocked"):
                discover(
                    campaign=root,
                    binary=root / "does-not-matter",
                    contract=contract,
                    workflow=workflow,
                    step=step,
                    ledger=BudgetLedger(contract, root / "remote-ledger.json"),
                    output=root / "browser-output",
                    timeout=1,
                )

    def test_remote_browser_requires_broker_and_actions_are_explicitly_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = contract_value("https://example.test", confirmed=True)
            remote["origins"][0]["allowedMethods"].append("POST")
            remote["authorization"].update(
                {
                    "allowBrowserNavigation": True,
                    "allowBrowserActions": True,
                    "allowStateChangingOperations": True,
                }
            )
            remote["effectClasses"]["disposable-write"]["permitted"] = True
            remote["actionPolicies"].append(
                {
                    "id": "owned-browser-write",
                    "originId": "app",
                    "pathPrefix": "/owned-submit",
                    "methods": ["POST"],
                    "effectClasses": ["disposable-write"],
                    "maxRequestBodyBytes": 4096,
                    "maxResponseBodyBytes": 16384,
                }
            )
            remote["networkContainment"].update(
                {
                    "remoteBrowserTraffic": "os-egress-enforced",
                    "evidence": {"namespace": "owned-browser-netns"},
                    "browserBroker": {
                        "mode": "os-enforced-broker-only",
                        "proxyUrl": "http://127.0.0.1:18080",
                        "brokerId": "owned-browser-broker",
                        "brokerVersion": "fixture-v1",
                        "directEgressBlocked": True,
                        "dnsOutsideBrokerBlocked": True,
                        "allowedOriginIds": ["app"],
                        "evidence": ["evidence/browser-netns.json"],
                    },
                }
            )
            contract_path = root / "remote.json"
            contract_path.write_text(json.dumps(remote, indent=2) + "\n")
            contract = WebCampaignContract.load(contract_path)
            flags = browser_network_flags(
                loopback_target=False,
                broker=remote["networkContainment"]["browserBroker"],
            )
            self.assertIn("--proxy-server=http://127.0.0.1:18080", flags)
            self.assertIn("--proxy-bypass-list=<-loopback>", flags)
            self.assertFalse(any("example.test" in flag for flag in flags))
            workflow = workflow_value()
            step = workflow["steps"][0]
            step.update(
                {
                    "type": "browser",
                    "identityId": "anonymous",
                    "session": "anonymous",
                    "path": "/",
                    "operationClass": "browser-action",
                    "browserActions": [
                        {
                            "id": "owned-submit",
                            "type": "click",
                            "selector": "#owned-submit",
                            "expectedRequests": [
                                {
                                    "originId": "app",
                                    "pathPrefix": "/owned-submit",
                                    "method": "POST",
                                    "effectClass": "disposable-write",
                                    "maxCount": 1,
                                }
                            ],
                        }
                    ],
                }
            )
            # A state-changing browser step needs an explicit compensating step.
            cleanup = dict(workflow["cleanupSteps"][0]) if workflow["cleanupSteps"] else None
            if cleanup is None:
                cleanup = dict(step)
                cleanup.update(
                    {
                        "id": "owned-submit-cleanup",
                        "type": "http",
                        "method": "POST",
                        "path": "/owned-submit",
                        "operationClass": "ordinary-http",
                        "effectClass": "disposable-write",
                        "browserActions": [],
                    }
                )
                workflow["cleanupSteps"] = [cleanup]
            validate_workflow(workflow, contract, dynamic=False)
            with self.assertRaisesRegex(WebContractError, "Chromium binary does not exist"):
                discover(
                    campaign=root,
                    binary=root / "missing-chrome",
                    contract=contract,
                    workflow=workflow,
                    step=step,
                    ledger=BudgetLedger(contract, root / "remote-ledger.json"),
                    output=root / "browser-output",
                    timeout=1,
                )

            invalid = json.loads(json.dumps(remote))
            invalid["networkContainment"]["browserBroker"]["proxyUrl"] = "https://proxy.example.test:443"
            invalid_path = root / "invalid-remote.json"
            invalid_path.write_text(json.dumps(invalid, indent=2) + "\n")
            with self.assertRaisesRegex(WebContractError, "explicit loopback proxy"):
                WebCampaignContract.load(invalid_path)

    def test_blind_discovery_derives_authorization_hypothesis_without_prepared_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = self.initialize_campaign(root)
            contract_path = campaign / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=True), indent=2) + "\n"
            )
            observations = {
                "schemaVersion": 1,
                "kind": "krineon-web-blind-observations",
                "prerequisiteVersion": "owned-fixture-v1",
                "observations": [
                    {
                        "id": "owner-reads-b",
                        "actorRef": "user-b",
                        "actorTenant": "tenant-b",
                        "resourceRef": "record-b",
                        "resourceOwnerRef": "user-b",
                        "resourceTenant": "tenant-b",
                        "action": "read-private-record",
                        "outcome": "allowed",
                        "securityRelevantSha256": "sha256:owned-b",
                        "resourceVisibility": "private",
                        "authoritative": True,
                        "ownedFixture": True,
                        "evidenceRef": "evidence/owner-b.json",
                    },
                    {
                        "id": "a-reads-a",
                        "actorRef": "user-a",
                        "actorTenant": "tenant-a",
                        "resourceRef": "record-a",
                        "resourceOwnerRef": "user-a",
                        "resourceTenant": "tenant-a",
                        "action": "read-private-record",
                        "outcome": "allowed",
                        "securityRelevantSha256": "sha256:owned-a",
                        "resourceVisibility": "private",
                        "authoritative": True,
                        "ownedFixture": True,
                        "evidenceRef": "evidence/owner-a.json",
                    },
                    {
                        "id": "a-reads-b",
                        "actorRef": "user-a",
                        "actorTenant": "tenant-a",
                        "resourceRef": "record-b",
                        "resourceOwnerRef": "user-b",
                        "resourceTenant": "tenant-b",
                        "action": "read-private-record",
                        "outcome": "allowed",
                        "securityRelevantSha256": "sha256:owned-b",
                        "resourceVisibility": "private",
                        "authoritative": True,
                        "ownedFixture": True,
                        "evidenceRef": "evidence/cross-owner.json",
                    },
                ],
            }
            observations_path = campaign / "evidence" / "blind-observations.json"
            observations_path.parent.mkdir(parents=True, exist_ok=True)
            observations_path.write_text(json.dumps(observations, indent=2) + "\n")
            discovery_path = campaign / "evidence" / "autonomous-discovery.json"
            result = blind_discover(campaign, contract_path, observations_path, discovery_path)
            self.assertFalse(result["preparedHypothesisUsed"])
            self.assertFalse(result["preparedWorkflowUsed"])
            self.assertFalse(result["preparedOracleUsed"])
            self.assertEqual(result["candidateCount"], 1)

            heldout_path = root / "heldout-discovery.json"
            heldout_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "evaluationId": "owned-autonomous-discovery",
                        "evaluationMode": "autonomous-discovery",
                        "contractSha256": WebCampaignContract.load(contract_path).digest,
                        "minimumPrecision": 1.0,
                        "minimumRecall": 1.0,
                        "cases": [
                            {
                                "mechanismFingerprint": mechanism_fingerprint(
                                    "object-authorization", "read-private-record"
                                ),
                                "expectedOutcome": "confirmed-invariant-disagreement",
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            enrollment_path = campaign / "evidence" / "blind-enrollment.json"
            enroll(campaign, contract_path, heldout_path, enrollment_path)
            score_path = campaign / "evidence" / "blind-score.json"
            evaluation = score_discovery(
                campaign,
                contract_path,
                heldout_path,
                enrollment_path,
                discovery_path,
                score_path,
            )
            self.assertTrue(evaluation["passed"], evaluation)
            self.assertEqual(evaluation["precision"], 1.0)
            self.assertEqual(evaluation["recall"], 1.0)

    def test_business_sequence_executes_signed_multi_actor_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = self.initialize_campaign(root)
            contract_path = campaign / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value(self.origin, confirmed=True), indent=2) + "\n"
            )
            workflow_path = campaign / "web" / "tenant-workflow.json"
            workflow_path.write_text(json.dumps(workflow_value(), indent=2) + "\n")
            signature = workflow_path.with_suffix(".json.sig")
            approve(campaign, contract_path, workflow_path, signature)
            signed_workflow = load_object(workflow_path)
            state_oracle = {
                "schemaVersion": 1,
                "id": "owned-record-isolation",
                "family": "object-authorization",
                "claim": "user A cannot read user B's private record",
                "ruleBasis": "owned fixture tenant-isolation rule",
                "ruleBasisConfidence": "owner-specified",
                "prerequisiteVersion": "owned-fixture-prerequisite-v1",
                "consistencyWindowSeconds": 0,
                "requiredObservations": [
                    "owner-readback",
                    "other-owner-readback",
                    "anonymous-negative-readback",
                    "cross-owner-readback",
                ],
                "terminalObservations": ["cross-owner-readback"],
                "assertions": [
                    {
                        "id": "owner-control",
                        "role": "baseline-control",
                        "operator": "equals",
                        "left": {
                            "observation": "other-owner-readback",
                            "field": "state.status",
                        },
                        "right": {"literal": 200},
                        "expected": True,
                    },
                    {
                        "id": "anonymous-control",
                        "role": "enforcing-negative",
                        "operator": "equals",
                        "left": {
                            "observation": "anonymous-negative-readback",
                            "field": "state.status",
                        },
                        "right": {"literal": 403},
                        "expected": True,
                    },
                    {
                        "id": "cross-owner-isolation",
                        "role": "positive-invariant",
                        "operator": "equals",
                        "left": {
                            "observation": "cross-owner-readback",
                            "field": "state.status",
                        },
                        "right": {"literal": 403},
                        "expected": True,
                    },
                ],
            }
            business = compile_business_logic(
                {
                    "kind": "krineon-web-workflow-model",
                    "identityModel": [{"id": "user-a"}, {"id": "user-b"}],
                    "resourceModel": [{"id": "tenant-a"}, {"id": "tenant-b"}],
                    "workflowModel": [],
                },
                {
                    "schemaVersion": 1,
                    "prerequisiteVersion": "owned-fixture-prerequisite-v1",
                    "rules": [
                        {
                            "id": "tenant-record-owner-rule",
                            "title": "Private tenant records remain owner-bound",
                            "family": "object-authorization",
                            "statement": "only the tenant owner can read its private record",
                            "basis": "owned fixture policy",
                            "basisConfidence": "owner-specified",
                            "attackerStartingAuthority": "ordinary user-a member",
                            "actors": ["user-a", "user-b"],
                            "resources": ["tenant-a", "tenant-b"],
                            "normalWorkflow": [
                                "baseline-a",
                                "baseline-b",
                                "negative-b",
                            ],
                            "counterfactual": [
                                "baseline-a",
                                "baseline-b",
                                "negative-b",
                                "attack-b",
                            ],
                            "fixture": {
                                "owned": True,
                                "namespace": "krineon-web-test",
                                "irreversible": False,
                                "disposable": True,
                                "factoryRef": "fixture:create-tenant-pair",
                                "readbackRef": "fixture:read-tenant-record",
                                "cleanupRef": "fixture:reset-tenant-pair",
                                "version": "fixture-v1",
                            },
                            "stateOracle": state_oracle,
                        }
                    ],
                },
            )
            graph = build_graph(signed_workflow, business)
            plan_id = graph["plans"][0]["id"]
            output = campaign / "evidence" / "web" / "business-sequence"
            before = OwnedFixtureHandler.requests_seen
            with mock.patch.dict(
                os.environ,
                {
                    "KRINEON_SECRET_USER_A": "token-a",
                    "KRINEON_SECRET_USER_B": "token-b",
                },
                clear=False,
            ):
                result = execute_plan(
                    campaign,
                    graph,
                    plan_id,
                    "counterfactual",
                    output,
                )
            self.assertEqual(OwnedFixtureHandler.requests_seen - before, 4)
            self.assertEqual(result["oracleResult"]["outcome"], "confirmed-disagreement")
            self.assertEqual(
                result["state"]["actors"]["user-a"]["effectiveActor"], "user-a"
            )
            self.assertTrue(result["cleanupComplete"])
            tampered = json.loads(json.dumps(graph))
            tampered["operations"][0]["cost"]["maxRequests"] = 2
            request_count = OwnedFixtureHandler.requests_seen
            with self.assertRaisesRegex(WebContractError, "coordinator-signed workflow"):
                execute_plan(
                    campaign,
                    tampered,
                    plan_id,
                    "counterfactual",
                    campaign / "evidence" / "web" / "tampered-business-sequence",
                )
            self.assertEqual(OwnedFixtureHandler.requests_seen, request_count)

    def test_approved_bounded_pair_uses_shared_budget_and_defers_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = self.initialize_campaign(root)
            contract_value_document = contract_value(self.origin, confirmed=True)
            contract_value_document["origins"][0]["allowedMethods"] = [
                "GET",
                "HEAD",
                "POST",
            ]
            contract_value_document["origins"][0]["maxConcurrentRequests"] = 2
            contract_value_document["effectClasses"]["disposable-write"][
                "permitted"
            ] = True
            contract_value_document["authorization"].update(
                {
                    "allowStateChangingOperations": True,
                    "allowBoundedConcurrency": True,
                    "boundedRaceApproval": {
                        "approved": True,
                        "disposableFixture": "krineon-race-fixture",
                        "maxParticipants": 2,
                        "availabilityObjective": False,
                    },
                }
            )
            contract_value_document["budget"]["maxConcurrentRequests"] = 2
            contract_value_document["actionPolicies"] = [
                {
                    "id": "owned-race",
                    "originId": "app",
                    "pathPrefix": "/race",
                    "methods": ["POST"],
                    "effectClasses": ["disposable-write"],
                    "maxRequestBodyBytes": 4096,
                    "maxResponseBodyBytes": 16384,
                }
            ]
            contract_path = campaign / "web-campaign.json"
            contract_path.write_text(
                json.dumps(contract_value_document, indent=2) + "\n"
            )

            def race_operation(actor: str, operation_id: str) -> dict[str, object]:
                return {
                    "id": operation_id,
                    "actorRef": {
                        "id": actor,
                        "role": "member",
                        "tenant": "owned-race",
                        "session": "session-a" if actor == "user-a" else "session-b",
                        "verified": True,
                        "effectiveActor": actor,
                        "capabilityVersion": "owned-race-identities-v1",
                    },
                    "actionRef": {
                        "runner": "krineon-http-broker-v1",
                        "workflow": f"web/{operation_id}.json",
                        "signature": f"web/{operation_id}.json.sig",
                        "campaignContract": "web-campaign.json",
                        "workflowId": f"workflow-{operation_id}",
                        "stepId": operation_id,
                        "effectClass": "disposable-write",
                    },
                    "resourceBindings": [
                        {
                            "id": "owned-race-resource",
                            "kind": "once-only-fixture",
                            "parent": "owned-root",
                            "tenant": "owned-race",
                            "owner": "owned-race",
                            "version": "v1",
                            "generation": "g1",
                            "fixtureNamespace": "krineon-race-fixture",
                            "owned": True,
                            "disposable": True,
                        }
                    ],
                    "requires": {
                        "operator": "fact",
                        "type": "state",
                        "ref": "race-not-started",
                        "expected": False,
                        "evidence": [],
                    },
                    "produces": [],
                    "consumes": [],
                    "invalidates": [],
                    "authorityBinding": {
                        "actor": actor,
                        "resource": "owned-race-resource",
                        "action": "bounded-write",
                        "version": "v1",
                    },
                    "ordering": {
                        "after": [],
                        "before": [],
                        "asyncBoundary": True,
                        "sequencingHintOnly": False,
                        "dependencyConfidence": "replay-confirmed",
                        "evidence": ["owner-approved paired fixture"],
                    },
                    "observations": [
                        {
                            "id": f"{operation_id}-readback",
                            "kind": "authoritative-readback",
                            "authoritative": True,
                            "evidenceOrigin": "server-response",
                            "resourceBindingRef": "owned-race-resource",
                            "stateSelectors": {"status": "response.status"},
                        }
                    ],
                    "consistencyWindow": {
                        "basis": "synchronous owned race fixture",
                        "maximumSeconds": 0,
                    },
                    "cleanup": {
                        "hookRef": f"workflow-{operation_id}:cleanup-{operation_id}",
                        "irreversible": False,
                    },
                    "cost": {
                        "maxRequests": 2,
                        "maxSteps": 2,
                        "maxBytes": 32768,
                        "maxPolling": 0,
                        "maxEffects": 2,
                        "maxConcurrencyParticipants": 2,
                    },
                }

            baseline_operation = race_operation("user-a", "race-baseline")
            baseline_operation["cost"]["maxConcurrencyParticipants"] = 1
            operations = [
                baseline_operation,
                race_operation("user-a", "race-a"),
                race_operation("user-b", "race-b"),
            ]

            def race_workflow(operation: dict[str, object]) -> dict[str, object]:
                operation_id = str(operation["id"])
                actor = str(operation["actorRef"]["id"])

                def step(step_id: str, path: str) -> dict[str, object]:
                    return {
                        "id": step_id,
                        "type": "http",
                        "originId": "app",
                        "identityId": actor,
                        "method": "POST",
                        "path": path,
                        "headers": [],
                        "effectClass": "disposable-write",
                        "operationClass": "bounded-concurrency",
                        "resource": {
                            "id": "owned-race-resource",
                            "kind": "once-only-fixture",
                            "expectedOwner": "owned-race",
                            "selectedResource": path,
                            "permittedAction": "bounded-write",
                        },
                        "intent": "bounded-once-only-invariant",
                        "observationContext": {
                            "evidenceOrigin": "owned fixture response",
                            "cacheLayer": "not-applicable",
                            "executionContext": "approved paired HTTP request",
                        },
                        "limits": {
                            "maximumEffect": "one disposable fixture transition",
                            "maxActions": 1,
                            "maxInputBytes": 4096,
                            "timeoutSeconds": 5,
                            "cleanupPlan": "reset owned race fixture",
                            "retryPolicy": "never",
                            "idempotent": False,
                        },
                        "extract": [],
                    }

                paired_member = operation["cost"]["maxConcurrencyParticipants"] == 2
                main = step(operation_id, "/race" if paired_member else "/race/reset")
                cleanup = step(f"cleanup-{operation_id}", "/race/reset")
                main["operationClass"] = (
                    "bounded-concurrency" if paired_member else "ordinary-http"
                )
                cleanup["operationClass"] = main["operationClass"]
                expected_status = 209 if paired_member else 200
                oracle = {
                    "schemaVersion": 1,
                    "id": f"oracle-{operation_id}",
                    "kind": "business-invariant",
                    "claim": "the approved pair reached the synchronized fixture",
                    "requiredObservations": [
                        {"step": operation_id, "field": "response.status"}
                    ],
                    "assertions": [
                        {
                            "id": "baseline",
                            "role": "baseline-control",
                            "operator": "equals",
                            "left": {"step": operation_id, "field": "response.status"},
                            "right": {"literal": expected_status},
                            "expected": True,
                        },
                        {
                            "id": "negative",
                            "role": "enforcing-negative",
                            "operator": "equals",
                            "left": {"step": operation_id, "field": "response.status"},
                            "right": {"literal": expected_status},
                            "expected": True,
                        },
                        {
                            "id": "positive",
                            "role": "positive-invariant",
                            "operator": "equals",
                            "left": {"step": operation_id, "field": "response.status"},
                            "right": {"literal": expected_status},
                            "expected": True,
                        },
                    ],
                    "inconclusiveWhenMissing": True,
                }
                return {
                    "schemaVersion": 1,
                    "prerequisiteVersion": "owned-race-prerequisite-v1",
                    "id": f"workflow-{operation_id}",
                    "title": f"Approved bounded pair member {operation_id}",
                    "hypothesis": "Two admitted operations overlap on the owned fixture.",
                    "competingExplanations": [
                        {
                            "id": "H1",
                            "statement": "The paired broker synchronized both operations.",
                            "expectedObservations": ["HTTP 209"],
                        },
                        {
                            "id": "H2",
                            "statement": "The operations executed sequentially.",
                            "expectedObservations": ["HTTP 200"],
                        },
                    ],
                    "changedVariable": "paired dispatch",
                    "steps": [main],
                    "operationContracts": [operation],
                    "oracles": [oracle],
                    "cleanupSteps": [cleanup],
                    "coordinatorApproval": {
                        "approved": False,
                        "approvedBy": "",
                        "approvedAt": None,
                        "contractSha256": "",
                    },
                }

            for operation in operations:
                workflow_path = campaign / str(operation["actionRef"]["workflow"])
                workflow_path.write_text(
                    json.dumps(race_workflow(operation), indent=2) + "\n"
                )
                approve(
                    campaign,
                    contract_path,
                    workflow_path,
                    workflow_path.with_suffix(".json.sig"),
                )

            state_oracle = {
                "schemaVersion": 1,
                "id": "paired-overlap",
                "family": "bounded-concurrency",
                "claim": "the approved pair overlaps on the owned disposable fixture",
                "ruleBasis": "owned fixture concurrency rule",
                "ruleBasisConfidence": "owner-specified",
                "prerequisiteVersion": "owned-race-prerequisite-v1",
                "consistencyWindowSeconds": 0,
                "requiredObservations": [
                    "race-baseline-readback",
                    "race-a-readback",
                    "race-b-readback",
                ],
                "terminalObservations": ["race-a-readback", "race-b-readback"],
                "assertions": [
                    {
                        "id": "first-overlapped",
                        "role": "baseline-control",
                        "operator": "equals",
                        "left": {
                            "observation": "race-baseline-readback",
                            "field": "state.status",
                        },
                        "right": {"literal": 200},
                        "expected": True,
                    },
                    {
                        "id": "second-overlapped",
                        "role": "enforcing-negative",
                        "operator": "equals",
                        "left": {"observation": "race-b-readback", "field": "state.status"},
                        "right": {"literal": 209},
                        "expected": True,
                    },
                    {
                        "id": "pair-is-bounded",
                        "role": "positive-invariant",
                        "operator": "equals",
                        "left": {"literal": 2},
                        "right": {"literal": 2},
                        "expected": True,
                    },
                ],
            }
            business = compile_business_logic(
                {
                    "kind": "krineon-web-workflow-model",
                    "identityModel": [{"id": "user-a"}, {"id": "user-b"}],
                    "resourceModel": [{"id": "owned-race-resource"}],
                    "workflowModel": [],
                },
                {
                    "schemaVersion": 1,
                    "prerequisiteVersion": "owned-race-prerequisite-v1",
                    "rules": [
                        {
                            "id": "owned-paired-race",
                            "title": "Owned two-participant race",
                            "family": "bounded-concurrency",
                            "statement": "only the approved staged pair may run concurrently",
                            "basis": "owned fixture policy",
                            "basisConfidence": "owner-specified",
                            "attackerStartingAuthority": "two owned member identities",
                            "actors": ["user-a", "user-b"],
                            "resources": ["owned-race-resource"],
                            "normalWorkflow": ["race-baseline"],
                            "counterfactual": [
                                "race-baseline",
                                "race-a",
                                "race-b",
                            ],
                            "pairedConcurrencyApproved": True,
                            "fixture": {
                                "owned": True,
                                "namespace": "krineon-race-fixture",
                                "irreversible": False,
                                "disposable": True,
                                "factoryRef": "fixture:reset-race",
                                "readbackRef": "fixture:race-status",
                                "cleanupRef": "fixture:reset-race",
                                "version": "race-fixture-v1",
                            },
                            "stateOracle": state_oracle,
                        }
                    ],
                },
            )
            graph = build_graph(
                {"schemaVersion": 1, "operationContracts": operations}, business
            )
            with mock.patch.dict(
                os.environ,
                {
                    "KRINEON_SECRET_USER_A": "token-a",
                    "KRINEON_SECRET_USER_B": "token-b",
                },
                clear=False,
            ):
                result = execute_plan(
                    campaign,
                    graph,
                    graph["plans"][0]["id"],
                    "counterfactual",
                    campaign / "evidence" / "web" / "bounded-pair",
                )
            self.assertTrue(OwnedFixtureHandler.race_overlap_observed)
            self.assertEqual(OwnedFixtureHandler.race_max_active, 0)
            self.assertEqual(result["oracleResult"]["outcome"], "observed-preservation")
            self.assertTrue(result["cleanupComplete"])


if __name__ == "__main__":
    unittest.main()
