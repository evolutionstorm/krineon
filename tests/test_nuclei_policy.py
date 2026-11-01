from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.ffuf_adapter import compile_plan as compile_ffuf_plan
from scripts.ffuf_adapter import import_results as import_ffuf_results
from scripts.ffuf_adapter import validate_profile as validate_ffuf_profile
from scripts.nuclei_adapter import (
    execute_replay,
    prepare_run,
    probe_engine,
    validate_replay_fixture,
    verify_replay,
)
from scripts.nuclei_template_policy import admit_templates, validate_profile
from scripts.web_contract import WebContractError
from scripts.web_nuclei_adapter import main as legacy_nuclei_main


ROOT = Path(__file__).resolve().parents[1]


def load_asset(name: str) -> dict:
    return json.loads((ROOT / "assets" / name).read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reviewed_entry(template_id: str, relative: str, digest: str, requests: int = 1) -> dict:
    return {
        "id": template_id,
        "path": relative,
        "sha256": digest,
        "expandedSha256": digest,
        "track": "first-principles",
        "provenance": "generic-invariant",
        "agentGenerated": False,
        "independentAdmissionReview": {
            "status": "confirmed",
            "reviewer": "independent-reviewer",
            "evidence": "owned review record",
        },
        "ownedFixtureExecution": {
            "status": "confirmed",
            "fixture": "owned-loopback",
            "evidence": "owned fixture record",
        },
        "approval": {
            "effect": "read-only",
            "methods": ["GET"],
            "allowedPathPrefixes": ["/fixture/canary"],
            "allowedOriginIds": ["owned-loopback-fixture"],
            "redirects": False,
            "maxRequests": requests,
            "maxRequestBytes": 0,
            "maxResponseBytes": 65536,
            "ownedFixtureNamespace": "owned-nuclei-test",
        },
    }


class NucleiAndFfufPolicyTests(unittest.TestCase):
    def test_legacy_direct_nuclei_adapter_is_fail_closed(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(legacy_nuclei_main([]), 2)

    def test_reviewed_generic_template_is_admitted(self) -> None:
        profile = load_asset("nuclei-profile.template.json")
        manifest = load_asset("nuclei-reviewed-templates.manifest.json")
        result = admit_templates(profile, manifest, ROOT)
        self.assertEqual(result["expandedRequestCount"], 1)
        self.assertEqual(result["acceptedTemplates"][0]["resultLabel"], "observation-only")
        self.assertFalse(result["businessLogicDependency"])

    def test_untagged_race_and_redirect_templates_are_rejected(self) -> None:
        for unsafe_line, expected in (
            ("    race-count: 2\n", "payload expansion"),
            ("    redirects: true\n", "redirects"),
        ):
            with self.subTest(unsafe_line=unsafe_line), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                template = root / "unsafe.yaml"
                template.write_text(
                    """id: untagged-check
info:
  name: Untagged check
  author: owned
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/fixture/canary"
"""
                    + unsafe_line,
                    encoding="utf-8",
                )
                manifest = {
                    "schemaVersion": 1,
                    "kind": "krineon-nuclei-reviewed-template-manifest",
                    "id": "owned-manifest",
                    "templateCommit": "owned-v1",
                    "reviewPolicy": "complete-expanded-template",
                    "templates": [reviewed_entry("untagged-check", "unsafe.yaml", sha(template))],
                }
                profile = load_asset("nuclei-profile.template.json")
                profile["selectedTemplateIds"] = ["untagged-check"]
                with self.assertRaisesRegex(WebContractError, expected):
                    admit_templates(profile, manifest, root)

    def test_implicit_download_or_cloud_configuration_is_refused(self) -> None:
        profile = load_asset("nuclei-profile.template.json")
        profile["effectiveConfiguration"]["remoteTemplateDownloads"] = True
        with self.assertRaisesRegex(WebContractError, "remoteTemplateDownloads"):
            validate_profile(profile)
        profile = load_asset("nuclei-profile.template.json")
        profile["effectiveConfiguration"]["cloudUpload"] = True
        with self.assertRaisesRegex(WebContractError, "cloudUpload"):
            validate_profile(profile)

    def test_broker_bypass_is_refused_before_scanner_execution(self) -> None:
        plan = {
            "kind": "krineon-nuclei-run-plan",
            "engine": {"binarySha256": "a" * 64},
            "admission": {"acceptedTemplates": []},
        }
        fixture = load_asset("nuclei-broker-replay.template.json")
        fixture["targetTrafficAcquiredBy"] = "nuclei-direct"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(WebContractError, "broker"):
                validate_replay_fixture(fixture, plan, evidence_root=Path(directory))

    def test_owned_authenticated_broker_replay_and_independent_semantic_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = root / "fake-nuclei.py"
            engine.write_text(
                """#!/usr/bin/env python3
import json, pathlib, sys, urllib.request
if '-version' in sys.argv or '--version' in sys.argv:
    print('fake-nuclei 1.0')
    raise SystemExit(0)
if '-h' in sys.argv or '--help' in sys.argv:
    print('\\n'.join(['-disable-update-check','-disable-redirects','-jsonl','-no-interactsh','-rate-limit','-bulk-size','-concurrency','-retries','-output','-templates','-target','-max-redirects','-no-color']))
    raise SystemExit(0)
output_flag = '-output' if '-output' in sys.argv else '-o'
output = pathlib.Path(sys.argv[sys.argv.index(output_flag) + 1])
target_flag = '-target' if '-target' in sys.argv else '-u'
target = sys.argv[sys.argv.index(target_flag) + 1]
with urllib.request.urlopen(target + '/fixture/canary', timeout=2) as response:
    body = response.read()
if body != b'KRINEON_OWNED_CANARY':
    raise SystemExit('owned replay canary did not match')
output.write_text(json.dumps({'template-id':'krineon-owned-canary','matched-at':'http://127.0.0.1/fixture/canary','request':'SECRET','response':'KRINEON_OWNED_CANARY'}) + '\\n')
""",
                encoding="utf-8",
            )
            engine.chmod(0o700)
            probe = probe_engine(engine)
            profile = load_asset("nuclei-profile.template.json")
            profile["id"] = "owned-nuclei-profile"
            profile["engine"].update(
                {
                    "path": str(engine),
                    "sha256": probe["binarySha256"],
                    "versionOutputSha256": probe["versionOutputSha256"],
                    "helpOutputSha256": probe["helpOutputSha256"],
                }
            )
            manifest_path = ROOT / "assets" / "nuclei-reviewed-templates.manifest.json"
            profile["templateManifest"]["sha256"] = sha(manifest_path)
            manifest = load_asset("nuclei-reviewed-templates.manifest.json")
            plan = prepare_run(
                profile,
                manifest,
                probe,
                root=ROOT,
                manifest_path=manifest_path,
            )
            launcher = root / "sandbox-launcher.py"
            launcher.write_text(
                """#!/usr/bin/env python3
import os, sys
index = sys.argv.index('--')
command = sys.argv[index + 1:]
target = command[command.index('-target') + 1]
assert target.startswith('http://127.0.0.1:')
for flag in ('-disable-update-check','-disable-redirects','-no-interactsh'):
    assert flag in command
os.execv(command[0], command)
""",
                encoding="utf-8",
            )
            launcher.chmod(0o700)
            evidence = root / "nuclei-sandbox-proof.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "kind": "krineon-nuclei-containment-evidence",
                        "executedBy": "krineon-coordinator",
                        "engineSha256": probe["binarySha256"],
                        "loopbackReplayReachable": True,
                        "alternateEngineEgressBlocked": True,
                        "updatesAndUploadsBlocked": True,
                    }
                ),
                encoding="utf-8",
            )
            fixture = load_asset("nuclei-broker-replay.template.json")
            fixture["containment"].update(
                {
                    "engineSha256": probe["binarySha256"],
                    "evidence": [{"path": evidence.name, "sha256": sha(evidence)}],
                    "launcher": {
                        "path": str(launcher),
                        "sha256": sha(launcher),
                        "interface": "argv-prefix-double-dash",
                        "arguments": [],
                    },
                }
            )
            fixture["routes"][0].update(
                {
                    "bodyBase64": base64.b64encode(b"KRINEON_OWNED_CANARY").decode(),
                    "brokerObservationSha256": "b" * 64,
                    "identityBindingVersion": "owned-user-a-v1",
                }
            )
            output = root / "result"
            result = execute_replay(
                plan,
                fixture,
                root=ROOT,
                evidence_root=root,
                output=output,
            )
            self.assertEqual(len(result["matchIds"]), 1)
            self.assertEqual(result["brokerTargetRequestsCharged"], 1)
            self.assertEqual(result["loopbackReplayRequestsCharged"], 1)
            observation = result["observations"][0]
            self.assertNotIn("request", observation)
            self.assertNotIn("response", observation)
            self.assertTrue(observation["semanticReplayRequired"])
            replay = {
                "schemaVersion": 1,
                "kind": "krineon-nuclei-semantic-replay",
                "results": [
                    {
                        "matchId": result["matchIds"][0],
                        "runner": "krineon-http-broker",
                        "independentIdentity": True,
                        "oracleOutcome": "confirmed-disagreement",
                    }
                ],
            }
            verdict = verify_replay(result, replay)
            self.assertEqual(
                verdict["confirmedInvariantBreakMatchIds"], result["matchIds"]
            )
            self.assertFalse(verdict["matchesPromotedDirectly"])

    def test_ffuf_candidates_are_bounded_and_results_remain_observations(self) -> None:
        profile = load_asset("ffuf-profile.template.json")
        profile["id"] = "owned-ffuf-profile"
        profile["prerequisiteVersion"] = "fixture-v1"
        plan = compile_ffuf_plan(profile)
        self.assertEqual(plan["preflight"]["maximumRequests"], 1)
        result = import_ffuf_results(
            plan,
            {
                "schemaVersion": 1,
                "kind": "krineon-ffuf-broker-results",
                "prerequisiteVersion": "fixture-v1",
                "executedBy": "krineon-web-broker",
                "workflowCoverageBefore": 1,
                "workflowCoverageAfter": 2,
                "observations": [
                    {
                        "candidateId": "observed-sibling-operation",
                        "accessState": "application-response",
                        "status": 200,
                        "bodySha256": "c" * 64,
                        "confounders": ["soft-404"],
                    }
                ],
            },
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["observations"][0]["classification"], "endpoint-observation")
        self.assertFalse(result["stopExpansion"])
        profile["recursion"] = True
        with self.assertRaisesRegex(WebContractError, "recursion"):
            validate_ffuf_profile(profile)

    def test_ffuf_stops_on_bot_or_rate_limit(self) -> None:
        profile = load_asset("ffuf-profile.template.json")
        profile["prerequisiteVersion"] = "fixture-v1"
        plan = compile_ffuf_plan(profile)
        result = import_ffuf_results(
            plan,
            {
                "schemaVersion": 1,
                "kind": "krineon-ffuf-broker-results",
                "prerequisiteVersion": "fixture-v1",
                "executedBy": "krineon-web-broker",
                "workflowCoverageBefore": 1,
                "workflowCoverageAfter": 1,
                "observations": [
                    {
                        "candidateId": "observed-sibling-operation",
                        "accessState": "environment-blocked",
                    }
                ],
            },
        )
        self.assertEqual(result["outcome"], "environment-blocked")
        self.assertTrue(result["stopExpansion"])


if __name__ == "__main__":
    unittest.main()
