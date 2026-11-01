from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_contract import WebContractError
from scripts.web_policy import classify_access_response, validate_http_replay_headers
from scripts.web_surface_map import build_surface_map
from scripts.web_workflow_model import build_workflow_model


def request(
    request_id: str,
    actor: str,
    method: str,
    path: str,
    *,
    dependencies: list[str],
) -> dict[str, object]:
    return {
        "id": request_id,
        "identityId": actor,
        "workflowId": "project-lifecycle",
        "effectClass": "read-only" if method == "GET" else "disposable-write",
        "resource": {
            "id": "project-a",
            "kind": "project",
            "expectedOwner": "user-a",
        },
        "expectedRule": "only the project owner may read or mutate the project",
        "dependsOn": dependencies,
        "request": {
            "protocol": "http/1.1",
            "byteExact": True,
            "signed": False,
            "exactReplay": {"immutableAuthenticationFields": []},
            "semantic": {"method": method, "path": path},
        },
    }


class WebSurfaceWorkflowTests(unittest.TestCase):
    def test_access_classifier_separates_bot_auth_and_application_responses(self) -> None:
        challenge = classify_access_response(
            status=200,
            headers=[("Content-Type", "text/html")],
            body=b"<title>Verify you are human</title><div class=cf-chl-widget>",
            authenticated=False,
        )
        self.assertEqual(challenge["state"], "environment-blocked")
        self.assertFalse(challenge["eligibleForSecurityConclusion"])

        login = classify_access_response(
            status=200,
            headers=[("Content-Type", "text/html")],
            body=b'<form action="/login"><input type="password"></form>',
            authenticated=True,
        )
        self.assertEqual(login["state"], "auth-inconclusive")
        self.assertTrue(login["loginHtmlWith200"])

        denial = classify_access_response(
            status=403,
            headers=[("Content-Type", "application/json")],
            body=b'{"error":"forbidden"}',
            authenticated=True,
        )
        self.assertEqual(denial["state"], "application-response")
        self.assertTrue(denial["eligibleForSecurityConclusion"])

    def test_raw_http_replay_cannot_claim_browser_fingerprint(self) -> None:
        with self.assertRaisesRegex(WebContractError, "fingerprint"):
            validate_http_replay_headers(
                {}, [("User-Agent", "copied chrome"), ("Sec-Fetch-Site", "same-origin")]
            )
        with self.assertRaisesRegex(WebContractError, "headerContext"):
            validate_http_replay_headers({}, [("Origin", "https://app.example")])
        with self.assertRaisesRegex(WebContractError, "headerContext"):
            validate_http_replay_headers({}, [("X-CSRF-Token", "owned-token")])
        record = validate_http_replay_headers(
            {
                "headerContext": {
                    "mode": "owned-browser-capture",
                    "sourceObservation": "evidence/browser-observation.json",
                    "preservedHeaders": ["Origin", "Accept", "X-CSRF-Token"],
                    "intentionalChanges": [
                        {
                            "name": "X-Test-Variant",
                            "reason": "one-variable representation control",
                            "controlStep": "baseline",
                        }
                    ],
                }
            },
            [
                ("Origin", "https://app.example"),
                ("Accept", "application/json"),
                ("X-CSRF-Token", "owned-token"),
            ],
        )
        self.assertEqual(record["client"], "http-client-replay")
        self.assertFalse(record["browserEquivalent"])

    def test_small_bundle_discovers_lifecycle_two_identities_and_next_question(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_path = root / "bundle.json"
            bundle = {
                "schemaVersion": 1,
                "kind": "krineon-web-request-bundle",
                "metadata": {
                    "identities": {
                        "user-a": {
                            "tenant": "tenant-a",
                            "roles": ["member"],
                            "session": "session-a",
                        },
                        "user-b": {
                            "tenant": "tenant-b",
                            "roles": ["member"],
                            "session": "session-b",
                        },
                    }
                },
                "coverage": {"identityLabels": ["user-a", "user-b"]},
                "requests": [
                    request("create-project", "user-a", "POST", "/projects", dependencies=[]),
                    request("read-project", "user-a", "GET", "/projects/project-a", dependencies=["create-project"]),
                    request("delete-project", "user-a", "DELETE", "/projects/project-a", dependencies=["read-project"]),
                ],
            }
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            html = root / "fixture.html"
            html.write_text(
                '<form action="/projects" method="post"><input name="name"></form>',
                encoding="utf-8",
            )
            surface = build_surface_map(
                bundles=[bundle_path],
                browser_observations=[],
                html_files=[html],
                javascript_files=[],
                api_specs=[],
                graphql_schemas=[],
            )
            self.assertEqual(len(surface["identityModel"]), 2)
            self.assertEqual(len(surface["operationModel"]), 3)
            self.assertEqual(surface["discoveryHints"][0]["forms"][0]["action"], "/projects")

            surface_path = root / "surface.json"
            surface_path.write_text(json.dumps(surface), encoding="utf-8")
            model = build_workflow_model(surface, surface_path)
            self.assertTrue(model["workflowModel"][0]["multiStep"])
            question = model["nextUnresolvedSecurityQuestion"]
            self.assertEqual(question["kind"], "cross-identity-authorization")
            self.assertIn("user-b", question["question"])
            self.assertIn("project-a", question["question"])
            self.assertFalse(model["coverageLedger"]["requestCountIsCoverage"])


if __name__ == "__main__":
    unittest.main()
