from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_endpoint_catalog import build_catalog
from scripts.web_js_api_extract import extract


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class WebJavaScriptApiCatalogTests(unittest.TestCase):
    def test_web_profile_requires_api_catalog_before_hypothesis_lanes(self) -> None:
        project = Path(__file__).resolve().parents[1]
        profile = json.loads((project / "profiles" / "web-app.json").read_text())
        lanes = {item["id"]: item for item in profile["lanes"]}
        for lane_id in (
            "web-authorization-oracles",
            "web-workflow-state-modeling",
            "web-cache-serialization-tools",
        ):
            self.assertIn(
                "web-api-browser-discovery",
                lanes[lane_id]["dependsOn"],
            )

    def test_structural_runtime_and_workflow_layers_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = root / "app.min.js"
            bundle.write_text(
                "const BASE='/api';const custom=(p,o)=>fetch(BASE+p,o);"
                "custom('/projects/'+projectId+'/share',{method:'POST',headers:{"
                "'Content-Type':'application/json','X-CSRF-Token':csrf},"
                "body:JSON.stringify({memberId:memberId})});"
                "fetch('/graphql?query=OwnedProject');"
                "fetch(new URL('./module-api',import.meta.url));"
                "new WebSocket('wss://app.example.test/ws');"
                "import('/lazy.js');"
                "unknownTransport('/api/unknown-call');"
                "const decoy='https://example.invalid/docs/delete-everything';\n"
                "//# sourceMappingURL=app.min.js.map\n",
                encoding="utf-8",
            )
            lazy = root / "lazy.js"
            lazy.write_text(
                "export const redeem=(invitationId)=>fetch('/api/invitations/'"
                "+invitationId+'/redeem',{method:'POST'});\n",
                encoding="utf-8",
            )
            source_map = root / "app.min.js.map"
            write_json(
                source_map,
                {
                    "version": 3,
                    "file": "app.min.js",
                    "sources": ["src/client.ts"],
                    "sourcesContent": ["export const owned = true"],
                    "names": [],
                    "mappings": "AAAA",
                },
            )

            def create_manifest(actor: str, tenant: str, runtime_path: str) -> Path:
                observation = root / f"observation-{actor}.json"
                events = root / f"events-{actor}.json"
                write_json(
                    observation,
                    {
                        "identityId": actor,
                        "expectedTenant": tenant,
                        "stepId": f"journey-{actor}",
                    },
                )
                write_json(
                    events,
                    [
                        {
                            "method": "Network.requestWillBeSent",
                            "params": {
                                "requestId": f"request-{actor}",
                                "loaderId": "loader-1",
                                "request": {
                                    "url": "https://app.example.test/graphql?query=OwnedProject&token=must-not-leak",
                                    "method": "GET",
                                    "headers": {},
                                },
                                "initiator": {"type": "script", "stack": {}},
                            },
                        },
                        {
                            "method": "Network.requestWillBeSent",
                            "params": {
                                "requestId": f"role-{actor}",
                                "loaderId": "loader-1",
                                "request": {
                                    "url": f"https://app.example.test{runtime_path}",
                                    "method": "GET",
                                    "headers": {},
                                },
                                "initiator": {"type": "script"},
                            },
                        },
                    ],
                )
                manifest = root / f"manifest-{actor}.json"
                artifacts = []
                for path, url, map_path in (
                    (bundle, "https://app.example.test/assets/app.min.js", source_map),
                    (lazy, "https://app.example.test/lazy.js", None),
                ):
                    artifacts.append(
                        {
                            "path": path.name,
                            "url": url,
                            "documentUrl": "https://app.example.test/account",
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "kind": "script",
                            "retrievalOrigin": "approved-browser-session",
                            "retrievalApproved": True,
                            "identityId": actor,
                            "tenant": tenant,
                            "session": f"session-{actor}",
                            "journey": f"journey-{actor}",
                            "workflowPrerequisites": [f"journey-{actor}"],
                            **(
                                {
                                    "sourceMapPath": map_path.name,
                                    "sourceMapProvenance": "referenced-by-loaded-script",
                                }
                                if map_path
                                else {}
                            ),
                        }
                    )
                write_json(
                    manifest,
                    {
                        "schemaVersion": 1,
                        "deploymentEpoch": "fixture-build-1",
                        "artifacts": artifacts,
                        "runtimeObservations": [
                            {
                                "browserObservationPath": observation.name,
                                "cdpEventsPath": events.name,
                            }
                        ],
                        "journeys": [{"identityId": actor, "stepId": f"journey-{actor}"}],
                        "unavailableArtifacts": [
                            {"url": "https://app.example.test/feature-gated.js", "reason": "journey not reached"}
                        ],
                    },
                )
                return manifest

            first = extract(
                create_manifest("user-a", "tenant-a", "/api/user-a-only"), root
            )
            second = extract(
                create_manifest("user-b", "tenant-b", "/api/user-b-only"), root
            )
            first_path = root / "extraction-user-a.json"
            second_path = root / "extraction-user-b.json"
            write_json(first_path, first)
            write_json(second_path, second)

            static = first["endpointCandidates"]
            self.assertTrue(
                any(row["semanticPathTemplate"] == "/api/projects/{projectId}/share" for row in static),
                static,
            )
            invitation = next(
                row for row in static if row["semanticPathTemplate"].endswith("/redeem")
            )
            self.assertIn("invitationId", invitation["dynamicValueDependencies"])
            self.assertTrue(any(row["operationKind"] == "graphql" for row in static))
            self.assertTrue(any(row["operationKind"] == "websocket" for row in static))
            self.assertTrue(
                any(row["semanticPathTemplate"] == "/assets/module-api" for row in static)
            )
            self.assertTrue(any(row["frameworkFactIds"] for row in static))
            self.assertTrue(
                any(row["sourceMapMapping"]["status"] == "mapped" for row in static)
            )
            self.assertFalse(
                any("delete-everything" in row["semanticPathTemplate"] for row in static)
            )
            self.assertFalse(
                any("unknown-call" in row["semanticPathTemplate"] for row in static)
            )
            self.assertTrue(
                any("delete-everything" in hint["semanticPathTemplate"] for hint in first["literalHints"])
            )
            self.assertNotIn("must-not-leak", json.dumps(first))

            catalog = build_catalog([first_path, second_path])
            self.assertEqual(catalog["coverageClaim"], "measured-partial-never-all-apis")
            self.assertTrue(catalog["staticRuntimeCorrelations"])
            self.assertTrue(catalog["roleSurfaceDifferences"])
            self.assertTrue(catalog["workflowHypotheses"])
            self.assertEqual(
                catalog["ledger"]["nextCheapestLegitimateAction"]["kind"],
                "legitimate-journey-artifact-collection",
            )
            self.assertFalse(any(row["safeValidationEligible"] for row in catalog["endpoints"]))

    def test_function_scopes_and_graphql_body_operations_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = root / "scoped.js"
            bundle.write_text(
                "function one(){const route='/api/one';fetch(route+'/share',{"
                "method:'POST',headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify({operationName:'CreateOne',"
                "query:'mutation CreateOne { createOne }'})});}"
                "function two(){const route='/api/two';fetch(route+'/share',{"
                "method:'POST',headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify({operationName:'CreateTwo',"
                "query:'mutation CreateTwo { createTwo }'})});}"
                "function unresolved(){let route='/api/stale';route=runtimeRoute();"
                "fetch(route+'/share',{method:'GET'});}",
                encoding="utf-8",
            )
            manifest = root / "manifest.json"
            write_json(
                manifest,
                {
                    "schemaVersion": 1,
                    "deploymentEpoch": "scoped-build-1",
                    "artifacts": [
                        {
                            "path": bundle.name,
                            "url": "https://app.example.test/assets/scoped.js",
                            "documentUrl": "https://app.example.test/account",
                            "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                            "kind": "script",
                            "retrievalOrigin": "approved-browser-session",
                            "retrievalApproved": True,
                            "identityId": "owned-user",
                            "tenant": "owned-tenant",
                            "session": "owned-session",
                            "journey": "owned-journey",
                            "workflowPrerequisites": ["owned-journey"],
                        }
                    ],
                    "runtimeObservations": [],
                    "journeys": [],
                    "unavailableArtifacts": [],
                },
            )
            result = extract(manifest, root)
            graphql = [
                row
                for row in result["endpointCandidates"]
                if row["operationKind"] == "graphql"
            ]
            self.assertEqual(
                {
                    (row["semanticPathTemplate"], row["graphqlOperation"])
                    for row in graphql
                },
                {
                    ("/api/one/share", "CreateOne"),
                    ("/api/two/share", "CreateTwo"),
                },
            )
            self.assertEqual(len({row["endpointId"] for row in graphql}), 2)
            unresolved = [
                row
                for row in result["endpointCandidates"]
                if row["callee"] == "fetch" and not row["expressionFullyResolved"]
            ]
            self.assertTrue(unresolved)
            self.assertTrue(
                all(row["semanticPathTemplate"] != "/api/stale/share" for row in unresolved)
            )
            self.assertTrue(
                all(row["confidence"] == "symbolic-candidate" for row in unresolved)
            )


if __name__ == "__main__":
    unittest.main()
