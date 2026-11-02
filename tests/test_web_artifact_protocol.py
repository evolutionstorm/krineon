import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_artifact_graph import build as build_artifact_graph
from scripts.web_protocol_model import build as build_protocol_model


class WebArtifactProtocolTest(unittest.TestCase):
    def test_recursive_artifact_and_permission_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "client-artifacts"
            artifacts.mkdir()
            entry = artifacts / "entry.js"
            chunk = artifacts / "chunk.js"
            entry.write_text(
                'import("./chunk.js"); import("./lazy.js"); '
                'const routes=[{path:"/admin", permission:"admin.read"}]; '
                'const permissionEndpoint="/api/permissions";\n',
                encoding="utf-8",
            )
            chunk.write_text('const route={path:"/profile", role:"member"};\n', encoding="utf-8")
            manifest = {
                "schemaVersion": 1,
                "deploymentEpoch": "build-1",
                "artifacts": [
                    {
                        "path": "client-artifacts/entry.js",
                        "url": "http://127.0.0.1:8000/entry.js",
                        "sha256": "entry",
                        "mimeType": "text/javascript",
                        "identityId": "admin",
                        "tenant": "tenant-a",
                        "journey": "admin-home",
                    },
                    {
                        "path": "client-artifacts/chunk.js",
                        "url": "http://127.0.0.1:8000/chunk.js",
                        "sha256": "chunk",
                        "mimeType": "text/javascript",
                        "identityId": "admin",
                        "tenant": "tenant-a",
                        "journey": "admin-home",
                    },
                ],
            }
            manifest_path = root / "client-artifact-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            graph = build_artifact_graph(manifest_path, root)
            self.assertTrue(any(edge["resolved"] for edge in graph["edges"]))
            self.assertEqual(
                graph["unresolvedArtifacts"][0]["url"],
                "http://127.0.0.1:8000/lazy.js",
            )
            routes = {row["path"]: row for row in graph["permissionGraph"]["routes"]}
            self.assertIn("admin.read", routes["/admin"]["permissionCandidates"])
            self.assertFalse(graph["permissionGraph"]["edges"][0]["serverAuthorizationClaimed"])
            self.assertEqual(
                graph["acquisitionExperiments"][0]["execution"],
                "requires-web-contract-and-browser-approval",
            )

    def test_websocket_and_sse_values_are_not_copied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = [
                {
                    "method": "Network.webSocketCreated",
                    "params": {"requestId": "ws-1", "url": "ws://127.0.0.1/socket"},
                },
                {
                    "method": "Network.webSocketWillSendHandshakeRequest",
                    "params": {
                        "requestId": "ws-1",
                        "request": {"headers": {"Origin": "http://127.0.0.1", "Cookie": "redacted"}},
                    },
                },
                {
                    "method": "Network.webSocketHandshakeResponseReceived",
                    "params": {"requestId": "ws-1", "response": {"status": 101, "headers": {}}},
                },
                {
                    "method": "Network.webSocketFrameSent",
                    "params": {
                        "requestId": "ws-1",
                        "response": {
                            "opcode": 1,
                            "payloadData": '{"type":"subscribe","token":"DO-NOT-RETAIN","room":"owned"}',
                        },
                    },
                },
                {
                    "method": "Network.requestWillBeSent",
                    "params": {
                        "requestId": "sse-1",
                        "request": {"url": "http://127.0.0.1/events", "method": "GET"},
                    },
                },
                {
                    "method": "Network.responseReceived",
                    "params": {
                        "requestId": "sse-1",
                        "response": {
                            "url": "http://127.0.0.1/events",
                            "status": 200,
                            "mimeType": "text/event-stream",
                            "headers": {"Content-Type": "text/event-stream"},
                        },
                    },
                },
                {
                    "method": "Network.eventSourceMessageReceived",
                    "params": {
                        "requestId": "sse-1",
                        "eventName": "update",
                        "eventId": "sensitive-id",
                        "data": '{"resource":"owned","secret":"DO-NOT-RETAIN"}',
                    },
                },
            ]
            events_path = root / "events.json"
            events_path.write_text(json.dumps(events), encoding="utf-8")
            model = build_protocol_model(
                events_path,
                workflow_id="workflow-1",
                step_id="step-1",
                identity_id="actor-a",
                tenant="tenant-a",
                deployment_epoch="build-1",
            )
            self.assertEqual(model["coverage"]["websocketChannels"], 1)
            self.assertEqual(model["coverage"]["sseChannels"], 1)
            self.assertEqual(model["coverage"]["sentFrames"], 1)
            serialized = json.dumps(model)
            self.assertNotIn("DO-NOT-RETAIN", serialized)
            self.assertNotIn("sensitive-id", serialized)
            frame = model["channels"][0]["frames"][0]
            self.assertEqual(frame["shape"]["token"], "redacted-field")
            self.assertEqual(frame["discriminator"], "subscribe")
            self.assertFalse(model["retention"]["rawPayloadsCopied"])


if __name__ == "__main__":
    unittest.main()
