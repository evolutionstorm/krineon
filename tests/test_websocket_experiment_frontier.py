import json
import tempfile
import unittest
from pathlib import Path

from scripts.websocket_experiment_frontier import build
from scripts.web_rea_bootstrap import prepare


class WebSocketExperimentFrontierTest(unittest.TestCase):
    def test_observed_channel_generates_stateful_security_frontier(self) -> None:
        model = {
            "kind": "krineon-websocket-sse-protocol-model",
            "eventsSha256": "a" * 64,
            "channels": [
                {
                    "id": "WS-owned",
                    "transport": "websocket",
                    "url": "wss://app.example.test/realtime",
                    "frames": [{"direction": "sent", "format": "binary"}],
                }
            ],
            "operations": [
                {"channelId": "WS-owned", "direction": "sent", "operation": "subscribe"}
            ],
        }
        identities = [
            {"id": "owner-a", "tenant": "tenant-a", "roles": ["member"], "verified": True},
            {"id": "owner-b", "tenant": "tenant-b", "roles": ["member"], "verified": True},
        ]
        frontier = build(model, identities)
        families = {value["family"] for value in frontier["experiments"]}
        self.assertTrue(frontier["policy"]["specialFocus"])
        self.assertEqual(frontier["coverage"]["observedWebSocketChannels"], 1)
        self.assertEqual(frontier["coverage"]["blockedExperiments"], 0)
        self.assertIn("handshake-identity-and-session-binding", families)
        self.assertIn("per-message-identity-and-resource-authorization", families)
        self.assertIn("cross-tenant-message-authorization", families)
        self.assertIn("revocation-expiry-and-reconnect", families)
        self.assertIn("message-replay-order-and-alternate-consumer", families)
        self.assertIn("binary-frame-parser-differential", families)
        for experiment in frontier["experiments"]:
            self.assertLessEqual(experiment["limits"]["maxConnections"], 2)
            self.assertLessEqual(experiment["limits"]["maxFramesPerConnection"], 16)
            self.assertFalse(experiment["limits"]["availabilityObjective"])

    def test_no_channel_creates_explicit_acquisition_blocker(self) -> None:
        frontier = build(
            {
                "kind": "krineon-websocket-sse-protocol-model",
                "eventsSha256": "b" * 64,
                "channels": [],
                "operations": [],
            },
            [],
        )
        self.assertEqual(frontier["coverage"]["pendingExperiments"], 0)
        self.assertEqual(frontier["experiments"][0]["state"], "blocked")
        self.assertEqual(frontier["experiments"][0]["family"], "websocket-surface-acquisition")

    def test_rea_bootstrap_targets_only_retained_campaign_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            (campaign / "campaign.json").write_text(
                json.dumps({"commit": "frozen"}), encoding="utf-8"
            )
            browser = campaign / "evidence" / "web" / "browser-1"
            artifacts = browser / "client-artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / "app.js").write_text("export const route='/api/x';\n", encoding="utf-8")
            (browser / "client-artifact-manifest.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "deploymentEpoch": "build-1",
                        "artifacts": [
                            {
                                "path": "client-artifacts/app.js",
                                "sha256": "c" * 64,
                                "url": "https://app.example.test/app.js",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            prepared = prepare(campaign, browser)
            spec = json.loads(prepared["specPath"].read_text(encoding="utf-8"))
            self.assertEqual(spec["operation"], "javascript-application")
            self.assertEqual(
                spec["target"],
                "evidence/web/browser-1/client-artifacts",
            )
            self.assertTrue(prepared["status"]["requiredWhenAvailable"])
            self.assertFalse(prepared["status"]["policy"]["findingPromotionAllowed"])


if __name__ == "__main__":
    unittest.main()
