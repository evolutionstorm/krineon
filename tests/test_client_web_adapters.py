from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from lane_activation import build_activation


class ClientWebAdapterTests(unittest.TestCase):
    def test_opencode_adapter_routes_web_campaigns_to_canonical_contract(self) -> None:
        adapter = (PROJECT / ".opencode/skills/krineon/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("High/Critical web application audits", adapter)
        self.assertIn("../../../SKILL.md", adapter)
        self.assertIn("../../../references/opencode.md", adapter)
        self.assertIn("../../../references/web-app.md", adapter)
        self.assertIn("primary agent owns web authorization", adapter)

    def test_canonical_skill_routes_both_clients_to_runtime_adapters(self) -> None:
        skill = (PROJECT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/opencode.md", skill)
        self.assertIn("references/omp.md", skill)
        self.assertIn("active client's runtime adapter", skill)

    def test_web_execution_remains_coordinator_owned_on_both_clients(self) -> None:
        for name in ("opencode.md", "omp.md"):
            adapter = (PROJECT / "references" / name).read_text(encoding="utf-8")
            self.assertIn("coordinator", adapter.lower())
            self.assertIn("literal credentials", adapter)
            self.assertIn("browser profiles", adapter)
            self.assertIn("redacted", adapter)
            self.assertIn("campaign authorization", adapter)
            self.assertIn("independent", adapter.lower())

    def test_readme_has_native_web_invocation_for_each_client(self) -> None:
        readme = (PROJECT / "README.md").read_text(encoding="utf-8")
        web = readme.split("## Test a web application", 1)[1].split(
            "## Update Krineon", 1
        )[0]
        self.assertIn("Codex: $krineon", web)
        self.assertIn("OpenCode: @krineon", web)
        self.assertIn("OMP: /skill:krineon", web)
        self.assertIn("offline plan first", web)

    def test_measured_omp_browser_capability_activates_web_browser_lane(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign.json"
            campaign.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "profile": "web-app",
                        "target": "owned-web-target",
                        "repository": "",
                        "commit": "deployment-epoch-1",
                        "localCheckout": "",
                        "mode": "authorized-web",
                        "authorization": {"confirmed": True},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            facts = root / "facts.json"
            facts.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "kind": "krineon-capability-facts",
                        "facts": [
                            {
                                "id": "runtime.browser-cdp",
                                "state": "present",
                                "provenance": {
                                    "trust": "tool-measurement",
                                    "basis": "OMP coordinator observed its controlled browser tool",
                                },
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            web_campaign = root / "web-campaign.json"
            web_campaign.write_text(
                json.dumps(
                    {
                        "authorization": {"allowBrowserNavigation": True},
                        "requestInputs": {},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = build_activation(
                campaign_path=campaign,
                profile_path=PROJECT / "profiles/web-app.json",
                facts_path=facts,
                web_campaign_path=web_campaign,
            )
            browser = next(
                lane
                for lane in result["lanes"]
                if lane["laneId"] == "web-api-browser-discovery"
            )
            self.assertEqual(browser["state"], "eligible")
            self.assertIn("runtime.browser-cdp", browser["selectedCapabilities"])


if __name__ == "__main__":
    unittest.main()
