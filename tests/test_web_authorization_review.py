from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.web_contract import WebCampaignContract, WebContractError


PROJECT = Path(__file__).resolve().parents[1]
TOOL = PROJECT / "scripts" / "web_contract.py"
TEMPLATE = PROJECT / "assets" / "web-campaign.template.json"
ACCOUNT_TEMPLATE = PROJECT / "assets" / "web-owned-accounts.template.json"


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for signed approval")
class WebAuthorizationReviewTests(unittest.TestCase):
    def run_tool(self, *arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, expected, completed.stderr)
        return completed

    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        campaign = root / "campaign"
        campaign.mkdir()
        rules = campaign / "PROGRAM_RULES.md"
        rules.write_text("Owned staging application only.\n", encoding="utf-8")
        contract = campaign / "web-campaign.json"
        contract.write_bytes(TEMPLATE.read_bytes())
        (campaign / "campaign.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "profile": "web-app",
                    "authorization": {"confirmed": False},
                    "webContract": "web-campaign.json",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        review = root / "review.json"
        return campaign, contract, review

    def test_review_is_hash_bound_signed_and_required_for_live_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, contract, review = self.fixture(Path(directory))
            prepared = self.run_tool(
                "prepare-review", str(contract), "--output", str(review)
            )
            self.assertFalse(json.loads(prepared.stdout)["trafficExecuted"])
            value = json.loads(review.read_text(encoding="utf-8"))
            value.update(
                {
                    "approvedBy": "coordinator-reviewer",
                    "programRulesDate": dt.date.today().isoformat(),
                    "validUntil": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
                    ).replace(microsecond=0).isoformat(),
                    "environmentOwner": "researcher-owned-staging",
                    "ownedFixtureNamespace": "owned-fixture-01",
                }
            )
            value["review"] = {name: True for name in value["review"]}
            review.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            authorized = self.run_tool(
                "authorize", str(campaign), str(contract), str(review)
            )
            result = json.loads(authorized.stdout)
            self.assertTrue(result["authorizationConfirmed"])
            self.assertFalse(result["trafficExecuted"])
            loaded = WebCampaignContract.load(contract)
            loaded.require_live_authorization()
            approval = campaign / result["approvalRecord"]
            signature = campaign / result["approvalSignature"]
            self.assertTrue(approval.is_file())
            self.assertTrue(signature.is_file())
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            self.assertTrue(campaign_record["authorization"]["confirmed"])
            tampered = json.loads(contract.read_text(encoding="utf-8"))
            tampered["budget"]["totalRequests"] += 1
            contract.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                WebContractError, "not bound to the current contract"
            ):
                WebCampaignContract.load(contract).require_live_authorization()

    def test_changed_program_rules_invalidate_live_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, contract, review = self.fixture(Path(directory))
            self.run_tool("prepare-review", str(contract), "--output", str(review))
            value = json.loads(review.read_text(encoding="utf-8"))
            value.update(
                {
                    "approvedBy": "coordinator-reviewer",
                    "programRulesDate": dt.date.today().isoformat(),
                    "validUntil": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
                    ).replace(microsecond=0).isoformat(),
                    "environmentOwner": "researcher-owned-staging",
                    "ownedFixtureNamespace": "owned-fixture-01",
                }
            )
            value["review"] = {name: True for name in value["review"]}
            review.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            self.run_tool("authorize", str(campaign), str(contract), str(review))
            (campaign / "PROGRAM_RULES.md").write_text(
                "Changed program limits.\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(WebContractError, "current program rules"):
                WebCampaignContract.load(contract).require_live_authorization()

    def test_changed_contract_and_incomplete_review_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, contract, review = self.fixture(Path(directory))
            self.run_tool("prepare-review", str(contract), "--output", str(review))
            changed = json.loads(contract.read_text(encoding="utf-8"))
            changed["budget"]["totalRequests"] += 1
            contract.write_text(json.dumps(changed, indent=2) + "\n", encoding="utf-8")
            rejected = self.run_tool(
                "authorize", str(campaign), str(contract), str(review), expected=2
            )
            self.assertIn("does not match the current contract", rejected.stderr)

            self.run_tool("prepare-review", str(contract), "--output", str(review))
            value = json.loads(review.read_text(encoding="utf-8"))
            value.update(
                {
                    "approvedBy": "coordinator-reviewer",
                    "programRulesDate": dt.date.today().isoformat(),
                    "validUntil": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
                    ).replace(microsecond=0).isoformat(),
                    "environmentOwner": "researcher-owned-staging",
                    "ownedFixtureNamespace": "owned-fixture-01",
                }
            )
            review.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            rejected = self.run_tool(
                "authorize", str(campaign), str(contract), str(review), expected=2
            )
            self.assertIn("authorization review is incomplete", rejected.stderr)

    def test_owned_accounts_activate_the_full_bounded_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, contract, _ = self.fixture(Path(directory))
            manifest = campaign / "web" / "owned-accounts.json"
            manifest.parent.mkdir()
            value = json.loads(ACCOUNT_TEMPLATE.read_text(encoding="utf-8"))
            value.update(
                {
                    "confirmedBy": "researcher-owner",
                    "environmentOwner": "researcher-owned-trial",
                    "ownedFixtureNamespace": "owned-fixture-01",
                    "programRulesDate": dt.date.today().isoformat(),
                    "validUntil": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
                    ).replace(microsecond=0).isoformat(),
                }
            )
            value["accounts"][0]["expectedTenant"] = "owned-trial"
            manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

            activated = self.run_tool(
                "activate-owned-testing",
                str(campaign),
                str(contract),
                str(manifest),
            )
            result = json.loads(activated.stdout)
            self.assertTrue(result["authorizationConfirmed"])
            self.assertEqual(result["mode"], "owned-full-testing")
            self.assertIn("POST", result["allowedMethods"])
            self.assertIn("PROPFIND", result["allowedMethods"])
            self.assertTrue(result["autoApproveBoundedWorkflows"])

            loaded = WebCampaignContract.load(contract)
            loaded.require_live_authorization()
            authorization = loaded.raw["authorization"]
            self.assertTrue(authorization["ownedFullTesting"]["enabled"])
            self.assertTrue(authorization["allowStateChangingOperations"])
            self.assertTrue(authorization["allowBrowserActions"])
            self.assertTrue(authorization["allowUploads"])
            self.assertTrue(authorization["allowWebSockets"])
            self.assertFalse(authorization["allowExternalCallbacks"])
            self.assertTrue(all(identity.verification_status == "verified" for identity in loaded.identities.values()))
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            self.assertEqual(campaign_record["authorization"]["mode"], "owned-full-testing")

    def test_owned_accounts_reject_literal_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, contract, _ = self.fixture(Path(directory))
            manifest = campaign / "web" / "owned-accounts.json"
            manifest.parent.mkdir()
            value = json.loads(ACCOUNT_TEMPLATE.read_text(encoding="utf-8"))
            value.update(
                {
                    "confirmedBy": "researcher-owner",
                    "environmentOwner": "researcher-owned-trial",
                    "ownedFixtureNamespace": "owned-fixture-01",
                    "programRulesDate": dt.date.today().isoformat(),
                    "validUntil": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
                    ).replace(microsecond=0).isoformat(),
                }
            )
            value["accounts"][0]["password"] = "must-not-be-retained"
            manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            rejected = self.run_tool(
                "activate-owned-testing",
                str(campaign),
                str(contract),
                str(manifest),
                expected=2,
            )
            self.assertIn("contains a literal credential", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
