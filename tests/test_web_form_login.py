from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_cdp_runner import (
    automatic_login_expression,
    automatic_login_status_expression,
    automatic_username_step_expression,
    browser_action_expression,
    password_ready_expression,
)
from scripts.web_contract import WebCampaignContract, redact
from scripts.web_identity import IdentityBroker
from scripts.web_secret_store import SecretStore
from scripts.web_workflow import validate_browser_actions
from tests.test_web_app_profile import contract_value


class WebFormLoginTests(unittest.TestCase):
    def form_contract(self, root: Path) -> WebCampaignContract:
        value = contract_value("http://127.0.0.1:8123", confirmed=True)
        identity = value["identities"][0]
        identity.pop("credentialRef")
        identity.pop("secretVersion")
        identity["credentialType"] = "form-login"
        identity["allowedTransports"] = ["browser"]
        identity["login"] = {
            "usernameRef": "secret://user-a-username",
            "usernameVersion": "user-a-username-v1",
            "passwordRef": "secret://user-a-password",
            "passwordVersion": "user-a-password-v1",
            "timeoutSeconds": 10,
            "maxSubmitRequests": 2,
        }
        path = root / "campaign.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return WebCampaignContract.load(path)

    def test_form_login_identity_resolves_two_private_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            contract = self.form_contract(campaign)
            store = SecretStore(root / "secrets", forbidden_root=campaign)
            store.put(
                "secret://user-a-username",
                "owned@example.test",
                kind="username",
                version="user-a-username-v1",
            )
            store.put(
                "secret://user-a-password",
                "correct horse battery staple",
                kind="password",
                version="user-a-password-v1",
            )
            identity = contract.identities["user-a"]
            broker = IdentityBroker(contract, secret_store=store)
            self.assertEqual(
                broker.form_login_credentials(identity),
                ("owned@example.test", "correct horse battery staple"),
            )

    def test_login_driver_is_fixed_code_and_redacts_both_values(self) -> None:
        login = {
            "usernameSelector": "",
            "passwordSelector": "",
            "submitSelector": "",
            "successSelector": "#account-menu",
            "successPathPrefix": "/app",
        }
        username = "private-user@example.test"
        password = "private-password-value"
        expression = automatic_login_expression(login, username, password)
        self.assertIn(username, expression)
        self.assertIn(password, expression)
        sanitized = redact(
            {"method": "Runtime.evaluate", "expression": expression},
            [username, password],
        )
        serialized = json.dumps(sanitized)
        self.assertNotIn(username, serialized)
        self.assertNotIn(password, serialized)
        status = automatic_login_status_expression(login, "https://app.test/login")
        self.assertNotIn(username, status)
        self.assertNotIn(password, status)
        username_stage = automatic_username_step_expression(login, username)
        self.assertIn(username, username_stage)
        self.assertNotIn(password, username_stage)
        self.assertNotIn(username, password_ready_expression(login))

    def test_common_form_actions_are_declarative(self) -> None:
        step = {
            "browserActions": [
                {"id": "accept", "type": "check", "selector": "#accept"},
                {"id": "submit", "type": "submit", "selector": "#login"},
                {
                    "id": "continue",
                    "type": "press",
                    "selector": "#name",
                    "key": "Enter",
                },
                {
                    "id": "settings",
                    "type": "navigate",
                    "path": "/settings",
                    "useOwnedFullTestRequestPolicy": True,
                    "maxMutationRequests": 2,
                },
            ]
        }
        actions = validate_browser_actions(step)
        self.assertEqual(
            [item["type"] for item in actions],
            ["check", "submit", "press", "navigate"],
        )
        self.assertIn("checked", browser_action_expression(actions[0], None))
        self.assertIn("requestSubmit", browser_action_expression(actions[1], None))


if __name__ == "__main__":
    unittest.main()
