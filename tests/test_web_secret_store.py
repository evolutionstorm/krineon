from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.web_secret_store import SecretStore


PROJECT = Path(__file__).resolve().parents[1]
SECRET_TOOL = PROJECT / "scripts" / "web_secret_store.py"


class WebSecretStoreCliTests(unittest.TestCase):
    def test_environment_name_stores_secret_without_argument_or_output_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            campaign.mkdir()
            store_path = root / "private-secrets"
            secret = "owned-test-token-that-must-not-be-printed"
            environment = dict(os.environ)
            environment["KRINEON_OWNED_TOKEN"] = secret
            arguments = [
                sys.executable,
                str(SECRET_TOOL),
                str(store_path),
                "--forbidden-root",
                str(campaign),
                "--put-reference",
                "secret://owned-user",
                "--kind",
                "bearer",
                "--env",
                "KRINEON_OWNED_TOKEN",
                "--version",
                "owned-user-v1",
            ]
            self.assertNotIn(secret, arguments)
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            result = json.loads(completed.stdout)
            self.assertFalse(result["secretValueExposed"])
            stored = SecretStore(store_path, forbidden_root=campaign).get(
                "secret://owned-user", version="owned-user-v1"
            )
            self.assertEqual(stored, secret.encode())

    def test_secret_file_must_be_owner_restricted_and_not_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            campaign.mkdir()
            source = root / "token.txt"
            source.write_text("owned-file-token", encoding="utf-8")
            source.chmod(0o644)
            base = [
                sys.executable,
                str(SECRET_TOOL),
                str(root / "store"),
                "--forbidden-root",
                str(campaign),
                "--put-reference",
                "secret://owned-file-user",
                "--kind",
                "bearer",
                "--secret-file",
                str(source),
            ]
            rejected = subprocess.run(base, check=False, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("accessible by other users", rejected.stderr)

            source.chmod(0o600)
            accepted = subprocess.run(base, check=False, capture_output=True, text=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertNotIn("owned-file-token", accepted.stdout + accepted.stderr)


if __name__ == "__main__":
    unittest.main()
