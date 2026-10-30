from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import chromium_replay  # noqa: E402
from platform_support import (  # noqa: E402
    host_platform,
    normalize_architecture,
    resource_limit_plan,
)


class PlatformSupportTests(unittest.TestCase):
    def test_apple_silicon_aliases_normalize_to_arm64(self) -> None:
        for value in ("arm64", "arm64e", "aarch64", "armx64"):
            self.assertEqual(normalize_architecture(value), "arm64")

    def test_darwin_arm64_is_supported(self) -> None:
        record = host_platform(system="Darwin", machine="arm64")
        self.assertEqual(record["architecture"], "arm64")
        self.assertTrue(record["darwinArm64"])
        self.assertTrue(record["posixHarnessSupported"])

    def test_darwin_memory_limit_is_labelled_best_effort(self) -> None:
        plan = resource_limit_plan(
            {"memoryMb": 512, "timeoutMs": 1000}, system="Darwin"
        )
        self.assertIn(plan["addressSpace"], {"best-effort-darwin", "unavailable"})
        self.assertIn("not a security sandbox", plan["limitation"].lower())

    def test_darwin_seatbelt_evidence_requires_browser_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / "sentinel"
            sentinel.write_text("owned\n", encoding="utf-8")

            def fake_check(
                pid: int,
                operation: str,
                filter_type: int,
                argument: Path | None = None,
            ) -> dict[str, object]:
                denied = pid != 500
                return {
                    "available": True,
                    "pid": pid,
                    "operation": operation,
                    "filterType": filter_type,
                    "argument": str(argument) if argument else None,
                    "returnCode": 1 if denied else 0,
                    "denied": denied,
                    "allowed": not denied,
                }

            with mock.patch.object(
                chromium_replay,
                "read_darwin_process",
                return_value={"available": True, "pid": 600, "command": "renderer"},
            ), mock.patch.object(
                chromium_replay, "darwin_sandbox_check", side_effect=fake_check
            ):
                evidence = chromium_replay.sandbox_evidence(
                    [{"type": "renderer", "id": 600}],
                    [],
                    browser_pid=500,
                    sentinel_path=sentinel,
                    system="Darwin",
                )
                self.assertTrue(evidence["darwinSeatbeltVerified"])
                self.assertTrue(evidence["verified"])

                failed = chromium_replay.sandbox_evidence(
                    [{"type": "renderer", "id": 600}],
                    [],
                    browser_pid=601,
                    sentinel_path=sentinel,
                    system="Darwin",
                )
                self.assertFalse(failed["darwinSeatbeltVerified"])
                self.assertFalse(failed["verified"])


if __name__ == "__main__":
    unittest.main()
