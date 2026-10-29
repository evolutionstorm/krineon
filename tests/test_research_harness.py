from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PROBE = PROJECT / "scripts" / "tool_probe.py"


class HarnessTests(unittest.TestCase):
    def run_cli(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(HARNESS), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def create_campaign(self, parent: Path) -> Path:
        campaign = parent / "campaign"
        self.run_cli(
            "init",
            str(campaign),
            "--target",
            "example-target",
            "--repo",
            "https://example.invalid/repository",
            "--commit",
            "0123456789abcdef",
        )
        return campaign

    def test_init_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(len(launch["tasks"]), 10)
            self.assertTrue((campaign / "tasks" / "wave-1-boundary-map.md").is_file())
            self.assertTrue((campaign / "AUTHORIZATION.md").is_file())

    def test_gate_failure_then_reportable_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F001",
                "--title",
                "Example candidate",
                "--lane",
                "protocol-differential",
                "--originator",
                "worker-origin",
            )
            self.run_cli("gate", str(campaign), "F001", "--level", "candidate", expected=1)

            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-review",
                "--agent",
                "codex:gate-review",
                "--role",
                "reviewer",
            )
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001-gate",
            )
            replay_claim = json.loads(
                self.run_cli("claim", str(campaign), "worker-review", "--json").stdout
            )
            replay_result = campaign / "gate-replay.json"
            replay_result.write_text(
                json.dumps(
                    {
                        "independentReplay": {
                            "findingId": "F001",
                            "originator": "worker-origin",
                            "reviewer": "worker-review",
                            "passed": True,
                        }
                    }
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker-review",
                replay_claim["taskId"],
                "--lease-token",
                replay_claim["leaseToken"],
                "--result",
                str(replay_result),
                "--idempotency-key",
                "gate-replay-F001-1",
                "--replay-of",
                "F001",
            )

            path = campaign / "findings" / "F001.json"
            finding = json.loads(path.read_text())
            finding["rootCause"] = "Producer and consumer disagree about the encoded length domain."
            finding["impact"] = "Owned test identity crosses an authorization boundary."
            finding["preconditions"] = ["supported configuration"]
            finding["evidence"] = ["evidence/verification-results.json"]
            finding["controls"] = {
                "baseline": "ordinary request succeeds",
                "negative": "enforcing guard rejects the payload",
                "positive": "only the disputed representation crosses the guard",
                "patched": "patched version rejects it",
            }
            for key in finding["gates"]:
                finding["gates"][key] = True
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F001", "--level", "reportable")
            finding["independentReplays"][0]["sha256"] = "0" * 64
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli(
                "gate", str(campaign), "F001", "--level", "reportable", expected=1
            )

    def test_durable_scheduler_dependencies_and_idempotent_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "plan",
                str(campaign),
                "--max-concurrency",
                "2",
                "--lease-seconds",
                "30",
            )
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-a",
                "--agent",
                "codex:test-a",
                "--role",
                "originator",
            )
            claim = self.run_cli("claim", str(campaign), "worker-a", "--json")
            assignment = json.loads(claim.stdout)
            self.assertEqual(assignment["taskId"], "coordinator-setup")
            self.assertTrue(Path(assignment["workspace"]).is_dir())
            self.assertTrue((Path(assignment["workspace"]) / "KRINEON_ASSIGNMENT.json").is_file())

            no_second = self.run_cli(
                "claim", str(campaign), "worker-a", "--json", expected=3
            )
            self.assertFalse(json.loads(no_second.stdout)["claimed"])

            result = campaign / "coordinator-result.json"
            result.write_text(json.dumps({"summary": "setup complete"}) + "\n")
            submit_args = (
                "submit",
                str(campaign),
                "worker-a",
                "coordinator-setup",
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "setup-attempt-1",
            )
            self.run_cli(*submit_args)
            self.run_cli(*submit_args)

            wave_one = self.run_cli("claim", str(campaign), "worker-a", "--json")
            self.assertEqual(json.loads(wave_one.stdout)["lane"], "boundary-map")

    @unittest.skipUnless(shutil.which("git"), "Git is required for worktree provisioning")
    def test_claim_provisions_detached_git_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            checkout = parent / "source"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.name", "Krineon Test"],
                check=True,
            )
            (checkout / "target.txt").write_text("pinned source\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "target.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            campaign = parent / "campaign"
            self.run_cli(
                "init",
                str(campaign),
                "--target",
                "local-fixture",
                "--repo",
                str(checkout),
                "--checkout",
                str(checkout),
                "--commit",
                revision,
            )
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-git",
                "--agent",
                "codex:git-test",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "worker-git", "--json").stdout
            )
            workspace = Path(assignment["workspace"])
            metadata = json.loads((workspace / "KRINEON_ASSIGNMENT.json").read_text())
            self.assertEqual(metadata["workspaceMode"], "git-worktree")
            self.assertEqual((workspace / "target.txt").read_text(), "pinned source\n")
            actual_revision = subprocess.run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(actual_revision, revision)

    def test_lease_recovery_cancel_and_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--max-attempts", "2")
            self.run_cli("queue", str(campaign))
            for worker in ("worker-a", "worker-b"):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )
            first = json.loads(
                self.run_cli("claim", str(campaign), "worker-a", "--json").stdout
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE task_id=?",
                (first["taskId"],),
            )
            database.commit()
            database.close()
            self.run_cli("recover", str(campaign))
            second = json.loads(
                self.run_cli("claim", str(campaign), "worker-b", "--json").stdout
            )
            self.assertEqual(second["taskId"], first["taskId"])
            self.assertEqual(second["attempt"], 2)
            self.run_cli(
                "cancel",
                str(campaign),
                second["taskId"],
                "--reason",
                "superseded by safer experiment",
            )
            self.run_cli(
                "retry",
                str(campaign),
                second["taskId"],
                "--reason",
                "corrected task packet",
                "--extend-attempts",
            )

    def test_timeout_is_enforced_at_result_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--task-timeout-seconds", "1")
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-timeout",
                "--agent",
                "codex:timeout-test",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "worker-timeout", "--json").stdout
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE tasks SET started_at='2000-01-01T00:00:00+00:00' WHERE task_id=?",
                (assignment["taskId"],),
            )
            database.commit()
            database.close()
            result = campaign / "late-result.json"
            result.write_text(json.dumps({"summary": "too late"}) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "worker-timeout",
                assignment["taskId"],
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "late-result-1",
                expected=1,
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            state = database.execute(
                "SELECT state FROM tasks WHERE task_id=?", (assignment["taskId"],)
            ).fetchone()[0]
            database.close()
            self.assertEqual(state, "timed-out")

    def test_campaign_budget_stops_queued_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--budget-seconds", "60")
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-budget",
                "--agent",
                "codex:budget-test",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE metadata SET value=? WHERE key='deadlineAt'",
                (json.dumps("2000-01-01T00:00:00+00:00"),),
            )
            database.commit()
            database.close()
            self.run_cli("recover", str(campaign))
            self.run_cli(
                "claim", str(campaign), "worker-budget", "--json", expected=4
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            runnable = database.execute(
                "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running')"
            ).fetchone()[0]
            database.close()
            self.assertEqual(runnable, 0)

    def test_independent_replay_enforces_distinct_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            for worker, role in (("origin", "originator"), ("review", "reviewer")):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                    "--role",
                    role,
                )
            self.run_cli(
                "register",
                str(campaign),
                "F001",
                "--title",
                "Replay candidate",
                "--lane",
                "protocol-differential",
                "--originator",
                "origin",
            )
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001",
            )

            # The originator is excluded from the high-priority replay task and
            # therefore claims the normal coordinator task instead.
            origin_claim = json.loads(
                self.run_cli("claim", str(campaign), "origin", "--json").stdout
            )
            self.assertNotEqual(origin_claim["taskId"], "replay-F001")
            review_claim = json.loads(
                self.run_cli("claim", str(campaign), "review", "--json").stdout
            )
            self.assertEqual(review_claim["taskId"], "replay-F001")
            replay_result = campaign / "replay.json"
            replay_result.write_text(
                json.dumps(
                    {
                        "independentReplay": {
                            "findingId": "F001",
                            "originator": "origin",
                            "reviewer": "review",
                            "passed": True,
                        }
                    }
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "review",
                "replay-F001",
                "--lease-token",
                review_claim["leaseToken"],
                "--result",
                str(replay_result),
                "--idempotency-key",
                "replay-F001-review-1",
                "--replay-of",
                "F001",
            )
            finding = json.loads((campaign / "findings" / "F001.json").read_text())
            self.assertTrue(finding["gates"]["independent_replay"])
            self.assertEqual(finding["independentReplays"][0]["reviewer"], "review")

    def test_hash_and_lint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            (campaign / "reports" / "REPORT.md").write_text("# Exact pinned report\n", encoding="utf-8")
            self.run_cli("hash", str(campaign))
            manifest = (campaign / "SHA256SUMS").read_text()
            self.assertIn("reports/REPORT.md", manifest)
            self.assertIn("campaign.json", manifest)
            self.run_cli("lint", str(campaign), "--strict")

    def test_tool_probe_is_json(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(PROBE), "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertIn("commands", payload)
        self.assertIn("trailmark", payload["commands"])
        self.assertIn("joern", payload["commands"])
        self.assertIn("tree-sitter", payload["commands"])
        self.assertIn("z3", payload["commands"])
        self.assertIn("z3", payload["pythonModules"])


if __name__ == "__main__":
    unittest.main()
