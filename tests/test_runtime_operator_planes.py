import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from scripts.operator_workbench import WorkbenchServer
from scripts.runtime_plane import (
    ExecutionRuntime,
    ProcessObservation,
    RuntimePlaneError,
    RuntimeStore,
    docker_offline_runner,
    runtime_status,
)
from scripts.swarm_control import ControlStore


class RuntimeOperatorPlanesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "campaign.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "mode": "local-lab",
                    "authorization": {
                        "confirmed": True,
                        "allowedEnvironment": "owned disposable fixture",
                    },
                }
            ),
            encoding="utf-8",
        )
        self.workspace = self.root / "worktrees" / "task-a"
        self.workspace.mkdir(parents=True)
        self.target = self.workspace / "owned-verifier"
        self.target.write_text("owned target\n", encoding="utf-8")
        self.target_hash = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.observer = self.workspace / "owned-observer"
        self.observer.write_text("owned observer\n", encoding="utf-8")
        self.observer_hash = hashlib.sha256(self.observer.read_bytes()).hexdigest()
        self.recipe = {
            "schemaVersion": 1,
            "recipeId": "recipe-a",
            "taskId": "task-a",
            "workerId": "worker-origin",
            "sessionId": "session-origin",
            "workspace": "worktrees/task-a",
            "command": ["/workspace/owned-verifier", "--json"],
            "environment": {"KRINEON_CASE": "positive"},
            "sandbox": {
                "mode": "docker-offline",
                "image": "example/runner@sha256:" + "a" * 64,
                "timeoutSeconds": 30,
                "memoryMb": 512,
                "cpus": 1,
                "pids": 64,
            },
            "network": {"mode": "none"},
            "targetHashes": {
                "owned-verifier": self.target_hash,
                "owned-observer": self.observer_hash,
            },
            "assertions": {
                "exitCode": 0,
                "stdoutContains": ["PASS", "owned"],
                "stderrNotContains": ["AddressSanitizer"],
                "stdoutRegex": [r'"case":\s*"positive"'],
            },
            "alternateObserver": {
                "command": ["/workspace/owned-observer", "--evidence", "/evidence"],
                "environment": {},
                "assertions": {
                    "exitCode": 0,
                    "stdoutRegex": [r'"observer":\s*"independent"'],
                    "stderrNotContains": ["runtime observer failed"],
                },
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def runner(recipe, workspace, output):
        del workspace, output
        if recipe["command"][0] == "/workspace/owned-observer":
            return ProcessObservation(
                0,
                json.dumps({"observer": "independent", "terminal": "owned"}).encode(),
                b"",
            )
        value = recipe["environment"]["KRINEON_CASE"]
        return ProcessObservation(
            0,
            json.dumps({"result": "PASS", "case": value, "terminal": "owned"}).encode(),
            b"",
        )

    def create_sessions(self, store: RuntimeStore) -> None:
        store.create_session(
            session_id="session-origin",
            task_id="task-a",
            worker_id="worker-origin",
            agent_identity="agent-origin",
            provider="codex",
            model="test-model",
        )
        store.create_session(
            session_id="session-reviewer",
            task_id="task-a",
            worker_id="worker-reviewer",
            agent_identity="agent-reviewer",
            provider="codex",
            model="test-model",
        )

    def test_execution_ledger_artifacts_and_fresh_replay(self) -> None:
        runtime = ExecutionRuntime(self.root, runner=self.runner)
        try:
            self.create_sessions(runtime.store)
            first = runtime.run(self.recipe)
            self.assertEqual(first["state"], "passed")
            self.assertTrue(first["assertionsPassed"])
            stdout_path = self.root / first["stdout"]["relative_path"]
            self.assertEqual(hashlib.sha256(stdout_path.read_bytes()).hexdigest(), first["stdout"]["sha256"])

            replay = runtime.replay(first["runId"], "session-reviewer")
            self.assertEqual(replay["verdict"], "passed")
            self.assertTrue(replay["sameRecipe"])
            self.assertTrue(replay["sameTargetHashes"])
            self.assertTrue(replay["alternateObserverPassed"])

            events = list(runtime.store.connection.execute("SELECT * FROM events ORDER BY event_id"))
            starts = [row for row in events if row["event_type"] == "tool_started"]
            finishes = [row for row in events if row["event_type"] == "tool_finished"]
            self.assertEqual(len(starts), 2)
            self.assertEqual({row["tool_call_id"] for row in starts}, {row["tool_call_id"] for row in finishes})
            observer_starts = [row for row in events if row["event_type"] == "alternate_observer_started"]
            observer_finishes = [row for row in events if row["event_type"] == "alternate_observer_finished"]
            self.assertEqual(len(observer_starts), 2)
            self.assertEqual(
                {row["tool_call_id"] for row in observer_starts},
                {row["tool_call_id"] for row in observer_finishes},
            )
            self.assertEqual(runtime_status(self.root)["counts"]["replays"], 1)
            control = ControlStore(self.root)
            try:
                components = {
                    row["component_id"]: row["state"]
                    for row in control.connection.execute(
                        "SELECT component_id,state FROM swarm_components"
                    ).fetchall()
                }
                self.assertEqual(components["provider:codex"], "unknown")
                self.assertEqual(components["tool:recipe-a"], "healthy")
                self.assertTrue(any(key.startswith("model:runtime-model-") for key in components))
                self.assertEqual(
                    control.connection.execute(
                        "SELECT COUNT(*) AS n FROM swarm_invocations WHERE component_id='tool:recipe-a'"
                    ).fetchone()["n"],
                    2,
                )
            finally:
                control.close()
        finally:
            runtime.close()

    def test_replay_rejects_same_agent_identity_and_target_drift(self) -> None:
        runtime = ExecutionRuntime(self.root, runner=self.runner)
        try:
            runtime.store.create_session(
                session_id="session-origin", task_id="task-a", worker_id="worker-origin",
                agent_identity="same-agent", provider="codex", model="test-model",
            )
            runtime.store.create_session(
                session_id="session-reviewer", task_id="task-a", worker_id="worker-reviewer",
                agent_identity="same-agent", provider="codex", model="test-model",
            )
            first = runtime.run(self.recipe)
            with self.assertRaisesRegex(RuntimePlaneError, "different agent identity"):
                runtime.replay(first["runId"], "session-reviewer")
            self.target.write_text("changed target\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlaneError, "target hash changed"):
                runtime.run(self.recipe)
        finally:
            runtime.close()

    def test_alternate_observer_is_a_separate_enforcing_process(self) -> None:
        def runner(recipe, workspace, output):
            del workspace, output
            if recipe["command"][0] == "/workspace/owned-observer":
                return ProcessObservation(2, b'{"observer":"failed"}', b"observer rejected evidence")
            return ProcessObservation(
                0,
                b'{"result":"PASS","case":"positive","terminal":"owned"}',
                b"",
            )

        runtime = ExecutionRuntime(self.root, runner=runner)
        try:
            self.create_sessions(runtime.store)
            result = runtime.run(self.recipe)
            self.assertTrue(result["assertionsPassed"])
            self.assertFalse(result["alternateObserverPassed"])
            self.assertEqual(result["state"], "failed")
            replay = runtime.replay(result["runId"], "session-reviewer")
            self.assertEqual(replay["verdict"], "failed")
        finally:
            runtime.close()

    def test_read_only_authenticated_operator_workbench(self) -> None:
        runtime = ExecutionRuntime(self.root, runner=self.runner)
        try:
            self.create_sessions(runtime.store)
            runtime.run(self.recipe)
        finally:
            runtime.close()

        server = WorkbenchServer(("127.0.0.1", 0), self.root, "test-token-value-with-sufficient-entropy")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(base + "/api/status", timeout=2)
            self.assertEqual(missing.exception.code, 401)

            request = urllib.request.Request(
                base + "/api/status",
                headers={"Authorization": "Bearer test-token-value-with-sufficient-entropy"},
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                body = json.load(response)
            self.assertEqual(body["counts"]["runs"], 1)

            mutation = urllib.request.Request(
                base + "/api/status",
                method="POST",
                data=b"{}",
                headers={"Authorization": "Bearer test-token-value-with-sufficient-entropy"},
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(mutation, timeout=2)
            self.assertEqual(rejected.exception.code, 405)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_docker_runner_is_offline_read_only_and_digest_pinned(self) -> None:
        output = self.root / "output"
        output.mkdir()
        with mock.patch("scripts.runtime_plane.shutil.which", return_value="/usr/bin/docker"), mock.patch(
            "scripts.runtime_plane.subprocess.run",
            return_value=mock.Mock(returncode=0, stdout=b"PASS", stderr=b""),
        ) as executed:
            observation = docker_offline_runner(self.recipe, self.workspace, output)
        self.assertEqual(observation.exit_code, 0)
        command = executed.call_args.args[0]
        self.assertIn("--network", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("no-new-privileges", command)
        self.assertEqual(command[command.index("--pull") + 1], "never")
        self.assertTrue(any("@sha256:" + "a" * 64 in item for item in command))


if __name__ == "__main__":
    unittest.main()
