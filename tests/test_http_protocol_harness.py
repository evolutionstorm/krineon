from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "http_protocol_harness.py"
SERVER = PROJECT / "tests" / "fixtures" / "protocol_server.py"


def can_bind_loopback() -> bool:
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_port(port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise AssertionError(f"server did not listen on {port}")


class HttpProtocolHarnessTests(unittest.TestCase):
    @unittest.skipUnless(can_bind_loopback(), "loopback sockets are unavailable")
    def test_stateful_raw_differential_concurrent_redirect_and_websocket_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps({"commit": "a" * 40, "authorization": {"confirmed": True}}) + "\n"
            )
            ports = [free_port(), free_port()]
            processes = [
                subprocess.Popen(
                    [sys.executable, str(SERVER), "--port", str(port), "--marker", marker],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                for port, marker in zip(ports, ("one", "two"), strict=True)
            ]
            try:
                for port in ports:
                    wait_port(port)
                spec = root / "protocol.json"
                spec.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "targets": {
                                "framework": {"host": "127.0.0.1", "port": ports[0]},
                                "origin": {"host": "127.0.0.1", "port": ports[1]},
                            },
                            "sessions": {
                                "attacker": {"role": "user", "tenant": "red", "cookies": {}, "variables": {}},
                                "victim": {"role": "admin", "tenant": "blue", "cookies": {}, "variables": {}},
                            },
                            "steps": [
                                {
                                    "id": "login",
                                    "type": "request",
                                    "target": "framework",
                                    "session": "attacker",
                                    "request": {"method": "POST", "path": "/login", "headers": [], "body": {"text": "login"}},
                                    "assertions": [{"kind": "status", "equals": 200}],
                                    "extract": [{"name": "token", "from": "json", "path": "token"}],
                                },
                                {
                                    "id": "raw-duplicates",
                                    "target": "framework",
                                    "session": "attacker",
                                    "request": {
                                        "method": "POST",
                                        "path": "/echo",
                                        "headers": [["X-Duplicate", "a"], ["X-Duplicate", "b"], ["Content-Length", "6"], ["Content-Length", "5"], ["Authorization", "Bearer ${token}"]],
                                        "body": {"text": "hello"},
                                        "framing": "manual",
                                    },
                                    "assertions": [
                                        {"kind": "status", "equals": 200},
                                        {"kind": "body-contains", "value": "\"duplicates\": [\"a\", \"b\"]"},
                                        {"kind": "body-contains", "value": "hello"},
                                    ],
                                },
                                {
                                    "id": "multipart-chunked",
                                    "target": "framework",
                                    "session": "attacker",
                                    "request": {
                                        "method": "POST",
                                        "path": "/echo",
                                        "headers": [["Content-Type", "multipart/form-data; boundary=owned-boundary"]],
                                        "body": {
                                            "multipart": {
                                                "boundary": "owned-boundary",
                                                "parts": [
                                                    {"headers": [["Content-Disposition", "form-data; name=field"]], "body": {"text": "alpha"}},
                                                    {"headers": [["Content-Disposition", "form-data; name=file; filename=a.txt"]], "body": {"text": "beta"}}
                                                ]
                                            }
                                        },
                                        "framing": "chunked",
                                        "chunkSizes": [7, 11, 13]
                                    },
                                    "assertions": [{"kind": "body-contains", "value": "alpha"}]
                                },
                                {
                                    "id": "encoded-path",
                                    "target": "framework",
                                    "request": {"pathBase64": "L2hlYWx0aA==", "headers": []},
                                    "assertions": [{"kind": "body-contains", "value": "ok"}]
                                },
                                {
                                    "id": "prime",
                                    "target": "framework",
                                    "session": "attacker",
                                    "request": {"path": "/prime", "headers": []},
                                    "assertions": [{"kind": "body-contains", "value": "primed"}],
                                },
                                {
                                    "id": "victim-redirect",
                                    "target": "framework",
                                    "session": "victim",
                                    "maxRedirects": 1,
                                    "request": {"path": "/redirect", "headers": []},
                                    "assertions": [{"kind": "body-contains", "value": "victim-sees-prime"}],
                                },
                                {
                                    "id": "stream",
                                    "target": "framework",
                                    "request": {"path": "/chunked-response", "headers": []},
                                    "assertions": [{"kind": "body-contains", "value": "firstsecond"}],
                                },
                                {
                                    "id": "parallel",
                                    "type": "concurrent",
                                    "requests": [
                                        {"target": "framework", "session": "attacker", "request": {"path": "/health", "headers": []}, "assertions": [{"kind": "status", "equals": 200}]},
                                        {"target": "framework", "session": "victim", "request": {"path": "/health", "headers": []}, "assertions": [{"kind": "status", "equals": 200}]},
                                    ],
                                },
                                {
                                    "id": "proxy-origin-differential",
                                    "type": "differential",
                                    "targets": ["framework", "origin"],
                                    "session": "attacker",
                                    "request": {"path": "/different", "headers": []},
                                    "expectDisagreement": True,
                                },
                                {
                                    "id": "websocket",
                                    "type": "websocket",
                                    "target": "framework",
                                    "session": "attacker",
                                    "request": {"path": "/ws", "headers": []},
                                    "frames": [{"opcode": 1, "body": {"text": "owned-echo"}}],
                                    "expectText": "owned-echo",
                                },
                            ],
                        }
                    )
                    + "\n"
                )
                output = campaign / "protocol-output"
                run = subprocess.run(
                    [sys.executable, str(HARNESS), str(campaign), str(spec), str(output)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                retained = (output / "protocol-run.json").read_text() if (output / "protocol-run.json").is_file() else ""
                self.assertEqual(run.returncode, 0, f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}\nresult:\n{retained}")
                result = json.loads((output / "protocol-run.json").read_text())
                self.assertEqual(result["status"], "passed")
                self.assertEqual(len(result["steps"]), 10)
                self.assertEqual(len(result["steps"][5]["redirectChain"]), 2)
                self.assertGreaterEqual(len(result["steps"][6]["response"]["chunks"]), 2)
                self.assertTrue(result["steps"][8]["disagreement"])
                self.assertEqual(result["steps"][9]["receivedFrames"][0]["text"], "owned-echo")
                self.assertIn("session", result["sessions"]["attacker"]["cookieHashes"])
                self.assertIn("token", result["sessions"]["attacker"]["variableHashes"])
            finally:
                for process in processes:
                    process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    if process.stderr is not None:
                        process.stderr.close()


if __name__ == "__main__":
    unittest.main()
