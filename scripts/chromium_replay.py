#!/usr/bin/env python3
"""Run a bounded owned-page Chromium replay over the DevTools Protocol.

The caller owns campaign policy and artifact registration. This module owns the
disposable loopback server, fresh browser profile, CDP transport, network
containment, process evidence, and deterministic replay record.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import http.server
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse


class ChromiumReplayError(Exception):
    """A browser replay could not be executed safely or completely."""


FORBIDDEN_EXACT_FLAGS = {
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--single-process",
    "--in-process-gpu",
    "--allow-natives-syntax",
    "--expose-gc",
    "--disable-web-security",
    "--disable-site-isolation-trials",
}
FORBIDDEN_FLAG_PREFIXES = (
    "--js-flags",
    "--javascript-harmony",
    "--renderer-cmd-prefix",
    "--utility-cmd-prefix",
    "--proxy-server",
    "--proxy-bypass-list",
    "--host-resolver-rules",
    "--force-webrtc-ip-handling-policy",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_browser_flags(flags: list[str]) -> None:
    for flag in flags:
        name = flag.split("=", 1)[0]
        if name in FORBIDDEN_EXACT_FLAGS or any(
            name.startswith(prefix) for prefix in FORBIDDEN_FLAG_PREFIXES
        ):
            raise ChromiumReplayError(
                f"browser replay refuses sandbox-disabling or internal V8 flag: {flag}"
            )


def safe_entry(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ChromiumReplayError("entry must be a relative path without traversal")
    return path.as_posix()


def copy_owned_site(
    source: Path,
    destination: Path,
    *,
    max_files: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    if not source.is_dir():
        raise ChromiumReplayError(f"owned page directory is not a directory: {source}")
    files: list[tuple[Path, Path]] = []
    total = 0
    for candidate in sorted(source.rglob("*")):
        if candidate.is_symlink():
            raise ChromiumReplayError(f"owned page tree contains a symlink: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ChromiumReplayError(f"owned page tree contains a non-regular file: {candidate}")
        relative = candidate.relative_to(source)
        size = candidate.stat().st_size
        if size > max_file_bytes:
            raise ChromiumReplayError(f"owned page file exceeds size limit: {relative}")
        total += size
        if total > max_total_bytes:
            raise ChromiumReplayError("owned page tree exceeds total size limit")
        files.append((candidate, relative))
        if len(files) > max_files:
            raise ChromiumReplayError("owned page tree exceeds file-count limit")
    if not files:
        raise ChromiumReplayError("owned page directory is empty")
    manifest: list[dict[str, Any]] = []
    for candidate, relative in files:
        retained = destination / relative
        retained.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, retained)
        manifest.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256_file(retained),
                "size": retained.stat().st_size,
            }
        )
    return manifest


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        server = self.server
        if isinstance(server, OwnedHTTPServer):
            if len(server.requests) < server.request_limit:
                server.requests.append(
                    {
                        "at": time.time(),
                        "client": self.client_address[0],
                        "method": self.command,
                        "path": self.path,
                        "message": format % args,
                    }
                )
            else:
                server.requests_dropped += 1


class OwnedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, root: Path, request_limit: int = 10000):
        self.requests: list[dict[str, Any]] = []
        self.request_limit = request_limit
        self.requests_dropped = 0
        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args, directory=str(root), **kwargs
        )
        super().__init__(("127.0.0.1", 0), handler)


class OwnedPageServer:
    def __init__(self, root: Path):
        self.server = OwnedHTTPServer(root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "OwnedPageServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class WebSocket:
    """Minimal RFC 6455 client sufficient for a local CDP endpoint."""

    def __init__(self, url: str, timeout: float, max_message_bytes: int):
        parsed = urlparse(url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ChromiumReplayError("CDP endpoint must be an unencrypted loopback websocket")
        if parsed.port is None:
            raise ChromiumReplayError("CDP endpoint has no port")
        self.socket = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
        self.socket.settimeout(timeout)
        self.max_message_bytes = max_message_bytes
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = self._read_http_headers()
        if not response.startswith(b"HTTP/1.1 101"):
            raise ChromiumReplayError(
                "CDP websocket upgrade failed: "
                + response.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            )

    def _read_http_headers(self) -> bytes:
        value = bytearray()
        while b"\r\n\r\n" not in value:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ChromiumReplayError("CDP websocket closed during handshake")
            value.extend(chunk)
            if len(value) > 64 * 1024:
                raise ChromiumReplayError("CDP websocket returned oversized headers")
        return bytes(value)

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise ChromiumReplayError("CDP websocket closed unexpectedly")
            chunks.extend(chunk)
        return bytes(chunks)

    def send_text(self, value: str) -> None:
        payload = value.encode("utf-8")
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x81])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + masked)

    def receive_text(self) -> str:
        fragments = bytearray()
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            final = bool(first & 0x80)
            length = second & 0x7F
            masked = bool(second & 0x80)
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > self.max_message_bytes:
                raise ChromiumReplayError("CDP websocket message exceeds configured size limit")
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length)
            if masked:
                payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            if opcode == 0x8:
                raise ChromiumReplayError("CDP websocket closed")
            if opcode == 0x9:
                self._send_control(0xA, payload)
                continue
            if opcode in (0x1, 0x0):
                fragments.extend(payload)
                if len(fragments) > self.max_message_bytes:
                    raise ChromiumReplayError("fragmented CDP message exceeds configured size limit")
                if final:
                    return fragments.decode("utf-8")

    def _send_control(self, opcode: int, payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        header = bytes([0x80 | opcode, 0x80 | len(payload)]) + mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(header + masked)

    def close(self) -> None:
        try:
            self._send_control(0x8, b"")
        except OSError:
            pass
        self.socket.close()


@dataclass
class CDPClient:
    websocket: WebSocket
    allowed_origin: str
    event_limit: int
    next_id: int = 1
    events: list[dict[str, Any]] = field(default_factory=list)
    console: list[dict[str, Any]] = field(default_factory=list)
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    network_failures: list[dict[str, Any]] = field(default_factory=list)
    blocked_external: list[str] = field(default_factory=list)
    crashed: bool = False
    events_dropped: int = 0

    def append_capped(self, values: list[Any], value: Any) -> None:
        if len(values) < self.event_limit:
            values.append(value)

    def _send(self, method: str, params: dict[str, Any] | None, session_id: str | None) -> int:
        command_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"id": command_id, "method": method}
        if params:
            message["params"] = params
        if session_id:
            message["sessionId"] = session_id
        self.websocket.send_text(json.dumps(message, separators=(",", ":")))
        return command_id

    def command(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        deadline: float,
    ) -> dict[str, Any]:
        command_id = self._send(method, params, session_id)
        while time.monotonic() < deadline:
            message = json.loads(self.websocket.receive_text())
            if message.get("id") == command_id:
                if "error" in message:
                    raise ChromiumReplayError(f"CDP {method} failed: {message['error']}")
                return message.get("result") or {}
            self.handle_event(message, session_id=session_id)
        raise ChromiumReplayError(f"CDP command timed out: {method}")

    def handle_event(self, message: dict[str, Any], *, session_id: str | None) -> None:
        method = str(message.get("method") or "")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if len(self.events) < self.event_limit:
            self.events.append(message)
        else:
            self.events_dropped += 1
        if method == "Fetch.requestPaused":
            request_id = str(params.get("requestId") or "")
            request = params.get("request") if isinstance(params.get("request"), dict) else {}
            url = str(request.get("url") or "")
            parsed = urlparse(url)
            allowed = url.startswith(self.allowed_origin + "/") or parsed.scheme in {
                "about",
                "data",
                "blob",
            }
            if allowed:
                self._send("Fetch.continueRequest", {"requestId": request_id}, session_id)
            else:
                self.append_capped(self.blocked_external, url)
                self._send(
                    "Fetch.failRequest",
                    {"requestId": request_id, "errorReason": "Aborted"},
                    session_id,
                )
        elif method == "Runtime.consoleAPICalled":
            self.append_capped(self.console, params)
        elif method == "Runtime.exceptionThrown":
            self.append_capped(self.exceptions, params)
        elif method == "Network.loadingFailed":
            self.append_capped(self.network_failures, params)
        elif method in {"Inspector.targetCrashed", "Target.targetCrashed"}:
            self.crashed = True

    def wait_for(
        self,
        method: str,
        *,
        session_id: str | None,
        deadline: float,
        after_index: int = 0,
    ) -> dict[str, Any]:
        for message in self.events[after_index:]:
            if message.get("method") == method:
                params = message.get("params")
                return params if isinstance(params, dict) else {}
        while time.monotonic() < deadline:
            message = json.loads(self.websocket.receive_text())
            self.handle_event(message, session_id=session_id)
            if message.get("method") == method:
                params = message.get("params")
                return params if isinstance(params, dict) else {}
        raise ChromiumReplayError(f"CDP event timed out: {method}")


def wait_for_devtools(profile: Path, process: subprocess.Popen[bytes], deadline: float) -> str:
    active = profile / "DevToolsActivePort"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ChromiumReplayError(f"Chromium exited before CDP was ready: {process.returncode}")
        if active.is_file():
            lines = active.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) >= 2 and lines[0].isdigit() and lines[1].startswith("/"):
                return f"ws://127.0.0.1:{lines[0]}{lines[1]}"
        time.sleep(0.05)
    raise ChromiumReplayError("Chromium did not publish DevToolsActivePort before timeout")


def read_proc_status(pid: int) -> dict[str, Any]:
    status_path = Path(f"/proc/{pid}/status")
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    result: dict[str, Any] = {"pid": pid, "available": False}
    try:
        values: dict[str, str] = {}
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values[key] = value.strip()
        result.update(
            {
                "available": True,
                "name": values.get("Name", ""),
                "noNewPrivs": values.get("NoNewPrivs", ""),
                "seccomp": values.get("Seccomp", ""),
                "cmdline": [
                    item.decode("utf-8", errors="replace")
                    for item in cmdline_path.read_bytes().split(b"\0")
                    if item
                ],
            }
        )
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return result


def read_darwin_process(pid: int) -> dict[str, Any]:
    result: dict[str, Any] = {"pid": pid, "available": False}
    try:
        completed = subprocess.run(
            ["ps", "-ww", "-p", str(pid), "-o", "pid=,ppid=,command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)
        return result
    output = completed.stdout.strip()
    result.update(
        {
            "available": completed.returncode == 0 and bool(output),
            "returnCode": completed.returncode,
            "command": output[:8000],
        }
    )
    return result


def darwin_sandbox_check(
    pid: int, operation: str, filter_type: int, argument: Path | None = None
) -> dict[str, Any]:
    candidates = [
        "/usr/lib/system/libsystem_sandbox.dylib",
        ctypes.util.find_library("System"),
        "/usr/lib/libSystem.B.dylib",
    ]
    errors: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            library = ctypes.CDLL(candidate, use_errno=True)
            checker = library.sandbox_check
            checker.restype = ctypes.c_int
            ctypes.set_errno(0)
            common = (
                ctypes.c_int(pid),
                ctypes.c_char_p(operation.encode("utf-8")),
                ctypes.c_int(filter_type),
            )
            if argument is None:
                return_code = int(checker(*common))
            else:
                return_code = int(
                    checker(*common, ctypes.c_char_p(os.fsencode(argument)))
                )
            error_number = ctypes.get_errno()
            return {
                "available": return_code >= 0,
                "library": candidate,
                "pid": pid,
                "operation": operation,
                "filterType": filter_type,
                "argument": str(argument) if argument is not None else None,
                "returnCode": return_code,
                "denied": return_code > 0,
                "allowed": return_code == 0,
                "errno": error_number,
            }
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            errors.append(f"{candidate}: {exc}")
    return {
        "available": False,
        "pid": pid,
        "operation": operation,
        "filterType": filter_type,
        "argument": str(argument) if argument is not None else None,
        "errors": errors,
    }


def sandbox_evidence(
    processes: list[dict[str, Any]],
    flags: list[str],
    *,
    browser_pid: int | None = None,
    sentinel_path: Path | None = None,
    system: str | None = None,
) -> dict[str, Any]:
    system_value = system or platform.system()
    forbidden_absent = True
    try:
        validate_browser_flags(flags)
    except ChromiumReplayError:
        forbidden_absent = False
    renderer_rows: list[dict[str, Any]] = []
    for process in processes:
        if str(process.get("type")) != "renderer":
            continue
        try:
            pid = int(process.get("id"))
        except (TypeError, ValueError):
            continue
        row: dict[str, Any] = {"cdp": process}
        if system_value == "Linux":
            row["proc"] = read_proc_status(pid)
        elif system_value == "Darwin":
            row["darwinProcess"] = read_darwin_process(pid)
            if sentinel_path is not None:
                row["seatbeltFileRead"] = darwin_sandbox_check(
                    pid, "file-read-data", 1, sentinel_path
                )
            row["seatbeltProcessExec"] = darwin_sandbox_check(
                pid, "process-exec", 1, Path("/bin/true")
            )
        renderer_rows.append(row)
    linux_verified = system_value == "Linux" and bool(renderer_rows) and all(
        row["proc"].get("available")
        and row["proc"].get("seccomp") == "2"
        and row["proc"].get("noNewPrivs") == "1"
        for row in renderer_rows
    )
    browser_control = (
        darwin_sandbox_check(browser_pid, "file-read-data", 1, sentinel_path)
        if system_value == "Darwin"
        and browser_pid is not None
        and sentinel_path is not None
        else None
    )
    darwin_verified = (
        system_value == "Darwin"
        and bool(renderer_rows)
        and isinstance(browser_control, dict)
        and browser_control.get("available") is True
        and browser_control.get("allowed") is True
        and all(
            row.get("darwinProcess", {}).get("available") is True
            and row.get("seatbeltFileRead", {}).get("available") is True
            and row.get("seatbeltFileRead", {}).get("denied") is True
            and row.get("seatbeltProcessExec", {}).get("available") is True
            and row.get("seatbeltProcessExec", {}).get("denied") is True
            for row in renderer_rows
        )
    )
    verified = forbidden_absent and (
        linux_verified if system_value == "Linux" else darwin_verified
    )
    return {
        "requested": True,
        "platform": system_value,
        "forbiddenFlagsAbsent": forbidden_absent,
        "rendererProcesses": renderer_rows,
        "linuxSeccompAndNoNewPrivsVerified": linux_verified,
        "darwinSeatbeltVerified": darwin_verified,
        "darwinBrowserFileReadControl": browser_control,
        "verified": verified,
        "limitation": (
            "Linux promotion requires renderer Seccomp=2 and NoNewPrivs=1. "
            "Darwin promotion requires Seatbelt to deny renderer file-read and "
            "process-exec queries while the browser-process file-read control succeeds. "
            "Unsupported platforms fail closed."
        ),
    }


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def drain_stream(
    stream: Any,
    limit: int,
    destination: bytearray,
    state: dict[str, bool],
) -> None:
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                state["truncated"] = True
    finally:
        stream.close()


def run_browser_case(
    *,
    binary: Path,
    flags: list[str],
    server: OwnedPageServer,
    entry: str,
    expression: str,
    expected: Any,
    output_dir: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    max_cdp_message_bytes: int,
    event_limit: int,
    headless: bool,
) -> dict[str, Any]:
    validate_browser_flags(flags)
    output_dir.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + timeout_seconds
    with tempfile.TemporaryDirectory(prefix="krineon-chrome-profile-") as profile_value:
        profile = Path(profile_value)
        stdout_path = output_dir / "chromium.stdout.log"
        stderr_path = output_dir / "chromium.stderr.log"
        command = [
            str(binary),
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--metrics-recording-only",
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=127.0.0.1",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]
        if headless:
            command.append("--headless=new")
        command.extend(flags)
        command.append("about:blank")
        display_command = [
            "<registered-chromium>",
            *["--user-data-dir=<temporary-profile>" if item.startswith("--user-data-dir=") else item for item in command[1:]],
        ]
        process = subprocess.Popen(
            command,
            cwd=str(binary.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_data = bytearray()
        stderr_data = bytearray()
        stdout_state = {"truncated": False}
        stderr_state = {"truncated": False}
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = threading.Thread(
            target=drain_stream,
            args=(process.stdout, max_output_bytes, stdout_data, stdout_state),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=drain_stream,
            args=(process.stderr, max_output_bytes, stderr_data, stderr_state),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        websocket: WebSocket | None = None
        client: CDPClient | None = None
        record: dict[str, Any] = {
            "status": "running",
            "entry": entry,
            "url": f"{server.origin}/{entry}",
            "expression": expression,
            "expected": expected,
            "command": display_command,
            "profileDisposable": True,
            "freshProcess": True,
            "startedAtUnix": time.time(),
        }
        try:
            endpoint = wait_for_devtools(profile, process, deadline)
            websocket = WebSocket(
                endpoint,
                max(0.1, deadline - time.monotonic()),
                max_cdp_message_bytes,
            )
            client = CDPClient(websocket, server.origin, event_limit)
            version = client.command("Browser.getVersion", deadline=deadline)
            created = client.command(
                "Target.createTarget", {"url": "about:blank"}, deadline=deadline
            )
            target_id = str(created.get("targetId") or "")
            if not target_id:
                raise ChromiumReplayError("CDP did not return a target ID")
            attached = client.command(
                "Target.attachToTarget",
                {"targetId": target_id, "flatten": True},
                deadline=deadline,
            )
            session_id = str(attached.get("sessionId") or "")
            if not session_id:
                raise ChromiumReplayError("CDP did not return a session ID")
            for method in (
                "Page.enable",
                "Runtime.enable",
                "Network.enable",
                "Log.enable",
                "Profiler.enable",
            ):
                client.command(method, session_id=session_id, deadline=deadline)
            client.command(
                "Profiler.startPreciseCoverage",
                {"callCount": True, "detailed": True},
                session_id=session_id,
                deadline=deadline,
            )
            client.command(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
                session_id=session_id,
                deadline=deadline,
            )
            navigation_event_start = len(client.events)
            navigation = client.command(
                "Page.navigate",
                {"url": record["url"]},
                session_id=session_id,
                deadline=deadline,
            )
            client.wait_for(
                "Page.loadEventFired",
                session_id=session_id,
                deadline=deadline,
                after_index=navigation_event_start,
            )
            location_result = client.command(
                "Runtime.evaluate",
                {"expression": "globalThis.location.href", "returnByValue": True},
                session_id=session_id,
                deadline=deadline,
            )
            location_object = (
                location_result.get("result")
                if isinstance(location_result.get("result"), dict)
                else {}
            )
            final_url = str(location_object.get("value") or "")
            final_url_owned = final_url.startswith(server.origin + "/")
            evaluated = client.command(
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "userGesture": False,
                },
                session_id=session_id,
                deadline=deadline,
            )
            result_object = evaluated.get("result") if isinstance(evaluated.get("result"), dict) else {}
            actual = result_object.get("value")
            exception_details = evaluated.get("exceptionDetails")
            precise_coverage = client.command(
                "Profiler.takePreciseCoverage",
                session_id=session_id,
                deadline=deadline,
            )
            coverage_path = output_dir / "v8-coverage.json"
            coverage_path.write_text(
                json.dumps(
                    {"result": precise_coverage.get("result", [])}, indent=2
                )
                + "\n",
                encoding="utf-8",
            )
            client.command(
                "Profiler.stopPreciseCoverage",
                session_id=session_id,
                deadline=deadline,
            )
            screenshot = client.command(
                "Page.captureScreenshot",
                {"format": "png", "fromSurface": True},
                session_id=session_id,
                deadline=deadline,
            )
            screenshot_path = output_dir / "page.png"
            screenshot_path.write_bytes(base64.b64decode(str(screenshot.get("data") or "")))
            processes_result = client.command("SystemInfo.getProcessInfo", deadline=deadline)
            processes = (
                processes_result.get("processInfo")
                if isinstance(processes_result.get("processInfo"), list)
                else []
            )
            sandbox_sentinel = output_dir / "sandbox-sentinel.txt"
            sandbox_sentinel.write_text(
                f"krineon-owned-{secrets.token_hex(16)}\n", encoding="utf-8"
            )
            sandbox = sandbox_evidence(
                processes,
                flags,
                browser_pid=process.pid,
                sentinel_path=sandbox_sentinel,
            )
            record.update(
                {
                    "status": "completed",
                    "browserVersion": version,
                    "navigation": navigation,
                    "actual": actual,
                    "finalUrl": final_url,
                    "finalUrlOwned": final_url_owned,
                    "expressionMatched": (
                        actual == expected and not exception_details and final_url_owned
                    ),
                    "evaluationException": exception_details,
                    "console": client.console,
                    "exceptions": client.exceptions,
                    "networkFailures": client.network_failures,
                    "blockedExternalRequests": sorted(set(client.blocked_external)),
                    "targetCrashed": client.crashed,
                    "sandbox": sandbox,
                    "sandboxSentinel": {
                        "path": "sandbox-sentinel.txt",
                        "sha256": sha256_file(sandbox_sentinel),
                        "size": sandbox_sentinel.stat().st_size,
                    },
                    "screenshot": {
                        "path": "page.png",
                        "sha256": sha256_file(screenshot_path),
                        "size": screenshot_path.stat().st_size,
                    },
                    "v8Coverage": {
                        "path": "v8-coverage.json",
                        "sha256": sha256_file(coverage_path),
                        "size": coverage_path.stat().st_size,
                    },
                    "eventCount": len(client.events),
                    "eventsTruncated": client.events_dropped > 0,
                    "eventsDropped": client.events_dropped,
                }
            )
            (output_dir / "cdp-events.json").write_text(
                json.dumps(client.events, indent=2) + "\n", encoding="utf-8"
            )
            try:
                client.command("Browser.close", deadline=deadline)
            except (ChromiumReplayError, OSError, socket.timeout):
                pass
        except Exception as exc:
            record.update({"status": "failed", "error": str(exc)})
        finally:
            if websocket is not None:
                websocket.close()
            terminate_process(process)
            stdout_thread.join(timeout=3)
            stderr_thread.join(timeout=3)
            record["browserExitCode"] = process.returncode
            stdout_path.write_bytes(bytes(stdout_data))
            stderr_path.write_bytes(bytes(stderr_data))
            record["stdout"] = bytes(stdout_data).decode("utf-8", errors="replace")
            record["stderr"] = bytes(stderr_data).decode("utf-8", errors="replace")
            record["stdoutTruncated"] = stdout_state["truncated"]
            record["stderrTruncated"] = stderr_state["truncated"]
            record["endedAtUnix"] = time.time()
    return record

