#!/usr/bin/env python3
"""Tiny CDP-speaking process used only to test the owned-page runner."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import sys
from pathlib import Path


PNG = base64.b64encode(
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDAT\x08\xd7c\xf8\xcf"
    b"\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")


def read_headers(connection: socket.socket) -> bytes:
    value = bytearray()
    while b"\r\n\r\n" not in value:
        value.extend(connection.recv(4096))
    return bytes(value)


def read_exact(connection: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise EOFError
        value.extend(chunk)
    return bytes(value)


def receive(connection: socket.socket) -> dict[str, object]:
    first, second = read_exact(connection, 2)
    opcode = first & 0x0F
    if opcode == 8:
        raise EOFError
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", read_exact(connection, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", read_exact(connection, 8))[0]
    mask = read_exact(connection, 4) if second & 0x80 else b""
    payload = read_exact(connection, size)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return json.loads(payload.decode("utf-8"))


def send(connection: socket.socket, value: dict[str, object]) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(payload) < 126:
        header = bytes([0x81, len(payload)])
    elif len(payload) < 65536:
        header = bytes([0x81, 126]) + struct.pack("!H", len(payload))
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", len(payload))
    connection.sendall(header + payload)


def main() -> int:
    profile = None
    for argument in sys.argv[1:]:
        if argument.startswith("--user-data-dir="):
            profile = Path(argument.split("=", 1)[1])
            break
    if profile is None:
        return 2
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    profile.mkdir(parents=True, exist_ok=True)
    (profile / "DevToolsActivePort").write_text(
        f"{port}\n/devtools/browser/fake\n", encoding="utf-8"
    )
    connection, _ = listener.accept()
    headers = read_headers(connection)
    key = ""
    for line in headers.decode("latin-1").split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    connection.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii")
    )
    current_url = "about:blank"
    while True:
        try:
            message = receive(connection)
        except EOFError:
            break
        identifier = message.get("id")
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        result: dict[str, object] = {}
        if method == "Browser.getVersion":
            result = {"product": "FakeChromium/1", "protocolVersion": "1.3"}
        elif method == "Target.createTarget":
            result = {"targetId": "owned-page-target"}
        elif method == "Target.attachToTarget":
            result = {"sessionId": "owned-page-session"}
        elif method == "Page.navigate":
            current_url = str(params.get("url") or "")
            result = {"frameId": "owned-page-frame"}
        elif method == "Runtime.evaluate":
            expression = str(params.get("expression") or "")
            value: object
            if expression == "globalThis.location.href":
                value = current_url
            else:
                value = "control" not in current_url
            result = {"result": {"type": "boolean", "value": value}}
        elif method == "Page.captureScreenshot":
            result = {"data": PNG}
        elif method == "SystemInfo.getProcessInfo":
            result = {"processInfo": [{"type": "renderer", "id": os.getpid(), "cpuTime": 0}]}
        send(connection, {"id": identifier, "result": result})
        if method == "Page.navigate":
            send(connection, {"method": "Page.loadEventFired", "params": {"timestamp": 1}})
        if method == "Browser.close":
            break
    connection.close()
    listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
