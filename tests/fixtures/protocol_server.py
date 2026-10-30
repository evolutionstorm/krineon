#!/usr/bin/env python3
"""Owned raw HTTP/WebSocket fixture for protocol-harness tests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socketserver
import struct
import threading
import time
from typing import Any


STATE = {"primed": False}
LOCK = threading.Lock()


def read_request(connection: Any) -> tuple[bytes, list[tuple[str, str]], bytes]:
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(4096)
        if not chunk:
            break
        raw.extend(chunk)
    head, _, remainder = bytes(raw).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers.append((name.decode("latin-1"), value.lstrip().decode("latin-1")))
    lower = {name.lower(): value for name, value in headers}
    body = bytearray(remainder)
    if lower.get("transfer-encoding", "").lower() == "chunked":
        decoded = bytearray()
        pending = body
        while True:
            while b"\r\n" not in pending:
                pending.extend(connection.recv(4096))
            line, _, rest = bytes(pending).partition(b"\r\n")
            size = int(line.split(b";", 1)[0], 16)
            pending = bytearray(rest)
            if size == 0:
                break
            while len(pending) < size + 2:
                pending.extend(connection.recv(4096))
            decoded.extend(pending[:size])
            pending = pending[size + 2:]
        body = decoded
    elif "content-length" in lower:
        length = int(lower["content-length"])
        while len(body) < length:
            body.extend(connection.recv(length - len(body)))
        body = body[:length]
    return lines[0], headers, bytes(body)


def response(connection: Any, status: int, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
    reasons = {101: "Switching Protocols", 200: "OK", 302: "Found", 400: "Bad Request"}
    values = list(headers or [])
    values.append(("Content-Length", str(len(body))))
    values.append(("Connection", "close"))
    head = f"HTTP/1.1 {status} {reasons[status]}\r\n".encode()
    for name, value in values:
        head += f"{name}: {value}\r\n".encode("latin-1")
    connection.sendall(head + b"\r\n" + body)


def websocket(connection: Any, headers: list[tuple[str, str]]) -> None:
    key = next(value for name, value in headers if name.lower() == "sec-websocket-key")
    accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    connection.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    first = connection.recv(2)
    if len(first) < 2:
        return
    length = first[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", connection.recv(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", connection.recv(8))[0]
    mask = connection.recv(4)
    payload = b""
    while len(payload) < length:
        payload += connection.recv(length - len(payload))
    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    connection.sendall(bytes([0x81, len(payload)]) + payload)


class Handler(socketserver.BaseRequestHandler):
    marker = "one"

    def handle(self) -> None:
        request_line, headers, body = read_request(self.request)
        parts = request_line.split(b" ")
        if len(parts) < 2:
            return
        path = parts[1].decode("latin-1")
        if path == "/ws":
            websocket(self.request, headers)
            return
        if path == "/login":
            response(self.request, 200, b'{"token":"owned-token"}', [("Set-Cookie", "session=attacker; HttpOnly")])
        elif path == "/prime":
            with LOCK:
                STATE["primed"] = True
            response(self.request, 200, b"primed")
        elif path == "/victim":
            with LOCK:
                value = b"victim-sees-prime" if STATE["primed"] else b"unprimed"
            response(self.request, 200, value)
        elif path == "/redirect":
            response(self.request, 302, b"", [("Location", "/victim")])
        elif path == "/echo":
            duplicates = [value for name, value in headers if name.lower() == "x-duplicate"]
            payload = json.dumps({"duplicates": duplicates, "body": body.decode("utf-8", "replace")}).encode()
            response(self.request, 200, payload, [("Content-Type", "application/json")])
        elif path == "/chunked-response":
            self.request.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n")
            time.sleep(0.02)
            self.request.sendall(b"6\r\nsecond\r\n0\r\n\r\n")
        elif path == "/different":
            response(self.request, 200, self.marker.encode())
        elif path == "/health":
            response(self.request, 200, b"ok")
        else:
            response(self.request, 400, b"unknown")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--marker", default="one")
    args = parser.parse_args()
    Handler.marker = args.marker
    with socketserver.ThreadingTCPServer(("127.0.0.1", args.port), Handler) as server:
        server.daemon_threads = True
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
