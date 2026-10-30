#!/usr/bin/env python3
"""Replay stateful raw HTTP and WebSocket sequences with byte-level evidence."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SAFE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def expand(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, str):
        return VARIABLE.sub(lambda match: variables.get(match.group(1), match.group(0)), value)
    if isinstance(value, list):
        return [expand(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: expand(item, variables) for key, item in value.items()}
    return value


def campaign_record(root: Path) -> dict[str, Any]:
    path = root / "campaign.json"
    if not path.is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    value = json.loads(path.read_text(encoding="utf-8"))
    authorization = value.get("authorization") if isinstance(value, dict) else None
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise RuntimeError("protocol execution requires confirmed campaign authorization")
    return value


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_target(target: dict[str, Any], authorization: dict[str, Any]) -> None:
    host = str(target.get("host") or "")
    port = int(target.get("port") or 0)
    if not host or not (1 <= port <= 65535):
        raise RuntimeError("each target requires a valid host and port")
    if is_loopback(host):
        return
    allowed = authorization.get("protocolTargets")
    endpoint = f"{host}:{port}"
    if not isinstance(allowed, list) or endpoint not in {str(value) for value in allowed}:
        raise RuntimeError(
            f"remote target {endpoint} is not listed in authorization.protocolTargets"
        )


def body_bytes(body: Any, spec_root: Path, variables: dict[str, str]) -> bytes:
    if body is None:
        return b""
    if isinstance(body, str):
        return expand(body, variables).encode("utf-8")
    if not isinstance(body, dict):
        raise RuntimeError("body must be text or an object")
    if "text" in body:
        return expand(str(body["text"]), variables).encode(str(body.get("encoding") or "utf-8"))
    if "base64" in body:
        return base64.b64decode(expand(str(body["base64"]), variables), validate=True)
    if "file" in body:
        candidate = (spec_root / expand(str(body["file"]), variables)).resolve()
        candidate.relative_to(spec_root)
        return candidate.read_bytes()
    if "multipart" in body:
        multipart = body["multipart"]
        if not isinstance(multipart, dict):
            raise RuntimeError("multipart body must be an object")
        boundary = expand(str(multipart.get("boundary") or "krineon-boundary"), variables)
        output = bytearray()
        for part in multipart.get("parts", []):
            if not isinstance(part, dict):
                raise RuntimeError("multipart part must be an object")
            output.extend(f"--{boundary}\r\n".encode("ascii"))
            for name, value in header_pairs(part.get("headers", []), variables):
                output.extend(name + b": " + value + b"\r\n")
            output.extend(b"\r\n")
            output.extend(body_bytes(part.get("body"), spec_root, variables))
            output.extend(b"\r\n")
        output.extend(f"--{boundary}--\r\n".encode("ascii"))
        return bytes(output)
    raise RuntimeError("body object requires text, base64, file, or multipart")


def header_pairs(value: Any, variables: dict[str, str]) -> list[tuple[bytes, bytes]]:
    if not isinstance(value, list):
        raise RuntimeError("headers must be an ordered list to preserve duplicates")
    result: list[tuple[bytes, bytes]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise RuntimeError("each header must be [name, value]")
        name = expand(str(item[0]), variables).encode("latin-1")
        header_value = expand(str(item[1]), variables).encode("latin-1")
        if b"\r" in name + header_value or b"\n" in name + header_value:
            raise RuntimeError("header names and values cannot contain line breaks")
        result.append((name, header_value))
    return result


def encode_chunked(body: bytes, request: dict[str, Any]) -> bytes:
    configured = request.get("chunkSizes")
    sizes = [int(value) for value in configured] if isinstance(configured, list) else [len(body)]
    if any(value <= 0 for value in sizes):
        raise RuntimeError("chunk sizes must be positive")
    output = bytearray()
    offset = 0
    extension = str(request.get("chunkExtension") or "")
    for size in sizes:
        if offset >= len(body):
            break
        chunk = body[offset : offset + size]
        offset += len(chunk)
        suffix = f";{extension}" if extension else ""
        output.extend(f"{len(chunk):x}{suffix}\r\n".encode("ascii"))
        output.extend(chunk + b"\r\n")
    if offset < len(body):
        chunk = body[offset:]
        output.extend(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
    output.extend(b"0\r\n")
    for name, value in header_pairs(request.get("trailers", []), {}):
        output.extend(name + b": " + value + b"\r\n")
    output.extend(b"\r\n")
    return bytes(output)


def request_bytes(
    request: dict[str, Any],
    target: dict[str, Any],
    session: dict[str, Any],
    variables: dict[str, str],
    spec_root: Path,
) -> bytes:
    if "rawBase64" in request:
        return base64.b64decode(expand(str(request["rawBase64"]), variables), validate=True)
    method = expand(str(request.get("method") or "GET"), variables).encode("ascii")
    if "pathBase64" in request:
        path = base64.b64decode(expand(str(request["pathBase64"]), variables), validate=True)
    else:
        path = expand(str(request.get("path") or "/"), variables).encode("latin-1")
    version = str(request.get("version") or "HTTP/1.1").encode("ascii")
    headers = header_pairs(request.get("headers", []), variables)
    lower_names = [name.lower() for name, _ in headers]
    if b"host" not in lower_names:
        default_port = 443 if bool(target.get("tls")) else 80
        authority = str(target["host"])
        if int(target["port"]) != default_port:
            authority += f":{target['port']}"
        headers.append((b"Host", authority.encode("latin-1")))
        lower_names.append(b"host")
    cookies = session.get("cookies") if isinstance(session.get("cookies"), dict) else {}
    if cookies and b"cookie" not in lower_names:
        cookie_value = "; ".join(f"{name}={value}" for name, value in sorted(cookies.items()))
        headers.append((b"Cookie", cookie_value.encode("latin-1")))
        lower_names.append(b"cookie")
    body = body_bytes(request.get("body"), spec_root, variables)
    framing = str(request.get("framing") or "content-length")
    if framing == "chunked":
        if b"transfer-encoding" not in lower_names:
            headers.append((b"Transfer-Encoding", b"chunked"))
        wire_body = encode_chunked(body, request)
    elif framing == "content-length":
        if b"content-length" not in lower_names:
            headers.append((b"Content-Length", str(len(body)).encode("ascii")))
        wire_body = body
    elif framing == "manual":
        wire_body = body
    else:
        raise RuntimeError(f"unknown request framing: {framing}")
    if b"connection" not in lower_names:
        headers.append((b"Connection", b"close"))
    output = bytearray(method + b" " + path + b" " + version + b"\r\n")
    for name, value in headers:
        output.extend(name + b": " + value + b"\r\n")
    output.extend(b"\r\n" + wire_body)
    return bytes(output)


def open_socket(target: dict[str, Any], timeout: float) -> tuple[socket.socket, str | None]:
    connection = socket.create_connection((str(target["host"]), int(target["port"])), timeout)
    certificate_hash = None
    if bool(target.get("tls")):
        context = ssl.create_default_context()
        if target.get("insecureSkipVerify") is True:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        server_name = str(target.get("serverName") or target["host"])
        wrapped = context.wrap_socket(connection, server_hostname=server_name)
        certificate = wrapped.getpeercert(binary_form=True)
        certificate_hash = sha256_bytes(certificate) if certificate else None
        connection = wrapped
    connection.settimeout(timeout)
    return connection, certificate_hash


def receive_bytes(
    connection: socket.socket, *, timeout: float, max_bytes: int, idle_timeout: float
) -> tuple[bytes, list[dict[str, int]]]:
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    chunks: list[dict[str, int]] = []
    output = bytearray()
    while len(output) < max_bytes and time.monotonic() < deadline:
        connection.settimeout(min(idle_timeout, max(0.01, deadline - time.monotonic())))
        try:
            chunk = connection.recv(min(65536, max_bytes - len(output)))
        except socket.timeout:
            break
        if not chunk:
            break
        output.extend(chunk)
        chunks.append({"offset": len(output) - len(chunk), "size": len(chunk), "atNs": time.monotonic_ns() - started})
    return bytes(output), chunks


def decode_chunked(value: bytes, offset: int) -> tuple[bytes, int] | None:
    output = bytearray()
    cursor = offset
    while True:
        line_end = value.find(b"\r\n", cursor)
        if line_end < 0:
            return None
        token = value[cursor:line_end].split(b";", 1)[0]
        try:
            size = int(token, 16)
        except ValueError:
            return None
        cursor = line_end + 2
        if size == 0:
            trailer_end = value.find(b"\r\n\r\n", cursor)
            if trailer_end >= 0:
                return bytes(output), trailer_end + 4
            if value[cursor:cursor + 2] == b"\r\n":
                return bytes(output), cursor + 2
            return None
        if cursor + size + 2 > len(value) or value[cursor + size:cursor + size + 2] != b"\r\n":
            return None
        output.extend(value[cursor:cursor + size])
        cursor += size + 2


def parse_responses(raw: bytes) -> list[dict[str, Any]]:
    responses: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(raw):
        header_end = raw.find(b"\r\n\r\n", cursor)
        if header_end < 0:
            break
        lines = raw[cursor:header_end].split(b"\r\n")
        status_parts = lines[0].split(b" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            break
        headers: list[list[str]] = []
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            headers.append([name.decode("latin-1"), value.lstrip().decode("latin-1")])
        body_start = header_end + 4
        lower: dict[str, list[str]] = {}
        for name, value in headers:
            lower.setdefault(name.lower(), []).append(value)
        transfer = ",".join(lower.get("transfer-encoding", [])).lower()
        if "chunked" in transfer:
            decoded = decode_chunked(raw, body_start)
            if decoded is None:
                body, end = raw[body_start:], len(raw)
            else:
                body, end = decoded
        elif lower.get("content-length"):
            try:
                length = int(lower["content-length"][-1])
            except ValueError:
                length = len(raw) - body_start
            end = min(len(raw), body_start + max(0, length))
            body = raw[body_start:end]
        else:
            body, end = raw[body_start:], len(raw)
        responses.append({
            "version": status_parts[0].decode("latin-1"),
            "status": int(status_parts[1]),
            "reason": status_parts[2].decode("latin-1") if len(status_parts) > 2 else "",
            "headers": headers,
            "body": body,
            "bodySha256": sha256_bytes(body),
            "bodySize": len(body),
        })
        if end <= cursor:
            break
        cursor = end
    return responses


def update_cookies(session: dict[str, Any], responses: list[dict[str, Any]]) -> None:
    cookies = session.setdefault("cookies", {})
    for response in responses:
        for name, value in response["headers"]:
            if name.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0]
            if "=" not in pair:
                continue
            cookie_name, cookie_value = pair.split("=", 1)
            cookies[cookie_name.strip()] = cookie_value.strip()


def assertion_results(assertions: Any, responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values = assertions if isinstance(assertions, list) else []
    last = responses[-1] if responses else {"status": None, "body": b"", "headers": []}
    retained: list[dict[str, Any]] = []
    for index, assertion in enumerate(values):
        if not isinstance(assertion, dict):
            raise RuntimeError("assertion must be an object")
        kind = str(assertion.get("kind") or "")
        expected = assertion.get("equals", assertion.get("value"))
        if kind == "status":
            observed, matched = last["status"], last["status"] == int(expected)
        elif kind == "response-count":
            observed, matched = len(responses), len(responses) == int(expected)
        elif kind in {"body-contains", "body-not-contains"}:
            needle = str(expected).encode("utf-8")
            present = needle in last["body"]
            observed = present
            matched = present if kind == "body-contains" else not present
        elif kind == "body-sha256":
            observed, matched = last.get("bodySha256"), last.get("bodySha256") == str(expected)
        elif kind == "header-equals":
            header_name = str(assertion.get("name") or "").lower()
            observed = [value for name, value in last["headers"] if name.lower() == header_name]
            matched = str(expected) in observed
        else:
            raise RuntimeError(f"unknown assertion kind: {kind}")
        retained.append({"id": str(assertion.get("id") or f"assertion-{index + 1}"), "kind": kind, "matched": matched, "observed": observed})
    return retained


def retained_responses(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in response.items() if key != "body"}
        for response in responses
    ]


class SequenceRunner:
    def __init__(self, root: Path, spec_path: Path, spec: dict[str, Any], output: Path):
        self.root = root
        self.spec_path = spec_path
        self.spec_root = spec_path.parent
        self.spec = spec
        self.output = output
        self.targets = spec["targets"]
        self.sessions = spec.get("sessions", {})
        self.variables = {str(key): str(value) for key, value in spec.get("variables", {}).items()}
        self.lock = threading.Lock()

    def variables_for(self, session_name: str) -> dict[str, str]:
        values = dict(self.variables)
        session = self.sessions[session_name]
        values.update({str(key): str(value) for key, value in session.get("variables", {}).items()})
        return values

    def redirect_target(self, url: str, current_name: str) -> tuple[str, str]:
        current = self.targets[current_name]
        base_scheme = "https" if bool(current.get("tls")) else "http"
        base = f"{base_scheme}://{current['host']}:{current['port']}/"
        resolved = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlsplit(resolved)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        for name, target in self.targets.items():
            if (
                str(target["host"]).lower() == str(parsed.hostname or "").lower()
                and int(target["port"]) == port
                and bool(target.get("tls")) == (parsed.scheme == "https")
            ):
                path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                return name, path
        raise RuntimeError(f"redirect leaves the declared target set: {resolved}")

    def execute_request(self, step_id: str, definition: dict[str, Any], ordinal: str = "0") -> dict[str, Any]:
        target_name = str(definition["target"])
        session_name = str(definition.get("session") or "anonymous")
        if target_name not in self.targets or session_name not in self.sessions:
            raise RuntimeError(f"unknown target or session in {step_id}")
        with self.lock:
            variables = self.variables_for(session_name)
        current_request = expand(definition.get("request", {}), variables)
        current_target_name = target_name
        redirect_limit = int(definition.get("maxRedirects", 0))
        started = time.time_ns()
        exchanges: list[dict[str, Any]] = []
        for hop in range(redirect_limit + 1):
            current_target = self.targets[current_target_name]
            with self.lock:
                session_snapshot = json.loads(json.dumps(self.sessions[session_name]))
            wire = request_bytes(current_request, current_target, session_snapshot, variables, self.spec_root)
            connection, certificate_hash = open_socket(current_target, float(definition.get("connectTimeout", 5)))
            try:
                connection.sendall(wire)
                raw, chunks = receive_bytes(
                    connection,
                    timeout=float(definition.get("timeout", 10)),
                    max_bytes=int(definition.get("maxResponseBytes", 16 * 1024 * 1024)),
                    idle_timeout=float(definition.get("idleTimeout", 0.5)),
                )
            finally:
                connection.close()
            responses = parse_responses(raw)
            with self.lock:
                update_cookies(self.sessions[session_name], responses)
            exchanges.append({
                "target": current_target_name,
                "wire": wire,
                "raw": raw,
                "chunks": chunks,
                "responses": responses,
                "certificate": certificate_hash,
            })
            if hop >= redirect_limit or not responses or responses[-1]["status"] not in {301, 302, 303, 307, 308}:
                break
            locations = [value for name, value in responses[-1]["headers"] if name.lower() == "location"]
            if not locations:
                break
            current_target_name, redirected_path = self.redirect_target(locations[-1], current_target_name)
            method = str(current_request.get("method") or "GET").upper()
            current_request = dict(current_request)
            current_request["path"] = redirected_path
            current_request.pop("pathBase64", None)
            current_request["headers"] = [
                pair
                for pair in current_request.get("headers", [])
                if str(pair[0]).lower() not in {"host", "content-length", "transfer-encoding", "connection", "cookie"}
            ]
            if responses[-1]["status"] == 303 or (responses[-1]["status"] in {301, 302} and method == "POST"):
                current_request["method"] = "GET"
                current_request.pop("body", None)
                current_request["framing"] = "content-length"
        finished = time.time_ns()
        run_dir = self.output / "steps" / step_id / ordinal
        run_dir.mkdir(parents=True, exist_ok=True)
        retained_exchanges: list[dict[str, Any]] = []
        for hop, exchange in enumerate(exchanges):
            request_path = run_dir / f"request-{hop}.bin"
            response_path = run_dir / f"response-{hop}.bin"
            request_path.write_bytes(exchange["wire"])
            response_path.write_bytes(exchange["raw"])
            retained_exchanges.append({
                "target": exchange["target"],
                "request": {"path": request_path.relative_to(self.output).as_posix(), "sha256": sha256_bytes(exchange["wire"]), "size": len(exchange["wire"])},
                "response": {"path": response_path.relative_to(self.output).as_posix(), "sha256": sha256_bytes(exchange["raw"]), "size": len(exchange["raw"]), "chunks": exchange["chunks"], "messages": retained_responses(exchange["responses"])},
                "peerCertificateSha256": exchange["certificate"],
            })
        responses = exchanges[-1]["responses"] if exchanges else []
        assertions = assertion_results(definition.get("assertions"), responses)
        record = {
            "target": target_name,
            "session": session_name,
            "startedNs": started,
            "finishedNs": finished,
            "request": retained_exchanges[0]["request"],
            "response": retained_exchanges[-1]["response"],
            "peerCertificateSha256": retained_exchanges[-1]["peerCertificateSha256"],
            "redirectChain": retained_exchanges,
            "assertions": assertions,
            "passed": bool(responses) and all(value["matched"] for value in assertions),
        }
        self.extract(definition.get("extract"), responses, session_name)
        return record

    def extract(self, definitions: Any, responses: list[dict[str, Any]], session_name: str) -> None:
        if not isinstance(definitions, list) or not responses:
            return
        last = responses[-1]
        for definition in definitions:
            if not isinstance(definition, dict) or not definition.get("name"):
                raise RuntimeError("extract entries require a name")
            source = str(definition.get("from") or "body-regex")
            if source == "body-regex":
                match = re.search(str(definition["pattern"]), last["body"].decode("utf-8", "replace"))
                if not match:
                    raise RuntimeError(f"extract {definition['name']} did not match")
                value = match.group(int(definition.get("group", 1)))
            elif source == "header":
                header_name = str(definition["header"]).lower()
                matches = [value for name, value in last["headers"] if name.lower() == header_name]
                if not matches:
                    raise RuntimeError(f"extract {definition['name']} header absent")
                value = matches[-1]
            elif source == "json":
                value: Any = json.loads(last["body"])
                for part in str(definition["path"]).split("."):
                    value = value[int(part)] if isinstance(value, list) else value[part]
                value = str(value)
            else:
                raise RuntimeError(f"unknown extraction source: {source}")
            with self.lock:
                if str(definition.get("scope") or "session") == "global":
                    self.variables[str(definition["name"])] = value
                else:
                    self.sessions[session_name].setdefault("variables", {})[str(definition["name"])] = value

    def execute_websocket(self, step_id: str, definition: dict[str, Any]) -> dict[str, Any]:
        target_name = str(definition["target"])
        session_name = str(definition.get("session") or "anonymous")
        target = self.targets[target_name]
        variables = self.variables_for(session_name)
        request = expand(definition.get("request", {}), variables)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        headers = list(request.get("headers", []))
        headers.extend([["Upgrade", "websocket"], ["Connection", "Upgrade"], ["Sec-WebSocket-Version", "13"], ["Sec-WebSocket-Key", key]])
        request["headers"] = headers
        request["framing"] = "manual"
        wire = request_bytes(request, target, self.sessions[session_name], variables, self.spec_root)
        connection, certificate_hash = open_socket(target, float(definition.get("connectTimeout", 5)))
        connection.sendall(wire)
        handshake = bytearray()
        while b"\r\n\r\n" not in handshake and len(handshake) < 65536:
            handshake.extend(connection.recv(4096))
        parsed = parse_responses(bytes(handshake))
        sent_frames: list[dict[str, Any]] = []
        received_frames: list[dict[str, Any]] = []
        if parsed and parsed[-1]["status"] == 101:
            for index, frame in enumerate(definition.get("frames", [])):
                payload = body_bytes(frame.get("body", ""), self.spec_root, variables)
                opcode = int(frame.get("opcode", 1))
                mask = secrets.token_bytes(4)
                first = 0x80 | opcode
                length = len(payload)
                if length < 126:
                    header = bytes([first, 0x80 | length])
                elif length <= 65535:
                    header = bytes([first, 0x80 | 126]) + struct.pack("!H", length)
                else:
                    header = bytes([first, 0x80 | 127]) + struct.pack("!Q", length)
                masked = bytes(value ^ mask[position % 4] for position, value in enumerate(payload))
                encoded = header + mask + masked
                connection.sendall(encoded)
                sent_frames.append({"index": index, "opcode": opcode, "payloadSha256": sha256_bytes(payload), "size": len(payload)})
                connection.settimeout(float(definition.get("timeout", 5)))
                response_header = connection.recv(2)
                if len(response_header) < 2:
                    break
                response_opcode = response_header[0] & 0x0F
                response_length = response_header[1] & 0x7F
                if response_length == 126:
                    response_length = struct.unpack("!H", connection.recv(2))[0]
                elif response_length == 127:
                    response_length = struct.unpack("!Q", connection.recv(8))[0]
                response_payload = b""
                while len(response_payload) < response_length:
                    response_payload += connection.recv(response_length - len(response_payload))
                received_frames.append({"index": index, "opcode": response_opcode, "payloadSha256": sha256_bytes(response_payload), "size": len(response_payload), "text": response_payload.decode("utf-8", "replace") if response_opcode == 1 else None})
        connection.close()
        run_dir = self.output / "steps" / step_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "handshake-request.bin").write_bytes(wire)
        (run_dir / "handshake-response.bin").write_bytes(bytes(handshake))
        expected_text = definition.get("expectText")
        passed = bool(parsed and parsed[-1]["status"] == 101)
        if expected_text is not None:
            passed = passed and any(item.get("text") == str(expected_text) for item in received_frames)
        return {"target": target_name, "session": session_name, "peerCertificateSha256": certificate_hash, "handshake": retained_responses(parsed), "sentFrames": sent_frames, "receivedFrames": received_frames, "passed": passed}

    def run_step(self, step: dict[str, Any]) -> dict[str, Any]:
        step_id = str(step["id"])
        kind = str(step.get("type") or "request")
        if kind == "request":
            result = self.execute_request(step_id, step)
        elif kind == "concurrent":
            requests = step.get("requests")
            if not isinstance(requests, list) or not requests:
                raise RuntimeError("concurrent step requires requests")
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(step.get("maxWorkers", len(requests)))) as executor:
                futures = [executor.submit(self.execute_request, step_id, request, str(index)) for index, request in enumerate(requests)]
                runs = [future.result() for future in futures]
            result = {"runs": runs, "passed": all(run["passed"] for run in runs)}
        elif kind == "differential":
            target_names = step.get("targets")
            if not isinstance(target_names, list) or len(target_names) < 2:
                raise RuntimeError("differential step requires at least two targets")
            runs = []
            for index, target_name in enumerate(target_names):
                definition = dict(step)
                definition["target"] = target_name
                definition["assertions"] = []
                runs.append(self.execute_request(step_id, definition, str(index)))
            signatures = [
                [(message["status"], message["bodySha256"], message["bodySize"]) for message in run["response"]["messages"]]
                for run in runs
            ]
            disagreement = any(value != signatures[0] for value in signatures[1:])
            expected = bool(step.get("expectDisagreement", True))
            result = {"runs": runs, "signatures": signatures, "disagreement": disagreement, "passed": disagreement == expected}
        elif kind == "websocket":
            result = self.execute_websocket(step_id, step)
        else:
            raise RuntimeError(f"unknown step type: {kind}")
        result["id"] = step_id
        result["type"] = kind
        return result


def validate_state_model(value: Any, step_ids: list[str]) -> dict[str, Any]:
    if value is None:
        return {
            "initialState": "unspecified",
            "transitions": [],
            "requiredTransitionPairs": [],
            "reductionMustPreserve": [],
        }
    if not isinstance(value, dict):
        raise RuntimeError("stateModel must be an object")
    initial = str(value.get("initialState") or "").strip()
    if not initial:
        raise RuntimeError("stateModel.initialState is required")
    raw_transitions = value.get("transitions")
    if not isinstance(raw_transitions, list) or not raw_transitions:
        raise RuntimeError("stateModel.transitions must be a non-empty list")
    order = {step_id: index for index, step_id in enumerate(step_ids)}
    transitions: list[dict[str, str]] = []
    prior = initial
    previous_index = -1
    for index, raw in enumerate(raw_transitions):
        field = f"stateModel.transitions[{index}]"
        if not isinstance(raw, dict):
            raise RuntimeError(f"{field} must be an object")
        normalized = {
            name: str(raw.get(name) or "").strip()
            for name in (
                "stepId",
                "from",
                "to",
                "operation",
                "authorityBefore",
                "authorityAfter",
                "ownershipBefore",
                "ownershipAfter",
                "invariant",
            )
        }
        missing = [name for name, content in normalized.items() if not content]
        if missing:
            raise RuntimeError(f"{field} is missing: {', '.join(missing)}")
        if normalized["stepId"] not in order:
            raise RuntimeError(f"{field}.stepId does not name a protocol step")
        if order[normalized["stepId"]] <= previous_index:
            raise RuntimeError("state transitions must follow protocol step order")
        if normalized["from"] != prior:
            raise RuntimeError(
                f"{field}.from must continue state {prior!r}"
            )
        previous_index = order[normalized["stepId"]]
        prior = normalized["to"]
        transitions.append(normalized)
    raw_pairs = value.get("requiredTransitionPairs")
    if not isinstance(raw_pairs, list) or not raw_pairs:
        raise RuntimeError("stateModel.requiredTransitionPairs must be non-empty")
    pairs: list[list[str]] = []
    for index, pair in enumerate(raw_pairs):
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) and item.strip() for item in pair)
        ):
            raise RuntimeError(
                f"stateModel.requiredTransitionPairs[{index}] must be [from, to]"
            )
        pairs.append([pair[0].strip(), pair[1].strip()])
    preserve = value.get("reductionMustPreserve")
    if not isinstance(preserve, list) or not preserve or not all(
        isinstance(item, str) and item.strip() for item in preserve
    ):
        raise RuntimeError("stateModel.reductionMustPreserve must be non-empty text")
    return {
        "initialState": initial,
        "transitions": transitions,
        "requiredTransitionPairs": pairs,
        "reductionMustPreserve": list(dict.fromkeys(item.strip() for item in preserve)),
    }


def state_trace(
    state_model: dict[str, Any], retained_steps: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_step = {str(step["id"]): step for step in retained_steps}
    trace: list[dict[str, Any]] = []
    exercised: set[tuple[str, str]] = set()
    for transition in state_model["transitions"]:
        passed = bool(by_step[transition["stepId"]]["passed"])
        record = {**transition, "exercised": passed}
        trace.append(record)
        if passed:
            exercised.add((transition["from"], transition["to"]))
    required = [tuple(pair) for pair in state_model["requiredTransitionPairs"]]
    missing = [list(pair) for pair in required if pair not in exercised]
    coverage = {
        "declared": [list(pair) for pair in required],
        "exercised": [list(pair) for pair in sorted(exercised)],
        "missing": missing,
        "passed": not missing,
    }
    return trace, coverage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    args = parser.parse_args(argv)
    try:
        root = args.campaign.expanduser().resolve()
        campaign = campaign_record(root)
        spec_path = args.spec.expanduser().resolve()
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or spec.get("schemaVersion") != 1:
            raise RuntimeError("protocol spec must be a schemaVersion 1 object")
        variables = {str(key): str(value) for key, value in spec.get("variables", {}).items()}
        for value in args.var:
            if "=" not in value:
                raise RuntimeError("--var requires NAME=VALUE")
            name, content = value.split("=", 1)
            variables[name] = content
        spec["variables"] = variables
        expanded_targets = expand(spec.get("targets"), variables)
        if not isinstance(expanded_targets, dict) or not expanded_targets:
            raise RuntimeError("protocol spec requires targets")
        spec["targets"] = expanded_targets
        authorization = campaign["authorization"]
        for target in spec["targets"].values():
            if not isinstance(target, dict):
                raise RuntimeError("target definitions must be objects")
            validate_target(target, authorization)
        sessions = spec.get("sessions")
        if not isinstance(sessions, dict):
            sessions = {}
        sessions.setdefault("anonymous", {"role": "anonymous", "tenant": None, "cookies": {}, "variables": {}})
        spec["sessions"] = sessions
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps:
            raise RuntimeError("protocol spec requires at least one step")
        ids = [str(step.get("id") or "") for step in steps if isinstance(step, dict)]
        if len(ids) != len(steps) or len(set(ids)) != len(ids) or not all(SAFE_ID.fullmatch(value) for value in ids):
            raise RuntimeError("step IDs must be unique safe identifiers")
        state_model = validate_state_model(spec.get("stateModel"), ids)
        output = args.output.expanduser().resolve()
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        runner = SequenceRunner(root, spec_path, spec, output)
        retained_steps = [runner.run_step(step) for step in steps]
        trace, transition_coverage = state_trace(state_model, retained_steps)
        session_summary = {
            name: {
                "role": value.get("role"),
                "tenant": value.get("tenant"),
                "cookieHashes": {key: sha256_bytes(str(content).encode()) for key, content in value.get("cookies", {}).items()},
                "variableHashes": {key: sha256_bytes(str(content).encode()) for key, content in value.get("variables", {}).items()},
            }
            for name, value in runner.sessions.items()
        }
        result = {
            "schemaVersion": 1,
            "producer": "krineon-http-protocol-harness",
            "runId": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8],
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "campaignCommit": campaign.get("commit"),
            "spec": {"path": str(spec_path), "sha256": sha256_file(spec_path)},
            "harness": {"path": str(Path(__file__).resolve()), "sha256": sha256_file(Path(__file__).resolve())},
            "targets": spec["targets"],
            "steps": retained_steps,
            "stateTrace": trace,
            "transitionCoverage": transition_coverage,
            "reductionContract": {
                "mustPreserve": state_model["reductionMustPreserve"],
                "historySensitive": bool(state_model["transitions"]),
            },
            "sessions": session_summary,
            "status": (
                "passed"
                if all(step["passed"] for step in retained_steps)
                and transition_coverage["passed"]
                else "failed"
            ),
        }
        write_json(output / "protocol-run.json", result)
        print(output / "protocol-run.json")
        return 0 if result["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError, socket.error, ssl.SSLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
