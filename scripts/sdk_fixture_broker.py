#!/usr/bin/env python3
"""Run a hash-pinned application fixture behind private secrets and egress policy.

The historical module name is retained for compatibility.  Schema version 2 is
provider-neutral: a coordinator supplies a pinned command, typed operations,
secret-to-environment bindings, exact endpoint policy, and bounded budgets.
Workers receive an opaque fixture identifier and a loopback control API; they
never receive fixture credentials or unrestricted process execution.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from web_contract import WebContractError, atomic_json
from web_secret_store import SecretStore


FIXTURE_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
WORKER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
OPERATION_ID = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
DNS_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
DEFAULT_RPC_PREFIX = "KRINEON_RPC "
MAX_CONTROL_BODY = 64 * 1024
MAX_LOG_LINE = 256 * 1024
DEFAULT_BUDGETS = {
    "maxOperations": 250,
    "maxProxyConnections": 256,
    "maxProxyBytes": 128 * 1024 * 1024,
}


class BrokerError(RuntimeError):
    """A broker configuration, policy, or runtime failure."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def private_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def require_dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerError(f"{field} must be an object")
    return value


def require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise BrokerError(f"{field} must be an array")
    return value


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BrokerError(f"{field} must be a non-empty string")
    return value.strip()


def resolved_path(value: Any, field: str, *, base: Path) -> Path:
    raw = Path(require_string(value, field)).expanduser()
    return (raw if raw.is_absolute() else base / raw).resolve()


@dataclass(frozen=True)
class SecretBinding:
    store: Path
    reference: str
    version: str | None
    environment: str
    prefix: str
    min_length: int
    max_length: int
    pattern: str | None


@dataclass(frozen=True)
class EndpointPolicy:
    host: str
    port: int
    allow_private: bool


@dataclass(frozen=True)
class OperationPolicy:
    kind: str
    max_calls: int
    max_payload_bytes: int
    allowed_fields: frozenset[str]
    required_fields: frozenset[str]
    field_types: dict[str, str]
    allow_additional_fields: bool


@dataclass(frozen=True)
class BrokerConfig:
    source: Path
    schema_version: int
    fixture_id: str
    application_id: str
    provider: str | None
    campaign_root: Path
    working_directory: Path
    command: tuple[str, ...]
    artifact_hashes: dict[Path, str]
    secret_bindings: tuple[SecretBinding, ...]
    environment: dict[str, str]
    approved_endpoints: tuple[EndpointPolicy, ...]
    operation_policies: dict[str, OperationPolicy]
    rpc_prefix: str
    ready_event: str
    shutdown_operation: str
    export_standard_proxy_environment: bool
    budgets: dict[str, int]
    startup_timeout: int
    operation_timeout: int
    evidence_directory: Path
    descriptor_path: Path
    pid_path: Path

    @property
    def allowed_operations(self) -> frozenset[str]:
        return frozenset(self.operation_policies)

    @property
    def approved_hosts(self) -> frozenset[str]:
        return frozenset(endpoint.host for endpoint in self.approved_endpoints)

    # Compatibility accessors for callers that inspect schema-v1 fields.
    @property
    def secret_store(self) -> Path:
        return self.secret_bindings[0].store

    @property
    def secret_ref(self) -> str:
        return self.secret_bindings[0].reference

    @property
    def secret_version(self) -> str | None:
        return self.secret_bindings[0].version


def _legacy_configuration(raw: dict[str, Any]) -> dict[str, Any]:
    """Translate the original LaunchDarkly schema into the universal model."""
    if raw.get("provider") != "launchdarkly-node":
        raise BrokerError("schemaVersion 1 supports only provider launchdarkly-node")
    budgets = require_dict(raw.get("budgets", {}), "budgets")
    operation_limits = {
        "evaluate": int(budgets.get("maxEvaluations", 150)),
        "set-context": int(budgets.get("maxContextChanges", 25)),
        "track": int(budgets.get("maxTrackEvents", 25)),
        "restart": int(budgets.get("maxRestarts", 8)),
    }
    operation_fields = {
        "status": ("broker", [], [], {}),
        "evaluate": (
            "fixture",
            ["flagKey", "defaultValue", "context"],
            ["flagKey"],
            {"flagKey": "string", "defaultValue": "any", "context": "object"},
        ),
        "set-context": ("fixture", ["context"], ["context"], {"context": "object"}),
        "track": (
            "fixture",
            ["eventKey", "data", "context"],
            ["eventKey"],
            {"eventKey": "string", "data": "any", "context": "object"},
        ),
        "restart": ("broker", [], [], {}),
        "shutdown": ("broker", [], [], {}),
    }
    admitted = require_list(raw.get("allowedOperations"), "allowedOperations")
    operations: dict[str, Any] = {}
    for name_value in admitted:
        name = require_string(name_value, "allowedOperations[]")
        if name not in operation_fields:
            raise BrokerError(f"schemaVersion 1 operation is unsupported: {name}")
        kind, allowed, required, types = operation_fields[name]
        operations[name] = {
            "kind": kind,
            "maxCalls": operation_limits.get(name, 0),
            "maxPayloadBytes": 16384,
            "allowedFields": allowed,
            "requiredFields": required,
            "fieldTypes": types,
        }
    legacy_hosts = [
        require_string(host, "approvedHosts[]").lower()
        for host in require_list(raw.get("approvedHosts"), "approvedHosts")
    ]
    launchdarkly_hosts = {
        "stream.launchdarkly.com",
        "sdk.launchdarkly.com",
        "events.launchdarkly.com",
    }
    if not legacy_hosts or not set(legacy_hosts).issubset(launchdarkly_hosts):
        raise BrokerError(
            "schemaVersion 1 approvedHosts must use documented LaunchDarkly SDK hosts"
        )
    return {
        "schemaVersion": 2,
        "provider": "launchdarkly-node",
        "fixtureId": raw.get("fixtureId"),
        "applicationId": "launchdarkly-node-server-sdk",
        "campaignRoot": raw.get("campaignRoot"),
        "workingDirectory": raw.get("workingDirectory"),
        "command": {
            "executable": raw.get("nodeExecutable", "node"),
            "arguments": [raw.get("entrypoint")],
        },
        "artifacts": raw.get("artifacts"),
        "secrets": [
            {
                **require_dict(raw.get("secret"), "secret"),
                "environment": "LAUNCHDARKLY_SDK_KEY",
                "prefix": "sdk-",
                "minLength": 24,
                "maxLength": 516,
                "pattern": "^sdk-[A-Za-z0-9_-]{20,512}$",
            }
        ],
        "environment": {
            "KRINEON_SDK_BROKER_MODE": "1",
        },
        "approvedEndpoints": [
            {"host": host, "port": 443, "allowPrivate": False}
            for host in legacy_hosts
        ],
        "protocol": {
            "rpcPrefix": DEFAULT_RPC_PREFIX,
            "readyEvent": "ready",
            "shutdownOperation": "shutdown",
        },
        "operations": operations,
        "proxy": {"exportStandardEnvironment": False},
        "budgets": {
            "maxOperations": budgets.get("maxOperations", 250),
            "maxProxyConnections": budgets.get("maxProxyConnections", 256),
            "maxProxyBytes": budgets.get("maxProxyBytes", 128 * 1024 * 1024),
        },
        "startupTimeoutSeconds": raw.get("startupTimeoutSeconds", 30),
        "operationTimeoutSeconds": raw.get("operationTimeoutSeconds", 15),
    }


def _positive_integer(value: Any, field: str, *, allow_zero: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BrokerError(f"{field} must be an integer")
    if value < 0 if allow_zero else value <= 0:
        qualifier = "non-negative" if allow_zero else "positive"
        raise BrokerError(f"{field} must be a {qualifier} integer")
    return value


def _operation_policy(name: str, value: Any) -> OperationPolicy:
    raw = require_dict(value, f"operations.{name}")
    kind = require_string(raw.get("kind", "fixture"), f"operations.{name}.kind")
    if kind not in {"fixture", "broker"}:
        raise BrokerError(f"operations.{name}.kind must be fixture or broker")
    max_calls = _positive_integer(
        raw.get("maxCalls", 0), f"operations.{name}.maxCalls", allow_zero=True
    )
    max_payload = _positive_integer(
        raw.get("maxPayloadBytes", 16384), f"operations.{name}.maxPayloadBytes"
    )
    if max_payload > MAX_CONTROL_BODY:
        raise BrokerError(f"operations.{name}.maxPayloadBytes exceeds the control limit")
    allowed = frozenset(
        require_string(item, f"operations.{name}.allowedFields[]")
        for item in require_list(raw.get("allowedFields", []), f"operations.{name}.allowedFields")
    )
    required = frozenset(
        require_string(item, f"operations.{name}.requiredFields[]")
        for item in require_list(raw.get("requiredFields", []), f"operations.{name}.requiredFields")
    )
    if not required.issubset(allowed):
        raise BrokerError(f"operations.{name}.requiredFields must be allowed")
    types_raw = require_dict(raw.get("fieldTypes", {}), f"operations.{name}.fieldTypes")
    supported = {"any", "string", "object", "array", "boolean", "number", "null"}
    field_types: dict[str, str] = {}
    for field, type_name_value in types_raw.items():
        if field not in allowed:
            raise BrokerError(f"operations.{name}.fieldTypes contains an unlisted field")
        type_name = require_string(type_name_value, f"operations.{name}.fieldTypes.{field}")
        if type_name not in supported:
            raise BrokerError(f"operations.{name}.fieldTypes.{field} is unsupported")
        field_types[field] = type_name
    return OperationPolicy(
        kind=kind,
        max_calls=max_calls,
        max_payload_bytes=max_payload,
        allowed_fields=allowed,
        required_fields=required,
        field_types=field_types,
        allow_additional_fields=bool(raw.get("allowAdditionalFields", False)),
    )


def load_config(path: Path | str) -> BrokerConfig:
    source = Path(path).expanduser().resolve()
    if source.is_symlink() or not source.is_file():
        raise BrokerError("broker configuration must be a regular non-symlink file")
    raw = require_dict(json.loads(source.read_text(encoding="utf-8")), "configuration")
    original_schema = raw.get("schemaVersion")
    if original_schema == 1:
        raw = _legacy_configuration(raw)
    elif original_schema != 2:
        raise BrokerError("broker configuration requires schemaVersion 1 or 2")
    fixture_id = require_string(raw.get("fixtureId"), "fixtureId")
    if not FIXTURE_ID.fullmatch(fixture_id):
        raise BrokerError("fixtureId must be a lowercase stable identifier")

    base = source.parent
    campaign_root = resolved_path(raw.get("campaignRoot"), "campaignRoot", base=base)
    campaign_root.mkdir(parents=True, exist_ok=True)
    working = resolved_path(raw.get("workingDirectory"), "workingDirectory", base=base)
    if not working.is_dir():
        raise BrokerError("workingDirectory must exist")
    application_id = require_string(raw.get("applicationId"), "applicationId")
    command_raw = require_dict(raw.get("command"), "command")
    executable_value = require_string(command_raw.get("executable"), "command.executable")
    located = shutil.which(executable_value) if "/" not in executable_value else executable_value
    if not located:
        raise BrokerError("command.executable is unavailable")
    executable = Path(located).expanduser().resolve()
    if not executable.is_file():
        raise BrokerError("command.executable must resolve to a regular file")
    arguments = tuple(
        require_string(item, "command.arguments[]")
        for item in require_list(command_raw.get("arguments", []), "command.arguments")
    )
    command = (str(executable), *arguments)

    artifacts_raw = require_list(raw.get("artifacts"), "artifacts")
    if not artifacts_raw:
        raise BrokerError("artifacts must pin every fixture-controlled executable input")
    artifact_hashes: dict[Path, str] = {}
    for index, item in enumerate(artifacts_raw):
        artifact = require_dict(item, f"artifacts[{index}]")
        artifact_path = resolved_path(
            artifact.get("path"), f"artifacts[{index}].path", base=working
        )
        expected = require_string(
            artifact.get("sha256"), f"artifacts[{index}].sha256"
        )
        if not SHA256.fullmatch(expected):
            raise BrokerError(f"artifacts[{index}].sha256 must be lowercase SHA-256")
        if not artifact_path.is_file() or not inside(artifact_path, working):
            raise BrokerError(f"artifacts[{index}].path must be inside workingDirectory")
        actual = sha256_file(artifact_path)
        if not hmac.compare_digest(actual, expected):
            raise BrokerError(
                f"artifact hash mismatch for {artifact_path}: expected {expected}, observed {actual}"
            )
        artifact_hashes[artifact_path] = expected
    controlled_command_paths: set[Path] = set()
    if inside(executable, working):
        controlled_command_paths.add(executable)
    for argument in arguments:
        candidate = (working / argument).resolve()
        if candidate.is_file() and inside(candidate, working):
            controlled_command_paths.add(candidate)
    missing = controlled_command_paths.difference(artifact_hashes)
    if missing:
        raise BrokerError(
            "artifacts must include command-controlled files: "
            + ", ".join(sorted(path.name for path in missing))
        )

    secret_bindings: list[SecretBinding] = []
    used_environment: set[str] = set()
    for index, item in enumerate(require_list(raw.get("secrets", []), "secrets")):
        secret = require_dict(item, f"secrets[{index}]")
        store = resolved_path(secret.get("store"), f"secrets[{index}].store", base=base)
        if inside(store, campaign_root) or inside(store, working):
            raise BrokerError("secret stores must be outside the campaign and fixture worktree")
        reference = require_string(secret.get("reference"), f"secrets[{index}].reference")
        if not reference.startswith("secret://"):
            raise BrokerError(f"secrets[{index}].reference must use secret://")
        version = secret.get("version")
        if version is not None:
            version = require_string(version, f"secrets[{index}].version")
        environment_name = require_string(
            secret.get("environment"), f"secrets[{index}].environment"
        )
        if not ENVIRONMENT_NAME.fullmatch(environment_name) or environment_name in used_environment:
            raise BrokerError("secret environment names must be unique valid identifiers")
        used_environment.add(environment_name)
        min_length = _positive_integer(
            secret.get("minLength", 1), f"secrets[{index}].minLength"
        )
        max_length = _positive_integer(
            secret.get("maxLength", 16384), f"secrets[{index}].maxLength"
        )
        if min_length > max_length:
            raise BrokerError(f"secrets[{index}] has an invalid length range")
        prefix_value = secret.get("prefix", "")
        if not isinstance(prefix_value, str):
            raise BrokerError(f"secrets[{index}].prefix must be a string")
        pattern_value = secret.get("pattern")
        if pattern_value is not None:
            pattern_value = require_string(pattern_value, f"secrets[{index}].pattern")
            try:
                re.compile(pattern_value)
            except re.error as exc:
                raise BrokerError(f"secrets[{index}].pattern is invalid") from exc
        secret_bindings.append(
            SecretBinding(
                store=store,
                reference=reference,
                version=version,
                environment=environment_name,
                prefix=prefix_value,
                min_length=min_length,
                max_length=max_length,
                pattern=pattern_value,
            )
        )

    endpoints: list[EndpointPolicy] = []
    seen_endpoints: set[tuple[str, int]] = set()
    for index, item in enumerate(
        require_list(raw.get("approvedEndpoints", []), "approvedEndpoints")
    ):
        endpoint = require_dict(item, f"approvedEndpoints[{index}]")
        host = require_string(endpoint.get("host"), f"approvedEndpoints[{index}].host").lower()
        try:
            ipaddress.ip_address(host)
            valid_host = True
        except ValueError:
            valid_host = bool(DNS_HOST.fullmatch(host))
        if not valid_host:
            raise BrokerError("approved endpoint hosts must be exact DNS names or IP literals")
        port = _positive_integer(endpoint.get("port", 443), f"approvedEndpoints[{index}].port")
        if port > 65535 or (host, port) in seen_endpoints:
            raise BrokerError("approved endpoints must be unique and use a valid port")
        seen_endpoints.add((host, port))
        endpoints.append(EndpointPolicy(host, port, bool(endpoint.get("allowPrivate", False))))
    operations_raw = require_dict(raw.get("operations"), "operations")
    operation_policies: dict[str, OperationPolicy] = {}
    for name, value in operations_raw.items():
        if not isinstance(name, str) or not OPERATION_ID.fullmatch(name):
            raise BrokerError("operation names must be stable lowercase identifiers")
        operation_policies[name] = _operation_policy(name, value)
    if not {"status", "shutdown"}.issubset(operation_policies):
        raise BrokerError("operations must include status and shutdown")
    if operation_policies["status"].kind != "broker" or operation_policies["shutdown"].kind != "broker":
        raise BrokerError("status and shutdown must be broker operations")
    for name, policy in operation_policies.items():
        if policy.kind == "broker" and name not in {"status", "restart", "shutdown"}:
            raise BrokerError(f"unsupported broker operation in configuration: {name}")
    if "restart" in operation_policies and operation_policies["restart"].kind != "broker":
        raise BrokerError("restart must be a broker operation")

    protocol = require_dict(raw.get("protocol", {}), "protocol")
    rpc_prefix = require_string(protocol.get("rpcPrefix", DEFAULT_RPC_PREFIX), "protocol.rpcPrefix")
    if len(rpc_prefix.encode("utf-8")) > 128 or "\n" in rpc_prefix or "\r" in rpc_prefix:
        raise BrokerError("protocol.rpcPrefix must be a single short line prefix")
    ready_event = require_string(protocol.get("readyEvent", "ready"), "protocol.readyEvent")
    shutdown_operation = require_string(
        protocol.get("shutdownOperation", "shutdown"), "protocol.shutdownOperation"
    )
    environment_raw = require_dict(raw.get("environment", {}), "environment")
    environment: dict[str, str] = {}
    for name, value in environment_raw.items():
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name):
            raise BrokerError("environment keys must be valid identifiers")
        if name in used_environment or not isinstance(value, str):
            raise BrokerError("environment values must be strings and cannot replace secrets")
        environment[name] = value
    proxy_raw = require_dict(raw.get("proxy", {}), "proxy")

    budget_raw = require_dict(raw.get("budgets", {}), "budgets")
    budgets = dict(DEFAULT_BUDGETS)
    for name in budgets:
        if name in budget_raw:
            value = budget_raw[name]
            budgets[name] = _positive_integer(value, f"budgets.{name}")

    startup_timeout = int(raw.get("startupTimeoutSeconds", 30))
    operation_timeout = int(raw.get("operationTimeoutSeconds", 15))
    if not 5 <= startup_timeout <= 120:
        raise BrokerError("startupTimeoutSeconds must be between 5 and 120")
    if not 1 <= operation_timeout <= 60:
        raise BrokerError("operationTimeoutSeconds must be between 1 and 60")

    evidence_directory = campaign_root / "evidence" / "application-fixtures" / fixture_id
    descriptor_path = campaign_root / "private" / "application-fixtures" / f"{fixture_id}.json"
    pid_path = campaign_root / "private" / "application-fixtures" / f"{fixture_id}.pid"
    return BrokerConfig(
        source=source,
        schema_version=int(original_schema),
        fixture_id=fixture_id,
        application_id=application_id,
        provider=raw.get("provider") if isinstance(raw.get("provider"), str) else None,
        campaign_root=campaign_root,
        working_directory=working,
        command=command,
        artifact_hashes=artifact_hashes,
        secret_bindings=tuple(secret_bindings),
        environment=environment,
        approved_endpoints=tuple(endpoints),
        operation_policies=operation_policies,
        rpc_prefix=rpc_prefix,
        ready_event=ready_event,
        shutdown_operation=shutdown_operation,
        export_standard_proxy_environment=bool(proxy_raw.get("exportStandardEnvironment", True)),
        budgets=budgets,
        startup_timeout=startup_timeout,
        operation_timeout=operation_timeout,
        evidence_directory=evidence_directory,
        descriptor_path=descriptor_path,
        pid_path=pid_path,
    )


class Redactor:
    def __init__(self, secret_values: str | list[str] | tuple[str, ...]):
        if isinstance(secret_values, str):
            secret_values = [secret_values]
        variants: set[str] = set()
        for secret_value in secret_values:
            variants.add(secret_value)
            variants.add(base64.b64encode(secret_value.encode("utf-8")).decode("ascii"))
        self._values = sorted((value for value in variants if value), key=len, reverse=True)

    def text(self, value: str) -> str:
        result = value
        for secret in self._values:
            result = result.replace(secret, "[REDACTED]")
        return result

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.value(item) for key, item in value.items()}
        return value


class EvidenceLedger:
    def __init__(self, directory: Path, redactor: Redactor):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "events.jsonl"
        self.redactor = redactor
        self.lock = threading.Lock()
        self.sequence = 0
        self.previous = "0" * 64
        self._resume()

    def _resume(self) -> None:
        if not self.path.exists():
            return
        previous = "0" * 64
        sequence = 0
        for line_number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BrokerError(
                    f"evidence ledger contains invalid JSON at line {line_number}"
                ) from exc
            if record.get("previousDigest") != previous:
                raise BrokerError(
                    f"evidence ledger chain mismatch at line {line_number}"
                )
            retained_digest = record.pop("recordDigest", None)
            actual_digest = hashlib.sha256(canonical(record)).hexdigest()
            if not isinstance(retained_digest, str) or not hmac.compare_digest(
                retained_digest, actual_digest
            ):
                raise BrokerError(
                    f"evidence ledger digest mismatch at line {line_number}"
                )
            current_sequence = record.get("sequence")
            if current_sequence != sequence + 1:
                raise BrokerError(
                    f"evidence ledger sequence mismatch at line {line_number}"
                )
            sequence = current_sequence
            previous = retained_digest
        self.sequence = sequence
        self.previous = previous

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.sequence += 1
            record = {
                "schemaVersion": 1,
                "sequence": self.sequence,
                "recordedAt": utc_now(),
                "eventType": event_type,
                "previousDigest": self.previous,
                "payload": self.redactor.value(payload),
            }
            digest = hashlib.sha256(canonical(record)).hexdigest()
            record["recordDigest"] = digest
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(self.path, 0o600)
            self.previous = digest
            return record


class BrokerBudgets:
    def __init__(
        self,
        limits: dict[str, int],
        operation_limits: dict[str, int],
        state_path: Path,
    ):
        self.limits = limits
        self.operation_limits = operation_limits
        self.state_path = state_path
        self.counts = {name: 0 for name in limits}
        self.operation_counts = {name: 0 for name in operation_limits}
        self.lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        value = require_dict(
            json.loads(self.state_path.read_text(encoding="utf-8")), "budget state"
        )
        if value.get("schemaVersion") != 1:
            raise BrokerError("fixture budget state has an unsupported schema")
        retained = require_dict(value.get("counts"), "budget state counts")
        for name in self.counts:
            candidate = retained.get(name, 0)
            if not isinstance(candidate, int) or candidate < 0:
                raise BrokerError(f"fixture budget state is invalid for {name}")
            self.counts[name] = candidate
        retained_operations = require_dict(
            value.get("operationCounts", {}), "budget state operationCounts"
        )
        if not retained_operations:
            legacy_operation_counts = {
                "evaluate": retained.get("maxEvaluations", 0),
                "set-context": retained.get("maxContextChanges", 0),
                "track": retained.get("maxTrackEvents", 0),
                "restart": retained.get("maxRestarts", 0),
            }
            retained_operations = {
                name: count
                for name, count in legacy_operation_counts.items()
                if name in self.operation_counts
            }
        for name in self.operation_counts:
            candidate = retained_operations.get(name, 0)
            if not isinstance(candidate, int) or candidate < 0:
                raise BrokerError(f"fixture budget state is invalid for operation {name}")
            self.operation_counts[name] = candidate

    def _persist(self) -> None:
        atomic_json(
            self.state_path,
            {
                "schemaVersion": 1,
                "updatedAt": utc_now(),
                "limits": self.limits,
                "counts": self.counts,
                "operationLimits": self.operation_limits,
                "operationCounts": self.operation_counts,
            },
        )

    def consume(self, operation: str) -> dict[str, int]:
        if operation in {"status", "shutdown"}:
            return self.snapshot()
        with self.lock:
            if self.counts["maxOperations"] >= self.limits["maxOperations"]:
                raise BrokerError("fixture operation budget is exhausted")
            specific_limit = self.operation_limits.get(operation, 0)
            if specific_limit and self.operation_counts[operation] >= specific_limit:
                raise BrokerError(f"fixture {operation} budget is exhausted")
            self.counts["maxOperations"] += 1
            if operation in self.operation_counts:
                self.operation_counts[operation] += 1
            self._persist()
            return self.snapshot_unlocked()

    def consume_proxy_connection(self) -> int:
        with self.lock:
            if self.counts["maxProxyConnections"] >= self.limits["maxProxyConnections"]:
                raise BrokerError("proxy connection budget is exhausted")
            self.counts["maxProxyConnections"] += 1
            self._persist()
            return self.counts["maxProxyConnections"]

    def add_proxy_bytes(self, amount: int) -> int:
        with self.lock:
            next_value = self.counts["maxProxyBytes"] + amount
            if next_value > self.limits["maxProxyBytes"]:
                raise BrokerError("proxy byte budget is exhausted")
            self.counts["maxProxyBytes"] = next_value
            self._persist()
            return next_value

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return self.snapshot_unlocked()

    def snapshot_unlocked(self) -> dict[str, int]:
        values = dict(self.counts)
        values.update(
            {f"operation:{name}": count for name, count in self.operation_counts.items()}
        )
        return values


class AllowlistProxy:
    """A CONNECT-only proxy pinned to exact coordinator-approved endpoints."""

    def __init__(
        self,
        endpoints: tuple[EndpointPolicy, ...],
        ledger: EvidenceLedger,
        budgets: BrokerBudgets,
    ):
        self.endpoints = {(item.host, item.port): item for item in endpoints}
        self.ledger = ledger
        self.budgets = budgets
        self.connection_count = 0
        self.byte_count = 0
        self.lock = threading.Lock()
        owner = self

        class ProxyHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                owner._handle(self)

        class ProxyServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = ProxyServer(("127.0.0.1", 0), ProxyHandler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="krineon-sdk-egress-proxy",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()
        self.ledger.append(
            "proxy-started",
            {
                "bind": "127.0.0.1",
                "port": self.port,
                "approvedEndpoints": [
                    {
                        "host": item.host,
                        "port": item.port,
                        "allowPrivate": item.allow_private,
                    }
                    for item in sorted(
                        self.endpoints.values(), key=lambda endpoint: (endpoint.host, endpoint.port)
                    )
                ],
            },
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _reserve_connection(self, host: str, port: int) -> None:
        count = self.budgets.consume_proxy_connection()
        with self.lock:
            self.connection_count = count
        self.ledger.append("proxy-connect", {"host": host, "port": port, "connection": count})

    @staticmethod
    def _connect_endpoint(endpoint: EndpointPolicy) -> socket.socket:
        candidates = socket.getaddrinfo(
            endpoint.host, endpoint.port, type=socket.SOCK_STREAM
        )
        errors: list[str] = []
        for family, socktype, proto, _, address in candidates:
            ip = ipaddress.ip_address(address[0])
            if not endpoint.allow_private and not ip.is_global:
                errors.append(f"rejected non-public address {ip}")
                continue
            remote = socket.socket(family, socktype, proto)
            remote.settimeout(10)
            try:
                remote.connect(address)
                remote.settimeout(None)
                return remote
            except OSError as exc:
                errors.append(str(exc))
                remote.close()
        raise BrokerError("could not connect to an approved public endpoint: " + "; ".join(errors))

    def _handle(self, handler: socketserver.StreamRequestHandler) -> None:
        first = handler.rfile.readline(8193)
        if len(first) > 8192:
            return
        try:
            method, authority, _ = first.decode("ascii").strip().split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            return
        header_bytes = len(first)
        while True:
            line = handler.rfile.readline(8193)
            header_bytes += len(line)
            if header_bytes > 16384:
                return
            if line in {b"\r\n", b"\n", b""}:
                break
        if method != "CONNECT" or authority.count(":") != 1:
            handler.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            return
        host, port_text = authority.rsplit(":", 1)
        host = host.lower()
        try:
            port = int(port_text)
        except ValueError:
            port = -1
        endpoint = self.endpoints.get((host, port))
        if endpoint is None:
            self.ledger.append("proxy-denied", {"host": host, "port": port_text})
            handler.wfile.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            return
        try:
            self._reserve_connection(host, port)
            remote = self._connect_endpoint(endpoint)
        except (BrokerError, OSError) as exc:
            self.ledger.append("proxy-error", {"host": host, "error": str(exc)})
            handler.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        handler.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        handler.wfile.flush()
        sockets = [handler.connection, remote]
        transferred = 0
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = remote if source is handler.connection else handler.connection
                    target.sendall(data)
                    transferred += len(data)
                    byte_count = self.budgets.add_proxy_bytes(len(data))
                    with self.lock:
                        self.byte_count = byte_count
        except (OSError, BrokerError):
            return
        finally:
            remote.close()
            self.ledger.append(
                "proxy-disconnect", {"host": host, "port": port, "bytes": transferred}
            )


class FixtureProcess:
    def __init__(
        self,
        config: BrokerConfig,
        secret_values: dict[str, str],
        proxy: AllowlistProxy,
        ledger: EvidenceLedger,
        redactor: Redactor,
    ):
        self.config = config
        self.secret_values = secret_values
        self.proxy = proxy
        self.ledger = ledger
        self.redactor = redactor
        self.process: subprocess.Popen[str] | None = None
        self.pending: dict[str, queue.Queue[dict[str, Any]]] = {}
        self.pending_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.ready = threading.Event()
        self.generation = 0

    def _environment(self) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "KRINEON_FIXTURE_BROKER_MODE": "1",
            "KRINEON_FIXTURE_PROXY_HOST": "127.0.0.1",
            "KRINEON_FIXTURE_PROXY_PORT": str(self.proxy.port),
        }
        environment.update(self.config.environment)
        environment.update(self.secret_values)
        # Kept for schema-v1 LaunchDarkly fixtures during migration.
        if self.config.provider == "launchdarkly-node":
            environment["KRINEON_SDK_PROXY_PORT"] = str(self.proxy.port)
        if self.config.export_standard_proxy_environment:
            proxy_url = f"http://127.0.0.1:{self.proxy.port}"
            environment.update(
                {
                    "HTTP_PROXY": proxy_url,
                    "HTTPS_PROXY": proxy_url,
                    "http_proxy": proxy_url,
                    "https_proxy": proxy_url,
                    "NO_PROXY": "127.0.0.1,localhost",
                    "no_proxy": "127.0.0.1,localhost",
                }
            )
        for name in ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        return environment

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            raise BrokerError("fixture is already running")
        self.ready.clear()
        self.generation += 1
        self.process = subprocess.Popen(
            list(self.config.command),
            cwd=self.config.working_directory,
            env=self._environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            shell=False,
            start_new_session=True,
        )
        threading.Thread(target=self._stdout_reader, daemon=True).start()
        threading.Thread(target=self._stderr_reader, daemon=True).start()
        self.ledger.append(
            "fixture-started",
            {"pid": self.process.pid, "generation": self.generation},
        )
        if not self.ready.wait(self.config.startup_timeout):
            code = self.process.poll()
            self.stop(force=True)
            raise BrokerError(f"fixture did not become ready; exitCode={code}")

    def _stdout_reader(self) -> None:
        assert self.process and self.process.stdout
        path = self.config.evidence_directory / "fixture.stdout.log"
        for raw in self.process.stdout:
            line = self.redactor.text(raw.rstrip("\n")[:MAX_LOG_LINE])
            with path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            os.chmod(path, 0o600)
            if not line.startswith(self.config.rpc_prefix):
                self.ledger.append("fixture-stdout", {"line": line})
                continue
            try:
                record = json.loads(line[len(self.config.rpc_prefix) :])
            except json.JSONDecodeError:
                self.ledger.append("fixture-protocol-error", {"line": line})
                continue
            if record.get("kind") == "response":
                request_id = str(record.get("id") or "")
                with self.pending_lock:
                    target = self.pending.get(request_id)
                if target:
                    target.put(record)
            else:
                self.ledger.append("fixture-event", require_dict(record, "fixture event"))
                if record.get("type") == self.config.ready_event:
                    self.ready.set()

    def _stderr_reader(self) -> None:
        assert self.process and self.process.stderr
        path = self.config.evidence_directory / "fixture.stderr.log"
        for raw in self.process.stderr:
            line = self.redactor.text(raw.rstrip("\n")[:MAX_LOG_LINE])
            with path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            os.chmod(path, 0o600)
            self.ledger.append("fixture-stderr", {"line": line})

    def request(self, operation: str, payload: dict[str, Any] | None = None) -> Any:
        process = self.process
        if not process or process.poll() is not None or not process.stdin:
            raise BrokerError("fixture is not running")
        request_id = secrets.token_hex(12)
        response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self.pending_lock:
            self.pending[request_id] = response_queue
        request = {"id": request_id, "operation": operation, **(payload or {})}
        try:
            with self.write_lock:
                process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                process.stdin.flush()
            response = response_queue.get(timeout=self.config.operation_timeout)
        except queue.Empty as exc:
            raise BrokerError(f"fixture operation timed out: {operation}") from exc
        finally:
            with self.pending_lock:
                self.pending.pop(request_id, None)
        if not response.get("ok"):
            raise BrokerError(str(response.get("error") or "fixture operation failed"))
        return response.get("result")

    def stop(self, *, force: bool = False) -> None:
        process = self.process
        if not process or process.poll() is not None:
            return
        if not force:
            try:
                self.request(self.config.shutdown_operation)
                process.wait(timeout=5)
            except (BrokerError, subprocess.TimeoutExpired):
                force = True
        if force and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        self.ledger.append(
            "fixture-stopped",
            {"generation": self.generation, "exitCode": process.returncode},
        )


def validate_context(value: Any) -> dict[str, Any]:
    context = require_dict(value, "context")
    kind = require_string(context.get("kind"), "context.kind")
    key = require_string(context.get("key"), "context.key")
    if not KEY.fullmatch(kind) or not KEY.fullmatch(key):
        raise BrokerError("context kind and key contain unsupported characters")
    if len(canonical(context)) > 8192:
        raise BrokerError("context exceeds the retained-evidence limit")
    return context


def validate_key(value: Any, field: str) -> str:
    key = require_string(value, field)
    if not KEY.fullmatch(key):
        raise BrokerError(f"{field} contains unsupported characters")
    return key


def _matches_json_type(value: Any, type_name: str) -> bool:
    if type_name == "any":
        return True
    if type_name == "null":
        return value is None
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    return False


def validate_operation_payload(
    operation: str, payload: dict[str, Any], policy: OperationPolicy
) -> dict[str, Any]:
    encoded = canonical(payload)
    if len(encoded) > policy.max_payload_bytes:
        raise BrokerError(f"fixture {operation} payload exceeds its admitted limit")
    fields = frozenset(payload)
    if not policy.allow_additional_fields:
        extra = fields.difference(policy.allowed_fields)
        if extra:
            raise BrokerError(
                f"fixture {operation} payload contains unsupported fields: "
                + ", ".join(sorted(extra))
            )
    missing = policy.required_fields.difference(fields)
    if missing:
        raise BrokerError(
            f"fixture {operation} payload is missing required fields: "
            + ", ".join(sorted(missing))
        )
    for field, type_name in policy.field_types.items():
        if field in payload and not _matches_json_type(payload[field], type_name):
            raise BrokerError(
                f"fixture {operation} field {field} must have JSON type {type_name}"
            )
    return payload


class BrokerState:
    def __init__(self, config: BrokerConfig):
        self.config = config
        secret_values: dict[str, str] = {}
        for binding in config.secret_bindings:
            store = SecretStore(
                binding.store,
                forbidden_roots=(config.campaign_root, config.working_directory),
            )
            secret_bytes = store.get(binding.reference, version=binding.version)
            try:
                secret = secret_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BrokerError(
                    f"secret for {binding.environment} is not UTF-8"
                ) from exc
            if not binding.min_length <= len(secret) <= binding.max_length:
                raise BrokerError(
                    f"secret for {binding.environment} violates its configured length policy"
                )
            if binding.prefix and not secret.startswith(binding.prefix):
                raise BrokerError(
                    f"secret for {binding.environment} violates its configured prefix policy"
                )
            if binding.pattern and re.fullmatch(binding.pattern, secret) is None:
                raise BrokerError(
                    f"secret for {binding.environment} violates its configured pattern policy"
                )
            secret_values[binding.environment] = secret
        self.redactor = Redactor(tuple(secret_values.values()))
        self.ledger = EvidenceLedger(config.evidence_directory, self.redactor)
        self.budgets = BrokerBudgets(
            config.budgets,
            {
                name: policy.max_calls
                for name, policy in config.operation_policies.items()
                if policy.max_calls
            },
            config.evidence_directory / "budget-state.json",
        )
        self.proxy = AllowlistProxy(config.approved_endpoints, self.ledger, self.budgets)
        self.fixture = FixtureProcess(
            config, secret_values, self.proxy, self.ledger, self.redactor
        )
        self.token = secrets.token_urlsafe(32)
        self.shutdown_requested = threading.Event()
        self.operation_lock = threading.RLock()
        self.started_at = utc_now()

    def start(self) -> None:
        self.proxy.start()
        self.fixture.start()
        manifest = {
            "schemaVersion": 2,
            "fixtureId": self.config.fixture_id,
            "applicationId": self.config.application_id,
            "provider": self.config.provider,
            "startedAt": self.started_at,
            "secretBindings": [
                {
                    "reference": binding.reference,
                    "version": binding.version,
                    "environment": binding.environment,
                }
                for binding in self.config.secret_bindings
            ],
            "approvedEndpoints": [
                {
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "allowPrivate": endpoint.allow_private,
                }
                for endpoint in self.config.approved_endpoints
            ],
            "allowedOperations": sorted(self.config.allowed_operations),
            "budgets": self.config.budgets,
            "artifacts": [
                {
                    "path": path.relative_to(self.config.working_directory).as_posix(),
                    "sha256": digest,
                }
                for path, digest in sorted(
                    self.config.artifact_hashes.items(), key=lambda item: str(item[0])
                )
            ],
            "configurationSha256": sha256_file(self.config.source),
            "evidenceLedger": "events.jsonl",
        }
        atomic_json(self.config.evidence_directory / "manifest.json", manifest)
        self.ledger.append("broker-ready", {"fixtureId": self.config.fixture_id})

    def close(self) -> None:
        with self.operation_lock:
            self.fixture.stop(force=False)
            self.proxy.close()
            self.ledger.append(
                "broker-stopped",
                {
                    "fixtureId": self.config.fixture_id,
                    "budgetCounts": self.budgets.snapshot(),
                    "proxyConnections": self.proxy.connection_count,
                    "proxyBytes": self.proxy.byte_count,
                },
            )

    def status(self) -> dict[str, Any]:
        process = self.fixture.process
        return {
            "fixtureId": self.config.fixture_id,
            "applicationId": self.config.application_id,
            "provider": self.config.provider,
            "ready": bool(process and process.poll() is None and self.fixture.ready.is_set()),
            "generation": self.fixture.generation,
            "pid": process.pid if process and process.poll() is None else None,
            "approvedEndpoints": [
                {
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "allowPrivate": endpoint.allow_private,
                }
                for endpoint in self.config.approved_endpoints
            ],
            "allowedOperations": sorted(self.config.allowed_operations),
            "budgetLimits": self.config.budgets,
            "budgetCounts": self.budgets.snapshot(),
            "proxyConnections": self.proxy.connection_count,
            "proxyBytes": self.proxy.byte_count,
            "startedAt": self.started_at,
        }

    def operate(self, operation: str, payload: dict[str, Any], worker_id: str) -> Any:
        policy = self.config.operation_policies.get(operation)
        if policy is None:
            raise BrokerError(f"operation is not admitted by this fixture: {operation}")
        if not WORKER_ID.fullmatch(worker_id):
            raise BrokerError("worker identity is required")
        retained_payload = validate_operation_payload(operation, payload, policy)
        with self.operation_lock:
            counts = self.budgets.consume(operation)
            if operation == "status":
                result = self.status()
            elif operation == "restart":
                self.fixture.stop(force=False)
                self.fixture.start()
                result = self.status()
            elif operation == "shutdown":
                result = {"stopping": True}
                self.shutdown_requested.set()
            elif policy.kind == "fixture":
                result = self.fixture.request(operation, retained_payload)
            else:
                raise BrokerError(f"unsupported broker operation: {operation}")
            self.ledger.append(
                "control-operation",
                {
                    "workerId": worker_id,
                    "operation": operation,
                    "request": retained_payload,
                    "response": result,
                    "budgetCounts": counts,
                },
            )
            return result


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: BrokerState):
        self.state = state
        super().__init__(("127.0.0.1", 0), ControlHandler)


class ControlHandler(BaseHTTPRequestHandler):
    server: ControlServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.state.token}"
        return hmac.compare_digest(supplied, expected)

    def _route(self) -> tuple[str, str] | None:
        prefix = f"/v1/fixtures/{self.server.state.config.fixture_id}/"
        if not self.path.startswith(prefix):
            return None
        operation = self.path[len(prefix) :]
        if "/" in operation or not operation:
            return None
        return self.server.state.config.fixture_id, operation

    def do_GET(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        route = self._route()
        if not route or route[1] != "status":
            self._json(404, {"error": "not found"})
            return
        worker = self.headers.get("X-Krineon-Worker", "coordinator")
        try:
            result = self.server.state.operate("status", {}, worker)
            self._json(200, {"ok": True, "result": result})
        except BrokerError as exc:
            self._json(409, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        route = self._route()
        if not route:
            self._json(404, {"error": "not found"})
            return
        operation = route[1]
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            self._json(400, {"error": "invalid content length"})
            return
        if length < 0 or length > MAX_CONTROL_BODY:
            self._json(413, {"error": "request body exceeds the broker limit"})
            return
        try:
            body = self.rfile.read(length)
            payload = json.loads(body or b"{}")
            payload = require_dict(payload, "control payload")
            worker = self.headers.get("X-Krineon-Worker", "coordinator")
            result = self.server.state.operate(operation, payload, worker)
            self._json(200, {"ok": True, "result": result})
        except (BrokerError, WebContractError, json.JSONDecodeError) as exc:
            self._json(409, {"ok": False, "error": str(exc)})


def descriptor_value(state: BrokerState, server: ControlServer) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "fixtureId": state.config.fixture_id,
        "applicationId": state.config.application_id,
        "provider": state.config.provider,
        "baseUrl": f"http://127.0.0.1:{server.server_address[1]}",
        "controlToken": state.token,
        "pid": os.getpid(),
        "allowedOperations": sorted(state.config.allowed_operations),
        "createdAt": utc_now(),
    }


def serve(config_path: Path) -> int:
    config = load_config(config_path)
    config.pid_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_handle = config.pid_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise BrokerError("a broker already owns this fixture") from exc
    lock_handle.seek(0)
    lock_handle.truncate()
    lock_handle.write(str(os.getpid()) + "\n")
    lock_handle.flush()
    os.fsync(lock_handle.fileno())
    os.chmod(config.pid_path, 0o600)

    state = BrokerState(config)
    server: ControlServer | None = None
    server_thread: threading.Thread | None = None
    try:
        state.start()
        server = ControlServer(state)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        private_write(
            config.descriptor_path,
            json.dumps(descriptor_value(state, server), indent=2, sort_keys=True) + "\n",
        )
        state.shutdown_requested.wait()
        return 0
    finally:
        config.descriptor_path.unlink(missing_ok=True)
        if server:
            server.shutdown()
            server.server_close()
        if server_thread:
            server_thread.join(timeout=5)
        state.close()
        lock_handle.close()
        config.pid_path.unlink(missing_ok=True)


def read_descriptor(config: BrokerConfig) -> dict[str, Any]:
    if config.descriptor_path.is_symlink() or not config.descriptor_path.is_file():
        raise BrokerError("fixture broker descriptor is unavailable")
    mode = config.descriptor_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise BrokerError("fixture broker descriptor is not private")
    value = require_dict(
        json.loads(config.descriptor_path.read_text(encoding="utf-8")), "descriptor"
    )
    if value.get("fixtureId") != config.fixture_id:
        raise BrokerError("fixture broker descriptor identity mismatch")
    return value


def control_request(
    config: BrokerConfig,
    operation: str,
    payload: dict[str, Any],
    worker: str,
) -> dict[str, Any]:
    descriptor = read_descriptor(config)
    base = require_string(descriptor.get("baseUrl"), "descriptor.baseUrl")
    token = require_string(descriptor.get("controlToken"), "descriptor.controlToken")
    url = f"{base}/v1/fixtures/{config.fixture_id}/{operation}"
    data = None if operation == "status" else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="GET" if operation == "status" else "POST",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Krineon-Worker": worker,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=config.operation_timeout + 2) as response:
            return require_dict(json.loads(response.read()), "control response")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error")
        except (json.JSONDecodeError, AttributeError):
            detail = str(exc)
        raise BrokerError(f"broker rejected {operation}: {detail}") from exc


def start_daemon(config_path: Path) -> dict[str, Any]:
    config = load_config(config_path)
    try:
        existing = read_descriptor(config)
        pid = int(existing.get("pid") or 0)
        os.kill(pid, 0)
        status = control_request(config, "status", {}, "coordinator-start-check")
        result = require_dict(status.get("result"), "existing broker status")
        if not status.get("ok") or result.get("fixtureId") != config.fixture_id:
            raise BrokerError("existing broker failed its authenticated identity check")
        return {
            "fixtureId": config.fixture_id,
            "pid": pid,
            "state": "already-running",
            "ready": bool(result.get("ready")),
        }
    except (BrokerError, OSError, ValueError):
        config.descriptor_path.unlink(missing_ok=True)

    config.evidence_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    daemon_log = config.evidence_directory / "broker-daemon.log"
    log_handle = daemon_log.open("ab", buffering=0)
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "serve", str(config.source)],
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=log_handle,
        close_fds=True,
        start_new_session=True,
    )
    log_handle.close()
    deadline = time.monotonic() + config.startup_timeout + 5
    while time.monotonic() < deadline:
        if config.descriptor_path.is_file():
            descriptor = read_descriptor(config)
            return {
                "fixtureId": config.fixture_id,
                "pid": int(descriptor["pid"]),
                "state": "running",
                "allowedOperations": descriptor["allowedOperations"],
            }
        code = process.poll()
        if code is not None:
            raise BrokerError(f"broker exited during startup with status {code}; inspect {daemon_log}")
        time.sleep(0.1)
    process.terminate()
    raise BrokerError(f"broker startup timed out; inspect {daemon_log}")


def parse_json_argument(value: str | None, field: str, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise BrokerError(f"{field} must be valid JSON") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "serve", "start"):
        sub = subparsers.add_parser(command)
        sub.add_argument("config", type=Path)
    control = subparsers.add_parser("control")
    control.add_argument("config", type=Path)
    control.add_argument("operation")
    control.add_argument("--worker", default="coordinator")
    control.add_argument(
        "--payload-json",
        help="Complete JSON object for any admitted application operation",
    )
    # Compatibility shorthands for the original LaunchDarkly fixture.
    control.add_argument("--flag-key")
    control.add_argument("--event-key")
    control.add_argument("--context-json")
    control.add_argument("--data-json")
    control.add_argument("--default-json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            config = load_config(args.config)
            result = {
                "valid": True,
                "fixtureId": config.fixture_id,
                "applicationId": config.application_id,
                "provider": config.provider,
                "configurationSha256": sha256_file(config.source),
                "artifacts": [
                    {
                        "path": path.relative_to(
                            config.working_directory
                        ).as_posix(),
                        "sha256": digest,
                    }
                    for path, digest in sorted(
                        config.artifact_hashes.items(),
                        key=lambda item: str(item[0]),
                    )
                ],
                "approvedEndpoints": [
                    {
                        "host": endpoint.host,
                        "port": endpoint.port,
                        "allowPrivate": endpoint.allow_private,
                    }
                    for endpoint in config.approved_endpoints
                ],
                "allowedOperations": sorted(config.allowed_operations),
                "secretBindings": [
                    {
                        "reference": binding.reference,
                        "version": binding.version,
                        "environment": binding.environment,
                    }
                    for binding in config.secret_bindings
                ],
            }
        elif args.command == "serve":
            return serve(args.config)
        elif args.command == "start":
            result = start_daemon(args.config)
        else:
            config = load_config(args.config)
            payload_value = parse_json_argument(args.payload_json, "--payload-json", {})
            payload = require_dict(payload_value, "--payload-json")
            if args.payload_json is None and args.operation == "evaluate":
                payload["flagKey"] = args.flag_key
                payload["defaultValue"] = parse_json_argument(
                    args.default_json, "--default-json", False
                )
            elif args.payload_json is None and args.operation == "set-context":
                payload["context"] = parse_json_argument(
                    args.context_json, "--context-json", None
                )
            elif args.payload_json is None and args.operation == "track":
                payload["eventKey"] = args.event_key
                payload["data"] = parse_json_argument(args.data_json, "--data-json", {})
            if (
                args.payload_json is None
                and args.context_json
                and args.operation in {"evaluate", "track"}
            ):
                payload["context"] = parse_json_argument(
                    args.context_json, "--context-json", None
                )
            result = control_request(config, args.operation, payload, args.worker)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (BrokerError, WebContractError, OSError, json.JSONDecodeError) as exc:
        print(f"application fixture broker error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
