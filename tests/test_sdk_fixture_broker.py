import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from sdk_fixture_broker import (
    BrokerError,
    BrokerState,
    control_request,
    load_config,
    sha256_file,
    start_daemon,
)
from web_secret_store import SecretStore


FAKE_FIXTURE = r"""
import { createInterface } from 'node:readline';

let context = {kind: 'user', key: 'initial-context'};
function emit(value) {
  process.stdout.write(`KRINEON_RPC ${JSON.stringify(value)}\n`);
}
emit({kind: 'event', type: 'ready', flagKey: 'owned-flag', contextKey: context.key});
const input = createInterface({input: process.stdin, crlfDelay: Infinity});
for await (const line of input) {
  const request = JSON.parse(line);
  let result;
  if (request.operation === 'status') {
    result = {ready: true, contextKey: context.key};
  } else if (request.operation === 'set-context') {
    context = request.context;
    result = {contextKey: context.key, contextKind: context.kind};
  } else if (request.operation === 'evaluate') {
    const selected = request.context ?? context;
    result = {flagKey: request.flagKey, contextKey: selected.key, value: true};
  } else if (request.operation === 'track') {
    result = {eventKey: request.eventKey, contextKey: context.key, flushed: true};
  } else if (request.operation === 'shutdown') {
    emit({kind: 'response', id: request.id, ok: true, result: {stopping: true}});
    break;
  } else {
    emit({kind: 'response', id: request.id, ok: false, error: 'unsupported'});
    continue;
  }
  emit({kind: 'response', id: request.id, ok: true, result});
}
"""


UNIVERSAL_FIXTURE = r"""
import { createInterface } from 'node:readline';

function emit(value) {
  process.stdout.write(`APP_RPC ${JSON.stringify(value)}\n`);
}
console.error(`redaction-probe:${process.env.APP_TOKEN}:${process.env.SIGNING_SECRET}`);
emit({kind: 'event', type: 'initialized', application: 'owned-generic-app'});
const input = createInterface({input: process.stdin, crlfDelay: Infinity});
for await (const line of input) {
  const request = JSON.parse(line);
  if (request.operation === 'mutate-owned-fixture') {
    emit({
      kind: 'response',
      id: request.id,
      ok: true,
      result: {
        resource: request.resource,
        enabled: request.enabled,
        hasCredentials: Boolean(process.env.APP_TOKEN && process.env.SIGNING_SECRET),
        mode: process.env.FIXTURE_MODE,
        proxy: process.env.HTTPS_PROXY,
      },
    });
  } else if (request.operation === 'stop-fixture') {
    emit({kind: 'response', id: request.id, ok: true, result: {stopping: true}});
    break;
  } else {
    emit({kind: 'response', id: request.id, ok: false, error: 'unsupported'});
  }
}
"""


def fixture(tmp_path: Path, *, hosts: list[str] | None = None, evaluations: int = 2) -> Path:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    worktree = tmp_path / "fixture"
    worktree.mkdir()
    entrypoint = worktree / "connect.mjs"
    entrypoint.write_text(FAKE_FIXTURE, encoding="utf-8")
    lockfile = worktree / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    store_root = tmp_path / "private-secrets"
    store = SecretStore(store_root, forbidden_roots=(campaign, worktree))
    store.put(
        "secret://launchdarkly-node-sdk-key",
        "sdk-owned-test-value-0123456789",
        kind="api-key",
    )

    config = tmp_path / "sdk-broker.json"
    config.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "provider": "launchdarkly-node",
                "fixtureId": "owned-launchdarkly-node",
                "campaignRoot": str(campaign),
                "workingDirectory": str(worktree),
                "entrypoint": "connect.mjs",
                "nodeExecutable": shutil.which("node"),
                "artifacts": [
                    {"path": "connect.mjs", "sha256": sha256_file(entrypoint)},
                    {"path": "package-lock.json", "sha256": sha256_file(lockfile)},
                ],
                "secret": {
                    "store": str(store_root),
                    "reference": "secret://launchdarkly-node-sdk-key",
                    "version": None,
                },
                "approvedHosts": hosts
                or [
                    "stream.launchdarkly.com",
                    "sdk.launchdarkly.com",
                    "events.launchdarkly.com",
                ],
                "allowedOperations": [
                    "status",
                    "evaluate",
                    "set-context",
                    "track",
                    "restart",
                    "shutdown",
                ],
                "startupTimeoutSeconds": 10,
                "operationTimeoutSeconds": 5,
                "budgets": {
                    "maxOperations": 20,
                    "maxEvaluations": evaluations,
                    "maxContextChanges": 2,
                    "maxTrackEvents": 2,
                    "maxRestarts": 2,
                    "maxProxyConnections": 4,
                    "maxProxyBytes": 1048576,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return config


def universal_fixture(tmp_path: Path) -> Path:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    worktree = tmp_path / "generic-fixture"
    worktree.mkdir()
    entrypoint = worktree / "fixture.mjs"
    entrypoint.write_text(UNIVERSAL_FIXTURE, encoding="utf-8")

    store_root = tmp_path / "private-secrets"
    store = SecretStore(store_root, forbidden_roots=(campaign, worktree))
    store.put("secret://owned-app-token", "token-owned-123456", kind="api-key")
    store.put("secret://owned-signing-secret", "signing-owned-654321", kind="api-key")

    config = tmp_path / "application-broker.json"
    config.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "fixtureId": "owned-generic-application",
                "applicationId": "generic-owned-service",
                "campaignRoot": str(campaign),
                "workingDirectory": str(worktree),
                "command": {
                    "executable": shutil.which("node"),
                    "arguments": ["fixture.mjs"],
                },
                "artifacts": [
                    {"path": "fixture.mjs", "sha256": sha256_file(entrypoint)}
                ],
                "secrets": [
                    {
                        "store": str(store_root),
                        "reference": "secret://owned-app-token",
                        "environment": "APP_TOKEN",
                        "prefix": "token-",
                        "minLength": 8,
                        "maxLength": 64,
                    },
                    {
                        "store": str(store_root),
                        "reference": "secret://owned-signing-secret",
                        "environment": "SIGNING_SECRET",
                        "minLength": 8,
                        "maxLength": 64,
                    },
                ],
                "environment": {"FIXTURE_MODE": "owned-test"},
                "approvedEndpoints": [
                    {"host": "api.example.test", "port": 8443, "allowPrivate": True}
                ],
                "proxy": {"exportStandardEnvironment": True},
                "protocol": {
                    "rpcPrefix": "APP_RPC ",
                    "readyEvent": "initialized",
                    "shutdownOperation": "stop-fixture",
                },
                "operations": {
                    "status": {
                        "kind": "broker",
                        "maxCalls": 0,
                        "maxPayloadBytes": 2,
                        "allowedFields": [],
                        "requiredFields": [],
                    },
                    "mutate-owned-fixture": {
                        "kind": "fixture",
                        "maxCalls": 1,
                        "maxPayloadBytes": 1024,
                        "allowedFields": ["resource", "enabled"],
                        "requiredFields": ["resource", "enabled"],
                        "fieldTypes": {"resource": "string", "enabled": "boolean"},
                    },
                    "restart": {
                        "kind": "broker",
                        "maxCalls": 2,
                        "maxPayloadBytes": 2,
                        "allowedFields": [],
                        "requiredFields": [],
                    },
                    "shutdown": {
                        "kind": "broker",
                        "maxCalls": 0,
                        "maxPayloadBytes": 2,
                        "allowedFields": [],
                        "requiredFields": [],
                    },
                },
                "budgets": {
                    "maxOperations": 8,
                    "maxProxyConnections": 4,
                    "maxProxyBytes": 1048576,
                },
                "startupTimeoutSeconds": 10,
                "operationTimeoutSeconds": 5,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return config


def test_broker_runs_bounded_fixture_without_exposing_sdk_key(tmp_path: Path) -> None:
    config = load_config(fixture(tmp_path))
    state = BrokerState(config)
    try:
        state.start()
        status = state.operate("status", {}, "worker-a")
        assert status["ready"] is True
        assert status["generation"] == 1

        changed = state.operate(
            "set-context",
            {"context": {"kind": "user", "key": "owned-context-b"}},
            "worker-a",
        )
        assert changed["contextKey"] == "owned-context-b"

        evaluated = state.operate(
            "evaluate",
            {"flagKey": "owned-flag", "defaultValue": False},
            "worker-b",
        )
        assert evaluated == {
            "flagKey": "owned-flag",
            "contextKey": "owned-context-b",
            "value": True,
        }

        tracked = state.operate(
            "track",
            {"eventKey": "owned-event", "data": {"source": "test"}},
            "worker-b",
        )
        assert tracked["flushed"] is True

        restarted = state.operate("restart", {}, "coordinator")
        assert restarted["generation"] == 2
    finally:
        state.close()

    retained = "\n".join(
        path.read_text(encoding="utf-8")
        for path in config.evidence_directory.iterdir()
        if path.is_file()
    )
    assert "sdk-owned-test-value-0123456789" not in retained
    records = [
        json.loads(line)
        for line in (config.evidence_directory / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert all(len(record["recordDigest"]) == 64 for record in records)
    for previous, current in zip(records, records[1:]):
        assert current["previousDigest"] == previous["recordDigest"]


def test_broker_enforces_per_operation_budget(tmp_path: Path) -> None:
    config = load_config(fixture(tmp_path, evaluations=1))
    state = BrokerState(config)
    try:
        state.start()
        state.operate(
            "evaluate",
            {"flagKey": "owned-flag", "defaultValue": False},
            "worker-a",
        )
        with pytest.raises(BrokerError, match="evaluate budget"):
            state.operate(
                "evaluate",
                {"flagKey": "owned-flag", "defaultValue": False},
                "worker-a",
            )
    finally:
        state.close()


def test_budget_and_evidence_chain_survive_broker_restart(tmp_path: Path) -> None:
    config = load_config(fixture(tmp_path, evaluations=1))
    first = BrokerState(config)
    try:
        first.start()
        first.operate(
            "evaluate",
            {"flagKey": "owned-flag", "defaultValue": False},
            "originator",
        )
    finally:
        first.close()

    records_before = [
        json.loads(line)
        for line in (config.evidence_directory / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    last_sequence = records_before[-1]["sequence"]
    last_digest = records_before[-1]["recordDigest"]

    second = BrokerState(load_config(config.source))
    try:
        second.start()
        with pytest.raises(BrokerError, match="evaluate budget"):
            second.operate(
                "evaluate",
                {"flagKey": "owned-flag", "defaultValue": False},
                "independent-reviewer",
            )
    finally:
        second.close()

    records_after = [
        json.loads(line)
        for line in (config.evidence_directory / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    resumed = records_after[len(records_before)]
    assert resumed["sequence"] == last_sequence + 1
    assert resumed["previousDigest"] == last_digest


def test_daemon_exposes_authenticated_loopback_control_and_cleans_up(
    tmp_path: Path,
) -> None:
    config = load_config(fixture(tmp_path))
    started = start_daemon(config.source)
    assert started["state"] == "running"
    try:
        status = control_request(config, "status", {}, "coordinator-test")
        assert status["ok"] is True
        assert status["result"]["fixtureId"] == "owned-launchdarkly-node"
        assert status["result"]["ready"] is True

        repeated = start_daemon(config.source)
        assert repeated["state"] == "already-running"
        assert repeated["pid"] == started["pid"]
        assert repeated["ready"] is True

        stopped = control_request(config, "shutdown", {}, "coordinator-test")
        assert stopped == {"ok": True, "result": {"stopping": True}}
        deadline = time.monotonic() + 10
        while config.descriptor_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not config.descriptor_path.exists()
        while time.monotonic() < deadline:
            try:
                reaped, _ = os.waitpid(int(started["pid"]), os.WNOHANG)
                if reaped:
                    break
            except ChildProcessError:
                pass
            try:
                os.kill(int(started["pid"]), 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            pytest.fail("broker daemon remained alive after shutdown")
    finally:
        if config.descriptor_path.exists():
            try:
                control_request(config, "shutdown", {}, "test-cleanup")
            except (BrokerError, OSError):
                pass


def test_broker_rejects_non_launchdarkly_egress_host(tmp_path: Path) -> None:
    config = fixture(tmp_path, hosts=["example.com"])
    with pytest.raises(BrokerError, match="documented LaunchDarkly SDK hosts"):
        load_config(config)


def test_broker_rejects_changed_fixture_artifact(tmp_path: Path) -> None:
    config = fixture(tmp_path)
    raw = json.loads(config.read_text(encoding="utf-8"))
    Path(raw["workingDirectory"], "connect.mjs").write_text("changed\n", encoding="utf-8")
    with pytest.raises(BrokerError, match="artifact hash mismatch"):
        load_config(config)


def test_schema_v2_runs_arbitrary_fixture_with_multiple_secrets_and_typed_rpc(
    tmp_path: Path,
) -> None:
    config = load_config(universal_fixture(tmp_path))
    assert config.application_id == "generic-owned-service"
    assert config.provider is None
    assert config.command[1:] == ("fixture.mjs",)
    assert [(item.host, item.port, item.allow_private) for item in config.approved_endpoints] == [
        ("api.example.test", 8443, True)
    ]

    state = BrokerState(config)
    try:
        state.start()
        result = state.operate(
            "mutate-owned-fixture",
            {"resource": "owned-resource", "enabled": True},
            "generic-worker",
        )
        assert result["resource"] == "owned-resource"
        assert result["enabled"] is True
        assert result["hasCredentials"] is True
        assert result["mode"] == "owned-test"
        assert result["proxy"].startswith("http://127.0.0.1:")

        with pytest.raises(BrokerError, match="JSON type boolean"):
            state.operate(
                "mutate-owned-fixture",
                {"resource": "owned-resource", "enabled": "yes"},
                "generic-worker",
            )
        with pytest.raises(BrokerError, match="unsupported fields"):
            state.operate(
                "mutate-owned-fixture",
                {"resource": "owned-resource", "enabled": True, "shell": "id"},
                "generic-worker",
            )
        with pytest.raises(BrokerError, match="mutate-owned-fixture budget"):
            state.operate(
                "mutate-owned-fixture",
                {"resource": "owned-resource-2", "enabled": False},
                "generic-worker",
            )
    finally:
        state.close()

    retained = "\n".join(
        path.read_text(encoding="utf-8")
        for path in config.evidence_directory.iterdir()
        if path.is_file()
    )
    assert "token-owned-123456" not in retained
    assert "signing-owned-654321" not in retained
    assert "redaction-probe:[REDACTED]:[REDACTED]" in retained


def test_schema_v2_requires_every_worktree_command_file_to_be_pinned(tmp_path: Path) -> None:
    config = universal_fixture(tmp_path)
    raw = json.loads(config.read_text(encoding="utf-8"))
    raw["artifacts"] = []
    config.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    with pytest.raises(BrokerError, match="artifacts must pin"):
        load_config(config)
