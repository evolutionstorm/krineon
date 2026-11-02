from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.burp_mcp_adapter import (
    BurpMcpError,
    complete_call,
    prepare_call,
    register_session,
)
from scripts.web_budget import SharedWebBudget
from scripts.web_contract import WebCampaignContract
from tests.test_web_app_profile import contract_value


def write_private(path: Path, value: str | dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, dict):
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    else:
        path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return path


def campaign_fixture(tmp_path: Path) -> tuple[Path, Path, dict]:
    root = tmp_path / "campaign"
    root.mkdir()
    (root / "campaign.json").write_text(
        json.dumps({"schemaVersion": 1, "target": "owned-web-fixture"}) + "\n",
        encoding="utf-8",
    )
    contract = contract_value("https://owned.test", confirmed=True)
    contract_path = root / "web-campaign.json"
    contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    manifest = tmp_path / "burp-session.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "client": "codex",
                "serverName": "burp",
                "connected": True,
                "dedicatedProject": True,
                "burpTargetApprovalEnabled": True,
                "burpVersion": "2026.10",
                "extensionVersion": "1.3.0",
                "tools": [
                    {"name": "send_http1_request", "observedFromClient": True, "inputSchema": {"type": "object"}},
                    {"name": "get_proxy_http_history_regex", "observedFromClient": True, "inputSchema": {"type": "object"}},
                    {"name": "create_repeater_tab", "observedFromClient": True, "inputSchema": {"type": "object"}},
                    {"name": "set_project_options", "observedFromClient": True, "inputSchema": {"type": "object"}},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    session = register_session(root, manifest)
    return root, contract_path, session


def request_arguments(root: Path, *, host: str = "owned.test") -> Path:
    return write_private(
        root / "private" / "burp-mcp" / "request.json",
        {
            "content": (
                "GET /account HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Authorization: Bearer owned-secret\r\n"
                "Connection: close\r\n\r\n"
            ),
            "targetHostname": host,
            "targetPort": 443,
            "usesHttps": True,
        },
    )


def call_spec(root: Path, session: dict, arguments: Path, **updates: object) -> Path:
    value = {
        "schemaVersion": 1,
        "sessionId": session["sessionId"],
        "toolName": "send_http1_request",
        "capability": "http-send",
        "originId": "app",
        "identityId": "user-a",
        "effectClass": "read-only",
        "operationClass": "ordinary-http",
        "intent": "Check one owned authorization boundary",
        "argumentsFile": arguments.relative_to(root).as_posix(),
        "maxResultBytes": 4096,
        "timeoutSeconds": 30,
    }
    value.update(updates)
    path = root / "call-spec.json"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


def test_burp_mcp_call_is_scope_budget_and_evidence_bound(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = request_arguments(root)
    prepared = prepare_call(root, contract_path, call_spec(root, session, arguments))
    assert prepared["url"] == "https://owned.test/account"
    assert prepared["method"] == "GET"
    assert prepared["policy"]["findingPromotionAllowed"] is False
    public_record = root / "tools" / "burp-mcp" / "calls" / f"{prepared['capabilityId']}.json"
    assert "owned-secret" not in public_record.read_text(encoding="utf-8")

    result = write_private(
        root / "private" / "burp-mcp" / "result.txt",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    )
    receipt = root / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "capabilityId": prepared["capabilityId"],
                "serverName": "burp",
                "toolName": "send_http1_request",
                "toolSchemaSha256": prepared["toolSchemaSha256"],
                "argumentsSha256": prepared["argumentsSha256"],
                "outcome": "success",
                "targetRequestDispatched": True,
                "resultFile": result.relative_to(root).as_posix(),
                "truncated": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    completed = complete_call(root, prepared["capabilityId"], receipt)
    assert completed["status"] == "completed"
    assert completed["eligibleForSecurityConclusion"] is False
    assert completed["eligibleForNegativeConclusion"] is False
    ledger = SharedWebBudget(
        WebCampaignContract.load(contract_path),
        root / "evidence" / "web" / "budget-ledger.sqlite3",
    ).read()
    operation = next(row for row in ledger["operations"] if row["id"] == prepared["capabilityId"])
    assert operation["status"] == "completed"


def test_burp_mcp_rejects_out_of_scope_service(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = request_arguments(root, host="outside.test")
    with pytest.raises(BurpMcpError, match="target service"):
        prepare_call(root, contract_path, call_spec(root, session, arguments))


def test_burp_mcp_rejects_group_readable_private_arguments(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = request_arguments(root)
    arguments.chmod(0o640)
    with pytest.raises(BurpMcpError, match="mode 0600"):
        prepare_call(root, contract_path, call_spec(root, session, arguments))


def test_burp_mcp_blocks_configuration_tools(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = write_private(
        root / "private" / "burp-mcp" / "config.json",
        {"json": "{}"},
    )
    spec = call_spec(
        root,
        session,
        arguments,
        toolName="set_project_options",
        capability="blocked",
    )
    with pytest.raises(BurpMcpError, match="not admitted"):
        prepare_call(root, contract_path, spec)


def test_burp_mcp_history_requires_filtered_exact_host_and_marks_truncation(
    tmp_path: Path,
) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = write_private(
        root / "private" / "burp-mcp" / "history.json",
        {"regex": "owned\\.test", "count": 2, "offset": 0},
    )
    prepared = prepare_call(
        root,
        contract_path,
        call_spec(
            root,
            session,
            arguments,
            toolName="get_proxy_http_history_regex",
            capability="http-history-read",
            identityId="anonymous",
        ),
    )
    result = write_private(
        root / "private" / "burp-mcp" / "history-result.txt",
        "{\"request\":\"GET / HTTP/1.1\"}... (truncated)",
    )
    receipt = root / "history-receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "capabilityId": prepared["capabilityId"],
                "serverName": "burp",
                "toolName": "get_proxy_http_history_regex",
                "toolSchemaSha256": prepared["toolSchemaSha256"],
                "argumentsSha256": prepared["argumentsSha256"],
                "outcome": "success",
                "targetRequestDispatched": False,
                "resultFile": result.relative_to(root).as_posix(),
                "truncated": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    completed = complete_call(root, prepared["capabilityId"], receipt)
    assert completed["truncated"] is True
    assert completed["eligibleForNegativeConclusion"] is False


def test_burp_mcp_history_rejects_broad_regex(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = write_private(
        root / "private" / "burp-mcp" / "broad-history.json",
        {"regex": "owned\\.test|.*", "count": 2, "offset": 0},
    )
    spec = call_spec(
        root,
        session,
        arguments,
        toolName="get_proxy_http_history_regex",
        capability="http-history-read",
        identityId="anonymous",
    )
    with pytest.raises(BurpMcpError, match="must equal"):
        prepare_call(root, contract_path, spec)


def test_burp_mcp_rejects_arguments_changed_after_preparation(tmp_path: Path) -> None:
    root, contract_path, session = campaign_fixture(tmp_path)
    arguments = request_arguments(root)
    prepared = prepare_call(root, contract_path, call_spec(root, session, arguments))
    arguments.write_text("{}\n", encoding="utf-8")
    arguments.chmod(0o600)
    result = write_private(
        root / "private" / "burp-mcp" / "changed-result.txt",
        "not executed",
    )
    receipt = root / "changed-receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "capabilityId": prepared["capabilityId"],
                "serverName": "burp",
                "toolName": "send_http1_request",
                "toolSchemaSha256": prepared["toolSchemaSha256"],
                "argumentsSha256": prepared["argumentsSha256"],
                "outcome": "error",
                "targetRequestDispatched": False,
                "resultFile": result.relative_to(root).as_posix(),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BurpMcpError, match="changed after preparation"):
        complete_call(root, prepared["capabilityId"], receipt)
    call = json.loads(
        (
            root
            / "tools"
            / "burp-mcp"
            / "calls"
            / f"{prepared['capabilityId']}.json"
        ).read_text(encoding="utf-8")
    )
    assert call["status"] == "rejected"
