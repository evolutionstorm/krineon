#!/usr/bin/env python3
"""Legacy Nuclei template admission helper.

Direct scanner execution through this compatibility module is disabled. Use
``scripts/nuclei_adapter.py`` so Nuclei sees only a loopback replay of response
data already acquired by Krineon's broker. ``admitted_template`` remains for
reading older campaign contracts and fails closed on unsafe templates.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .experiment_control import authority_paths, sign_file
    from .web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        sha256_bytes,
    )
    from .web_workflow import load_object, verify
except ImportError:
    from experiment_control import authority_paths, sign_file
    from web_contract import (
        BudgetLedger,
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
        sha256_bytes,
    )
    from web_workflow import load_object, verify


FORBIDDEN = re.compile(
    r"(?im)^\s*(?:headless|javascript|code|network|dns|file|payloads|attack|race|fuzzing|flow|workflows?|unsafe|pipeline|threads|redirects|max-redirects|host-redirects|cookie-reuse)\s*:"
)
LITERAL_URL = re.compile(r"https?://", re.IGNORECASE)
METHOD = re.compile(r"(?im)^\s*method\s*:\s*([A-Za-z]+)\s*$")
RAW_METHOD = re.compile(r"(?m)^\s*(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP/")
REQUEST_BLOCK = re.compile(r"(?im)^\s*(?:-\s*)?(?:method|raw)\s*:")
PATH_VALUE = re.compile(r"(?m)^\s*-\s*['\"]?([^'\"\s]+)['\"]?\s*$")
RAW_TARGET = re.compile(r"(?m)^\s*(?:GET|HEAD|OPTIONS)\s+(\S+)\s+HTTP/")
HOST_HEADER = re.compile(r"(?im)^\s*Host\s*:\s*(.+?)\s*$")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loopback_origin(url: str) -> bool:
    host = urlsplit(url).hostname
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def admitted_template(contract: WebCampaignContract, template_id: str) -> tuple[Path, int]:
    nuclei = contract.raw.get("nuclei")
    if not isinstance(nuclei, dict) or nuclei.get("enabled") is not True:
        raise WebContractError("Nuclei is disabled in the web campaign")
    templates = nuclei.get("admittedTemplates")
    if not isinstance(templates, list):
        raise WebContractError("nuclei.admittedTemplates must be an array")
    matches = [item for item in templates if isinstance(item, dict) and item.get("id") == template_id]
    if len(matches) != 1:
        raise WebContractError("workflow references an unadmitted Nuclei template")
    item = matches[0]
    path = (contract.path.parent / str(item.get("path") or "")).resolve()
    path.relative_to(contract.path.parent.resolve())
    if not path.is_file() or sha256_file(path) != item.get("sha256"):
        raise WebContractError("Nuclei template is missing or its hash changed")
    text = path.read_text(encoding="utf-8")
    if FORBIDDEN.search(text):
        raise WebContractError("Nuclei template uses a forbidden execution feature")
    without_base = text.replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
    if LITERAL_URL.search(without_base) or "env(" in text:
        raise WebContractError("Nuclei template can address an external or environment-derived URL")
    methods = [value.upper() for value in METHOD.findall(text)] + [
        value.upper() for value in RAW_METHOD.findall(text)
    ]
    if any(value not in {"GET", "HEAD", "OPTIONS"} for value in methods):
        raise WebContractError("Nuclei template contains a state-changing method")
    for value in PATH_VALUE.findall(text):
        if "{{BaseURL}}" in value and value != "{{BaseURL}}":
            raise WebContractError("Nuclei path must use the exact admitted BaseURL")
        if "{{RootURL}}" in value:
            raise WebContractError("Nuclei templates cannot reset to the root URL")
    if any(value != "{{Path}}" for value in RAW_TARGET.findall(text)):
        raise WebContractError("raw Nuclei requests must use the exact admitted Path")
    if any(value.strip() != "{{Hostname}}" for value in HOST_HEADER.findall(text)):
        raise WebContractError("Nuclei templates cannot override the admitted Host")
    static_count = len(REQUEST_BLOCK.findall(text))
    declared = int(item.get("maxRequests") or 0)
    if static_count < 1 or declared != static_count:
        raise WebContractError("Nuclei maxRequests must equal the statically counted request blocks")
    return path, declared


def terminate(process: subprocess.Popen[bytes]) -> None:
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


def main(argv: list[str] | None = None) -> int:
    print(
        "error: direct Nuclei execution is disabled; use scripts/nuclei_adapter.py "
        "with a broker-acquired replay fixture",
        file=sys.stderr,
    )
    return 2

    # This unreachable compatibility implementation is retained temporarily so
    # old campaign evidence remains readable. It must never regain a call path.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("contract")
    parser.add_argument("workflow")
    parser.add_argument("--signature")
    parser.add_argument("--step", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger")
    args = parser.parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    workflow_path = Path(args.workflow).expanduser().resolve()
    signature = (
        Path(args.signature).expanduser().resolve()
        if args.signature
        else workflow_path.with_suffix(workflow_path.suffix + ".sig")
    )
    output = Path(args.output).expanduser().resolve()
    lease: ExecutionLease | None = None
    try:
        executable = shutil.which("nuclei")
        if executable is None:
            raise WebContractError("Nuclei is not installed")
        contract = WebCampaignContract.load(contract_path)
        approval = verify(campaign, contract_path, workflow_path, signature)
        if not approval["passed"]:
            raise WebContractError("workflow approval failed")
        workflow = load_object(workflow_path)
        matches = [item for item in workflow["steps"] if item.get("id") == args.step]
        if len(matches) != 1 or matches[0].get("type") != "nuclei":
            raise WebContractError("--step must select one Nuclei workflow step")
        step = matches[0]
        lease = ExecutionLease(
            campaign / "evidence" / "web" / "execution.lock", "nuclei"
        )
        lease.acquire()
        admitted = contract.admitted_request(
            origin_id=str(step.get("originId") or ""),
            path_or_url=str(step.get("path") or "/"),
            method="GET",
            effect_class="read-only",
            operation="nuclei",
            operation_class=str(step.get("operationClass") or "nuclei-read"),
        )
        if contract.identity_for_origin(
            str(step.get("identityId") or "anonymous"), admitted["originId"]
        ) is not None:
            raise WebContractError(
                "authenticated Nuclei execution is unsupported; use the controlled HTTP broker"
            )
        if not loopback_origin(admitted["url"]):
            raise WebContractError(
                "remote Nuclei execution is blocked until OS-enforced broker-only egress is available"
            )
        template, request_count = admitted_template(contract, str(step.get("templateId") or ""))
        ledger = BudgetLedger(
            contract,
            Path(args.ledger).expanduser().resolve()
            if args.ledger
            else campaign / "evidence" / "web" / "budget-ledger.json",
        )
        run_id = "run-" + secrets.token_hex(12)
        for index in range(request_count):
            operation_id = "op-" + hashlib.sha256(
                f"{run_id}\0{step['id']}\0{index + 1}".encode("utf-8")
            ).hexdigest()[:40]
            ledger.reserve(
                operation_id=operation_id,
                request_bytes=len(admitted["url"]),
                estimated_response_bytes=int(admitted["maxResponseBodyBytes"]),
                cleanup=False,
                adapter="nuclei",
            )
        output.mkdir(parents=True, exist_ok=False)
        result_path = output / "nuclei.jsonl"
        command = [
            executable,
            "-u", admitted["url"],
            "-t", str(template),
            "-jsonl",
            "-o", str(result_path),
            "-rate-limit", str(max(1, int(contract.raw["budget"]["maxRequestsPerSecond"]))),
            "-bulk-size", "1",
            "-concurrency", "1",
            "-retries", "0",
            "-max-redirects", "0",
            "-disable-redirects",
            "-no-interactsh",
            "-disable-update-check",
            "-no-color",
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=int(contract.raw["budget"]["maxWallSeconds"]))
        except subprocess.TimeoutExpired:
            terminate(process)
            raise WebContractError("Nuclei exceeded the campaign wall-clock budget")
        (output / "stdout.log").write_bytes(stdout[:1024 * 1024])
        (output / "stderr.log").write_bytes(stderr[:1024 * 1024])
        record = {
            "schemaVersion": 1,
            "runId": run_id,
            "driver": "admitted-nuclei",
            "stepId": step["id"],
            "template": str(template.relative_to(contract.path.parent)),
            "templateSha256": sha256_file(template),
            "reservedRequests": request_count,
            "returnCode": process.returncode,
            "matchCount": len(result_path.read_text(encoding="utf-8").splitlines()) if result_path.is_file() else 0,
            "note": "Scanner matches are observations, not vulnerability verdicts.",
        }
        budget_path = output / "budget-ledger.json"
        atomic_json(budget_path, ledger.read(), mode=0o600)
        record["budgetLedgerSha256"] = sha256_bytes(budget_path.read_bytes())
        observation_path = output / "observation.json"
        atomic_json(observation_path, record, mode=0o600)
        private_key, _ = authority_paths(campaign)
        if not private_key.is_file():
            raise WebContractError("campaign experiment authority is not initialized")
        sign_file(private_key, observation_path, output / "observation.json.sig")
        print(json.dumps(record, indent=2))
        return 0 if process.returncode == 0 else 1
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if lease is not None:
            lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
