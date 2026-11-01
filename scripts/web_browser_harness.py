#!/usr/bin/env python3
"""Execute approved multi-role browser scenarios in isolated Chromium profiles.

This wrapper intentionally reuses the owned-loopback CDP runner. It does not
turn that runner into an unrestricted remote browser. Each scenario run starts
a new browser process and disposable profile and shares one revocable campaign
budget with every other target-facing adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .experiment_control import authority_paths, sign_file
    from .web_budget import SharedWebBudget
    from .web_cdp_runner import discover
    from .web_contract import ExecutionLease, WebCampaignContract, WebContractError, atomic_json
    from .web_secret_store import SecretStore
    from .web_workflow import load_object, verify
except ImportError:
    from experiment_control import authority_paths, sign_file
    from web_budget import SharedWebBudget
    from web_cdp_runner import discover
    from web_contract import ExecutionLease, WebCampaignContract, WebContractError, atomic_json
    from web_secret_store import SecretStore
    from web_workflow import load_object, verify


ROLES = {"attacker", "victim", "reviewer"}
CAPABILITIES = {
    "fresh-process-per-run",
    "fresh-profile-per-run",
    "sandbox-enabled",
    "normal-web-security",
    "browser-generated-request-context",
    "challenge-state-classification",
    "loopback-random-cdp",
    "early-target-auto-attach",
    "fetch-scope-enforcement",
    "network-events",
    "console-exceptions",
    "dom-and-storage-discovery",
    "service-worker-discovery",
    "downloads-denied",
    "headed",
    "headless",
}


def validate_scenario(value: dict[str, Any], workflow: dict[str, Any]) -> dict[str, Any]:
    if value.get("schemaVersion") != 1:
        raise WebContractError("browser scenario schemaVersion must be 1")
    if not str(value.get("id") or ""):
        raise WebContractError("browser scenario requires an id")
    required = value.get("requiredCapabilities", [])
    if not isinstance(required, list) or any(item not in CAPABILITIES for item in required):
        raise WebContractError("browser scenario requests an unsupported capability")
    runs = value.get("runs")
    if not isinstance(runs, list) or not runs:
        raise WebContractError("browser scenario requires runs")
    steps = {str(step.get("id") or ""): step for step in workflow.get("steps", [])}
    seen: set[str] = set()
    for run in runs:
        if not isinstance(run, dict):
            raise WebContractError("browser scenario run must be an object")
        run_id = str(run.get("id") or "")
        if not run_id or run_id in seen:
            raise WebContractError("browser run ids must be unique")
        seen.add(run_id)
        if run.get("role") not in ROLES:
            raise WebContractError("browser run role must be attacker, victim, or reviewer")
        if run.get("mode") not in {"headed", "headless"}:
            raise WebContractError("browser run mode must be headed or headless")
        step_id = str(run.get("workflowStep") or "")
        if step_id not in steps or str(steps[step_id].get("type") or "") != "browser":
            raise WebContractError("browser run must select a browser workflow step")
        if int(run.get("timeoutSeconds") or 0) < 1:
            raise WebContractError("browser run requires a positive timeoutSeconds")
    return {"runs": len(runs), "roles": sorted({str(run["role"]) for run in runs})}


def browser_version(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    return completed.stdout.strip()


def execute(
    *,
    campaign: Path,
    contract: WebCampaignContract,
    workflow: dict[str, Any],
    scenario: dict[str, Any],
    binary: Path,
    output: Path,
    ledger: SharedWebBudget,
    secret_store: SecretStore | None,
) -> dict[str, Any]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise WebContractError("Chromium browser scenarios must not run as root")
    if not binary.is_file():
        raise WebContractError("pinned Chromium binary does not exist")
    summary = validate_scenario(scenario, workflow)
    output.mkdir(parents=True, exist_ok=False)
    steps = {str(step["id"]): step for step in workflow["steps"]}
    results = []
    for run in scenario["runs"]:
        if ledger.is_cancelled():
            raise WebContractError("browser scenario capability was cancelled")
        run_output = output / str(run["id"])
        result = discover(
            campaign=campaign,
            binary=binary,
            contract=contract,
            workflow=workflow,
            step=steps[str(run["workflowStep"])],
            ledger=ledger,
            output=run_output,
            timeout=float(run["timeoutSeconds"]),
            secret_store=secret_store,
            headed=run["mode"] == "headed",
            required_capabilities=set(scenario.get("requiredCapabilities", [])),
        )
        results.append(
            {
                "id": run["id"],
                "role": run["role"],
                "mode": run["mode"],
                "stepId": result["stepId"],
                "freshProfile": result["freshProfile"],
                "sandboxVerified": result["sandbox"]["verified"],
                "requestCount": result["requestCount"],
                "blockedRequests": len(result["blockedRequests"]),
                "observation": str(run_output / "browser-observation.json"),
            }
        )
    record = {
        "schemaVersion": 1,
        "scenarioId": scenario["id"],
        "workflowId": workflow["id"],
        "contractSha256": contract.digest,
        "binary": str(binary),
        "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "browserVersion": browser_version(binary),
        "platform": platform.platform(),
        "capabilities": sorted(CAPABILITIES),
        "separateProcessAndProfilePerRun": True,
        "summary": summary,
        "runs": results,
    }
    budget_path = output / "budget-ledger.json"
    atomic_json(budget_path, ledger.read(), mode=0o600)
    record["budgetLedgerSha256"] = hashlib.sha256(budget_path.read_bytes()).hexdigest()
    observation = output / "scenario-observation.json"
    atomic_json(observation, record, mode=0o600)
    private_key, _ = authority_paths(campaign)
    if not private_key.is_file():
        raise WebContractError("campaign experiment authority is not initialized")
    sign_file(private_key, observation, output / "scenario-observation.json.sig")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("contract")
    parser.add_argument("workflow")
    parser.add_argument("scenario")
    parser.add_argument("--signature")
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger")
    parser.add_argument("--secret-store")
    args = parser.parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    workflow_path = Path(args.workflow).expanduser().resolve()
    signature = Path(args.signature).expanduser().resolve() if args.signature else workflow_path.with_suffix(workflow_path.suffix + ".sig")
    lease: ExecutionLease | None = None
    try:
        contract = WebCampaignContract.load(contract_path)
        verification = verify(campaign, contract_path, workflow_path, signature)
        if not verification["passed"]:
            raise WebContractError("workflow approval failed: " + ", ".join(verification["errors"]))
        workflow = load_object(workflow_path)
        scenario = load_object(args.scenario)
        validate_scenario(scenario, workflow)
        lease = ExecutionLease(campaign / "evidence" / "web" / "execution.lock", "browser")
        lease.acquire()
        ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else campaign / "evidence" / "web" / "budget-ledger.sqlite3"
        result = execute(
            campaign=campaign,
            contract=contract,
            workflow=workflow,
            scenario=scenario,
            binary=Path(args.chromium).expanduser().resolve(),
            output=Path(args.output).expanduser().resolve(),
            ledger=SharedWebBudget(contract, ledger_path),
            secret_store=SecretStore(args.secret_store, forbidden_root=campaign, forbidden_roots=contract.raw["requestInputs"].get("sourceRoots", [])) if args.secret_store else None,
        )
        print(json.dumps({"scenarioId": result["scenarioId"], "runs": len(result["runs"])}, indent=2))
        return 0
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if lease is not None:
            lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
