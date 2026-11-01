#!/usr/bin/env python3
"""Validate and coordinator-sign bounded web experiment workflows."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .experiment_control import (
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )
    from .web_contract import WebCampaignContract, WebContractError, atomic_json
    from .web_oracle import validate_oracle
    from .web_identity import IdentityBroker
    from .web_policy import validate_http_replay_headers, validate_step_envelope
    from .web_sequence_planner import validate_operation
except ImportError:
    from experiment_control import (
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )
    from web_contract import WebCampaignContract, WebContractError, atomic_json
    from web_oracle import validate_oracle
    from web_identity import IdentityBroker
    from web_policy import validate_http_replay_headers, validate_step_envelope
    from web_sequence_planner import validate_operation


def load_object(path: Path | str) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected a JSON object in {resolved}")
    return value


def validate_workflow(
    workflow: dict[str, Any], contract: WebCampaignContract, *, dynamic: bool
) -> dict[str, Any]:
    if workflow.get("schemaVersion") != 1:
        raise WebContractError("workflow schemaVersion must be 1")
    for field in ("id", "title", "hypothesis", "changedVariable"):
        if not str(workflow.get(field) or "").strip():
            raise WebContractError(f"workflow requires {field}")
    prerequisite_version = workflow.get("prerequisiteVersion")
    if prerequisite_version is not None:
        prerequisite_version = str(prerequisite_version).strip()
        if prerequisite_version in {
            "",
            "unknown",
            "unspecified-prerequisite-version",
        }:
            raise WebContractError(
                "workflow prerequisiteVersion must be stable when supplied"
            )
    explanations = workflow.get("competingExplanations")
    if not isinstance(explanations, list) or len(explanations) < 2:
        raise WebContractError("workflow requires at least two competing explanations")
    for explanation in explanations:
        if not isinstance(explanation, dict) or not str(explanation.get("id") or ""):
            raise WebContractError("each competing explanation requires an id")
        if not str(explanation.get("statement") or ""):
            raise WebContractError("each competing explanation requires a statement")
        if not isinstance(explanation.get("expectedObservations"), list) or not explanation.get(
            "expectedObservations"
        ):
            raise WebContractError(
                "each explanation requires at least one expected observation"
            )
    steps = workflow.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WebContractError("workflow requires at least one step")
    cleanup_steps = workflow.get("cleanupSteps")
    if not isinstance(cleanup_steps, list):
        raise WebContractError("cleanupSteps must be an array")
    seen: set[str] = set()
    writes = 0
    for collection, cleanup in ((steps, False), (cleanup_steps, True)):
        for step in collection:
            if not isinstance(step, dict):
                raise WebContractError("workflow step must be an object")
            step_id = str(step.get("id") or "")
            if not step_id or step_id in seen:
                raise WebContractError("workflow step ids must be nonempty and unique")
            seen.add(step_id)
            resource = step.get("resource")
            if not isinstance(resource, dict) or any(
                not str(resource.get(field) or "").strip()
                for field in (
                    "id",
                    "kind",
                    "expectedOwner",
                    "selectedResource",
                    "permittedAction",
                )
            ):
                raise WebContractError(
                    "each workflow step requires a typed resource with id, kind, "
                    "expectedOwner, selectedResource, and permittedAction"
                )
            validate_step_envelope(step, cleanup=cleanup)
            observation_context = step.get("observationContext")
            if not isinstance(observation_context, dict) or any(
                not str(observation_context.get(field) or "").strip()
                for field in ("evidenceOrigin", "cacheLayer", "executionContext")
            ):
                raise WebContractError(
                    "each workflow step requires evidenceOrigin, cacheLayer, and executionContext"
                )
            step_type = str(step.get("type") or "http")
            if step_type not in {"http", "browser", "nuclei"}:
                raise WebContractError(f"unsupported workflow step type: {step_type}")
            effect = str(step.get("effectClass") or "unknown")
            default_operation_class = {
                "http": "ordinary-http",
                "browser": "browser-discovery",
                "nuclei": "nuclei-read",
            }[step_type]
            operation_class = str(
                step.get("operationClass") or default_operation_class
            )
            if effect == "disposable-write":
                writes += 1
            if cleanup and effect != "disposable-write":
                raise WebContractError("cleanup steps must use disposable-write")
            contract.admitted_request(
                origin_id=str(step.get("originId") or ""),
                path_or_url=str(step.get("path") or step.get("url") or ""),
                method=str(step.get("method") or "GET"),
                effect_class=effect,
                cleanup=cleanup,
                operation=step_type,
                operation_class=operation_class,
                require_live_authorization=dynamic,
            )
            identity = contract.identity_for_origin(
                str(step.get("identityId") or "anonymous"),
                str(step.get("originId") or ""),
            )
            if dynamic and identity is not None:
                IdentityBroker(contract).authorize(
                    identity.id,
                    origin_id=str(step.get("originId") or ""),
                    path_or_url=str(step.get("path") or step.get("url") or ""),
                    transport="browser" if step_type == "browser" else "http",
                )
            if step_type == "nuclei" and identity is not None:
                raise WebContractError(
                    "authenticated Nuclei steps are unsupported; use an HTTP step"
                )
            session = str(
                step.get("session")
                or (identity.session if identity is not None else "anonymous")
            )
            expected_session = identity.session if identity is not None else "anonymous"
            if session != expected_session:
                raise WebContractError(
                    "workflow session must match the selected contract identity"
                )
            headers = step.get("headers", [])
            if not isinstance(headers, list):
                raise WebContractError("step headers must be an ordered array")
            for header in headers:
                if not isinstance(header, list) or len(header) != 2:
                    raise WebContractError("step headers must be [name, value] pairs")
                if str(header[0]).lower() in {
                    "authorization",
                    "cookie",
                    "proxy-authorization",
                    "x-api-key",
                    "api-key",
                }:
                    raise WebContractError(
                        "workflow may not contain credential headers; use identityId"
                    )
            normalized_headers = [(str(item[0]), str(item[1])) for item in headers]
            if step_type == "browser" and normalized_headers:
                raise WebContractError(
                    "browser steps must let Chrome generate browser-context headers"
                )
            if step_type == "http":
                validate_http_replay_headers(step, normalized_headers)
    if writes and not cleanup_steps:
        raise WebContractError("disposable writes require explicit cleanup steps")
    operation_contracts = workflow.get("operationContracts", [])
    if not isinstance(operation_contracts, list):
        raise WebContractError("operationContracts must be an array")
    normalized_operations = [validate_operation(value) for value in operation_contracts]
    operation_ids = {value["id"] for value in normalized_operations}
    if len(operation_ids) != len(normalized_operations):
        raise WebContractError("operation contract ids must be unique")
    known_steps = {
        str(value.get("id") or "")
        for value in [*steps, *cleanup_steps]
        if isinstance(value, dict)
    }
    for operation in normalized_operations:
        if operation["actionRef"]["workflowId"] != workflow["id"]:
            raise WebContractError("operation actionRef.workflowId must match workflow id")
        if operation["actionRef"]["stepId"] not in known_steps:
            raise WebContractError("operation actionRef.stepId is not a workflow step")
    oracles = workflow.get("oracles")
    if not isinstance(oracles, list) or not oracles:
        raise WebContractError("workflow requires at least one executable oracle")
    for oracle in oracles:
        if not isinstance(oracle, dict):
            raise WebContractError("workflow oracle must be an object")
        validate_oracle(oracle)
    approval = workflow.get("coordinatorApproval")
    if not isinstance(approval, dict):
        raise WebContractError("workflow requires coordinatorApproval")
    return {
        "workflowId": workflow["id"],
        "steps": len(steps),
        "cleanupSteps": len(cleanup_steps),
        "oracles": len(oracles),
        "writes": writes,
        "operationContracts": len(normalized_operations),
        "prerequisiteVersion": prerequisite_version,
    }


def approve(
    campaign: Path, contract_path: Path, workflow_path: Path, signature_path: Path
) -> dict[str, Any]:
    contract = WebCampaignContract.load(contract_path)
    contract.require_live_authorization()
    workflow = load_object(workflow_path)
    summary = validate_workflow(workflow, contract, dynamic=True)
    authority = ensure_authority(campaign)
    campaign_record = load_object(campaign / "campaign.json")
    campaign_record["experimentAuthority"] = {
        key: value for key, value in authority.items() if key != "privateKey"
    }
    atomic_json(campaign / "campaign.json", campaign_record)
    approval = workflow["coordinatorApproval"]
    approval.update(
        {
            "approved": True,
            "approvedBy": "coordinator",
            "approvedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "contractSha256": contract.digest,
        }
    )
    atomic_json(workflow_path, workflow)
    private, _ = authority_paths(campaign)
    sign_file(private, workflow_path, signature_path)
    return {
        **summary,
        "approved": True,
        "signature": str(signature_path),
        "contractSha256": contract.digest,
        "authorityPublicKey": authority["publicKey"],
    }


def verify(
    campaign: Path, contract_path: Path, workflow_path: Path, signature_path: Path
) -> dict[str, Any]:
    contract = WebCampaignContract.load(contract_path)
    workflow = load_object(workflow_path)
    summary = validate_workflow(workflow, contract, dynamic=True)
    approval = workflow["coordinatorApproval"]
    errors: list[str] = []
    if approval.get("approved") is not True:
        errors.append("approval:not-approved")
    if approval.get("approvedBy") != "coordinator":
        errors.append("approval:identity")
    if approval.get("contractSha256") != contract.digest:
        errors.append("approval:contract-hash")
    try:
        public = control_public_key(campaign)
        if not verify_file(public, workflow_path, signature_path):
            errors.append("approval:signature")
    except Exception as exc:  # The exact authority error is retained for review.
        errors.append(f"approval:authority:{exc}")
    return {**summary, "passed": not errors, "errors": errors}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "approve", "verify"):
        command = sub.add_parser(name)
        command.add_argument("campaign")
        command.add_argument("contract")
        command.add_argument("workflow")
        command.add_argument("--signature")
        command.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    campaign = Path(args.campaign).expanduser().resolve()
    contract = Path(args.contract).expanduser().resolve()
    workflow = Path(args.workflow).expanduser().resolve()
    signature = (
        Path(args.signature).expanduser().resolve()
        if args.signature
        else workflow.with_suffix(workflow.suffix + ".sig")
    )
    try:
        if args.command == "validate":
            contract_value = WebCampaignContract.load(contract)
            result = validate_workflow(
                load_object(workflow), contract_value, dynamic=False
            )
            result["passed"] = True
        elif args.command == "approve":
            result = approve(campaign, contract, workflow, signature)
            result["passed"] = True
        else:
            result = verify(campaign, contract, workflow, signature)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(("PASS" if result.get("passed") else "FAIL") + ": " + args.command)
        return 0 if result.get("passed") else 1
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
