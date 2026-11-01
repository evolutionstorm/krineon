#!/usr/bin/env python3
"""Execute approved business-workflow histories through registered web adapters."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import os
import sys
import threading
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

try:
    from .experiment_control import control_public_key, verify_file
    from .research_harness import verified_web_observation
    from .web_browser_harness import main as run_browser_scenario
    from .web_budget import SharedWebBudget
    from .web_contract import (
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
    )
    from .web_execution_broker import WebExecutionBroker, main as run_http_broker
    from .web_secret_store import SecretStore
    from .web_sequence_planner import validate_operation
    from .web_sequence_evidence import digest as sequence_digest, validate_specification
    from .web_state_oracles import compare, evaluate as evaluate_state_oracle
    from .web_workflow import load_object, verify as verify_workflow
except ImportError:
    from experiment_control import control_public_key, verify_file
    from research_harness import verified_web_observation
    from web_browser_harness import main as run_browser_scenario
    from web_budget import SharedWebBudget
    from web_contract import (
        ExecutionLease,
        WebCampaignContract,
        WebContractError,
        atomic_json,
    )
    from web_execution_broker import WebExecutionBroker, main as run_http_broker
    from web_secret_store import SecretStore
    from web_sequence_planner import validate_operation
    from web_sequence_evidence import digest as sequence_digest, validate_specification
    from web_state_oracles import compare, evaluate as evaluate_state_oracle
    from web_workflow import load_object, verify as verify_workflow


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def safe_campaign_path(campaign: Path, value: str, field: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise WebContractError(f"{field} must be campaign-relative")
    resolved = (campaign / relative).resolve()
    try:
        resolved.relative_to(campaign.resolve())
    except ValueError as error:
        raise WebContractError(f"{field} escapes the campaign") from error
    if not resolved.is_file():
        raise WebContractError(f"{field} does not exist: {value}")
    return resolved


def nested(value: Any, path: str) -> Any:
    current = value
    for part in path.split(".") if path else []:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise WebContractError(f"observation selector is missing: {path}")
    return current


def serializable_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: sorted(value) if isinstance(value, set) else value
        for key, value in state.items()
    }


def authority_versions(operation: dict[str, Any], state: dict[str, Any]) -> None:
    actor_id = operation["actorRef"]["id"]
    session_versions = state["sessionRefreshVersions"]
    permission_versions = state["permissionVersions"]
    current_session = session_versions.get(actor_id)
    current_permission = permission_versions.get(actor_id)
    transition = operation.get("identityTransition")
    if transition:
        if (
            current_session != transition["fromSessionRefreshVersion"]
            or current_permission != transition["permissionVersionBefore"]
            or operation["actorRef"]["sessionRefreshVersion"]
            != transition["fromSessionRefreshVersion"]
            or operation["actorRef"]["permissionVersion"]
            != transition["permissionVersionBefore"]
        ):
            raise WebContractError("reauthentication does not match the current identity state")
        return
    if (
        current_session != operation["actorRef"]["sessionRefreshVersion"]
        or current_permission != operation["actorRef"]["permissionVersion"]
    ):
        raise WebContractError(
            "operation identity versions do not match current session and application permission state"
        )


def parse_time(value: Any) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def value_not_expired(
    produced: dict[str, Any], operation: dict[str, Any], state: dict[str, Any]
) -> bool:
    policy = produced.get("expiryPolicy")
    if policy == "never":
        return True
    if policy == "operation-bounded":
        return produced.get("_sequenceRunId") == state.get("sequenceRunId")
    if policy == "session-bounded":
        actor_id = operation["actorRef"]["id"]
        return produced.get("_sessionRefreshVersion") == state[
            "sessionRefreshVersions"
        ].get(actor_id)
    if policy == "absolute-time":
        try:
            return dt.datetime.now(dt.timezone.utc) <= parse_time(produced["expiryValue"])
        except (KeyError, TypeError, ValueError):
            return False
    if policy == "relative-seconds":
        try:
            issued = parse_time(produced["_issuedAt"])
            return dt.datetime.now(dt.timezone.utc) <= issued + dt.timedelta(
                seconds=float(produced["expiryValue"])
            )
        except (KeyError, TypeError, ValueError):
            return False
    return False


def evaluate_async_wait(
    operation: dict[str, Any], observations: list[dict[str, Any]]
) -> tuple[bool, str | None]:
    wait = operation.get("asyncWait")
    if wait is None:
        return True, None
    observation = next(
        (value for value in observations if value["id"] == wait["observationId"]),
        None,
    )
    if observation is None:
        return False, "missing-telemetry"
    state = observation["state"]
    attempts = state.get(wait["attemptsField"])
    if not isinstance(attempts, int) or isinstance(attempts, bool):
        return False, "missing-telemetry"
    if attempts < 0 or attempts > wait["maxPolls"]:
        raise WebContractError("observed async polling exceeds the signed polling budget")
    if compare(wait["operator"], state.get(wait["stateField"]), wait.get("expected")):
        return True, None
    return False, "inaccessible-business-state"


def retained_evidence_hashes(campaign: Path, evidence: dict[str, list[str]]) -> list[str]:
    hashes = set()
    for references in evidence.values():
        for reference in references:
            path = (campaign / reference).resolve()
            try:
                path.relative_to(campaign.resolve())
            except ValueError as error:
                raise WebContractError("runner evidence escapes the campaign") from error
            if not path.is_file():
                raise WebContractError(f"runner evidence is missing: {reference}")
            hashes.add(hashlib.sha256(path.read_bytes()).hexdigest())
    return sorted(hashes)


def requirement_satisfied(
    requirement: dict[str, Any], state: dict[str, Any]
) -> bool:
    operator = requirement["operator"]
    if operator == "and":
        return all(requirement_satisfied(value, state) for value in requirement["clauses"])
    if operator == "or":
        return any(requirement_satisfied(value, state) for value in requirement["clauses"])
    ref = str(requirement["ref"])
    expected = requirement.get("expected", True)
    fact_type = requirement["type"]
    if fact_type == "operation":
        observed = ref in state["completedOperations"]
    elif fact_type == "server-value":
        observed = ref in state["serverValues"] and ref not in state["invalidatedValues"]
    elif fact_type == "approval":
        observed = ref in state["approvals"]
    elif fact_type == "relationship":
        observed = ref in state["relationships"]
    elif fact_type == "capability":
        observed = ref in state["capabilities"]
    elif fact_type == "authority":
        observed = ref in state["authorityBindings"]
    elif fact_type == "state":
        observed = ref in state["authoritativeFacts"]
    else:
        observed = False
    return observed == expected


def unsatisfied_requirement_refs(
    requirement: dict[str, Any], state: dict[str, Any]
) -> set[str]:
    if requirement["operator"] == "fact":
        return set() if requirement_satisfied(requirement, state) else {str(requirement["ref"])}
    rows = [unsatisfied_requirement_refs(value, state) for value in requirement["clauses"]]
    if requirement["operator"] == "and":
        return set().union(*rows)
    return set() if any(not value for value in rows) else set().union(*rows)


def workflow_groups(
    campaign: Path, operations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for operation in operations:
        action = operation["actionRef"]
        key = (action["runner"], action["campaignContract"], action["workflow"])
        group = by_key.get(key)
        if group is None:
            group = {"key": key, "operations": [], "action": action}
            by_key[key] = group
            groups.append(group)
        group["operations"].append(operation)
    for group in groups:
        action = group["action"]
        workflow_path = safe_campaign_path(campaign, action["workflow"], "actionRef.workflow")
        signature = safe_campaign_path(campaign, action["signature"], "actionRef.signature")
        contract = safe_campaign_path(
            campaign, action["campaignContract"], "actionRef.campaignContract"
        )
        verification = verify_workflow(campaign, contract, workflow_path, signature)
        if not verification["passed"]:
            raise WebContractError(
                "workflow approval failed: " + ", ".join(verification["errors"])
            )
        workflow = load_object(workflow_path)
        signed_operations = {
            value["actionRef"]["stepId"]: value
            for value in (
                validate_operation(item)
                for item in workflow.get("operationContracts", [])
            )
        }
        if not signed_operations:
            raise WebContractError(
                "sequence execution requires coordinator-signed operationContracts"
            )
        selected = {value["actionRef"]["stepId"] for value in group["operations"]}
        actual = {
            str(value.get("id") or "")
            for value in workflow.get("steps", [])
            if isinstance(value, dict)
        }
        if selected != actual:
            raise WebContractError(
                "each execution unit must select every step in its signed workflow exactly once"
            )
        selected_order = [
            value["actionRef"]["stepId"] for value in group["operations"]
        ]
        actual_order = [
            str(value.get("id") or "")
            for value in workflow.get("steps", [])
            if isinstance(value, dict)
        ]
        if selected_order != actual_order:
            raise WebContractError(
                "operation order must match the signed workflow step order"
            )
        step_by_id = {
            str(value.get("id") or ""): value
            for value in workflow.get("steps", [])
            if isinstance(value, dict)
        }
        for operation in group["operations"]:
            step = step_by_id[operation["actionRef"]["stepId"]]
            signed_operation = signed_operations.get(operation["actionRef"]["stepId"])
            if signed_operation is None or signed_operation != operation:
                raise WebContractError(
                    "operation contract does not exactly match the coordinator-signed workflow"
                )
            if str(step.get("identityId") or "anonymous") != operation["actorRef"]["id"]:
                raise WebContractError("operation actor does not match the signed workflow step")
            resource = step.get("resource") if isinstance(step.get("resource"), dict) else {}
            bound = {value["id"] for value in operation["resourceBindings"]}
            if str(resource.get("id") or "") not in bound:
                raise WebContractError("operation resource does not match the signed workflow step")
        group.update(
            {
                "workflowPath": workflow_path,
                "signaturePath": signature,
                "contractPath": contract,
                "workflow": workflow,
            }
        )
    return groups


def run_group(
    campaign: Path,
    group: dict[str, Any],
    output: Path,
    *,
    secret_store: Path | None,
) -> tuple[dict[str, Any], list[str]]:
    action = group["action"]
    runner = action["runner"]
    arguments = [
        str(campaign),
        str(group["contractPath"]),
        str(group["workflowPath"]),
        "--signature",
        str(group["signaturePath"]),
        "--output",
        str(output),
    ]
    if secret_store is not None:
        arguments.extend(["--secret-store", str(secret_store)])
    if runner == "krineon-http-broker-v1":
        with redirect_stdout(io.StringIO()):
            return_code = run_http_broker(arguments)
        if return_code != 0:
            raise WebContractError("registered HTTP workflow execution failed")
        observation_path = output / "observation.json"
        signature_path = output / "observation.json.sig"
        budget_path = output / "budget-ledger.json"
        passed, errors, _ = verified_web_observation(
            campaign,
            contract_path=group["contractPath"],
            workflow_path=group["workflowPath"],
            workflow_signature=group["signaturePath"],
            observation_path=observation_path,
            observation_signature=signature_path,
            budget_ledger_path=budget_path,
            require_disagreement=False,
        )
        if not passed:
            raise WebContractError(
                "HTTP observation verification failed: " + ", ".join(errors)
            )
        return load_json(observation_path), [
            observation_path.relative_to(campaign).as_posix(),
            signature_path.relative_to(campaign).as_posix(),
            budget_path.relative_to(campaign).as_posix(),
        ]
    if runner == "krineon-chrome-cdp-v1":
        scenario = safe_campaign_path(campaign, action["scenario"], "actionRef.scenario")
        registry_path = safe_campaign_path(
            campaign, "web-runner-registry.json", "web runner registry"
        )
        registry = load_json(registry_path)
        runners = registry.get("browserRunners")
        if registry.get("schemaVersion") != 1 or not isinstance(runners, list):
            raise WebContractError("web runner registry is invalid")
        matches = [
            value
            for value in runners
            if isinstance(value, dict)
            and value.get("id") == action.get("browserRunnerRef")
        ]
        if len(matches) != 1:
            raise WebContractError("browserRunnerRef is not coordinator-registered")
        binary = Path(str(matches[0].get("path") or "")).expanduser().resolve()
        if not binary.is_file():
            raise WebContractError("registered Chromium binary does not exist")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != matches[0].get("sha256"):
            raise WebContractError("registered Chromium binary hash changed")
        browser_arguments = [
            str(campaign),
            str(group["contractPath"]),
            str(group["workflowPath"]),
            str(scenario),
            "--signature",
            str(group["signaturePath"]),
            "--chromium",
            str(binary),
            "--output",
            str(output),
        ]
        if secret_store is not None:
            browser_arguments.extend(["--secret-store", str(secret_store)])
        with redirect_stdout(io.StringIO()):
            return_code = run_browser_scenario(browser_arguments)
        if return_code != 0:
            raise WebContractError("registered browser scenario execution failed")
        observation_path = output / "scenario-observation.json"
        signature_path = output / "scenario-observation.json.sig"
        if not verify_file(control_public_key(campaign), observation_path, signature_path):
            raise WebContractError("browser scenario signature verification failed")
        return load_json(observation_path), [
            observation_path.relative_to(campaign).as_posix(),
            signature_path.relative_to(campaign).as_posix(),
        ]
    raise WebContractError("unsupported registered workflow runner")


def run_bounded_pair(
    campaign: Path,
    groups: list[dict[str, Any]],
    outputs: list[Path],
    *,
    secret_store: Path | None,
) -> list[tuple[dict[str, Any], list[str]]]:
    if len(groups) != 2 or len(outputs) != 2:
        raise WebContractError("bounded pair requires exactly two execution units")
    if any(group["action"]["runner"] != "krineon-http-broker-v1" for group in groups):
        raise WebContractError("bounded pair currently supports only the fixed HTTP broker")
    contract_paths = {group["contractPath"] for group in groups}
    if len(contract_paths) != 1:
        raise WebContractError("bounded pair must share one campaign contract")
    contract_path = next(iter(contract_paths))
    contract = WebCampaignContract.load(contract_path)
    authorization = contract.raw["authorization"]
    race = authorization["boundedRaceApproval"]
    if (
        authorization.get("allowBoundedConcurrency") is not True
        or race.get("approved") is not True
        or int(race.get("maxParticipants") or 0) != 2
        or race.get("availabilityObjective") is not False
    ):
        raise WebContractError("campaign contract does not approve a two-participant race")
    fixture = str(race.get("disposableFixture") or "")
    for group in groups:
        if len(group["operations"]) != 1 or len(group["workflow"].get("steps", [])) != 1:
            raise WebContractError("each bounded pair member must contain one signed operation")
        operation = group["operations"][0]
        if operation["cost"]["maxConcurrencyParticipants"] != 2:
            raise WebContractError("bounded pair member must declare two participants")
        if any(
            value["fixtureNamespace"] != fixture
            for value in operation["resourceBindings"]
        ):
            raise WebContractError(
                "bounded pair resource does not match the approved disposable fixture"
            )
        step = group["workflow"]["steps"][0]
        if step.get("operationClass") != "bounded-concurrency":
            raise WebContractError(
                "bounded pair workflow step must use operationClass bounded-concurrency"
            )
    if int(contract.raw["budget"]["maxConcurrentRequests"]) < 2:
        raise WebContractError("campaign budget does not permit the approved pair")

    ledger = SharedWebBudget(
        contract, campaign / "evidence" / "web" / "budget-ledger.sqlite3"
    )
    dispatch_barrier = threading.Barrier(2)
    completion_barrier = threading.Barrier(2)
    finalization_barrier = threading.Barrier(2)
    brokers = []
    for group, output in zip(groups, outputs, strict=True):
        brokers.append(
            WebExecutionBroker(
                campaign,
                contract,
                group["workflow"],
                ledger,
                output,
                SecretStore(
                    secret_store,
                    forbidden_root=campaign,
                    forbidden_roots=contract.raw["requestInputs"].get("sourceRoots", []),
                )
                if secret_store
                else None,
                allow_bounded_concurrency=True,
                dispatch_barrier=dispatch_barrier,
                completion_barrier=completion_barrier,
                finalization_barrier=finalization_barrier,
            )
        )
    lease = ExecutionLease(
        campaign / "evidence" / "web" / "execution.lock", "bounded-http-pair"
    )
    lease.acquire()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(broker.run) for broker in brokers]
            documents = [future.result() for future in futures]
    finally:
        lease.release()
    results = []
    for group, output, document in zip(groups, outputs, documents, strict=True):
        if document.get("failure") or document.get("cleanupErrors"):
            raise WebContractError(
                "bounded pair member failed: "
                + str(document.get("failure") or document.get("cleanupErrors"))
            )
        observation_path = output / "observation.json"
        signature_path = output / "observation.json.sig"
        budget_path = output / "budget-ledger.json"
        passed, errors, _ = verified_web_observation(
            campaign,
            contract_path=group["contractPath"],
            workflow_path=group["workflowPath"],
            workflow_signature=group["signaturePath"],
            observation_path=observation_path,
            observation_signature=signature_path,
            budget_ledger_path=budget_path,
            require_disagreement=False,
        )
        if not passed:
            raise WebContractError(
                "bounded pair observation verification failed: " + ", ".join(errors)
            )
        results.append(
            (
                document,
                [
                    observation_path.relative_to(campaign).as_posix(),
                    signature_path.relative_to(campaign).as_posix(),
                    budget_path.relative_to(campaign).as_posix(),
                ],
            )
        )
    return results


def observation_by_step(document: dict[str, Any], step_id: str) -> dict[str, Any]:
    for collection in (document.get("steps", []), document.get("runs", [])):
        for value in collection if isinstance(collection, list) else []:
            if not isinstance(value, dict):
                continue
            if str(value.get("id") or value.get("stepId") or value.get("workflowStep") or "") == step_id:
                return value
    raise WebContractError(f"runner output has no observation for workflow step {step_id}")


def build_state_observations(
    operations: list[dict[str, Any]],
    runner_documents: dict[str, dict[str, Any]],
    evidence: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    observations = []
    by_operation: dict[str, list[dict[str, Any]]] = {}
    for operation in operations:
        workflow_id = operation["actionRef"]["workflowId"]
        document = runner_documents[workflow_id]
        step = observation_by_step(document, operation["actionRef"]["stepId"])
        retained = []
        for contract in operation["observations"]:
            selectors = contract.get("stateSelectors")
            if not isinstance(selectors, dict) or not selectors:
                raise WebContractError("operation observation requires stateSelectors")
            state = {
                str(name): nested(step, str(selector))
                for name, selector in selectors.items()
            }
            binding = next(
                value
                for value in operation["resourceBindings"]
                if value["id"] == contract["resourceBindingRef"]
            )
            item = {
                "id": str(contract.get("id") or ""),
                "kind": str(contract.get("kind") or "authoritative-readback"),
                "authenticatedActor": operation["actorRef"]["id"],
                "effectiveActor": operation["actorRef"]["effectiveActor"],
                "resourceId": binding["id"],
                "ownerId": binding["owner"],
                "tenantId": binding["tenant"],
                "generation": binding["generation"],
                "evidenceOrigin": contract["evidenceOrigin"],
                "observedAt": str(
                    contract.get("observedAt")
                    or document.get("completedAt")
                    or document.get("createdAt")
                    or __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat()
                ),
                "state": state,
                "authoritative": True,
                "evidence": evidence[workflow_id],
            }
            observations.append(item)
            retained.append(item)
        by_operation[operation["id"]] = retained
    return observations, by_operation


def update_state(
    state: dict[str, Any],
    operation: dict[str, Any],
    observations: list[dict[str, Any]],
    step_specification: dict[str, Any] | None = None,
) -> None:
    state["completedOperations"].append(operation["id"])
    state["authorityBindings"].add(
        ":".join(operation["authorityBinding"].values())
    )
    state["authoritativeFacts"].update(
        f"state:{value['resourceId']}:{key}={item}"
        for value in observations
        for key, item in value["state"].items()
    )
    evidence_ids = {value["id"] for value in observations}
    for produced in operation["produces"]:
        if produced["provenance"].split(":", 1)[-1] not in evidence_ids:
            continue
        retained_value = dict(produced)
        retained_value["_issuedAt"] = min(
            (value["observedAt"] for value in observations),
            default=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        retained_value["_sequenceRunId"] = state.get("sequenceRunId")
        retained_value["_sessionRefreshVersion"] = state[
            "sessionRefreshVersions"
        ].get(operation["actorRef"]["id"])
        state["serverValues"][produced["id"]] = retained_value
        if produced["kind"] == "approval":
            state["approvals"][produced["id"]] = retained_value
        elif produced["kind"] == "relationship":
            state["relationships"][produced["id"]] = retained_value
        elif produced["kind"] == "capability":
            state["capabilities"][produced["id"]] = retained_value
        elif produced["kind"] == "job":
            state["jobs"][produced["id"]] = retained_value
    for invalidated in operation["invalidates"]:
        state["invalidatedValues"].add(invalidated["id"])
    transition = operation.get("identityTransition")
    if transition:
        actor_id = operation["actorRef"]["id"]
        state["sessionRefreshVersions"][actor_id] = transition[
            "toSessionRefreshVersion"
        ]
        if (
            state["permissionVersions"][actor_id]
            != transition["permissionVersionAfter"]
        ):
            raise WebContractError(
                "reauthentication attempted to restore or alter application permission state"
            )
    for permission in (step_specification or {}).get(
        "applicationPermissionTransitions", []
    ):
        actor_id = permission["actorRef"]
        if state["permissionVersions"].get(actor_id) != permission["from"]:
            raise WebContractError("application permission transition starts from stale state")
        state["permissionVersions"][actor_id] = permission["to"]


def admit_group(
    group: dict[str, Any],
    state: dict[str, Any],
    *,
    history: str,
    allowed_unsatisfied: set[str],
    allowed_stale_values: set[str],
    allowed_replayed_values: set[str],
    exceptions_used: dict[str, set[str]],
) -> set[str]:
    consumed_values: set[str] = set()
    prospective_state = {
        **state,
        "completedOperations": list(state["completedOperations"]),
        "sessionRefreshVersions": dict(state["sessionRefreshVersions"]),
        "permissionVersions": dict(state["permissionVersions"]),
    }
    for operation in group["operations"]:
        authority_versions(operation, prospective_state)
        unsatisfied = unsatisfied_requirement_refs(
            operation["requires"], prospective_state
        )
        if unsatisfied and not (
            history == "counterfactual" and unsatisfied.issubset(allowed_unsatisfied)
        ):
            raise WebContractError(
                f"server-visible prerequisites are not established for {operation['id']}"
            )
        exceptions_used["unsatisfiedRequirementRefs"].update(unsatisfied)
        for consumed in operation["consumes"]:
            produced = state["serverValues"].get(consumed["id"])
            invalidated = consumed["id"] in state["invalidatedValues"]
            replayed = consumed["id"] in state["consumedValues"]
            stale_exception = (
                history == "counterfactual"
                and consumed["id"] in allowed_stale_values
            )
            replay_exception = (
                history == "counterfactual"
                and consumed["id"] in allowed_replayed_values
            )
            if (
                produced is None
                or (invalidated and not stale_exception)
                or (
                    replayed
                    and produced is not None
                    and produced.get("singleUse") is not False
                    and not replay_exception
                )
                or (produced is not None and not value_not_expired(produced, operation, state))
            ):
                raise WebContractError(
                    f"consumed server value is unavailable, invalidated, or already used: {consumed['id']}"
                )
            if invalidated:
                exceptions_used["invalidatedValueRefs"].add(consumed["id"])
            if replayed:
                exceptions_used["replayedValueRefs"].add(consumed["id"])
            consumed_values.add(consumed["id"])
            if produced.get("intendedConsumer") not in {
                operation["actorRef"]["id"],
                operation["actorRef"]["effectiveActor"],
            }:
                raise WebContractError(
                    f"consumed value was not issued for this consumer: {consumed['id']}"
                )
            if consumed["actorBinding"] not in {
                operation["actorRef"]["id"],
                operation["actorRef"]["effectiveActor"],
            }:
                raise WebContractError(
                    f"consumed value is not bound to this operation actor: {consumed['id']}"
                )
            if produced["version"] != consumed["version"]:
                raise WebContractError(
                    f"consumed value generation does not match its producer: {consumed['id']}"
                )
            same_binding = (
                produced["actorBinding"] == consumed["actorBinding"]
                and produced["resourceBinding"] == consumed["resourceBinding"]
            )
            if not same_binding and (
                consumed["transferPolicy"] != "application-observed"
                or not consumed["transferEvidence"]
            ):
                raise WebContractError(
                    f"cross-identity value transfer is not application-observed: {consumed['id']}"
                )
        # Only operation ordering may be satisfied prospectively inside a
        # signed execution unit. Values and state still require a server
        # observation from an earlier completed unit.
        prospective_state["completedOperations"].append(operation["id"])
        transition = operation.get("identityTransition")
        if transition:
            prospective_state["sessionRefreshVersions"][
                operation["actorRef"]["id"]
            ] = transition["toSessionRefreshVersion"]
    return consumed_values


def execute_plan(
    campaign: Path,
    graph: dict[str, Any],
    plan_id: str,
    history: str,
    output: Path,
    *,
    secret_store: Path | None = None,
) -> dict[str, Any]:
    if graph.get("kind") not in {
        "krineon-web-sequence-graph",
        "krineon-web-forbidden-composition-frontier",
    }:
        raise WebContractError("input is not a Krineon sequence graph")
    plans = [value for value in graph.get("plans", []) if value.get("id") == plan_id]
    if len(plans) != 1:
        raise WebContractError("select one sequence plan")
    plan = plans[0]
    if history not in plan.get("histories", {}):
        raise WebContractError("select a declared legitimate, disputed, or control history")
    if not plan.get("executable") or not isinstance(plan.get("stateOracle"), dict):
        raise WebContractError("plan has no executable state oracle")
    by_id = {
        value["id"]: validate_operation(value) for value in graph.get("operations", [])
    }
    operations = [by_id[value] for value in plan["histories"][history]]
    specification = plan.get("sequenceSpecification")
    if graph.get("kind") == "krineon-web-forbidden-composition-frontier":
        specification = validate_specification(specification)
        if plan.get("sequenceSpecificationSha256") != sequence_digest(specification):
            raise WebContractError("sequence specification hash does not match the plan")
    step_specifications = {
        value["operationId"]: value
        for value in (specification or {}).get("steps", [])
    }
    exception_contract = plan.get("counterfactualExceptions", {})
    allowed_unsatisfied = set(
        map(str, exception_contract.get("unsatisfiedRequirementRefs", []))
    )
    allowed_stale_values = set(
        map(str, exception_contract.get("invalidatedValueRefs", []))
    ).union(map(str, exception_contract.get("replayedValueRefs", [])))
    allowed_replayed_values = set(
        map(str, exception_contract.get("replayedValueRefs", []))
    )
    exceptions_used = {
        "unsatisfiedRequirementRefs": set(),
        "invalidatedValueRefs": set(),
        "replayedValueRefs": set(),
    }
    run_id = str(uuid.uuid4())
    state = json.loads(json.dumps(plan["executionState"]))
    if specification:
        state.setdefault("actors", {}).update(
            {
                value["id"]: value
                for value in specification["verifiedContext"]["actors"]
            }
        )
    state.update(
        {
            "sequenceRunId": run_id,
            "capabilities": {},
            "authorityBindings": set(),
            "authoritativeFacts": set(),
            "invalidatedValues": set(state.get("invalidatedValues", [])),
            "consumedValues": set(state.get("consumedValues", [])),
            "sessionRefreshVersions": {
                actor_id: actor["sessionRefreshVersion"]
                for actor_id, actor in state.get("actors", {}).items()
            },
            "permissionVersions": {
                actor_id: actor["permissionVersion"]
                for actor_id, actor in state.get("actors", {}).items()
            },
        }
    )
    initial_authority = (specification or {}).get("verifiedContext", {}).get(
        "initialAuthority", {}
    )
    state["sessionRefreshVersions"].update(
        initial_authority.get("sessionRefreshVersions", {})
    )
    state["permissionVersions"].update(initial_authority.get("permissionVersions", {}))
    groups = workflow_groups(campaign, operations)
    output.mkdir(parents=True, exist_ok=False)
    runner_documents: dict[str, dict[str, Any]] = {}
    evidence: dict[str, list[str]] = {}
    state_observations: list[dict[str, Any]] = []
    transition_timeline: list[dict[str, Any]] = []
    async_inconclusive: str | None = None
    pair_indices = [
        index
        for index, group in enumerate(groups)
        if any(
            operation["cost"]["maxConcurrencyParticipants"] == 2
            for operation in group["operations"]
        )
    ]
    if pair_indices and (
        plan.get("family") != "bounded-concurrency"
        or len(pair_indices) != 2
        or pair_indices[1] != pair_indices[0] + 1
    ):
        raise WebContractError(
            "paired operations must be the one adjacent approved bounded-concurrency pair"
        )
    if (
        plan.get("family") == "bounded-concurrency"
        and history == "counterfactual"
        and len(pair_indices) != 2
    ):
        raise WebContractError("counterfactual bounded-concurrency history has no staged pair")

    index = 0
    while index < len(groups):
        selected_groups = [groups[index]]
        paired = pair_indices and index == pair_indices[0]
        if paired:
            selected_groups.append(groups[index + 1])
        consumed_by_group = [
            admit_group(
                group,
                state,
                history=history,
                allowed_unsatisfied=allowed_unsatisfied,
                allowed_stale_values=allowed_stale_values,
                allowed_replayed_values=allowed_replayed_values,
                exceptions_used=exceptions_used,
            )
            for group in selected_groups
        ]
        outputs = [
            output / f"unit-{index + offset + 1}"
            for offset in range(len(selected_groups))
        ]
        if paired:
            execution_results = run_bounded_pair(
                campaign,
                selected_groups,
                outputs,
                secret_store=secret_store,
            )
        else:
            execution_results = [
                run_group(
                    campaign,
                    selected_groups[0],
                    outputs[0],
                    secret_store=secret_store,
                )
            ]
        for group, consumed_values, (document, references) in zip(
            selected_groups, consumed_by_group, execution_results, strict=True
        ):
            workflow_id = group["action"]["workflowId"]
            if workflow_id in runner_documents:
                raise WebContractError("a workflow may execute only once per bounded history")
            runner_documents[workflow_id] = document
            evidence[workflow_id] = references
            group_observations, operation_observations = build_state_observations(
                group["operations"],
                {workflow_id: document},
                {workflow_id: references},
            )
            state_observations.extend(group_observations)
            for operation in group["operations"]:
                before = serializable_state(state)
                retained = operation_observations[operation["id"]]
                update_state(
                    state,
                    operation,
                    retained,
                    step_specifications.get(operation["id"]),
                )
                complete, reason = evaluate_async_wait(operation, retained)
                transition_timeline.append(
                    {
                        "operationId": operation["id"],
                        "beforeStateSha256": sequence_digest(before),
                        "afterStateSha256": sequence_digest(serializable_state(state)),
                        "observationIds": [value["id"] for value in retained],
                        "referenceExpectation": step_specifications.get(
                            operation["id"], {}
                        ).get("referenceExpectation"),
                        "implementationObservation": (
                            "predicate-satisfied" if complete else reason
                        ),
                    }
                )
                if not complete:
                    async_inconclusive = reason
            state["consumedValues"].update(consumed_values)
        index += len(selected_groups)
        if async_inconclusive:
            break
    cleanup_complete = all(
        not document.get("cleanupErrors") for document in runner_documents.values()
    )
    declared_exceptions = {
        "unsatisfiedRequirementRefs": allowed_unsatisfied,
        "invalidatedValueRefs": set(
            map(str, exception_contract.get("invalidatedValueRefs", []))
        ),
        "replayedValueRefs": set(
            map(str, exception_contract.get("replayedValueRefs", []))
        ),
    }
    unused_exceptions = {
        key: sorted(value.difference(exceptions_used[key]))
        for key, value in declared_exceptions.items()
        if value.difference(exceptions_used[key])
    }
    oracle_document = {
        "schemaVersion": 1,
        "prerequisiteVersion": graph["prerequisiteVersion"],
        "runState": (
            async_inconclusive
            or (
            "missing-telemetry"
            if history == "counterfactual" and unused_exceptions
            else "completed"
            )
        ),
        "cleanupComplete": cleanup_complete,
        "observations": state_observations,
    }
    evaluation = evaluate_state_oracle(plan["stateOracle"], oracle_document)
    public_state = {
        **state,
        "authorityBindings": sorted(state["authorityBindings"]),
        "authoritativeFacts": sorted(state["authoritativeFacts"]),
        "invalidatedValues": sorted(state["invalidatedValues"]),
        "consumedValues": sorted(state["consumedValues"]),
    }
    result = {
        "schemaVersion": 1,
        "kind": "krineon-web-sequence-execution",
        "planId": plan_id,
        "history": history,
        "runId": run_id,
        "prerequisiteVersion": graph["prerequisiteVersion"],
        "state": public_state,
        "observations": state_observations,
        "oracleResult": evaluation,
        "cleanupComplete": cleanup_complete,
        "runnerEvidence": evidence,
        "runnerEvidenceHashes": retained_evidence_hashes(campaign, evidence),
        "executedOperationIds": [value["id"] for value in operations[: len(transition_timeline)]],
        "transitionTimeline": transition_timeline,
        "sequenceSpecification": specification,
        "sequenceSpecificationSha256": sequence_digest(specification)
        if specification
        else None,
        "counterfactualExceptionsUsed": {
            key: sorted(value) for key, value in exceptions_used.items()
        },
        "unusedCounterfactualExceptions": unused_exceptions,
    }
    atomic_json(output / "sequence-result.json", result, mode=0o600)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("graph", type=Path)
    parser.add_argument("plan_id")
    parser.add_argument("history")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--secret-store", type=Path)
    args = parser.parse_args(argv)
    try:
        result = execute_plan(
            args.campaign.expanduser().resolve(),
            load_json(args.graph.expanduser().resolve()),
            args.plan_id,
            args.history,
            args.output.expanduser().resolve(),
            secret_store=args.secret_store.expanduser().resolve()
            if args.secret_store
            else None,
        )
        print(json.dumps({"planId": result["planId"], "outcome": result["oracleResult"]["outcome"]}, indent=2))
        return 0 if result["oracleResult"]["outcome"] != "inconclusive" else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
