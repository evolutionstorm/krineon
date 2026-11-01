#!/usr/bin/env python3
"""Build bounded multi-actor workflow experiments from explicit operation contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


RUNNERS = {"krineon-http-broker-v1", "krineon-chrome-cdp-v1"}
EFFECTS = {"read-only", "disposable-write"}


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def string_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise WebContractError(f"{field} must be a{' non-empty' if not allow_empty else ''} list")
    result = [text(item, field) for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} must not contain duplicates")
    return result


def validate_requirement(value: Any, field: str = "requires") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError(f"{field} must be a logical requirement object")
    operator = str(value.get("operator") or "")
    if operator in {"and", "or"}:
        clauses = value.get("clauses")
        if not isinstance(clauses, list) or not clauses:
            raise WebContractError(f"{field}.{operator} requires clauses")
        return {
            "operator": operator,
            "clauses": [
                validate_requirement(item, f"{field}.clauses[{index}]")
                for index, item in enumerate(clauses)
            ],
        }
    if operator != "fact":
        raise WebContractError(f"{field}.operator must be and, or, or fact")
    fact_type = str(value.get("type") or "")
    if fact_type not in {
        "state",
        "authority",
        "approval",
        "relationship",
        "capability",
        "server-value",
        "operation",
    }:
        raise WebContractError(f"{field}.type is unsupported")
    return {
        "operator": "fact",
        "type": fact_type,
        "ref": text(value.get("ref"), f"{field}.ref"),
        "expected": value.get("expected", True),
        "evidence": value.get("evidence", []),
    }


def requirement_refs(value: dict[str, Any]) -> set[str]:
    if value["operator"] == "fact":
        return {str(value["ref"])}
    return {
        ref
        for clause in value["clauses"]
        for ref in requirement_refs(clause)
    }


def validate_value_contract(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError(f"{field} must be an object")
    transfer_policy = str(value.get("transferPolicy") or "")
    if transfer_policy not in {"same-actor", "application-observed"}:
        raise WebContractError(
            f"{field}.transferPolicy must be same-actor or application-observed"
        )
    transfer_evidence = value.get("transferEvidence", [])
    if transfer_policy == "application-observed" and (
        not isinstance(transfer_evidence, list) or not transfer_evidence
    ):
        raise WebContractError(
            f"{field} application-observed transfer requires evidence"
        )
    lifecycle_explicit = (
        value.get("lifecycleExplicit") is True
        if "lifecycleExplicit" in value
        else all(
            name in value
            for name in ("issuer", "intendedConsumer", "expiryPolicy", "singleUse")
        )
    )
    expiry_policy = str(value.get("expiryPolicy") or "unspecified")
    if expiry_policy not in {
        "absolute-time",
        "relative-seconds",
        "operation-bounded",
        "session-bounded",
        "never",
        "unspecified",
    }:
        raise WebContractError(f"{field}.expiryPolicy is unsupported")
    expiry_value = value.get("expiryValue")
    if expiry_policy in {"absolute-time", "relative-seconds"} and (
        expiry_value is None or expiry_value == ""
    ):
        raise WebContractError(f"{field}.expiryValue is required by expiryPolicy")
    single_use = value.get("singleUse")
    if single_use is not None and not isinstance(single_use, bool):
        raise WebContractError(f"{field}.singleUse must be Boolean")
    return {
        "id": text(value.get("id"), f"{field}.id"),
        "kind": text(value.get("kind"), f"{field}.kind"),
        "provenance": text(value.get("provenance"), f"{field}.provenance"),
        "actorBinding": text(value.get("actorBinding"), f"{field}.actorBinding"),
        "resourceBinding": text(
            value.get("resourceBinding"), f"{field}.resourceBinding"
        ),
        "version": text(value.get("version"), f"{field}.version"),
        "transferPolicy": transfer_policy,
        "transferEvidence": transfer_evidence,
        "issuer": str(value.get("issuer") or value.get("actorBinding") or ""),
        "intendedConsumer": str(
            value.get("intendedConsumer") or value.get("actorBinding") or ""
        ),
        "expiryPolicy": expiry_policy,
        "expiryValue": expiry_value,
        "singleUse": single_use,
        "lifecycleExplicit": lifecycle_explicit,
    }


def validate_async_wait(raw: Any, observations: list[dict[str, Any]], cost: dict[str, int]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WebContractError("asynchronous operations require an observed asyncWait contract")
    mode = str(raw.get("mode") or "")
    if mode not in {"bounded-poll", "approved-event"}:
        raise WebContractError("asyncWait.mode must be bounded-poll or approved-event")
    observation_id = text(raw.get("observationId"), "asyncWait.observationId")
    observation = next(
        (value for value in observations if value["id"] == observation_id), None
    )
    if observation is None:
        raise WebContractError("asyncWait must select an authoritative operation observation")
    state_field = text(raw.get("stateField"), "asyncWait.stateField")
    attempts_field = text(raw.get("attemptsField"), "asyncWait.attemptsField")
    selectors = observation["stateSelectors"]
    if state_field not in selectors or attempts_field not in selectors:
        raise WebContractError("asyncWait state and attempt fields must be retained observations")
    operator = str(raw.get("operator") or "")
    if operator not in {"equals", "not-equals", "contains", "not-contains"}:
        raise WebContractError("asyncWait.operator is unsupported")
    max_polls = raw.get("maxPolls")
    if not isinstance(max_polls, int) or isinstance(max_polls, bool) or max_polls < 0:
        raise WebContractError("asyncWait.maxPolls must be a non-negative integer")
    if max_polls > cost["maxPolling"]:
        raise WebContractError("asyncWait.maxPolls exceeds the operation polling budget")
    retry_policy = str(raw.get("retryPolicy") or "")
    if retry_policy not in {"no-retry", "fixed-bounded", "owner-consistency-window"}:
        raise WebContractError("asyncWait.retryPolicy is unsupported")
    if mode == "bounded-poll" and max_polls < 1:
        raise WebContractError("bounded polling requires at least one approved poll")
    evidence = raw.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise WebContractError("asyncWait requires policy or workflow evidence")
    return {
        "mode": mode,
        "observationId": observation_id,
        "stateField": state_field,
        "attemptsField": attempts_field,
        "operator": operator,
        "expected": raw.get("expected"),
        "maxPolls": max_polls,
        "retryPolicy": retry_policy,
        "evidence": list(evidence),
        "unfinishedOutcome": "inconclusive",
    }


def validate_operation(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WebContractError("operation contract must be an object")
    operation_id = text(raw.get("id"), "operation.id")
    actor = raw.get("actorRef")
    if not isinstance(actor, dict) or actor.get("verified") is not True:
        raise WebContractError("actorRef must be a verified identity")
    normalized_actor = {
        "id": text(actor.get("id"), "actorRef.id"),
        "role": text(actor.get("role"), "actorRef.role"),
        "tenant": text(actor.get("tenant"), "actorRef.tenant"),
        "session": text(actor.get("session"), "actorRef.session"),
        "verified": True,
        "effectiveActor": text(
            actor.get("effectiveActor"), "actorRef.effectiveActor"
        ),
        "capabilityVersion": text(
            actor.get("capabilityVersion"), "actorRef.capabilityVersion"
        ),
        "sessionRefreshVersion": text(
            actor.get("sessionRefreshVersion") or actor.get("capabilityVersion"),
            "actorRef.sessionRefreshVersion",
        ),
        "permissionVersion": text(
            actor.get("permissionVersion") or actor.get("capabilityVersion"),
            "actorRef.permissionVersion",
        ),
        "authorityVersionsExplicit": (
            actor.get("authorityVersionsExplicit") is True
            if "authorityVersionsExplicit" in actor
            else "sessionRefreshVersion" in actor and "permissionVersion" in actor
        ),
    }
    action = raw.get("actionRef")
    if not isinstance(action, dict) or action.get("runner") not in RUNNERS:
        raise WebContractError("actionRef must select a registered web runner")
    effect = str(action.get("effectClass") or "")
    if effect not in EFFECTS:
        raise WebContractError("business sequence effect must be read-only or disposable-write")
    normalized_action = {
        "runner": action["runner"],
        "workflow": text(action.get("workflow"), "actionRef.workflow"),
        "signature": text(action.get("signature"), "actionRef.signature"),
        "campaignContract": text(
            action.get("campaignContract"), "actionRef.campaignContract"
        ),
        "workflowId": text(action.get("workflowId"), "actionRef.workflowId"),
        "stepId": text(action.get("stepId"), "actionRef.stepId"),
        "effectClass": effect,
    }
    if action["runner"] == "krineon-chrome-cdp-v1":
        normalized_action["scenario"] = text(
            action.get("scenario"), "actionRef.scenario"
        )
        normalized_action["browserRunnerRef"] = text(
            action.get("browserRunnerRef"), "actionRef.browserRunnerRef"
        )
    bindings = raw.get("resourceBindings")
    if not isinstance(bindings, list) or not bindings:
        raise WebContractError("resourceBindings must identify owned fixtures")
    normalized_bindings = []
    for index, binding in enumerate(bindings):
        if (
            not isinstance(binding, dict)
            or binding.get("owned") is not True
            or binding.get("disposable") is not True
        ):
            raise WebContractError("each resource binding must be owned and disposable")
        normalized_bindings.append(
            {
                "id": text(binding.get("id"), f"resourceBindings[{index}].id"),
                "kind": text(binding.get("kind"), f"resourceBindings[{index}].kind"),
                "parent": text(
                    binding.get("parent"), f"resourceBindings[{index}].parent"
                ),
                "tenant": text(
                    binding.get("tenant"), f"resourceBindings[{index}].tenant"
                ),
                "owner": text(
                    binding.get("owner"), f"resourceBindings[{index}].owner"
                ),
                "version": text(
                    binding.get("version"), f"resourceBindings[{index}].version"
                ),
                "generation": text(
                    binding.get("generation"),
                    f"resourceBindings[{index}].generation",
                ),
                "fixtureNamespace": text(
                    binding.get("fixtureNamespace"),
                    f"resourceBindings[{index}].fixtureNamespace",
                ),
                "owned": True,
                "disposable": True,
            }
        )
    requires = validate_requirement(raw.get("requires"))
    produces = [
        validate_value_contract(value, f"produces[{index}]")
        for index, value in enumerate(raw.get("produces", []))
    ]
    consumes = [
        validate_value_contract(value, f"consumes[{index}]")
        for index, value in enumerate(raw.get("consumes", []))
    ]
    invalidates = [
        validate_value_contract(value, f"invalidates[{index}]")
        for index, value in enumerate(raw.get("invalidates", []))
    ]
    binding_ids = {value["id"] for value in normalized_bindings}
    permitted_actors = {
        normalized_actor["id"],
        normalized_actor["effectiveActor"],
    }
    for field, values in (
        ("produces", produces),
        ("consumes", consumes),
        ("invalidates", invalidates),
    ):
        for value in values:
            if value["actorBinding"] not in permitted_actors:
                raise WebContractError(
                    f"{field} actorBinding must match the authenticated or effective actor"
                )
            if value["resourceBinding"] not in binding_ids:
                raise WebContractError(
                    f"{field} resourceBinding must select an exact owned operation resource"
                )
    authority = raw.get("authorityBinding")
    if not isinstance(authority, dict):
        raise WebContractError("authorityBinding must be an object")
    normalized_authority = {
        field: text(authority.get(field), f"authorityBinding.{field}")
        for field in ("actor", "resource", "action", "version")
    }
    if normalized_authority["actor"] not in permitted_actors:
        raise WebContractError(
            "authorityBinding.actor must match the authenticated or effective actor"
        )
    if normalized_authority["resource"] not in binding_ids:
        raise WebContractError(
            "authorityBinding.resource must select an exact owned operation resource"
        )
    ordering = raw.get("ordering")
    if not isinstance(ordering, dict):
        raise WebContractError("ordering must be an object")
    normalized_ordering = {
        "after": string_list(ordering.get("after", []), "ordering.after", allow_empty=True),
        "before": string_list(
            ordering.get("before", []), "ordering.before", allow_empty=True
        ),
        "asyncBoundary": bool(ordering.get("asyncBoundary")),
        "sequencingHintOnly": bool(ordering.get("sequencingHintOnly")),
        "dependencyConfidence": str(
            ordering.get("dependencyConfidence") or "hypothesized"
        ),
        "evidence": ordering.get("evidence", []),
    }
    if normalized_ordering["dependencyConfidence"] not in {
        "hypothesized",
        "replay-confirmed",
    }:
        raise WebContractError("ordering dependency confidence is unsupported")
    if normalized_ordering["sequencingHintOnly"] and normalized_ordering[
        "dependencyConfidence"
    ] == "replay-confirmed":
        raise WebContractError("a sequencing hint cannot be replay-confirmed")
    observations = raw.get("observations")
    if not isinstance(observations, list) or not observations:
        raise WebContractError("operation requires authoritative observations")
    normalized_observations = []
    for index, value in enumerate(observations):
        if not isinstance(value, dict) or value.get("authoritative") is not True:
            raise WebContractError("operation observations must be authoritative")
        if value.get("evidenceOrigin") not in {
            "server-response",
            "server-persisted-readback",
            "signed-browser-network-response",
            "owner-control-plane-readback",
        }:
            raise WebContractError("operation observation origin is not authoritative")
        binding_ref = text(
            value.get("resourceBindingRef"),
            f"observations[{index}].resourceBindingRef",
        )
        if binding_ref not in binding_ids:
            raise WebContractError(
                "observation resourceBindingRef must select an exact owned resource"
            )
        selectors = value.get("stateSelectors")
        if not isinstance(selectors, dict) or not selectors:
            raise WebContractError("operation observation requires stateSelectors")
        normalized_observations.append(
            {
                "id": text(value.get("id"), f"observations[{index}].id"),
                "kind": text(value.get("kind"), f"observations[{index}].kind"),
                "authoritative": True,
                "evidenceOrigin": value["evidenceOrigin"],
                "resourceBindingRef": binding_ref,
                "stateSelectors": {
                    text(name, "state selector name"): text(
                        selector, "state selector path"
                    )
                    for name, selector in selectors.items()
                },
                "observedAt": value.get("observedAt"),
            }
        )
    consistency = raw.get("consistencyWindow")
    if not isinstance(consistency, dict):
        raise WebContractError("consistencyWindow must be an object")
    maximum = consistency.get("maximumSeconds")
    if not isinstance(maximum, (int, float)) or maximum < 0:
        raise WebContractError("consistencyWindow.maximumSeconds must be non-negative")
    cleanup = raw.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("irreversible") is True:
        raise WebContractError("operation cleanup must be safe and reversible")
    if effect == "disposable-write" and not cleanup.get("hookRef"):
        raise WebContractError("disposable writes require a cleanup hook")
    cost = raw.get("cost")
    if not isinstance(cost, dict):
        raise WebContractError("operation cost must be an object")
    normalized_cost = {}
    for field in (
        "maxRequests",
        "maxSteps",
        "maxBytes",
        "maxPolling",
        "maxEffects",
        "maxConcurrencyParticipants",
    ):
        value = cost.get(field)
        if not isinstance(value, int) or value < 0:
            raise WebContractError(f"cost.{field} must be a non-negative integer")
        normalized_cost[field] = value
    if normalized_cost["maxConcurrencyParticipants"] > 2:
        raise WebContractError("business concurrency is limited to a staged pair")
    async_wait = None
    if any(value["kind"] == "job" for value in produces):
        async_wait = validate_async_wait(raw.get("asyncWait"), normalized_observations, normalized_cost)
    elif raw.get("asyncWait") is not None:
        async_wait = validate_async_wait(raw.get("asyncWait"), normalized_observations, normalized_cost)
    identity_transition = raw.get("identityTransition")
    normalized_identity_transition = None
    if identity_transition is not None:
        if not isinstance(identity_transition, dict) or identity_transition.get("kind") != "reauthenticate":
            raise WebContractError("identityTransition must be an explicit reauthenticate transition")
        normalized_identity_transition = {
            "kind": "reauthenticate",
            "fromSessionRefreshVersion": text(
                identity_transition.get("fromSessionRefreshVersion"),
                "identityTransition.fromSessionRefreshVersion",
            ),
            "toSessionRefreshVersion": text(
                identity_transition.get("toSessionRefreshVersion"),
                "identityTransition.toSessionRefreshVersion",
            ),
            "permissionVersionBefore": text(
                identity_transition.get("permissionVersionBefore"),
                "identityTransition.permissionVersionBefore",
            ),
            "permissionVersionAfter": text(
                identity_transition.get("permissionVersionAfter"),
                "identityTransition.permissionVersionAfter",
            ),
            "startingConditionsReestablished": identity_transition.get(
                "startingConditionsReestablished"
            )
            is True,
            "evidence": identity_transition.get("evidence", []),
        }
        if (
            normalized_identity_transition["permissionVersionBefore"]
            != normalized_identity_transition["permissionVersionAfter"]
        ):
            raise WebContractError(
                "reauthentication cannot restore or alter an application permission version"
            )
        if not normalized_identity_transition["startingConditionsReestablished"] or not normalized_identity_transition["evidence"]:
            raise WebContractError(
                "reauthentication must re-establish the hypothesis starting conditions with evidence"
            )
    return {
        "id": operation_id,
        "actorRef": normalized_actor,
        "actionRef": normalized_action,
        "resourceBindings": normalized_bindings,
        "requires": requires,
        "produces": produces,
        "consumes": consumes,
        "invalidates": invalidates,
        "authorityBinding": normalized_authority,
        "ordering": normalized_ordering,
        "observations": normalized_observations,
        "consistencyWindow": consistency,
        "cleanup": cleanup,
        "cost": normalized_cost,
        "asyncWait": async_wait,
        "identityTransition": normalized_identity_transition,
    }


def sum_cost(operations: list[dict[str, Any]]) -> dict[str, int]:
    fields = operations[0]["cost"].keys() if operations else []
    return {field: sum(int(value["cost"][field]) for value in operations) for field in fields}


def minimization_candidates(
    history: list[str], operations: dict[str, dict[str, Any]], edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Identify only candidates; never erase history without a fresh replay."""

    if len(history) < 3:
        return []
    required = {history[0], history[-1]}
    for edge in edges:
        if edge.get("from") in history and edge.get("to") in history:
            required.update({str(edge["from"]), str(edge["to"])})
    for operation_id in history:
        operation = operations[operation_id]
        required.update(
            ref
            for ref in requirement_refs(operation["requires"])
            if ref in operations
        )
        if operation["invalidates"] or operation["actionRef"]["effectClass"] != "read-only":
            required.add(operation_id)
    return [
        {
            "operationId": operation_id,
            "status": "candidate-requires-counterfactual-replay",
            "preserve": [
                "actor identity",
                "resource ownership and generation",
                "server-issued values",
                "nonce and invalidation history",
            ],
        }
        for operation_id in history[1:-1]
        if operation_id not in required
    ]


def semantic_adapter(
    operations: list[dict[str, Any]], edges: list[dict[str, Any]], plans: list[dict[str, Any]]
) -> dict[str, Any]:
    facts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for operation in operations:
        actor = operation["actorRef"]
        actor_fact = f"actor:{actor['id']}:{actor['capabilityVersion']}"
        if actor_fact not in seen:
            seen.add(actor_fact)
            facts.append(
                {
                    "id": actor_fact,
                    "kind": "verified-actor",
                    "confidence": "owner-specified",
                    "actorId": actor["id"],
                    "tenantId": actor["tenant"],
                    "operation": "identity-fixture",
                }
            )
        for resource in operation["resourceBindings"]:
            resource_fact = f"resource:{resource['id']}:{resource['generation']}"
            if resource_fact in seen:
                continue
            seen.add(resource_fact)
            facts.append(
                {
                    "id": resource_fact,
                    "kind": "concrete-resource",
                    "confidence": "owner-specified",
                    "actorId": resource["owner"],
                    "tenantId": resource["tenant"],
                    "resourceId": resource["id"],
                    "operation": "owned-fixture",
                    "stateBefore": resource["generation"],
                }
            )
        facts.append(
            {
                "id": f"transition:{operation['id']}",
                "kind": "workflow-transition",
                "confidence": "hypothesized",
                "actorId": actor["id"],
                "tenantId": actor["tenant"],
                "resourceId": operation["resourceBindings"][0]["id"],
                "operation": operation["id"],
                "stateBefore": "requires-authoritative-readback",
                "stateAfter": "requires-authoritative-readback",
            }
        )
        for produced in operation["produces"]:
            kind = "job" if produced["kind"] == "job" else "approval" if produced["kind"] == "approval" else None
            if kind:
                facts.append(
                    {
                        "id": f"{kind}:{produced['id']}",
                        "kind": kind,
                        "confidence": "hypothesized",
                        "actorId": produced["actorBinding"],
                        "resourceId": produced["resourceBinding"],
                        "operation": operation["id"],
                        "valueProvenance": produced["provenance"],
                    }
                )
    relations = [
        {
            "id": stable_id("BLR", edge),
            "kind": "web-workflow-edge",
            "profile": "web-app",
            "from": f"transition:{edge['from']}",
            "to": f"transition:{edge['to']}",
            "relationState": "known"
            if edge.get("status") == "replay-confirmed"
            else "inferred",
            "evidence": edge.get("evidence", []),
        }
        for edge in edges
    ]
    candidates = [
        {
            "id": plan["id"],
            "kind": "business-workflow-differential",
            "question": f"Does {plan['family']} preserve the explicit business rule?",
            "executableOracle": bool(plan["executable"]),
            "blockedReason": (
                None
                if plan["executable"]
                else plan.get("blockedReason")
                or "an explicit authoritative state oracle is required"
            ),
            "estimatedExecutions": sum(
                value.get("maxRequests", 0)
                for value in plan["cost"].values()
            ),
        }
        for plan in plans
    ]
    return {"facts": facts, "relations": relations, "experimentCandidates": candidates}


def build_graph(
    workflow: dict[str, Any], business_logic: dict[str, Any]
) -> dict[str, Any]:
    if workflow.get("schemaVersion") != 1:
        raise WebContractError("workflow template schemaVersion must be 1")
    if business_logic.get("kind") != "krineon-web-business-logic":
        raise WebContractError("input is not compiled business logic")
    operations = [validate_operation(value) for value in workflow.get("operationContracts", [])]
    by_id = {value["id"]: value for value in operations}
    if len(by_id) != len(operations) or not operations:
        raise WebContractError("operationContracts must be non-empty with unique ids")
    produced_by: dict[str, str] = {}
    for operation in operations:
        for produced in operation["produces"]:
            if produced["id"] in produced_by:
                raise WebContractError(f"value has multiple producers: {produced['id']}")
            produced_by[produced["id"]] = operation["id"]
    edges = []
    for operation in operations:
        for predecessor in operation["ordering"]["after"]:
            if predecessor not in by_id:
                raise WebContractError(f"unknown ordering predecessor: {predecessor}")
            edges.append(
                {
                    "from": predecessor,
                    "to": operation["id"],
                    "kind": "ordering",
                    "status": operation["ordering"]["dependencyConfidence"],
                    "sequencingHintOnly": operation["ordering"]["sequencingHintOnly"],
                    "evidence": operation["ordering"]["evidence"],
                }
            )
        for consumed in operation["consumes"]:
            producer = produced_by.get(consumed["id"])
            if producer:
                edges.append(
                    {
                        "from": producer,
                        "to": operation["id"],
                        "kind": "produced-consumed-value",
                        "value": consumed["id"],
                        "status": "replay-confirmed"
                        if consumed["provenance"].startswith("broker-observation:")
                        else "hypothesized",
                        "identityTransferPermitted": consumed["actorBinding"]
                        == by_id[producer]["produces"][
                            next(
                                index
                                for index, value in enumerate(by_id[producer]["produces"])
                                if value["id"] == consumed["id"]
                            )
                        ]["actorBinding"]
                        or consumed["transferPolicy"] == "application-observed",
                    }
                )
    plans = []
    for hypothesis in business_logic.get("hypotheses", []):
        if not isinstance(hypothesis, dict):
            continue
        normal_ids = list(map(str, hypothesis.get("normalWorkflow", [])))
        counterfactual_ids = list(map(str, hypothesis.get("counterfactual", [])))
        unknown = [value for value in [*normal_ids, *counterfactual_ids] if value not in by_id]
        if unknown:
            raise WebContractError(
                "business hypothesis references unknown operations: " + ", ".join(unknown)
            )
        normal = [by_id[value] for value in normal_ids]
        counterfactual = [by_id[value] for value in counterfactual_ids]
        if hypothesis["family"] == "bounded-concurrency":
            normal_pair_members = [
                value
                for value in normal
                if value["cost"]["maxConcurrencyParticipants"] == 2
            ]
            counterfactual_pair_members = [
                value
                for value in counterfactual
                if value["cost"]["maxConcurrencyParticipants"] == 2
            ]
            if normal_pair_members or len(counterfactual_pair_members) != 2:
                raise WebContractError(
                    "bounded concurrency requires a sequential normal history and exactly two counterfactual pair members"
                )
        actors = {
            value["actorRef"]["id"]: value["actorRef"]
            for value in [*normal, *counterfactual]
        }
        resources = {
            value["id"]: value
            for operation in [*normal, *counterfactual]
            for value in operation["resourceBindings"]
        }
        plan = {
                "id": stable_id(
                    "BSP", [hypothesis["id"], normal_ids, counterfactual_ids]
                ),
                "hypothesisId": hypothesis["id"],
                "family": hypothesis["family"],
                "prerequisiteVersion": business_logic["prerequisiteVersion"],
                "executionState": {
                    "actors": actors,
                    "resources": resources,
                    "serverValues": {},
                    "jobs": {},
                    "approvals": {},
                    "relationships": {},
                    "completedOperations": [],
                    "invalidatedValues": [],
                },
                "histories": {
                    "normal": normal_ids,
                    "counterfactual": counterfactual_ids,
                },
                "cost": {
                    "normal": sum_cost(normal),
                    "counterfactual": sum_cost(counterfactual),
                },
                "stateOracle": hypothesis.get("stateOracle"),
                "executable": hypothesis.get("stateOracle") is not None,
                "blockedReason": None,
                "counterfactualExceptions": hypothesis.get(
                    "counterfactualExceptions",
                    {
                        "unsatisfiedRequirementRefs": [],
                        "invalidatedValueRefs": [],
                        "replayedValueRefs": [],
                    },
                ),
                "requiredEvidence": hypothesis.get("minimumEvidence", []),
                "cleanupRequired": any(
                    operation["actionRef"]["effectClass"] == "disposable-write"
                    for operation in [*normal, *counterfactual]
                ),
            }
        plan["minimizationCandidates"] = {
            "normal": minimization_candidates(normal_ids, by_id, edges),
            "counterfactual": minimization_candidates(counterfactual_ids, by_id, edges),
        }
        plans.append(plan)
    adapter = semantic_adapter(operations, edges, plans)
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-sequence-graph",
        "prerequisiteVersion": business_logic["prerequisiteVersion"],
        "operations": operations,
        "edges": edges,
        "plans": plans,
        "semanticIRAdapter": adapter,
        "policy": {
            "markdownPositionProvesCausality": False,
            "allActorsAndResourcesRetained": True,
            "authenticatedAndEffectiveActorDistinct": True,
            "localStateSatisfiesPrerequisites": False,
            "unknownConsistencyIsBypass": False,
            "irreversibleActionsBlocked": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    parser.add_argument("business_logic", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        workflow = json.loads(args.workflow.read_text(encoding="utf-8"))
        business = json.loads(args.business_logic.read_text(encoding="utf-8"))
        result = build_graph(workflow, business)
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"operations": len(result["operations"]), "plans": len(result["plans"])}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
