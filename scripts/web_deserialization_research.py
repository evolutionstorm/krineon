#!/usr/bin/env python3
"""Generate and evaluate bounded deserialization-boundary experiments.

The generator supports small JSON structure mutations only. It never imports,
evaluates, instantiates, or executes target-controlled types. Target reachability
must be established by a coordinator-approved runner and retained observations.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


INGRESS_KINDS = {
    "structured-import",
    "signed-opaque-state",
    "cookie",
    "rpc-message",
    "typed-json",
    "framework-serialization",
    "supported-upload-import",
}
CONFIDENCE = {"observed", "source-supported"}
INTEGRITY = {"none", "signed", "mac", "encrypted-and-authenticated", "unknown"}
MUTATIONS = {"set-field", "remove-field", "replace-type", "add-field", "reorder-object"}
SIGNATURE_MODES = {
    "not-applicable",
    "preserve-legitimate",
    "recompute-owned-test-authority",
    "invalid-signature-control",
}
ALLOWED_CANARY_EFFECTS = {
    "owned-record-label-change",
    "owned-role-selection-observation",
    "owned-dispatch-selection-observation",
    "owned-import-state-change",
}
FORBIDDEN_EFFECTS = {
    "shell",
    "command-execution",
    "file-write",
    "external-callback",
    "generic-gadget-chain",
    "crash",
    "denial-of-service",
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def string_list(value: Any, field: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise WebContractError(f"{field} requires at least {minimum} entries")
    result = [text(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise WebContractError(f"{field} contains duplicates")
    return result


def pointer_parts(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise WebContractError("mutation JSON pointers must be empty or begin with /")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def parent_at(value: Any, pointer: str) -> tuple[Any, str]:
    parts = pointer_parts(pointer)
    if not parts:
        raise WebContractError("a mutation cannot replace the document root")
    current = value
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise WebContractError(f"mutation pointer does not exist: {pointer}")
    return current, parts[-1]


def depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 0


def apply_mutation(baseline: Any, mutation: dict[str, Any]) -> Any:
    result = copy.deepcopy(baseline)
    operation = mutation["operation"]
    pointer = mutation["pointer"]
    parent, key = parent_at(result, pointer)
    exists = (isinstance(parent, dict) and key in parent) or (
        isinstance(parent, list) and key.isdigit() and int(key) < len(parent)
    )
    if operation == "add-field":
        if not isinstance(parent, dict) or key in parent:
            raise WebContractError("add-field requires a new object property")
        parent[key] = mutation["value"]
    elif operation == "remove-field":
        if not exists:
            raise WebContractError("remove-field requires an existing value")
        if isinstance(parent, dict):
            del parent[key]
        else:
            parent.pop(int(key))
    elif operation in {"set-field", "replace-type"}:
        if not exists:
            raise WebContractError(f"{operation} requires an existing value")
        if operation == "replace-type":
            previous = parent[key] if isinstance(parent, dict) else parent[int(key)]
            if type(previous) is type(mutation["value"]):
                raise WebContractError("replace-type must change the JSON value type")
        if isinstance(parent, dict):
            parent[key] = mutation["value"]
        else:
            parent[int(key)] = mutation["value"]
    elif operation == "reorder-object":
        target = parent.get(key) if isinstance(parent, dict) else parent[int(key)]
        if not isinstance(target, dict):
            raise WebContractError("reorder-object requires an object target")
        reordered = {item: target[item] for item in reversed(list(target))}
        if isinstance(parent, dict):
            parent[key] = reordered
        else:
            parent[int(key)] = reordered
    else:
        raise WebContractError("unsupported structure mutation")
    return result


def validate_experiment(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("deserialization experiment schemaVersion must be 1")
    if raw.get("kind") != "krineon-web-deserialization-experiment":
        raise WebContractError("input is not a Krineon deserialization experiment")
    for field in ("id", "title", "prerequisiteVersion"):
        text(raw.get(field), field)
    ingress = raw.get("ingress")
    if not isinstance(ingress, dict) or ingress.get("kind") not in INGRESS_KINDS:
        raise WebContractError("deserialization experiment requires a supported real ingress")
    if ingress.get("confidence") not in CONFIDENCE:
        raise WebContractError("deserialization ingress must be observed or source-supported")
    for field in ("workflowRef", "consumer", "evidence"):
        if field == "evidence":
            string_list(ingress.get(field), f"ingress.{field}")
        else:
            text(ingress.get(field), f"ingress.{field}")
    baseline = raw.get("baseline")
    if not isinstance(baseline, dict) or baseline.get("owned") is not True:
        raise WebContractError("deserialization baseline must come from an owned account")
    for field in ("actorRef", "representationRef", "sha256", "objectType"):
        text(baseline.get(field), f"baseline.{field}")
    boundary = raw.get("boundary")
    if not isinstance(boundary, dict) or boundary.get("integrityBoundary") not in INTEGRITY:
        raise WebContractError("deserialization boundary requires an integrity classification")
    for field in ("expectedRepresentation", "objectType", "identityBinding", "consumer"):
        text(boundary.get(field), f"boundary.{field}")
    acquisition = raw.get("attackerAcquisition")
    if not isinstance(acquisition, list):
        raise WebContractError("deserialization experiment requires acquisition evidence")
    for item in acquisition:
        if not isinstance(item, dict):
            raise WebContractError("attacker acquisition entries must be objects")
        for field in ("item", "source", "evidence"):
            text(item.get(field), f"attackerAcquisition.{field}")
        if item.get("requiresPrivateVictimArtifact") is not False:
            raise WebContractError("deserialization experiment cannot depend on a private victim artifact")
    budget = raw.get("mutationBudget")
    if not isinstance(budget, dict):
        raise WebContractError("deserialization experiment requires a mutation budget")
    limits = {"maxCases": 32, "maxSerializedBytes": 262144, "maxDepth": 16}
    for field, ceiling in limits.items():
        value = budget.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling:
            raise WebContractError(f"mutationBudget.{field} must be between 1 and {ceiling}")
    mutations = raw.get("mutations")
    if not isinstance(mutations, list) or not mutations or len(mutations) > budget["maxCases"]:
        raise WebContractError("deserialization mutations exceed the bounded case budget")
    ids = set()
    for mutation in mutations:
        if not isinstance(mutation, dict) or mutation.get("operation") not in MUTATIONS:
            raise WebContractError("deserialization mutation is unsupported")
        mutation_id = text(mutation.get("id"), "mutation.id")
        if mutation_id in ids:
            raise WebContractError("deserialization mutation ids must be unique")
        ids.add(mutation_id)
        pointer_parts(text(mutation.get("pointer"), f"mutation {mutation_id}.pointer"))
        if mutation["operation"] in {"set-field", "replace-type", "add-field"} and "value" not in mutation:
            raise WebContractError(f"mutation {mutation_id} requires a value")
    signature = raw.get("signaturePolicy")
    if not isinstance(signature, dict) or signature.get("mode") not in SIGNATURE_MODES:
        raise WebContractError("deserialization experiment requires a signature policy")
    if signature["mode"] == "recompute-owned-test-authority":
        if signature.get("ownedAuthority") is not True:
            raise WebContractError("signature recomputation requires owned test authority")
        string_list(signature.get("evidence"), "signaturePolicy.evidence")
    if boundary["integrityBoundary"] != "none":
        text(signature.get("invalidSignatureControlId"), "signaturePolicy.invalidSignatureControlId")
    effect = raw.get("effectPolicy")
    if not isinstance(effect, dict):
        raise WebContractError("deserialization experiment requires an effect policy")
    allowed = set(string_list(effect.get("allowedCanaryEffects"), "effectPolicy.allowedCanaryEffects"))
    if not allowed.issubset(ALLOWED_CANARY_EFFECTS):
        raise WebContractError("deserialization effect policy permits an unsupported effect")
    forbidden = set(effect.get("forbiddenEffects", []))
    if forbidden != FORBIDDEN_EFFECTS:
        raise WebContractError("deserialization experiment must explicitly forbid dangerous default effects")
    if effect.get("ownedResourceOnly") is not True or effect.get("persistent") is not False:
        raise WebContractError("deserialization canary effects must be owned and nonpersistent")
    controls = raw.get("controls")
    if not isinstance(controls, dict):
        raise WebContractError("deserialization experiment requires controls")
    for field in ("legitimateBaselineCaseId", "benignTypeControlId", "independentReplayRef"):
        text(controls.get(field), f"controls.{field}")
    if boundary["integrityBoundary"] != "none":
        text(controls.get("invalidSignatureControlId"), "controls.invalidSignatureControlId")
        if controls["invalidSignatureControlId"] != signature["invalidSignatureControlId"]:
            raise WebContractError("signature policy and control reference different invalid-signature cases")
    string_list(raw.get("configurationPreconditions"), "configurationPreconditions")
    return dict(raw)


def generate_variants(spec_raw: dict[str, Any], baseline: Any) -> dict[str, Any]:
    spec = validate_experiment(spec_raw)
    encoded = json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(encoded).hexdigest() != spec["baseline"]["sha256"]:
        raise WebContractError("baseline JSON does not match the retained canonical SHA-256")
    cases = []
    for mutation in spec["mutations"]:
        candidate = apply_mutation(baseline, mutation)
        if depth(candidate) > spec["mutationBudget"]["maxDepth"]:
            raise WebContractError("generated mutation exceeds the depth budget")
        payload = json.dumps(
            candidate,
            sort_keys=mutation["operation"] != "reorder-object",
            separators=(",", ":"),
        ).encode()
        if len(payload) > spec["mutationBudget"]["maxSerializedBytes"]:
            raise WebContractError("generated mutation exceeds the serialized-byte budget")
        cases.append(
            {
                "id": mutation["id"],
                "operation": mutation["operation"],
                "payload": json.loads(payload),
                "serializedUtf8": payload.decode("utf-8"),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-deserialization-cases",
        "experimentId": spec["id"],
        "prerequisiteVersion": spec["prerequisiteVersion"],
        "cases": cases,
        "targetExecutionRequired": True,
        "evaluatedInsideKrineon": False,
    }


def validate_case_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebContractError("deserialization observation must be an object")
    for field in ("caseId", "runnerEvidence"):
        if field == "runnerEvidence":
            string_list(value.get(field), field)
        else:
            text(value.get(field), field)
    for field in (
        "parsingAccepted",
        "objectConstructed",
        "unsafeTypeOrAuthoritySelected",
        "ownedCanaryEffectObserved",
        "ownedResource",
        "independentControlPassed",
        "acquisitionComplete",
        "signatureAccepted",
        "crashObserved",
        "externalEffectObserved",
    ):
        if not isinstance(value.get(field), bool):
            raise WebContractError(f"deserialization observation {field} must be Boolean")
    if value["ownedCanaryEffectObserved"]:
        if value.get("canaryEffectKind") not in ALLOWED_CANARY_EFFECTS:
            raise WebContractError("deserialization observation uses an unsupported canary effect")
    return dict(value)


def evaluate(spec_raw: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    spec = validate_experiment(spec_raw)
    if document.get("schemaVersion") != 1 or document.get("kind") != "krineon-web-deserialization-observations":
        raise WebContractError("input is not a deserialization observation document")
    if document.get("prerequisiteVersion") != spec["prerequisiteVersion"]:
        return {"outcome": "inconclusive", "reason": "deployment-drift"}
    replay = document.get("independentReplay")
    if not isinstance(replay, dict):
        return {"outcome": "inconclusive", "reason": "independent-replay-missing"}
    if (
        replay.get("status") != "confirmed"
        or replay.get("freshRunner") is not True
        or replay.get("samePrerequisiteVersion") is not True
        or replay.get("evidenceRef") != spec["controls"]["independentReplayRef"]
    ):
        return {"outcome": "inconclusive", "reason": "independent-replay-invalid"}
    observations = [validate_case_observation(value) for value in document.get("observations", [])]
    by_id = {value["caseId"]: value for value in observations}
    if len(by_id) != len(observations):
        raise WebContractError("deserialization observation case ids must be unique")
    controls = spec["controls"]
    expected_ids = {
        controls["legitimateBaselineCaseId"],
        controls["benignTypeControlId"],
        *(value["id"] for value in spec["mutations"]),
    }
    if spec["boundary"]["integrityBoundary"] != "none":
        expected_ids.add(controls["invalidSignatureControlId"])
    unknown = sorted(set(by_id).difference(expected_ids))
    missing = sorted(expected_ids.difference(by_id))
    if unknown:
        raise WebContractError("deserialization observations contain unknown cases")
    if missing:
        return {"outcome": "inconclusive", "reason": "missing-cases", "missingCaseIds": missing}
    baseline = by_id.get(controls["legitimateBaselineCaseId"])
    benign = by_id.get(controls["benignTypeControlId"])
    if baseline is None or benign is None:
        return {"outcome": "inconclusive", "reason": "missing-controls"}
    if not baseline["parsingAccepted"] or not baseline["objectConstructed"]:
        return {"outcome": "inconclusive", "reason": "legitimate-baseline-failed"}
    if benign["unsafeTypeOrAuthoritySelected"] or benign["ownedCanaryEffectObserved"]:
        return {"outcome": "inconclusive", "reason": "benign-control-failed"}
    if spec["boundary"]["integrityBoundary"] != "none":
        invalid = by_id.get(controls["invalidSignatureControlId"])
        if invalid is None:
            return {"outcome": "inconclusive", "reason": "missing-invalid-signature-control"}
        if invalid["signatureAccepted"] or invalid["objectConstructed"]:
            return {"outcome": "inconclusive", "reason": "signature-control-failed"}
    stages = {
        "parsing": False,
        "objectConstruction": False,
        "unsafeTypeOrAuthoritySelection": False,
        "securityConsequence": False,
    }
    confirmed = []
    for observation in observations:
        if observation["crashObserved"] or observation["externalEffectObserved"]:
            return {"outcome": "inconclusive", "reason": "prohibited-effect-stop"}
        stages["parsing"] |= observation["parsingAccepted"]
        stages["objectConstruction"] |= observation["objectConstructed"]
        stages["unsafeTypeOrAuthoritySelection"] |= observation[
            "unsafeTypeOrAuthoritySelected"
        ]
        consequence = (
            observation["parsingAccepted"]
            and observation["objectConstructed"]
            and observation["unsafeTypeOrAuthoritySelected"]
            and observation["ownedCanaryEffectObserved"]
            and observation["ownedResource"]
            and observation["independentControlPassed"]
            and observation["acquisitionComplete"]
        )
        stages["securityConsequence"] |= consequence
        if consequence:
            confirmed.append(observation["caseId"])
    return {
        "outcome": "confirmed-deserialization-invariant-break" if confirmed else "invariant-preserved",
        "confirmedCaseIds": confirmed,
        "evidenceLevels": stages,
        "remoteExecutionClaimed": False,
        "note": "Execution impact requires separate authorization and a bounded production-equivalent terminal.",
        "independentReplay": "confirmed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("experiment", type=Path)
    generate = sub.add_parser("generate")
    generate.add_argument("experiment", type=Path)
    generate.add_argument("baseline", type=Path)
    generate.add_argument("--output", required=True, type=Path)
    run = sub.add_parser("evaluate")
    run.add_argument("experiment", type=Path)
    run.add_argument("observations", type=Path)
    run.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        spec = validate_experiment(load_object(args.experiment))
        if args.command == "validate":
            print(json.dumps({"valid": True, "id": spec["id"]}, indent=2))
            return 0
        if args.command == "generate":
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            result = generate_variants(spec, baseline)
        else:
            result = evaluate(spec, load_object(args.observations))
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not str(result.get("outcome", "")).startswith("inconclusive") else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
