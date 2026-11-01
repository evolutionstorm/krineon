#!/usr/bin/env python3
"""Gate web findings on demonstrated authority, effect, replay, and safe packaging."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
    from .web_evidence import load_object, sha, text, text_list, validate_evidence
except ImportError:
    from web_contract import WebContractError, atomic_json
    from web_evidence import load_object, sha, text, text_list, validate_evidence


IMPACT_CLASSES = {
    "confidentiality",
    "integrity",
    "unauthorized-transaction-entitlement",
    "cross-tenant-authority",
    "browser-execution",
    "server-execution",
    "program-defined-critical-effect",
}
SECRET_PATTERNS = (
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{12,}"),
    re.compile(rb"(?i)(?:cookie|set-cookie)\s*:\s*[^\r\n]{12,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{12,}"),
)
REQUIRED_SANITIZED_SURFACES = {
    "request-headers",
    "request-bodies",
    "response-headers",
    "response-bodies",
    "urls",
    "html-dom",
    "screenshots",
    "downloads",
    "browser-storage",
    "har-cdp-logs",
    "nuclei-output",
    "exception-traces",
    "generated-commands",
}


def safe_path(root: Path, value: Any, field: str) -> Path:
    relative = Path(text(value, field))
    if relative.is_absolute() or ".." in relative.parts:
        raise WebContractError(f"{field} escapes the package root")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise WebContractError(f"{field} escapes the package root") from error
    if not path.is_file():
        raise WebContractError(f"{field} is missing")
    return path


def validate_artifacts(
    raw: Any,
    *,
    root: Path,
    classification: str,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise WebContractError(f"{classification} artifact list must be non-empty")
    result = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise WebContractError("artifact entries must be objects")
        prefix = f"artifacts.{classification}[{index}]"
        path = safe_path(root, item.get("path"), f"{prefix}.path")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != sha(item.get("sha256"), f"{prefix}.sha256"):
            raise WebContractError(f"{prefix} hash changed")
        if item.get("classification") != classification:
            raise WebContractError(f"{prefix} has the wrong artifact tier")
        if classification == "reviewer":
            if item.get("sanitized") is not True or item.get("syntheticDataOnly") is not True:
                raise WebContractError("reviewer artifacts must be sanitized and synthetic")
            if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
                raise WebContractError("reviewer package leak check found credential-like data")
        elif item.get("restricted") is not True or item.get("encrypted") is not True:
            raise WebContractError("private artifacts must remain encrypted and restricted")
        result.append({**item, "path": path.relative_to(root).as_posix()})
    return result


def validate_finding(
    raw: dict[str, Any], evidence_raw: dict[str, Any], *, package_root: Path
) -> dict[str, Any]:
    evidence = validate_evidence(evidence_raw)
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-web-finding":
        raise WebContractError("input is not a Krineon web finding")
    finding_id = text(raw.get("id"), "id")
    experiment_id = text(raw.get("experimentId"), "experimentId")
    if finding_id != evidence["findingId"] or experiment_id != evidence["experimentId"]:
        raise WebContractError("evidence is bound to another finding or experiment")
    text(raw.get("title"), "title")
    text(raw.get("profile"), "profile")
    if raw.get("autonomousSubmissionAllowed") is not False:
        raise WebContractError("Krineon cannot autonomously submit a report")

    approval = raw.get("approvalBinding")
    if not isinstance(approval, dict):
        raise WebContractError("approvalBinding must be an object")
    if approval.get("findingId") != finding_id or approval.get("experimentId") != experiment_id:
        raise WebContractError("approval is bound to another finding or experiment")
    if approval.get("observationEpoch") != evidence["observationEpoch"]["id"]:
        raise WebContractError("approval observation epoch differs from the evidence")
    sha(approval.get("recipeSha256"), "approvalBinding.recipeSha256")
    sha(approval.get("authorizationContractSha256"), "approvalBinding.authorizationContractSha256")
    approval_identities = approval.get("identityBindings")
    if not isinstance(approval_identities, list) or not approval_identities:
        raise WebContractError("approvalBinding.identityBindings must be non-empty")
    normalized_approval_identities: dict[str, str] = {}
    for index, identity in enumerate(approval_identities):
        if not isinstance(identity, dict):
            raise WebContractError("approval identity bindings must be objects")
        identity_id = text(identity.get("id"), f"approvalBinding.identityBindings[{index}].id")
        binding_version = text(
            identity.get("bindingVersion"),
            f"approvalBinding.identityBindings[{index}].bindingVersion",
        )
        if identity_id in normalized_approval_identities:
            raise WebContractError("approval identity binding is duplicated")
        normalized_approval_identities[identity_id] = binding_version
    approval_resources = set(
        text_list(approval.get("resourceIds"), "approvalBinding.resourceIds")
    )
    approval_oracle = sha(
        approval.get("oracleEvidenceSha256"),
        "approvalBinding.oracleEvidenceSha256",
    )

    start = raw.get("attackerStartingPoint")
    ingress = raw.get("ingress")
    rule = raw.get("violatedRule")
    if not isinstance(start, dict) or not isinstance(ingress, dict) or not isinstance(rule, dict):
        raise WebContractError("attackerStartingPoint, ingress, and violatedRule are required")
    for field in ("identity", "tenant", "privilege"):
        text(start.get(field), f"attackerStartingPoint.{field}")
    text_list(start.get("prerequisites", []), "attackerStartingPoint.prerequisites", empty=True)
    if ingress.get("observed") is not True or ingress.get("inScope") is not True:
        raise WebContractError("the actual ingress must be observed and in scope")
    text(ingress.get("url"), "ingress.url")
    text(ingress.get("method"), "ingress.method")
    sha(ingress.get("evidenceSha256"), "ingress.evidenceSha256")
    text(rule.get("claim"), "violatedRule.claim")
    text(rule.get("basis"), "violatedRule.basis")

    evidence_identities = {
        str(item["id"]): {
            "tenant": str(item["tenant"]),
            "bindingVersion": str(item["bindingVersion"]),
        }
        for item in evidence["identities"]
    }
    if start["identity"] not in evidence_identities:
        raise WebContractError("attacker identity is absent from the bound evidence")
    if evidence_identities[start["identity"]]["tenant"] != start["tenant"]:
        raise WebContractError("attacker tenant differs from the verified identity binding")
    expected_identity_bindings = {
        identity_id: value["bindingVersion"]
        for identity_id, value in evidence_identities.items()
    }
    if normalized_approval_identities != expected_identity_bindings:
        raise WebContractError("approval identity bindings differ from the evidence")

    evidence_fixtures = {str(item["id"]) for item in evidence["fixtures"]}
    resources = text_list(raw.get("ownedResourceIds"), "ownedResourceIds")
    if not set(resources).issubset(evidence_fixtures):
        raise WebContractError("finding references a resource absent from owned evidence")
    if approval_resources != set(resources):
        raise WebContractError("approval resource bindings differ from the finding")
    controls = raw.get("semanticControls")
    if not isinstance(controls, dict):
        raise WebContractError("semanticControls must be an object")
    for name in ("positive", "negative", "counterfactual"):
        values = controls.get(name)
        if not isinstance(values, list) or not values:
            raise WebContractError(f"semanticControls.{name} must be non-empty")
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise WebContractError("semantic controls must be objects")
            text(value.get("claim"), f"semanticControls.{name}[{index}].claim")
            sha(value.get("evidenceSha256"), f"semanticControls.{name}[{index}].evidenceSha256")

    effect = raw.get("effect")
    if not isinstance(effect, dict) or effect.get("impactClass") not in IMPACT_CLASSES:
        raise WebContractError("effect impactClass is unsupported")
    for field in ("claim", "boundaryCrossed", "terminalClass"):
        text(effect.get(field), f"effect.{field}")
    if effect.get("independentlyVerified") is not True:
        raise WebContractError("the claimed effect requires independent verification")
    effect_oracle = sha(effect.get("oracleEvidenceSha256"), "effect.oracleEvidenceSha256")
    if approval_oracle != effect_oracle:
        raise WebContractError("approval oracle binding differs from the observed effect")
    claim = raw.get("supportedClaim")
    if not isinstance(claim, dict) or claim.get("complete") is not True:
        raise WebContractError("supportedClaim must be complete")
    text(claim.get("statement"), "supportedClaim.statement")
    text_list(claim.get("conditions"), "supportedClaim.conditions")
    text_list(claim.get("unknowns", []), "supportedClaim.unknowns", empty=True)
    root_status = claim.get("internalRootCauseStatus")
    if root_status not in {"confirmed", "hypothesis", "unknown"}:
        raise WebContractError("internalRootCauseStatus is unsupported")
    source_locations = claim.get("sourceLocations", [])
    if not isinstance(source_locations, list):
        raise WebContractError("sourceLocations must be a list")
    if evidence["provenance"]["mode"] == "blackbox" and (
        root_status == "confirmed" or source_locations
    ):
        raise WebContractError("black-box findings cannot claim an exact internal root cause")

    severity = raw.get("severityAssessment")
    if not isinstance(severity, dict):
        raise WebContractError("severityAssessment must be an object")
    for field in ("startingPrivileges", "prerequisites", "boundaryCrossed", "consequence", "programRating"):
        text(severity.get(field), f"severityAssessment.{field}")
    replay = raw.get("independentReplay")
    if not isinstance(replay, dict):
        raise WebContractError("independentReplay must be an object")
    if (
        replay.get("freshSecretBindings") is not True
        or replay.get("freshFixtureGenerations") is not True
        or replay.get("isolatedBrowserSession") is not True
        or replay.get("staleCookieJarReused") is not False
        or replay.get("workflowPreconditionsPreserved") is not True
        or replay.get("cachePreconditionsPreserved") is not True
        or replay.get("originatorInterpretationAcceptedWithoutChallenge") is not False
    ):
        raise WebContractError(
            "independent replay requires fresh bindings, preserved prerequisites, and an independent observer"
        )
    if replay.get("prerequisiteVersion") != evidence["observationEpoch"]["prerequisiteVersion"]:
        raise WebContractError("independent replay used another prerequisite version")
    if replay.get("observationEpoch") != evidence["observationEpoch"]["id"]:
        raise WebContractError("independent replay occurred on another deployment epoch")
    if replay.get("observerChallengeOutcome") != "survived":
        raise WebContractError("a refuted or missing observer challenge blocks promotion")
    sha(replay.get("evidenceSha256"), "independentReplay.evidenceSha256")
    cleanup = raw.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("status") not in {"verified", "not-required"}:
        raise WebContractError("cleanup must be verified or not required")
    text(cleanup.get("evidence"), "cleanup.evidence")

    artifacts = raw.get("artifacts")
    if not isinstance(artifacts, dict):
        raise WebContractError("artifacts must be an object")
    private = validate_artifacts(artifacts.get("private"), root=package_root, classification="private")
    reviewer = validate_artifacts(artifacts.get("reviewer"), root=package_root, classification="reviewer")
    sanitization = artifacts.get("reviewerSanitization")
    if not isinstance(sanitization, dict):
        raise WebContractError("artifacts.reviewerSanitization must be an object")
    covered = set(
        text_list(
            sanitization.get("coveredSurfaces"),
            "artifacts.reviewerSanitization.coveredSurfaces",
        )
    )
    missing_surfaces = sorted(REQUIRED_SANITIZED_SURFACES - covered)
    if missing_surfaces:
        raise WebContractError(
            "reviewer sanitization coverage is incomplete: " + ", ".join(missing_surfaces)
        )
    if sanitization.get("unexpectedThirdPartyData") is not False:
        raise WebContractError("unexpected third-party data blocks the reviewer package")
    if sanitization.get("leakScanPassed") is not True:
        raise WebContractError("reviewer package leak scan did not pass")
    sha(
        sanitization.get("leakScanEvidenceSha256"),
        "artifacts.reviewerSanitization.leakScanEvidenceSha256",
    )
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-finding-gate-verdict",
        "findingId": finding_id,
        "experimentId": experiment_id,
        "passed": True,
        "impactClass": effect["impactClass"],
        "terminalClass": effect["terminalClass"],
        "observationEpoch": evidence["observationEpoch"]["id"],
        "blackboxRootCauseMayRemainUnknown": evidence["provenance"]["mode"] == "blackbox",
        "sourceLinkedPathBypassesEffectGate": False,
        "packageLeakCheckPassed": True,
        "privateArtifactCount": len(private),
        "reviewerArtifactCount": len(reviewer),
        "autonomousSubmissionAllowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("finding", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_finding(
            load_object(args.finding),
            load_object(args.evidence),
            package_root=args.package_root.expanduser().resolve(),
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"accepted": True, "findingId": result["findingId"]}, indent=2))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
