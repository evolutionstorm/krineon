#!/usr/bin/env python3
"""Select executable Krineon lanes and minimal context from measured capability facts.

Missing capabilities never prove that a research family is irrelevant. The
engine marks such lanes planning-only so they remain visible without receiving
runtime authority or dominating executable work.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = PROJECT_ROOT / "profiles" / "lane-capabilities.json"
FACT_STATES = {"present", "absent", "unknown"}
TRUST_LEVELS = {"tool-measurement", "source-supported", "owner-specified", "inferred"}


class ActivationError(ValueError):
    """Capability evidence or activation policy is malformed."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path, field: str) -> dict[str, Any]:
    if not path.is_file():
        raise ActivationError(f"{field} does not exist: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ActivationError(f"{field} must contain a JSON object: {path}")
    return value


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ActivationError(f"{field} must be a non-empty string")
    return value.strip()


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def fact_entry(
    fact_id: str,
    state: str,
    *,
    source: str,
    selector: str,
    trust: str,
    source_sha256: str = "",
) -> dict[str, str]:
    if state not in FACT_STATES:
        raise ActivationError(f"invalid state for {fact_id}: {state}")
    if trust not in TRUST_LEVELS:
        raise ActivationError(f"invalid trust for {fact_id}: {trust}")
    return {
        "id": fact_id,
        "state": state,
        "source": source,
        "sourceSha256": source_sha256,
        "selector": selector,
        "trust": trust,
    }


def campaign_facts(campaign_path: Path, campaign: dict[str, Any]) -> list[dict[str, str]]:
    source_hash = sha256(campaign_path)
    result = [
        fact_entry(
            f"profile.{require_text(campaign.get('profile'), 'campaign.profile')}",
            "present",
            source=campaign_path.as_posix(),
            source_sha256=source_hash,
            selector="$.profile",
            trust="owner-specified",
        ),
        fact_entry(
            f"mode.{str(campaign.get('mode') or 'unknown')}",
            "present",
            source=campaign_path.as_posix(),
            source_sha256=source_hash,
            selector="$.mode",
            trust="owner-specified",
        ),
        fact_entry(
            "authorization.confirmed",
            "present" if (campaign.get("authorization") or {}).get("confirmed") is True else "absent",
            source=campaign_path.as_posix(),
            source_sha256=source_hash,
            selector="$.authorization.confirmed",
            trust="owner-specified",
        ),
    ]
    checkout = str(campaign.get("localCheckout") or "").strip()
    if checkout:
        checkout_path = Path(checkout).expanduser()
        result.append(
            fact_entry(
                "target.source-tree",
                "present" if checkout_path.is_dir() else "unknown",
                source=campaign_path.as_posix(),
                source_sha256=source_hash,
                selector="$.localCheckout",
                trust="owner-specified",
            )
        )
    elif campaign.get("mode") == "source" and campaign.get("repository") and campaign.get("commit"):
        result.append(
            fact_entry(
                "target.source-tree",
                "present",
                source=campaign_path.as_posix(),
                source_sha256=source_hash,
                selector="$.mode + $.repository + $.commit",
                trust="owner-specified",
            )
        )
    if campaign.get("profile") == "web-app":
        result.append(
            fact_entry(
                "target.web-application",
                "present",
                source=campaign_path.as_posix(),
                source_sha256=source_hash,
                selector="$.profile",
                trust="owner-specified",
            )
        )
    return result


def web_campaign_facts(path: Path) -> list[dict[str, str]]:
    raw = load_json(path, "web campaign")
    source_hash = sha256(path)
    authorization = raw.get("authorization") if isinstance(raw.get("authorization"), dict) else {}
    request_inputs = raw.get("requestInputs") if isinstance(raw.get("requestInputs"), dict) else {}
    result = [
        fact_entry(
            "authorization.browser-navigation",
            "present" if authorization.get("allowBrowserNavigation") is True else "absent",
            source=path.as_posix(),
            source_sha256=source_hash,
            selector="$.authorization.allowBrowserNavigation",
            trust="owner-specified",
        )
    ]
    if any(request_inputs.get(field) for field in ("requestBundles", "harFiles", "burpExports")):
        result.append(
            fact_entry(
                "evidence.http-captures",
                "present",
                source=path.as_posix(),
                source_sha256=source_hash,
                selector="$.requestInputs",
                trust="owner-specified",
            )
        )
    if request_inputs.get("sourceRoots"):
        result.append(
            fact_entry(
                "target.source-tree",
                "present",
                source=path.as_posix(),
                source_sha256=source_hash,
                selector="$.requestInputs.sourceRoots",
                trust="owner-specified",
            )
        )
    return result


def tool_facts(path: Path) -> list[dict[str, str]]:
    raw = load_json(path, "tool inventory")
    source_hash = sha256(path)
    result: list[dict[str, str]] = []
    commands = raw.get("commands")
    if not isinstance(commands, dict):
        raise ActivationError("tool inventory commands must be an object")
    for name, details in sorted(commands.items()):
        if not isinstance(details, dict):
            raise ActivationError(f"tool inventory entry must be an object: {name}")
        result.append(
            fact_entry(
                f"tool.{name}",
                "present" if details.get("available") is True else "absent",
                source=path.as_posix(),
                source_sha256=source_hash,
                selector=f"$.commands.{name}.available",
                trust="tool-measurement",
            )
        )
    modules = raw.get("pythonModules", {})
    if not isinstance(modules, dict):
        raise ActivationError("tool inventory pythonModules must be an object")
    for name, details in sorted(modules.items()):
        if not isinstance(details, dict):
            raise ActivationError(f"python module inventory entry must be an object: {name}")
        result.append(
            fact_entry(
                f"python.{name}",
                "present" if details.get("available") is True else "absent",
                source=path.as_posix(),
                source_sha256=source_hash,
                selector=f"$.pythonModules.{name}.available",
                trust="tool-measurement",
            )
        )
    return result


def explicit_facts(path: Path) -> list[dict[str, str]]:
    raw = load_json(path, "capability facts")
    if raw.get("kind") != "krineon-capability-facts" or raw.get("schemaVersion") != 1:
        raise ActivationError("capability facts must use schemaVersion 1 and kind krineon-capability-facts")
    source_hash = sha256(path)
    facts = raw.get("facts")
    if not isinstance(facts, list):
        raise ActivationError("capability facts must contain a facts list")
    result: list[dict[str, str]] = []
    for index, item in enumerate(facts):
        if not isinstance(item, dict):
            raise ActivationError(f"facts[{index}] must be an object")
        fact_id = require_text(item.get("id"), f"facts[{index}].id")
        state = require_text(item.get("state"), f"facts[{index}].state")
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            raise ActivationError(f"facts[{index}].provenance must be an object")
        trust = require_text(provenance.get("trust"), f"facts[{index}].provenance.trust")
        basis = require_text(provenance.get("basis"), f"facts[{index}].provenance.basis")
        result.append(
            fact_entry(
                fact_id,
                state,
                source=path.as_posix(),
                source_sha256=source_hash,
                selector=f"$.facts[{index}] ({basis})",
                trust=trust,
            )
        )
    return result


def fingerprint_facts(path: Path) -> list[dict[str, str]]:
    raw = load_json(path, "fingerprint analysis")
    if raw.get("kind") != "krineon-fingerprint-disagreement-analysis":
        raise ActivationError("fingerprint analysis has an unexpected kind")
    count = raw.get("disagreementCount")
    if not isinstance(count, int) or count < 0:
        raise ActivationError("fingerprint disagreementCount must be a non-negative integer")
    return [
        fact_entry(
            "evidence.fingerprint-disagreement",
            "present" if count else "absent",
            source=path.as_posix(),
            source_sha256=sha256(path),
            selector="$.disagreementCount",
            trust="tool-measurement",
        )
    ]


def resolve_facts(entries: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for entry in entries:
        grouped[entry["id"]].append(entry)
    resolved: dict[str, dict[str, Any]] = {}
    for fact_id, members in sorted(grouped.items()):
        states = {member["state"] for member in members if member["state"] != "unknown"}
        if states == {"present"}:
            state, conflict = "present", False
        elif states == {"absent"}:
            state, conflict = "absent", False
        elif states:
            state, conflict = "unknown", True
        else:
            state, conflict = "unknown", False
        resolved[fact_id] = {
            "id": fact_id,
            "state": state,
            "conflict": conflict,
            "executionEligible": state == "present"
            and any(
                member["state"] == "present" and member["trust"] != "inferred"
                for member in members
            ),
            "evidence": members,
        }
    return resolved


def is_present(facts: dict[str, dict[str, Any]], fact_id: str) -> bool:
    return (facts.get(fact_id) or {}).get("executionEligible") is True


def rule_matches(rule: dict[str, Any], profile: str, lane_id: str) -> bool:
    profiles = rule.get("profiles", [])
    lanes = rule.get("laneIds", [])
    if profiles and profile not in profiles:
        return False
    return not lanes or lane_id in lanes


def requirements(rule: dict[str, Any], facts: dict[str, dict[str, Any]]) -> tuple[bool, list[str]]:
    all_values = [str(value) for value in rule.get("requiresAll", [])]
    any_values = [str(value) for value in rule.get("requiresAny", [])]
    missing = [value for value in all_values if not is_present(facts, value)]
    any_satisfied = not any_values or any(is_present(facts, value) for value in any_values)
    if not any_satisfied:
        missing.append("any:" + "|".join(any_values))
    return not missing, missing


def validate_contexts(catalog: dict[str, Any]) -> None:
    packs = catalog.get("contextPacks")
    if not isinstance(packs, dict):
        raise ActivationError("lane catalog contextPacks must be an object")
    for pack_id, paths in packs.items():
        if not isinstance(paths, list) or not paths:
            raise ActivationError(f"context pack must be a non-empty list: {pack_id}")
        for raw in paths:
            path = (PROJECT_ROOT / str(raw)).resolve()
            if PROJECT_ROOT.resolve() not in path.parents and path != PROJECT_ROOT.resolve():
                raise ActivationError(f"context path escapes project root: {raw}")
            if not path.is_file():
                raise ActivationError(f"context path does not exist: {raw}")


def context_paths(catalog: dict[str, Any], pack_ids: set[str]) -> list[str]:
    packs = catalog["contextPacks"]
    unknown = pack_ids.difference(packs)
    if unknown:
        raise ActivationError("unknown context packs: " + ", ".join(sorted(unknown)))
    return sorted({str(path) for pack_id in pack_ids for path in packs[pack_id]})


def build_activation(
    *,
    campaign_path: Path,
    profile_path: Path,
    catalog_path: Path = DEFAULT_CATALOG,
    tool_inventory_path: Path | None = None,
    facts_path: Path | None = None,
    web_campaign_path: Path | None = None,
    fingerprint_path: Path | None = None,
) -> dict[str, Any]:
    campaign = load_json(campaign_path, "campaign")
    profile = load_json(profile_path, "profile")
    catalog = load_json(catalog_path, "lane catalog")
    validate_contexts(catalog)
    profile_name = require_text(campaign.get("profile"), "campaign.profile")
    if profile.get("name") != profile_name:
        raise ActivationError("campaign and profile names do not match")
    entries = campaign_facts(campaign_path, campaign)
    inputs = [{"kind": "campaign", "path": campaign_path.as_posix(), "sha256": sha256(campaign_path)}]
    for path, kind, loader in (
        (tool_inventory_path, "tool-inventory", tool_facts),
        (facts_path, "capability-facts", explicit_facts),
        (web_campaign_path, "web-campaign", web_campaign_facts),
        (fingerprint_path, "fingerprint-analysis", fingerprint_facts),
    ):
        if path is not None and path.is_file():
            entries.extend(loader(path))
            inputs.append({"kind": kind, "path": path.as_posix(), "sha256": sha256(path)})
    facts = resolve_facts(entries)
    base_packs = set(catalog.get("profileContextPacks", {}).get(profile_name, []))
    rules = catalog.get("laneRules")
    augmentations = catalog.get("augmentations", [])
    if not isinstance(rules, list) or not isinstance(augmentations, list):
        raise ActivationError("laneRules and augmentations must be lists")
    lane_results: list[dict[str, Any]] = []
    lanes = profile.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        raise ActivationError("profile lanes must be a non-empty list")
    for lane in lanes:
        if not isinstance(lane, dict):
            raise ActivationError("profile lane must be an object")
        lane_id = require_text(lane.get("id"), "lane.id")
        packs = set(base_packs)
        missing: list[str] = []
        applied_rules: list[str] = []
        selected_capabilities: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict) or not rule_matches(rule, profile_name, lane_id):
                continue
            rule_id = require_text(rule.get("id"), "laneRule.id")
            applied_rules.append(rule_id)
            packs.update(str(value) for value in rule.get("contextPacks", []))
            satisfied, rule_missing = requirements(rule, facts)
            if not satisfied:
                missing.extend(rule_missing)
            else:
                selected_capabilities.update(str(value) for value in rule.get("requiresAll", []))
                selected_capabilities.update(
                    value for value in map(str, rule.get("requiresAny", [])) if is_present(facts, value)
                )
        for augmentation in augmentations:
            if not isinstance(augmentation, dict) or not rule_matches(augmentation, profile_name, lane_id):
                continue
            satisfied, _ = requirements(augmentation, facts)
            if satisfied:
                packs.update(str(value) for value in augmentation.get("contextPacks", []))
                selected_capabilities.update(str(value) for value in augmentation.get("requiresAll", []))
                selected_capabilities.update(
                    value
                    for value in map(str, augmentation.get("requiresAny", []))
                    if is_present(facts, value)
                )
        missing = sorted(set(missing))
        state = "eligible" if not missing else "planning-only"
        lane_results.append(
            {
                "laneId": lane_id,
                "state": state,
                "priorityAdjustment": 0 if state == "eligible" else -25,
                "appliedRules": applied_rules,
                "selectedCapabilities": sorted(selected_capabilities),
                "missingCapabilities": missing,
                "contextPacks": sorted(packs),
                "contextFiles": context_paths(catalog, packs),
                "runtimeAuthority": state == "eligible",
                "instructions": (
                    "execute only separately authorized lane experiments"
                    if state == "eligible"
                    else "analyze retained evidence and design acquisition experiments; do not claim or exercise missing runtime capability"
                ),
            }
        )
    counts = Counter(lane["state"] for lane in lane_results)
    return {
        "schemaVersion": 1,
        "kind": "krineon-lane-activation",
        "generatedAt": utc_now(),
        "profile": profile_name,
        "inputs": inputs,
        "facts": facts,
        "lanes": lane_results,
        "summary": dict(sorted(counts.items())),
        "policy": {
            "missingCapabilityState": "planning-only",
            "unknownDoesNotBecomeAbsent": True,
            "planningOnlyLanesRemainVisible": True,
            "capabilitiesDoNotExpandAuthorization": True,
        },
    }


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--tool-inventory", type=Path)
    parser.add_argument("--facts", type=Path)
    parser.add_argument("--web-campaign", type=Path)
    parser.add_argument("--fingerprint-analysis", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_activation(
            campaign_path=args.campaign,
            profile_path=args.profile,
            catalog_path=args.catalog,
            tool_inventory_path=args.tool_inventory,
            facts_path=args.facts,
            web_campaign_path=args.web_campaign,
            fingerprint_path=args.fingerprint_analysis,
        )
    except (ActivationError, json.JSONDecodeError, OSError) as error:
        parser.error(str(error))
    atomic_json(args.output, result)
    print(
        f"lane activation: {result['summary'].get('eligible', 0)} eligible, "
        f"{result['summary'].get('planning-only', 0)} planning-only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
