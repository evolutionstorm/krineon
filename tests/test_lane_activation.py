import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from lane_activation import build_activation


def write(path: Path, value: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


def campaign(tmp_path: Path, profile: str, *, confirmed: bool = False, mode: str = "local-lab") -> Path:
    return write(
        tmp_path / "campaign.json",
        {
            "schemaVersion": 1,
            "profile": profile,
            "target": "owned-target",
            "repository": "https://example.invalid/owned.git",
            "commit": "a" * 40,
            "localCheckout": "",
            "mode": mode,
            "authorization": {"confirmed": confirmed},
        },
    )


def tools(tmp_path: Path, *, chrome: bool = False, rea: bool = False) -> Path:
    return write(
        tmp_path / "tools.json",
        {
            "commands": {
                "chromium": {"available": chrome},
                "google-chrome": {"available": False},
                "rea": {"available": rea},
                "FuzzilliCli": {"available": False},
                "afl-fuzz": {"available": False},
            },
            "pythonModules": {"playwright": {"available": False}},
        },
    )


def facts(tmp_path: Path, entries: list[tuple[str, str]]) -> Path:
    return write(
        tmp_path / "facts.json",
        {
            "schemaVersion": 1,
            "kind": "krineon-capability-facts",
            "facts": [
                {
                    "id": fact_id,
                    "state": state,
                    "provenance": {
                        "trust": "source-supported",
                        "basis": f"owned fixture proves {fact_id}",
                    },
                }
                for fact_id, state in entries
            ],
        },
    )


def by_lane(result: dict, lane_id: str) -> dict:
    return next(lane for lane in result["lanes"] if lane["laneId"] == lane_id)


def test_missing_runtime_keeps_lane_visible_as_planning_only(tmp_path: Path) -> None:
    result = build_activation(
        campaign_path=campaign(tmp_path, "chrome-v8"),
        profile_path=ROOT / "profiles" / "chrome-v8.json",
        tool_inventory_path=tools(tmp_path),
        facts_path=facts(tmp_path, [("target.source-tree", "present")]),
    )
    browser = by_lane(result, "chromium-integration")
    assert browser["state"] == "planning-only"
    assert browser["runtimeAuthority"] is False
    assert "any:tool.chromium|tool.google-chrome" in browser["missingCapabilities"]
    assert "references/chrome-v8.md" in browser["contextFiles"]


def test_measured_browser_and_source_capabilities_activate_lanes(tmp_path: Path) -> None:
    result = build_activation(
        campaign_path=campaign(tmp_path, "chrome-v8"),
        profile_path=ROOT / "profiles" / "chrome-v8.json",
        tool_inventory_path=tools(tmp_path, chrome=True),
        facts_path=facts(tmp_path, [("target.source-tree", "present")]),
    )
    assert by_lane(result, "v8-static-analysis-lead-generation")["state"] == "eligible"
    browser = by_lane(result, "chromium-integration")
    assert browser["state"] == "eligible"
    assert "tool.chromium" in browser["selectedCapabilities"]
    assert "references/fingerprint-disagreement.md" in browser["contextFiles"]


def test_rea_and_fingerprint_contexts_are_conditionally_selected(tmp_path: Path) -> None:
    fingerprint = write(
        tmp_path / "fingerprint.json",
        {
            "kind": "krineon-fingerprint-disagreement-analysis",
            "disagreementCount": 1,
        },
    )
    result = build_activation(
        campaign_path=campaign(tmp_path, "critical-rce", mode="source"),
        profile_path=ROOT / "profiles" / "critical-rce.json",
        tool_inventory_path=tools(tmp_path, rea=True),
        facts_path=facts(tmp_path, [("target.shipped-artifact", "present")]),
        fingerprint_path=fingerprint,
    )
    stock = by_lane(result, "stock-deployment-reachability")
    assert "references/rea.md" in stock["contextFiles"]
    assert "references/fingerprint-disagreement.md" in stock["contextFiles"]
    assert "tool.rea" in stock["selectedCapabilities"]


def test_conflicting_capability_evidence_resolves_to_unknown(tmp_path: Path) -> None:
    checkout = tmp_path / "source"
    checkout.mkdir()
    campaign_path = campaign(tmp_path, "critical-rce")
    raw = json.loads(campaign_path.read_text())
    raw["localCheckout"] = str(checkout)
    campaign_path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    result = build_activation(
        campaign_path=campaign_path,
        profile_path=ROOT / "profiles" / "critical-rce.json",
        facts_path=facts(tmp_path, [("target.source-tree", "absent")]),
    )
    assert result["facts"]["target.source-tree"]["state"] == "unknown"
    assert result["facts"]["target.source-tree"]["conflict"] is True
    assert by_lane(result, "static-analysis-lead-generation")["state"] == "planning-only"


def test_inferred_fact_cannot_grant_runtime_capability(tmp_path: Path) -> None:
    facts_path = write(
        tmp_path / "facts.json",
        {
            "schemaVersion": 1,
            "kind": "krineon-capability-facts",
            "facts": [
                {
                    "id": "target.source-tree",
                    "state": "present",
                    "provenance": {
                        "trust": "inferred",
                        "basis": "an unverified worker inference",
                    },
                }
            ],
        },
    )
    result = build_activation(
        campaign_path=campaign(tmp_path, "critical-rce"),
        profile_path=ROOT / "profiles" / "critical-rce.json",
        facts_path=facts_path,
    )
    fact = result["facts"]["target.source-tree"]
    assert fact["state"] == "present"
    assert fact["executionEligible"] is False
    assert by_lane(result, "static-analysis-lead-generation")["state"] == "planning-only"


def test_web_browser_requires_tool_and_separate_authorization(tmp_path: Path) -> None:
    web_campaign = write(
        tmp_path / "web-campaign.json",
        {
            "authorization": {"allowBrowserNavigation": True},
            "requestInputs": {},
        },
    )
    result = build_activation(
        campaign_path=campaign(tmp_path, "web-app", confirmed=True),
        profile_path=ROOT / "profiles" / "web-app.json",
        tool_inventory_path=tools(tmp_path, chrome=True),
        web_campaign_path=web_campaign,
    )
    browser = by_lane(result, "web-api-browser-discovery")
    assert browser["state"] == "eligible"
    assert set(browser["selectedCapabilities"]) >= {
        "authorization.confirmed",
        "authorization.browser-navigation",
        "tool.chromium",
    }


def test_owned_full_testing_exports_runtime_authority_facts(tmp_path: Path) -> None:
    web_campaign = write(
        tmp_path / "web-campaign.json",
        {
            "authorization": {
                "allowBrowserNavigation": True,
                "allowStateChangingOperations": True,
                "allowUploads": True,
                "allowWebSockets": True,
                "allowCacheMutation": True,
                "allowDeserializationExperiments": True,
                "allowBoundedConcurrency": True,
                "ownedFullTesting": {"enabled": True},
            },
            "requestInputs": {},
        },
    )
    result = build_activation(
        campaign_path=campaign(tmp_path, "web-app", confirmed=True),
        profile_path=ROOT / "profiles" / "web-app.json",
        tool_inventory_path=tools(tmp_path),
        web_campaign_path=web_campaign,
    )
    for fact_id in (
        "authorization.owned-full-testing",
        "authorization.state-changing",
        "authorization.uploads",
        "authorization.websockets",
        "authorization.cache-mutation",
        "authorization.deserialization-experiments",
        "authorization.bounded-concurrency",
    ):
        assert result["facts"][fact_id]["state"] == "present"
        assert result["facts"][fact_id]["executionEligible"] is True
