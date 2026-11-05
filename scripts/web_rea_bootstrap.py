#!/usr/bin/env python3
"""Prepare and, when available, run REA on retained web client artifacts.

The bootstrap performs no target traffic. It operates only on JavaScript and
other client artifacts that an approved Chromium journey already retained
inside the campaign. REA observations remain untrusted hypotheses until a
separate source or runtime experiment confirms them.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .rea_adapter import ReaAdapterError, run_adapter
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from rea_adapter import ReaAdapterError, run_adapter
    from web_contract import WebContractError, atomic_json


def _inside(root: Path, value: Path, field: str) -> Path:
    resolved = value.expanduser().resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise WebContractError(f"{field} must remain inside the campaign") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise WebContractError(f"{field} must not traverse symbolic links")
    return resolved


def prepare(campaign: Path, browser_output: Path) -> dict[str, Any]:
    """Create a campaign-bound REA request for one browser artifact capture."""
    root = campaign.expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise WebContractError(f"not a Krineon campaign: {root}")
    output = _inside(root, browser_output, "browser output")
    manifest = _inside(root, output / "client-artifact-manifest.json", "artifact manifest")
    artifacts = _inside(root, output / "client-artifacts", "client artifacts")
    if not manifest.is_file():
        raise WebContractError("browser output has no client-artifact manifest")
    if not artifacts.is_dir():
        raise WebContractError("browser output has no retained client-artifacts directory")
    try:
        manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebContractError("client-artifact manifest is invalid JSON") from exc
    retained = manifest_value.get("artifacts") if isinstance(manifest_value, dict) else None
    if not isinstance(retained, list) or not retained:
        raise WebContractError("REA requires at least one browser-retained client artifact")

    specification = {
        "schemaVersion": 1,
        "operation": "javascript-application",
        "target": artifacts.relative_to(root).as_posix(),
        "provider": None,
        "buildManifest": None,
        "timeoutSeconds": 900,
        "purpose": (
            "Reverse engineer browser-loaded production client artifacts before "
            "deeper web workflow and WebSocket experiments"
        ),
        "expectedOutputs": [
            "module, import, and dynamic-loading relationships",
            "route, API, WebSocket constructor, and message-handler relationships",
            "client capability and permission-check boundaries",
            "source-to-generated-artifact mappings",
            "explicit coverage, limitations, and residual unknowns",
        ],
    }
    spec_path = output / "rea-web-analysis.json"
    atomic_json(spec_path, specification, mode=0o600)
    status = {
        "schemaVersion": 1,
        "kind": "krineon-web-rea-bootstrap",
        "state": "ready" if shutil.which("rea") else "tool-unavailable",
        "requiredWhenAvailable": True,
        "targetTraffic": False,
        "browserOutput": output.relative_to(root).as_posix(),
        "artifactManifest": manifest.relative_to(root).as_posix(),
        "artifactCount": len(retained),
        "specification": spec_path.relative_to(root).as_posix(),
        "policy": {
            "targetContentIsUntrusted": True,
            "findingPromotionAllowed": False,
            "requiresIndependentSourceOrRuntimeComparison": True,
            "patchDiffingAllowed": False,
        },
    }
    status_path = output / "rea-web-bootstrap.json"
    atomic_json(status_path, status, mode=0o600)
    return {"status": status, "statusPath": status_path, "specPath": spec_path}


def run_when_available(campaign: Path, browser_output: Path) -> dict[str, Any]:
    prepared = prepare(campaign, browser_output)
    status = dict(prepared["status"])
    status_path: Path = prepared["statusPath"]
    if status["state"] == "tool-unavailable":
        status["nextAction"] = (
            "Install or expose REA separately, then rerun this retained specification; "
            "do not replace the missing analysis with guessed relationships."
        )
        atomic_json(status_path, status, mode=0o600)
        return status
    try:
        result = run_adapter(
            campaign.expanduser().resolve(),
            prepared["specPath"],
            browser_output.expanduser().resolve() / "rea-web-run.json",
        )
        status.update(
            {
                "state": "completed",
                "runId": result["runId"],
                "runRecord": (
                    browser_output.expanduser().resolve() / "rea-web-run.json"
                ).relative_to(campaign.expanduser().resolve()).as_posix(),
                "evidencePath": result["evidencePath"],
                "hypothesisCount": len(result["hypotheses"]),
            }
        )
    except (OSError, ReaAdapterError, subprocess.TimeoutExpired) as exc:
        status.update(
            {
                "state": "analysis-failed",
                "error": str(exc)[:1000],
                "nextAction": "repair the REA integration and rerun the frozen artifact specification",
            }
        )
    atomic_json(status_path, status, mode=0o600)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("browser_output", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = (
            prepare(args.campaign, args.browser_output)["status"]
            if args.prepare_only
            else run_when_available(args.campaign, args.browser_output)
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["state"] in {"ready", "completed", "tool-unavailable"} else 2
    except (OSError, ValueError, WebContractError) as exc:
        print(f"web REA bootstrap error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
