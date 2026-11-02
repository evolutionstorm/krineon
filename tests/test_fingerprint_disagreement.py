import hashlib
import json
import sys
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fingerprint_disagreement import FingerprintError, analyze


def evidence(root: Path, name: str, body: str) -> dict[str, str]:
    path = root / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "selector": "$.response.headers",
    }


def observation(
    identifier: str,
    family: str,
    value: str,
    evidence_ref: dict[str, str],
    *,
    route: str = "/",
    epoch: str = "epoch-1",
) -> dict:
    return {
        "id": identifier,
        "observer": {"id": identifier, "family": family, "kind": "tool"},
        "scope": {
            "origin": "app",
            "hostname": "app.test",
            "port": "443",
            "route": route,
            "method": "GET",
            "actor": "anonymous",
            "session": "fresh-a",
            "backend": "unknown",
            "deploymentEpoch": epoch,
        },
        "observedAt": "2026-11-02T12:00:00Z",
        "evidence": [evidence_ref],
        "signals": [
            {
                "id": "framework-version",
                "component": "framework",
                "property": "reported-version",
                "value": value,
            }
        ],
    }


def write_set(root: Path, name: str, observations: list[dict], *, epoch: str = "epoch-1") -> Path:
    path = root / name
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "kind": "krineon-fingerprint-observation-set",
                "target": {"id": "owned-target", "deploymentEpoch": epoch},
                "observations": observations,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_independent_same_scope_conflict_is_planning_only(tmp_path: Path) -> None:
    first = evidence(tmp_path, "browser.json", "browser says 1.0")
    second = evidence(tmp_path, "artifact.json", "artifact says 2.0")
    source = write_set(
        tmp_path,
        "fingerprints.json",
        [
            observation("browser", "browser-runtime", "1.0", first),
            observation("artifact", "artifact-parser", "2.0", second),
        ],
    )
    result = analyze(tmp_path, [source])
    assert result["disagreementCount"] == 1
    disagreement = result["disagreements"][0]
    assert disagreement["classification"] == "observer-conflict"
    assert disagreement["promotionEligible"] is False
    assert disagreement["independentObserverFamilies"] == [
        "artifact-parser",
        "browser-runtime",
    ]
    assert result["plannerCandidates"][0]["state"] == "planning-only"
    assert result["policy"]["vulnerabilityVerdicts"] is False


def test_one_dimension_route_split_generates_targeted_experiment(tmp_path: Path) -> None:
    first = evidence(tmp_path, "public.json", "public build A")
    second = evidence(tmp_path, "admin.json", "admin build B")
    source = write_set(
        tmp_path,
        "routes.json",
        [
            observation("public", "browser-runtime", "build-a", first, route="/"),
            observation("admin", "browser-runtime", "build-b", second, route="/admin"),
        ],
    )
    result = analyze(tmp_path, [source])
    assert result["disagreementCount"] == 1
    split = result["disagreements"][0]
    assert split["classification"] == "scope-split"
    assert split["differingDimension"] == "route"
    assert split["nextExperiment"]["changedVariables"] == ["route"]
    assert "security-relevant invariant" in split["nextExperiment"]["objective"]


def test_different_deployment_epochs_do_not_create_a_split(tmp_path: Path) -> None:
    first = evidence(tmp_path, "old.json", "old")
    second = evidence(tmp_path, "new.json", "new")
    old = write_set(
        tmp_path,
        "old-set.json",
        [observation("old", "browser-runtime", "1.0", first, epoch="epoch-old")],
        epoch="epoch-old",
    )
    new = write_set(
        tmp_path,
        "new-set.json",
        [observation("new", "browser-runtime", "2.0", second, epoch="epoch-new")],
        epoch="epoch-new",
    )
    result = analyze(tmp_path, [old, new])
    assert result["disagreementCount"] == 0


def test_evidence_hash_and_secret_values_fail_closed(tmp_path: Path) -> None:
    ref = evidence(tmp_path, "response.json", "bounded response")
    bad_hash = dict(ref)
    bad_hash["sha256"] = "0" * 64
    source = write_set(
        tmp_path,
        "bad-hash.json",
        [observation("browser", "browser-runtime", "1.0", bad_hash)],
    )
    with pytest.raises(FingerprintError, match="digest mismatch"):
        analyze(tmp_path, [source])

    secret_source = write_set(
        tmp_path,
        "secret.json",
        [observation("secret", "browser-runtime", "Authorization: Bearer owned-secret-value", ref)],
    )
    with pytest.raises(FingerprintError, match="credential or secret"):
        analyze(tmp_path, [secret_source])


def test_symlinked_evidence_fails_closed(tmp_path: Path) -> None:
    real = evidence(tmp_path, "real.json", "bounded response")
    linked_directory = tmp_path / "linked-evidence"
    linked_directory.symlink_to(tmp_path / "evidence", target_is_directory=True)
    linked = dict(real)
    linked["path"] = "linked-evidence/real.json"
    source = write_set(
        tmp_path,
        "symlink.json",
        [observation("browser", "browser-runtime", "1.0", linked)],
    )
    with pytest.raises(FingerprintError, match="must not traverse a symlink"):
        analyze(tmp_path, [source])
