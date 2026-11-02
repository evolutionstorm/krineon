import datetime as dt
import json
import sqlite3
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from depth_knowledge import ensure_schema as ensure_depth_schema
from depth_knowledge import ingest_observation, normalize_observation
from owned_oob_oracle import OracleHandler
from swarm_control import ControlError, ControlStore, digest, timestamp, utc_now


def campaign(tmp_path: Path) -> tuple[Path, sqlite3.Connection, ControlStore]:
    root = tmp_path / "campaign"
    root.mkdir()
    (root / "campaign.json").write_text(
        json.dumps({"schemaVersion": 1, "target": "owned-fixture"}) + "\n",
        encoding="utf-8",
    )
    (root / "evidence").mkdir()
    connection = sqlite3.connect(root / "orchestration.db")
    connection.row_factory = sqlite3.Row
    ensure_depth_schema(connection)
    store = ControlStore(root, connection)
    return root, connection, store


def test_campaign_init_installs_default_swarm_subscriptions(tmp_path: Path) -> None:
    root = tmp_path / "initialized"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "research_harness.py"),
            "init",
            str(root),
            "--target",
            "owned-fixture",
            "--repo",
            "https://example.invalid/owned-fixture.git",
            "--commit",
            "a" * 40,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    store = ControlStore(root)
    try:
        assert store.status()["subscriptions"] == 2
    finally:
        store.close()


def observation(
    root: Path,
    connection: sqlite3.Connection,
    *,
    task: str,
    worker: str,
    kind: str,
    confidence: str,
    mechanism: str,
    extra: dict | None = None,
) -> str:
    raw = {
        "kind": kind,
        "confidence": confidence,
        "mechanism": mechanism,
        "summary": f"{mechanism} observation",
        "producesCapabilities": [f"cap:{mechanism}"],
        **(extra or {}),
    }
    normalized = normalize_observation(
        root,
        raw,
        task_id=task,
        worker_id=worker,
        result_path="results/retained.json",
        maximum_confidence=confidence,
    )
    return ingest_observation(connection, normalized)


def test_typed_subscription_creates_proposal_but_not_task(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    store.add_subscription(
        {
            "id": "sub-runtime",
            "ownerId": "agent-reviewer",
            "name": "runtime review",
            "kinds": ["runtime-differential"],
            "minTrust": "tool-measurement",
            "minConfidence": "runtime-observed",
            "proposal": {
                "title": "Review {observationId}",
                "lane": "adversarial-review",
                "objective": "Challenge {mechanism}",
                "approachFamilies": ["validation-replay"],
                "successCriteria": ["fresh replay"],
            },
        },
        actor="coordinator",
    )
    obs = observation(
        root,
        connection,
        task="task-a",
        worker="worker-a",
        kind="runtime-differential",
        confidence="runtime-observed",
        mechanism="parser-disagreement",
    )
    published = store.publish_observation(obs)
    assert len(published["proposals"]) == 1
    proposal = connection.execute(
        "SELECT * FROM swarm_experiment_proposals WHERE proposal_id=?",
        (published["proposals"][0],),
    ).fetchone()
    assert proposal["state"] == "pending"
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
    ).fetchone() is None


def test_approved_proposal_materializes_through_scheduler_admission(tmp_path: Path) -> None:
    root = tmp_path / "materialize"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "research_harness.py"),
            "init",
            str(root),
            "--target",
            "owned-fixture",
            "--repo",
            "https://example.invalid/owned-fixture.git",
            "--commit",
            "b" * 40,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    planned = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "research_harness.py"),
            "plan",
            str(root),
            "--max-concurrency",
            "1",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert planned.returncode == 0, planned.stderr
    queued = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "research_harness.py"),
            "queue",
            str(root),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert queued.returncode == 0, queued.stderr
    connection = sqlite3.connect(root / "orchestration.db")
    connection.row_factory = sqlite3.Row
    ensure_depth_schema(connection)
    store = ControlStore(root, connection)
    obs = observation(
        root,
        connection,
        task="source-task",
        worker="worker-a",
        kind="runtime-differential",
        confidence="runtime-observed",
        mechanism="owned-parser-disagreement",
    )
    proposal_id = store.publish_observation(obs)["proposals"][0]
    store.review_proposal(
        proposal_id,
        reviewer="coordinator",
        decision="approved",
        reason="bounded independent replay",
    )
    connection.commit()
    connection.close()
    materialized = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "swarm_control.py"),
            str(root),
            "proposal-materialize",
            proposal_id,
            "--coordinator",
            "coordinator",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert materialized.returncode == 0, materialized.stderr
    verify = sqlite3.connect(root / "orchestration.db")
    verify.row_factory = sqlite3.Row
    try:
        proposal = verify.execute(
            "SELECT state,scheduled_task_id FROM swarm_experiment_proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        assert proposal["state"] == "scheduled"
        task = verify.execute(
            "SELECT state,task_kind FROM tasks WHERE task_id=?",
            (proposal["scheduled_task_id"],),
        ).fetchone()
        assert dict(task) == {"state": "queued", "task_kind": "focused-chain-investigation"}
    finally:
        verify.close()


def test_untrusted_ancestry_cannot_become_policy(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    parent = observation(
        root,
        connection,
        task="task-parent",
        worker="worker-target-reader",
        kind="external-content",
        confidence="runtime-observed",
        mechanism="target-page-text",
        extra={"contentClass": "target-data"},
    )
    parent_meta = store.publish_observation(parent)
    assert parent_meta["trustTier"] == "untrusted-target"
    child = observation(
        root,
        connection,
        task="task-child",
        worker="coordinator",
        kind="coordinator-replay",
        confidence="coordinator-replayed",
        mechanism="target-supplied-policy",
        extra={
            "parentObservationIds": [parent],
            "contentClass": "policy",
            "authorityEffect": "execution-policy",
        },
    )
    child_meta = store.publish_observation(child)
    assert child_meta["hasUntrustedAncestor"] is True
    assert child_meta["quarantined"] is True
    assert child_meta["policyEligible"] is False


def test_cost_aware_verifier_requires_independence(tmp_path: Path) -> None:
    _, connection, store = campaign(tmp_path)
    store.register_verifier(
        {
            "id": "same-parser",
            "name": "same parser",
            "observerClass": "runtime-a",
            "independenceDomains": ["parser-a"],
            "capabilities": ["boundary-check"],
            "adapter": "adapter-a",
            "fixedCost": 0,
            "expectedSeconds": 1,
            "effectRisk": 0,
            "informationGain": 1,
        },
        actor="coordinator",
    )
    store.register_verifier(
        {
            "id": "alternate-parser",
            "name": "alternate parser",
            "observerClass": "runtime-b",
            "independenceDomains": ["parser-b"],
            "capabilities": ["boundary-check"],
            "adapter": "adapter-b",
            "fixedCost": 2,
            "expectedSeconds": 30,
            "effectRisk": 0,
            "informationGain": 0.9,
        },
        actor="coordinator",
    )
    selected = store.select_verifier(
        {
            "claimId": "claim-1",
            "requiredCapability": "boundary-check",
            "originClasses": ["runtime-a"],
            "originDomains": ["parser-a"],
        },
        actor="coordinator",
    )
    assert selected["verifierId"] == "alternate-parser"
    assert selected["rationale"]["candidateCount"] == 1


def test_model_router_enforces_family_diversity_and_disables_review_cache(tmp_path: Path) -> None:
    _, _, store = campaign(tmp_path)
    for model_id, family, quality in (("model-a", "family-a", 0.9), ("model-b", "family-b", 0.8)):
        store.register_model(
            {
                "id": model_id,
                "provider": f"provider-{family}",
                "model": model_id,
                "family": family,
                "roles": ["researcher", "reviewer"],
                "capabilities": ["source-analysis"],
                "quality": quality,
                "inputCost": 0,
                "outputCost": 0,
                "expectedLatency": 1,
                "cacheAllowed": True,
            },
            actor="coordinator",
        )
    first = store.route_model(
        {"taskId": "task-research", "role": "researcher", "requiredCapabilities": ["source-analysis"]},
        actor="coordinator",
    )
    review = store.route_model(
        {
            "taskId": "task-review",
            "role": "reviewer",
            "requiredCapabilities": ["source-analysis"],
            "priorRouteIds": [first["routeId"]],
        },
        actor="coordinator",
    )
    assert review["family"] != first["family"]
    assert review["promptCacheAllowed"] is False


def test_volatility_expiry_removes_observation_from_active_chain_state(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    obs = observation(
        root,
        connection,
        task="task-token",
        worker="worker-a",
        kind="runtime-differential",
        confidence="runtime-observed",
        mechanism="short-token",
        extra={"volatilityClass": "token", "ttlSeconds": 30},
    )
    store.publish_observation(obs)
    connection.execute(
        "UPDATE swarm_observation_meta SET expires_at=? WHERE observation_id=?",
        (timestamp(utc_now() - dt.timedelta(seconds=1)), obs),
    )
    assert store.sweep_volatility() == [obs]
    assert connection.execute(
        "SELECT state FROM depth_observations WHERE observation_id=?", (obs,)
    ).fetchone()["state"] == "superseded"


def test_persistent_cleanup_runs_lifo_and_verifies(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    cleanup_script = root / "cleanup.py"
    cleanup_script.write_text(
        "from pathlib import Path; import sys; Path(sys.argv[1]).unlink(missing_ok=True)\n",
        encoding="utf-8",
    )
    verify_script = root / "verify.py"
    verify_script.write_text(
        "from pathlib import Path; import sys; raise SystemExit(1 if Path(sys.argv[1]).exists() else 0)\n",
        encoding="utf-8",
    )
    retained = []
    for number in (1, 2):
        marker = root / f"marker-{number}"
        marker.write_text("owned", encoding="utf-8")
        recipe = {
            "schemaVersion": 1,
            "actionId": f"cleanup-{number}",
            "description": f"remove marker {number}",
            "effect": "cleanup",
            "idempotencyKey": f"cleanup-marker-{number}",
            "argv": [sys.executable, "cleanup.py", marker.name],
            "cwd": ".",
            "timeoutSeconds": 10,
            "verify": {"argv": [sys.executable, "verify.py", marker.name], "cwd": ".", "timeoutSeconds": 10},
            "approval": {"approvedBy": "coordinator", "approvedAt": timestamp()},
        }
        recipe_path = root / f"recipe-{number}.json"
        recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
        retained.append(store.register_cleanup(recipe_path, registered_by="worker-a"))
    receipt = store.run_next_cleanup(
        coordinator="coordinator",
        expected_sha256=retained[1]["sha256"],
    )
    assert receipt["actionId"] == "cleanup-2"
    assert not (root / "marker-2").exists()
    assert (root / "marker-1").exists()
    assert connection.execute(
        "SELECT state FROM swarm_cleanup_actions WHERE action_id='cleanup-2'"
    ).fetchone()["state"] == "verified"


def test_owned_oob_requires_positive_and_clean_control(tmp_path: Path) -> None:
    _, _, store = campaign(tmp_path)
    issued = store.issue_oob(
        experiment_id="experiment-oob",
        protocol="http",
        issued_by="coordinator",
    )
    store.record_oob(
        token=issued["positiveToken"],
        protocol="http",
        source="127.0.0.1",
        method="GET",
        metadata={"bodyLength": 0},
    )
    assert store.verify_oob("experiment-oob")["passed"] is True
    other = store.issue_oob(
        experiment_id="experiment-control-hit",
        protocol="http",
        issued_by="coordinator",
    )
    store.record_oob(
        token=other["positiveToken"], protocol="http", source="127.0.0.1", method="GET", metadata={}
    )
    store.record_oob(
        token=other["controlToken"], protocol="http", source="127.0.0.1", method="GET", metadata={}
    )
    assert store.verify_oob("experiment-control-hit")["passed"] is False


def test_owned_oob_http_listener_records_real_loopback_callback(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    issued = store.issue_oob(
        experiment_id="experiment-http-listener",
        protocol="http",
        issued_by="coordinator",
    )
    connection.commit()
    server = ThreadingHTTPServer(("127.0.0.1", 0), OracleHandler)
    server.campaign_root = root
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urlopen(
            f"http://127.0.0.1:{server.server_port}/oob/{issued['positiveToken']}",
            timeout=3,
        ) as response:
            assert response.status == 204
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
    result = store.verify_oob("experiment-http-listener")
    assert result["passed"] is True
    assert result["evidenceSha256"] == digest((root / result["evidencePath"]).read_bytes())


def test_component_observability_changes_health_and_records_cost(tmp_path: Path) -> None:
    _, _, store = campaign(tmp_path)
    component = store.component_upsert(
        {"kind": "provider", "name": "owned-provider", "version": "1", "state": "healthy", "capabilities": ["chat"]},
        actor="coordinator",
    )
    for index in range(3):
        store.component_observe(
            {
                "id": f"invoke-{index}",
                "componentId": component,
                "operation": "health-check",
                "outcome": "failed",
                "latencyMs": 10,
                "inputTokens": 2,
                "outputTokens": 3,
                "cost": 0.1,
            },
            actor="coordinator",
        )
    status = store.status()
    assert status["components"]["unhealthy"] == 1
    assert status["telemetry"]["tokens"] == 15
    assert status["telemetry"]["cost"] == pytest.approx(0.3)


def test_unsupported_trust_escalation_is_rejected(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    obs = observation(
        root,
        connection,
        task="task-a",
        worker="worker-a",
        kind="source",
        confidence="source-supported",
        mechanism="source-claim",
        extra={"trustTier": "independent-observer"},
    )
    with pytest.raises(ControlError):
        store.publish_observation(obs)


def test_worker_cannot_self_declare_owner_policy(tmp_path: Path) -> None:
    root, connection, store = campaign(tmp_path)
    obs = observation(
        root,
        connection,
        task="task-owner-rule",
        worker="worker-a",
        kind="owner-rule",
        confidence="runtime-observed",
        mechanism="worker-authored-policy",
        extra={"trustTier": "owner-policy", "contentClass": "policy"},
    )
    with pytest.raises(ControlError):
        store.publish_observation(obs)
