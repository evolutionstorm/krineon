import json
import sys
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from state_machine_inventory import (
    InventoryError,
    discover_state_machines,
    extract_inventory,
    merge_inventory,
    validate_inventory,
)
from research_harness import validate_state_machine_task_result


def proof(observation: str) -> dict[str, str]:
    return {
        "kind": "source",
        "reference": "src/stream.ts:10",
        "observation": observation,
    }


def machine(*, invalid: bool = False) -> dict:
    reachable_invalid = []
    if invalid:
        reachable_invalid.append(
            {
                "id": "invalid-ready-after-close",
                "kind": "invalid-transition",
                "state": "",
                "transition": "retry-connect",
                "violatedInvariants": ["closed-is-terminal"],
                "actualPath": ["close", "retry timer fires", "connect"],
                "attackerControl": "attacker can force the recorded transport failure",
                "requiredHistory": ["client entered closed state"],
                "retrySchedule": ["retry timer remains armed after close"],
                "concurrencySchedule": ["close races retry callback"],
                "status": "runtime-reproduced",
                "evidence": [
                    {
                        "kind": "trace",
                        "reference": "evidence/retry-close.json",
                        "observation": "retry callback connected after close",
                    }
                ],
                "controls": [
                    {
                        "kind": "replay",
                        "reference": "evidence/retry-close-control.json",
                        "observation": "cancelling the timer preserves closed state",
                    }
                ],
            }
        )
    return {
        "id": "stream-lifecycle",
        "name": "Stream connection lifecycle",
        "kind": "implicit",
        "scope": "production stream client",
        "initialStates": ["idle"],
        "states": [
            {
                "id": "idle",
                "description": "no active connection",
                "entryConditions": ["client constructed"],
                "exitConditions": ["connect requested"],
                "confidence": "source-supported",
                "evidence": [proof("constructor initializes idle state")],
            },
            {
                "id": "ready",
                "description": "stream is active",
                "entryConditions": ["connect succeeds"],
                "exitConditions": ["close or failure"],
                "confidence": "source-supported",
                "evidence": [proof("successful connection marks the client ready")],
            },
            {
                "id": "closed",
                "description": "client has been closed",
                "entryConditions": ["close completes"],
                "exitConditions": [],
                "confidence": "source-supported",
                "evidence": [proof("close marks the client closed")],
            },
        ],
        "invariants": [
            {
                "id": "closed-is-terminal",
                "statement": "a closed client cannot reconnect",
                "appliesInStates": ["closed"],
                "basis": "target close contract",
                "evidence": [proof("close contract rejects later work")],
            }
        ],
        "transitions": [
            {
                "id": "retry-connect",
                "from": ["idle", "ready", "closed"],
                "to": "ready",
                "trigger": "transport retry callback",
                "actor": "runtime retry scheduler",
                "guards": [
                    {
                        "condition": "client is not closed",
                        "requiredOutcome": "true",
                        "attackerInfluence": "transport input can schedule retry but cannot set closed",
                    }
                ],
                "effects": ["replace active stream"],
                "retry": {
                    "possible": True,
                    "policy": "bounded exponential backoff",
                    "identityOrIdempotencyBinding": "same client generation",
                    "stateAfterFailure": "idle",
                },
                "concurrency": {
                    "possible": True,
                    "interleavings": ["close before retry callback"],
                    "serializationOrLocking": "event-loop task ordering",
                    "sharedState": ["closed flag", "retry timer"],
                },
                "confidence": "source-supported",
                "evidence": [proof("retry callback checks the closed flag")],
            }
        ],
        "reachableInvalid": reachable_invalid,
        "unknowns": ["whether close cancels an already queued callback"],
        "evidence": [proof("stream lifecycle source entrypoint")],
    }


def inventory(*, invalid: bool = False) -> dict:
    return {
        "schemaVersion": 1,
        "target": "mixed-language-target",
        "revision": "a" * 40,
        "createdAt": "2026-11-06T00:00:00+00:00",
        "updatedAt": "2026-11-06T00:00:00+00:00",
        "status": "populated",
        "machines": [machine(invalid=invalid)],
        "coverage": {},
    }


def test_inventory_counts_retry_concurrency_and_reachable_invalid() -> None:
    result = validate_inventory(inventory(invalid=True), allow_empty=False)
    assert result["coverage"] == {
        "explicitMachinesReviewed": 0,
        "implicitMachinesReviewed": 1,
        "retryTransitionsReviewed": 1,
        "concurrentTransitionsReviewed": 1,
        "reachableInvalidStates": 1,
        "unresolvedMachines": ["stream-lifecycle"],
        "sourceFilesScanned": 0,
        "sourceLanguagesObserved": [],
        "unpromotedSourceCandidates": 0,
    }


def test_runtime_invalid_transition_requires_an_enforcing_control() -> None:
    value = inventory(invalid=True)
    value["machines"][0]["reachableInvalid"][0]["controls"] = []
    with pytest.raises(InventoryError, match="controls must be an array and must not be empty"):
        validate_inventory(value, allow_empty=False)


def test_locked_merge_rejects_conflicting_machine_interpretation(tmp_path: Path) -> None:
    retained = tmp_path / "state-machine-inventory.json"
    proposal = tmp_path / "proposal.json"
    retained.write_text(json.dumps(inventory()), encoding="utf-8")
    changed = inventory()
    changed["machines"][0]["scope"] = "a different runtime"
    proposal.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(InventoryError, match="conflicting machine"):
        merge_inventory(retained, proposal)


def test_state_machine_lane_completion_is_bound_to_populated_inventory(
    tmp_path: Path,
) -> None:
    retained = tmp_path / "state-machine-inventory.json"
    retained.write_text(json.dumps(inventory()), encoding="utf-8")
    result = {
        "stateMachineAnalysis": {
            "inventory": "state-machine-inventory.json",
            "machinesReviewed": ["stream-lifecycle"],
            "transitionsReviewed": ["retry-connect"],
            "retryPathsReviewed": ["retry-connect"],
            "concurrencyPathsReviewed": ["close before retry callback"],
            "reachableInvalidConclusions": [],
        }
    }
    validate_state_machine_task_result(tmp_path, result)

    result["stateMachineAnalysis"]["machinesReviewed"] = ["invented-machine"]
    with pytest.raises(SystemExit, match="unknown machines"):
        validate_state_machine_task_result(tmp_path, result)


def test_universal_discovery_extracts_multiple_languages_without_promoting_claims(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.ts").write_text(
        """
enum ConnectionState { Idle, Connecting, Ready, Closed }
let connectionState = ConnectionState.Idle;
function connect() { connectionState = ConnectionState.Connecting; }
function onReady() { connectionState = ConnectionState.Ready; }
function close() { connectionState = ConnectionState.Closed; }
let timer = null;
function retryWithBackoff() { if (connectionState === ConnectionState.Closed) return; connect(); }
""",
        encoding="utf-8",
    )
    (tmp_path / "worker.rs").write_text(
        """
enum JobPhase { Queued, Running, Cancelled, Complete }
fn worker_thread() { mutex.lock(); atomic.compare_exchange(0, 1); }
fn cancel_job() { rollback(); }
""",
        encoding="utf-8",
    )
    (tmp_path / "parser.py").write_text(
        """
parse_status = "header"
if parse_status == "body":
    assert cursor <= frame_length
parse_status = "complete"
""",
        encoding="utf-8",
    )

    result = discover_state_machines(tmp_path, revision="b" * 40)

    assert result["mode"] == "candidate-only"
    assert result["languages"] == {"rust": 1, "typescript": 1, "python": 1}
    assert result["filesScanned"] == 3
    assert any(row["candidateKind"] == "explicit" for row in result["candidates"])
    assert any(row["candidateKind"] == "retry" for row in result["candidates"])
    assert any(row["candidateKind"] == "concurrency" for row in result["candidates"])
    assert all(row["promotionState"] == "source-signal-only" for row in result["candidates"])
    assert all("reachableInvalid" not in row for row in result["candidates"])


def test_extract_updates_one_inventory_but_keeps_candidates_unpromoted(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "service.go").write_text(
        """
package service
type SessionStatus int
func reconnectWithBackoff() { if sessionStatus == Closed { return }; connect() }
func shutdown() { sessionStatus = Closed }
""",
        encoding="utf-8",
    )
    retained = tmp_path / "state-machine-inventory.json"
    value = inventory()
    value["machines"] = []
    retained.write_text(json.dumps(value), encoding="utf-8")

    result = extract_inventory(retained, source)

    assert result["discovery"]["filesScanned"] == 1
    assert result["discovery"]["candidates"]
    assert result["machines"] == []
    assert result["status"] == "uninitialized"
    assert result["coverage"]["unpromotedSourceCandidates"] > 0
