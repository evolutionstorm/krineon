#!/usr/bin/env python3
"""Evaluate workerd lifetime traces against explicit ownership invariants."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get("event"), str):
            raise RuntimeError(f"trace line {number} is not an event object")
        value = {**value, "traceLine": number}
        events.append(value)
    return events


def evaluate(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    assessments: dict[str, list[dict[str, Any]]] = {
        "confirmedDisagreements": [],
        "preserved": [],
        "inconclusive": [],
    }
    registered_fields: dict[tuple[str, str], int] = {}
    visited_fields: set[tuple[str, str]] = set()
    gc_completed = False
    moved: dict[str, tuple[str, Any, int]] = {}
    borrows: dict[str, dict[str, Any]] = {}
    owner_generation: dict[str, tuple[Any, int]] = {}
    known_objects: set[str] = set()
    dead: dict[str, int] = {}
    buffers: dict[str, tuple[Any, int]] = {}
    pointers: dict[str, tuple[str, Any, int]] = {}
    scheduled: dict[str, tuple[str, int]] = {}
    assessed_moves: set[str] = set()
    assessed_borrows: set[str] = set()
    assessed_pointers: set[str] = set()
    assessed_callbacks: set[str] = set()

    def add(
        outcome: str,
        family: str,
        event: dict[str, Any],
        reason: str,
        origin: int | None = None,
        missing: list[str] | None = None,
    ) -> None:
        bucket = {
            "confirmed": "confirmedDisagreements",
            "preserved": "preserved",
            "inconclusive": "inconclusive",
        }[outcome]
        assessments[bucket].append({
            "family": family,
            "traceLine": event["traceLine"],
            "originTraceLine": origin,
            "object": event.get("object") or event.get("handle") or event.get("pointer"),
            "reason": reason,
            "missingTelemetry": missing or [],
        })

    for event in events:
        kind = event["event"]
        obj = str(event.get("object") or "")
        if kind == "register-traced":
            field = str(event.get("field") or "")
            if obj and field:
                registered_fields[(obj, field)] = event["traceLine"]
        elif kind == "gc-begin":
            visited_fields.clear()
            gc_completed = False
        elif kind == "gc-visit":
            field = str(event.get("field") or "")
            if obj and field:
                visited_fields.add((obj, field))
        elif kind == "gc-end":
            gc_completed = True
        elif kind == "handle-use" and (obj, str(event.get("field") or "")) in registered_fields:
            key = (obj, str(event.get("field") or ""))
            if "alive" not in event or not gc_completed:
                missing = []
                if "alive" not in event:
                    missing.append("handle alive/collected state")
                if not gc_completed:
                    missing.append("gc-end before handle use")
                add("inconclusive", "missing-gc-visitation", event, "GC lifetime telemetry is incomplete", registered_fields[key], missing)
            elif event.get("alive") is False and key not in visited_fields:
                add("confirmed", "missing-gc-visitation", event, "unvisited traced handle used after explicit collection", registered_fields[key])
            elif event.get("alive") is True:
                add("preserved", "missing-gc-visitation", event, "traced handle remained alive through the observed GC cycle", registered_fields[key])
            else:
                add("inconclusive", "missing-gc-visitation", event, "handle was visited but reported collected; this trace does not isolate missing visitation", registered_fields[key], ["consistent collector identity telemetry"])
        elif kind == "handle-move":
            source = str(event.get("from") or "")
            destination = str(event.get("to") or "")
            if source and destination and event.get("generation") is not None:
                moved[source] = (destination, event.get("generation"), event["traceLine"])
            else:
                add("inconclusive", "traced-handle-move", event, "move identity or generation telemetry is incomplete", missing=["from", "to", "generation"])
        elif kind == "handle-use":
            handle = str(event.get("handle") or obj)
            if handle in moved:
                assessed_moves.add(handle)
                if event.get("generation") is None:
                    add("inconclusive", "traced-handle-move", event, "use generation telemetry is missing", moved[handle][2], ["generation"])
                elif event.get("generation") == moved[handle][1]:
                    add("confirmed", "traced-handle-move", event, "moved-from traced handle generation was used", moved[handle][2])
                else:
                    add("preserved", "traced-handle-move", event, "the later use names a different handle generation", moved[handle][2])
        elif kind == "owner-register" or kind == "owner-generation":
            if obj:
                owner_generation[obj] = (event.get("generation"), event["traceLine"])
        elif kind == "borrow":
            pointer = str(event.get("pointer") or "")
            if pointer:
                borrows[pointer] = {
                    "owner": obj,
                    "generation": event.get("generation"),
                    "line": event["traceLine"],
                    "reentered": False,
                    "reentryLine": None,
                }
        elif kind == "js-reentry":
            for value in borrows.values():
                value["reentered"] = True
                value["reentryLine"] = event["traceLine"]
        elif kind == "pointer-use":
            pointer = str(event.get("pointer") or "")
            borrow = borrows.get(pointer)
            if borrow:
                assessed_borrows.add(pointer)
                if not borrow["owner"] or borrow["generation"] is None:
                    add("inconclusive", "borrowed-pointer-js-reentry", event, "borrow identity or generation telemetry is incomplete", borrow["line"], ["owner", "borrow generation"])
                elif not borrow["reentered"]:
                    add("preserved", "borrowed-pointer-js-reentry", event, "pointer use occurred before any observed JavaScript reentry", borrow["line"])
                elif (
                    borrow["owner"] not in owner_generation
                    or owner_generation[borrow["owner"]][0] is None
                    or owner_generation[borrow["owner"]][1]
                    <= int(borrow["reentryLine"] or 0)
                ):
                    add("inconclusive", "borrowed-pointer-js-reentry", event, "owner generation after reentry was not observed", borrow["line"], ["owner-generation after js-reentry"])
                elif owner_generation[borrow["owner"]][0] != borrow["generation"]:
                    add("confirmed", "borrowed-pointer-js-reentry", event, "borrowed pointer was used after an explicit owner-generation change", borrow["line"])
                else:
                    add("preserved", "borrowed-pointer-js-reentry", event, "owner generation was explicitly unchanged across reentry", borrow["line"])
            buffer_pointer = pointers.get(pointer)
            if buffer_pointer:
                assessed_pointers.add(pointer)
                owner, acquired_generation, origin = buffer_pointer
                if not owner or acquired_generation is None:
                    add("inconclusive", "arraybuffer-detach-resize-ownership", event, "pointer acquisition identity or generation is incomplete", origin, ["buffer identity", "acquired generation"])
                elif (
                    owner not in buffers
                    or buffers[owner][0] is None
                    or buffers[owner][1] <= origin
                ):
                    add("inconclusive", "arraybuffer-detach-resize-ownership", event, "current ArrayBuffer generation was not observed", origin, ["buffer generation at use"])
                elif buffers[owner][0] != acquired_generation:
                    add("confirmed", "arraybuffer-detach-resize-ownership", event, "pointer was used after an explicit ArrayBuffer generation change", origin)
                else:
                    add("preserved", "arraybuffer-detach-resize-ownership", event, "ArrayBuffer generation was explicitly unchanged at pointer use", origin)
        elif kind == "object-register":
            if obj:
                known_objects.add(obj)
            dead.pop(obj, None)
        elif kind == "cancel-or-destroy":
            if obj:
                known_objects.add(obj)
                dead[obj] = event["traceLine"]
        elif kind in {"buffer-register", "buffer-generation", "buffer-detach-or-resize"}:
            if obj:
                buffers[obj] = (event.get("generation"), event["traceLine"])
        elif kind == "pointer-acquire":
            pointer = str(event.get("pointer") or "")
            if pointer:
                pointers[pointer] = (obj, event.get("generation"), event["traceLine"])
        elif kind == "io-schedule":
            callback = str(event.get("callback") or "")
            context = str(event.get("context") or "")
            if callback and context:
                scheduled[callback] = (context, event["traceLine"])

        if kind == "callback-enter" and obj:
            if obj in dead:
                add("confirmed", "cancellation-destructor-ordering", event, "callback entered after explicit object cancellation or destruction", dead[obj])
            elif obj in known_objects:
                add("preserved", "cancellation-destructor-ordering", event, "callback entered while the object was explicitly live")
            else:
                add("inconclusive", "cancellation-destructor-ordering", event, "callback object identity was not registered", missing=["object-register"])
        if kind == "callback-enter" and event.get("callback") is not None:
            callback = str(event.get("callback"))
            assessed_callbacks.add(callback)
            schedule = scheduled.get(callback)
            if schedule is None:
                add("inconclusive", "iocontext-affinity", event, "callback scheduling context was not observed", missing=["io-schedule"])
            elif not str(event.get("context") or "") or "explicitTransfer" not in event:
                add("inconclusive", "iocontext-affinity", event, "callback context or transfer telemetry is incomplete", schedule[1], ["callback context", "explicitTransfer"])
            elif str(event.get("context")) != schedule[0] and event.get("explicitTransfer") is not True:
                add("confirmed", "iocontext-affinity", event, "callback entered a different IoContext without an explicit transfer", schedule[1])
            else:
                add("preserved", "iocontext-affinity", event, "callback retained its IoContext or recorded an explicit transfer", schedule[1])

    terminal = events[-1] if events else {"traceLine": 0, "event": "trace-end"}
    for handle, (_, _, origin) in moved.items():
        if handle not in assessed_moves:
            add("inconclusive", "traced-handle-move", terminal, "trace ended before a post-move use or safe terminal state was observed", origin, ["post-move use or terminal disposition"])
    for pointer, borrow in borrows.items():
        if borrow["reentered"] and pointer not in assessed_borrows:
            add("inconclusive", "borrowed-pointer-js-reentry", terminal, "trace ended before the borrowed pointer's post-reentry disposition was observed", borrow["line"], ["pointer-use or explicit discard"])
    for pointer, (_, _, origin) in pointers.items():
        if pointer not in assessed_pointers:
            add("inconclusive", "arraybuffer-detach-resize-ownership", terminal, "trace ended before the acquired pointer's disposition was observed", origin, ["pointer-use or explicit discard"])
    for callback, (_, origin) in scheduled.items():
        if callback not in assessed_callbacks:
            add("inconclusive", "iocontext-affinity", terminal, "trace ended before callback execution or cancellation was observed", origin, ["callback-enter or callback-cancelled"])
    if not any(assessments.values()):
        add("inconclusive", "trace-coverage", terminal, "trace contains no complete lifetime experiment", missing=["family-specific event sequence"])
    return assessments


def run(args: argparse.Namespace) -> int:
    trace = Path(args.trace).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    events = load_trace(trace)
    assessments = evaluate(events)
    confirmed = assessments["confirmedDisagreements"]
    inconclusive = assessments["inconclusive"]
    outcome = (
        "confirmed-invariant-disagreement"
        if confirmed
        else "inconclusive-missing-telemetry"
        if inconclusive
        else "observed-invariant-preservation"
    )
    record = {
        "schemaVersion": 1,
        "producer": "krineon-workerd-lifetime-oracle",
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "trace": {"path": str(trace), "sha256": sha256_file(trace), "events": len(events)},
        **assessments,
        "outcome": outcome,
        "invariantViolated": bool(confirmed),
        "vulnerabilityVerdictProduced": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": str(output),
        "outcome": outcome,
        "confirmed": len(confirmed),
        "preserved": len(assessments["preserved"]),
        "inconclusive": len(inconclusive),
    }, indent=2))
    return 1 if confirmed else 3 if inconclusive else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
