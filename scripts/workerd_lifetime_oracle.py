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


def evaluate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    registered_fields: dict[tuple[str, str], int] = {}
    visited_fields: set[tuple[str, str]] = set()
    moved: dict[str, tuple[str, Any, int]] = {}
    borrows: dict[str, dict[str, Any]] = {}
    owner_generation: dict[str, Any] = {}
    dead: dict[str, int] = {}
    buffers: dict[str, Any] = {}
    pointers: dict[str, tuple[str, Any, int]] = {}
    scheduled: dict[str, tuple[str, int]] = {}

    def add(family: str, event: dict[str, Any], reason: str, origin: int | None = None) -> None:
        violations.append({
            "family": family,
            "traceLine": event["traceLine"],
            "originTraceLine": origin,
            "object": event.get("object") or event.get("handle") or event.get("pointer"),
            "reason": reason,
        })

    for event in events:
        kind = event["event"]
        obj = str(event.get("object") or "")
        if kind == "register-traced":
            registered_fields[(obj, str(event.get("field") or ""))] = event["traceLine"]
        elif kind == "gc-begin":
            visited_fields.clear()
        elif kind == "gc-visit":
            visited_fields.add((obj, str(event.get("field") or "")))
        elif kind == "handle-use" and event.get("alive") is False:
            key = (obj, str(event.get("field") or ""))
            if key in registered_fields and key not in visited_fields:
                add("missing-gc-visitation", event, "unvisited traced handle used after collection", registered_fields[key])
        elif kind == "handle-move":
            moved[str(event.get("from") or "")] = (
                str(event.get("to") or ""), event.get("generation"), event["traceLine"]
            )
        elif kind == "handle-use":
            handle = str(event.get("handle") or obj)
            if handle in moved and event.get("generation") == moved[handle][1]:
                add("traced-handle-move", event, "moved-from traced handle used", moved[handle][2])
        elif kind == "owner-register" or kind == "owner-generation":
            owner_generation[obj] = event.get("generation")
        elif kind == "borrow":
            borrows[str(event.get("pointer") or "")] = {
                "owner": obj,
                "generation": event.get("generation"),
                "line": event["traceLine"],
                "reentered": False,
            }
        elif kind == "js-reentry":
            for value in borrows.values():
                value["reentered"] = True
        elif kind == "pointer-use":
            pointer = str(event.get("pointer") or "")
            borrow = borrows.get(pointer)
            if borrow and borrow["reentered"] and owner_generation.get(borrow["owner"]) != borrow["generation"]:
                add("borrowed-pointer-js-reentry", event, "borrowed pointer used after reentry changed owner generation", borrow["line"])
            buffer_pointer = pointers.get(pointer)
            if buffer_pointer and buffers.get(buffer_pointer[0]) != buffer_pointer[1]:
                add("arraybuffer-detach-resize-ownership", event, "pointer used after ArrayBuffer generation changed", buffer_pointer[2])
        elif kind == "object-register":
            dead.pop(obj, None)
        elif kind == "cancel-or-destroy":
            dead[obj] = event["traceLine"]
        elif kind == "callback-enter" and obj in dead:
            add("cancellation-destructor-ordering", event, "callback entered after object cancellation or destruction", dead[obj])
        elif kind == "buffer-register" or kind == "buffer-detach-or-resize":
            buffers[obj] = event.get("generation")
        elif kind == "pointer-acquire":
            pointers[str(event.get("pointer") or "")] = (obj, event.get("generation"), event["traceLine"])
        elif kind == "io-schedule":
            scheduled[str(event.get("callback") or "")] = (
                str(event.get("context") or ""), event["traceLine"]
            )
        elif kind == "callback-enter" and event.get("callback") is not None:
            callback = str(event.get("callback"))
            schedule = scheduled.get(callback)
            if schedule and str(event.get("context") or "") != schedule[0] and event.get("explicitTransfer") is not True:
                add("iocontext-affinity", event, "callback entered a different IoContext without an explicit transfer", schedule[1])
    return violations


def run(args: argparse.Namespace) -> int:
    trace = Path(args.trace).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    events = load_trace(trace)
    violations = evaluate(events)
    record = {
        "schemaVersion": 1,
        "producer": "krineon-workerd-lifetime-oracle",
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "trace": {"path": str(trace), "sha256": sha256_file(trace), "events": len(events)},
        "violations": violations,
        "invariantViolated": bool(violations),
        "vulnerabilityVerdictProduced": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(output), "violations": len(violations)}, indent=2))
    return 1 if violations else 0


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
