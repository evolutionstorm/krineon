#!/usr/bin/env python3
"""Extract workerd/V8 lifetime hypotheses and concrete runtime trace plans.

This is a candidate generator, not a vulnerability classifier. Every emitted
candidate names source locations, the state transition to instrument, and the
runtime event sequence needed to falsify or confirm the hypothesis.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SOURCE_SUFFIXES = {".c++", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
TRACED_TYPE = re.compile(
    r"\b(?:jsg::(?:V8Ref|JsRef|V8RefTo)|v8::(?:TracedReference|Global|Persistent))"
    r"\s*<[^;>{}]+>\s+(\w+)\s*(?:[;={])"
)
MOVE = re.compile(r"\b(?:kj::mv|std::move)\s*\(\s*(\w+)\s*\)")
BORROW = re.compile(
    r"\b(?:auto|const\s+auto|[\w:<>]+\s*\*|[\w:<>]+\s*&?)\s+(\w+)\s*=\s*"
    r"([^;\n]+?\.(?:get|data|begin|GetBackingStore|Data)\s*\([^;\n]*\))"
)
REENTRY = re.compile(
    r"\b(?:runMicrotasks|PerformMicrotaskCheckpoint|jsg::Lock|lock\.run|"
    r"callback|invoke|call|then|resolve|reject)\b"
)
BUFFER_CHANGE = re.compile(r"\b(?:Detach|Resize|Transfer|Reallocate|Neuter)\s*\(")
CALLBACK = re.compile(r"\b(?:then|catch_|onCancel|onDisconnect|addListener|queueMicrotask)\s*\(")


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def balanced_spans(text: str, declaration: re.Pattern[str]) -> Iterable[tuple[re.Match[str], int, int]]:
    for match in declaration.finditer(text):
        opening = text.find("{", match.end() - 1)
        if opening < 0:
            continue
        depth = 0
        for index in range(opening, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    yield match, opening, index + 1
                    break


def function_spans(text: str) -> Iterable[tuple[str, int, int]]:
    declaration = re.compile(
        r"(?m)^\s*(?:template\s*<[^;{}]+>\s*)?(?:[\w:<>~*&]+\s+)+"
        r"([~\w:]+)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
    )
    for match, start, end in balanced_spans(text, declaration):
        yield match.group(1), start, end


def source(path: Path, line: int) -> str:
    return f"{path.as_posix()}:{line}"


def candidate(
    *,
    family: str,
    path: Path,
    line: int,
    symbol: str,
    observation: str,
    instrumentation: list[dict[str, Any]],
    oracle_events: list[str],
) -> dict[str, Any]:
    identity = hashlib.sha256(
        json.dumps([family, path.as_posix(), line, symbol], separators=(",", ":")).encode()
    ).hexdigest()[:18]
    return {
        "id": "WL-" + identity,
        "family": family,
        "status": "source-candidate-runtime-oracle-required",
        "symbol": symbol,
        "source": source(path, line),
        "observation": observation,
        "instrumentation": instrumentation,
        "oracle": {
            "producer": "krineon-workerd-lifetime-trace",
            "requiredEvents": oracle_events,
            "verifier": "scripts/workerd_lifetime_oracle.py",
            "verdictBoundary": "runtime invariant violation, not vulnerability or RCE",
        },
    }


def analyze_file(relative: Path, text: str) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    class_decl = re.compile(r"\b(?:class|struct)\s+(\w+)[^{;]*\{")
    for class_match, opening, end in balanced_spans(text, class_decl):
        body = text[opening:end]
        fields = list(TRACED_TYPE.finditer(body))
        if not fields:
            continue
        visitors = [
            span for span in function_spans(body)
            if any(name in span[0] for name in ("visitForGc", "visitForMemoryInfo", "trace"))
        ]
        visitor_text = "\n".join(body[start:finish] for _, start, finish in visitors)
        for field in fields:
            name = field.group(1)
            if re.search(rf"\b{re.escape(name)}\b", visitor_text):
                continue
            absolute = opening + field.start()
            values.append(candidate(
                family="missing-gc-visitation",
                path=relative,
                line=line_number(text, absolute),
                symbol=f"{class_match.group(1)}::{name}",
                observation="a traced V8 handle is not named by any class GC visitor candidate",
                instrumentation=[
                    {"at": source(relative, line_number(text, absolute)), "emit": "register-traced"},
                    {"at": f"{class_match.group(1)}::visitForGc", "emit": "gc-visit"},
                    {"at": "post-GC use", "emit": "handle-use"},
                ],
                oracle_events=["register-traced", "gc-begin", "gc-visit", "gc-end", "handle-use"],
            ))

    for function, start, end in function_spans(text):
        body = text[start:end]
        base_line = line_number(text, start)
        for match in MOVE.finditer(body):
            name = match.group(1)
            remainder = body[match.end():]
            later = re.search(rf"\b{re.escape(name)}\b", remainder)
            if later:
                values.append(candidate(
                    family="traced-handle-move",
                    path=relative,
                    line=base_line + body.count("\n", 0, match.start()),
                    symbol=function,
                    observation=f"moved-from handle {name} is referenced later in the same function",
                    instrumentation=[
                        {"at": source(relative, base_line + body.count("\n", 0, match.start())), "emit": "handle-move"},
                        {"at": source(relative, base_line + body.count("\n", 0, match.end() + later.start())), "emit": "handle-use"},
                    ],
                    oracle_events=["handle-register", "handle-move", "handle-use"],
                ))

        for match in BORROW.finditer(body):
            name = match.group(1)
            remainder = body[match.end():]
            reentry = REENTRY.search(remainder)
            if not reentry:
                continue
            after = remainder[reentry.end():]
            use = re.search(rf"\b{re.escape(name)}\b", after)
            if not use:
                continue
            family = (
                "arraybuffer-detach-resize-ownership"
                if re.search(r"ArrayBuffer|BackingStore|\.Data\s*\(", match.group(2))
                or BUFFER_CHANGE.search(remainder[: reentry.end() + use.end()])
                else "borrowed-pointer-js-reentry"
            )
            borrow_line = base_line + body.count("\n", 0, match.start())
            use_line = base_line + body.count(
                "\n", 0, match.end() + reentry.end() + use.start()
            )
            values.append(candidate(
                family=family,
                path=relative,
                line=borrow_line,
                symbol=function,
                observation=f"borrowed value {name} survives a possible JavaScript reentry before reuse",
                instrumentation=[
                    {"at": source(relative, borrow_line), "emit": "pointer-acquire" if family.startswith("arraybuffer") else "borrow"},
                    {"at": source(relative, base_line + body.count("\n", 0, match.end() + reentry.start())), "emit": "js-reentry"},
                    {"at": source(relative, use_line), "emit": "pointer-use"},
                ],
                oracle_events=(
                    [
                        "buffer-register",
                        "pointer-acquire",
                        "buffer-detach-or-resize or post-acquisition buffer-generation",
                        "pointer-use",
                    ]
                    if family.startswith("arraybuffer")
                    else ["owner-register", "borrow", "js-reentry", "owner-generation", "pointer-use"]
                ),
            ))

        if (function.startswith("~") or "cancel" in function.lower() or "disconnect" in function.lower()) and CALLBACK.search(body):
            values.append(candidate(
                family="cancellation-destructor-ordering",
                path=relative,
                line=base_line,
                symbol=function,
                observation="a cancellation or destructor path schedules or enters a callback",
                instrumentation=[
                    {"at": source(relative, base_line), "emit": "cancel-or-destroy"},
                    {"at": "scheduled callback entry", "emit": "callback-enter"},
                ],
                oracle_events=["object-register", "cancel-or-destroy", "callback-enter"],
            ))

        if "IoContext" in body and CALLBACK.search(body):
            explicit = re.search(
                r"IoContext::current|runInContext|withIoContext|kj::Own\s*<\s*IoContext",
                body,
            )
            if not explicit:
                values.append(candidate(
                    family="iocontext-affinity",
                    path=relative,
                    line=base_line,
                    symbol=function,
                    observation="an asynchronous callback uses IoContext without an explicit affinity transfer candidate",
                    instrumentation=[
                        {"at": source(relative, base_line), "emit": "io-schedule"},
                        {"at": "callback entry", "emit": "callback-enter"},
                    ],
                    oracle_events=[
                        "io-context-register",
                        "io-schedule",
                        "callback-enter with context and explicitTransfer",
                    ],
                ))
    return values


def run(args: argparse.Namespace) -> int:
    checkout = Path(args.checkout).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    if not checkout.is_dir():
        raise RuntimeError("workerd checkout is absent")
    candidates: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    for path in sorted(checkout.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(part in {"node_modules", ".git", "bazel-out", "out"} for part in path.parts):
            continue
        relative = path.relative_to(checkout)
        text = path.read_text(encoding="utf-8", errors="replace")
        found = analyze_file(relative, text)
        candidates.extend(found)
        files.append({"path": relative.as_posix(), "sha256": sha256_file(path), "candidates": len(found)})
    record = {
        "schemaVersion": 1,
        "producer": "krineon-workerd-lifetime-analysis",
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checkout": str(checkout),
        "files": files,
        "candidates": candidates,
        "families": sorted({value["family"] for value in candidates}),
        "vulnerabilityVerdictsProduced": False,
        "limitations": [
            "source candidates require the emitted runtime trace plan",
            "absence of a named visitor or affinity helper is not itself a defect",
            "runtime invariant violations still require independent replay and impact analysis",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"analysis": str(output), "files": len(files), "candidates": len(candidates)}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
