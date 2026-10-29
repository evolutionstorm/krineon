#!/usr/bin/env python3
"""Emit syntax-aware security leads from one pinned source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterator


LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".rs": "rust",
    ".ts": "typescript",
    ".tsx": "tsx",
}

PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "execution-sink",
        "execution-sink-backtrace",
        ("exec", "spawn", "system", "popen", "eval", "function", "dlopen", "loadlibrary"),
    ),
    (
        "code-loading-sink",
        "capability-code-loading",
        ("require", "import", "loadmodule", "loadlibrary", "compile", "instantiate"),
    ),
    (
        "memory-native-sink",
        "memory-lifetime",
        ("memcpy", "memmove", "strcpy", "realloc", "malloc", "free", "mmap", "unsafe"),
    ),
    (
        "validation-guard",
        "ingress-authority",
        ("validate", "verify", "authorize", "authenticate", "sanitize", "checkbounds", "checklength"),
    ),
    (
        "public-ingress",
        "ingress-authority",
        ("handler", "request", "route", "decode", "deserialize", "parse", "receive", "dispatch"),
    ),
)

CALL_HINTS = ("call", "invocation", "macro_invocation", "new_expression")
FUNCTION_HINTS = ("function", "method", "constructor", "declaration", "definition")
SKIP_PARTS = {".git", ".next", "node_modules", "target", "dist", "build", "vendor"}


def parser_for(language: str):
    try:
        from tree_sitter_languages import get_parser  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "tree_sitter_languages is unavailable; install it outside the campaign or record the limitation"
        ) from exc
    try:
        return get_parser(language)
    except Exception as exc:  # library versions expose different exception types
        raise RuntimeError(f"Tree-sitter parser unavailable for {language}: {exc}") from exc


def walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def text_for(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def classify(text: str, node_type: str) -> tuple[str, str, str] | None:
    lowered = text.lower()
    is_call = any(hint in node_type for hint in CALL_HINTS)
    is_function = any(hint in node_type for hint in FUNCTION_HINTS)
    if not (is_call or is_function):
        return None
    for kind, family, terms in PATTERNS:
        for term in terms:
            if term in lowered:
                if kind == "public-ingress" and not is_function:
                    continue
                return kind, family, term
    return None


def lead_id(path: str, line: int, kind: str, term: str) -> str:
    digest = hashlib.sha256(f"{path}:{line}:{kind}:{term}".encode()).hexdigest()[:16]
    return f"SL-{digest}"


def source_files(root: Path, explicit_language: str | None) -> Iterator[tuple[Path, str]]:
    paths = [root] if root.is_file() else root.rglob("*")
    for path in paths:
        relative_parts = (Path(path.name) if root.is_file() else path.relative_to(root)).parts
        if not path.is_file() or any(part in SKIP_PARTS for part in relative_parts):
            continue
        language = explicit_language or LANGUAGES.get(path.suffix.lower())
        if language:
            yield path, language


def census(root: Path, language: str | None, max_leads: int) -> dict[str, Any]:
    parsers: dict[str, Any] = {}
    leads: list[dict[str, Any]] = []
    stats = {"filesParsed": 0, "parseErrors": 0, "nodesVisited": 0}
    for path, file_language in source_files(root, language):
        parser = parsers.setdefault(file_language, parser_for(file_language))
        source = path.read_bytes()
        tree = parser.parse(source)
        stats["filesParsed"] += 1
        if tree.root_node.has_error:
            stats["parseErrors"] += 1
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        for node in walk(tree.root_node):
            stats["nodesVisited"] += 1
            if len(leads) >= max_leads:
                break
            raw = " ".join(text_for(source, node).split())
            if not raw or len(raw) > 1200:
                continue
            match = classify(raw, node.type)
            if not match:
                continue
            kind, family, term = match
            line = node.start_point[0] + 1
            leads.append(
                {
                    "id": lead_id(relative, line, kind, term),
                    "tool": "tree-sitter",
                    "kind": kind,
                    "title": f"{kind.replace('-', ' ').title()}: {term}",
                    "location": f"{relative}:{line}",
                    "line": line,
                    "language": file_language,
                    "nodeType": node.type,
                    "excerpt": raw[:500],
                    "approachFamily": family,
                    "provenance": {
                        "source": str(root),
                        "syntaxAware": True,
                        "staticOnly": True,
                        "runtimeValidated": False,
                    },
                }
            )
        if len(leads) >= max_leads:
            break
    return {
        "schemaVersion": 1,
        "tool": "tree-sitter",
        "source": str(root),
        "languageOverride": language,
        "stats": stats,
        "truncated": len(leads) >= max_leads,
        "leads": leads,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--language")
    parser.add_argument("--max-leads", type=int, default=500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    root = args.source.expanduser().resolve()
    if not root.exists():
        parser.error(f"source does not exist: {root}")
    if args.max_leads < 1:
        parser.error("--max-leads must be positive")
    try:
        result = census(root, args.language, args.max_leads)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
