#!/usr/bin/env python3
"""Map Next/React/Node production structure into runtime hypotheses, never verdicts."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROJECT = Path(__file__).resolve().parents[1]
RESEARCH_HARNESS = PROJECT / "scripts" / "research_harness.py"
SOURCE_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DIRECTIVES = {"use client", "use server", "use cache", "use strict"}
DEFAULT_AUTH_SIGNALS = {
    "auth", "authorize", "getServerSession", "getSession", "getToken", "requireAuth",
    "requireUser", "verifySession", "verifyToken", "withAuth",
}
DEFAULT_CACHE_SIGNALS = {
    "cache", "unstable_cache", "revalidatePath", "revalidateTag", "updateTag",
    "refresh", "noStore", "unstable_noStore", "fetch",
}
APPROACH_FAMILY = {
    "route-runtime-alignment": "stock-reachability",
    "middleware-handler-order": "ingress-authority",
    "directive-boundary": "capability-code-loading",
    "dynamic-module-identity": "capability-code-loading",
    "cache-revalidation-isolation": "representation-parser",
    "environment-runtime-branch": "stock-reachability",
}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    column: int


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, root: Path | None = None) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix() if root else str(path),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def stable_id(prefix: str, *parts: Any) -> str:
    encoded = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def project_path(spec_path: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = spec_path.parent / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise RuntimeError(f"projectRoot is not a directory: {candidate}")
    return candidate


def campaign_value(root: Path) -> dict[str, Any]:
    path = root / "campaign.json"
    if not path.is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    return read_json(path)


def decode_string(source: str, start: int, quote: str) -> tuple[str, int, int]:
    result: list[str] = []
    index = start + 1
    lines = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while index < len(source):
        current = source[index]
        if current == quote:
            return "".join(result), index + 1, lines
        if current == "\n":
            lines += 1
        if current != "\\":
            result.append(current)
            index += 1
            continue
        index += 1
        if index >= len(source):
            break
        escaped = source[index]
        if escaped == "\n":
            lines += 1
            index += 1
            continue
        if escaped in escapes:
            result.append(escapes[escaped])
            index += 1
            continue
        if escaped == "x" and index + 2 < len(source):
            try:
                result.append(chr(int(source[index + 1:index + 3], 16)))
                index += 3
                continue
            except ValueError:
                pass
        if escaped == "u" and index + 4 < len(source):
            try:
                result.append(chr(int(source[index + 1:index + 5], 16)))
                index += 5
                continue
            except ValueError:
                pass
        result.append(escaped)
        index += 1
    return "".join(result), index, lines


def lex_javascript(source: str) -> list[Token]:
    """Return structural tokens; comments and regex bodies are never treated as facts."""
    tokens: list[Token] = []
    index = 0
    line = 1
    column = 0
    previous_can_end_expression = False
    while index < len(source):
        current = source[index]
        if current in " \t\r\f\v":
            index += 1
            column += 1
            continue
        if current == "\n":
            index += 1
            line += 1
            column = 0
            previous_can_end_expression = False
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = len(source) - 2 if end < 0 else end
            body = source[index:end + 2]
            newline_count = body.count("\n")
            if newline_count:
                line += newline_count
                column = len(body.rsplit("\n", 1)[-1])
            else:
                column += len(body)
            index = end + 2
            continue
        token_line, token_column = line, column
        if current in {"'", '"'}:
            value, end, added_lines = decode_string(source, index, current)
            consumed = source[index:end]
            tokens.append(Token("string", value, token_line, token_column))
            line += added_lines
            column = len(consumed.rsplit("\n", 1)[-1]) if added_lines else column + len(consumed)
            index = end
            previous_can_end_expression = True
            continue
        if current == "`":
            end = index + 1
            escaped = False
            interpolation = False
            while end < len(source):
                char = source[end]
                if not escaped and char == "`":
                    end += 1
                    break
                if not escaped and source.startswith("${", end):
                    interpolation = True
                escaped = not escaped and char == "\\"
                if char != "\\":
                    escaped = False
                end += 1
            consumed = source[index:end]
            tokens.append(Token("template", consumed[1:-1] if not interpolation else "<interpolated>", token_line, token_column))
            newline_count = consumed.count("\n")
            line += newline_count
            column = len(consumed.rsplit("\n", 1)[-1]) if newline_count else column + len(consumed)
            index = end
            previous_can_end_expression = True
            continue
        if current.isalpha() or current in "_$":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            value = source[index:end]
            tokens.append(Token("identifier", value, token_line, token_column))
            column += end - index
            index = end
            previous_can_end_expression = value not in {"return", "throw", "case", "delete", "void", "typeof", "new", "in", "of"}
            continue
        if current.isdigit():
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "._"):
                end += 1
            tokens.append(Token("number", source[index:end], token_line, token_column))
            column += end - index
            index = end
            previous_can_end_expression = True
            continue
        if current == "/" and not previous_can_end_expression:
            end = index + 1
            escaped = False
            in_class = False
            while end < len(source):
                char = source[end]
                if not escaped:
                    if char == "[":
                        in_class = True
                    elif char == "]":
                        in_class = False
                    elif char == "/" and not in_class:
                        end += 1
                        while end < len(source) and source[end].isalpha():
                            end += 1
                        break
                    elif char == "\n":
                        break
                escaped = not escaped and char == "\\"
                if char != "\\":
                    escaped = False
                end += 1
            tokens.append(Token("regex", source[index:end], token_line, token_column))
            column += end - index
            index = end
            previous_can_end_expression = True
            continue
        operator = next((value for value in ("===", "!==", "=>", "?.", "??", "&&", "||", "==", "!=", "<=", ">=", "**") if source.startswith(value, index)), current)
        tokens.append(Token("punct", operator, token_line, token_column))
        index += len(operator)
        column += len(operator)
        previous_can_end_expression = operator in {")", "]", "}"}
    return tokens


def fact(path: Path, root: Path, kind: str, token: Token | None, details: dict[str, Any]) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    line = token.line if token else 1
    column = token.column if token else 0
    value = {
        "kind": kind,
        "source": relative,
        "line": line,
        "column": column,
        **details,
    }
    value["id"] = stable_id("FF", kind, relative, line, column, details)
    return value


def dotted_name(tokens: list[Token], end: int) -> tuple[str, int]:
    if end < 0 or tokens[end].kind != "identifier":
        return "", end
    parts = [tokens[end].value]
    index = end - 1
    while index >= 1 and tokens[index].value in {".", "?."} and tokens[index - 1].kind == "identifier":
        parts.insert(0, tokens[index - 1].value)
        index -= 2
    return ".".join(parts), index + 1


def statement_snippet(source: str, line: int, limit: int = 280) -> str:
    rows = source.splitlines()
    if not rows:
        return ""
    return rows[max(0, line - 1)][:limit]


def call_literal_arguments(tokens: list[Token], open_index: int, maximum: int = 8) -> list[str]:
    depth = 0
    values: list[str] = []
    for token in tokens[open_index:]:
        if token.value == "(":
            depth += 1
        elif token.value == ")":
            depth -= 1
            if depth == 0:
                break
        elif token.kind == "string" and depth > 0:
            values.append(token.value)
            if len(values) >= maximum:
                break
    return values


def scan_javascript(
    path: Path,
    root: Path,
    classification: str,
    auth_signals: set[str],
    cache_signals: set[str],
    maximum_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    size = path.stat().st_size
    inventory = {**artifact(path, root), "classification": classification, "parsed": size <= maximum_bytes}
    if size > maximum_bytes:
        return [], [inventory]
    source = path.read_text(encoding="utf-8", errors="replace")
    tokens = lex_javascript(source)
    facts: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens) and tokens[index].value == ";":
        index += 1
    while index < len(tokens) and tokens[index].kind == "string" and tokens[index].value in DIRECTIVES:
        facts.append(fact(path, root, "directive", tokens[index], {"directive": tokens[index].value, "classification": classification}))
        index += 1
        if index < len(tokens) and tokens[index].value == ";":
            index += 1

    for index, token in enumerate(tokens):
        if token.value == "import":
            if index + 1 < len(tokens) and tokens[index + 1].value == "(":
                argument = tokens[index + 2] if index + 2 < len(tokens) else None
                literal = bool(argument and argument.kind in {"string", "template"} and argument.value != "<interpolated>")
                facts.append(fact(path, root, "dynamic-import", token, {"specifier": argument.value if argument else "<missing>", "literalSpecifier": literal, "classification": classification, "snippet": statement_snippet(source, token.line)}))
            else:
                upper = min(len(tokens), index + 40)
                specifier = None
                for cursor in range(index + 1, upper):
                    if tokens[cursor].value == ";":
                        break
                    if tokens[cursor].kind == "string" and (cursor == index + 1 or tokens[cursor - 1].value == "from"):
                        specifier = tokens[cursor]
                        break
                if specifier:
                    facts.append(fact(path, root, "static-import", token, {"specifier": specifier.value, "classification": classification}))
        if token.value == "export":
            upper = min(len(tokens), index + 30)
            for cursor in range(index + 1, upper):
                if tokens[cursor].value == ";":
                    break
                if tokens[cursor].value == "from" and cursor + 1 < len(tokens) and tokens[cursor + 1].kind == "string":
                    facts.append(fact(path, root, "static-import", token, {"specifier": tokens[cursor + 1].value, "reexport": True, "classification": classification}))
                    break
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor].value == "async":
                cursor += 1
            if cursor < len(tokens) and tokens[cursor].value == "function" and cursor + 1 < len(tokens):
                name = tokens[cursor + 1].value
                if name in HTTP_METHODS:
                    facts.append(fact(path, root, "http-handler", tokens[cursor + 1], {"method": name, "classification": classification}))
            if cursor + 1 < len(tokens) and tokens[cursor].value in {"const", "let", "var"}:
                name = tokens[cursor + 1].value
                if name in HTTP_METHODS:
                    facts.append(fact(path, root, "http-handler", tokens[cursor + 1], {"method": name, "classification": classification}))
                if name in {"runtime", "revalidate", "dynamic", "preferredRegion"}:
                    value = tokens[cursor + 3].value if cursor + 3 < len(tokens) and tokens[cursor + 2].value == "=" else None
                    facts.append(fact(path, root, "runtime-config", tokens[cursor + 1], {"name": name, "value": value, "classification": classification}))
        if token.value == "require" and index + 1 < len(tokens) and tokens[index + 1].value == "(":
            argument = tokens[index + 2] if index + 2 < len(tokens) else None
            if argument and argument.kind in {"string", "number", "identifier", "template"}:
                facts.append(fact(path, root, "dynamic-import", token, {"specifier": argument.value, "literalSpecifier": argument.kind in {"string", "number"}, "mechanism": "require", "classification": classification, "snippet": statement_snippet(source, token.line)}))
                if argument.kind == "number":
                    facts.append(fact(path, root, "module-identity-use", token, {"identity": argument.value, "mechanism": "require", "classification": classification}))
        if token.value == "process" and index + 4 < len(tokens):
            same_line = {candidate.value for candidate in tokens if candidate.line == token.line}
            branch_operators = sorted(same_line.intersection({"if", "switch", "?", "&&", "||", "??"}))
            if tokens[index + 1].value in {".", "?."} and tokens[index + 2].value == "env" and tokens[index + 3].value in {".", "?."} and tokens[index + 4].kind == "identifier":
                facts.append(fact(path, root, "environment-read", token, {"variable": tokens[index + 4].value, "branchCandidate": bool(branch_operators), "branchOperators": branch_operators, "classification": classification, "snippet": statement_snippet(source, token.line)}))
            elif tokens[index + 1].value in {".", "?."} and tokens[index + 2].value == "env" and tokens[index + 3].value == "[" and tokens[index + 4].kind == "string":
                facts.append(fact(path, root, "environment-read", token, {"variable": tokens[index + 4].value, "branchCandidate": bool(branch_operators), "branchOperators": branch_operators, "classification": classification, "snippet": statement_snippet(source, token.line)}))
        if token.value == "(" and index > 0:
            name, start = dotted_name(tokens, index - 1)
            if not name:
                continue
            base = name.rsplit(".", 1)[-1]
            facts.append(
                fact(
                    path,
                    root,
                    "call-operation",
                    tokens[start],
                    {
                        "callee": name,
                        "literalArguments": call_literal_arguments(tokens, index),
                        "classification": classification,
                        "snippet": statement_snippet(source, tokens[start].line),
                    },
                )
            )
            if base in auth_signals:
                facts.append(fact(path, root, "authentication-signal", tokens[start], {"callee": name, "classification": classification, "snippet": statement_snippet(source, tokens[start].line)}))
            if base in cache_signals:
                facts.append(fact(path, root, "cache-operation", tokens[start], {"callee": name, "operation": base, "literalArguments": call_literal_arguments(tokens, index), "classification": classification, "snippet": statement_snippet(source, tokens[start].line)}))
            if base.lower() in {method.lower() for method in HTTP_METHODS} and "." in name:
                if index + 1 < len(tokens) and tokens[index + 1].kind == "string":
                    facts.append(fact(path, root, "http-handler", tokens[start], {"method": base.upper(), "route": tokens[index + 1].value, "frameworkCall": name, "classification": classification}))
    unique = {row["id"]: row for row in facts}
    return sorted(unique.values(), key=lambda row: (row["source"], row["line"], row["column"], row["kind"])), [inventory]


def route_from_source(relative: str) -> str | None:
    path = Path(relative)
    parts = list(path.parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    stem = Path(parts[-1]).stem
    if parts[0] == "app" and stem in {"page", "route"}:
        route_parts = parts[1:-1]
    elif parts[0] == "pages":
        route_parts = parts[1:-1] + ([] if stem == "index" else [stem])
    else:
        return None
    cleaned: list[str] = []
    for part in route_parts:
        if (part.startswith("(") and part.endswith(")")) or part.startswith("@"):
            continue
        if part.startswith("[[...") and part.endswith("]]"):
            cleaned.append("*" + part[5:-2])
        elif part.startswith("[...") and part.endswith("]"):
            cleaned.append("*" + part[4:-1])
        elif part.startswith("[") and part.endswith("]"):
            cleaned.append(":" + part[1:-1])
        else:
            cleaned.append(part)
    return "/" + "/".join(cleaned)


def expand_patterns(root: Path, patterns: Iterable[Any], maximum: int) -> tuple[list[Path], int]:
    files: set[Path] = set()
    omitted = 0
    for pattern in patterns:
        value = str(pattern)
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise RuntimeError(f"analysis glob must be project-relative: {value}")
        for match in glob.glob(str(root / value), recursive=True):
            path = Path(match).resolve()
            path.relative_to(root)
            if not path.is_file() or path.is_symlink():
                continue
            if len(files) >= maximum:
                omitted += 1
            else:
                files.add(path)
    return sorted(files), omitted


def default_patterns(framework: str) -> dict[str, list[str]]:
    source_roots = ["app", "pages", "src", "lib", "routes"]
    sources = [f"{root}/**/*{extension}" for root in source_roots for extension in SOURCE_EXTENSIONS]
    sources += [f"middleware{extension}" for extension in SOURCE_EXTENSIONS]
    sources += [f"proxy{extension}" for extension in SOURCE_EXTENSIONS]
    if framework == "nextjs":
        return {
            "source": sources,
            "generated": [".next/server/**/*.js", ".next/server/**/*.mjs", ".next/static/**/*.js"],
            "vendored": [
                "node_modules/next/dist/server/**/*.js",
                "node_modules/next/dist/compiled/react-server-dom*/**/*.js",
                "node_modules/react/cjs/*.js",
                "node_modules/react-dom/cjs/*.js",
            ],
            "manifests": [".next/**/*manifest*.json", ".next/**/*manifest*.js", ".next/BUILD_ID"],
            "sourceMaps": [".next/**/*.map"],
        }
    if framework == "react":
        return {
            "source": sources,
            "generated": ["dist/**/*.js", "build/**/*.js", "out/**/*.js"],
            "vendored": ["node_modules/react/cjs/*.js", "node_modules/react-dom/cjs/*.js", "node_modules/react-server-dom*/cjs/*.js"],
            "manifests": ["dist/**/*manifest*.json", "build/**/*manifest*.json"],
            "sourceMaps": ["dist/**/*.map", "build/**/*.map", "out/**/*.map"],
        }
    return {
        "source": sources,
        "generated": ["dist/**/*.js", "build/**/*.js", "out/**/*.js"],
        "vendored": [],
        "manifests": ["dist/**/*manifest*.json", "build/**/*manifest*.json"],
        "sourceMaps": ["dist/**/*.map", "build/**/*.map", "out/**/*.map"],
    }


def manifest_facts(path: Path, root: Path) -> list[dict[str, Any]]:
    relative = path.relative_to(root).as_posix()
    if path.name == "BUILD_ID":
        return [fact(path, root, "build-identity", None, {"valueSha256": sha256_bytes(path.read_bytes())})]
    if path.suffix != ".json":
        return []
    try:
        document = read_json(path)
    except (OSError, json.JSONDecodeError, RuntimeError):
        return []
    rows: list[dict[str, Any]] = []
    name = path.name
    if name in {"app-paths-manifest.json", "pages-manifest.json"}:
        for route, bundle in document.items():
            if isinstance(bundle, str):
                rows.append(fact(path, root, "manifest-route", None, {"route": str(route), "bundle": bundle, "manifest": relative}))
    if name == "routes-manifest.json":
        for section in ("staticRoutes", "dynamicRoutes"):
            for entry in document.get(section, []):
                if isinstance(entry, dict) and (entry.get("page") or entry.get("route")):
                    rows.append(fact(path, root, "manifest-route", None, {"route": str(entry.get("page") or entry.get("route")), "regexp": entry.get("regex"), "section": section, "manifest": relative}))
        rewrites = document.get("rewrites")
        rewrite_rows = [*rewrites.get("beforeFiles", []), *rewrites.get("afterFiles", []), *rewrites.get("fallback", [])] if isinstance(rewrites, dict) else (rewrites or [])
        for entry in rewrite_rows:
            if isinstance(entry, dict) and entry.get("source"):
                rows.append(fact(path, root, "route-rewrite", None, {"sourceRoute": entry.get("source"), "destination": entry.get("destination"), "manifest": relative}))
    if name == "middleware-manifest.json":
        middleware = document.get("middleware")
        for route, entry in middleware.items() if isinstance(middleware, dict) else []:
            if not isinstance(entry, dict):
                continue
            matchers = entry.get("matchers") if isinstance(entry.get("matchers"), list) else []
            rows.append(fact(path, root, "middleware-entry", None, {"route": str(route), "files": entry.get("files", []), "regexps": [str(item.get("regexp")) for item in matchers if isinstance(item, dict) and item.get("regexp")], "manifest": relative}))
    if name in {"app-build-manifest.json", "build-manifest.json", "react-loadable-manifest.json"}:
        pages = document.get("pages") if isinstance(document.get("pages"), dict) else document
        for identity, chunks in pages.items() if isinstance(pages, dict) else []:
            if isinstance(chunks, list) and all(isinstance(item, str) for item in chunks):
                rows.append(fact(path, root, "module-identity", None, {"identity": str(identity), "chunks": chunks, "manifest": relative}))
    if name == "prerender-manifest.json":
        for route, entry in document.get("routes", {}).items():
            if isinstance(entry, dict):
                rows.append(fact(path, root, "prerender-cache", None, {"route": str(route), "initialRevalidateSeconds": entry.get("initialRevalidateSeconds"), "dataRoute": entry.get("dataRoute"), "manifest": relative}))
    if "server-reference-manifest" in name:
        for runtime in ("node", "edge"):
            entries = document.get(runtime)
            for identity, entry in entries.items() if isinstance(entries, dict) else []:
                if not isinstance(entry, dict):
                    continue
                rows.append(fact(path, root, "server-reference-identity", None, {"runtime": runtime, "identity": str(identity), "workers": entry.get("workers", {}), "layer": entry.get("layer", {}), "manifest": relative}))
    return rows


BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def decode_vlq(segment: str) -> list[int]:
    values: list[int] = []
    value = 0
    shift = 0
    for char in segment:
        digit = BASE64.find(char)
        if digit < 0:
            raise ValueError("invalid source-map VLQ")
        continuation = digit & 32
        digit &= 31
        value += digit << shift
        if continuation:
            shift += 5
            continue
        negative = value & 1
        value >>= 1
        values.append(-value if negative else value)
        value = 0
        shift = 0
    if shift:
        raise ValueError("truncated source-map VLQ")
    return values


def normalize_map_source(map_path: Path, root: Path, source_root: str, source: str) -> str:
    value = source
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/]*)/?", "", value)
    value = value.removeprefix("webpack://").removeprefix("_N_E/").removeprefix("./")
    combined = Path(source_root) / value if source_root else Path(value)
    candidates = [map_path.parent / combined, root / combined, root / value]
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved == root or root in resolved.parents:
                return resolved.relative_to(root).as_posix()
        except OSError:
            continue
    return combined.as_posix()


def decode_source_map(path: Path, root: Path, document: dict[str, Any], generated_line_offset: int = 0, generated_column_offset: int = 0) -> list[dict[str, Any]]:
    if isinstance(document.get("sections"), list):
        rows: list[dict[str, Any]] = []
        for section in document["sections"]:
            if not isinstance(section, dict) or not isinstance(section.get("map"), dict):
                continue
            offset = section.get("offset") if isinstance(section.get("offset"), dict) else {}
            rows.extend(decode_source_map(path, root, section["map"], generated_line_offset + int(offset.get("line") or 0), generated_column_offset + int(offset.get("column") or 0)))
        return rows
    sources = document.get("sources")
    mappings = document.get("mappings")
    if not isinstance(sources, list) or not isinstance(mappings, str):
        return []
    normalized = [normalize_map_source(path, root, str(document.get("sourceRoot") or ""), str(source)) for source in sources]
    rows: list[dict[str, Any]] = []
    source_index = 0
    original_line = 0
    original_column = 0
    name_index = 0
    for generated_line, line_value in enumerate(mappings.split(";")):
        generated_column = 0
        for segment in line_value.split(","):
            if not segment:
                continue
            values = decode_vlq(segment)
            generated_column += values[0]
            if len(values) < 4:
                continue
            source_index += values[1]
            original_line += values[2]
            original_column += values[3]
            if len(values) >= 5:
                name_index += values[4]
            if 0 <= source_index < len(normalized):
                rows.append({
                    "source": normalized[source_index],
                    "originalLine": original_line + 1,
                    "originalColumn": original_column,
                    "generatedLine": generated_line + 1 + generated_line_offset,
                    "generatedColumn": generated_column + (generated_column_offset if generated_line == 0 else 0),
                })
    return rows


def source_map_relations(map_files: list[Path], root: Path, facts: list[dict[str, Any]], maximum_relations: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_location: dict[tuple[str, int], list[dict[str, Any]]] = {}
    map_records: list[dict[str, Any]] = []
    for path in map_files:
        try:
            document = read_json(path)
            entries = decode_source_map(path, root, document)
        except (OSError, json.JSONDecodeError, RuntimeError, ValueError):
            continue
        generated = str(document.get("file") or path.name.removesuffix(".map"))
        generated_path = (path.parent / generated).resolve()
        try:
            generated_relative = generated_path.relative_to(root).as_posix()
        except ValueError:
            generated_relative = generated
        map_records.append({**artifact(path, root), "generatedFile": generated_relative, "mappingEntries": len(entries)})
        for entry in entries:
            by_location.setdefault((entry["source"], entry["originalLine"]), []).append({**entry, "generatedFile": generated_relative, "sourceMap": path.relative_to(root).as_posix()})
    relations: list[dict[str, Any]] = []
    for row in facts:
        matches = by_location.get((str(row.get("source")), int(row.get("line") or 0)), [])
        if not matches:
            continue
        nearest = sorted(matches, key=lambda entry: (abs(int(entry["originalColumn"]) - int(row.get("column") or 0)), entry["generatedFile"], entry["generatedLine"]))[:4]
        for entry in nearest:
            relation = {
                "id": stable_id("FR", "source-bundle", row["id"], entry),
                "kind": "source-to-bundle",
                "sourceFact": row["id"],
                **entry,
                "mappingPrecision": "source-line",
            }
            relations.append(relation)
            if len(relations) >= maximum_relations:
                return relations, map_records
    return relations, map_records


def resolve_relative_import(root: Path, source: str, specifier: str) -> str | None:
    if not specifier.startswith("."):
        return None
    base = (root / source).parent / specifier
    candidates = [base, *[Path(str(base) + extension) for extension in SOURCE_EXTENSIONS], *[base / ("index" + extension) for extension in SOURCE_EXTENSIONS]]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve().relative_to(root).as_posix()
    return None


def concrete_route(route: str) -> str:
    parts = []
    for part in route.split("/"):
        if part.startswith(":"):
            parts.append("krineon-probe")
        elif part.startswith("*"):
            parts.extend(["krineon", "probe"])
        else:
            parts.append(part)
    value = "/".join(parts)
    return value if value.startswith("/") else "/" + value


def route_matches(regex: str, route: str) -> bool | None:
    try:
        return re.search(regex, route) is not None
    except re.error:
        return None


def build_relations(root: Path, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    directives = {row["source"]: row for row in facts if row["kind"] == "directive" and row.get("directive") != "use strict"}
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in facts:
        by_source.setdefault(str(row.get("source") or ""), []).append(row)
    for row in facts:
        if row["kind"] not in {"static-import", "dynamic-import"}:
            continue
        target = resolve_relative_import(root, row["source"], str(row.get("specifier") or ""))
        relation = {
            "id": stable_id("FR", "module-edge", row["id"], target or row.get("specifier")),
            "kind": "module-edge",
            "sourceFact": row["id"],
            "sourceModule": row["source"],
            "targetModule": target,
            "specifier": row.get("specifier"),
            "dynamic": row["kind"] == "dynamic-import",
            "sourceDirective": directives.get(row["source"], {}).get("directive"),
            "targetDirective": directives.get(target or "", {}).get("directive"),
        }
        relation["crossesDirectiveBoundary"] = bool(relation["sourceDirective"] and relation["targetDirective"] and relation["sourceDirective"] != relation["targetDirective"])
        relations.append(relation)
    adjacency: dict[str, set[str]] = {}
    for relation in relations:
        if relation["kind"] == "module-edge" and relation.get("targetModule"):
            adjacency.setdefault(str(relation["sourceModule"]), set()).add(str(relation["targetModule"]))

    def reachable(start: str) -> set[str]:
        result = {start}
        frontier = [start]
        while frontier and len(result) <= 5000:
            current = frontier.pop()
            for target in adjacency.get(current, set()):
                if target not in result:
                    result.add(target)
                    frontier.append(target)
        return result
    source_routes = [row for row in facts if row["kind"] == "source-route"]
    manifest_routes = [row for row in facts if row["kind"] == "manifest-route"]
    for source_route in source_routes:
        for manifest_route in manifest_routes:
            if source_route.get("route") != manifest_route.get("route"):
                continue
            handler_facts = [row["id"] for row in by_source.get(str(source_route.get("source")), []) if row["kind"] == "http-handler"]
            relations.append({
                "id": stable_id("FR", "route-source-manifest", source_route["id"], manifest_route["id"]),
                "kind": "route-source-manifest",
                "route": source_route.get("route"),
                "sourceRouteFact": source_route["id"],
                "manifestRouteFact": manifest_route["id"],
                "handlerFacts": handler_facts,
                "bundle": manifest_route.get("bundle"),
            })
    routes = [*source_routes, *manifest_routes]
    middleware = [row for row in facts if row["kind"] == "middleware-entry"]
    middleware_auth = [
        row["id"] for row in facts
        if row["kind"] == "authentication-signal"
        and Path(str(row.get("source") or "")).stem in {"middleware", "proxy"}
    ]
    for route in routes:
        path = concrete_route(str(route.get("route") or "/"))
        source_peer = route if route["kind"] == "source-route" else next(
            (candidate for candidate in source_routes if candidate.get("route") == route.get("route")),
            route,
        )
        route_source = str(source_peer.get("source") or "")
        reachable_sources = reachable(route_source) if route_source else set()
        dependency_facts = [
            row for row in facts
            if row.get("source") in reachable_sources
            and row["kind"] in {"authentication-signal", "cache-operation", "environment-read", "dynamic-import", "call-operation"}
        ]
        if dependency_facts:
            relations.append({
                "id": stable_id("FR", "route-runtime-dependencies", route["id"], [row["id"] for row in dependency_facts]),
                "kind": "route-runtime-dependencies",
                "routeFact": route["id"],
                "route": route.get("route"),
                "sourceModule": route_source,
                "reachableModules": sorted(reachable_sources),
                "authenticationFacts": [row["id"] for row in dependency_facts if row["kind"] == "authentication-signal"],
                "cacheFacts": [row["id"] for row in dependency_facts if row["kind"] == "cache-operation"],
                "environmentFacts": [row["id"] for row in dependency_facts if row["kind"] == "environment-read"],
                "dynamicImportFacts": [row["id"] for row in dependency_facts if row["kind"] == "dynamic-import"],
                "operationFacts": [row["id"] for row in dependency_facts if row["kind"] == "call-operation"],
                "reachabilityStatus": "source-module-graph-only-runtime-verification-required",
            })
        cache_facts = [
            row for row in dependency_facts
            if row["kind"] == "cache-operation" and row.get("operation") not in {"revalidatePath", "revalidateTag", "updateTag", "refresh"}
        ]
        revalidation_facts = [
            row for row in dependency_facts
            if row["kind"] == "cache-operation" and row.get("operation") in {"revalidatePath", "revalidateTag", "updateTag", "refresh"}
        ]
        if cache_facts or revalidation_facts:
            relations.append({
                "id": stable_id("FR", "cache-revalidation-path", route["id"], [row["id"] for row in cache_facts], [row["id"] for row in revalidation_facts]),
                "kind": "cache-revalidation-path",
                "routeFact": route["id"],
                "route": route.get("route"),
                "sourceModule": route_source,
                "cacheFacts": [row["id"] for row in cache_facts],
                "revalidationFacts": [row["id"] for row in revalidation_facts],
                "runtimeKeyMappingRequired": True,
            })
        matches: list[str] = []
        indeterminate: list[str] = []
        for entry in middleware:
            regexps = entry.get("regexps") if isinstance(entry.get("regexps"), list) else []
            for regex in regexps:
                outcome = route_matches(str(regex), path)
                if outcome is True:
                    matches.append(entry["id"])
                elif outcome is None:
                    indeterminate.append(entry["id"])
        relations.append({
            "id": stable_id("FR", "middleware-route", route["id"], matches, indeterminate),
            "kind": "middleware-route",
            "routeFact": route["id"],
            "route": route.get("route"),
            "concretePath": path,
            "matchedMiddleware": sorted(set(matches)),
            "indeterminateMiddleware": sorted(set(indeterminate)),
            "handlerAuthSignals": [row["id"] for row in dependency_facts if row["kind"] == "authentication-signal"],
            "middlewareAuthSignals": middleware_auth,
            "operationFacts": [row["id"] for row in dependency_facts if row["kind"] == "call-operation"],
            "dominanceStatus": "runtime-verification-required",
        })
    return relations


def make_hypothesis(kind: str, title: str, fact_ids: list[str], experiment: dict[str, Any]) -> dict[str, Any]:
    identity = stable_id("FH", kind, sorted(set(fact_ids)), experiment)
    return {
        "id": identity,
        "classification": "runtime-hypothesis",
        "kind": kind,
        "title": title,
        "evidenceFacts": sorted(set(fact_ids)),
        "runtimeExperiment": experiment,
        "state": "not-executed",
        "conclusion": "none-until-runtime-discriminator",
    }


def build_hypotheses(facts: list[dict[str, Any]], relations: list[dict[str, Any]], maximum: int) -> list[dict[str, Any]]:
    by_id = {row["id"]: row for row in facts}
    hypotheses: list[dict[str, Any]] = []
    for relation in relations:
        if relation["kind"] == "middleware-route":
            route = str(relation.get("route") or "/")
            route_fact = by_id.get(str(relation.get("routeFact")), {})
            evidence = [
                str(relation.get("routeFact")),
                *relation.get("matchedMiddleware", []),
                *relation.get("indeterminateMiddleware", []),
                *relation.get("handlerAuthSignals", []),
                *relation.get("middlewareAuthSignals", []),
            ]
            hypotheses.append(make_hypothesis(
                "middleware-handler-order",
                f"Measure middleware and handler ordering for {route}",
                evidence,
                {
                    "entrypoint": relation["concretePath"],
                    "productionSurfaces": ["middleware", "route-handlers"],
                    "steps": [
                        {"actor": "unauthenticated-control", "request": {"method": "GET", "path": relation["concretePath"]}},
                        {"actor": "owned-authenticated-control", "request": {"method": "GET", "path": relation["concretePath"]}},
                    ],
                    "measure": ["middleware coverage", "handler coverage", "status", "location", "set-cookie", "response hash"],
                    "discriminator": "Record whether the production middleware executes before the selected handler in both controls; do not infer authorization from source markers.",
                },
            ))
        if relation["kind"] == "module-edge" and relation.get("crossesDirectiveBoundary"):
            hypotheses.append(make_hypothesis(
                "directive-boundary",
                f"Resolve the shipped boundary from {relation['sourceModule']} to {relation['targetModule']}",
                [str(relation["sourceFact"])],
                {
                    "productionSurfaces": ["client-server-boundary", "browser-bundle", "server-rendering"],
                    "steps": [
                        {"action": "build through framework adapter and locate both modules in emitted server/client artifacts"},
                        {"action": "invoke the importing entrypoint and retain server plus browser coverage"},
                        {"action": "repeat with a non-crossing sibling import as the control"},
                    ],
                    "measure": ["selected bundle", "module identity", "serialization boundary", "runtime side"],
                    "discriminator": "Compare the emitted and executed runtime identity for the crossing and control imports.",
                },
            ))
        if relation["kind"] == "cache-revalidation-path":
            route = concrete_route(str(relation.get("route") or "/"))
            hypotheses.append(make_hypothesis(
                "cache-revalidation-isolation",
                f"Measure cache-key and revalidation isolation for {relation.get('route')}",
                [str(relation["routeFact"]), *relation.get("cacheFacts", []), *relation.get("revalidationFacts", [])],
                {
                    "entrypoint": route,
                    "productionSurfaces": ["cache", "revalidation", "route-handlers"],
                    "steps": [
                        {"actor": "owned-primer-A", "request": {"method": "GET", "path": route}, "semanticInput": "A"},
                        {"actor": "owned-primer-B", "request": {"method": "GET", "path": route}, "semanticInput": "B"},
                        {"actor": "owned-revalidator", "action": "invoke the mapped revalidation operation for A"},
                        {"actor": "independent-observer", "action": "read A and B after revalidation"},
                    ],
                    "measure": ["runtime cache-key components", "response hashes", "cache status", "revalidation coverage"],
                    "discriminator": "Determine from runtime evidence whether the keys and invalidation targets for A and B remain distinct; source call adjacency is not proof.",
                },
            ))
        if len(hypotheses) >= maximum:
            break
    for row in facts:
        if row["kind"] == "http-handler" and row.get("route"):
            route = concrete_route(str(row["route"]))
            method = str(row.get("method") or "GET")
            source_auth = [
                candidate["id"] for candidate in facts
                if candidate["kind"] == "authentication-signal" and candidate.get("source") == row.get("source")
            ]
            hypotheses.append(make_hypothesis(
                "route-runtime-alignment",
                f"Verify {method} {row['route']} reaches its declared handler",
                [row["id"]],
                {
                    "entrypoint": route,
                    "productionSurfaces": ["raw-http", "route-handlers"],
                    "steps": [
                        {"actor": "baseline", "request": {"method": method, "path": route}},
                        {"actor": "negative-sibling", "request": {"method": method, "path": route + "-krineon-miss"}},
                    ],
                    "measure": ["raw response", "handler coverage", "loaded module"],
                    "discriminator": "The baseline must execute the declared handler while the negative sibling must not.",
                },
            ))
            if source_auth:
                hypotheses.append(make_hypothesis(
                    "middleware-handler-order",
                    f"Measure authentication and handler order for {method} {row['route']}",
                    [row["id"], *source_auth],
                    {
                        "entrypoint": route,
                        "productionSurfaces": ["raw-http", "route-handlers"],
                        "steps": [
                            {"actor": "unauthenticated-control", "request": {"method": method, "path": route}},
                            {"actor": "owned-authenticated-control", "request": {"method": method, "path": route}},
                        ],
                        "measure": ["authentication-call coverage", "handler side-effect coverage", "status", "response hash"],
                        "discriminator": "Measure whether the authentication call dominates handler effects in the production artifact; the source call name alone proves nothing.",
                    },
                ))
        elif row["kind"] == "manifest-route":
            route = concrete_route(str(row.get("route") or "/"))
            hypotheses.append(make_hypothesis(
                "route-runtime-alignment",
                f"Verify manifest route {row.get('route')} reaches its emitted artifact",
                [row["id"]],
                {
                    "entrypoint": route,
                    "productionSurfaces": ["app-router", "pages-router", "route-handlers"],
                    "steps": [{"actor": "baseline", "request": {"method": "GET", "path": route}}, {"actor": "negative-sibling", "request": {"method": "GET", "path": route + "-krineon-miss"}}],
                    "measure": ["raw response", "executed bundle coverage", "manifest identity"],
                    "discriminator": "The baseline must execute the manifest-selected bundle while the negative sibling must not.",
                },
            ))
        elif row["kind"] == "dynamic-import":
            hypotheses.append(make_hypothesis(
                "dynamic-module-identity",
                f"Measure production module identity for {row.get('specifier')}",
                [row["id"]],
                {
                    "productionSurfaces": ["node-runtime", "edge-runtime", "browser-bundle"],
                    "steps": [
                        {"action": "invoke the containing production entrypoint with a baseline that reaches this import"},
                        {"action": "repeat with a semantics-preserving specifier representation when the entrypoint accepts one"},
                    ],
                    "measure": ["resolved module URL", "manifest ID", "loaded chunk", "source-mapped coverage"],
                    "discriminator": "Retain a differential only if equivalent representations select different shipped module identities or runtime sides.",
                },
            ))
        elif row["kind"] == "cache-operation":
            hypotheses.append(make_hypothesis(
                "cache-revalidation-isolation",
                f"Measure key and revalidation behavior at {row['source']}:{row['line']}",
                [row["id"]],
                {
                    "productionSurfaces": ["cache", "revalidation"],
                    "steps": [
                        {"actor": "owned-primer-A", "action": "invoke with semantic input A"},
                        {"actor": "owned-primer-B", "action": "invoke with different semantic input B"},
                        {"actor": "independent-observer", "action": "read A and B before and after the mapped revalidation operation"},
                    ],
                    "measure": ["cache key", "response hash", "cache status", "revalidation target", "runtime coverage"],
                    "discriminator": "Record whether A and B remain isolated across prime, read, and revalidation; no cache-security conclusion follows from the call name alone.",
                },
            ))
        elif row["kind"] == "environment-read":
            hypotheses.append(make_hypothesis(
                "environment-runtime-branch",
                f"Compare production behavior across {row.get('variable')} states",
                [row["id"]],
                {
                    "productionSurfaces": ["node-runtime", "edge-runtime"],
                    "steps": [
                        {"environment": {str(row.get("variable")): "<unset>"}, "action": "build and exercise the same retained request"},
                        {"environment": {str(row.get("variable")): "krineon-control"}, "action": "build and exercise the same retained request"},
                    ],
                    "measure": ["deployment artifact hashes", "selected route", "loaded module", "response hash", "coverage"],
                    "discriminator": "Attribute any difference to the exact emitted artifacts and branch coverage before creating a security claim.",
                },
            ))
        if len(hypotheses) >= maximum:
            break
    unique = {row["id"]: row for row in hypotheses}
    return list(unique.values())[:maximum]


def schedule_hypotheses(campaign: Path, hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not (campaign / "orchestration.db").is_file():
        raise RuntimeError("--ingest requires an initialized orchestration.db")
    scheduled: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        task_id = "framework-" + hypothesis["id"].split("-", 1)[-1]
        family = APPROACH_FAMILY.get(hypothesis["kind"], "stock-reachability")
        command = [
            sys.executable, str(RESEARCH_HARNESS), "task-add", str(campaign), task_id,
            "--title", hypothesis["title"],
            "--lane", "framework-runtime-hypothesis",
            "--objective", f"Execute hypothesis {hypothesis['id']} against the pinned production adapter artifact. Retain raw controls and the measured discriminator; a source fact is not a vulnerability verdict.",
            "--approach-family", family,
            "--success-criterion", "A production adapter and protocol/browser replay records the stated discriminator and its negative control with source-mapped runtime coverage.",
            "--priority", "520",
            "--max-attempts", "2",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
        if completed.returncode != 0 and "already" not in completed.stderr.lower():
            raise RuntimeError(f"failed to schedule {task_id}: {completed.stderr.strip()}")
        scheduled.append({"hypothesis": hypothesis["id"], "taskId": task_id, "idempotentExisting": completed.returncode != 0})
    return scheduled


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ingest", action="store_true", help="schedule runtime-validation tasks")
    args = parser.parse_args(argv)
    try:
        campaign_root = args.campaign.expanduser().resolve()
        campaign = campaign_value(campaign_root)
        spec_path = args.spec.expanduser().resolve()
        spec = read_json(spec_path)
        if spec.get("schemaVersion") != 1 or spec.get("framework") not in {"nextjs", "react", "node"}:
            raise RuntimeError("analysis spec requires schemaVersion 1 and framework nextjs, react, or node")
        root = project_path(spec_path, str(spec["projectRoot"]))
        output = args.output.expanduser().resolve()
        output.relative_to(campaign_root)
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("analysis output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        framework = str(spec["framework"])
        patterns = default_patterns(framework)
        pattern_fields = {
            "source": "sourceGlobs",
            "generated": "generatedGlobs",
            "vendored": "vendoredGlobs",
            "manifests": "manifestGlobs",
            "sourceMaps": "sourceMapGlobs",
        }
        for key, field in pattern_fields.items():
            if isinstance(spec.get(field), list):
                patterns[key] = list(map(str, spec[field]))
        limits = {
            "source": int(spec.get("maxSourceFiles", 5000)),
            "generated": int(spec.get("maxGeneratedFiles", 3000)),
            "vendored": int(spec.get("maxVendoredFiles", 2000)),
            "manifests": int(spec.get("maxManifestFiles", 1000)),
            "sourceMaps": int(spec.get("maxSourceMapFiles", 3000)),
        }
        selected: dict[str, list[Path]] = {}
        omitted: dict[str, int] = {}
        for key, globs in patterns.items():
            selected[key], omitted[key] = expand_patterns(root, globs, limits[key])
        adapter_record = None
        adapter_path: Path | None = None
        if spec.get("adapterRecord"):
            adapter_path = Path(str(spec["adapterRecord"])).expanduser()
            if not adapter_path.is_absolute():
                adapter_path = spec_path.parent / adapter_path
            adapter_path = adapter_path.resolve()
            adapter_record = read_json(adapter_path)
            if adapter_record.get("producer") != "krineon-framework-adapter" or adapter_record.get("status") != "passed":
                raise RuntimeError("adapterRecord is not a passed Krineon framework adapter run")
            if Path(str(adapter_record.get("projectRoot"))).resolve() != root or adapter_record.get("framework") != framework:
                raise RuntimeError("adapterRecord project/framework does not match analysis spec")
        auth_signals = set(map(str, spec.get("authSignals", DEFAULT_AUTH_SIGNALS)))
        cache_signals = set(map(str, spec.get("cacheSignals", DEFAULT_CACHE_SIGNALS)))
        maximum_bytes = int(spec.get("maxParsedFileBytes", 4 * 1024 * 1024))
        facts: list[dict[str, Any]] = []
        inventories: list[dict[str, Any]] = []
        for classification in ("source", "generated", "vendored"):
            for path in selected[classification]:
                if path.suffix not in SOURCE_EXTENSIONS:
                    continue
                rows, inventory = scan_javascript(path, root, classification, auth_signals, cache_signals, maximum_bytes)
                facts.extend(rows)
                inventories.extend(inventory)
                if classification == "source":
                    route = route_from_source(path.relative_to(root).as_posix())
                    if route is not None:
                        facts.append(fact(path, root, "source-route", None, {"route": route, "entryKind": Path(path).stem, "classification": classification}))
        for path in selected["manifests"]:
            facts.extend(manifest_facts(path, root))
        facts = list({row["id"]: row for row in facts}.values())
        facts.sort(key=lambda row: (row["kind"], row.get("source", ""), row.get("line", 0), row["id"]))
        relations = build_relations(root, facts)
        source_relations, map_records = source_map_relations(
            selected["sourceMaps"], root, facts, int(spec.get("maxSourceBundleRelations", 20000))
        )
        relations.extend(source_relations)
        hypotheses = build_hypotheses(facts, relations, int(spec.get("maxHypotheses", 500)))
        scheduled = schedule_hypotheses(campaign_root, hypotheses) if args.ingest else []
        fact_counts: dict[str, int] = {}
        for row in facts:
            fact_counts[row["kind"]] = fact_counts.get(row["kind"], 0) + 1
        relation_counts: dict[str, int] = {}
        for row in relations:
            relation_counts[row["kind"]] = relation_counts.get(row["kind"], 0) + 1
        run = {
            "schemaVersion": 1,
            "producer": "krineon-framework-analysis",
            "runId": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8],
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "framework": framework,
            "campaignCommit": campaign.get("commit"),
            "projectRoot": str(root),
            "spec": artifact(spec_path),
            "analyzer": artifact(Path(__file__).resolve()),
            "adapterRecord": artifact(adapter_path) if adapter_path else None,
            "analysisContract": {
                "outputClass": "runtime-hypotheses",
                "vulnerabilityVerdictsProduced": False,
                "sourceMarkersProveDominance": False,
                "runtimeValidationRequired": True,
                "patchedVersionComparisonUsed": False,
                "gitHistoryUsed": False,
            },
            "parser": {
                "kind": "structural-javascript-tokenizer",
                "commentsExcluded": True,
                "regularExpressionBodiesExcluded": True,
                "nameSignalsCreateFactsNotConclusions": True,
            },
            "selection": {key: {"selected": len(value), "omittedByLimit": omitted[key], "patterns": patterns[key]} for key, value in selected.items()},
            "runtimeFiles": inventories,
            "sourceMaps": map_records,
            "facts": facts,
            "factCounts": fact_counts,
            "relations": relations,
            "relationCounts": relation_counts,
            "hypotheses": hypotheses,
            "scheduledTasks": scheduled,
            "status": "passed",
        }
        run_path = output / "framework-analysis.json"
        write_json(run_path, run)
        campaign_runs = campaign.get("frameworkAnalysisRuns")
        if not isinstance(campaign_runs, list):
            campaign_runs = []
        campaign_runs.append({"framework": framework, "path": run_path.relative_to(campaign_root).as_posix(), "sha256": sha256_file(run_path), "hypotheses": len(hypotheses)})
        campaign["frameworkAnalysisRuns"] = campaign_runs
        write_json(campaign_root / "campaign.json", campaign)
        print(run_path)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
