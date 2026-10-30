#!/usr/bin/env python3
"""Generate semantic-equivalent framework inputs across concrete representations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Callable


KINDS = ("json", "url", "headers", "multipart", "rsc", "server-action", "manifest")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def reverse_objects(value: Any, reverse: bool) -> Any:
    if isinstance(value, dict):
        keys = list(value)
        if reverse:
            keys.reverse()
        return {key: reverse_objects(value[key], reverse) for key in keys}
    if isinstance(value, list):
        return [reverse_objects(item, reverse) for item in value]
    return value


def json_variant(model: Any, index: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    style = index % 4
    reordered = reverse_objects(model, style in {1, 3})
    if style == 0:
        text = json.dumps(reordered, separators=(",", ":"), ensure_ascii=False)
        label = "compact-utf8"
    elif style == 1:
        text = json.dumps(reordered, indent=2, ensure_ascii=False)
        label = "pretty-reversed-keys"
    elif style == 2:
        text = json.dumps(reordered, separators=(", ", ": "), ensure_ascii=True)
        label = "ascii-escaped"
    else:
        indent = rng.choice([1, 3, 4])
        text = json.dumps(reordered, indent=indent, ensure_ascii=True)
        label = f"ascii-reversed-indent-{indent}"
    trailing = (" " * (index // 4)) + ("\n" if index % 2 else "")
    return (text + trailing).encode("utf-8"), {"representation": label, "contentType": "application/json"}


def normalize_url_model(model: dict[str, Any]) -> dict[str, Any]:
    return {
        "scheme": str(model.get("scheme") or "https").lower(),
        "host": str(model["host"]).lower(),
        "port": int(model["port"]) if model.get("port") is not None else None,
        "pathSegments": [str(value) for value in model.get("pathSegments", [])],
        "query": [[str(pair[0]), str(pair[1])] for pair in model.get("query", [])],
        "fragment": str(model.get("fragment") or ""),
    }


def percent_case(value: str, upper: bool) -> str:
    return re_percent(value, lambda token: token.upper() if upper else token.lower())


def re_percent(value: str, transform: Callable[[str], str]) -> str:
    output = []
    index = 0
    while index < len(value):
        if value[index] == "%" and index + 2 < len(value):
            output.append("%" + transform(value[index + 1:index + 3]))
            index += 3
        else:
            output.append(value[index])
            index += 1
    return "".join(output)


def encode_unreserved(value: str, toggle: bool) -> str:
    output = []
    for character in value:
        if toggle and character.isalnum() and ord(character) < 128:
            output.append(f"%{ord(character):02X}")
        else:
            output.append(urllib.parse.quote(character, safe="-._~"))
    return "".join(output)


def url_variant(model: dict[str, Any], index: int, _rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    normalized = normalize_url_model(model)
    authority = "".join(
        character.upper() if character.isalpha() and (index >> (position % 16)) & 1 else character
        for position, character in enumerate(normalized["host"])
    )
    if normalized["port"] is not None:
        authority += f":{normalized['port']}"
    encoded_segments = [encode_unreserved(value, index % 3 == 2) for value in normalized["pathSegments"]]
    path = "/" + "/".join(encoded_segments)
    query = urllib.parse.urlencode(
        [(pair[0], pair[1]) for pair in normalized["query"]],
        doseq=False,
        quote_via=urllib.parse.quote,
    )
    fragment = urllib.parse.quote(normalized["fragment"], safe="-._~")
    url = urllib.parse.urlunsplit((normalized["scheme"], authority, path, query, fragment))
    url = percent_case(url, index % 2 == 0)
    return url.encode("ascii"), {"representation": f"url-percent-style-{index % 3}", "contentType": "text/uri-list"}


def normalize_headers(model: Any) -> list[list[str]]:
    if not isinstance(model, list):
        raise RuntimeError("headers model must be an ordered list")
    return [[str(pair[0]).lower(), str(pair[1]).strip()] for pair in model]


def header_name(name: str, style: int) -> str:
    if style == 0:
        return name.lower()
    if style == 1:
        return "-".join(part.capitalize() for part in name.split("-"))
    return name.upper()


def headers_variant(model: Any, index: int, _rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    normalized = normalize_headers(model)
    whitespace = (" " * (1 + index // 3)) if index % 3 != 2 else ("\t" * (1 + index // 3))
    lines = [f"{header_name(name, index % 3)}:{whitespace}{value}" for name, value in normalized]
    return ("\r\n".join(lines) + "\r\n").encode("latin-1"), {"representation": f"header-case-ows-{index % 3}", "contentType": "message/http-headers"}


def part_body(part: dict[str, Any]) -> bytes:
    if "bodyBase64" in part:
        return base64.b64decode(str(part["bodyBase64"]), validate=True)
    return str(part.get("bodyText") or "").encode("utf-8")


def normalize_multipart(model: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for part in model.get("parts", []):
        headers = normalize_headers(part.get("headers", []))
        body = part_body(part)
        result.append({"headers": headers, "bodySha256": sha256(body), "bodyBase64": base64.b64encode(body).decode()})
    return result


def render_multipart(parts: list[dict[str, Any]], boundary: str, style: int) -> bytes:
    output = bytearray()
    for part in parts:
        output.extend(f"--{boundary}\r\n".encode())
        for name, value in part["headers"]:
            output.extend(f"{header_name(name, style)}: {value}\r\n".encode("latin-1"))
        output.extend(b"\r\n" + base64.b64decode(part["bodyBase64"]) + b"\r\n")
    output.extend(f"--{boundary}--\r\n".encode())
    return bytes(output)


def multipart_variant(model: dict[str, Any], index: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    parts = normalize_multipart(model)
    boundary = f"krineon-{index:04x}-{rng.getrandbits(32):08x}"
    body = render_multipart(parts, boundary, index % 3)
    return body, {"representation": f"multipart-boundary-{index}", "contentType": f"multipart/form-data; boundary={boundary}"}


def normalize_rsc(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in model.get("rows", []):
        rows.append({"id": int(row["id"]), "tag": str(row.get("tag") or ""), "payload": row.get("payload")})
    return rows


def rsc_variant(model: dict[str, Any], index: int, _rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    rows = normalize_rsc(model)
    output = bytearray()
    for row in rows:
        identifier = ("0" * (index // 4)) + format(row["id"], "X" if index % 2 else "x")
        payload = row["payload"]
        if isinstance(payload, (dict, list)):
            payload_text = json.dumps(
                reverse_objects(payload, index % 2 == 1),
                separators=(",", ":") if index % 3 == 0 else (", ", ": "),
                ensure_ascii=index % 3 == 2,
            )
        else:
            payload_text = str(payload)
        output.extend(f"{identifier}:{row['tag']}{payload_text}\n".encode("utf-8"))
    return bytes(output), {"representation": f"flight-row-json-style-{index % 4}", "contentType": "text/x-component"}


def normalize_fields(model: dict[str, Any]) -> list[list[str]]:
    fields = model.get("fields")
    if not isinstance(fields, list):
        raise RuntimeError("server-action model requires ordered fields")
    return [[str(pair[0]), str(pair[1])] for pair in fields]


def server_action_variant(model: dict[str, Any], index: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    fields = normalize_fields(model)
    if index % 2 == 0:
        body = urllib.parse.urlencode(
            [(pair[0], pair[1]) for pair in fields],
            doseq=False,
            quote_via=urllib.parse.quote,
        ).encode()
        content_type = "application/x-www-form-urlencoded"
        label = "urlencoded"
    else:
        parts = [
            {
                "headers": [["content-disposition", f"form-data; name=\"{name}\""]],
                "bodySha256": sha256(value.encode()),
                "bodyBase64": base64.b64encode(value.encode()).decode(),
            }
            for name, value in fields
        ]
        boundary = f"action-{index:04x}-{rng.getrandbits(32):08x}"
        body = render_multipart(parts, boundary, index % 3)
        content_type = f"multipart/form-data; boundary={boundary}"
        label = "multipart"
    envelope = canonical({"contentType": content_type, "bodyBase64": base64.b64encode(body).decode()})
    return envelope, {"representation": label, "contentType": "application/vnd.krineon.http-body+json", "innerContentType": content_type}


def semantic_model(kind: str, model: Any) -> Any:
    if kind in {"json", "manifest"}:
        return model
    if kind == "url":
        return normalize_url_model(model)
    if kind == "headers":
        return normalize_headers(model)
    if kind == "multipart":
        return normalize_multipart(model)
    if kind == "rsc":
        return normalize_rsc(model)
    if kind == "server-action":
        return normalize_fields(model)
    raise RuntimeError(f"unsupported kind: {kind}")


def parse_header_block(value: bytes) -> list[list[str]]:
    result: list[list[str]] = []
    for line in value.split(b"\r\n"):
        if not line:
            continue
        if b":" not in line:
            raise RuntimeError("generated header line has no colon")
        name, content = line.split(b":", 1)
        result.append([name.decode("latin-1").lower(), content.decode("latin-1").strip()])
    return result


def parse_multipart(value: bytes, content_type: str) -> list[dict[str, Any]]:
    match = next(
        (
            item.split("=", 1)[1].strip().strip('"')
            for item in content_type.split(";")[1:]
            if item.strip().lower().startswith("boundary=")
        ),
        None,
    )
    if not match:
        raise RuntimeError("generated multipart content type has no boundary")
    delimiter = b"--" + match.encode("ascii")
    result: list[dict[str, Any]] = []
    for segment in value.split(delimiter)[1:]:
        if segment.startswith(b"--"):
            break
        if segment.startswith(b"\r\n"):
            segment = segment[2:]
        if not segment:
            continue
        head, separator, body = segment.partition(b"\r\n\r\n")
        if not separator or not body.endswith(b"\r\n"):
            raise RuntimeError("generated multipart part is malformed")
        body = body[:-2]
        headers = parse_header_block(head + b"\r\n")
        result.append(
            {
                "headers": headers,
                "bodySha256": sha256(body),
                "bodyBase64": base64.b64encode(body).decode(),
            }
        )
    return result


def decode_semantic(kind: str, value: bytes, metadata: dict[str, Any], model: Any) -> Any:
    if kind in {"json", "manifest"}:
        return json.loads(value)
    if kind == "url":
        parsed = urllib.parse.urlsplit(value.decode("ascii"))
        return {
            "scheme": parsed.scheme.lower(),
            "host": str(parsed.hostname or "").lower(),
            "port": parsed.port,
            "pathSegments": (
                []
                if parsed.path in {"", "/"}
                else [urllib.parse.unquote(part) for part in parsed.path.split("/")[1:]]
            ),
            "query": [[name, content] for name, content in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)],
            "fragment": urllib.parse.unquote(parsed.fragment),
        }
    if kind == "headers":
        return parse_header_block(value)
    if kind == "multipart":
        return parse_multipart(value, str(metadata["contentType"]))
    if kind == "rsc":
        expected = normalize_rsc(model)
        rows = []
        lines = value.decode("utf-8").splitlines()
        if len(lines) != len(expected):
            raise RuntimeError("generated RSC row count changed")
        for line, expected_row in zip(lines, expected, strict=True):
            identifier, remainder = line.split(":", 1)
            tag = str(expected_row["tag"])
            if not remainder.startswith(tag):
                raise RuntimeError("generated RSC row tag changed")
            payload_text = remainder[len(tag):]
            payload = json.loads(payload_text) if isinstance(expected_row["payload"], (dict, list)) else payload_text
            rows.append({"id": int(identifier, 16), "tag": tag, "payload": payload})
        return rows
    if kind == "server-action":
        envelope = json.loads(value)
        content_type = str(envelope["contentType"])
        body = base64.b64decode(str(envelope["bodyBase64"]), validate=True)
        if content_type == "application/x-www-form-urlencoded":
            return [[name, content] for name, content in urllib.parse.parse_qsl(body.decode(), keep_blank_values=True)]
        parts = parse_multipart(body, content_type)
        fields: list[list[str]] = []
        for part in parts:
            disposition = next(
                content
                for name, content in part["headers"]
                if name == "content-disposition"
            )
            name_match = next(
                (item.split("=", 1)[1].strip().strip('"') for item in disposition.split(";")[1:] if item.strip().startswith("name=")),
                None,
            )
            if name_match is None:
                raise RuntimeError("generated Server Action part has no name")
            fields.append([name_match, base64.b64decode(part["bodyBase64"]).decode()])
        return fields
    raise RuntimeError(f"unsupported kind: {kind}")


def generate(kind: str, model: Any, index: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    if kind in {"json", "manifest"}:
        return json_variant(model, index, rng)
    if kind == "url":
        return url_variant(model, index, rng)
    if kind == "headers":
        return headers_variant(model, index, rng)
    if kind == "multipart":
        return multipart_variant(model, index, rng)
    if kind == "rsc":
        return rsc_variant(model, index, rng)
    if kind == "server-action":
        return server_action_variant(model, index, rng)
    raise RuntimeError(f"unsupported kind: {kind}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    try:
        spec_path = args.spec.expanduser().resolve()
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or spec.get("schemaVersion") != 1:
            raise RuntimeError("generator spec must be a schemaVersion 1 object")
        kind = str(spec.get("kind") or "")
        if kind not in KINDS:
            raise RuntimeError(f"kind must be one of: {', '.join(KINDS)}")
        if args.count < 1 or args.count > 100000:
            raise RuntimeError("--count must be between 1 and 100000")
        output = args.output.expanduser().resolve()
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        model = spec.get("model")
        semantic = semantic_model(kind, model)
        semantic_hash = sha256(canonical(semantic))
        rng = random.Random(args.seed)
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        attempts = 0
        while len(records) < args.count and attempts < args.count * 20:
            body, metadata = generate(kind, model, attempts, rng)
            attempts += 1
            observed_semantic = decode_semantic(kind, body, metadata, model)
            if canonical(observed_semantic) != canonical(semantic):
                raise RuntimeError(
                    f"generated {kind} representation does not round-trip to its semantic model"
                )
            digest = sha256(body)
            if digest in seen:
                continue
            seen.add(digest)
            suffix = ".json" if kind in {"json", "manifest", "server-action"} else ".bin"
            path = output / f"{len(records):08d}-{digest[:12]}{suffix}"
            path.write_bytes(body)
            records.append({
                "path": path.name,
                "sha256": digest,
                "size": len(body),
                "semanticGroupSha256": semantic_hash,
                "semanticRoundTripVerified": True,
                **metadata,
            })
        if len(records) < args.count:
            raise RuntimeError(f"generator produced only {len(records)} unique variants")
        manifest = {
            "schemaVersion": 1,
            "producer": "krineon-structured-input-generator",
            "kind": kind,
            "seed": args.seed,
            "requested": args.count,
            "semanticGroupSha256": semantic_hash,
            "semanticModelSha256": semantic_hash,
            "allSemanticRoundTripsVerified": True,
            "spec": {"path": str(spec_path), "sha256": sha256(spec_path.read_bytes())},
            "outputs": records,
        }
        atomic_json(output / "generation.json", manifest)
        print(output / "generation.json")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
