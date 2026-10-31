#!/usr/bin/env python3
"""Bootstrap a Krineon campaign from source coordinates and optional program intake.

When supplied, intake text is preserved verbatim and used for deterministic
inferences. It is not a prerequisite for source-only analysis and is never
treated as authorization for live testing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_HARNESS = PROJECT_ROOT / "scripts" / "research_harness.py"
TOOL_PROBE = PROJECT_ROOT / "scripts" / "tool_probe.py"

URL_RE = re.compile(r"https?://[^\s<>\[\]{}\"'`]+", re.IGNORECASE)
SCOPE_HEADING_RE = re.compile(
    r"^\s{0,3}(?:#{1,6}\s*)?(?:in[- ]scope(?: assets?| vulnerabilities?)?|scope|eligible assets?|assets? in scope)\s*:?[ \t]*$",
    re.IGNORECASE,
)
OUT_HEADING_RE = re.compile(
    r"^\s{0,3}(?:#{1,6}\s*)?(?:out[- ]of[- ]scope(?: assets?| vulnerabilities?)?|excluded|exclusions?|not eligible)\s*:?[ \t]*$",
    re.IGNORECASE,
)
ANY_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+|^[A-Z][A-Za-z0-9 /&()_-]{2,}:\s*$")
LIST_PREFIX_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|\|)")
V8_RE = re.compile(r"\b(?:chrome|chromium|v8|blink)\b", re.IGNORECASE)


class BootstrapError(Exception):
    """A user-facing intake error."""


def read_input(path_value: str) -> bytes:
    if path_value == "-":
        return sys.stdin.buffer.read()
    path = Path(path_value).expanduser().resolve()
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BootstrapError(f"cannot read program guidelines {path}: {exc}") from exc


def decode_text(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BootstrapError("program guidelines must be UTF-8 text") from exc


def parse_max_concurrency(value: str) -> str | int:
    text = value.strip().lower()
    if text == "auto":
        return "auto"
    try:
        parsed = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "max concurrency must be 'auto' or a positive integer"
        ) from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError(
            "max concurrency must be 'auto' or a positive integer"
        )
    return parsed


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def clean_url(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


def extract_urls(text: str) -> list[str]:
    return unique(clean_url(match.group(0)) for match in URL_RE.finditer(text))


def canonical_repo_url(value: str) -> str | None:
    parsed = urlsplit(value)
    host = parsed.netloc.lower()
    parts = [part for part in parsed.path.split("/") if part]
    if host in {
        "github.com",
        "www.github.com",
        "gitlab.com",
        "www.gitlab.com",
        "codeberg.org",
    }:
        if len(parts) < 2:
            return None
        path = "/" + "/".join(parts[:2])
        if path.endswith(".git"):
            path = path[:-4]
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    if host.endswith(".googlesource.com") and parts:
        return urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(parts), "", ""))
    if value.endswith(".git"):
        return value[:-4]
    return None


def extract_repositories(urls: Iterable[str]) -> list[str]:
    return unique(
        candidate
        for candidate in (canonical_repo_url(value) for value in urls)
        if candidate is not None
    )


def strip_list_prefix(line: str) -> str:
    value = line.strip()
    if value.startswith("|"):
        cells = [cell.strip() for cell in value.strip("|").split("|")]
        return " | ".join(cell for cell in cells if cell and not set(cell) <= {"-", ":"})
    return re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", value).strip()


def extract_sections(text: str) -> tuple[list[str], list[str]]:
    """Extract review candidates without pretending to parse arbitrary policy prose."""

    scope: list[str] = []
    excluded: list[str] = []
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if SCOPE_HEADING_RE.match(line):
            section = "scope"
            continue
        if OUT_HEADING_RE.match(line):
            section = "out"
            continue
        if section and ANY_HEADING_RE.match(line) and not LIST_PREFIX_RE.match(line):
            section = None
            continue
        if not section or not line.strip():
            continue
        if LIST_PREFIX_RE.match(line) or URL_RE.search(line):
            item = strip_list_prefix(line)
            if not item or item.lower() in {"asset", "severity", "eligible", "scope"}:
                continue
            (scope if section == "scope" else excluded).append(item)

    # Scope tables often omit an explicit heading in copied program text. Keep
    # eligible repository and asset lines as candidates, but mark all inferred
    # entries for coordinator review in onboarding.json.
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if URL_RE.search(line) and any(
            token in lowered for token in ("eligible", "source code", "domain", "wildcard")
        ):
            scope.append(strip_list_prefix(line))
    return unique(scope), unique(excluded)


def infer_profile(text: str, repositories: Iterable[str]) -> tuple[str, list[str]]:
    evidence = [value for value in repositories if V8_RE.search(value)]
    if V8_RE.search(text):
        evidence.append("program text contains a Chrome/Chromium/V8/Blink target")
    if evidence:
        return "chrome-v8", unique(evidence)
    return "critical-rce", [
        "no installed target-specific profile matched; using Critical/RCE source analysis"
    ]


def git_output(checkout: Path, *arguments: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        return None
    return completed.stdout.strip() or None


def derive_target(repository: str) -> str:
    parsed = urlsplit(repository)
    if parsed.path:
        return Path(parsed.path.rstrip("/")).name.removesuffix(".git") or parsed.netloc
    return parsed.netloc or "program-target"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BootstrapError(f"expected a JSON object in {path}")
    return data


def run_checked(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if completed.returncode:
        command = " ".join(arguments)
        raise BootstrapError(
            f"command failed ({completed.returncode}): {command}\n{completed.stderr.strip()}"
        )
    return completed


def render_authorization(
    *,
    target: str,
    repository: str,
    commit: str,
    profile: str,
    program_url: str,
    digest: str,
    scope_digest: str,
    confirmed: bool,
    allowed_environment: str,
    scope: list[str],
    excluded: list[str],
    unresolved: list[str],
) -> str:
    scope_lines = (
        "\n".join(f"- {item}" for item in scope)
        or "- No entries inferred; coordinator review required."
    )
    excluded_lines = (
        "\n".join(f"- {item}" for item in excluded)
        or "- No entries inferred; read the retained rules before testing."
    )
    unresolved_lines = "\n".join(f"- {item}" for item in unresolved) or "- None."
    return f"""# Authorization record

- Target: {target}
- Repository or asset: {repository}
- Exact revision: {commit}
- Campaign profile: {profile}
- Program URL: {program_url or 'not recorded'}
{f'- Program-guidelines SHA-256: {digest}' if digest else '- Program-guidelines input: not supplied'}
{f'- Program-scope SHA-256: {scope_digest}' if scope_digest else '- Program-scope input: not supplied separately'}
- Authorization confirmed: {'YES' if confirmed else 'NO'}
- Allowed environment: {allowed_environment}
- Allowed actions: source review and bounded verification in the recorded owned environment
- Prohibited actions: third-party data access, service degradation, persistence,
  uncontrolled code execution, and activity outside the retained program scope
- Stop conditions: stop before live, shared-system, testnet, account, wallet, or
  production interaction unless that exact action and asset are explicitly authorized

## In-scope candidates

{scope_lines}

## Out-of-scope candidates

{excluded_lines}

## Unresolved intake items

{unresolved_lines}

When present, `PROGRAM_GUIDELINES.md` and `PROGRAM_SCOPE.md` are authoritative
retained inputs. This optional summary is not an authorization gate. Resolve
scope uncertainty before any live or shared-system action.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir")
    parser.add_argument(
        "--guidelines",
        help="optional UTF-8 program guidelines/scope file, or - to read standard input",
    )
    parser.add_argument(
        "--scope",
        help="optional separate UTF-8 scope file; preserved independently",
    )
    parser.add_argument("--target")
    parser.add_argument("--repo", help="source repository; inferred from guidelines when unique")
    parser.add_argument("--checkout", help="existing local Git checkout")
    parser.add_argument(
        "--commit", help="exact source revision; derived from --checkout when omitted"
    )
    parser.add_argument("--program-url")
    parser.add_argument(
        "--profile", choices=("auto", "critical-rce", "chrome-v8"), default="auto"
    )
    parser.add_argument("--mode", choices=("source", "local-lab"), default="source")
    parser.add_argument(
        "--clone",
        action="store_true",
        help="clone the inferred public repository into CAMPAIGN_DIR/source",
    )
    parser.add_argument(
        "--confirm-authorization",
        action="store_true",
        help="record researcher confirmation for source/local-owned testing only",
    )
    parser.add_argument(
        "--authorization-record",
        action="store_true",
        help="write optional AUTHORIZATION.md human-readable summary",
    )
    parser.add_argument("--allowed-environment", default="local owned fixture")
    parser.add_argument(
        "--max-concurrency", type=parse_max_concurrency, default="auto"
    )
    parser.add_argument("--no-queue", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        campaign_root = Path(args.campaign_dir).expanduser().resolve()
        if campaign_root.exists() and any(campaign_root.iterdir()):
            raise BootstrapError(f"refusing to initialize non-empty directory: {campaign_root}")

        if not args.guidelines and not args.repo and not args.checkout:
            raise BootstrapError(
                "without --guidelines, provide --repo or --checkout for source analysis"
            )
        payload = read_input(args.guidelines) if args.guidelines else b""
        scope_payload = read_input(args.scope) if args.scope else b""
        text = decode_text(payload) if payload else ""
        if scope_payload:
            text += "\n" + decode_text(scope_payload)
        digest = sha256_bytes(payload) if payload else ""
        scope_digest = sha256_bytes(scope_payload) if scope_payload else ""
        scope, excluded = extract_sections(text)
        urls = extract_urls(text)
        all_repositories = extract_repositories(urls)
        scoped_repositories = extract_repositories(extract_urls("\n".join(scope)))
        repositories = scoped_repositories or all_repositories
        profile_text = "\n".join(scope) if scope else text
        profile_repositories = unique(
            [*(repositories or []), *([args.repo] if args.repo else [])]
        )
        inferred_profile, profile_evidence = infer_profile(
            profile_text, profile_repositories
        )
        profile = inferred_profile if args.profile == "auto" else args.profile

        repository = args.repo or (repositories[0] if len(repositories) == 1 else "")
        checkout = Path(args.checkout).expanduser().resolve() if args.checkout else None
        if checkout is not None and not checkout.is_dir():
            raise BootstrapError(f"local checkout does not exist: {checkout}")
        if checkout is not None and not repository:
            repository = git_output(checkout, "remote", "get-url", "origin") or str(checkout)
        if args.clone and not repository:
            raise BootstrapError("--clone requires --repo or one uniquely inferred repository")

        target = args.target or (derive_target(repository) if repository else "program-target")
        commit = args.commit or (git_output(checkout, "rev-parse", "HEAD") if checkout else None)
        commit = commit or "pending-pin"
        repository = repository or "pending-source-repository"
        program_url = args.program_url or next(
            (
                value
                for value in urls
                if any(
                    host in urlsplit(value).netloc.lower()
                    for host in ("hackerone", "bugcrowd", "yeswehack", "intigriti")
                )
            ),
            "",
        )

        run_checked(
            [
                sys.executable,
                str(RESEARCH_HARNESS),
                "init",
                str(campaign_root),
                "--target",
                target,
                "--repo",
                repository,
                "--commit",
                commit,
                "--profile",
                profile,
                "--mode",
                args.mode,
                *(["--checkout", str(checkout)] if checkout else []),
                *(["--program-url", program_url] if program_url else []),
                *(["--authorization-record"] if args.authorization_record else []),
            ]
        )
        if payload:
            (campaign_root / "PROGRAM_GUIDELINES.md").write_bytes(payload)
        if scope_payload:
            (campaign_root / "PROGRAM_SCOPE.md").write_bytes(scope_payload)

        if args.clone:
            source = campaign_root / "source"
            run_checked(["git", "clone", "--", repository, str(source)])
            checkout = source.resolve()
            commit = args.commit or git_output(checkout, "rev-parse", "HEAD") or "pending-pin"

        unresolved: list[str] = []
        if repository == "pending-source-repository":
            unresolved.append("Identify the exact in-scope source repository or test asset.")
        if commit == "pending-pin":
            unresolved.append(
                "Acquire the source and pin the exact tested revision before dynamic testing."
            )
        if len(repositories) > 1 and not args.repo:
            unresolved.append(
                "Choose the intended repository from the multiple repository URLs in the rules."
            )
        if payload and not scope:
            unresolved.append(
                "Review and transcribe the exact in-scope assets from the retained program rules."
            )
        if payload and not args.confirm_authorization:
            unresolved.append(
                "Confirm authorization after checking the selected asset against the retained rules."
            )

        campaign = read_json(campaign_root / "campaign.json")
        campaign.update(
            {
                "target": target,
                "repository": repository,
                "localCheckout": str(checkout) if checkout else "",
                "commit": commit,
                "programUrl": program_url,
                "scope": scope,
                "outOfScope": excluded,
            }
        )
        campaign["authorization"] = {
            "confirmed": bool(args.confirm_authorization),
            "basis": (
                (
                    f"Researcher confirmed the selected source/local-owned campaign against "
                    f"PROGRAM_GUIDELINES.md (SHA-256 {digest})."
                    if digest
                    else "Researcher confirmed the selected source/local-owned campaign."
                )
                if args.confirm_authorization
                else "Source-only analysis; live and shared-system actions are not authorized."
            ),
            "allowedEnvironment": args.allowed_environment,
            "stopConditions": [
                "stop before live or shared-system testing without asset-specific authorization",
                "stop on third-party data exposure, service degradation, or scope ambiguity",
            ],
        }
        write_json(campaign_root / "campaign.json", campaign)
        if args.authorization_record:
            (campaign_root / "AUTHORIZATION.md").write_text(
                render_authorization(
                    target=target,
                    repository=repository,
                    commit=commit,
                    profile=profile,
                    program_url=program_url,
                    digest=digest,
                    scope_digest=scope_digest,
                    confirmed=bool(args.confirm_authorization),
                    allowed_environment=args.allowed_environment,
                    scope=scope,
                    excluded=excluded,
                    unresolved=unresolved,
                ),
                encoding="utf-8",
            )

        onboarding = {
            "schemaVersion": 1,
            "guidelines": (
                {
                    "path": "PROGRAM_GUIDELINES.md",
                    "sha256": digest,
                    "bytes": len(payload),
                }
                if payload
                else None
            ),
            "scopeInput": (
                {
                    "path": "PROGRAM_SCOPE.md",
                    "sha256": scope_digest,
                    "bytes": len(scope_payload),
                }
                if scope_payload
                else None
            ),
            "inference": {
                "urls": urls,
                "repositoryCandidates": repositories,
                "allRepositoryCandidates": all_repositories,
                "scopeCandidates": scope,
                "outOfScopeCandidates": excluded,
                "profile": inferred_profile,
                "profileEvidence": profile_evidence,
                "requiresHumanReview": bool(payload or scope_payload),
            },
            "resolved": {
                "target": target,
                "repository": repository,
                "checkout": str(checkout) if checkout else "",
                "commit": commit,
                "profile": profile,
                "mode": args.mode,
                "programUrl": program_url,
                "authorizationConfirmed": bool(args.confirm_authorization),
                "authorizationRecord": (
                    "AUTHORIZATION.md" if args.authorization_record else None
                ),
            },
            "unresolved": unresolved,
            "safety": {
                "liveTestingInferred": False,
                "note": (
                    "Public program text is not treated as authority outside its explicit "
                    "assets and actions."
                ),
            },
        }
        write_json(campaign_root / "onboarding.json", onboarding)

        run_checked(
            [
                sys.executable,
                str(RESEARCH_HARNESS),
                "plan",
                str(campaign_root),
                "--max-concurrency",
                str(args.max_concurrency),
            ]
        )
        run_checked(
            [
                sys.executable,
                str(TOOL_PROBE),
                "--output",
                str(campaign_root / "tools" / "tool-probe.json"),
            ]
        )
        if not args.no_queue:
            run_checked(
                [sys.executable, str(RESEARCH_HARNESS), "queue", str(campaign_root)]
            )

        output = {
            "campaign": str(campaign_root),
            "profile": profile,
            "target": target,
            "repository": repository,
            "commit": commit,
            "authorizationConfirmed": bool(args.confirm_authorization),
            "queued": not args.no_queue,
            "unresolved": unresolved,
            "next": [
                (
                    "python3 scripts/research_harness.py worker-register "
                    f"{campaign_root} coordinator --agent AGENT_ID --role coordinator"
                ),
                f"python3 scripts/research_harness.py claim {campaign_root} coordinator --json",
            ],
        }
        if args.json:
            print(json.dumps(output, indent=2))
        else:
            print(f"campaign ready: {campaign_root}")
            print(f"profile: {profile}; queued: {str(not args.no_queue).lower()}")
            print(f"authorization confirmed: {str(bool(args.confirm_authorization)).lower()}")
            if unresolved:
                print("unresolved intake items:")
                for item in unresolved:
                    print(f"- {item}")
            print("next:")
            for command in output["next"]:
                print(command)
        return 0
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
