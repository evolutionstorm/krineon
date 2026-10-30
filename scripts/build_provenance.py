#!/usr/bin/env python3
"""Capture and verify independently derived Chrome/V8 build provenance."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from experiment_control import ensure_authority, sign_file, verify_signed_record
from platform_support import normalize_architecture


class ProvenanceError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def run(command: list[str], *, cwd: Path | None = None, timeout: float = 30) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "command": command,
        "returnCode": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace")[:200000],
        "stderr": completed.stderr.decode("utf-8", "replace")[:200000],
    }


def git_output(checkout: Path, *arguments: str) -> str:
    result = run(["git", "-C", str(checkout), *arguments])
    if result["returnCode"] != 0:
        raise ProvenanceError(
            "git provenance command failed: " + (result["stderr"] or result["stdout"])
        )
    return str(result["stdout"]).strip()


def parse_gn_args(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        name, value = [item.strip() for item in line.split("=", 1)]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        if value in {"true", "false"}:
            values[name] = value == "true"
        elif re.fullmatch(r"-?[0-9]+", value):
            values[name] = int(value)
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            values[name] = value[1:-1]
        else:
            values[name] = value
    return values


def compiler_identity(commands: str) -> dict[str, Any]:
    candidates: list[str] = []
    for line in commands.splitlines():
        try:
            token = line.strip().split()[0]
        except IndexError:
            continue
        name = Path(token).name
        if any(value in name for value in ("clang", "gcc", "g++", "cc", "c++")):
            candidates.append(token)
    executable = shutil.which(candidates[0]) if candidates else None
    if executable is None:
        return {"path": None, "version": None, "versionSha256": None}
    resolved = str(Path(executable).resolve())
    observation = run([resolved, "--version"])
    output = (observation["stdout"] or observation["stderr"]).strip()
    return {
        "path": resolved,
        "version": output[:4000],
        "versionSha256": sha256_bytes(output.encode()),
    }


def dependency_revisions(checkout: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    submodules = git_output(checkout, "submodule", "status", "--recursive")
    for line in submodules.splitlines():
        match = re.match(r"^[ +-]?([0-9a-f]{40,64})\s+(\S+)", line.strip())
        if match:
            rows.append({"path": match.group(2), "revision": match.group(1)})
    for name in ("DEPS", ".gclient", "v8_revision", "package-lock.json"):
        path = checkout / name
        if path.is_file():
            rows.append({"path": name, "revision": sha256_file(path)})
    return sorted(rows, key=lambda value: value["path"])


def untracked_artifacts(checkout: Path) -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["git", "-C", str(checkout), "ls-files", "--others", "--exclude-standard", "-z"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ProvenanceError("cannot enumerate untracked source artifacts")
    values: list[dict[str, Any]] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8", "surrogateescape")
        path = checkout / relative
        if path.is_file():
            values.append(
                {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}
            )
    return sorted(values, key=lambda value: value["path"])


def inspect_architecture(binary: Path) -> dict[str, Any]:
    file_tool = shutil.which("file")
    if not file_tool:
        raise ProvenanceError("the file tool is required for architecture provenance")
    observation = run([file_tool, "-b", str(binary)])
    output = str(observation["stdout"] or observation["stderr"])
    architectures: set[str] = set()
    lowered = output.lower()
    if "x86-64" in lowered or "x86_64" in lowered:
        architectures.add("x86_64")
    if "arm64" in lowered or "aarch64" in lowered:
        architectures.add("arm64")
    if not architectures:
        architectures.add(normalize_architecture(platform.machine()))
    return {"architectures": sorted(architectures), "fileOutput": output.strip()}


def sanitizer_probe(binary: Path, cwd: Path, flags: list[str]) -> dict[str, Any]:
    data = binary.read_bytes()
    symbol_present = b"__asan_init" in data or b"__asan_report_" in data
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
        "ASAN_OPTIONS": "help=1:detect_leaks=0:abort_on_error=0",
    }
    try:
        completed = subprocess.run(
            [str(binary), *flags],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"")
        return {
            "symbolPresent": symbol_present,
            "runtimeHelpObserved": False,
            "functional": False,
            "timedOut": True,
            "outputSha256": sha256_bytes(output),
        }
    output = completed.stdout + completed.stderr
    runtime_present = any(
        marker in output
        for marker in (
            b"Available flags for AddressSanitizer",
            b"quarantine_size",
            b"detect_stack_use_after_return",
        )
    )
    return {
        "symbolPresent": symbol_present,
        "runtimeHelpObserved": runtime_present,
        "functional": symbol_present and runtime_present,
        "returnCode": completed.returncode,
        "outputSha256": sha256_bytes(output),
    }


def reprl_probe(binary: Path, cwd: Path, flags: list[str]) -> dict[str, Any]:
    """Perform the REPRL HELO handshake without executing a testcase."""

    if os.name != "posix":
        return {"functional": False, "reason": "REPRL probe requires POSIX file descriptors"}
    parent_control_read, child_control_write = os.pipe()
    child_control_read, parent_control_write = os.pipe()
    child_data_read, parent_data_write = os.pipe()
    parent_data_read, child_data_write = os.pipe()
    child_fds = (child_control_read, child_control_write, child_data_read, child_data_write)

    def prepare() -> None:
        for source, destination in zip(child_fds, (100, 101, 102, 103)):
            os.dup2(source, destination)

    process: subprocess.Popen[bytes] | None = None
    greeting = b""
    echoed = False
    try:
        process = subprocess.Popen(
            [str(binary), *flags, "--reprl"],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=child_fds,
            preexec_fn=prepare,
        )
        for fd in child_fds:
            os.close(fd)
        readable, _, _ = select.select([parent_control_read], [], [], 2.0)
        if readable:
            greeting = os.read(parent_control_read, 4)
            if greeting == b"HELO":
                os.write(parent_control_write, b"HELO")
                echoed = True
    except (OSError, subprocess.SubprocessError) as error:
        return {"functional": False, "reason": str(error)}
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for fd in (
            parent_control_read,
            parent_control_write,
            parent_data_read,
            parent_data_write,
            *child_fds,
        ):
            try:
                os.close(fd)
            except OSError:
                pass
    return {
        "functional": greeting == b"HELO" and echoed,
        "greetingHex": greeting.hex(),
        "echoed": echoed,
    }


def capture(args: argparse.Namespace) -> int:
    campaign = Path(args.campaign_dir).expanduser().resolve()
    checkout = Path(args.checkout).expanduser().resolve()
    build_dir = Path(args.build_dir).expanduser().resolve()
    binary = Path(args.binary).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    if not (campaign / "campaign.json").is_file():
        raise ProvenanceError("campaign is not initialized")
    if not checkout.is_dir() or not (checkout / ".git").exists():
        raise ProvenanceError("checkout must be a Git worktree")
    if not build_dir.is_dir() or not binary.is_file():
        raise ProvenanceError("build directory or binary is absent")
    binary.relative_to(build_dir)
    gn_args_path = build_dir / "args.gn"
    ninja_path = build_dir / "build.ninja"
    if not gn_args_path.is_file() or not ninja_path.is_file():
        raise ProvenanceError("build directory requires args.gn and build.ninja")
    ninja = shutil.which("ninja")
    if not ninja:
        raise ProvenanceError("ninja is required to derive effective build commands")
    commands_observation = run(
        [ninja, "-C", str(build_dir), "-t", "commands", args.target], timeout=60
    )
    commands = str(commands_observation["stdout"])
    if commands_observation["returnCode"] != 0 or not commands.strip():
        raise ProvenanceError("ninja did not return an effective command for the target")
    revision = git_output(checkout, "rev-parse", "HEAD")
    status = git_output(checkout, "status", "--porcelain=v1", "--untracked-files=all")
    diff = run(["git", "-C", str(checkout), "diff", "--binary", "HEAD"])
    diff_bytes = str(diff["stdout"]).encode()
    dependencies = dependency_revisions(checkout)
    untracked = untracked_artifacts(checkout)
    dependency_digest = sha256_bytes(
        json.dumps(dependencies, sort_keys=True, separators=(",", ":")).encode()
    )
    gn_args = parse_gn_args(gn_args_path)
    flags = list(args.flag or [])
    sanitizer = (
        sanitizer_probe(binary, build_dir, flags)
        if args.role == "asan"
        else {"functional": False, "notRequiredForRole": True}
    )
    reprl = (
        reprl_probe(binary, build_dir, flags)
        if args.role == "fuzzilli-reprl"
        else {"functional": False, "notRequiredForRole": True}
    )
    architecture = inspect_architecture(binary)
    record = {
        "schemaVersion": 1,
        "producer": "krineon-build-provenance",
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "build": {
            "name": args.name,
            "kind": args.kind,
            "role": args.role,
            "binary": artifact(binary),
            "buildDirectory": str(build_dir),
            "target": args.target,
            "runtimeFlags": flags,
        },
        "source": {
            "checkout": str(checkout),
            "revision": revision,
            "dependencyRevisions": dependencies,
            "dependencyDigest": dependency_digest,
            "workingTreeStatus": status.splitlines(),
            "untrackedArtifacts": untracked,
            "appliedPatch": {
                "sha256": sha256_bytes(diff_bytes),
                "size": len(diff_bytes),
            },
        },
        "configuration": {
            "gnArgs": artifact(gn_args_path),
            "effectiveGnArgs": gn_args,
            "ninjaFile": artifact(ninja_path),
            "effectiveCommandsSha256": sha256_bytes(commands.encode()),
            "effectiveCommands": commands.splitlines(),
            "compiler": compiler_identity(commands),
        },
        "capabilities": {
            "addressSanitizer": sanitizer,
            "reprl": reprl,
            "sandbox": {
                "v8EnableSandbox": gn_args.get("v8_enable_sandbox"),
                "isChrome": args.kind == "chrome",
            },
        },
        "architecture": architecture,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    authority = ensure_authority(campaign)
    campaign_path = campaign / "campaign.json"
    campaign_record = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign_record["experimentAuthority"] = {
        key: authority[key]
        for key in ("algorithm", "publicKey", "publicKeySha256")
    }
    campaign_path.write_text(
        json.dumps(campaign_record, indent=2) + "\n", encoding="utf-8"
    )
    signature = output.with_suffix(output.suffix + ".sig")
    sign_file(Path(authority["privateKey"]), output, signature)
    print(json.dumps({"manifest": str(output), "signature": str(signature)}, indent=2))
    return 0


def verify_manifest(campaign: Path, manifest_path: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    record = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("producer") != "krineon-build-provenance":
        return {}, ["manifest producer is not krineon-build-provenance"]
    signature = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    valid, signature_errors, _ = verify_signed_record(
        campaign, manifest_path, signature, producer="krineon-build-provenance"
    )
    if not valid:
        errors.extend("signature:" + value for value in signature_errors)
    build = record.get("build") if isinstance(record.get("build"), dict) else {}
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    config = record.get("configuration") if isinstance(record.get("configuration"), dict) else {}
    binary_record = build.get("binary") if isinstance(build.get("binary"), dict) else {}
    binary = Path(str(binary_record.get("path") or ""))
    checkout = Path(str(source.get("checkout") or ""))
    build_dir = Path(str(build.get("buildDirectory") or ""))
    if not binary.is_file() or sha256_file(binary) != binary_record.get("sha256"):
        errors.append("binary hash or path does not match manifest")
    if not checkout.is_dir() or not (checkout / ".git").exists():
        errors.append("source checkout is unavailable")
    else:
        try:
            if git_output(checkout, "rev-parse", "HEAD") != source.get("revision"):
                errors.append("source revision changed")
            current_status = git_output(
                checkout, "status", "--porcelain=v1", "--untracked-files=all"
            ).splitlines()
            if current_status != source.get("workingTreeStatus"):
                errors.append("source working-tree state changed")
            if untracked_artifacts(checkout) != source.get("untrackedArtifacts"):
                errors.append("untracked source artifacts changed")
            dependencies = dependency_revisions(checkout)
            digest = sha256_bytes(
                json.dumps(dependencies, sort_keys=True, separators=(",", ":")).encode()
            )
            if digest != source.get("dependencyDigest"):
                errors.append("dependency revisions changed")
            diff = run(["git", "-C", str(checkout), "diff", "--binary", "HEAD"])
            diff_bytes = str(diff["stdout"]).encode()
            if sha256_bytes(diff_bytes) != (source.get("appliedPatch") or {}).get("sha256"):
                errors.append("applied patch set changed")
        except ProvenanceError as error:
            errors.append(str(error))
    gn_record = config.get("gnArgs") if isinstance(config.get("gnArgs"), dict) else {}
    gn_path = Path(str(gn_record.get("path") or ""))
    ninja_record = config.get("ninjaFile") if isinstance(config.get("ninjaFile"), dict) else {}
    ninja_path = Path(str(ninja_record.get("path") or ""))
    if not gn_path.is_file() or sha256_file(gn_path) != gn_record.get("sha256"):
        errors.append("GN args changed or are absent")
    if not ninja_path.is_file() or sha256_file(ninja_path) != ninja_record.get("sha256"):
        errors.append("Ninja graph changed or is absent")
    ninja = shutil.which("ninja")
    if ninja and build_dir.is_dir():
        observed = run(
            [ninja, "-C", str(build_dir), "-t", "commands", str(build.get("target"))],
            timeout=60,
        )
        if sha256_bytes(str(observed["stdout"]).encode()) != config.get("effectiveCommandsSha256"):
            errors.append("effective build commands changed")
    else:
        errors.append("cannot rederive effective build commands")
    compiler = config.get("compiler") if isinstance(config.get("compiler"), dict) else {}
    compiler_path = Path(str(compiler.get("path") or ""))
    if not compiler_path.is_file():
        errors.append("effective build compiler is absent")
    else:
        observed_compiler = run([str(compiler_path), "--version"])
        observed_version = str(
            observed_compiler["stdout"] or observed_compiler["stderr"]
        ).strip()
        if observed_compiler["returnCode"] != 0:
            errors.append("effective build compiler cannot be re-executed")
        elif sha256_bytes(observed_version.encode()) != compiler.get("versionSha256"):
            errors.append("effective build compiler identity changed")
    effective_args = config.get("effectiveGnArgs")
    if not isinstance(effective_args, dict):
        errors.append("effective GN args are absent")
        effective_args = {}
    for required in ("target_cpu", "is_debug", "v8_enable_sandbox"):
        if required not in effective_args:
            errors.append(f"GN args omit security-relevant setting {required}")
    architecture = record.get("architecture") if isinstance(record.get("architecture"), dict) else {}
    if binary.is_file():
        actual_arch = inspect_architecture(binary)["architectures"]
        if sorted(actual_arch) != sorted(architecture.get("architectures", [])):
            errors.append("binary architecture observation changed")
    capabilities = record.get("capabilities") if isinstance(record.get("capabilities"), dict) else {}
    role = str(build.get("role") or "")
    sanitizer = capabilities.get("addressSanitizer") or {}
    reprl = capabilities.get("reprl") or {}
    if role == "asan":
        if effective_args.get("is_asan") is not True:
            errors.append("ASan role lacks is_asan=true")
        commands = "\n".join(config.get("effectiveCommands", []))
        if "sanitize=address" not in commands and "asan" not in commands.lower():
            errors.append("effective commands lack AddressSanitizer instrumentation")
        if sanitizer.get("functional") is not True:
            errors.append("AddressSanitizer runtime probe did not pass")
    if role == "fuzzilli-reprl":
        if effective_args.get("v8_fuzzilli") is not True:
            errors.append("REPRL role lacks v8_fuzzilli=true")
        if reprl.get("functional") is not True:
            errors.append("REPRL handshake did not pass")
    return record, errors


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    capture_parser = sub.add_parser("capture")
    capture_parser.add_argument("campaign_dir")
    capture_parser.add_argument("name")
    capture_parser.add_argument("--kind", choices=("d8", "chrome"), required=True)
    capture_parser.add_argument(
        "--role",
        choices=("release", "asan", "debug", "jitless", "sandboxed-chrome", "fuzzilli-reprl", "other"),
        required=True,
    )
    capture_parser.add_argument("--checkout", required=True)
    capture_parser.add_argument("--build-dir", required=True)
    capture_parser.add_argument("--binary", required=True)
    capture_parser.add_argument("--target", required=True)
    capture_parser.add_argument("--flag", action="append")
    capture_parser.add_argument("--output", required=True)
    capture_parser.set_defaults(func=capture)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, ProvenanceError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
