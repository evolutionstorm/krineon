#!/usr/bin/env python3
"""Build, launch, exercise, and freeze production framework configurations."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
PROTOCOL_HARNESS = PROJECT / "scripts" / "http_protocol_harness.py"
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}
SURFACES = {
    "nextjs": {
        "app-router", "pages-router", "middleware", "server-actions", "rsc",
        "route-handlers", "rewrites", "image-optimization", "node-runtime",
        "edge-runtime", "standalone",
    },
    "react": {
        "react-dom", "hydration", "server-rendering", "rsc", "browser-bundle",
        "source-maps", "client-server-boundary",
    },
    "node": {
        "raw-http", "express", "fastify", "koa", "cli-parser", "native-addon",
        "worker-threads",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, root: Path | None = None) -> dict[str, Any]:
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


def read_campaign(root: Path) -> dict[str, Any]:
    path = root / "campaign.json"
    if not path.is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    value = json.loads(path.read_text(encoding="utf-8"))
    authorization = value.get("authorization") if isinstance(value, dict) else None
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise RuntimeError("adapter execution requires confirmed campaign authorization")
    return value


def project_path(spec_path: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = spec_path.parent / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise RuntimeError(f"projectRoot is not a directory: {candidate}")
    return candidate


def package_json(root: Path) -> dict[str, Any]:
    path = root / "package.json"
    if not path.is_file():
        raise RuntimeError("adapter project requires package.json")
    return json.loads(path.read_text(encoding="utf-8"))


def package_names(value: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        current = value.get(key)
        if isinstance(current, dict):
            result.update(str(name) for name in current)
    return result


def command_is_development(command: list[str], package: dict[str, Any]) -> bool:
    lowered = [str(token).lower() for token in command]
    forbidden = {"dev", "develop", "development", "--watch", "--watch-all"}
    if any(token in forbidden for token in lowered):
        return True
    executable = Path(lowered[0]).name
    script_name: str | None = None
    if executable in {"npm", "pnpm", "yarn", "bun"}:
        if len(lowered) >= 3 and lowered[1] in {"run", "run-script"}:
            script_name = str(command[2])
        elif executable == "yarn" and len(lowered) >= 2:
            script_name = str(command[1])
    scripts = package.get("scripts")
    if script_name and isinstance(scripts, dict) and script_name in scripts:
        try:
            script_tokens = shlex.split(str(scripts[script_name]))
        except ValueError:
            return True
        return command_is_development(script_tokens, {"scripts": {}})
    return False


def validate_framework(spec: dict[str, Any], root: Path) -> None:
    framework = str(spec.get("framework") or "")
    if framework not in SURFACES:
        raise RuntimeError("framework must be nextjs, react, or node")
    surfaces = spec.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        raise RuntimeError("adapter requires explicit production surfaces")
    unknown = set(map(str, surfaces)) - SURFACES[framework]
    if unknown:
        raise RuntimeError(f"unknown {framework} surfaces: {sorted(unknown)}")
    package = package_json(root)
    packages = package_names(package)
    if framework == "nextjs" and "next" not in packages:
        raise RuntimeError("Next.js adapter requires a pinned next dependency")
    if framework == "react" and not {"react", "react-dom"}.issubset(packages):
        raise RuntimeError("React adapter requires pinned react and react-dom dependencies")
    lockfile = str(spec.get("lockfile") or "")
    if Path(lockfile).name not in LOCKFILES:
        raise RuntimeError("adapter requires an explicit supported lockfile")
    lock_path = (root / lockfile).resolve()
    lock_path.relative_to(root)
    if not lock_path.is_file():
        raise RuntimeError(f"declared lockfile is absent: {lockfile}")
    cases = spec.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("adapter requires at least one runtime case")
    names: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not case.get("name"):
            raise RuntimeError("each adapter case requires a name")
        name = str(case["name"])
        if name in names:
            raise RuntimeError(f"duplicate adapter case: {name}")
        names.add(name)
        case_surfaces = case.get("surfaces", surfaces)
        if not isinstance(case_surfaces, list) or not case_surfaces:
            raise RuntimeError(f"case {name} requires production surfaces")
        unknown_case = set(map(str, case_surfaces)) - SURFACES[framework]
        if unknown_case:
            raise RuntimeError(f"unknown {framework} surfaces in case {name}: {sorted(unknown_case)}")
        surface_evidence = merged(spec.get("surfaceEvidence"), case.get("surfaceEvidence"))
        for surface in case_surfaces:
            patterns = surface_evidence.get(str(surface))
            if not isinstance(patterns, list) or not patterns:
                raise RuntimeError(f"case {name} requires hashed evidence globs for surface {surface}")
        environment = merged(spec.get("environment"), case.get("environment"))
        if environment.get("NODE_ENV") != "production":
            raise RuntimeError(f"case {name} must set NODE_ENV=production")
        for label in ("installCommand", "buildCommand"):
            command = case.get(label, spec.get(label))
            if command is None and label == "installCommand":
                continue
            validate_command(command, f"case {name} {label}")
            if command_is_development(command, package):
                raise RuntimeError(f"case {name} uses a development command")
        launch = merged(spec.get("launch"), case.get("launch"))
        if not launch:
            raise RuntimeError(f"case {name} requires a production launch definition")
        validate_command(launch.get("command"), f"case {name} launch command")
        if command_is_development(launch["command"], package):
            raise RuntimeError(f"case {name} launch command is development-only")
        artifacts = case.get("deploymentArtifacts", spec.get("deploymentArtifacts"))
        if not isinstance(artifacts, list) or not artifacts:
            raise RuntimeError(f"case {name} requires deploymentArtifacts")
        probes = case.get("compilerProbes", spec.get("compilerProbes"))
        if not isinstance(probes, list) or not probes:
            raise RuntimeError(f"case {name} requires compilerProbes")


def validate_command(value: Any, label: str) -> None:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError(f"{label} must be a non-empty argv list")


def merged(base: Any, override: Any) -> dict[str, Any]:
    result = dict(base) if isinstance(base, dict) else {}
    if isinstance(override, dict):
        result.update(override)
    return result


def resolve_executable(value: str, cwd: Path | None = None) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() and "/" in value and cwd is not None:
        candidate = cwd / candidate
    if candidate.is_absolute() or "/" in value:
        candidate = candidate.resolve()
        if not candidate.is_file():
            raise RuntimeError(f"executable is absent: {candidate}")
        return candidate
    located = shutil.which(value)
    if not located:
        raise RuntimeError(f"executable is unavailable: {value}")
    return Path(located).absolute()


def interpolate(command: list[str], *, runtime: Path, root: Path, port: int) -> list[str]:
    return [
        token.replace("{runtime}", str(runtime)).replace("{project}", str(root)).replace("{port}", str(port))
        for token in command
    ]


def clean_environment(overrides: dict[str, Any], pass_names: list[str], *, runtime: Path, port: int) -> dict[str, str]:
    names = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", *map(str, pass_names)}
    environment = {name: os.environ[name] for name in names if name in os.environ}
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C")
    environment.setdefault("LC_ALL", "C")
    environment["PATH"] = str(runtime.parent) + os.pathsep + environment["PATH"]
    for key, value in overrides.items():
        environment[str(key)] = str(value).replace("{port}", str(port)).replace("{runtime}", str(runtime))
    return environment


def environment_record(environment: dict[str, str]) -> list[dict[str, Any]]:
    plain = {"NODE_ENV", "NEXT_RUNTIME", "CI"}
    return [
        {
            "name": name,
            "value": value if name in plain else None,
            "valueSha256": hashlib.sha256(value.encode()).hexdigest(),
        }
        for name, value in sorted(environment.items())
    ]


def run_command(
    name: str,
    command: list[str] | None,
    *,
    root: Path,
    environment: dict[str, str],
    output: Path,
    timeout: int,
) -> dict[str, Any]:
    if command is None:
        return {"name": name, "status": "not-configured"}
    started = time.time_ns()
    completed = subprocess.run(command, cwd=root, env=environment, check=False, capture_output=True, timeout=timeout)
    stdout = output / f"{name}.stdout.bin"
    stderr = output / f"{name}.stderr.bin"
    stdout.write_bytes(completed.stdout)
    stderr.write_bytes(completed.stderr)
    return {
        "name": name,
        "status": "completed" if completed.returncode == 0 else "failed",
        "command": command,
        "startedNs": started,
        "finishedNs": time.time_ns(),
        "returnCode": completed.returncode,
        "stdout": file_record(stdout, output),
        "stderr": file_record(stderr, output),
    }


def artifact_files(root: Path, patterns: list[Any]) -> list[Path]:
    files: set[Path] = set()
    for pattern in patterns:
        value = str(pattern)
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise RuntimeError(f"artifact glob must be project-relative: {value}")
        for match in glob.glob(str(root / value), recursive=True):
            path = Path(match).resolve()
            path.relative_to(root)
            if path.is_file() and not path.is_symlink():
                files.add(path)
    return sorted(files)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_ready(host: str, port: int, path: str, timeout: float, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + timeout
    request = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"launched process exited before readiness: {process.returncode}")
        try:
            with socket.create_connection((host, port), 0.25) as connection:
                connection.sendall(request)
                data = connection.recv(64)
                if data.startswith(b"HTTP/"):
                    return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("production artifact did not become ready")


def git_identity(root: Path) -> dict[str, Any]:
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1"], check=False, capture_output=True, text=True)
    return {
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "dirtyBeforeBuild": bool(status.stdout),
        "statusSha256": hashlib.sha256(status.stdout.encode()).hexdigest(),
    }


def run_case(
    *,
    campaign_root: Path,
    spec_path: Path,
    spec: dict[str, Any],
    case: dict[str, Any],
    root: Path,
    output: Path,
) -> dict[str, Any]:
    name = str(case["name"])
    case_output = output / "cases" / name
    case_output.mkdir(parents=True)
    runtime = resolve_executable(str(case.get("runtime") or spec.get("runtime") or "node"))
    port = int(case.get("port") or 0) or free_port()
    environment = clean_environment(
        merged(spec.get("environment"), case.get("environment")),
        list(spec.get("passEnvironment", [])) + list(case.get("passEnvironment", [])),
        runtime=runtime,
        port=port,
    )
    timeout = int(case.get("commandTimeout") or spec.get("commandTimeout") or 900)
    install_value = case.get("installCommand", spec.get("installCommand"))
    build_value = case.get("buildCommand", spec.get("buildCommand"))
    install = interpolate(install_value, runtime=runtime, root=root, port=port) if install_value else None
    build = interpolate(build_value, runtime=runtime, root=root, port=port)
    records = [
        run_command("install", install, root=root, environment=environment, output=case_output, timeout=timeout),
        run_command("build", build, root=root, environment=environment, output=case_output, timeout=timeout),
    ]
    if any(record["status"] == "failed" for record in records):
        raise RuntimeError(f"case {name} install or production build failed")
    probes: list[dict[str, Any]] = []
    for index, probe in enumerate(case.get("compilerProbes", spec.get("compilerProbes", [])), 1):
        if not isinstance(probe, dict):
            raise RuntimeError("compiler probe must be an object")
        probe_command = interpolate(probe["command"], runtime=runtime, root=root, port=port)
        record = run_command(f"compiler-{index}", probe_command, root=root, environment=environment, output=case_output, timeout=60)
        if record["status"] != "completed":
            raise RuntimeError(f"compiler probe {index} failed")
        executable = resolve_executable(probe_command[0], root)
        record["executable"] = file_record(executable)
        command_artifacts: list[dict[str, Any]] = []
        for argument in probe_command[1:]:
            candidate = Path(argument).expanduser()
            if not candidate.is_absolute() and ("/" in argument or "\\" in argument):
                candidate = root / candidate
            if candidate.is_file():
                command_artifacts.append(file_record(candidate.resolve()))
        record["commandArtifacts"] = command_artifacts
        record["label"] = str(probe.get("name") or f"compiler-{index}")
        probes.append(record)
    deployment_patterns = case.get("deploymentArtifacts", spec.get("deploymentArtifacts"))
    deployed = artifact_files(root, deployment_patterns)
    if not deployed:
        raise RuntimeError(f"case {name} produced no deployment artifacts")
    generated = artifact_files(root, case.get("generatedArtifacts", spec.get("generatedArtifacts", deployment_patterns)))
    surface_evidence_patterns = merged(spec.get("surfaceEvidence"), case.get("surfaceEvidence"))
    surface_evidence: dict[str, list[dict[str, Any]]] = {}
    for surface in case.get("surfaces", spec["surfaces"]):
        files = artifact_files(root, surface_evidence_patterns[str(surface)])
        if not files:
            raise RuntimeError(f"case {name} has no concrete evidence for surface {surface}")
        surface_evidence[str(surface)] = [file_record(path, root) for path in files]
    launch = merged(spec.get("launch"), case.get("launch"))
    launch_command = interpolate(launch["command"], runtime=runtime, root=root, port=port)
    launch_environment = dict(environment)
    launch_environment.update({str(key): str(value).replace("{port}", str(port)) for key, value in launch.get("environment", {}).items()})
    stdout_path = case_output / "launch.stdout.bin"
    stderr_path = case_output / "launch.stderr.bin"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(launch_command, cwd=root, env=launch_environment, stdout=stdout, stderr=stderr)
        launch_started = time.time_ns()
        exercise_record: dict[str, Any] | None = None
        try:
            wait_ready(str(launch.get("host") or "127.0.0.1"), port, str(launch.get("readyPath") or "/"), float(launch.get("readyTimeout") or 30), process)
            exercise_value = case.get("exerciseSpec", spec.get("exerciseSpec"))
            if not exercise_value:
                raise RuntimeError(f"case {name} requires exerciseSpec")
            exercise_path = (spec_path.parent / str(exercise_value)).resolve()
            exercise_output = case_output / "exercise"
            completed = subprocess.run(
                [sys.executable, str(PROTOCOL_HARNESS), str(campaign_root), str(exercise_path), str(exercise_output), "--var", f"PORT={port}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=int(launch.get("exerciseTimeout") or 120),
            )
            if completed.returncode != 0:
                raise RuntimeError(f"case {name} protocol exercise failed: {completed.stderr.strip()}")
            result_path = Path(completed.stdout.strip()).resolve()
            exercise_record = file_record(result_path)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    version = subprocess.run([str(runtime), "--version"], check=False, capture_output=True, text=True, timeout=30)
    expected_prefix = str(case.get("expectedRuntimeVersionPrefix") or "")
    if expected_prefix and not version.stdout.strip().startswith(expected_prefix):
        raise RuntimeError(f"case {name} runtime version does not match {expected_prefix}")
    return {
        "name": name,
        "surfaces": case.get("surfaces", spec["surfaces"]),
        "runtime": {**file_record(runtime), "version": version.stdout.strip()},
        "environment": environment_record(environment),
        "commands": records,
        "compilerProbes": probes,
        "surfaceEvidence": surface_evidence,
        "generatedArtifacts": [file_record(path, root) for path in generated],
        "deploymentArtifacts": [file_record(path, root) for path in deployed],
        "launch": {
            "command": launch_command,
            "environment": environment_record(launch_environment),
            "startedNs": launch_started,
            "host": str(launch.get("host") or "127.0.0.1"),
            "port": port,
            "exitCodeAfterTermination": process.returncode,
            "stdout": file_record(stdout_path, case_output),
            "stderr": file_record(stderr_path, case_output),
        },
        "exercise": exercise_record,
        "status": "passed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        campaign_root = args.campaign.expanduser().resolve()
        campaign = read_campaign(campaign_root)
        spec_path = args.spec.expanduser().resolve()
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or spec.get("schemaVersion") != 1:
            raise RuntimeError("adapter spec must be a schemaVersion 1 object")
        root = project_path(spec_path, str(spec["projectRoot"]))
        validate_framework(spec, root)
        output = args.output.expanduser().resolve()
        output.relative_to(campaign_root)
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("adapter output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        source_identity = git_identity(root)
        lockfile = (root / str(spec["lockfile"])).resolve()
        package_path = root / "package.json"
        cases = [
            run_case(campaign_root=campaign_root, spec_path=spec_path, spec=spec, case=case, root=root, output=output)
            for case in spec["cases"]
        ]
        manifest = {
            "schemaVersion": 1,
            "producer": "krineon-framework-adapter",
            "runId": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8],
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "framework": spec["framework"],
            "surfaces": spec["surfaces"],
            "campaignCommit": campaign.get("commit"),
            "projectRoot": str(root),
            "sourceIdentity": source_identity,
            "spec": file_record(spec_path),
            "package": file_record(package_path, root),
            "lockfile": file_record(lockfile, root),
            "adapter": file_record(Path(__file__).resolve()),
            "protocolHarness": file_record(PROTOCOL_HARNESS),
            "cases": cases,
            "status": "passed",
        }
        manifest_path = output / "framework-adapter-run.json"
        write_json(manifest_path, manifest)
        runs = campaign.get("frameworkAdapterRuns")
        if not isinstance(runs, list):
            runs = []
        runs.append({"framework": spec["framework"], "path": manifest_path.relative_to(campaign_root).as_posix(), "sha256": sha256_file(manifest_path)})
        campaign["frameworkAdapterRuns"] = runs
        write_json(campaign_root / "campaign.json", campaign)
        print(manifest_path)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
