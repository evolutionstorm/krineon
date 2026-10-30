#!/usr/bin/env python3
"""Report and normalize host capabilities used by Krineon runners."""

from __future__ import annotations

import platform
from typing import Any


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "aarch64": "arm64",
        "armx64": "arm64",
        "arm64e": "arm64",
        "amd64": "x86_64",
        "x64": "x86_64",
    }
    return aliases.get(normalized, normalized or "unknown")


def host_platform(
    *, system: str | None = None, machine: str | None = None
) -> dict[str, Any]:
    system_value = system or platform.system()
    machine_value = machine or platform.machine()
    architecture = normalize_architecture(machine_value)
    supported = system_value in {"Linux", "Darwin"} and architecture in {
        "arm64",
        "x86_64",
    }
    return {
        "system": system_value,
        "release": platform.release(),
        "machine": machine_value,
        "architecture": architecture,
        "darwinArm64": system_value == "Darwin" and architecture == "arm64",
        "posixHarnessSupported": supported,
        "python": platform.python_version(),
    }


def resource_limit_plan(config: dict[str, Any], *, system: str | None = None) -> dict[str, Any]:
    system_value = system or platform.system()
    try:
        import resource
    except ImportError:
        return {
            "system": system_value,
            "coreDump": "unavailable",
            "cpu": "unavailable",
            "addressSpace": "unavailable",
        }

    memory_requested = int(config.get("memoryMb") or 0) > 0
    address_space_available = hasattr(resource, "RLIMIT_AS")
    return {
        "system": system_value,
        "coreDump": "enforced" if hasattr(resource, "RLIMIT_CORE") else "unavailable",
        "cpu": "enforced" if hasattr(resource, "RLIMIT_CPU") else "unavailable",
        "addressSpace": (
            "not-requested"
            if not memory_requested
            else "best-effort-darwin"
            if system_value == "Darwin" and address_space_available
            else "enforced"
            if address_space_available
            else "unavailable"
        ),
        "memoryMb": int(config.get("memoryMb") or 0),
        "limitation": (
            "Darwin address-space limits are retained as best-effort evidence; "
            "they are not a security sandbox, so use a disposable VM for containment."
            if system_value == "Darwin" and memory_requested
            else "Resource limits are not a security sandbox."
        ),
    }
