"""Pure release parsing plus Docker capability-based platform detection."""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path
import platform as host_platform
import re
from typing import Mapping, Sequence

from scripts.platforms.model import (
    DockerRuntimeProfile,
    HostCapabilities,
    HostOsProfile,
    HostProfile,
)
from scripts.vulnerability_models import utc_timestamp
from scripts.vulnerability_scan import DockerClient, InventoryError, platform_argument
from scripts.vulnerability_scout import sanitize_command_error


QNAP_RELEASE_PATHS = (
    Path("/etc/config/uLinux.conf"),
    Path("/etc/default_config/uLinux.conf"),
)
OS_RELEASE_PATH = Path("/etc/os-release")
HOST_OS_MODES = ("auto", "qnap", "linux")
ARCHITECTURE_ALIASES = {
    "x86_64": "amd64",
    "x64": "amd64",
    "aarch64": "arm64",
    "arm64v8": "arm64",
    "armv7l": "arm/v7",
    "armv7": "arm/v7",
}
QNAP_IDS = {"qts", "qnap", "quts", "qutscloud"}
FAMILY_BY_ID = {
    "debian": "debian",
    "ubuntu": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "fedora": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "sles": "suse",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "arch": "arch",
    "manjaro": "arch",
    "alpine": "alpine",
}
SAFE_RELEASE_LENGTH = 160


def sanitize_release_value(value: object, fallback: str = "unknown") -> str:
    """Normalize one release value to bounded printable diagnostic text."""

    if not isinstance(value, str):
        return fallback
    printable = " ".join(value.replace("\x00", " ").split())
    printable = re.sub(r"[^\w .,+()/:@-]", "?", printable, flags=re.UNICODE)
    return printable[:SAFE_RELEASE_LENGTH] or fallback


def parse_release_values(raw_text: str) -> dict[str, str]:
    """Parse simple shell/INI release fields and ignore malformed lines."""

    values: dict[str, str] = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        normalized_key = key.strip().lower().replace(" ", "_")
        normalized_value = sanitize_release_value(value.strip().strip('"\''), "")
        if normalized_key and normalized_value:
            values[normalized_key] = normalized_value
    return values


def read_release_file(path: Path) -> dict[str, str]:
    """Return sanitized release fields or an empty mapping when unreadable."""

    try:
        return parse_release_values(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def first_value(values: Mapping[str, str], *keys: str) -> str | None:
    """Return the first non-empty release value for candidate keys."""

    for key in keys:
        value = values.get(key)
        if value:
            return value
    return None


def linux_family(os_id: str, id_like: str | None = None) -> str:
    """Map distribution identity to package guidance without forking runtime."""

    normalized_id = os_id.lower()
    if normalized_id in FAMILY_BY_ID:
        return FAMILY_BY_ID[normalized_id]
    for related in (id_like or "").lower().split():
        if related in FAMILY_BY_ID:
            return FAMILY_BY_ID[related]
    return "generic-linux"


def detect_host_os(
    requested: str = "auto",
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
) -> HostOsProfile:
    """Detect QNAP or standard Linux using only supplied release files."""

    if requested not in HOST_OS_MODES:
        raise ValueError(f"Unsupported host OS mode: {requested}")
    if requested == "qnap":
        return HostOsProfile(
            "qnap", "QNAP", None, None, "operator-override", "qts", "qnap"
        )

    if requested == "auto":
        for path in qnap_release_paths:
            values = read_release_file(path)
            if values:
                return HostOsProfile(
                    family="qnap",
                    name="QNAP QTS/QuTS hero",
                    version=first_value(
                        values, "version", "version_number", "firmware_version"
                    ),
                    model=first_value(
                        values, "model", "internal_model", "display_model"
                    ),
                    detection=f"release-file:{path}",
                    os_id="qts",
                    platform_adapter="qnap",
                )

    values = read_release_file(os_release_path)
    os_id = (first_value(values, "id") or "linux").lower()
    if requested == "auto" and os_id in QNAP_IDS:
        return HostOsProfile(
            family="qnap",
            name=first_value(values, "pretty_name", "name") or "QNAP",
            version=first_value(values, "version_id", "version"),
            model=None,
            detection="os-release",
            os_id="qts" if os_id == "qnap" else os_id,
            platform_adapter="qnap",
        )
    detected_name = (
        first_value(values, "pretty_name", "name")
        or sanitize_release_value(host_platform.system(), "Linux")
    )
    return HostOsProfile(
        family=linux_family(os_id, first_value(values, "id_like")),
        name=detected_name,
        version=first_value(values, "version_id", "version"),
        model=None,
        detection="operator-override" if requested == "linux" else "os-release",
        os_id=os_id,
        platform_adapter="standard-linux",
    )


def detect_docker_runtime(
    client: DockerClient, requested: str = "auto"
) -> DockerRuntimeProfile:
    """Select Swarm-wide or local-container inventory from Docker capability."""

    result = client.run(
        ["info", "--format", "{{.Swarm.LocalNodeState}}\t{{.Swarm.ControlAvailable}}"]
    )
    if result.return_code != 0:
        detail = sanitize_command_error(result.stderr or result.stdout)
        raise InventoryError(f"Docker daemon preflight failed: {detail}")
    fields = result.stdout.strip().lower().split("\t")
    if len(fields) != 2:
        raise InventoryError("Docker returned an invalid runtime capability response.")
    swarm_state, manager_text = fields
    manager = swarm_state == "active" and manager_text == "true"
    if requested == "swarm" and not manager:
        raise InventoryError(
            "Swarm mode was requested, but this node does not have manager control."
        )
    selected = (
        "swarm"
        if requested == "swarm" or (requested == "auto" and manager)
        else "containers"
    )
    return DockerRuntimeProfile(
        inventory_mode=selected,
        swarm_state=swarm_state or "unknown",
        manager=manager,
        detection="capability-auto" if requested == "auto" else "operator-override",
    )


def normalize_architecture(value: str) -> str:
    """Normalize common Docker and QNAP architecture names for Scout."""

    normalized = value.strip().lower()
    return ARCHITECTURE_ALIASES.get(normalized, normalized)


def resolve_platform(client: DockerClient, requested: str) -> str:
    """Resolve ``auto`` to a validated Docker daemon platform."""

    if requested != "auto":
        return platform_argument(requested)
    result = client.run(["info", "--format", "{{.OSType}}\t{{.Architecture}}"])
    if result.return_code != 0:
        detail = sanitize_command_error(result.stderr or result.stdout)
        raise InventoryError(f"Docker platform detection failed: {detail}")
    fields = result.stdout.strip().split("\t")
    if len(fields) != 2 or not all(fields):
        raise InventoryError("Docker returned an invalid platform response.")
    candidate = f"{fields[0].lower()}/{normalize_architecture(fields[1])}"
    try:
        return platform_argument(candidate)
    except argparse.ArgumentTypeError as error:
        raise InventoryError(
            f"Docker reported an unsupported platform: {candidate}"
        ) from error


def build_host_profile(
    host_os: HostOsProfile,
    docker: DockerRuntimeProfile,
    detected_at: str | None = None,
    scanner_available: bool | None = None,
) -> HostProfile:
    """Build the stable capability contract from adapter and Docker facts."""

    effective_scanner = (
        docker.daemon_available
        if scanner_available is None
        else scanner_available and docker.daemon_available
    )
    capabilities = HostCapabilities(
        image_vulnerability_scan=effective_scanner,
        focused_container_scan=effective_scanner,
        container_health=docker.daemon_available,
        expected_state_policy=docker.daemon_available,
        scan_progress=effective_scanner,
        runtime_hardening=False,
        guided_remediation="read-only" if docker.daemon_available else "unavailable",
        image_cleanup=docker.daemon_available,
        scheduler=(
            "qnap-persistent-crontab"
            if host_os.platform_adapter == "qnap"
            else "user-crontab"
        ),
    )
    return HostProfile(detected_at or utc_timestamp(), host_os, docker, capabilities)


def detect_platform_profile(
    client: DockerClient,
    requested_os: str = "auto",
    requested_runtime: str = "auto",
    requested_platform: str = "auto",
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
    detected_at: str | None = None,
) -> HostProfile:
    """Inspect Docker tools and return a complete profile even when unavailable."""

    host_os = detect_host_os(requested_os, qnap_release_paths, os_release_path)
    try:
        docker = detect_docker_runtime(client, requested_runtime)
    except InventoryError:
        docker = DockerRuntimeProfile(
            "containers", "unavailable", False, "capability-unavailable",
            daemon_available=False,
        )
        return build_host_profile(host_os, docker, detected_at)
    try:
        platform = resolve_platform(client, requested_platform)
    except InventoryError:
        platform = "unknown"
    compose = client.run(["compose", "version"])
    scout = client.run(["scout", "version"])
    docker = dataclasses.replace(
        docker,
        platform=platform,
        compose_available=compose.return_code == 0,
    )
    return build_host_profile(
        host_os,
        docker,
        detected_at,
        scanner_available=scout.return_code == 0,
    )
