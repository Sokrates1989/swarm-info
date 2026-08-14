"""Capability-aware Docker image security checks for Linux hosts.

The command selects a Swarm-wide service inventory only when the local Docker
daemon grants manager control. Otherwise it scans the exact image IDs attached
to local containers. Local-container evidence never falls back to a registry,
because a mutable remote tag may no longer identify the installed artifact.

Dependencies:
    - Python 3.10 or newer.
    - Docker CLI access to the local Docker daemon.
    - Docker Scout CLI available to the same operating-system user.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
import platform as host_platform
import sys
from typing import Any, Mapping, Sequence

from scripts.vulnerability_models import (
    ServiceRecord,
    build_report,
    utc_timestamp,
    write_json_atomic,
)
from scripts.vulnerability_scan import (
    DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
    DockerClient,
    InventoryError,
    ProgressCallback,
    collect_services,
    platform_argument,
    run_with_progress_heartbeat,
    scan_collected_services,
)
from scripts.vulnerability_scout import sanitize_command_error


DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent / "swarm_info" / "security_scan.json"
)
QNAP_RELEASE_PATHS = (
    Path("/etc/config/uLinux.conf"),
    Path("/etc/default_config/uLinux.conf"),
)
OS_RELEASE_PATH = Path("/etc/os-release")
RUNTIME_MODES = ("auto", "swarm", "containers")
HOST_OS_MODES = ("auto", "qnap", "linux")
CONTAINER_SCOPES = ("all", "running")
ARCHITECTURE_ALIASES = {
    "x86_64": "amd64",
    "x64": "amd64",
    "aarch64": "arm64",
    "arm64v8": "arm64",
    "armv7l": "arm/v7",
    "armv7": "arm/v7",
}


@dataclasses.dataclass(frozen=True)
class HostOsProfile:
    """Sanitized host operating-system identity for report metadata."""

    family: str
    name: str
    version: str | None
    model: str | None
    detection: str

    def to_dict(self) -> dict[str, str | None]:
        """Serialize the profile without host configuration contents."""

        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class DockerRuntimeProfile:
    """Selected Docker inventory mode and observed Swarm capability."""

    inventory_mode: str
    swarm_state: str
    manager: bool
    detection: str

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize the capability decision for auditability."""

        return dataclasses.asdict(self)


def parse_release_values(raw_text: str) -> dict[str, str]:
    """Parse simple shell/INI-style release fields into lowercase keys.

    Args:
        raw_text: Release file contents.

    Returns:
        Normalized key/value mapping. Sections and malformed lines are ignored.
    """

    values: dict[str, str] = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        normalized_key = key.strip().lower().replace(" ", "_")
        normalized_value = value.strip().strip('"\'')
        if normalized_key and normalized_value:
            values[normalized_key] = normalized_value
    return values


def read_release_file(path: Path) -> dict[str, str]:
    """Read a release file defensively.

    Args:
        path: Candidate operating-system release file.

    Returns:
        Parsed values, or an empty mapping when the file is unavailable.
    """

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


def detect_host_os(
    requested: str = "auto",
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
) -> HostOsProfile:
    """Detect QNAP or generic Linux without executing vendor commands.

    Args:
        requested: ``auto``, explicit ``qnap``, or generic ``linux``.
        qnap_release_paths: Candidate QNAP release files.
        os_release_path: Generic freedesktop release file.

    Returns:
        Sanitized host profile and whether it was detected or overridden.
    """

    if requested == "qnap":
        return HostOsProfile("qnap", "QNAP", None, None, "operator-override")

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
                    model=first_value(values, "model", "internal_model", "display_model"),
                    detection=f"release-file:{path}",
                )

    values = read_release_file(os_release_path)
    detected_family = first_value(values, "id") or "linux"
    detected_name = (
        first_value(values, "pretty_name", "name")
        or host_platform.system()
        or "Linux"
    )
    family = "linux" if requested == "linux" else detected_family.lower()
    if requested == "auto" and family in {"qts", "qnap", "quts", "qutscloud"}:
        family = "qnap"
    return HostOsProfile(
        family=family,
        name=detected_name,
        version=first_value(values, "version_id", "version"),
        model=None,
        detection="operator-override" if requested == "linux" else "os-release",
    )


def detect_docker_runtime(
    client: DockerClient, requested: str = "auto"
) -> DockerRuntimeProfile:
    """Select Swarm-wide or local-container inventory from Docker capability.

    Args:
        client: Docker command client.
        requested: ``auto``, ``swarm``, or ``containers``.

    Returns:
        Selected runtime profile.

    Raises:
        InventoryError: If Docker is unavailable or forced Swarm mode lacks
            manager control.
    """

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
    """Normalize common Docker/QNAP architecture names for Scout."""

    normalized = value.strip().lower()
    return ARCHITECTURE_ALIASES.get(normalized, normalized)


def resolve_platform(client: DockerClient, requested: str) -> str:
    """Resolve ``auto`` to the Docker daemon platform.

    Args:
        client: Docker command client.
        requested: Explicit Docker platform or ``auto``.

    Returns:
        Validated ``os/architecture[/variant]`` platform.

    Raises:
        InventoryError: If Docker cannot report a valid platform.
    """

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
        raise InventoryError(f"Docker reported an unsupported platform: {candidate}") from error


def parse_container_inspect(container_id: str, raw_json: str) -> ServiceRecord:
    """Parse one local ``docker container inspect`` response.

    Args:
        container_id: Requested container identifier.
        raw_json: Docker JSON response.

    Returns:
        Container name, configured image reference, Compose project, and exact
        local image ID.

    Raises:
        InventoryError: If required container fields are absent.
    """

    try:
        payload = json.loads(raw_json)[0]
        name = payload["Name"]
        image_id = payload["Image"]
        configuration = payload["Config"]
        image_reference = configuration["Image"]
        labels = configuration.get("Labels") or {}
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise InventoryError(
            f"Container {container_id} returned invalid inspect JSON."
        ) from error
    if not all(
        isinstance(value, str) and value.strip()
        for value in (name, image_id, image_reference)
    ):
        raise InventoryError(
            f"Container {container_id} has no valid name, image, or local image ID."
        )
    project = (
        labels.get("com.docker.compose.project")
        if isinstance(labels, dict)
        else None
    )
    return ServiceRecord(
        service_id=container_id,
        name=name.lstrip("/"),
        image=image_reference,
        stack=project if isinstance(project, str) and project else None,
        local_image_id=image_id,
    )


def collect_containers(
    client: DockerClient, scope: str = "all"
) -> list[ServiceRecord]:
    """Collect exact images behind local Docker containers.

    Args:
        client: Docker command client.
        scope: ``all`` includes stopped containers; ``running`` does not.

    Returns:
        Container records sorted by name.

    Raises:
        InventoryError: If listing or inspecting any selected container fails.
    """

    arguments = ["container", "ls"]
    if scope == "all":
        arguments.append("--all")
    arguments.extend(("--quiet", "--no-trunc"))
    listed = client.run(arguments)
    if listed.return_code != 0:
        detail = sanitize_command_error(listed.stderr or listed.stdout)
        raise InventoryError(f"Docker container inventory failed: {detail}")
    containers = []
    for container_id in (line.strip() for line in listed.stdout.splitlines()):
        if not container_id:
            continue
        inspected = client.run(["container", "inspect", container_id])
        if inspected.return_code != 0:
            detail = sanitize_command_error(inspected.stderr or inspected.stdout)
            raise InventoryError(f"Could not inspect container {container_id}: {detail}")
        containers.append(parse_container_inspect(container_id, inspected.stdout))
    return sorted(containers, key=lambda container: container.name)


def decorate_report(
    report: dict[str, Any],
    host_os: HostOsProfile,
    runtime: DockerRuntimeProfile | None,
    container_scope: str,
    warnings: Sequence[str],
) -> dict[str, Any]:
    """Add backward-compatible environment and resource-scope metadata."""

    inventory_mode = runtime.inventory_mode if runtime else "unknown"
    resource_type = "service" if inventory_mode == "swarm" else "container"
    report["environment"] = {
        "host_os": host_os.to_dict(),
        "docker": runtime.to_dict() if runtime else {"inventory_mode": "unknown"},
        "container_scope": container_scope if inventory_mode == "containers" else None,
    }
    report["scope"]["resource_type"] = resource_type
    report["scope"]["resource_count"] = report["scope"]["service_count"]
    report["summary"]["affected_resource_count"] = report["summary"][
        "affected_service_count"
    ]
    report["affected_resources"] = list(report["affected_services"])
    report["warnings"] = list(warnings)
    if inventory_mode == "containers":
        report["policy"]["source"] = "exact-local-image-only"
    return report


def run_security_check(
    client: DockerClient,
    runtime_mode: str = "auto",
    requested_platform: str = "auto",
    host_os_mode: str = "auto",
    container_scope: str = "all",
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
    progress: ProgressCallback | None = None,
    heartbeat_interval_seconds: float = DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
) -> tuple[dict[str, Any], int]:
    """Detect capabilities, inventory applicable workloads, and scan images.

    Args:
        client: Docker command client.
        runtime_mode: Requested inventory mode or capability auto-detection.
        requested_platform: Docker image platform or ``auto``.
        host_os_mode: Host OS detection mode.
        container_scope: Local-container inventory scope.
        qnap_release_paths: Candidate QNAP release files.
        os_release_path: Generic operating-system release file.
        progress: Optional operator-facing progress callback.
        heartbeat_interval_seconds: Seconds between long-running updates.

    Returns:
        Versioned report and exit code: 0 clean, 2 findings, or 3 incomplete.
    """

    started_at = utc_timestamp()
    host_os = detect_host_os(host_os_mode, qnap_release_paths, os_release_path)
    runtime: DockerRuntimeProfile | None = None
    warnings: list[str] = []
    resolved_platform = requested_platform if requested_platform != "auto" else "unknown"
    try:
        if progress:
            progress("[INFO] Detecting Docker runtime and image platform...")
        runtime = detect_docker_runtime(client, runtime_mode)
        resolved_platform = resolve_platform(client, requested_platform)
        if runtime.inventory_mode == "swarm":
            if progress:
                progress("[INFO] Collecting Swarm service image inventory...")
            resources = run_with_progress_heartbeat(
                lambda: collect_services(client),
                progress,
                "[INFO] Swarm service inventory is still running",
                heartbeat_interval_seconds,
            )
            report, exit_code = scan_collected_services(
                client,
                resources,
                resolved_platform,
                started_at,
                progress=progress,
                heartbeat_interval_seconds=heartbeat_interval_seconds,
            )
        else:
            if progress:
                progress(
                    f"[INFO] Collecting {container_scope} local-container image inventory..."
                )
            resources = run_with_progress_heartbeat(
                lambda: collect_containers(client, container_scope),
                progress,
                "[INFO] Local-container inventory is still running",
                heartbeat_interval_seconds,
            )
            report, exit_code = scan_collected_services(
                client,
                resources,
                resolved_platform,
                started_at,
                local_only=True,
                progress=progress,
                heartbeat_interval_seconds=heartbeat_interval_seconds,
            )
            if runtime_mode == "auto":
                warnings.append(
                    "Swarm-wide inventory is unavailable; evidence covers only "
                    f"{container_scope} containers on this Docker node."
                )
    except InventoryError as error:
        report = build_report(
            started_at, resolved_platform, [], [], [], None, str(error)
        )
        exit_code = 3
    return (
        decorate_report(report, host_os, runtime, container_scope, warnings),
        exit_code,
    )


def security_platform_argument(value: str) -> str:
    """Accept ``auto`` or validate an explicit Docker platform."""

    return value if value == "auto" else platform_argument(value)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the compatibility security-check command line."""

    parser = argparse.ArgumentParser(
        description=(
            "Scan Swarm service images on a manager, otherwise scan exact local "
            "container images (including QNAP Container Station)."
        )
    )
    parser.set_defaults(runtime_mode="auto")
    parser.add_argument(
        "--runtime-mode",
        choices=RUNTIME_MODES,
        help="Inventory mode (default: auto capability detection).",
    )
    parser.add_argument(
        "--container-mode",
        action="store_const",
        const="containers",
        dest="runtime_mode",
        help="Alias for --runtime-mode containers.",
    )
    parser.add_argument(
        "--os",
        "--host-os",
        choices=HOST_OS_MODES,
        default="auto",
        dest="host_os",
        help="Host OS hint (default: auto; qnap is supported).",
    )
    parser.add_argument(
        "--container-scope",
        choices=CONTAINER_SCOPES,
        default="all",
        help="Local containers to inspect (default: all).",
    )
    parser.add_argument(
        "--platform",
        type=security_platform_argument,
        default="auto",
        help="Image platform (default: auto from Docker daemon).",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Atomic JSON report path (default: {DEFAULT_OUTPUT_FILE}).",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the capability-aware check and always attempt report publication."""

    options = parse_arguments(arguments)
    report, exit_code = run_security_check(
        DockerClient(),
        runtime_mode=options.runtime_mode,
        requested_platform=options.platform,
        host_os_mode=options.host_os,
        container_scope=options.container_scope,
        progress=lambda message: print(message, flush=True),
    )
    try:
        write_json_atomic(options.output_file, report)
    except (OSError, TypeError) as error:
        print(f"[ERROR] Could not write security report: {error}", file=sys.stderr)
        return 3

    environment = report["environment"]
    host = environment["host_os"]
    resource_type = report["scope"]["resource_type"]
    resource_label = "services" if resource_type == "service" else "containers"
    inventory_label = (
        "Swarm services" if resource_type == "service" else "local containers"
    )
    scope_suffix = (
        f" ({environment['container_scope']})" if resource_type == "container" else ""
    )
    summary = report["summary"]
    version = f" {host['version']}" if host.get("version") else ""
    print(f"Host: {host['name']}{version} [{host['family']}]")
    print(f"Docker inventory: {inventory_label}{scope_suffix}")
    print(
        f"Image security check {summary['status']}: "
        f"{report['scope']['resource_count']} {resource_label}, "
        f"{summary['vulnerable_images']} vulnerable images, "
        f"{summary['clean_images']} clean, {summary['failed_images']} failed."
    )
    print(f"Report written to {options.output_file}")
    for warning in report["warnings"]:
        print(f"[WARN] {warning}", file=sys.stderr)
    for error in report["errors"]:
        print(f"[WARN] {error}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
