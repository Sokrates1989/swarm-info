"""Capability-aware Docker image security checks for Linux hosts.

The command selects a Swarm-wide service inventory only when the local Docker
daemon grants manager control. Otherwise it scans the exact image IDs attached
to local containers. Local-container evidence never falls back to a registry,
because a mutable remote tag may no longer identify the installed artifact.
QNAP CLI execution prepares private, home-backed Docker Scout temporary and
cache directories unless the operator already selected both locations.

Dependencies:
    - Python 3.10 or newer.
    - Docker CLI access to the local Docker daemon.
    - Docker Scout CLI available to the same operating-system user.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from scripts.container_inventory import (
    ContainerFocusError,
    ContainerInventoryFailure,
    collect_container_inventory,
    inspect_container,
    select_containers,
    validate_container_focus,
)
from scripts.operator_report import load_messages, message, safe_text, selected_locale
from scripts.platforms import (
    HOST_OS_MODES,
    OS_RELEASE_PATH,
    QNAP_RELEASE_PATHS,
    DockerRuntimeProfile,
    HostOsProfile,
    detect_docker_runtime,
    detect_host_os,
    platform_adapter_for,
    resolve_platform,
)
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


DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent / "swarm_info" / "security_scan.json"
)
DEFAULT_FOCUSED_OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "swarm_info"
    / "security_scan_focused.json"
)
RUNTIME_MODES = ("auto", "swarm", "containers")
CONTAINER_SCOPES = ("all", "running")
DEFAULT_SCOUT_TIMEOUT_MINUTES = 45.0
DEFAULT_SCAN_BUDGET_MINUTES = 240.0


def prepare_qnap_scout_client(
    client: DockerClient,
    host_os: HostOsProfile,
    environment: Mapping[str, str],
) -> tuple[DockerClient, dict[str, str] | None]:
    """Retain the public helper while delegating storage behavior to the adapter."""

    return platform_adapter_for(host_os).prepare_scout_client(client, environment)


def decorate_report(
    report: dict[str, Any],
    host_os: HostOsProfile,
    runtime: DockerRuntimeProfile | None,
    container_scope: str,
    warnings: Sequence[str],
    scout_work: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Add backward-compatible environment and resource-scope metadata."""

    inventory_mode = runtime.inventory_mode if runtime else "unknown"
    resource_type = "service" if inventory_mode == "swarm" else "container"
    report["environment"] = {
        "host_os": host_os.to_dict(),
        "docker": runtime.to_dict() if runtime else {"inventory_mode": "unknown"},
        "container_scope": container_scope if inventory_mode == "containers" else None,
        "docker_scout_work": dict(scout_work) if scout_work else None,
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


def annotate_container_focus(
    report: dict[str, Any],
    kind: str,
    selector: str,
    inventory_resource_count: int,
) -> None:
    """Mark container-focused evidence as separate from a full security report."""

    report["scope"].update(
        {
            "coverage": "focused",
            "selector": {"type": kind, "value": selector},
            "inventory_resource_count": inventory_resource_count,
        }
    )


def annotate_inventory_failures(
    report: dict[str, Any], failures: Sequence[ContainerInventoryFailure]
) -> None:
    """Preserve partial scan results while marking unreadable inventory incomplete."""

    report["inventory_errors"] = [failure.to_dict() for failure in failures]
    report["scope"]["inventory_failure_count"] = len(failures)
    report["scope"]["inventory_resource_count"] = (
        report["scope"]["service_count"] + len(failures)
    )
    if not failures:
        return
    known_errors = list(report.get("errors") or [])
    for failure in failures:
        if failure.error not in known_errors:
            known_errors.append(failure.error)
    report["errors"] = known_errors
    report["summary"]["complete"] = False
    report["summary"]["status"] = "incomplete"


def container_focus_error_report(
    started_at: str,
    platform: str,
    error: ContainerFocusError,
) -> dict[str, Any]:
    """Build machine-readable incomplete evidence for one invalid focus request."""

    report = build_report(
        started_at,
        platform,
        [],
        [],
        [],
        None,
        f"container-focus-{error.code}",
    )
    report["focus_error"] = {
        "code": error.code,
        "selector": error.selector,
        "matches": list(error.matches),
    }
    return report


def collect_focused_containers(
    client: DockerClient,
    scope: str,
    kind: str,
    selector: str,
) -> tuple[list[ServiceRecord], tuple[ContainerInventoryFailure, ...], int]:
    """Resolve focused local evidence without inspecting unrelated containers."""

    selected = validate_container_focus(kind, selector)
    if kind == "container":
        container = inspect_container(client, selected)
        if scope == "running" and container.running is not True:
            if container.running is False:
                raise ContainerFocusError("container-not-found", selected)
            raise InventoryError(
                f"Docker did not report whether container {selected} is running."
            )
        return [container], (), 1

    inventory = collect_container_inventory(
        client,
        scope,
        ancestor_image_id=selected,
    )
    if inventory.failures and not inventory.containers:
        raise InventoryError(inventory.failures[0].error)
    containers = select_containers(inventory.containers, kind, selected)
    return (
        containers,
        inventory.failures,
        len(inventory.containers) + len(inventory.failures),
    )


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
    process_environment: Mapping[str, str] | None = None,
    focus_kind: str | None = None,
    focus_selector: str | None = None,
    scan_budget_seconds: float | None = None,
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
        process_environment: Optional environment enabling QNAP Scout storage
            preparation. The CLI passes its process environment; embedded tests
            and callers can omit it to avoid filesystem side effects.
        focus_kind: Optional exact local selector type: container or image-id.
        focus_selector: Selector value paired with ``focus_kind``.
        scan_budget_seconds: Optional overall image-scanning time budget.

    Returns:
        Versioned report and exit code: 0 clean, 2 findings, or 3 incomplete.
    """

    started_at = utc_timestamp()
    host_os = detect_host_os(host_os_mode, qnap_release_paths, os_release_path)
    runtime: DockerRuntimeProfile | None = None
    scout_work: dict[str, str] | None = None
    warnings: list[str] = []
    inventory_failures: tuple[ContainerInventoryFailure, ...] = ()
    inventory_resource_count = 0
    resolved_platform = requested_platform if requested_platform != "auto" else "unknown"
    try:
        if process_environment is not None:
            client, scout_work = prepare_qnap_scout_client(
                client, host_os, process_environment
            )
        if progress:
            progress("[INFO] Detecting Docker runtime and image platform...")
        effective_runtime_mode = (
            "containers" if focus_kind and runtime_mode == "auto" else runtime_mode
        )
        runtime = detect_docker_runtime(client, effective_runtime_mode)
        resolved_platform = resolve_platform(client, requested_platform)
        if runtime.inventory_mode == "swarm":
            if focus_kind:
                raise InventoryError(
                    "Container-focused checks require local-container inventory mode."
                )
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
                scan_budget_seconds=scan_budget_seconds,
            )
        else:
            if progress:
                if focus_kind:
                    progress(
                        message(
                            load_messages(selected_locale(process_environment)),
                            f"security.focusInventory.{focus_kind}",
                        )
                    )
                else:
                    progress(
                        f"[INFO] Collecting {container_scope} local-container image inventory..."
                    )
            if focus_kind and focus_selector is not None:
                resources, inventory_failures, inventory_resource_count = (
                    run_with_progress_heartbeat(
                        lambda: collect_focused_containers(
                            client,
                            container_scope,
                            focus_kind,
                            focus_selector,
                        ),
                        progress,
                        "[INFO] Focused local-container inventory is still running",
                        heartbeat_interval_seconds,
                    )
                )
            else:
                inventory = run_with_progress_heartbeat(
                    lambda: collect_container_inventory(client, container_scope),
                    progress,
                    "[INFO] Local-container inventory is still running",
                    heartbeat_interval_seconds,
                )
                resources = list(inventory.containers)
                inventory_failures = inventory.failures
                inventory_resource_count = len(resources) + len(inventory_failures)
            report, exit_code = scan_collected_services(
                client,
                resources,
                resolved_platform,
                started_at,
                local_only=True,
                progress=progress,
                heartbeat_interval_seconds=heartbeat_interval_seconds,
                scan_budget_seconds=scan_budget_seconds,
            )
            annotate_inventory_failures(report, inventory_failures)
            if inventory_failures:
                exit_code = 3
            if runtime_mode == "auto":
                warnings.append(
                    "Swarm-wide inventory is unavailable; evidence covers only "
                    f"{container_scope} containers on this Docker node."
                )
    except ContainerFocusError as error:
        report = container_focus_error_report(
            started_at, resolved_platform, error
        )
        exit_code = 3
    except InventoryError as error:
        report = build_report(
            started_at, resolved_platform, [], [], [], None, str(error)
        )
        exit_code = 3
    decorated = decorate_report(
        report,
        host_os,
        runtime,
        container_scope,
        warnings,
        scout_work,
    )
    if focus_kind and focus_selector is not None:
        annotate_container_focus(
            decorated, focus_kind, focus_selector, inventory_resource_count
        )
    return decorated, exit_code


def security_platform_argument(value: str) -> str:
    """Accept ``auto`` or validate an explicit Docker platform."""

    return value if value == "auto" else platform_argument(value)


def positive_minutes(value: str) -> float:
    """Parse one positive finite minute value for execution limits."""

    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a number") from error
    if parsed <= 0 or parsed == float("inf") or parsed != parsed:
        raise argparse.ArgumentTypeError("value must be a positive finite number")
    return parsed


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
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
    focus = parser.add_mutually_exclusive_group()
    focus.add_argument(
        "--container",
        help=message(catalog, "security.containerOption"),
    )
    focus.add_argument(
        "--image-id",
        help=message(catalog, "security.imageIdOption"),
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
        help=message(catalog, "security.outputOption"),
    )
    parser.add_argument(
        "--scout-timeout-minutes",
        type=positive_minutes,
        default=DEFAULT_SCOUT_TIMEOUT_MINUTES,
        help=message(catalog, "securityJob.help.scoutTimeout"),
    )
    parser.add_argument(
        "--scan-budget-minutes",
        type=positive_minutes,
        default=DEFAULT_SCAN_BUDGET_MINUTES,
        help=message(catalog, "securityJob.help.scanBudget"),
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the capability-aware check and always attempt report publication."""

    catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, catalog)
    focus_kind = "container" if options.container is not None else None
    focus_selector = options.container
    if options.image_id is not None:
        focus_kind = "image-id"
        focus_selector = options.image_id
    output_file = options.output_file or (
        DEFAULT_FOCUSED_OUTPUT_FILE if focus_kind else DEFAULT_OUTPUT_FILE
    )
    if focus_kind and focus_selector is not None:
        print(
            message(
                catalog,
                "security.focusStarting",
                kind=message(catalog, f"security.focusKind.{focus_kind}"),
                selector=safe_text(focus_selector),
            ),
            flush=True,
        )
    report, exit_code = run_security_check(
        DockerClient(scout_timeout_seconds=options.scout_timeout_minutes * 60),
        runtime_mode=options.runtime_mode,
        requested_platform=options.platform,
        host_os_mode=options.host_os,
        container_scope=options.container_scope,
        progress=lambda message: print(message, flush=True),
        process_environment=os.environ,
        focus_kind=focus_kind,
        focus_selector=focus_selector,
        scan_budget_seconds=options.scan_budget_minutes * 60,
    )
    try:
        write_json_atomic(output_file, report)
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
    print(f"Report written to {output_file}")
    focus_error = report.get("focus_error")
    if isinstance(focus_error, Mapping):
        code = safe_text(focus_error.get("code"))
        matches = focus_error.get("matches")
        match_values = (
            matches
            if isinstance(matches, Sequence) and not isinstance(matches, (str, bytes))
            else []
        )
        examples = ", ".join(safe_text(item) for item in match_values)
        key = f"security.focusError.{code}"
        if key not in catalog:
            key = "security.focusError.unknown"
        print(
            message(
                catalog,
                key,
                selector=safe_text(focus_error.get("selector")),
                examples=examples or message(catalog, "common.none"),
            ),
            file=sys.stderr,
        )
    for warning in report["warnings"]:
        print(f"[WARN] {warning}", file=sys.stderr)
    for error in report["errors"]:
        if not str(error).startswith("container-focus-"):
            print(f"[WARN] {error}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
