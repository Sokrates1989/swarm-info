"""Run bounded, cache-aware local-container security jobs.

The job is the unattended execution boundary for standalone Linux and QNAP.
It inventories local containers without changing them, scans exact local image
IDs serially, publishes reports atomically, reuses matching fresh evidence,
retains history, and prevents overlapping Scout work.

Dependencies:
    - Python 3.10 or newer on a POSIX host.
    - Docker daemon access and Docker Scout for the same operating-system user.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from scripts.container_inventory import (
    ContainerInventoryFailure,
    collect_container_inventory,
)
from scripts.operator_report import load_messages, message, selected_locale
from scripts.security_check import (
    CONTAINER_SCOPES,
    DEFAULT_SCAN_BUDGET_MINUTES,
    DEFAULT_SCOUT_TIMEOUT_MINUTES,
    HOST_OS_MODES,
    OS_RELEASE_PATH,
    QNAP_RELEASE_PATHS,
    DEFAULT_OUTPUT_FILE,
    DockerRuntimeProfile,
    HostOsProfile,
    annotate_inventory_failures,
    decorate_report,
    detect_docker_runtime,
    detect_host_os,
    prepare_qnap_scout_client,
    resolve_platform,
    security_platform_argument,
)
from scripts.vulnerability_job import (
    DEFAULT_HISTORY_DAYS,
    ScanLock,
    cached_report_is_fresh,
    inspect_freshness,
    positive_float,
    positive_integer,
    print_report_result,
    publish_report,
    read_report,
    report_exit_code,
    utc_now,
)
from scripts.vulnerability_models import (
    ServiceRecord,
    build_report,
    group_image_targets,
    image_scope_fingerprint,
    utc_timestamp,
)
from scripts.vulnerability_scan import (
    DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
    DockerClient,
    InventoryError,
    ProgressCallback,
    scan_collected_services,
)


DEFAULT_SECURITY_CACHE_AGE_HOURS = 72.0
DEFAULT_SECURITY_MAX_AGE_HOURS = 96.0


@dataclasses.dataclass(frozen=True)
class SecurityJobInventory:
    """Hold one already-collected local-container scan scope.

    Attributes:
        client: Docker client configured for QNAP work storage and Scout timeout.
        host_os: Detected or operator-selected host profile.
        runtime: Explicit local-container runtime decision.
        platform: Resolved Docker image platform.
        container_scope: ``running`` or ``all`` inventory selection.
        resources: Readable container records.
        failures: Containers Docker could not inspect safely.
        inventory_resource_count: Readable plus unreadable container count.
        scout_work: Auditable QNAP temporary/cache directory selection.
    """

    client: DockerClient
    host_os: HostOsProfile
    runtime: DockerRuntimeProfile
    platform: str
    container_scope: str
    resources: tuple[ServiceRecord, ...]
    failures: tuple[ContainerInventoryFailure, ...]
    inventory_resource_count: int
    scout_work: Mapping[str, str] | None


def validate_security_job_policy(
    cache_age_hours: float,
    max_age_hours: float,
    scout_timeout_minutes: float,
    scan_budget_minutes: float,
    catalog: Mapping[str, str],
) -> None:
    """Reject contradictory cache, freshness, and execution limits."""

    if cache_age_hours >= max_age_hours:
        raise ValueError(message(catalog, "securityJob.invalidFreshness"))
    if scan_budget_minutes < scout_timeout_minutes:
        raise ValueError(message(catalog, "securityJob.invalidBudget"))


def security_cache_is_fresh(
    report: Mapping[str, Any] | None,
    fingerprint: str,
    platform: str,
    container_scope: str,
    cache_age_hours: float,
    scout_timeout_minutes: float,
    scan_budget_minutes: float,
    now: dt.datetime,
) -> bool:
    """Validate cached evidence against the exact local-container contract.

    Args:
        report: Existing parsed report, when available.
        fingerprint: Current resource-to-image scope fingerprint.
        platform: Resolved image platform.
        container_scope: Requested local-container scope.
        cache_age_hours: Maximum completed-report age eligible for reuse.
        scout_timeout_minutes: Required per-image timeout used by the evidence.
        scan_budget_minutes: Required overall scan budget used by the evidence.
        now: Timezone-aware cache reference time.

    Returns:
        ``True`` only for complete matching full-container evidence.
    """

    if not cached_report_is_fresh(
        report, fingerprint, platform, cache_age_hours, now
    ):
        return False
    if report is None:
        return False
    environment = report.get("environment")
    scope = report.get("scope")
    policy = report.get("policy")
    if (
        not isinstance(environment, Mapping)
        or not isinstance(scope, Mapping)
        or not isinstance(policy, Mapping)
    ):
        return False
    docker = environment.get("docker")
    return (
        isinstance(docker, Mapping)
        and docker.get("inventory_mode") == "containers"
        and environment.get("container_scope") == container_scope
        and scope.get("coverage", "full") == "full"
        and policy.get("scout_timeout_minutes") == scout_timeout_minutes
        and policy.get("scan_budget_minutes") == scan_budget_minutes
    )


def collect_security_job_inventory(
    client: DockerClient,
    requested_platform: str,
    host_os_mode: str,
    container_scope: str,
    process_environment: Mapping[str, str],
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
    progress: ProgressCallback | None = None,
) -> SecurityJobInventory:
    """Collect one local-container scope without invoking Docker Scout.

    Args:
        client: Docker client carrying the configured Scout timeout.
        requested_platform: Explicit image platform or ``auto``.
        host_os_mode: Host hint: ``auto``, ``qnap``, or ``linux``.
        container_scope: Local inventory selection.
        process_environment: Environment used for QNAP Scout storage.
        qnap_release_paths: Candidate QNAP release files.
        os_release_path: Generic Linux release file.
        progress: Optional operator-facing progress callback.

    Returns:
        Immutable inventory context suitable for cache comparison and scanning.

    Raises:
        InventoryError: If Docker capability, platform, or inventory fails.
    """

    host_os = detect_host_os(host_os_mode, qnap_release_paths, os_release_path)
    configured_client, scout_work = prepare_qnap_scout_client(
        client, host_os, process_environment
    )
    runtime = detect_docker_runtime(configured_client, "containers")
    platform = resolve_platform(configured_client, requested_platform)
    if progress:
        catalog = load_messages(selected_locale(process_environment))
        progress(message(catalog, "securityJob.inventory", scope=container_scope))
    inventory = collect_container_inventory(configured_client, container_scope)
    resources = tuple(inventory.containers)
    failures = tuple(inventory.failures)
    return SecurityJobInventory(
        client=configured_client,
        host_os=host_os,
        runtime=runtime,
        platform=platform,
        container_scope=container_scope,
        resources=resources,
        failures=failures,
        inventory_resource_count=len(resources) + len(failures),
        scout_work=scout_work,
    )


def add_execution_policy(
    report: dict[str, Any],
    scout_timeout_minutes: float,
    scan_budget_minutes: float,
) -> None:
    """Record the unattended execution bounds in machine-readable evidence."""

    report["policy"]["scout_timeout_minutes"] = scout_timeout_minutes
    report["policy"]["scan_budget_minutes"] = scan_budget_minutes


def scan_security_job_inventory(
    inventory: SecurityJobInventory,
    started_at: str,
    scout_timeout_minutes: float,
    scan_budget_minutes: float,
    progress: ProgressCallback | None = None,
) -> tuple[dict[str, Any], int]:
    """Scan one collected scope and apply QNAP/container report metadata.

    Args:
        inventory: Previously collected exact local-container scope.
        started_at: Canonical UTC start timestamp.
        scout_timeout_minutes: Per-image Scout command limit.
        scan_budget_minutes: Overall image-scanning budget.
        progress: Optional operator-facing progress callback.

    Returns:
        Decorated report and the public 0/2/3 exit status.
    """

    report, exit_code = scan_collected_services(
        inventory.client,
        inventory.resources,
        inventory.platform,
        started_at,
        local_only=True,
        progress=progress,
        heartbeat_interval_seconds=DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
        scan_budget_seconds=scan_budget_minutes * 60,
    )
    annotate_inventory_failures(report, inventory.failures)
    if inventory.failures:
        exit_code = 3
    decorated = decorate_report(
        report,
        inventory.host_os,
        inventory.runtime,
        inventory.container_scope,
        (),
        inventory.scout_work,
    )
    add_execution_policy(decorated, scout_timeout_minutes, scan_budget_minutes)
    return decorated, exit_code


def execute_security_job(
    output_file: Path,
    requested_platform: str,
    host_os_mode: str,
    container_scope: str,
    max_age_hours: float,
    history_days: int,
    force: bool,
    client: DockerClient,
    process_environment: Mapping[str, str],
    now: dt.datetime,
    cache_age_hours: float,
    scout_timeout_minutes: float,
    scan_budget_minutes: float,
    progress: ProgressCallback | None = None,
    qnap_release_paths: Sequence[Path] = QNAP_RELEASE_PATHS,
    os_release_path: Path = OS_RELEASE_PATH,
) -> int:
    """Inventory, reuse or scan, and publish while the caller owns the lock.

    Returns:
        0 for clean/reused clean, 2 for complete findings, or 3 for incomplete.
    """

    previous_report = read_report(output_file)
    started_at = utc_timestamp()
    try:
        inventory = collect_security_job_inventory(
            client,
            requested_platform,
            host_os_mode,
            container_scope,
            process_environment,
            qnap_release_paths,
            os_release_path,
            progress,
        )
    except InventoryError as error:
        host_os = detect_host_os(
            host_os_mode, qnap_release_paths, os_release_path
        )
        report = build_report(
            started_at,
            requested_platform if requested_platform != "auto" else "unknown",
            [],
            [],
            [],
            None,
            str(error),
        )
        report = decorate_report(
            report, host_os, None, container_scope, (), None
        )
        add_execution_policy(report, scout_timeout_minutes, scan_budget_minutes)
        publish_report(
            output_file, report, previous_report, max_age_hours, history_days, now
        )
        print_report_result(report, output_file)
        return 3

    targets = group_image_targets(inventory.resources)
    fingerprint = image_scope_fingerprint(targets)
    if not force and security_cache_is_fresh(
        previous_report,
        fingerprint,
        inventory.platform,
        container_scope,
        cache_age_hours,
        scout_timeout_minutes,
        scan_budget_minutes,
        now,
    ):
        catalog = load_messages(selected_locale(process_environment))
        print(message(catalog, "securityJob.cacheReuse", path=output_file))
        print_report_result(previous_report or {}, output_file)
        return report_exit_code(previous_report or {})

    report, exit_code = scan_security_job_inventory(
        inventory,
        started_at,
        scout_timeout_minutes,
        scan_budget_minutes,
        progress,
    )
    publish_report(
        output_file, report, previous_report, max_age_hours, history_days, now
    )
    print_report_result(report, output_file)
    return exit_code


def run_locked_security_job(
    output_file: Path,
    requested_platform: str,
    host_os_mode: str,
    container_scope: str,
    max_age_hours: float,
    history_days: int,
    force: bool,
    lock_file: Path | None = None,
    client: DockerClient | None = None,
    process_environment: Mapping[str, str] | None = None,
    now: dt.datetime | None = None,
    cache_age_hours: float = DEFAULT_SECURITY_CACHE_AGE_HOURS,
    scout_timeout_minutes: float = DEFAULT_SCOUT_TIMEOUT_MINUTES,
    scan_budget_minutes: float = DEFAULT_SCAN_BUDGET_MINUTES,
    progress: ProgressCallback | None = None,
) -> int:
    """Run or reuse one bounded local-container scan under a non-blocking lock.

    Returns:
        0 for clean/skipped, 2 for findings, or 3 for incomplete/failure.
    """

    environment = dict(os.environ if process_environment is None else process_environment)
    selected_client = (client or DockerClient()).with_scout_timeout(
        scout_timeout_minutes * 60
    )
    selected_lock = lock_file or output_file.with_suffix(output_file.suffix + ".lock")
    lock = ScanLock(selected_lock)
    catalog = load_messages(selected_locale(environment))
    try:
        if not lock.acquire():
            print(message(catalog, "securityJob.locked", path=selected_lock))
            return 0
        return execute_security_job(
            output_file,
            requested_platform,
            host_os_mode,
            container_scope,
            max_age_hours,
            history_days,
            force,
            selected_client,
            environment,
            now or utc_now(),
            cache_age_hours,
            scout_timeout_minutes,
            scan_budget_minutes,
            progress,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(
            message(catalog, "securityJob.failed", detail=error),
            file=sys.stderr,
        )
        return 3
    finally:
        lock.release()


def add_report_arguments(
    parser: argparse.ArgumentParser,
    catalog: Mapping[str, str],
) -> None:
    """Add report destination and freshness arguments to one parser."""

    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=message(catalog, "securityJob.help.output"),
    )
    parser.add_argument(
        "--max-age-hours",
        type=positive_float,
        default=DEFAULT_SECURITY_MAX_AGE_HOURS,
        help=message(catalog, "securityJob.help.freshness"),
    )


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse scheduled job or status-inspection arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    add_report_arguments(run_parser, catalog)
    run_parser.add_argument(
        "--platform",
        type=security_platform_argument,
        default="auto",
        help=message(catalog, "securityJob.help.platform"),
    )
    run_parser.add_argument(
        "--os",
        choices=HOST_OS_MODES,
        default="auto",
        dest="host_os",
        help=message(catalog, "securityJob.help.hostOs"),
    )
    run_parser.add_argument(
        "--container-scope",
        choices=CONTAINER_SCOPES,
        default="running",
        help=message(catalog, "securityJob.help.scope"),
    )
    run_parser.add_argument(
        "--cache-age-hours",
        type=positive_float,
        default=DEFAULT_SECURITY_CACHE_AGE_HOURS,
        help=message(catalog, "securityJob.help.cache"),
    )
    run_parser.add_argument(
        "--history-days",
        type=positive_integer,
        default=DEFAULT_HISTORY_DAYS,
        help=message(catalog, "securityJob.help.history"),
    )
    run_parser.add_argument(
        "--lock-file",
        type=Path,
        help=message(catalog, "securityJob.help.lock"),
    )
    run_parser.add_argument(
        "--scout-timeout-minutes",
        type=positive_float,
        default=DEFAULT_SCOUT_TIMEOUT_MINUTES,
        help=message(catalog, "securityJob.help.scoutTimeout"),
    )
    run_parser.add_argument(
        "--scan-budget-minutes",
        type=positive_float,
        default=DEFAULT_SCAN_BUDGET_MINUTES,
        help=message(catalog, "securityJob.help.scanBudget"),
    )
    run_parser.add_argument(
        "--force",
        action="store_true",
        help=message(catalog, "securityJob.help.force"),
    )
    status_parser = commands.add_parser("status")
    add_report_arguments(status_parser, catalog)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the requested scheduled-security operation."""

    catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, catalog)
    if options.command == "status":
        return inspect_freshness(options.output_file, options.max_age_hours)
    try:
        validate_security_job_policy(
            options.cache_age_hours,
            options.max_age_hours,
            options.scout_timeout_minutes,
            options.scan_budget_minutes,
            catalog,
        )
    except ValueError as error:
        print(message(catalog, "securityJob.failed", detail=error), file=sys.stderr)
        return 64
    return run_locked_security_job(
        options.output_file,
        options.platform,
        options.host_os,
        options.container_scope,
        options.max_age_hours,
        options.history_days,
        options.force,
        options.lock_file,
        cache_age_hours=options.cache_age_hours,
        scout_timeout_minutes=options.scout_timeout_minutes,
        scan_budget_minutes=options.scan_budget_minutes,
        progress=lambda text: print(text, flush=True),
    )


if __name__ == "__main__":
    raise SystemExit(main())
