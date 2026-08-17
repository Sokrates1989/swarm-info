"""Render concise operator pages from health and Docker Scout evidence.

The renderer is read-only: it never contacts Docker, changes service replicas,
or launches a vulnerability scan. Bash workflow pages own those side effects
and pass an explicit report path into this module.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any, Mapping, Sequence


LOCALE_DIRECTORY = Path(__file__).resolve().parent / "locales"
SUPPORTED_LOCALES = ("en", "de")


def selected_locale(environment: Mapping[str, str] | None = None) -> str:
    """Select German for a German process locale and English otherwise."""

    values = os.environ if environment is None else environment
    locale = values.get("SWARM_INFO_LOCALE") or values.get("LANG", "en")
    return "de" if locale.lower().startswith("de") else "en"


def load_messages(locale: str | None = None) -> dict[str, str]:
    """Load one complete locale catalog from the repository."""

    selected = locale or selected_locale()
    if selected not in SUPPORTED_LOCALES:
        selected = "en"
    payload = json.loads(
        (LOCALE_DIRECTORY / f"{selected}.json").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in payload.items()
    ):
        raise ValueError(f"Invalid locale catalog: {selected}")
    return payload


def message(catalog: Mapping[str, str], key: str, **values: object) -> str:
    """Format one required localized message with named values."""

    return catalog[key].format(**values)


def read_mapping(path: Path) -> dict[str, Any] | None:
    """Read a JSON object, returning ``None`` for absent or invalid data."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def parse_timestamp(value: object) -> dt.datetime | None:
    """Parse Unix seconds or an ISO-8601 value into an aware UTC datetime."""

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def age_text(value: dt.datetime | None, now: dt.datetime) -> str:
    """Format evidence age compactly without locale-sensitive date APIs."""

    if value is None:
        return "unknown"
    seconds = max(0, int((now - value).total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def safe_text(value: object) -> str:
    """Strip terminal control characters from untrusted report strings."""

    return "".join(
        character
        for character in str(value)
        if character >= " " and character != "\x7f"
    ).strip()


def nonnegative_integer(value: object) -> int:
    """Normalize a report count without accepting booleans or negatives."""

    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def report_resource_type(report: Mapping[str, Any] | None) -> str:
    """Return the normalized workload type carried by one scan report."""

    if report is None:
        return "unknown"
    scope = report.get("scope")
    if not isinstance(scope, Mapping):
        return "unknown"
    resource_type = scope.get("resource_type")
    return resource_type if resource_type in {"service", "container"} else "service"


def report_container_scope(report: Mapping[str, Any] | None) -> str:
    """Return the all/running container scope, defaulting safely to running."""

    if report is None:
        return "running"
    environment = report.get("environment")
    if not isinstance(environment, Mapping):
        return "running"
    scope = environment.get("container_scope")
    return scope if scope in {"all", "running"} else "running"


def render_service_health(
    report: Mapping[str, Any], catalog: Mapping[str, str], now: dt.datetime
) -> tuple[str, int]:
    """Render aggregate health plus only services requiring attention."""

    summary = report.get("summary")
    services = report.get("services")
    timestamp = report.get("timestamp")
    if not isinstance(summary, Mapping) or not isinstance(services, Sequence):
        raise ValueError("invalid health report")
    observed = parse_timestamp(
        timestamp.get("unix_format") if isinstance(timestamp, Mapping) else None
    )
    observed_label = (
        safe_text(timestamp.get("human_readable_format", "unknown"))
        if isinstance(timestamp, Mapping)
        else "unknown"
    )
    lines = [message(catalog, "health.title"), "-" * 70]
    lines.append(
        message(
            catalog,
            "health.report",
            timestamp=observed_label,
            age=age_text(observed, now),
        )
    )
    lines.append(
        message(
            catalog,
            "health.summary",
            total=nonnegative_integer(summary.get("total_services")),
            healthy=nonnegative_integer(summary.get("healthy")),
            degraded=nonnegative_integer(summary.get("degraded")),
            down=nonnegative_integer(summary.get("down")),
        )
    )
    unhealthy = [
        service
        for service in services
        if isinstance(service, Mapping) and service.get("healthy") is not True
    ]
    lines.append("")
    if not unhealthy:
        lines.append(f"✅ {message(catalog, 'health.allHealthy')}")
        return "\n".join(lines), 0
    lines.append(message(catalog, "health.needsAttention"))
    for service in unhealthy:
        status = safe_text(service.get("status", "unknown"))
        lines.append(
            message(
                catalog,
                "health.service",
                icon="❌" if status == "down" else "⚠️",
                name=safe_text(service.get("name", "unknown")),
                status=status,
                running=nonnegative_integer(service.get("replicas_running")),
                expected=nonnegative_integer(
                    service.get(
                        "monitoring_expected_replicas",
                        service.get("replicas_desired"),
                    )
                ),
                failures=nonnegative_integer(service.get("recent_failures")),
            )
        )
    lines.extend(
        [
            "",
            message(catalog, "health.followUp"),
            f"  {message(catalog, 'health.followUpCommand')}",
            message(catalog, "health.refresh"),
            f"  {message(catalog, 'health.refreshCommand')}",
        ]
    )
    return "\n".join(lines), 2


def vulnerability_state(
    report: Mapping[str, Any], now: dt.datetime, max_age_hours: float
) -> tuple[str, dt.datetime | None]:
    """Classify completeness and freshness of one scanner report."""

    summary = report.get("summary")
    completed = parse_timestamp(report.get("completed_at"))
    if not isinstance(summary, Mapping) or completed is None:
        return "invalid", completed
    if summary.get("complete") is not True or summary.get("status") == "incomplete":
        return "incomplete", completed
    if now - completed > dt.timedelta(hours=max_age_hours):
        return "stale", completed
    status = summary.get("status")
    return (status if status in {"clean", "vulnerable"} else "invalid"), completed


def scan_guidance(
    catalog: Mapping[str, str],
    report_path: Path,
    report: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return a warned, copy-ready scan action for unavailable evidence."""

    quoted_path = shlex.quote(str(report_path))
    is_container = (
        report_resource_type(report) == "container"
        or report_path.name.startswith("security_scan")
    )
    warning_key = (
        "vulnerability.containerScanWarning"
        if is_container
        else "vulnerability.scanWarning"
    )
    command_key = (
        "vulnerability.containerScanCommand"
        if is_container
        else "vulnerability.scanCommand"
    )
    return [
        message(catalog, warning_key),
        message(catalog, "vulnerability.scanOffer"),
        f"  {message(catalog, command_key, path=quoted_path)}",
    ]


def vulnerable_image_records(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return only normalized mappings marked vulnerable by the scanner."""

    images = report.get("images")
    if not isinstance(images, Sequence) or isinstance(images, (str, bytes)):
        return []
    return [
        image
        for image in images
        if isinstance(image, Mapping) and image.get("status") == "vulnerable"
    ]


def image_resource_names(image: Mapping[str, Any]) -> list[str]:
    """Return sanitized workload names mapped to one image record."""

    services = image.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        return []
    return [
        safe_text(service.get("name", "unknown"))
        for service in services
        if isinstance(service, Mapping)
    ]


def image_compose_owners(image: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return unique validated Compose ownership records for one image."""

    services = image.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        return []
    owners: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for service in services:
        if not isinstance(service, Mapping):
            continue
        project = safe_text(service.get("stack"))
        compose_service = safe_text(service.get("compose_service"))
        working_dir = safe_text(service.get("compose_working_dir"))
        raw_files = service.get("compose_config_files")
        file_values = (
            raw_files
            if isinstance(raw_files, Sequence)
            and not isinstance(raw_files, (str, bytes))
            else ()
        )
        files = tuple(
            safe_text(path)
            for path in file_values
            if safe_text(path)
        )
        if not any((project, compose_service, working_dir, files)):
            continue
        identity = (project, compose_service, working_dir, files)
        if identity in seen:
            continue
        seen.add(identity)
        owners.append(
            {
                "project": project or "unknown",
                "service": compose_service or "unknown",
                "working_dir": working_dir or "unknown",
                "config_files": files,
            }
        )
    return owners


def compose_redeploy_commands(image: Mapping[str, Any]) -> tuple[str, str, str]:
    """Build copy-ready Compose directory, pull, and one-service redeploy commands."""

    owners = image_compose_owners(image)
    actionable_owner = next(
        (
            owner
            for owner in owners
            if owner["working_dir"] != "unknown"
            and owner["service"] != "unknown"
        ),
        None,
    )
    if actionable_owner is None:
        return (
            "cd <COMPOSE_WORKING_DIR>",
            "docker compose -f <COMPOSE_FILE> pull <COMPOSE_SERVICE>",
            "docker compose -f <COMPOSE_FILE> up -d --no-deps --force-recreate <COMPOSE_SERVICE>",
        )
    owner = actionable_owner
    files = owner["config_files"]
    file_arguments = " ".join(f"-f {shlex.quote(path)}" for path in files)
    command_prefix = f"docker compose {file_arguments}".rstrip()
    compose_service = shlex.quote(owner["service"])
    return (
        f"cd {shlex.quote(owner['working_dir'])}",
        f"{command_prefix} pull {compose_service}",
        f"{command_prefix} up -d --no-deps --force-recreate {compose_service}",
    )


def container_failure_guidance(
    report: Mapping[str, Any], catalog: Mapping[str, str]
) -> list[str]:
    """Render actionable recovery only for unavailable exact local images."""

    images = report.get("images")
    if not isinstance(images, Sequence) or isinstance(images, (str, bytes)):
        return []
    failed = [
        image
        for image in images
        if isinstance(image, Mapping)
        and image.get("error_code") == "local-image-unavailable"
    ]
    if not failed:
        return []
    lines = ["", message(catalog, "vulnerability.localImageUnavailableTitle")]
    for image in failed[:5]:
        lines.append(
            message(
                catalog,
                "vulnerability.localImageUnavailable",
                image=safe_text(image.get("reference", "unknown")),
                image_id=safe_text(image.get("local_image_id", "unknown")),
                containers=", ".join(image_resource_names(image))
                or message(catalog, "common.none"),
            )
        )
        for owner in image_compose_owners(image)[:3]:
            lines.append(
                message(
                    catalog,
                    "vulnerability.imageCompose",
                    project=owner["project"],
                    service=owner["service"],
                    directory=owner["working_dir"],
                    files=", ".join(owner["config_files"])
                    or message(catalog, "common.none"),
                )
            )
    directory_command, pull_command, deploy_command = compose_redeploy_commands(
        failed[0]
    )
    lines.extend(
        [
            message(catalog, "vulnerability.localImageUnavailableRecovery"),
            f"  {directory_command}",
            f"  {pull_command}",
            f"  {deploy_command}",
        ]
    )
    return lines


def render_vulnerabilities(
    report: Mapping[str, Any] | None,
    report_path: Path,
    catalog: Mapping[str, str],
    now: dt.datetime,
    max_age_hours: float,
) -> tuple[str, int]:
    """Render fresh risk evidence and concrete remediation commands."""

    is_container = (
        report_resource_type(report) == "container"
        or report_path.name.startswith("security_scan")
    )
    title_key = (
        "vulnerability.containerTitle" if is_container else "vulnerability.title"
    )
    lines = [message(catalog, title_key), "-" * 70]
    if report is None:
        lines.append(message(catalog, "vulnerability.missing"))
        lines.extend(["", *scan_guidance(catalog, report_path, report)])
        return "\n".join(lines), 3
    state, completed = vulnerability_state(report, now, max_age_hours)
    if state in {"invalid", "incomplete", "stale"}:
        if state == "stale":
            lines.append(
                message(
                    catalog,
                    "vulnerability.stale",
                    age=age_text(completed, now),
                    limit=f"{max_age_hours:g}",
                )
            )
        else:
            lines.append(message(catalog, f"vulnerability.{state}"))
        if is_container and state == "incomplete":
            lines.extend(container_failure_guidance(report, catalog))
        lines.extend(["", *scan_guidance(catalog, report_path, report)])
        return "\n".join(lines), 3

    summary = report.get("summary", {})
    policy = report.get("policy", {})
    lines.append(
        message(
            catalog,
            "vulnerability.report",
            timestamp=safe_text(report.get("completed_at", "unknown")),
            age=age_text(completed, now),
            platform=safe_text(
                policy.get("platform", "unknown")
                if isinstance(policy, Mapping)
                else "unknown"
            ),
        )
    )
    if state == "clean":
        lines.extend(["", f"✅ {message(catalog, 'vulnerability.clean')}"])
        return "\n".join(lines), 0

    risk_key = (
        "vulnerability.containerRisk" if is_container else "vulnerability.risk"
    )
    affected_count = (
        summary.get("affected_resource_count")
        if is_container
        else summary.get("affected_service_count")
    )
    lines.append(
        message(
            catalog,
            risk_key,
            critical=nonnegative_integer(summary.get("critical")),
            high=nonnegative_integer(summary.get("high")),
            resources=nonnegative_integer(affected_count),
            services=nonnegative_integer(affected_count),
            images=nonnegative_integer(summary.get("vulnerable_images")),
        )
    )
    images = vulnerable_image_records(report)
    affected_key = (
        "vulnerability.affectedContainerImages"
        if is_container
        else "vulnerability.affectedImages"
    )
    lines.extend(["", message(catalog, affected_key)])
    for image in images[:8]:
        reference = safe_text(image.get("reference", "unknown"))
        counts = image.get("counts")
        resources = image_resource_names(image)
        lines.append(message(catalog, "vulnerability.image", image=reference))
        lines.append(
            message(
                catalog,
                "vulnerability.imageCounts",
                critical=nonnegative_integer(
                    counts.get("critical") if isinstance(counts, Mapping) else 0
                ),
                high=nonnegative_integer(
                    counts.get("high") if isinstance(counts, Mapping) else 0
                ),
            )
        )
        resource_key = (
            "vulnerability.imageContainers"
            if is_container
            else "vulnerability.imageServices"
        )
        lines.append(
            message(
                catalog,
                resource_key,
                resources=", ".join(resources) or message(catalog, "common.none"),
                services=", ".join(resources) or message(catalog, "common.none"),
            )
        )
        if is_container:
            for owner in image_compose_owners(image)[:3]:
                lines.append(
                    message(
                        catalog,
                        "vulnerability.imageCompose",
                        project=owner["project"],
                        service=owner["service"],
                        directory=owner["working_dir"],
                        files=", ".join(owner["config_files"])
                        or message(catalog, "common.none"),
                    )
                )
    if len(images) > 8:
        lines.append(
            message(catalog, "vulnerability.moreImages", count=len(images) - 8)
        )

    example_record = images[0] if images else {}
    example_image = safe_text(example_record.get("reference", "<IMAGE>"))
    if is_container:
        local_image_id = safe_text(example_record.get("local_image_id", "<IMAGE_ID>"))
        example_image = f"local://{local_image_id}"
    quoted_image = shlex.quote(example_image)
    quoted_path = shlex.quote(str(report_path))
    update_key = (
        "vulnerability.containerFixUpdate"
        if is_container
        else "vulnerability.fixUpdate"
    )
    deploy_key = (
        "vulnerability.containerFixDeploy"
        if is_container
        else "vulnerability.fixDeploy"
    )
    rescan_key = (
        "vulnerability.containerFixRescanCommand"
        if is_container
        else "vulnerability.fixRescanCommand"
    )
    if is_container:
        directory_command, pull_command, deploy_command = compose_redeploy_commands(
            example_record
        )
        deploy_commands = [
            f"  {directory_command}",
            f"  {pull_command}",
            f"  {deploy_command}",
            f"  docker inspect <CONTAINER>",
        ]
    else:
        deploy_commands = [
            f"  {message(catalog, 'vulnerability.fixDeployCommand')}",
            f"  {message(catalog, 'vulnerability.fixVerifyCommand')}",
        ]
    lines.extend(
        [
            "",
            message(catalog, "vulnerability.fixTitle"),
            message(catalog, "vulnerability.fixInspect"),
            f"  {message(catalog, 'vulnerability.scoutRecommendations', image=quoted_image)}",
            f"  {message(catalog, 'vulnerability.scoutCves', image=quoted_image)}",
            message(catalog, update_key),
            message(catalog, deploy_key),
            *deploy_commands,
            message(catalog, "vulnerability.fixRescan"),
            f"  {message(catalog, rescan_key, path=quoted_path)}",
        ]
    )
    return "\n".join(lines), 2


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the internal renderer command line."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("service-health", "vulnerabilities", "report-context")
    )
    parser.add_argument("--report-file", type=Path, required=True)
    parser.add_argument("--max-age-hours", type=float, default=30.0)
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Render the selected operator page and return its evidence state."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    options = parse_arguments(arguments)
    catalog = load_messages(options.locale)
    report = read_mapping(options.report_file)
    now = dt.datetime.now(dt.timezone.utc)
    try:
        if options.command == "report-context":
            if report is None:
                return 3
            print(
                f"{report_resource_type(report)}\t{report_container_scope(report)}"
            )
            return 0
        if options.command == "service-health":
            if report is None:
                print(
                    message(
                        catalog,
                        "common.invalidReport",
                        path=safe_text(options.report_file),
                    )
                )
                return 3
            output, exit_code = render_service_health(report, catalog, now)
        else:
            output, exit_code = render_vulnerabilities(
                report,
                options.report_file,
                catalog,
                now,
                options.max_age_hours,
            )
    except (KeyError, TypeError, ValueError):
        print(
            message(
                catalog,
                "common.invalidReport",
                path=safe_text(options.report_file),
            )
        )
        return 3
    print(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
