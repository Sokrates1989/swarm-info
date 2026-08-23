"""Install or remove the managed local-container security crontab block.

On generic Linux, the installer owns only its marked current-user block. On
QNAP, it owns the same markers in ``/etc/config/crontab`` and reloads cron using
the vendor-documented mechanism so the schedule survives reboot. Unrelated
entries remain untouched in both modes.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path
import shlex
import sys
from typing import Mapping, Sequence

from scripts.operator_report import load_messages, message, selected_locale
from scripts.platforms import platform_adapter_for
from scripts.security_check import (
    CONTAINER_SCOPES,
    HOST_OS_MODES,
    detect_host_os,
    security_platform_argument,
)
from scripts.security_job import (
    DEFAULT_SCAN_BUDGET_MINUTES,
    DEFAULT_SCOUT_TIMEOUT_MINUTES,
    DEFAULT_SECURITY_CACHE_AGE_HOURS,
    DEFAULT_SECURITY_MAX_AGE_HOURS,
    validate_security_job_policy,
)
from scripts.vulnerability_cron import (
    CrontabClient,
    bounded_integer,
    default_command_path,
    read_current_crontab,
    remove_managed_block,
    replace_crontab,
)
from scripts.vulnerability_job import (
    DEFAULT_HISTORY_DAYS,
    positive_float,
    positive_integer,
)


BLOCK_BEGIN = "# BEGIN swarm-info managed container security scan"
BLOCK_END = "# END swarm-info managed container security scan"


@dataclasses.dataclass(frozen=True)
class SecurityCronSettings:
    """Describe one managed daily container-security schedule.

    Attributes:
        command_path: Installed swarm-info executable or symlink.
        output_file: Atomic current-report destination.
        platform: Explicit image platform or ``auto``.
        host_os: Host hint passed to the capability-aware job.
        container_scope: Local inventory selection, normally ``running``.
        hour: Daily execution hour from 0 through 23.
        minute: Daily execution minute from 0 through 59.
        cache_age_hours: Minimum rescan interval for matching evidence.
        max_age_hours: Maximum accepted age for complete evidence.
        history_days: Previous-report retention period.
        scout_timeout_minutes: Maximum duration of one Scout image command.
        scan_budget_minutes: Maximum aggregate image-scanning duration.
        log_file: Append-only standard-output and standard-error destination.
        runtime_user: Optional user used by a persistent QNAP root crontab.
        runtime_home: Home directory paired with ``runtime_user``.
    """

    command_path: Path
    output_file: Path
    platform: str
    host_os: str
    container_scope: str
    hour: int
    minute: int
    cache_age_hours: float
    max_age_hours: float
    history_days: int
    scout_timeout_minutes: float
    scan_budget_minutes: float
    log_file: Path
    runtime_user: str | None = None
    runtime_home: Path | None = None
    operational_interval_minutes: int = 5
    operational_freshness_minutes: float = 15.0


@dataclasses.dataclass(frozen=True)
class QnapRuntimeIdentity:
    """Describe the non-root QNAP account that executes scheduled scans."""

    user_name: str
    home: Path
    user_id: int
    group_id: int


def cron_command(settings: SecurityCronSettings) -> str:
    """Render one safely quoted scheduled local-container command.

    The installed command directory is prepended to cron's minimal ``PATH``.
    QNAP installations place a Docker compatibility symlink beside
    ``swarm-info``, so this keeps non-interactive execution equivalent to the
    successful installer/dependency check without sourcing a login profile.
    """

    arguments = [
        settings.command_path.as_posix(),
        "--scheduled-security-check",
        "--container-mode",
        "--container-scope",
        settings.container_scope,
        "--os",
        settings.host_os,
        "--platform",
        settings.platform,
        "--output-file",
        settings.output_file.as_posix(),
        "--cache-age-hours",
        str(settings.cache_age_hours),
        "--max-age-hours",
        str(settings.max_age_hours),
        "--history-days",
        str(settings.history_days),
        "--scout-timeout-minutes",
        str(settings.scout_timeout_minutes),
        "--scan-budget-minutes",
        str(settings.scan_budget_minutes),
        "--schedule-hour",
        str(settings.hour),
        "--schedule-minute",
        str(settings.minute),
    ]
    command = " ".join(shlex.quote(argument) for argument in arguments)
    command_directory = shlex.quote(settings.command_path.parent.as_posix())
    direct_command = (
        f"PATH={command_directory}:$PATH {command} "
        f">> {shlex.quote(settings.log_file.as_posix())} 2>&1"
    )
    if settings.runtime_user is None:
        return direct_command
    runtime_home = shlex.quote(settings.runtime_home.as_posix())
    user_command = f"HOME={runtime_home} {direct_command}"
    return (
        f"/bin/su - {shlex.quote(settings.runtime_user)} -c "
        f"{shlex.quote(user_command)}"
    )


def operational_cron_command(settings: SecurityCronSettings) -> str:
    """Render the cheap five-minute local-container state command."""

    output_file = settings.output_file.with_name("container_state.json")
    log_file = settings.output_file.with_name("container_state.log")
    arguments = [
        settings.command_path.as_posix(),
        "--scheduled-container-state",
        "--os",
        settings.host_os,
        "--output-file",
        output_file.as_posix(),
        "--freshness-minutes",
        str(settings.operational_freshness_minutes),
    ]
    command = " ".join(shlex.quote(argument) for argument in arguments)
    command_directory = shlex.quote(settings.command_path.parent.as_posix())
    direct_command = (
        f"PATH={command_directory}:$PATH {command} "
        f">> {shlex.quote(log_file.as_posix())} 2>&1"
    )
    if settings.runtime_user is None:
        return direct_command
    runtime_home = shlex.quote(settings.runtime_home.as_posix())
    user_command = f"HOME={runtime_home} {direct_command}"
    return (
        f"/bin/su - {shlex.quote(settings.runtime_user)} -c "
        f"{shlex.quote(user_command)}"
    )


def managed_block(settings: SecurityCronSettings) -> str:
    """Render cheap operational and bounded daily security schedules."""

    operational_schedule = f"*/{settings.operational_interval_minutes} * * * *"
    security_schedule = f"{settings.minute} {settings.hour} * * *"
    return (
        f"{BLOCK_BEGIN}\n{operational_schedule} {operational_cron_command(settings)}\n"
        f"{security_schedule} {cron_command(settings)}\n{BLOCK_END}\n"
    )


def install_schedule(
    settings: SecurityCronSettings,
    client: CrontabClient | None = None,
) -> None:
    """Idempotently install this workflow while preserving all other entries."""

    selected_client = client or CrontabClient()
    current = read_current_crontab(selected_client)
    unmanaged = remove_managed_block(current, BLOCK_BEGIN, BLOCK_END)
    separator = "\n" if unmanaged else ""
    replace_crontab(
        selected_client,
        f"{unmanaged}{separator}{managed_block(settings)}",
    )


def remove_schedule(client: CrontabClient | None = None) -> bool:
    """Remove only the managed container-security block.

    Returns:
        ``True`` when managed content changed; otherwise ``False``.
    """

    selected_client = client or CrontabClient()
    current = read_current_crontab(selected_client)
    updated = remove_managed_block(current, BLOCK_BEGIN, BLOCK_END)
    if updated == current:
        return False
    replace_crontab(selected_client, updated)
    return True


def add_install_arguments(
    parser: argparse.ArgumentParser,
    catalog: Mapping[str, str],
) -> None:
    """Add validated schedule and execution-policy options."""

    parser.add_argument(
        "--command-path",
        type=Path,
        default=default_command_path(),
        help=message(catalog, "securityJob.help.command"),
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help=message(catalog, "securityJob.help.output"),
    )
    parser.add_argument(
        "--platform",
        type=security_platform_argument,
        default="auto",
        help=message(catalog, "securityJob.help.platform"),
    )
    parser.add_argument(
        "--os",
        choices=HOST_OS_MODES,
        default="auto",
        dest="host_os",
        help=message(catalog, "securityJob.help.hostOs"),
    )
    parser.add_argument(
        "--container-scope",
        choices=CONTAINER_SCOPES,
        default="running",
        help=message(catalog, "securityJob.help.scope"),
    )
    parser.add_argument(
        "--hour",
        type=bounded_integer(0, 23),
        default=3,
        help=message(catalog, "securityJob.help.hour"),
    )
    parser.add_argument(
        "--minute",
        type=bounded_integer(0, 59),
        default=17,
        help=message(catalog, "securityJob.help.minute"),
    )
    parser.add_argument(
        "--cache-age-hours",
        type=positive_float,
        default=DEFAULT_SECURITY_CACHE_AGE_HOURS,
        help=message(catalog, "securityJob.help.cache"),
    )
    parser.add_argument(
        "--max-age-hours",
        type=positive_float,
        default=DEFAULT_SECURITY_MAX_AGE_HOURS,
        help=message(catalog, "securityJob.help.freshness"),
    )
    parser.add_argument(
        "--history-days",
        type=positive_integer,
        default=DEFAULT_HISTORY_DAYS,
        help=message(catalog, "securityJob.help.history"),
    )
    parser.add_argument(
        "--scout-timeout-minutes",
        type=positive_float,
        default=DEFAULT_SCOUT_TIMEOUT_MINUTES,
        help=message(catalog, "securityJob.help.scoutTimeout"),
    )
    parser.add_argument(
        "--scan-budget-minutes",
        type=positive_float,
        default=DEFAULT_SCAN_BUDGET_MINUTES,
        help=message(catalog, "securityJob.help.scanBudget"),
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help=message(catalog, "securityJob.help.log"),
    )
    parser.add_argument(
        "--runtime-user",
        help=message(catalog, "securityJob.help.runtimeUser"),
    )


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse managed schedule installation or removal arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    add_install_arguments(install_parser, catalog)
    remove_parser = commands.add_parser("remove")
    remove_parser.add_argument(
        "--os",
        choices=HOST_OS_MODES,
        default="auto",
        dest="host_os",
        help=message(catalog, "securityJob.help.hostOs"),
    )
    return parser.parse_args(arguments)


def resolve_qnap_runtime_identity(
    requested_user: str | None,
    environment: Mapping[str, str],
    catalog: Mapping[str, str],
) -> QnapRuntimeIdentity:
    """Resolve the non-root account that owns Scout and Docker credentials."""

    user_name = requested_user or environment.get("SUDO_USER")
    if not user_name or user_name == "root":
        raise ValueError(message(catalog, "securityJob.qnapRuntimeUserRequired"))
    try:
        import pwd

        account = pwd.getpwnam(user_name)
    except (ImportError, KeyError) as error:
        raise ValueError(
            message(catalog, "securityJob.qnapRuntimeUserInvalid", user=user_name)
        ) from error
    return QnapRuntimeIdentity(
        user_name, Path(account.pw_dir), account.pw_uid, account.pw_gid
    )


def settings_from_options(
    options: argparse.Namespace,
    catalog: Mapping[str, str],
    runtime_identity: QnapRuntimeIdentity | None = None,
) -> SecurityCronSettings:
    """Build immutable settings and reject contradictory safety limits."""

    validate_security_job_policy(
        options.cache_age_hours,
        options.max_age_hours,
        options.scout_timeout_minutes,
        options.scan_budget_minutes,
        catalog,
    )
    return SecurityCronSettings(
        command_path=options.command_path,
        output_file=options.output_file,
        platform=options.platform,
        host_os=options.host_os,
        container_scope=options.container_scope,
        hour=options.hour,
        minute=options.minute,
        cache_age_hours=options.cache_age_hours,
        max_age_hours=options.max_age_hours,
        history_days=options.history_days,
        scout_timeout_minutes=options.scout_timeout_minutes,
        scan_budget_minutes=options.scan_budget_minutes,
        log_file=options.log_file or options.output_file.with_suffix(".log"),
        runtime_user=(runtime_identity.user_name if runtime_identity else None),
        runtime_home=(runtime_identity.home if runtime_identity else None),
    )


def prepare_report_directory(
    directory: Path,
    runtime_identity: QnapRuntimeIdentity | None,
) -> None:
    """Create a missing report/log directory for the eventual runtime user."""

    existed = directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    if not existed and runtime_identity is not None:
        os.chown(
            directory,
            runtime_identity.user_id,
            runtime_identity.group_id,
        )


def main(arguments: Sequence[str] | None = None) -> int:
    """Install or remove the managed current-user cron block."""

    catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, catalog)
    try:
        host_os = detect_host_os(options.host_os)
        adapter = platform_adapter_for(host_os)
        qnap_mode = adapter.name == "qnap"
        selected_client = adapter.crontab_client(catalog)

        if options.command == "remove":
            changed = remove_schedule(selected_client)
            key = "securityJob.removed" if changed else "securityJob.notInstalled"
            print(message(catalog, key))
            return 0
        if options.output_file is None:
            options.output_file = (
                adapter.default_evidence_directory(os.environ)
                / "security_scan-running.json"
            )
        runtime_identity = (
            resolve_qnap_runtime_identity(options.runtime_user, os.environ, catalog)
            if qnap_mode
            else None
        )
        settings = settings_from_options(options, catalog, runtime_identity)
        prepare_report_directory(settings.output_file.parent, runtime_identity)
        prepare_report_directory(settings.log_file.parent, runtime_identity)
        install_schedule(settings, selected_client)
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        print(
            message(catalog, "securityJob.cronFailure", detail=error),
            file=sys.stderr,
        )
        return 1
    print(
        message(
            catalog,
            "securityJob.installed",
            hour=f"{settings.hour:02d}",
            minute=f"{settings.minute:02d}",
        )
    )
    print(
        message(
            catalog,
            "securityJob.schedulePolicy",
            cache=f"{settings.cache_age_hours:g}",
            freshness=f"{settings.max_age_hours:g}",
        )
    )
    print(
        message(
            catalog,
            "securityJob.executionLimits",
            timeout=f"{settings.scout_timeout_minutes:g}",
            budget=f"{settings.scan_budget_minutes:g}",
        )
    )
    print(message(catalog, "securityJob.reportPath", path=settings.output_file))
    print(message(catalog, "securityJob.logPath", path=settings.log_file))
    if qnap_mode:
        print(
            message(catalog, "securityJob.qnapPersistent", user=settings.runtime_user)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
