"""Present and atomically publish batch image-update security assessments."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence, TextIO

from scripts.image_update_assessment import (
    ImageUpdateAssessmentError,
    assess_image_updates,
    load_json_report,
)
from scripts.operator_report import (
    SUPPORTED_LOCALES,
    load_messages,
    message,
    safe_text,
    selected_locale,
)
from scripts.platforms import HOST_OS_MODES, detect_host_os, platform_adapter_for
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_job import ScanLock
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DEFAULT_PLATFORM, DockerClient, platform_argument


def _prepare_scout_client(
    client: DockerClient,
    host_os_mode: str,
    environment: Mapping[str, str],
) -> DockerClient:
    """Apply host-adapter storage settings before candidate Scout scans."""

    host_os = detect_host_os(host_os_mode)
    prepared_client, _ = platform_adapter_for(host_os).prepare_scout_client(
        client,
        environment,
    )
    return prepared_client


def _preferred_file(name: str, fallback: Path) -> Path:
    """Prefer the shared report directory when it is already writable."""

    production = Path("/info_json") / name
    if production.parent.is_dir() and os.access(production.parent, os.W_OK):
        return production
    return fallback


def _default_candidate_report() -> Path:
    """Return the preferred Slice 1 candidate report path."""

    return _preferred_file(
        "image_update_candidates.json",
        Path(__file__).resolve().parent.parent
        / "swarm_info"
        / "image_update_candidates.json",
    )


def _default_output_file() -> Path:
    """Return the preferred batch assessment destination."""

    return _preferred_file(
        "image_update_assessment.json",
        Path(__file__).resolve().parent.parent
        / "swarm_info"
        / "image_update_assessment.json",
    )


def _source_vulnerability_report_path(
    candidate_report: Mapping[str, Any],
    candidate_report_path: Path,
    explicit_path: Path | None,
) -> Path:
    """Select the exact source snapshot recorded by candidate discovery.

    An explicit operator selection remains authoritative. Otherwise Slice 2
    follows the source path embedded in the Slice 1 evidence instead of using
    a mutable default report that may now describe a different Swarm state.
    Relative recorded paths are first checked beside the candidate report,
    which keeps copied evidence directories self-contained.
    """

    if explicit_path is not None:
        return explicit_path
    source = candidate_report.get("source_report")
    recorded = source.get("path") if isinstance(source, Mapping) else None
    if (
        not isinstance(recorded, str)
        or not recorded.strip()
        or "\x00" in recorded
    ):
        raise ImageUpdateAssessmentError("source-path-missing")
    recorded_path = Path(recorded).expanduser()
    if recorded_path.is_absolute():
        return recorded_path
    colocated_path = candidate_report_path.parent / recorded_path
    return colocated_path if colocated_path.is_file() else recorded_path


def _progress_presenter(catalog: Mapping[str, str]):
    """Build a localized presenter for structured assessment progress events."""

    def present(event: str, values: Mapping[str, object]) -> None:
        key = f"imageAssessment.progress.{event}"
        print(message(catalog, key, **values), flush=True)

    return present


def _render_summary(
    summary: Mapping[str, Any],
    catalog: Mapping[str, str],
    style: TerminalStyle,
    output: TextIO,
) -> None:
    """Render global current, removable, remaining, and scan counts."""

    current = summary["current"]
    removable = summary["deployable_fixable"]
    remaining = summary["conservative_remaining_after_best_candidates"]
    print(style.heading(message(catalog, "imageAssessment.title")), file=output)
    print("-" * 70, file=output)
    print(message(catalog, "imageAssessment.boundary"), file=output)
    print(
        message(
            catalog,
            "imageAssessment.current",
            critical=current["critical"],
            high=current["high"],
        ),
        file=output,
    )
    print(
        style.success(
            message(
                catalog,
                "imageAssessment.removable",
                critical=removable["critical"],
                high=removable["high"],
            )
        ),
        file=output,
    )
    print(
        message(
            catalog,
            "imageAssessment.remaining",
            critical=remaining["critical"],
            high=remaining["high"],
        ),
        file=output,
    )
    print(
        message(
            catalog,
            "imageAssessment.candidates",
            scanned=summary["scanned_candidate_count"],
            unique=summary["unique_candidate_count"],
            failed=summary["failed_candidate_count"],
            images=summary["images_with_verified_candidate"],
            services=summary["services_with_verified_candidate"],
        ),
        file=output,
    )


def _render_opportunities(
    services: Sequence[Mapping[str, Any]],
    catalog: Mapping[str, str],
    style: TerminalStyle,
    output: TextIO,
) -> None:
    """Render up to ten service-level verified update opportunities."""

    opportunities = [
        service
        for service in services
        if service["status"] in {"verified-clean", "verified-improvement"}
    ]
    if not opportunities:
        return
    print(file=output)
    print(style.heading(message(catalog, "imageAssessment.opportunities")), file=output)
    for service in opportunities[:10]:
        removed = service["deployable_fixable"]
        print(
            message(
                catalog,
                "imageAssessment.service",
                service=service["service"],
                critical=removed["critical"],
                high=removed["high"],
                candidate=service["best_candidate"],
                compatibility=message(
                    catalog,
                    f"imageDiscovery.compatibility.{service['compatibility']}",
                ),
            ),
            file=output,
        )
    if len(opportunities) > 10:
        print(
            message(
                catalog,
                "imageAssessment.moreServices",
                count=len(opportunities) - 10,
            ),
            file=output,
        )


def _render_incomplete(
    report: Mapping[str, Any],
    catalog: Mapping[str, str],
    style: TerminalStyle,
    output: TextIO,
) -> None:
    """Explain how to complete an assessment whose discovery was partial."""

    if report["complete"]:
        return
    print(file=output)
    print(style.warning(message(catalog, "imageAssessment.incomplete")), file=output)
    scan_errors = [
        error
        for error in report.get("errors", [])
        if isinstance(error, Mapping)
        and error.get("status") == "candidate-scan-failed"
    ]
    for error in scan_errors[:3]:
        print(
            style.warning(
                message(
                    catalog,
                    "imageAssessment.scanFailure",
                    reference=safe_text(error.get("reference", "unknown")),
                    detail=safe_text(error.get("detail", "unknown")),
                )
            ),
            file=output,
        )
    if len(scan_errors) > 3:
        print(
            message(
                catalog,
                "imageAssessment.moreScanFailures",
                count=len(scan_errors) - 3,
            ),
            file=output,
        )
    required_hosts = report.get("required_registry_hosts", [])
    if required_hosts:
        approvals = " ".join(
            f"--allow-registry-host {host}" for host in required_hosts
        )
        print(
            message(
                catalog,
                "imageAssessment.discoveryRetry",
                approvals=approvals,
            ),
            file=output,
        )


def render_outcome(
    report: Mapping[str, object],
    output_file: Path,
    catalog: Mapping[str, str],
    output: TextIO,
) -> None:
    """Render concise global and service-level verified update reductions."""

    style = TerminalStyle(output)
    _render_summary(report["summary"], catalog, style, output)
    _render_opportunities(report["services"], catalog, style, output)
    _render_incomplete(report, catalog, style, output)
    print(style.warning(message(catalog, "imageAssessment.authorization")), file=output)
    print(message(catalog, "imageAssessment.report", path=output_file), file=output)


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse the internal batch image-update assessment command."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "imageAssessment.description")
    )
    parser.add_argument(
        "--candidate-report-file",
        type=Path,
        default=_default_candidate_report(),
    )
    parser.add_argument(
        "--vulnerability-report-file",
        type=Path,
    )
    parser.add_argument("--output-file", type=Path, default=_default_output_file())
    parser.add_argument("--platform", type=platform_argument, default=DEFAULT_PLATFORM)
    parser.add_argument("--os", choices=HOST_OS_MODES, default="auto", dest="host_os")
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Scan all discovered candidates and atomically publish verified deltas."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    bootstrap_catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, bootstrap_catalog)
    catalog = load_messages(options.locale)
    lock_path = options.lock_file or options.output_file.with_suffix(
        options.output_file.suffix + ".lock"
    )
    lock = ScanLock(lock_path)
    try:
        if not lock.acquire():
            print(
                message(catalog, "imageAssessment.locked", path=lock_path),
                file=sys.stderr,
            )
            return 3
        candidate_report = load_json_report(
            options.candidate_report_file,
            1,
            "candidate-report",
        )
        vulnerability_report_path = _source_vulnerability_report_path(
            candidate_report,
            options.candidate_report_file,
            options.vulnerability_report_file,
        )
        vulnerability_report = load_json_report(
            vulnerability_report_path,
            2,
            "vulnerability-report",
        )
        client = _prepare_scout_client(
            DockerClient(),
            options.host_os,
            os.environ,
        )
        outcome = assess_image_updates(
            candidate_report,
            options.candidate_report_file,
            vulnerability_report,
            vulnerability_report_path,
            client,
            options.platform,
            progress=_progress_presenter(catalog),
        )
        write_json_atomic(options.output_file, outcome.report)
        render_outcome(outcome.report, options.output_file, catalog, sys.stdout)
        return outcome.exit_code
    except (ImageUpdateAssessmentError, OSError, RuntimeError, TypeError, ValueError) as error:
        code = getattr(error, "code", "operational-error")
        detail = getattr(error, "detail", safe_text(error))
        key = f"imageAssessment.error.{code}"
        if key not in catalog:
            key = "imageAssessment.error.operational-error"
        print(message(catalog, key, detail=detail), file=sys.stderr)
        return 3
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
