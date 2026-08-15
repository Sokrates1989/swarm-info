"""Prove whether one concrete image candidate reduces current vulnerabilities."""

from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping, Sequence, TextIO

from scripts.image_update_evidence import compare_candidate_evidence
from scripts.operator_report import (
    SUPPORTED_LOCALES,
    load_messages,
    message,
    safe_text,
    selected_locale,
)
from scripts.remediation_advice import inspect_image_metadata, version_compatibility
from scripts.remediation_policy import image_repository
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_focus import FocusSelectionError, select_focused_services
from scripts.vulnerability_job import ScanLock
from scripts.vulnerability_models import (
    ImageScanResult,
    ImageTarget,
    ServiceRecord,
    registry_from_reference,
    severity_counts,
    utc_timestamp,
    write_json_atomic,
)
from scripts.vulnerability_scan import (
    DEFAULT_PLATFORM,
    DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
    DockerClient,
    InventoryError,
    ScannerUnavailableError,
    collect_services,
    docker_scout_version,
    platform_argument,
    run_with_progress_heartbeat,
)
from scripts.vulnerability_scout import scan_image, scan_local_image


DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "swarm_info"
    / "image_update_comparison.json"
)
IMAGE_ID_PATTERN = re.compile(r"sha256:[a-fA-F0-9]{64}")


class ImageUpdateCheckError(RuntimeError):
    """Describe a safe comparison failure with a stable localized code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store one error code and bounded, sanitized detail."""

        super().__init__(code)
        self.code = code
        self.detail = safe_text(detail)[:500]


@dataclasses.dataclass(frozen=True)
class ResolvedImage:
    """Exact local or registry artifact selected for one side of a comparison."""

    requested_reference: str
    scan_reference: str
    source: str
    digest: str | None
    local_image_id: str | None
    version: str | None
    version_source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize identity evidence without registry credentials or raw output."""

        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ImageUpdateOutcome:
    """Complete comparison report and its public process status."""

    report: Mapping[str, Any]
    exit_code: int


def validate_image_reference(value: str) -> str:
    """Reject empty, control-bearing, whitespace-containing image references."""

    if (
        not value
        or len(value) > 512
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ImageUpdateCheckError("invalid-image-reference", value)
    return value


def _registry_reference(reference: str, digest: str) -> str:
    """Bind a mutable requested reference to its resolved registry digest."""

    name = reference.split("@", 1)[0]
    return f"{name}@{digest}"


def resolve_image(
    client: DockerClient,
    reference: str,
    platform: str,
) -> ResolvedImage:
    """Resolve a local image ID first, then an immutable registry digest."""

    selected = validate_image_reference(reference)
    metadata = inspect_image_metadata(client, selected, platform=platform)
    if metadata.local_image_id and IMAGE_ID_PATTERN.fullmatch(metadata.local_image_id):
        return ResolvedImage(
            selected,
            metadata.local_image_id.lower(),
            "local",
            metadata.digest,
            metadata.local_image_id.lower(),
            metadata.version,
            metadata.version_source,
        )
    if metadata.digest:
        return ResolvedImage(
            selected,
            _registry_reference(selected, metadata.digest),
            "registry",
            metadata.digest,
            None,
            metadata.version,
            metadata.version_source,
        )
    raise ImageUpdateCheckError("image-unresolved", selected)


def _target_for_resolved(image: ResolvedImage, label: str) -> ImageTarget:
    """Build one isolated immutable scanner target from resolved evidence."""

    service = ServiceRecord("comparison", label, image.requested_reference, None)
    return ImageTarget(
        key=f"comparison|{image.scan_reference}",
        registry=registry_from_reference(image.requested_reference),
        digest=image.digest if image.source == "registry" else None,
        references={image.scan_reference},
        services=[service],
        local_image_id=image.local_image_id,
    )


def scan_resolved_image(
    client: DockerClient,
    image: ResolvedImage,
    platform: str,
    label: str,
) -> ImageScanResult:
    """Scan exactly the local ID or digest proven during resolution."""

    target = _target_for_resolved(image, label)
    return (
        scan_local_image(client, target, platform)
        if image.source == "local"
        else scan_image(client, target, platform)
    )


def _current_service_image(client: DockerClient, selector: str) -> str:
    """Resolve one exact manager-visible service to its current image."""

    try:
        services = collect_services(client)
        selected = select_focused_services(services, "service", selector)
    except (InventoryError, FocusSelectionError) as error:
        detail = getattr(error, "selector", str(error))
        raise ImageUpdateCheckError("service-unresolved", detail) from error
    if len(selected) != 1:
        raise ImageUpdateCheckError("service-unresolved", selector)
    return selected[0].image


def _scan_payload(image: ResolvedImage, result: ImageScanResult) -> dict[str, Any]:
    """Serialize one exact artifact and its normalized Scout results."""

    counts = severity_counts(result.findings)
    return {
        **image.to_dict(),
        "status": result.status,
        "scan_source": result.scan_source,
        "scan_attempts": result.scan_attempts,
        "counts": {"total": len(result.findings), **counts},
        "finding_ids": sorted({finding.identifier for finding in result.findings}),
    }


def run_image_update_check(
    client: DockerClient,
    platform: str,
    candidate_image: str,
    *,
    current_image: str | None = None,
    service: str | None = None,
    progress: Callable[[str], None] | None = None,
    heartbeat_interval_seconds: float = DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
) -> ImageUpdateOutcome:
    """Scan current and candidate artifacts and return a fail-closed comparison."""

    if bool(current_image) == bool(service):
        raise ImageUpdateCheckError("current-selector-required")
    current_reference = (
        _current_service_image(client, service or "") if service else current_image or ""
    )
    if progress:
        progress("[INFO] Checking Docker Scout availability...")
    try:
        scanner_version = run_with_progress_heartbeat(
            lambda: docker_scout_version(client),
            progress,
            "[INFO] Docker Scout availability check is still running",
            heartbeat_interval_seconds,
        )
    except ScannerUnavailableError as error:
        raise ImageUpdateCheckError("scanner-unavailable", str(error)) from error

    resolved: list[ResolvedImage] = []
    results: list[ImageScanResult] = []
    references = (current_reference, candidate_image)
    labels = ("current", "candidate")
    for index, (reference, label) in enumerate(zip(references, labels), start=1):
        if progress:
            progress(f"[INFO] [{index}/2] Resolving {label} image {reference}...")
        image = run_with_progress_heartbeat(
            lambda reference=reference: resolve_image(client, reference, platform),
            progress,
            f"[INFO] [{index}/2] Still resolving {label} image",
            heartbeat_interval_seconds,
        )
        resolved.append(image)
        if progress:
            progress(
                f"[INFO] [{index}/2] Scanning exact {label} artifact "
                f"{image.scan_reference}..."
            )
        result = run_with_progress_heartbeat(
            lambda image=image, label=label: scan_resolved_image(
                client, image, platform, label
            ),
            progress,
            f"[INFO] [{index}/2] Docker Scout is still scanning {label} image",
            heartbeat_interval_seconds,
        )
        if result.status == "error":
            raise ImageUpdateCheckError(
                f"{label}-scan-failed",
                result.error or "unknown scanner failure",
            )
        results.append(result)

    current_counts = severity_counts(results[0].findings)
    comparison = compare_candidate_evidence(
        current_counts["critical"],
        current_counts["high"],
        (finding.identifier for finding in results[0].findings),
        results[1].findings,
    )
    repository_changed = (
        image_repository(resolved[0].requested_reference)
        != image_repository(resolved[1].requested_reference)
    )
    compatibility = (
        "repository-change"
        if repository_changed
        else version_compatibility(resolved[0].version, resolved[1].version)
    )
    report = {
        "schema_version": 1,
        "completed_at": utc_timestamp(),
        "scanner": {"name": "docker-scout", "version": scanner_version},
        "policy": {
            "platform": platform,
            "severities": ["critical", "high"],
            "fixable_only": True,
        },
        "selection": {"service": service},
        "current": _scan_payload(resolved[0], results[0]),
        "candidate": _scan_payload(resolved[1], results[1]),
        "comparison": comparison.to_dict(),
        "safety": {
            "repository_changed": repository_changed,
            "compatibility": compatibility,
            "compatibility_verified": False,
            "deployment_authorized": False,
        },
    }
    exit_code = 0 if comparison.status in {"verified-clean", "already-clean"} else 2
    return ImageUpdateOutcome(report, exit_code)


def _preferred_output_file() -> Path:
    """Prefer the shared report directory when it already exists and is writable."""

    production = Path("/info_json/image_update_comparison.json")
    if production.parent.is_dir() and os.access(production.parent, os.W_OK):
        return production
    return DEFAULT_OUTPUT_FILE


def render_outcome(
    outcome: ImageUpdateOutcome,
    output_file: Path,
    catalog: Mapping[str, str],
    output: TextIO,
) -> None:
    """Render a concise, localized current-versus-candidate security verdict."""

    style = TerminalStyle(output)
    report = outcome.report
    current = report["current"]
    candidate = report["candidate"]
    comparison = report["comparison"]
    safety = report["safety"]
    print(style.heading(message(catalog, "imageUpdate.title")), file=output)
    print("-" * 70, file=output)
    print(message(catalog, "imageUpdate.fixableMeaning"), file=output)
    print(
        message(
            catalog,
            "imageUpdate.identity",
            label=message(catalog, "imageUpdate.current"),
            requested=current["requested_reference"],
            resolved=current["scan_reference"],
        ),
        file=output,
    )
    print(
        message(
            catalog,
            "imageUpdate.identity",
            label=message(catalog, "imageUpdate.candidate"),
            requested=candidate["requested_reference"],
            resolved=candidate["scan_reference"],
        ),
        file=output,
    )
    print(
        message(
            catalog,
            "imageUpdate.counts",
            current_critical=comparison["current"]["critical"],
            current_high=comparison["current"]["high"],
            candidate_critical=comparison["candidate"]["critical"],
            candidate_high=comparison["candidate"]["high"],
        ),
        file=output,
    )
    verdict = message(
        catalog,
        f"imageUpdate.verdict.{comparison['status']}",
        removed=comparison["removed"]["total"],
        remaining=comparison["candidate"]["total"],
        new=len(comparison["new_finding_ids"]),
    )
    if comparison["status"] in {"verified-clean", "already-clean"}:
        print(style.success(verdict), file=output)
    elif comparison["status"] in {"verified-improvement", "mixed-improvement"}:
        print(style.warning(verdict), file=output)
    else:
        print(style.error(verdict), file=output)
    identifier_groups = (
        ("removed", comparison["removed"]["finding_ids"]),
        ("remaining", comparison["remaining_finding_ids"]),
        ("new", comparison["new_finding_ids"]),
    )
    for label, identifiers in identifier_groups:
        if not identifiers:
            continue
        sample = ", ".join(identifiers[:8])
        more = (
            message(catalog, "imageUpdate.more", count=len(identifiers) - 8)
            if len(identifiers) > 8
            else ""
        )
        print(
            message(
                catalog,
                "imageUpdate.findingSample",
                label=message(catalog, f"imageUpdate.findingSample.{label}"),
                sample=sample,
                more=more,
            ),
            file=output,
        )
    print(
        style.warning(
            message(
                catalog,
                "imageUpdate.compatibility",
                detail=message(
                    catalog,
                    f"imageUpdate.compatibility.{safety['compatibility']}",
                ),
            )
        ),
        file=output,
    )
    print(message(catalog, "imageUpdate.ownImages"), file=output)
    print(message(catalog, "imageUpdate.report", path=output_file), file=output)


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse the internal read-only image-update comparison command."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "imageUpdate.description")
    )
    current = parser.add_mutually_exclusive_group(required=True)
    current.add_argument("--service")
    current.add_argument("--current-image")
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--platform", type=platform_argument, default=DEFAULT_PLATFORM)
    parser.add_argument("--output-file", type=Path, default=_preferred_output_file())
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run two exact scans and atomically publish their update verdict."""

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
                message(catalog, "imageUpdate.locked", path=lock_path),
                file=sys.stderr,
            )
            return 3
        outcome = run_image_update_check(
            DockerClient(),
            options.platform,
            options.candidate_image,
            current_image=options.current_image,
            service=options.service,
            progress=lambda value: print(value, flush=True),
        )
        write_json_atomic(options.output_file, outcome.report)
        render_outcome(outcome, options.output_file, catalog, sys.stdout)
        return outcome.exit_code
    except (ImageUpdateCheckError, OSError, RuntimeError, TypeError, ValueError) as error:
        code = getattr(error, "code", "operational-error")
        detail = getattr(error, "detail", safe_text(error))
        key = f"imageUpdate.error.{code}"
        if key not in catalog:
            key = "imageUpdate.error.operational-error"
        print(message(catalog, key, detail=detail), file=sys.stderr)
        return 3
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
