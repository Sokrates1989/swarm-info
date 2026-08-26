"""Batch-scan discovered image candidates and calculate verified update deltas.

The assessment consumes immutable Slice 1 candidates and the exact source
vulnerability report. Candidate artifacts are scanned once per digest and the
results are reused across every consuming image and service. The output is
evidence only: compatibility and deployment remain operator decisions.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence

from scripts.image_update_assessment_report import (
    assess_image_record,
    assessment_summary,
    resource_rows,
    service_rows,
)
from scripts.operator_report import safe_text
from scripts.vulnerability_models import (
    ImageScanResult,
    ImageTarget,
    ServiceRecord,
    registry_from_reference,
    utc_timestamp,
)
from scripts.vulnerability_scan import (
    DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
    ScannerUnavailableError,
    docker_scout_version,
    run_with_progress_heartbeat,
)
from scripts.vulnerability_scout import CommandClient, scan_image


SCHEMA_VERSION = 1
FULL_SHA256_PATTERN = re.compile(r"sha256:[0-9a-fA-F]{64}")
ProgressCallback = Callable[[str, Mapping[str, object]], None]
Scanner = Callable[[CommandClient, ImageTarget, str], ImageScanResult]
VersionReader = Callable[[CommandClient], str]


class ImageUpdateAssessmentError(RuntimeError):
    """Describe one fail-closed assessment error with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a bounded single-line diagnostic without report contents."""

        super().__init__(code)
        self.code = code
        self.detail = safe_text(detail)[:500]


@dataclasses.dataclass(frozen=True)
class AssessmentOutcome:
    """Atomic batch-assessment report and its public process status."""

    report: Mapping[str, Any]
    exit_code: int


def load_json_report(path: Path, schema_version: int, code: str) -> dict[str, Any]:
    """Load one JSON object and require its expected schema version."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ImageUpdateAssessmentError(f"{code}-unreadable", str(path)) from error
    if not isinstance(payload, dict) or payload.get("schema_version") != schema_version:
        raise ImageUpdateAssessmentError(f"{code}-schema", str(path))
    return payload


def _notify(
    callback: ProgressCallback | None,
    event: str,
    **values: object,
) -> None:
    """Publish one structured progress event when a presenter is configured."""

    if callback is not None:
        callback(event, values)


def _report_images(report: Mapping[str, Any], code: str) -> list[Mapping[str, Any]]:
    """Return mapping-only image records from one validated report."""

    images = report.get("images")
    if not isinstance(images, list):
        raise ImageUpdateAssessmentError(f"{code}-images")
    if not all(isinstance(item, Mapping) for item in images):
        raise ImageUpdateAssessmentError(f"{code}-image-object")
    return list(images)


def _validate_source_identity(
    candidate_report: Mapping[str, Any],
    vulnerability_report: Mapping[str, Any],
) -> None:
    """Reject stale candidate evidence built from another vulnerability scope."""

    source = candidate_report.get("source_report")
    scope = vulnerability_report.get("scope")
    if not isinstance(source, Mapping) or not isinstance(scope, Mapping):
        raise ImageUpdateAssessmentError("source-identity-missing")
    expected = source.get("image_fingerprint")
    actual = scope.get("image_fingerprint")
    if not isinstance(expected, str) or not expected or expected != actual:
        raise ImageUpdateAssessmentError("source-fingerprint-mismatch")
    if source.get("completed_at") != vulnerability_report.get("completed_at"):
        raise ImageUpdateAssessmentError("source-timestamp-mismatch")


def _current_key(reference: object, digest: object) -> tuple[str, str]:
    """Build the exact source-image identity shared by both reports."""

    if not isinstance(reference, str) or not reference:
        raise ImageUpdateAssessmentError("current-reference")
    normalized_digest = digest.lower() if isinstance(digest, str) else ""
    if normalized_digest and not FULL_SHA256_PATTERN.fullmatch(normalized_digest):
        raise ImageUpdateAssessmentError("current-digest", reference)
    return reference, normalized_digest


def _source_index(
    vulnerability_report: Mapping[str, Any],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    """Index current evidence by reference and exact scanned artifact."""

    records: dict[tuple[str, str], Mapping[str, Any]] = {}
    for image in _report_images(vulnerability_report, "vulnerability-report"):
        key = _current_key(
            image.get("reference"),
            image.get("local_image_id") or image.get("digest"),
        )
        if key in records:
            raise ImageUpdateAssessmentError("source-image-duplicate", key[0])
        records[key] = image
    return records


def _candidate_target(candidate: Mapping[str, Any], platform: str) -> ImageTarget:
    """Validate and convert one immutable discovery candidate into a scan target."""

    reference = candidate.get("immutable_reference")
    digest = candidate.get("digest")
    candidate_platform = candidate.get("platform")
    if (
        not isinstance(reference, str)
        or not isinstance(digest, str)
        or not FULL_SHA256_PATTERN.fullmatch(digest)
        or not reference.endswith(f"@{digest}")
    ):
        raise ImageUpdateAssessmentError("candidate-identity")
    if candidate_platform != platform:
        raise ImageUpdateAssessmentError("candidate-platform", reference)
    service = ServiceRecord("candidate", "candidate", reference, None)
    return ImageTarget(
        key=f"candidate|{reference}",
        registry=registry_from_reference(reference),
        digest=digest.lower(),
        references={reference},
        services=[service],
    )


def _unique_candidates(
    candidate_images: Sequence[Mapping[str, Any]],
    platform: str,
) -> dict[str, tuple[Mapping[str, Any], ImageTarget]]:
    """Deduplicate discovered candidates by their exact immutable reference."""

    candidates: dict[str, tuple[Mapping[str, Any], ImageTarget]] = {}
    for image in candidate_images:
        raw_candidates = image.get("candidates")
        if not isinstance(raw_candidates, list):
            raise ImageUpdateAssessmentError("candidate-list")
        for candidate in raw_candidates:
            if not isinstance(candidate, Mapping):
                raise ImageUpdateAssessmentError("candidate-object")
            target = _candidate_target(candidate, platform)
            candidates.setdefault(target.display_reference, (candidate, target))
    return dict(sorted(candidates.items()))


def _scan_candidates(
    client: CommandClient,
    candidates: Mapping[str, tuple[Mapping[str, Any], ImageTarget]],
    platform: str,
    progress: ProgressCallback | None,
    heartbeat_interval_seconds: float,
    scanner: Scanner,
) -> tuple[dict[str, ImageScanResult], list[dict[str, str]]]:
    """Scan each exact candidate once while retaining progress and failures."""

    results: dict[str, ImageScanResult] = {}
    errors: list[dict[str, str]] = []
    total = len(candidates)
    for index, (reference, (_, target)) in enumerate(candidates.items(), start=1):
        values = {"index": index, "total": total, "reference": reference}
        _notify(progress, "scan-start", **values)
        result = run_with_progress_heartbeat(
            lambda target=target: scanner(client, target, platform),
            lambda _message, values=values: _notify(
                progress, "scan-heartbeat", **values
            ),
            "candidate-scan-heartbeat",
            heartbeat_interval_seconds,
        )
        results[reference] = result
        if result.status == "error":
            errors.append(
                {
                    "reference": reference,
                    "status": "candidate-scan-failed",
                    "detail": safe_text(result.error or "")[:500],
                }
            )
            _notify(progress, "scan-failed", **values)
        else:
            _notify(progress, "scan-complete", status=result.status, **values)
    return results, errors


def _scan_all_candidates(
    client: CommandClient,
    candidates: Mapping[str, tuple[Mapping[str, Any], ImageTarget]],
    platform: str,
    progress: ProgressCallback | None,
    heartbeat_interval_seconds: float,
    scanner: Scanner,
    version_reader: VersionReader,
) -> tuple[str | None, dict[str, ImageScanResult], list[dict[str, str]]]:
    """Validate Scout once, then scan every deduplicated candidate."""

    if not candidates:
        return None, {}, []
    _notify(progress, "scanner-check")
    try:
        scanner_version = run_with_progress_heartbeat(
            lambda: version_reader(client),
            lambda _message: _notify(progress, "scanner-heartbeat"),
            "scanner-check-heartbeat",
            heartbeat_interval_seconds,
        )
    except ScannerUnavailableError as error:
        raise ImageUpdateAssessmentError("scanner-unavailable", str(error)) from error
    scans, errors = _scan_candidates(
        client,
        candidates,
        platform,
        progress,
        heartbeat_interval_seconds,
        scanner,
    )
    return scanner_version, scans, errors


def _assess_images(
    candidate_images: Sequence[Mapping[str, Any]],
    sources: Mapping[tuple[str, str], Mapping[str, Any]],
    scans: Mapping[str, ImageScanResult],
) -> list[dict[str, Any]]:
    """Join candidates to their exact source evidence and assess each image."""

    assessed_images: list[dict[str, Any]] = []
    for discovery_image in candidate_images:
        current = discovery_image.get("current")
        if not isinstance(current, Mapping):
            raise ImageUpdateAssessmentError("current-object")
        key = _current_key(
            current.get("reference"),
            current.get("source_artifact")
            or current.get("local_image_id")
            or current.get("source_digest")
            or current.get("digest"),
        )
        source_image = sources.get(key)
        if source_image is None:
            raise ImageUpdateAssessmentError("current-source-missing", key[0])
        try:
            assessed_images.append(
                assess_image_record(discovery_image, source_image, scans)
            )
        except ValueError as error:
            raise ImageUpdateAssessmentError(str(error), key[0]) from error
    return assessed_images


def _assessment_exit_code(complete: bool, summary: Mapping[str, Any]) -> int:
    """Return the public clean, vulnerable, or incomplete process status."""

    if not complete:
        return 3
    return 2 if summary["current"]["total"] else 0


def _required_registry_hosts(candidate_report: Mapping[str, Any]) -> list[str]:
    """Return validated inherited network approvals for retry guidance."""

    hosts = candidate_report.get("required_registry_hosts")
    if not isinstance(hosts, list) or not all(
        isinstance(host, str) and host for host in hosts
    ):
        raise ImageUpdateAssessmentError("candidate-report-required-hosts")
    return sorted(set(hosts))


def _assessment_resource_type(images: Sequence[Mapping[str, Any]]) -> str:
    """Use container vocabulary only when every current image declares it."""

    declared = {
        current.get("resource_type")
        for image in images
        if isinstance((current := image.get("current")), Mapping)
    }
    return "container" if declared == {"container"} else "service"


def _assessment_report(
    candidate_report: Mapping[str, Any],
    candidate_report_path: Path,
    vulnerability_report: Mapping[str, Any],
    vulnerability_report_path: Path,
    platform: str,
    started_at: str,
    scanner_version: str | None,
    source_complete: bool,
    complete: bool,
    summary: Mapping[str, Any],
    services: Sequence[Mapping[str, Any]],
    resources: Sequence[Mapping[str, Any]],
    resource_type: str,
    images: Sequence[Mapping[str, Any]],
    errors: Sequence[Mapping[str, str]],
    discovery_errors: Sequence[object],
) -> dict[str, Any]:
    """Assemble one non-authorizing atomic assessment document."""

    return {
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "completed_at": utc_timestamp(),
        "complete": complete,
        "scanner": {"name": "docker-scout", "version": scanner_version},
        "policy": {
            "platform": platform,
            "resource_type": resource_type,
            "severities": ["critical", "high"],
            "fixable_only": True,
            "candidate_selection": "critical-then-high-reduction",
            "deployment_authorized": False,
        },
        "source_reports": {
            "candidate": {
                "path": str(candidate_report_path),
                "schema_version": candidate_report.get("schema_version"),
                "completed_at": candidate_report.get("completed_at"),
                "complete": candidate_report.get("complete") is True,
            },
            "vulnerability": {
                "path": str(vulnerability_report_path),
                "schema_version": vulnerability_report.get("schema_version"),
                "completed_at": vulnerability_report.get("completed_at"),
                "complete": source_complete,
                "image_fingerprint": candidate_report["source_report"].get(
                    "image_fingerprint"
                ),
            },
        },
        "scope": {
            "resource_type": resource_type,
            "resource_count": len(resources),
        },
        "summary": summary,
        "services": list(services),
        "resources": list(resources),
        "images": list(images),
        "errors": list(errors),
        "discovery_errors": list(discovery_errors),
        "required_registry_hosts": _required_registry_hosts(candidate_report),
    }


def assess_image_updates(
    candidate_report: Mapping[str, Any],
    candidate_report_path: Path,
    vulnerability_report: Mapping[str, Any],
    vulnerability_report_path: Path,
    client: CommandClient,
    platform: str,
    *,
    progress: ProgressCallback | None = None,
    heartbeat_interval_seconds: float = DEFAULT_PROGRESS_HEARTBEAT_SECONDS,
    scanner: Scanner = scan_image,
    version_reader: VersionReader = docker_scout_version,
) -> AssessmentOutcome:
    """Scan unique candidates and publish image plus workload-resource deltas."""

    started_at = utc_timestamp()
    _validate_source_identity(candidate_report, vulnerability_report)
    candidate_policy = candidate_report.get("policy")
    if not isinstance(candidate_policy, Mapping) or candidate_policy.get("platform") != platform:
        raise ImageUpdateAssessmentError("candidate-report-platform", platform)
    candidate_images = _report_images(candidate_report, "candidate-report")
    sources = _source_index(vulnerability_report)
    candidates = _unique_candidates(candidate_images, platform)
    scanner_version, scans, errors = _scan_all_candidates(
        client,
        candidates,
        platform,
        progress,
        heartbeat_interval_seconds,
        scanner,
        version_reader,
    )
    assessed_images = _assess_images(candidate_images, sources, scans)
    vulnerability_summary = vulnerability_report.get("summary")
    source_complete = bool(
        isinstance(vulnerability_summary, Mapping)
        and vulnerability_summary.get("complete") is True
    )
    complete = bool(candidate_report.get("complete")) and source_complete and not errors
    services = service_rows(assessed_images)
    resources = resource_rows(assessed_images)
    resource_type = _assessment_resource_type(assessed_images)
    discovery_errors = candidate_report.get("errors")
    if not isinstance(discovery_errors, list):
        raise ImageUpdateAssessmentError("candidate-report-errors")
    try:
        summary = assessment_summary(
            vulnerability_report,
            assessed_images,
            scans,
            services,
            resources,
            errors,
            len(discovery_errors),
            complete,
        )
    except ValueError as error:
        raise ImageUpdateAssessmentError(str(error)) from error
    report = _assessment_report(
        candidate_report,
        candidate_report_path,
        vulnerability_report,
        vulnerability_report_path,
        platform,
        started_at,
        scanner_version,
        source_complete,
        complete,
        summary,
        services,
        resources,
        resource_type,
        assessed_images,
        errors,
        discovery_errors,
    )
    return AssessmentOutcome(report, _assessment_exit_code(complete, summary))
