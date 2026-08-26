"""Project candidate scan evidence into image, service, and global deltas."""

from __future__ import annotations

import shlex
from typing import Any, Mapping, Sequence

from scripts.image_update_evidence import compare_candidate_evidence
from scripts.vulnerability_models import ImageScanResult, severity_counts


VERIFIED_STATES = frozenset({"verified-clean", "verified-improvement"})


def _scan_payload(result: ImageScanResult) -> dict[str, Any]:
    """Serialize one candidate scan without its synthetic target service."""

    counts = severity_counts(result.findings)
    payload: dict[str, Any] = {
        "status": result.status,
        "counts": {"total": len(result.findings), **counts},
        "finding_ids": sorted({finding.identifier for finding in result.findings}),
        "scanner_exit_code": result.scanner_exit_code,
        "scan_source": result.scan_source,
        "scan_attempts": result.scan_attempts,
        "registry_fallback": result.registry_fallback,
    }
    if result.error:
        payload["error"] = result.error
    if result.error_code:
        payload["error_code"] = result.error_code
    return payload


def _source_counts(image: Mapping[str, Any]) -> tuple[int, int, tuple[str, ...]]:
    """Return validated critical/high counts and finding identifiers."""

    counts = image.get("counts")
    findings = image.get("findings")
    if not isinstance(counts, Mapping) or not isinstance(findings, list):
        raise ValueError("current-evidence-missing")
    critical = counts.get("critical")
    high = counts.get("high")
    if (
        isinstance(critical, bool)
        or not isinstance(critical, int)
        or critical < 0
        or isinstance(high, bool)
        or not isinstance(high, int)
        or high < 0
    ):
        raise ValueError("current-counts-invalid")
    identifiers = tuple(
        sorted(
            {
                finding["id"]
                for finding in findings
                if isinstance(finding, Mapping)
                and isinstance(finding.get("id"), str)
                and finding["id"]
            }
        )
    )
    if critical + high and not identifiers:
        raise ValueError("current-finding-ids-missing")
    return critical, high, identifiers


def _comparison_rank(candidate: Mapping[str, Any]) -> tuple[int, int, int, str]:
    """Rank verified reductions by critical, high, then compatibility evidence."""

    comparison = candidate["comparison"]
    removed = comparison["removed"]
    compatibility_rank = {
        "same-minor": 4,
        "same-major": 3,
        "unknown": 2,
        "major-change": 1,
        "successor-manual-review": 0,
    }.get(str(candidate.get("compatibility")), 0)
    return (
        int(removed["critical"]),
        int(removed["high"]),
        compatibility_rank,
        str(candidate["immutable_reference"]),
    )


def _assessed_candidate(
    raw: Mapping[str, Any],
    result: ImageScanResult | None,
    critical: int,
    high: int,
    current_ids: Sequence[str],
) -> dict[str, Any]:
    """Attach one scan and comparison verdict to a discovered candidate."""

    candidate = dict(raw)
    candidate["deployment_authorized"] = False
    if result is None or result.status == "error":
        candidate["security_comparison"] = "scan-failed"
        candidate["scan"] = _scan_payload(result) if result is not None else None
        candidate["comparison"] = None
        return candidate
    comparison = compare_candidate_evidence(
        critical,
        high,
        current_ids,
        result.findings,
    )
    candidate["security_comparison"] = comparison.status
    candidate["scan"] = _scan_payload(result)
    candidate["comparison"] = comparison.to_dict()
    return candidate


def assess_image_record(
    discovery_image: Mapping[str, Any],
    source_image: Mapping[str, Any],
    scans: Mapping[str, ImageScanResult],
) -> dict[str, Any]:
    """Compare every candidate for one current image and select the best proof."""

    critical, high, current_ids = _source_counts(source_image)
    raw_candidates = discovery_image.get("candidates")
    if not isinstance(raw_candidates, list):
        raise ValueError("candidate-list")
    assessed = [
        _assessed_candidate(
            raw,
            scans.get(str(raw.get("immutable_reference"))),
            critical,
            high,
            current_ids,
        )
        for raw in raw_candidates
        if isinstance(raw, Mapping)
    ]
    verified = [
        candidate
        for candidate in assessed
        if candidate.get("security_comparison") in VERIFIED_STATES
    ]
    best = max(verified, key=_comparison_rank) if verified else None
    current = dict(discovery_image.get("current", {}))
    current["counts"] = {
        "critical": critical,
        "high": high,
        "total": critical + high,
    }
    return {
        "current": current,
        "discovery": dict(discovery_image.get("discovery", {})),
        "candidates": assessed,
        "best_verified_candidate": (
            {
                "immutable_reference": best["immutable_reference"],
                "reference": best.get("reference"),
                "tag": best.get("tag"),
                "version": best.get("version"),
                "version_source": best.get("version_source"),
                "compatibility": best.get("compatibility"),
                "tracks": best.get("tracks", []),
                "lifecycle": best.get("lifecycle"),
                "comparison": best["comparison"],
                "deployment_authorized": False,
            }
            if best is not None
            else None
        ),
    }


def _service_row(
    service: object,
    current: Mapping[str, Any],
    best: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Project one image comparison onto one consuming service."""

    comparison = best.get("comparison") if best is not None else None
    current_counts = current["counts"]
    status = "current-clean" if current_counts["total"] == 0 else "no-verified-candidate"
    if isinstance(comparison, Mapping):
        status = str(comparison["status"])
    return {
        "service": service,
        "current_reference": current.get("reference"),
        "current": current_counts,
        "best_candidate": best.get("immutable_reference") if best else None,
        "compatibility": best.get("compatibility") if best else None,
        "status": status,
        "deployable_fixable": (
            comparison.get("removed")
            if isinstance(comparison, Mapping)
            else {"critical": 0, "high": 0, "total": 0, "finding_ids": []}
        ),
        "candidate_remaining": (
            comparison.get("candidate")
            if isinstance(comparison, Mapping)
            else current_counts
        ),
        "deployment_authorized": False,
    }


def service_rows(images: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project best image evidence onto every affected service for later UI use."""

    rows: list[dict[str, Any]] = []
    for image in images:
        current = image["current"]
        raw_best = image.get("best_verified_candidate")
        best = raw_best if isinstance(raw_best, Mapping) else None
        for service in current.get("services", []):
            rows.append(_service_row(service, current, best))
    return sorted(rows, key=lambda item: str(item["service"]))


def _resource_records(current: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize additive resource records or synthesize legacy service rows."""

    raw_resources = current.get("resources")
    if isinstance(raw_resources, list):
        return [
            dict(resource)
            for resource in raw_resources
            if isinstance(resource, Mapping)
            and resource.get("type") in {"container", "service"}
            and isinstance(resource.get("name"), str)
            and resource["name"]
        ]
    raw_services = current.get("services")
    if not isinstance(raw_services, list):
        return []
    return [
        {
            "type": "service",
            "name": service,
            "selectors": {"service": service},
            "ownership": {
                "compose_project": None,
                "compose_service": None,
                "working_directory": None,
                "config_files": [],
                "complete": False,
            },
        }
        for service in raw_services
        if isinstance(service, str) and service
    ]


def _shell_command(arguments: Sequence[str]) -> str:
    """Render one copy-ready POSIX shell command from exact argument values."""

    return shlex.join(str(argument) for argument in arguments)


def _backup_command(path: str) -> str:
    """Create a timestamped, permission-preserving backup command."""

    quoted_path = shlex.quote(path)
    return (
        f"cp -p -- {quoted_path} "
        f"{quoted_path}.swarm-info.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    )


def _compose_arguments(resource: Mapping[str, Any]) -> list[str] | None:
    """Build the exact Compose ownership prefix or report incomplete mapping."""

    ownership = resource.get("ownership")
    if not isinstance(ownership, Mapping) or ownership.get("complete") is not True:
        return None
    project = ownership.get("compose_project")
    working_directory = ownership.get("working_directory")
    config_files = ownership.get("config_files")
    if (
        not isinstance(project, str)
        or not project
        or not isinstance(working_directory, str)
        or not working_directory
        or not isinstance(config_files, list)
        or not config_files
        or not all(isinstance(path, str) and path for path in config_files)
    ):
        return None
    arguments = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        working_directory,
    ]
    for path in config_files:
        arguments.extend(("--file", path))
    return arguments


def _resource_commands(
    resource: Mapping[str, Any],
    best: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Create non-authorizing host commands only from exact retained evidence."""

    name = str(resource["name"])
    selectors = resource.get("selectors")
    selector_values = selectors if isinstance(selectors, Mapping) else {}
    commands: dict[str, Any] = {
        "verify": _shell_command(["docker", "container", "inspect", name]),
        "focused_rescan": _shell_command(
            [
                "swarm-info",
                "--security-check",
                "--container",
                name,
                "--os",
                "auto",
            ]
        ),
    }
    candidate = best.get("immutable_reference") if best is not None else None
    if isinstance(candidate, str) and candidate:
        commands["candidate_pull"] = _shell_command(["docker", "pull", candidate])
    compose = _compose_arguments(resource)
    ownership = resource.get("ownership")
    if compose is None or not isinstance(ownership, Mapping):
        return commands
    compose_service = ownership.get("compose_service")
    config_files = ownership.get("config_files")
    compose_selector = selector_values.get("compose_service")
    if not isinstance(compose_service, str) or not compose_service:
        return commands
    commands.update(
        {
            "source_backup": [
                _backup_command(path) for path in config_files
            ],
            "compose_validate": _shell_command([*compose, "config", "--quiet"]),
            "compose_pull": _shell_command([*compose, "pull", compose_service]),
            "compose_build": _shell_command(
                [*compose, "build", "--pull", compose_service]
            ),
            "compose_recreate": _shell_command(
                [*compose, "up", "--detach", "--no-deps", compose_service]
            ),
            "verify": _shell_command([*compose, "ps", compose_service]),
        }
    )
    if isinstance(compose_selector, str) and compose_selector:
        commands["focused_rescan"] = _shell_command(
            [
                "swarm-info",
                "--security-check",
                "--compose-service",
                compose_selector,
                "--os",
                "auto",
            ]
        )
    return commands


def _resource_row(
    resource: Mapping[str, Any],
    current: Mapping[str, Any],
    best: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Project image evidence and safe host guidance onto one workload."""

    row = _service_row(resource["name"], current, best)
    row.update(
        {
            "resource_type": resource["type"],
            "resource": resource["name"],
            "selectors": dict(resource.get("selectors") or {}),
            "ownership": dict(resource.get("ownership") or {}),
            "current_lineage": {
                key: current.get(key)
                for key in (
                    "reference",
                    "repository",
                    "tag",
                    "digest",
                    "local_image_id",
                    "version",
                    "version_source",
                    "lifecycle",
                )
            },
            "candidate_lineage": (
                {
                    key: best.get(key)
                    for key in (
                        "reference",
                        "immutable_reference",
                        "tag",
                        "version",
                        "version_source",
                        "compatibility",
                        "tracks",
                        "lifecycle",
                    )
                }
                if best is not None
                else None
            ),
            "commands": _resource_commands(resource, best),
            "deployment_authorized": False,
        }
    )
    return row


def resource_rows(images: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project assessed image evidence onto container-native ownership rows."""

    rows: list[dict[str, Any]] = []
    for image in images:
        current = image["current"]
        raw_best = image.get("best_verified_candidate")
        best = raw_best if isinstance(raw_best, Mapping) else None
        rows.extend(
            _resource_row(resource, current, best)
            for resource in _resource_records(current)
        )
    return sorted(
        rows,
        key=lambda item: (str(item["resource_type"]), str(item["resource"])),
    )


def _source_summary_counts(report: Mapping[str, Any]) -> tuple[int, int]:
    """Return validated global source vulnerability counts."""

    source_summary = report.get("summary")
    if not isinstance(source_summary, Mapping):
        raise ValueError("vulnerability-summary-missing")
    critical = source_summary.get("critical")
    high = source_summary.get("high")
    if (
        isinstance(critical, bool)
        or not isinstance(critical, int)
        or critical < 0
        or isinstance(high, bool)
        or not isinstance(high, int)
        or high < 0
    ):
        raise ValueError("vulnerability-summary-invalid")
    return critical, high


def _selected_reductions(
    images: Sequence[Mapping[str, Any]],
) -> tuple[list[Mapping[str, Any]], int, int]:
    """Return best verified candidates and their total removed findings."""

    selected = [
        image["best_verified_candidate"]
        for image in images
        if isinstance(image["best_verified_candidate"], Mapping)
    ]
    removed_critical = sum(
        item["comparison"]["removed"]["critical"] for item in selected
    )
    removed_high = sum(
        item["comparison"]["removed"]["high"] for item in selected
    )
    return selected, removed_critical, removed_high


def assessment_summary(
    vulnerability_report: Mapping[str, Any],
    images: Sequence[Mapping[str, Any]],
    scans: Mapping[str, ImageScanResult],
    services: Sequence[Mapping[str, Any]],
    resources: Sequence[Mapping[str, Any]],
    errors: Sequence[Mapping[str, str]],
    discovery_error_count: int,
    complete: bool,
) -> dict[str, Any]:
    """Calculate aggregate candidate verdicts and conservative fix potential."""

    candidates = [candidate for image in images for candidate in image["candidates"]]
    verdicts = [str(candidate["security_comparison"]) for candidate in candidates]
    selected, removed_critical, removed_high = _selected_reductions(images)
    source_critical, source_high = _source_summary_counts(vulnerability_report)
    return {
        "status": (
            "incomplete"
            if not complete
            else ("attention" if source_critical + source_high else "clean")
        ),
        "complete": complete,
        "current": {
            "critical": source_critical,
            "high": source_high,
            "total": source_critical + source_high,
        },
        "deployable_fixable": {
            "critical": removed_critical,
            "high": removed_high,
            "total": removed_critical + removed_high,
            "definition": "removed-by-exact-candidate-scan",
            "deployment_authorized": False,
        },
        "conservative_remaining_after_best_candidates": {
            "critical": max(0, source_critical - removed_critical),
            "high": max(0, source_high - removed_high),
            "total": max(
                0,
                source_critical + source_high - removed_critical - removed_high,
            ),
        },
        "candidate_count": len(candidates),
        "unique_candidate_count": len(scans),
        "scanned_candidate_count": sum(
            result.status != "error" for result in scans.values()
        ),
        "failed_candidate_count": sum(
            result.status == "error" for result in scans.values()
        ),
        "verified_clean_count": verdicts.count("verified-clean"),
        "verified_improvement_count": verdicts.count("verified-improvement"),
        "mixed_improvement_count": verdicts.count("mixed-improvement"),
        "not_improved_count": verdicts.count("not-improved"),
        "regression_count": verdicts.count("regression"),
        "images_with_verified_candidate": len(selected),
        "services_with_verified_candidate": sum(
            item["status"] in VERIFIED_STATES for item in services
        ),
        "resources_with_verified_candidate": sum(
            item["status"] in VERIFIED_STATES for item in resources
        ),
        "error_count": len(errors),
        "discovery_error_count": discovery_error_count,
    }
