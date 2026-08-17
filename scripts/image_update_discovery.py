"""Discover read-only image update candidates from vulnerability evidence.

The workflow consumes an existing vulnerability report, enumerates only
explicitly approved registry hosts, classifies strict stable SemVer tracks,
and resolves selected tags through Docker to immutable artifact digests. It
does not run Docker Scout, mutate deployments, or authorize remediation.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence

from scripts.image_update_registry import (
    RegistryTag,
    RegistryTagClient,
    TagListing,
)
from scripts.image_update_selection import (
    CandidateSelection,
    SemanticVersion,
    latest_selection,
    parse_semver,
    select_semver_candidates,
    stable_tags,
    successor_selections,
)
from scripts.operator_report import (
    safe_text,
)
from scripts.remediation_advice import ImageMetadata, inspect_image_metadata
from scripts.remediation_policy import (
    RemediationPolicy,
    RemediationPolicyError,
    SuccessorRule,
    image_repository,
    load_policy,
)
from scripts.vulnerability_models import digest_from_reference, utc_timestamp
from scripts.vulnerability_scan import DockerClient


SCHEMA_VERSION = 1
DEFAULT_MAX_REGISTRY_TAGS = 2000
FULL_SHA256_PATTERN = re.compile(r"sha256:[0-9a-fA-F]{64}")
ProgressCallback = Callable[[int, int, str], None]


class ImageUpdateDiscoveryError(RuntimeError):
    """Describe one safe discovery failure with a stable localized code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a bounded single-line diagnostic without report contents."""

        super().__init__(code)
        self.code = code
        self.detail = safe_text(detail)[:500]


@dataclasses.dataclass(frozen=True)
class DiscoveryOutcome:
    """Complete candidate report and its public process exit status."""

    report: Mapping[str, Any]
    exit_code: int


def load_vulnerability_report(path: Path) -> dict[str, Any]:
    """Load the schema-v2 source report required for candidate discovery."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ImageUpdateDiscoveryError("report-unreadable", str(path)) from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise ImageUpdateDiscoveryError("report-schema", str(path))
    images = payload.get("images")
    if not isinstance(images, list):
        raise ImageUpdateDiscoveryError("report-images", str(path))
    return payload


def _reference_tag(reference: str) -> str:
    """Return the configured tag, defaulting an omitted tag to ``latest``."""

    name = reference.split("@", 1)[0]
    final_slash = name.rfind("/")
    final_colon = name.rfind(":")
    return name[final_colon + 1 :] if final_colon > final_slash else "latest"


def _timestamp(value: object) -> dt.datetime | None:
    """Parse one optional image timestamp into aware UTC time."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _lifecycle_evidence(
    tag: RegistryTag | None,
    metadata: ImageMetadata,
    now: dt.datetime,
) -> dict[str, Any]:
    """Prefer registry publication time and retain the exact evidence source."""

    published = _timestamp(tag.updated_at) if tag is not None else None
    source = tag.updated_at_source if published is not None and tag is not None else "unknown"
    if published is None:
        published = _timestamp(metadata.created_at)
        source = metadata.created_at_source if published is not None else "unknown"
    return {
        "timestamp": (
            published.isoformat().replace("+00:00", "Z")
            if published is not None
            else None
        ),
        "source": source,
        "age_days": (
            max(0.0, round((now - published).total_seconds() / 86400, 1))
            if published is not None
            else None
        ),
    }


def _current_reference(image: Mapping[str, Any]) -> str:
    """Bind the source image reference to its reported digest when available."""

    reference = image.get("reference")
    if not isinstance(reference, str) or not reference.strip():
        raise ImageUpdateDiscoveryError("image-reference")
    digest = image.get("digest")
    if (
        "@" not in reference
        and isinstance(digest, str)
        and FULL_SHA256_PATTERN.fullmatch(digest)
    ):
        return f"{reference}@{digest}"
    return reference


def _full_sha256(value: object) -> str | None:
    """Return one complete normalized SHA-256 digest or no identity."""

    if not isinstance(value, str) or not FULL_SHA256_PATTERN.fullmatch(value):
        return None
    return value.lower()


def _service_names(image: Mapping[str, Any]) -> list[str]:
    """Extract sorted service names without copying unrelated report fields."""

    services = image.get("services")
    if not isinstance(services, list):
        return []
    return sorted(
        {
            item["name"]
            for item in services
            if isinstance(item, Mapping)
            and isinstance(item.get("name"), str)
            and item["name"]
        }
    )


def _compatibility(
    current: SemanticVersion | None,
    candidate: SemanticVersion | None,
    successor: bool,
) -> str:
    """Classify visible version distance without claiming runtime compatibility."""

    if successor:
        return "successor-manual-review"
    if current is None or candidate is None:
        return "unknown"
    if current.major != candidate.major:
        return "major-change"
    if current.minor != candidate.minor:
        return "same-major"
    return "same-minor"


def _metadata_reference(repository: str, tag: str) -> str:
    """Build one canonical mutable reference for Docker metadata resolution."""

    return f"{repository}:{tag}"


def _cached_metadata(
    client: DockerClient,
    cache: dict[str, ImageMetadata],
    reference: str,
    platform: str,
) -> ImageMetadata:
    """Resolve registry metadata once for each exact requested reference."""

    if reference not in cache:
        cache[reference] = inspect_image_metadata(
            client, reference, registry=True, platform=platform
        )
    return cache[reference]


def _merge_current_metadata(
    reported: ImageMetadata,
    inspected: ImageMetadata,
) -> ImageMetadata:
    """Retain report identity when optional registry metadata is unavailable."""

    return ImageMetadata(
        digest=_full_sha256(inspected.digest) or _full_sha256(reported.digest),
        version=inspected.version or reported.version,
        version_source=(
            inspected.version_source
            if inspected.version is not None
            else reported.version_source
        ),
        local_image_id=inspected.local_image_id,
        created_at=inspected.created_at,
        created_at_source=inspected.created_at_source,
    )


def _resolve_candidates(
    client: DockerClient,
    selections: Sequence[CandidateSelection],
    current_digest: str | None,
    current_version: SemanticVersion | None,
    platform: str,
    now: dt.datetime,
    metadata_cache: dict[str, ImageMetadata],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Resolve candidate tags and merge track aliases by immutable digest."""

    candidates: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    for selection in selections:
        reference = _metadata_reference(selection.repository, selection.tag.name)
        metadata = _cached_metadata(client, metadata_cache, reference, platform)
        candidate_digest = _full_sha256(metadata.digest)
        if candidate_digest is None:
            errors.append({"repository": selection.repository, "status": "digest-unresolved"})
            continue
        if current_digest and candidate_digest == current_digest.lower():
            continue
        key = f"{selection.repository}@{candidate_digest}"
        existing = candidates.get(key)
        if existing is not None:
            existing["tags"] = sorted(set(existing["tags"]) | {selection.tag.name})
            existing["tracks"] = sorted(set(existing["tracks"]) | set(selection.tracks))
            continue
        candidate_version = selection.version or parse_semver(metadata.version)
        successor = selection.successor
        candidates[key] = {
            "reference": reference,
            "repository": selection.repository,
            "tag": selection.tag.name,
            "tags": [selection.tag.name],
            "digest": candidate_digest,
            "immutable_reference": f"{reference}@{candidate_digest}",
            "platform": platform,
            "version": metadata.version or (
                candidate_version.text() if candidate_version is not None else None
            ),
            "version_source": metadata.version_source,
            "tracks": list(selection.tracks),
            "source": selection.source,
            "compatibility": _compatibility(
                current_version, candidate_version, successor is not None
            ),
            "lifecycle": _lifecycle_evidence(selection.tag, metadata, now),
            "successor_evidence": (
                {
                    "id": successor.identifier,
                    "reason": successor.reason,
                    "url": successor.evidence_url,
                }
                if successor is not None
                else None
            ),
            "security_comparison": "not-scanned",
            "deployment_authorized": False,
        }
    return sorted(candidates.values(), key=lambda item: (item["repository"], item["tag"])), errors


def _collect_listings(
    image_records: Sequence[Mapping[str, Any]],
    policy: RemediationPolicy | None,
    registry_client: RegistryTagClient,
    max_tags: int,
    progress: ProgressCallback | None,
) -> tuple[list[str], dict[str, TagListing]]:
    """Enumerate each current or reviewed successor repository exactly once."""

    repositories = {
        image_repository(_current_reference(item)) for item in image_records
    }
    repositories.update(
        rule.successor_repository for rule in (policy.successors if policy else ())
    )
    ordered_repositories = sorted(repositories)
    listings: dict[str, TagListing] = {}
    for index, repository in enumerate(ordered_repositories, start=1):
        if progress is not None:
            progress(index, len(ordered_repositories), repository)
        listings[repository] = registry_client.list_tags(repository, max_tags)
    return ordered_repositories, listings


def _listing_diagnostics(
    listings: Mapping[str, TagListing],
) -> tuple[set[str], list[dict[str, str]]]:
    """Separate network approvals from sanitized operational errors."""

    required_hosts: set[str] = set()
    errors: list[dict[str, str]] = []
    for listing in listings.values():
        if listing.status == "registry-approval-required":
            required_hosts.add(listing.repository.registry)
        elif listing.status != "ok":
            errors.append(
                {
                    "repository": listing.repository.canonical,
                    "status": listing.status,
                    "detail": listing.error,
                }
            )
    return required_hosts, errors


@dataclasses.dataclass(frozen=True)
class CurrentImageEvidence:
    """Normalized current image identity used to select update tracks."""

    reference: str
    repository: str
    tag: str
    tag_record: RegistryTag | None
    metadata: ImageMetadata
    version: SemanticVersion | None


def _current_image_evidence(
    image: Mapping[str, Any],
    listing: TagListing,
    client: DockerClient,
    platform: str,
    metadata_cache: dict[str, ImageMetadata],
) -> CurrentImageEvidence:
    """Resolve current version and lifecycle metadata without trusting prefixes."""

    current_reference = _current_reference(image)
    repository = image_repository(current_reference)
    current_tag = _reference_tag(current_reference)
    current_tag_record = next(
        (tag for tag in listing.tags if tag.name == current_tag),
        None,
    )
    reported_digest = image.get("digest")
    metadata = ImageMetadata(
        digest=(
            _full_sha256(reported_digest)
            or _full_sha256(digest_from_reference(current_reference))
        ),
        version=(current_tag if parse_semver(current_tag) else None),
        version_source=("configured-tag" if parse_semver(current_tag) else "unknown"),
    )
    if listing.status == "ok":
        metadata = _merge_current_metadata(
            metadata,
            _cached_metadata(
                client,
                metadata_cache,
                current_reference,
                platform,
            ),
        )
    visible_version = parse_semver(current_tag) or parse_semver(metadata.version)
    return CurrentImageEvidence(
        current_reference,
        repository,
        current_tag,
        current_tag_record,
        metadata,
        visible_version,
    )


def _discover_for_image(
    image: Mapping[str, Any],
    listings: Mapping[str, TagListing],
    successors: Mapping[str, SuccessorRule],
    client: DockerClient,
    platform: str,
    evaluated_at: dt.datetime,
    metadata_cache: dict[str, ImageMetadata],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Build candidate and lifecycle evidence for one current report image."""

    repository = image_repository(_current_reference(image))
    listing = listings[repository]
    current = _current_image_evidence(
        image,
        listing,
        client,
        platform,
        metadata_cache,
    )
    selections = list(select_semver_candidates(current.version, listing))
    if current.tag.lower() == "latest":
        latest = latest_selection(listing, "latest-refresh")
        if latest is not None:
            selections.append(latest)
    successor = successors.get(repository)
    if successor is not None:
        selections.extend(
            successor_selections(
                successor,
                listings[successor.successor_repository],
            )
        )
    candidates, errors = _resolve_candidates(
        client,
        selections,
        current.metadata.digest,
        current.version,
        platform,
        evaluated_at,
        metadata_cache,
    )
    return (
        {
            "current": {
                "reference": str(image.get("reference", "")),
                "repository": repository,
                "tag": current.tag,
                "digest": current.metadata.digest,
                "platform": platform,
                "version": current.metadata.version,
                "version_source": current.metadata.version_source,
                "services": _service_names(image),
                "vulnerability_status": image.get("status"),
                "lifecycle": _lifecycle_evidence(
                    current.tag_record,
                    current.metadata,
                    evaluated_at,
                ),
            },
            "discovery": {
                "status": listing.status,
                "complete": listing.complete,
                "tag_count": len(listing.tags),
                "strict_semver_tag_count": len(stable_tags(listing)),
            },
            "candidates": candidates,
        },
        errors,
    )


def _build_report(
    *,
    report: Mapping[str, Any],
    report_path: Path,
    platform: str,
    max_tags: int,
    policy: RemediationPolicy | None,
    started_at: str,
    source_complete: bool,
    complete: bool,
    repositories: Sequence[str],
    required_hosts: set[str],
    images: list[dict[str, Any]],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    """Assemble the versioned, non-authorizing discovery report."""

    candidate_count = sum(len(item["candidates"]) for item in images)
    scope = report.get("scope")
    return {
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "completed_at": utc_timestamp(),
        "complete": complete,
        "source_report": {
            "path": str(report_path),
            "schema_version": report.get("schema_version"),
            "completed_at": report.get("completed_at"),
            "complete": source_complete,
            "image_fingerprint": (
                scope.get("image_fingerprint")
                if isinstance(scope, Mapping)
                else None
            ),
        },
        "policy": {
            "platform": platform,
            "strict_stable_semver_only": True,
            "max_registry_tags": max_tags,
            "network_requires_explicit_registry_hosts": True,
            "registry_credentials_used": False,
            "remediation_policy": str(policy.path) if policy is not None else None,
            "remediation_authorized": False,
        },
        "summary": {
            "image_count": len(images),
            "repository_count": len(repositories),
            "candidate_count": candidate_count,
            "images_with_candidates": sum(bool(item["candidates"]) for item in images),
            "successor_rule_count": len(policy.successors) if policy is not None else 0,
            "error_count": len(errors),
            "registry_approval_required_count": len(required_hosts),
        },
        "required_registry_hosts": sorted(required_hosts),
        "images": images,
        "errors": errors,
    }


def discover_image_updates(
    report: Mapping[str, Any],
    report_path: Path,
    client: DockerClient,
    registry_client: RegistryTagClient,
    platform: str,
    max_tags: int,
    policy: RemediationPolicy | None = None,
    now: dt.datetime | None = None,
    progress: ProgressCallback | None = None,
) -> DiscoveryOutcome:
    """Build complete read-only candidate and lifecycle evidence for every image."""

    evaluated_at = now or dt.datetime.now(dt.timezone.utc)
    started_at = utc_timestamp()
    raw_images = report.get("images")
    if not isinstance(raw_images, list):
        raise ImageUpdateDiscoveryError("report-images", str(report_path))
    image_records = [item for item in raw_images if isinstance(item, Mapping)]
    repositories, listings = _collect_listings(
        image_records,
        policy,
        registry_client,
        max_tags,
        progress,
    )
    required_hosts, errors = _listing_diagnostics(listings)
    successors = {
        rule.repository: rule for rule in (policy.successors if policy else ())
    }
    metadata_cache: dict[str, ImageMetadata] = {}
    output_images: list[dict[str, Any]] = []
    for image in image_records:
        discovered, image_errors = _discover_for_image(
            image,
            listings,
            successors,
            client,
            platform,
            evaluated_at,
            metadata_cache,
        )
        output_images.append(discovered)
        errors.extend(image_errors)

    source_summary = report.get("summary")
    source_complete = bool(
        isinstance(source_summary, Mapping) and source_summary.get("complete") is True
    )
    complete = source_complete and not required_hosts and not errors and all(
        item["discovery"]["complete"] for item in output_images
    )
    report_payload = _build_report(
        report=report,
        report_path=report_path,
        platform=platform,
        max_tags=max_tags,
        policy=policy,
        started_at=started_at,
        source_complete=source_complete,
        complete=complete,
        repositories=repositories,
        required_hosts=required_hosts,
        images=output_images,
        errors=errors,
    )
    return DiscoveryOutcome(report_payload, 0 if complete else 3)
