"""Read-only image-version evidence and validated remediation proposals."""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any, Mapping, Sequence

from scripts.remediation_engine import (
    CandidateValidation,
    RemediationExecutionError,
    validate_candidate_reference,
)
from scripts.remediation_policy import (
    CandidateImage,
    RemediationPolicy,
    RemediationPolicyError,
    image_repository,
    is_mutable_latest,
    parse_candidate_image,
)
from scripts.vulnerability_models import digest_from_reference
from scripts.vulnerability_scout import diagnostic_lines, sanitize_command_error
from scripts.vulnerability_scan import DockerClient


VERSION_LABELS = (
    "org.opencontainers.image.version",
    "org.label-schema.version",
)
TAG_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
BASE_IMAGE_PATTERN = re.compile(r"^Base image is\s+(.+?)\s*$", re.IGNORECASE)


@dataclasses.dataclass(frozen=True)
class ImageMetadata:
    """Registry or local image identity used for version and digest evidence."""

    digest: str | None = None
    version: str | None = None
    version_source: str = "unknown"


@dataclasses.dataclass(frozen=True)
class ScoutBaseAdvice:
    """The current base image and Scout's same-tag refresh recommendation."""

    status: str
    base_image: str | None = None
    refresh_tag: str | None = None
    error: str = ""


@dataclasses.dataclass(frozen=True)
class ImageAdvice:
    """Evidence displayed before the operator edits or deploys a service image."""

    current_tag: str
    current_digest: str | None
    current_version: str | None
    current_version_source: str
    scout: ScoutBaseAdvice
    proposal_state: str
    candidate: CandidateImage | None = None
    candidate_version: str | None = None
    candidate_source: str = "none"
    compatibility: str = "unknown"
    validation: CandidateValidation | None = None
    validation_error: str = ""
    policy_service_count: int = 0

    @property
    def validated_candidate(self) -> CandidateImage | None:
        """Return the proposal only after it passes the shared candidate validator."""

        return self.candidate if self.validation is not None else None


def _reference_tag(reference: str) -> str:
    """Return an explicit image tag, defaulting Docker's omitted tag to latest."""

    name = reference.split("@", 1)[0]
    final_slash = name.rfind("/")
    final_colon = name.rfind(":")
    if final_colon > final_slash:
        return name[final_colon + 1 :]
    return "latest"


def _version_from_config(config: Mapping[str, Any], tag: str) -> tuple[str | None, str]:
    """Prefer standard OCI version labels, then a meaningful configured tag."""

    labels = config.get("Labels") or config.get("labels") or {}
    if isinstance(labels, Mapping):
        normalized = {str(key).lower(): value for key, value in labels.items()}
        for label in VERSION_LABELS:
            value = normalized.get(label)
            if isinstance(value, str) and value.strip():
                return value.strip(), label
    if tag.lower() != "latest" and TAG_PATTERN.fullmatch(tag):
        return tag, "configured-tag"
    return None, "unknown"


def _parse_image_inspect(raw: str, tag: str) -> ImageMetadata | None:
    """Parse a local ``docker image inspect`` response without trusting free text."""

    try:
        payload = json.loads(raw)
        item = payload[0] if isinstance(payload, list) else payload
    except (IndexError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(item, Mapping):
        return None
    config = item.get("Config") or item.get("config") or {}
    version, source = (
        _version_from_config(config, tag)
        if isinstance(config, Mapping)
        else (None, "unknown")
    )
    digests = item.get("RepoDigests") or item.get("repoDigests") or []
    digest = None
    if isinstance(digests, Sequence) and not isinstance(digests, (str, bytes)):
        for reference in digests:
            if isinstance(reference, str) and digest_from_reference(reference):
                digest = digest_from_reference(reference)
                break
    return ImageMetadata(digest, version, source)


def _platform_descriptor(
    manifest: Mapping[str, Any], platform: str
) -> Mapping[str, Any] | None:
    """Select one real (non-attestation) manifest for the requested platform."""

    requested = platform.split("/")
    if len(requested) < 2:
        return None
    requested_os, requested_architecture = requested[:2]
    requested_variant = requested[2] if len(requested) > 2 else None
    descriptors = manifest.get("manifests")
    if not isinstance(descriptors, Sequence) or isinstance(descriptors, (str, bytes)):
        return None
    for descriptor in descriptors:
        if not isinstance(descriptor, Mapping):
            continue
        descriptor_platform = descriptor.get("platform")
        if not isinstance(descriptor_platform, Mapping):
            continue
        if descriptor_platform.get("os") != requested_os:
            continue
        if descriptor_platform.get("architecture") != requested_architecture:
            continue
        if requested_variant and descriptor_platform.get("variant") != requested_variant:
            continue
        return descriptor
    return None


def _parse_imagetools(raw: str, tag: str, platform: str) -> ImageMetadata | None:
    """Parse Buildx JSON registry metadata, including OCI image labels."""

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, Mapping):
        return None
    manifest = payload.get("manifest") or payload.get("Manifest") or {}
    image = (
        payload.get("image")
        or payload.get("Image")
        or payload.get(platform)
        or {}
    )
    digest = manifest.get("digest") if isinstance(manifest, Mapping) else None
    config = image.get("config") or image.get("Config") or {}
    version, source = (
        _version_from_config(config, tag)
        if isinstance(config, Mapping)
        else (None, "unknown")
    )
    if version is None and isinstance(manifest, Mapping):
        descriptor = _platform_descriptor(manifest, platform)
        annotations = descriptor.get("annotations") if descriptor else None
        if isinstance(annotations, Mapping):
            version, source = _version_from_config({"Labels": annotations}, tag)
    return ImageMetadata(
        digest if isinstance(digest, str) and digest_from_reference(f"x@{digest}") else None,
        version,
        source,
    )


def _parse_manifest_inspect(
    raw: str, tag: str, platform: str
) -> ImageMetadata | None:
    """Parse Docker's portable verbose manifest fallback for one platform."""

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    records = payload if isinstance(payload, list) else [payload]
    requested = platform.split("/")
    requested_os = requested[0] if requested else ""
    requested_architecture = requested[1] if len(requested) > 1 else ""
    requested_variant = requested[2] if len(requested) > 2 else None
    fallback: Mapping[str, Any] | None = None
    for record in records:
        if not isinstance(record, Mapping):
            continue
        fallback = fallback or record
        record_platform = record.get("Platform") or record.get("platform")
        if not isinstance(record_platform, Mapping):
            continue
        architecture = record_platform.get("architecture") or record_platform.get("Architecture")
        operating_system = record_platform.get("os") or record_platform.get("Os")
        variant = record_platform.get("variant") or record_platform.get("Variant")
        if operating_system != requested_os or architecture != requested_architecture:
            continue
        if requested_variant and variant != requested_variant:
            continue
        fallback = record
        break
    if fallback is None:
        return None
    digest = fallback.get("Digest") or fallback.get("digest")
    return ImageMetadata(
        digest if isinstance(digest, str) and digest_from_reference(f"x@{digest}") else None,
        tag if tag.lower() != "latest" else None,
        "configured-tag" if tag.lower() != "latest" else "unknown",
    )


def inspect_image_metadata(
    client: DockerClient,
    reference: str,
    registry: bool = False,
    platform: str = "linux/amd64",
) -> ImageMetadata:
    """Read local metadata first or query registry metadata through Buildx."""

    tag = _reference_tag(reference)
    if not registry:
        local = client.run(["image", "inspect", reference])
        if local.return_code == 0:
            parsed = _parse_image_inspect(local.stdout, tag)
            if parsed is not None:
                return parsed
    remote = client.run(
        [
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "{{json .}}",
            reference,
        ]
    )
    if remote.return_code == 0:
        parsed = _parse_imagetools(remote.stdout, tag, platform)
        if parsed is not None:
            return parsed
    manifest = client.run(["manifest", "inspect", "--verbose", reference])
    if manifest.return_code == 0:
        parsed = _parse_manifest_inspect(manifest.stdout, tag, platform)
        if parsed is not None:
            return parsed
    return ImageMetadata(
        version=tag if tag.lower() != "latest" else None,
        version_source=(
            "configured-tag" if tag.lower() != "latest" else "unknown"
        ),
    )


def parse_scout_base_advice(return_code: int, output: str) -> ScoutBaseAdvice:
    """Extract only stable base-image evidence from Scout's human report."""

    lines = diagnostic_lines(output)
    base_image = None
    refresh_tag = None
    in_refresh = False
    for line in lines:
        match = BASE_IMAGE_PATTERN.match(line)
        if match:
            base_image = match.group(1).strip()
            continue
        if line.lower() == "refresh base image":
            in_refresh = True
            continue
        if in_refresh and "│" in line:
            first_column = line.split("│", 1)[0].strip()
            if first_column.lower() == "tag" or not TAG_PATTERN.fullmatch(first_column):
                continue
            refresh_tag = first_column
            break
    lowered = " ".join(lines).lower()
    if "image has no base image" in lowered:
        return ScoutBaseAdvice("no-base")
    if base_image:
        return ScoutBaseAdvice("available", base_image, refresh_tag)
    if return_code not in {0, 2}:
        return ScoutBaseAdvice("error", error=sanitize_command_error(output))
    return ScoutBaseAdvice("unavailable")


def _policy_candidate(
    policy: RemediationPolicy | None,
    item: Mapping[str, Any],
) -> tuple[CandidateImage | None, int, str]:
    """Return one consistent enabled policy candidate for the selected consumers."""

    if policy is None:
        return None, 0, "none"
    services = {str(service) for service in item.get("services", [])}
    repository = image_repository(str(item.get("image", "")))
    matching = [
        target
        for target in policy.targets
        if target.enabled
        and target.service in services
        and target.repository == repository
    ]
    candidates = {target.candidate for target in matching}
    if len(candidates) > 1:
        return None, len(matching), "policy-conflict"
    return (next(iter(candidates)), len(matching), "policy") if candidates else (None, 0, "none")


def _major(version: str | None) -> int | None:
    """Extract a leading semantic-style major version when one is visible."""

    if not version:
        return None
    match = re.search(r"(?:^|[^0-9])v?(\d+)(?:\.|$)", version, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _compatibility(current: str | None, candidate: str | None) -> str:
    """Classify only the visible major-version relationship."""

    current_major = _major(current)
    candidate_major = _major(candidate)
    if current_major is None or candidate_major is None:
        return "unknown"
    return "same-major" if current_major == candidate_major else "major-change"


def analyze_image(
    client: DockerClient,
    item: Mapping[str, Any],
    platform: str,
    policy: RemediationPolicy | None = None,
    include_scout_recommendations: bool = True,
) -> ImageAdvice:
    """Gather version and candidate evidence, with optional base-image advice."""

    image = str(item.get("image", ""))
    current_tag = _reference_tag(image)
    current_digest = digest_from_reference(image)
    current_metadata = inspect_image_metadata(client, image, platform=platform)
    if include_scout_recommendations:
        recommendation = client.run(
            ["scout", "recommendations", "--platform", platform, image]
        )
        scout = parse_scout_base_advice(
            recommendation.return_code,
            "\n".join((recommendation.stderr, recommendation.stdout)),
        )
    else:
        scout = ScoutBaseAdvice("skipped")
    candidate, policy_count, source = _policy_candidate(policy, item)
    proposal_state = source if source == "policy-conflict" else "manual-review"
    candidate_metadata = ImageMetadata()

    if candidate is not None:
        candidate_metadata = inspect_image_metadata(
            client,
            candidate.reference,
            registry=True,
            platform=platform,
        )
        proposal_state = "candidate-found"
    elif current_tag.lower() == "latest" and current_digest:
        latest_reference = f"{image_repository(image)}:latest"
        deployed_registry_metadata = inspect_image_metadata(
            client,
            image,
            registry=True,
            platform=platform,
        )
        if current_metadata.version is None and deployed_registry_metadata.version:
            current_metadata = deployed_registry_metadata
        candidate_metadata = inspect_image_metadata(
            client,
            latest_reference,
            registry=True,
            platform=platform,
        )
        comparable_current_digest = deployed_registry_metadata.digest or current_digest
        if candidate_metadata.digest is None:
            proposal_state = "latest-unresolved"
        elif candidate_metadata.digest.lower() == comparable_current_digest.lower():
            proposal_state = "latest-current"
        else:
            try:
                candidate = parse_candidate_image(
                    f"{latest_reference}@{candidate_metadata.digest}"
                )
                source = "latest-refresh"
                proposal_state = "candidate-found"
            except RemediationPolicyError:
                proposal_state = "latest-unresolved"

    if candidate is None:
        return ImageAdvice(
            current_tag,
            current_digest,
            current_metadata.version,
            current_metadata.version_source,
            scout,
            proposal_state,
            candidate_source=source,
            policy_service_count=policy_count,
        )

    candidate_version = candidate_metadata.version or (
        candidate.tag if candidate.tag.lower() != "latest" else None
    )
    try:
        validation = validate_candidate_reference(
            client,
            candidate,
            str(item.get("service", "candidate")),
            item,
            platform,
        )
    except RemediationExecutionError as error:
        return ImageAdvice(
            current_tag,
            current_digest,
            current_metadata.version,
            current_metadata.version_source,
            scout,
            "candidate-rejected",
            candidate,
            candidate_version,
            source,
            _compatibility(current_metadata.version, candidate_version),
            validation_error=error.code,
            policy_service_count=policy_count,
        )
    return ImageAdvice(
        current_tag,
        current_digest,
        current_metadata.version,
        current_metadata.version_source,
        scout,
        "candidate-validated",
        candidate,
        candidate_version,
        source,
        _compatibility(current_metadata.version, candidate_version),
        validation,
        policy_service_count=policy_count,
    )
