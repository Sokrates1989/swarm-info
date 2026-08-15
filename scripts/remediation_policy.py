"""Strict policy and plan construction for vulnerability remediation.

The generated deployment map remains evidence, while this module loads the
operator-owned policy that authorizes a specific candidate image and source
edit.  A policy cannot weaken the mandatory backup, digest, repository, or
mapping safeguards enforced by the execution layer.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from scripts.deployment_mapping import normalized_image_reference
from scripts.vulnerability_models import digest_from_reference, utc_timestamp


POLICY_SCHEMA_VERSION = 2
SUPPORTED_POLICY_SCHEMA_VERSIONS = (1, POLICY_SCHEMA_VERSION)
PLAN_SCHEMA_VERSION = 2
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
TAG_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


class RemediationPolicyError(ValueError):
    """Describe rejected operator policy using a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a stable code and non-secret diagnostic detail."""

        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class CandidateImage:
    """One explicit immutable replacement image."""

    reference: str
    repository: str
    tag: str
    digest: str


@dataclasses.dataclass(frozen=True)
class SourceEdit:
    """A fail-closed declarative source-edit adapter configuration."""

    edit_type: str
    file: str
    image_key: str | None = None
    name_key: str | None = None
    version_key: str | None = None


@dataclasses.dataclass(frozen=True)
class PolicyTarget:
    """One installation-specific remediation authorization."""

    identifier: str
    enabled: bool
    service: str
    repository: str
    candidate: CandidateImage
    backup_status: str
    backup_reason: str
    auto_eligible: bool
    source: SourceEdit | None
    timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class RemediationPolicy:
    """Validated remediation policy loaded from an operator-owned file."""

    path: Path
    targets: tuple[PolicyTarget, ...]


def _required_string(mapping: Mapping[str, Any], key: str, code: str) -> str:
    """Return one non-empty policy string or raise a stable validation error."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RemediationPolicyError(code, key)
    return value.strip()


def _reject_unknown(
    mapping: Mapping[str, Any], allowed: set[str], code: str
) -> None:
    """Reject misspelled or unreviewed policy fields instead of ignoring them."""

    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise RemediationPolicyError(code, ", ".join(unknown))


def parse_candidate_image(value: str) -> CandidateImage:
    """Require a tagged image pinned to a complete SHA-256 digest."""

    name, separator, digest = value.strip().partition("@")
    if not separator or not SHA256_PATTERN.fullmatch(digest):
        raise RemediationPolicyError("candidateDigest")
    final_slash = name.rfind("/")
    final_colon = name.rfind(":")
    if final_colon <= final_slash or final_colon == len(name) - 1:
        raise RemediationPolicyError("candidateTag")
    tag = name[final_colon + 1 :]
    if not TAG_PATTERN.fullmatch(tag) or any(character.isspace() for character in name):
        raise RemediationPolicyError("candidateTag")
    normalized_name, _ = normalized_image_reference(name)
    repository = normalized_name.rsplit(":", 1)[0]
    return CandidateImage(value.strip(), repository, tag, digest.lower())


def image_repository(reference: str) -> str:
    """Return a canonical repository without tag or digest."""

    normalized, _ = normalized_image_reference(reference)
    return normalized.rsplit(":", 1)[0]


def is_mutable_latest(reference: object) -> bool:
    """Return whether a source image deliberately follows an unpinned latest tag."""

    if not isinstance(reference, str) or not reference.strip() or "@" in reference:
        return False
    name = reference.strip()
    final_slash = name.rfind("/")
    final_colon = name.rfind(":")
    tag = name[final_colon + 1 :] if final_colon > final_slash else "latest"
    return tag.lower() == "latest"


def _parse_source(raw: object) -> SourceEdit | None:
    """Parse an optional dotenv or exact Compose-image source adapter."""

    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise RemediationPolicyError("sourceObject")
    _reject_unknown(
        raw,
        {"type", "file", "image_key", "name_key", "version_key"},
        "sourceUnknownField",
    )
    edit_type = _required_string(raw, "type", "sourceType")
    file = _required_string(raw, "file", "sourceFile")
    source_path = Path(file)
    if source_path.is_absolute() or ".." in source_path.parts:
        raise RemediationPolicyError("sourcePath", file)
    if edit_type == "yaml_image":
        return SourceEdit(edit_type, file)
    if edit_type != "dotenv":
        raise RemediationPolicyError("sourceType", edit_type)
    image_key = raw.get("image_key")
    name_key = raw.get("name_key")
    version_key = raw.get("version_key")
    if image_key is not None:
        if not isinstance(image_key, str) or not SAFE_IDENTIFIER_PATTERN.fullmatch(
            image_key
        ):
            raise RemediationPolicyError("sourceKey", "image_key")
        if name_key is not None or version_key is not None:
            raise RemediationPolicyError("sourceKeysExclusive")
        return SourceEdit(edit_type, file, image_key=image_key)
    if not (
        isinstance(name_key, str)
        and SAFE_IDENTIFIER_PATTERN.fullmatch(name_key)
        and isinstance(version_key, str)
        and SAFE_IDENTIFIER_PATTERN.fullmatch(version_key)
    ):
        raise RemediationPolicyError("sourceKeysRequired")
    return SourceEdit(
        edit_type, file, name_key=name_key, version_key=version_key
    )


def _parse_target(raw: object, identifiers: set[str]) -> PolicyTarget:
    """Parse one strict policy target and reject duplicate identities."""

    if not isinstance(raw, Mapping):
        raise RemediationPolicyError("targetObject")
    _reject_unknown(
        raw,
        {
            "id",
            "enabled",
            "match",
            "candidate_image",
            "backup",
            "auto_eligible",
            "source",
            "verification",
        },
        "targetUnknownField",
    )
    identifier = _required_string(raw, "id", "targetId")
    if not SAFE_IDENTIFIER_PATTERN.fullmatch(identifier) or identifier in identifiers:
        raise RemediationPolicyError("targetId", identifier)
    identifiers.add(identifier)
    match = raw.get("match")
    if not isinstance(match, Mapping):
        raise RemediationPolicyError("targetMatch", identifier)
    _reject_unknown(match, {"service", "repository"}, "matchUnknownField")
    service = _required_string(match, "service", "targetService")
    if not SERVICE_PATTERN.fullmatch(service):
        raise RemediationPolicyError("targetService", identifier)
    repository = image_repository(
        _required_string(match, "repository", "targetRepository")
    )
    candidate = parse_candidate_image(
        _required_string(raw, "candidate_image", "candidateImage")
    )
    if candidate.repository != repository:
        raise RemediationPolicyError("candidateRepository", identifier)
    backup = raw.get("backup")
    if not isinstance(backup, Mapping):
        raise RemediationPolicyError("backupObject", identifier)
    _reject_unknown(backup, {"status", "reason"}, "backupUnknownField")
    backup_status = _required_string(backup, "status", "backupStatus")
    backup_reason = _required_string(backup, "reason", "backupReason")
    if len(backup_reason) > 500 or "\n" in backup_reason or "\r" in backup_reason:
        raise RemediationPolicyError("backupReason", identifier)
    verification = raw.get("verification", {})
    if not isinstance(verification, Mapping):
        raise RemediationPolicyError("verificationObject", identifier)
    _reject_unknown(
        verification, {"timeout_seconds"}, "verificationUnknownField"
    )
    timeout = verification.get("timeout_seconds", 300)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 30 <= timeout <= 1800:
        raise RemediationPolicyError("verificationTimeout", identifier)
    enabled = raw.get("enabled", True)
    auto_eligible = raw.get("auto_eligible", False)
    if not isinstance(enabled, bool) or not isinstance(auto_eligible, bool):
        raise RemediationPolicyError("booleanField", identifier)
    return PolicyTarget(
        identifier=identifier,
        enabled=enabled,
        service=service,
        repository=repository,
        candidate=candidate,
        backup_status=backup_status,
        backup_reason=backup_reason,
        auto_eligible=auto_eligible,
        source=_parse_source(raw.get("source")),
        timeout_seconds=timeout,
    )


def load_policy(path: Path) -> RemediationPolicy:
    """Load and validate a JSON remediation policy without expanding values."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RemediationPolicyError("policyUnreadable", str(path)) from error
    if not isinstance(payload, Mapping):
        raise RemediationPolicyError("policyObject")
    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_POLICY_SCHEMA_VERSIONS:
        raise RemediationPolicyError("policySchema")
    allowed_fields = {"schema_version", "targets"}
    if schema_version == POLICY_SCHEMA_VERSION:
        allowed_fields.add("generated_review")
    _reject_unknown(payload, allowed_fields, "policyUnknownField")
    generated_review = payload.get("generated_review")
    if generated_review is not None and not isinstance(generated_review, Mapping):
        raise RemediationPolicyError("policyReview")
    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes)):
        raise RemediationPolicyError("policyTargets")
    identifiers: set[str] = set()
    targets = tuple(_parse_target(item, identifiers) for item in raw_targets)
    services = [target.service for target in targets]
    if len(set(services)) != len(services):
        raise RemediationPolicyError("targetServiceDuplicate")
    return RemediationPolicy(path.resolve(), targets)


def _finding_ids(image: Mapping[str, Any]) -> list[str]:
    """Extract current normalized finding identifiers for plan evidence."""

    findings = image.get("findings")
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        return []
    return sorted(
        {
            item["id"]
            for item in findings
            if isinstance(item, Mapping)
            and isinstance(item.get("id"), str)
            and item["id"]
        }
    )


def _count(image: Mapping[str, Any], severity: str) -> int:
    """Return one non-negative per-image severity count."""

    counts = image.get("counts")
    value = counts.get(severity, 0) if isinstance(counts, Mapping) else 0
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def vulnerable_items(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten fresh vulnerable image evidence into priority-sorted services."""

    images = report.get("images")
    if not isinstance(images, Sequence) or isinstance(images, (str, bytes)):
        return []
    items: list[dict[str, Any]] = []
    for image in images:
        if not isinstance(image, Mapping) or image.get("status") != "vulnerable":
            continue
        services = image.get("services")
        service_names = sorted(
            service["name"]
            for service in services or []
            if isinstance(service, Mapping)
            and isinstance(service.get("name"), str)
        )
        service_records = {
            service["name"]: service
            for service in services or []
            if isinstance(service, Mapping)
            and isinstance(service.get("name"), str)
        }
        for service_name in service_names:
            service_image = service_records[service_name].get("image")
            exact_image = (
                service_image
                if isinstance(service_image, str) and service_image
                else str(image.get("reference", ""))
            )
            items.append(
                {
                    "service": service_name,
                    "image": exact_image,
                    "scan_reference": str(image.get("reference", "")),
                    "repository": image_repository(exact_image),
                    "critical": _count(image, "critical"),
                    "high": _count(image, "high"),
                    "finding_ids": _finding_ids(image),
                    "shared_service_count": len(service_names),
                    "services": service_names,
                }
            )
    return sorted(
        items,
        key=lambda item: (-item["critical"], -item["high"], item["service"]),
    )


def _mapping_index(deployment_map: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Index valid deployment-map records by exact service name."""

    services = deployment_map.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        return {}
    return {
        service["name"]: service
        for service in services
        if isinstance(service, Mapping) and isinstance(service.get("name"), str)
    }


def build_plan(
    report: Mapping[str, Any],
    deployment_map: Mapping[str, Any],
    policy: RemediationPolicy,
    force_attempt: bool = False,
) -> dict[str, Any]:
    """Merge scan, mapping, and explicit policy into a stable dry-run plan."""

    items = {item["service"]: item for item in vulnerable_items(report)}
    mappings = _mapping_index(deployment_map)
    entries: list[dict[str, Any]] = []
    for target in policy.targets:
        item = items.get(target.service)
        mapping = mappings.get(target.service, {})
        reasons: list[str] = []
        if not target.enabled:
            reasons.append("disabled")
        if item is None:
            reasons.append("service-not-vulnerable")
        elif item["repository"] != target.repository:
            reasons.append("repository-mismatch")
        elif not SHA256_PATTERN.fullmatch(
            digest_from_reference(item["image"]) or ""
        ):
            reasons.append("current-image-mutable")
        if target.backup_status != "not_required":
            reasons.append("backup-not-exempt")
        if not target.auto_eligible and not force_attempt:
            reasons.append("auto-not-authorized")
        mapping_status = mapping.get("status", "unknown")
        source_verified = mapping.get("source_verified", True) is True
        if (
            mapping_status == "mapped"
            and source_verified
            and target.candidate.tag.lower() == "latest"
            and is_mutable_latest(mapping.get("declared_image"))
        ):
            action = "latest-refresh"
        elif mapping_status == "mapped" and source_verified:
            action = "declarative"
        else:
            action = "runtime-override"
        if action == "declarative" and target.source is None:
            reasons.append("source-adapter-missing")
        entry = {
            "policy_id": target.identifier,
            "service": target.service,
            "action": action,
            "eligible": not reasons,
            "blocked_reasons": reasons,
            "current_image": item["image"] if item else None,
            "candidate_image": target.candidate.reference,
            "critical": item["critical"] if item else 0,
            "high": item["high"] if item else 0,
            "finding_ids": item["finding_ids"] if item else [],
            "shared_service_count": item["shared_service_count"] if item else 0,
            "mapping": dict(mapping),
            "source": dataclasses.asdict(target.source) if target.source else None,
            "backup": {
                "status": target.backup_status,
                "reason": target.backup_reason,
            },
            "verification": {"timeout_seconds": target.timeout_seconds},
        }
        entries.append(entry)
    entries.sort(key=lambda entry: (-entry["critical"], -entry["high"], entry["service"]))
    identity = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "report_completed_at": report.get("completed_at"),
        "report_fingerprint": (report.get("scope") or {}).get("image_fingerprint")
        if isinstance(report.get("scope"), Mapping)
        else None,
        "deployment_map_generated_at": deployment_map.get("generated_at"),
        "policy_path": str(policy.path),
        "force_attempt": force_attempt,
        "entries": entries,
    }
    stable_identity = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "report_completed_at": identity["report_completed_at"],
        "report_fingerprint": identity["report_fingerprint"],
        "force_attempt": force_attempt,
        "entries": entries,
    }
    serialized = json.dumps(stable_identity, sort_keys=True, separators=(",", ":"))
    return {
        **identity,
        "generated_at": utc_timestamp(),
        "plan_id": hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16],
        "summary": {
            "entries": len(entries),
            "eligible": sum(entry["eligible"] for entry in entries),
            "blocked": sum(not entry["eligible"] for entry in entries),
            "declarative": sum(
                entry["eligible"] and entry["action"] == "declarative"
                for entry in entries
            ),
            "runtime_overrides": sum(
                entry["eligible"] and entry["action"] == "runtime-override"
                for entry in entries
            ),
            "latest_refreshes": sum(
                entry["eligible"] and entry["action"] == "latest-refresh"
                for entry in entries
            ),
        },
    }
