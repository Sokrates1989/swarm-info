"""Strict installation-owned policy for standalone Compose remediation."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from scripts.remediation_policy import (
    CandidateImage,
    SourceEdit,
    image_repository,
    parse_candidate_image,
)


POLICY_SCHEMA_VERSION = 1
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
COMPOSE_PART_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
BACKUP_STATUSES = {"ready", "not_required"}


class ComposePolicyError(ValueError):
    """Describe rejected standalone policy using a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a stable code and bounded non-secret diagnostic detail."""

        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class ComposePolicyTarget:
    """One explicitly authorized Compose service and candidate image."""

    identifier: str
    enabled: bool
    compose_service: str
    repository: str
    candidate: CandidateImage
    backup_status: str
    backup_reason: str
    source: SourceEdit
    timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class ComposeRemediationPolicy:
    """Validated standalone remediation policy loaded from a local file."""

    path: Path
    targets: tuple[ComposePolicyTarget, ...]


def _reject_unknown(
    mapping: Mapping[str, Any], allowed: set[str], code: str
) -> None:
    """Reject misspelled or unreviewed fields instead of ignoring them."""

    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ComposePolicyError(code, ", ".join(unknown))


def _required_string(mapping: Mapping[str, Any], key: str, code: str) -> str:
    """Return one non-empty policy string or raise a stable error."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ComposePolicyError(code, key)
    return value.strip()


def _compose_selector(value: str) -> str:
    """Validate one exact Compose ``PROJECT/SERVICE`` selector."""

    project, separator, service = value.partition("/")
    if (
        not separator
        or "/" in service
        or not COMPOSE_PART_PATTERN.fullmatch(project)
        or not COMPOSE_PART_PATTERN.fullmatch(service)
    ):
        raise ComposePolicyError("composeSelector", value)
    return value


def _source_edit(raw: object) -> SourceEdit:
    """Require one simple mapped Compose YAML image source."""

    if not isinstance(raw, Mapping):
        raise ComposePolicyError("sourceObject")
    _reject_unknown(raw, {"type", "file"}, "sourceUnknownField")
    edit_type = _required_string(raw, "type", "sourceType")
    relative = _required_string(raw, "file", "sourceFile")
    path = Path(relative)
    if edit_type != "yaml_image":
        raise ComposePolicyError("sourceType", edit_type)
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        raise ComposePolicyError("sourcePath", relative)
    return SourceEdit(edit_type, relative)


def _target(raw: object, identifiers: set[str]) -> ComposePolicyTarget:
    """Parse one strict target and reject ambiguous policy state."""

    if not isinstance(raw, Mapping):
        raise ComposePolicyError("targetObject")
    _reject_unknown(
        raw,
        {
            "id",
            "enabled",
            "match",
            "candidate_image",
            "backup",
            "source",
            "verification",
        },
        "targetUnknownField",
    )
    identifier = _required_string(raw, "id", "targetId")
    if not IDENTIFIER_PATTERN.fullmatch(identifier) or identifier in identifiers:
        raise ComposePolicyError("targetId", identifier)
    identifiers.add(identifier)

    match = raw.get("match")
    if not isinstance(match, Mapping):
        raise ComposePolicyError("targetMatch", identifier)
    _reject_unknown(
        match, {"compose_service", "repository"}, "matchUnknownField"
    )
    compose_service = _compose_selector(
        _required_string(match, "compose_service", "composeSelector")
    )
    repository = image_repository(
        _required_string(match, "repository", "targetRepository")
    )
    try:
        candidate = parse_candidate_image(
            _required_string(raw, "candidate_image", "candidateImage")
        )
    except ValueError as error:
        code = getattr(error, "code", "candidateImage")
        raise ComposePolicyError(code, identifier) from error
    if candidate.repository != repository:
        raise ComposePolicyError("candidateRepository", identifier)

    backup = raw.get("backup")
    if not isinstance(backup, Mapping):
        raise ComposePolicyError("backupObject", identifier)
    _reject_unknown(backup, {"status", "reason"}, "backupUnknownField")
    backup_status = _required_string(backup, "status", "backupStatus")
    backup_reason = _required_string(backup, "reason", "backupReason")
    if backup_status not in BACKUP_STATUSES:
        raise ComposePolicyError("backupStatus", identifier)
    if len(backup_reason) > 500 or "\n" in backup_reason or "\r" in backup_reason:
        raise ComposePolicyError("backupReason", identifier)

    verification = raw.get("verification", {})
    if not isinstance(verification, Mapping):
        raise ComposePolicyError("verificationObject", identifier)
    _reject_unknown(
        verification, {"timeout_seconds"}, "verificationUnknownField"
    )
    timeout = verification.get("timeout_seconds", 300)
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 30 <= timeout <= 1800
    ):
        raise ComposePolicyError("verificationTimeout", identifier)
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ComposePolicyError("booleanField", identifier)
    return ComposePolicyTarget(
        identifier,
        enabled,
        compose_service,
        repository,
        candidate,
        backup_status,
        backup_reason,
        _source_edit(raw.get("source")),
        timeout,
    )


def load_compose_policy(path: Path) -> ComposeRemediationPolicy:
    """Load a strict standalone policy without expanding operator values."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ComposePolicyError("policyUnreadable", str(path)) from error
    if not isinstance(payload, Mapping):
        raise ComposePolicyError("policyObject")
    _reject_unknown(payload, {"schema_version", "targets"}, "policyUnknownField")
    if payload.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ComposePolicyError("policySchema")
    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes)):
        raise ComposePolicyError("policyTargets")
    identifiers: set[str] = set()
    targets = tuple(_target(item, identifiers) for item in raw_targets)
    selectors = [target.compose_service for target in targets]
    if len(set(selectors)) != len(selectors):
        raise ComposePolicyError("composeSelectorDuplicate")
    return ComposeRemediationPolicy(path.resolve(), targets)


def select_compose_target(
    policy: ComposeRemediationPolicy, selector: str
) -> ComposePolicyTarget:
    """Return the single enabled target for an exact Compose selector."""

    _compose_selector(selector)
    matches = [target for target in policy.targets if target.compose_service == selector]
    if len(matches) != 1:
        raise ComposePolicyError("targetNotFound", selector)
    if not matches[0].enabled:
        raise ComposePolicyError("targetDisabled", selector)
    return matches[0]
