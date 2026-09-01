"""Exact focused evidence and dry-run planning for Compose remediation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from scripts.compose_remediation_engine import (
    FULL_IMAGE_ID_LENGTH,
    PLAN_SCHEMA_VERSION,
    ComposeEvidence,
    ComposeRemediationError,
    PreparedComposeRemediation,
    _full_image_id,
    command_error,
    compose_arguments,
)
from scripts.compose_remediation_policy import ComposePolicyTarget
from scripts.remediation_engine import (
    RemediationExecutionError,
    validate_candidate_reference,
)
from scripts.remediation_policy import PolicyTarget, image_repository
from scripts.remediation_source import (
    SourceChange,
    SourceEditError,
    prepare_source_change,
)
from scripts.vulnerability_models import digest_from_reference, utc_timestamp
from scripts.vulnerability_scan import DockerClient


def _non_negative_count(mapping: Mapping[str, Any], key: str) -> int:
    """Read one non-negative integer count from focused evidence."""

    value = mapping.get(key, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ComposeRemediationError("focusedCounts", key)
    return value


def _load_report(path: Path) -> Mapping[str, Any]:
    """Load one JSON object without exposing its contents in diagnostics."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ComposeRemediationError("focusedReportUnreadable", str(path)) from error
    if not isinstance(payload, Mapping):
        raise ComposeRemediationError("focusedReportObject")
    return payload


def load_compose_evidence(path: Path, selector: str) -> ComposeEvidence:
    """Validate one complete focused Compose-service vulnerability report."""

    report = _load_report(path)
    scope = report.get("scope")
    if not isinstance(scope, Mapping):
        raise ComposeRemediationError("focusedScope")
    expected_selector = {"type": "compose-service", "value": selector}
    if (
        scope.get("resource_type") != "container"
        or scope.get("coverage") != "focused"
        or scope.get("selector") != expected_selector
        or scope.get("resource_count") != 1
        or scope.get("inventory_failure_count", 0) != 0
    ):
        raise ComposeRemediationError("focusedScope", selector)
    if report.get("errors") or report.get("inventory_errors"):
        raise ComposeRemediationError("focusedReportIncomplete")
    images = report.get("images")
    if not isinstance(images, Sequence) or isinstance(images, (str, bytes)):
        raise ComposeRemediationError("focusedImages")
    if len(images) != 1 or not isinstance(images[0], Mapping):
        raise ComposeRemediationError("focusedImageCount", str(len(images)))
    image = images[0]
    if image.get("status") != "vulnerable":
        raise ComposeRemediationError("focusedImageNotVulnerable")
    services = image.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        raise ComposeRemediationError("focusedServices")
    matching = [
        service
        for service in services
        if isinstance(service, Mapping)
        and f"{service.get('stack')}/{service.get('compose_service')}" == selector
    ]
    if len(matching) != 1:
        raise ComposeRemediationError("focusedServiceCount", str(len(matching)))
    service = matching[0]
    project, compose_service = selector.split("/", 1)
    name = service.get("name")
    current_reference = service.get("image")
    working_directory = service.get("compose_working_dir")
    config_values = service.get("compose_config_files")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(current_reference, str)
        or not current_reference
        or not isinstance(working_directory, str)
        or not working_directory
        or not isinstance(config_values, Sequence)
        or isinstance(config_values, (str, bytes))
        or not config_values
        or not all(isinstance(item, str) and item for item in config_values)
    ):
        raise ComposeRemediationError("focusedOwnership")
    digest = digest_from_reference(current_reference)
    if not digest or len(digest) != FULL_IMAGE_ID_LENGTH:
        raise ComposeRemediationError("currentImageMutable", current_reference)
    counts = image.get("counts")
    if not isinstance(counts, Mapping):
        raise ComposeRemediationError("focusedCounts")
    critical = _non_negative_count(counts, "critical")
    high = _non_negative_count(counts, "high")
    findings = image.get("findings")
    finding_ids = tuple(
        sorted(
            {
                item["id"]
                for item in findings or []
                if isinstance(item, Mapping)
                and isinstance(item.get("id"), str)
                and item["id"]
            }
        )
    )
    if critical + high <= 0 or not finding_ids:
        raise ComposeRemediationError("focusedFindings")
    platform = image.get("platform")
    completed_at = report.get("completed_at")
    if not isinstance(platform, str) or not platform or not isinstance(completed_at, str):
        raise ComposeRemediationError("focusedMetadata")
    root = Path(working_directory)
    files = tuple(
        Path(item) if Path(item).is_absolute() else root / item
        for item in config_values
    )
    return ComposeEvidence(
        selector,
        project,
        compose_service,
        name,
        current_reference,
        _full_image_id(image.get("local_image_id")),
        root,
        files,
        platform,
        critical,
        high,
        finding_ids,
        completed_at,
    )


def _resolved_mapping(
    evidence: ComposeEvidence, target: ComposePolicyTarget
) -> dict[str, Any]:
    """Resolve label-retained Compose files and the policy source exactly."""

    try:
        root = evidence.working_directory.resolve(strict=True)
    except OSError as error:
        raise ComposeRemediationError(
            "workingDirectory", str(evidence.working_directory)
        ) from error
    if not root.is_dir():
        raise ComposeRemediationError("workingDirectory", str(root))
    resolved_files: list[Path] = []
    for config_file in evidence.config_files:
        try:
            if config_file.is_symlink():
                raise ComposeRemediationError("configFileSymlink", str(config_file))
            resolved = config_file.resolve(strict=True)
        except OSError as error:
            raise ComposeRemediationError(
                "configFileUnavailable", str(config_file)
            ) from error
        if not resolved.is_file() or root not in resolved.parents:
            raise ComposeRemediationError("configFileOutsideProject", str(resolved))
        resolved_files.append(resolved)
    if len(set(resolved_files)) != len(resolved_files):
        raise ComposeRemediationError("configFileDuplicate")
    source_path = (root / target.source.file).resolve(strict=False)
    if resolved_files.count(source_path) != 1:
        raise ComposeRemediationError("sourceNotMappedConfig", str(source_path))
    return {
        "status": "mapped",
        "source_verified": True,
        "directory": str(root),
        "stack_file": str(source_path),
        "compose_service": evidence.service,
        "config_files": [str(path) for path in resolved_files],
    }


def prepare_compose_source_change(
    evidence: ComposeEvidence, target: ComposePolicyTarget
) -> tuple[SourceChange, tuple[Path, ...]]:
    """Prepare an exact source diff from focused ownership and policy."""

    if image_repository(evidence.current_reference) != target.repository:
        raise ComposeRemediationError("repositoryMismatch")
    mapping = _resolved_mapping(evidence, target)
    synthetic_target = PolicyTarget(
        identifier=target.identifier,
        enabled=True,
        service=evidence.container_name,
        repository=target.repository,
        candidate=target.candidate,
        backup_status=target.backup_status,
        backup_reason=target.backup_reason,
        auto_eligible=False,
        source=target.source,
        timeout_seconds=target.timeout_seconds,
    )
    try:
        change = prepare_source_change(
            synthetic_target,
            {"mapping": mapping, "current_image": evidence.current_reference},
        )
    except SourceEditError as error:
        raise ComposeRemediationError(error.code, error.detail) from error
    return change, tuple(Path(value) for value in mapping["config_files"])


def validate_replacement_config(
    client: DockerClient,
    evidence: ComposeEvidence,
    change: SourceChange,
    config_files: Sequence[Path],
) -> None:
    """Render the replacement through Compose without changing live source."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".swarm-info-compose-review.",
        suffix=change.path.suffix,
        dir=change.path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(change.replacement)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        reviewed_files = [
            temporary if path == change.path else path for path in config_files
        ]
        result = client.run(
            [*compose_arguments(evidence, reviewed_files), "config", "--quiet"]
        )
        if result.return_code != 0:
            raise command_error("composeValidationFailed", result)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_compose_remediation(
    client: DockerClient,
    target: ComposePolicyTarget,
    evidence: ComposeEvidence,
    *,
    sleeper: Callable[[float], None] = time.sleep,
) -> PreparedComposeRemediation:
    """Validate candidate, source mapping, diff, and rendered Compose config."""

    change, config_files = prepare_compose_source_change(evidence, target)
    try:
        validation = validate_candidate_reference(
            client,
            target.candidate,
            evidence.selector,
            {
                "critical": evidence.critical,
                "high": evidence.high,
                "finding_ids": list(evidence.finding_ids),
            },
            evidence.platform,
            sleeper=sleeper,
        )
    except RemediationExecutionError as error:
        raise ComposeRemediationError(error.code, error.detail) from error
    validate_replacement_config(client, evidence, change, config_files)
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "generated_at": utc_timestamp(),
        "status": "planned",
        "policy_id": target.identifier,
        "compose_service": evidence.selector,
        "current": {
            "reference": evidence.current_reference,
            "local_image_id": evidence.current_image_id,
            "critical": evidence.critical,
            "high": evidence.high,
            "finding_ids": list(evidence.finding_ids),
            "report_completed_at": evidence.completed_at,
        },
        "candidate": {
            "reference": target.candidate.reference,
            "critical": validation.critical,
            "high": validation.high,
            "finding_ids": list(validation.finding_ids),
        },
        "source": {
            "file": str(change.path),
            "config_files": [str(path) for path in config_files],
            "working_directory": str(evidence.working_directory.resolve()),
            "original_sha256": hashlib.sha256(change.original).hexdigest(),
            "replacement_sha256": hashlib.sha256(change.replacement).hexdigest(),
            "diff": change.diff,
        },
        "backup": {
            "status": target.backup_status,
            "reason": target.backup_reason,
            "source_file": None,
        },
        "verification": {"timeout_seconds": target.timeout_seconds},
        "events": [{"at": utc_timestamp(), "event": "dry-run-validated"}],
    }
    return PreparedComposeRemediation(target, evidence, change, validation, plan)
