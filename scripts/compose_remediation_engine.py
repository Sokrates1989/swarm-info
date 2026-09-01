"""Fail-closed planning and rollback primitives for Compose remediation."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Any, Callable, Mapping, Sequence

from scripts.compose_remediation_policy import ComposePolicyTarget
from scripts.deployment_mapping import image_references_match
from scripts.remediation_engine import CandidateValidation
from scripts.remediation_source import (
    SourceChange,
    SourceEditError,
    write_source_change,
)
from scripts.vulnerability_scan import CommandResult, DockerClient
from scripts.vulnerability_scout import sanitize_command_error


PLAN_SCHEMA_VERSION = 1
FULL_IMAGE_ID_LENGTH = len("sha256:") + 64


class ComposeRemediationError(RuntimeError):
    """Describe a blocked Compose action using a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a stable code and bounded non-secret diagnostic detail."""

        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class ComposeEvidence:
    """Exact focused container evidence for one Compose service."""

    selector: str
    project: str
    service: str
    container_name: str
    current_reference: str
    current_image_id: str
    working_directory: Path
    config_files: tuple[Path, ...]
    platform: str
    critical: int
    high: int
    finding_ids: tuple[str, ...]
    completed_at: str


@dataclasses.dataclass(frozen=True)
class ContainerSnapshot:
    """Live identity and readiness of one exact Compose container."""

    container_id: str
    name: str
    configured_image: str
    image_id: str
    running: bool
    health: str | None


@dataclasses.dataclass(frozen=True)
class PreparedComposeRemediation:
    """Reviewed source change and candidate evidence ready for a decision."""

    target: ComposePolicyTarget
    evidence: ComposeEvidence
    source_change: SourceChange
    candidate_validation: CandidateValidation
    plan: dict[str, Any]


def _full_image_id(value: object) -> str:
    """Return one exact local SHA-256 image ID or reject it."""

    if (
        not isinstance(value, str)
        or len(value) != FULL_IMAGE_ID_LENGTH
        or not value.startswith("sha256:")
    ):
        raise ComposeRemediationError("localImageId", str(value)[:100])
    try:
        int(value[7:], 16)
    except ValueError as error:
        raise ComposeRemediationError("localImageId", value[:100]) from error
    return value.lower()


def compose_arguments(
    evidence: ComposeEvidence, config_files: Sequence[Path]
) -> list[str]:
    """Build the exact project-scoped Compose command prefix."""

    arguments = [
        "compose",
        "--project-name",
        evidence.project,
        "--project-directory",
        str(evidence.working_directory.resolve()),
    ]
    for config_file in config_files:
        arguments.extend(["-f", str(config_file)])
    return arguments


def command_error(code: str, result: CommandResult) -> ComposeRemediationError:
    """Convert command failure to a sanitized remediation error."""

    return ComposeRemediationError(
        code, sanitize_command_error(result.stderr or result.stdout)
    )


def validate_current_config(
    client: DockerClient,
    evidence: ComposeEvidence,
    config_files: Sequence[Path],
) -> None:
    """Validate the current on-disk Compose sources without printing them."""

    result = client.run(
        [*compose_arguments(evidence, config_files), "config", "--quiet"]
    )
    if result.return_code != 0:
        raise command_error("composeValidationFailed", result)


def _container_ids(client: DockerClient, evidence: ComposeEvidence) -> list[str]:
    """List one exact Compose service without name-based fallback."""

    result = client.run(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={evidence.project}",
            "--filter",
            f"label=com.docker.compose.service={evidence.service}",
            "--format",
            "{{.ID}}",
        ]
    )
    if result.return_code != 0:
        raise command_error("containerListFailed", result)
    identifiers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(identifiers) != 1:
        raise ComposeRemediationError("containerCount", str(len(identifiers)))
    return identifiers


def inspect_compose_container(
    client: DockerClient, evidence: ComposeEvidence
) -> ContainerSnapshot:
    """Capture live artifact and readiness for the exact Compose service."""

    container_id = _container_ids(client, evidence)[0]
    result = client.run(["container", "inspect", container_id])
    if result.return_code != 0:
        raise command_error("containerInspectFailed", result)
    try:
        item = json.loads(result.stdout)[0]
        labels = item["Config"].get("Labels") or {}
        snapshot = ContainerSnapshot(
            container_id=item["Id"],
            name=str(item["Name"]).lstrip("/"),
            configured_image=item["Config"]["Image"],
            image_id=_full_image_id(item["Image"]),
            running=item["State"]["Running"] is True,
            health=(item["State"].get("Health") or {}).get("Status"),
        )
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ComposeRemediationError("containerInspectInvalid") from error
    if (
        labels.get("com.docker.compose.project") != evidence.project
        or labels.get("com.docker.compose.service") != evidence.service
    ):
        raise ComposeRemediationError("containerLabelsChanged")
    return snapshot


def pull_candidate(client: DockerClient, target: ComposePolicyTarget) -> str:
    """Pull the exact policy candidate and return its local image ID."""

    result = client.run(["image", "pull", target.candidate.reference])
    if result.return_code != 0:
        raise command_error("candidatePullFailed", result)
    result = client.run(
        ["image", "inspect", target.candidate.reference, "--format", "{{.Id}}"]
    )
    if result.return_code != 0:
        raise command_error("candidateInspectFailed", result)
    return _full_image_id(result.stdout.strip())


def recreate_compose_service(
    client: DockerClient,
    evidence: ComposeEvidence,
    config_files: Sequence[Path],
) -> None:
    """Recreate only the exact policy-approved Compose service."""

    result = client.run(
        [
            *compose_arguments(evidence, config_files),
            "up",
            "--detach",
            "--no-deps",
            evidence.service,
        ]
    )
    if result.return_code != 0:
        raise command_error("composeRecreateFailed", result)


def wait_for_image(
    client: DockerClient,
    evidence: ComposeEvidence,
    image_id: str,
    timeout_seconds: int,
    *,
    sleeper: Callable[[float], None] = time.sleep,
) -> ContainerSnapshot:
    """Wait for exact image identity and acceptable container readiness."""

    deadline = time.monotonic() + timeout_seconds
    last = "container-unavailable"
    while time.monotonic() < deadline:
        try:
            snapshot = inspect_compose_container(client, evidence)
            last = f"image={snapshot.image_id}; running={snapshot.running}; health={snapshot.health}"
            if (
                snapshot.image_id == image_id
                and snapshot.running
                and snapshot.health not in {"starting", "unhealthy"}
            ):
                return snapshot
        except ComposeRemediationError as error:
            last = error.code
        sleeper(2.0)
    raise ComposeRemediationError("composeConvergenceTimeout", last)


def write_source_backup(path: Path, payload: bytes) -> None:
    """Create one owner-only source backup without overwriting evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def restore_source_from_backup(
    source_path: Path,
    backup_path: Path,
    expected_current_sha256: str,
    expected_backup_sha256: str,
) -> None:
    """Atomically restore a verified backup over the expected current source."""

    current = source_path.read_bytes()
    original = backup_path.read_bytes()
    if hashlib.sha256(current).hexdigest() != expected_current_sha256:
        raise ComposeRemediationError("sourceChangedSincePlan", str(source_path))
    if hashlib.sha256(original).hexdigest() != expected_backup_sha256:
        raise ComposeRemediationError("backupHashMismatch", str(backup_path))
    mode = stat.S_IMODE(source_path.stat().st_mode)
    change = SourceChange(source_path, current, original, "", mode)
    try:
        write_source_change(change)
    except SourceEditError as error:
        raise ComposeRemediationError(error.code, error.detail) from error
