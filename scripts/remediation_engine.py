"""Safety checks and reversible execution for vulnerability remediation."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from scripts.deployment_mapping import image_references_match
from scripts.remediation_policy import CandidateImage, PolicyTarget
from scripts.remediation_source import SourceChange, write_source_change
from scripts.vulnerability_models import (
    ImageTarget,
    ServiceRecord,
    registry_from_reference,
    severity_counts,
)
from scripts.vulnerability_scan import DockerClient
from scripts.vulnerability_scout import sanitize_command_error, scan_image


class RemediationExecutionError(RuntimeError):
    """Describe a blocked or failed action using a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a stable code and redacted, bounded diagnostic detail."""

        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class CandidateValidation:
    """Candidate scan evidence compared with the current report."""

    status: str
    critical: int
    high: int
    finding_ids: tuple[str, ...]
    new_finding_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ServiceSnapshot:
    """Pre-action service image and observed replica state."""

    name: str
    image: str
    running: int
    desired: int


@dataclasses.dataclass(frozen=True)
class ActionResult:
    """Sanitized result suitable for a plan execution record."""

    status: str
    service: str
    candidate_image: str
    source_file: str | None = None
    config_drift: bool = False
    rolled_back: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the action result without command output or secrets."""

        return dataclasses.asdict(self)


def _target_for_candidate(
    candidate: CandidateImage, service_name: str
) -> ImageTarget:
    """Construct an isolated immutable Scout target for one policy candidate."""

    service = ServiceRecord("candidate", service_name, candidate.reference, None)
    return ImageTarget(
        key=f"{registry_from_reference(candidate.reference)}|{candidate.digest}",
        registry=registry_from_reference(candidate.reference),
        digest=candidate.digest,
        references={candidate.reference},
        services=[service],
    )


def validate_candidate(
    client: DockerClient,
    target: PolicyTarget,
    plan_entry: Mapping[str, Any],
    platform: str,
    sleeper: Callable[[float], None] = time.sleep,
) -> CandidateValidation:
    """Validate the explicit candidate from one auto-remediation policy target."""

    return validate_candidate_reference(
        client,
        target.candidate,
        target.service,
        plan_entry,
        platform,
        sleeper=sleeper,
    )


def validate_candidate_reference(
    client: DockerClient,
    candidate: CandidateImage,
    service_name: str,
    current_evidence: Mapping[str, Any],
    platform: str,
    sleeper: Callable[[float], None] = time.sleep,
) -> CandidateValidation:
    """Scan any immutable proposal using the same fail-closed auto-remedy rules."""

    current_ids = {
        item
        for item in current_evidence.get("finding_ids", [])
        if isinstance(item, str)
    }
    current_critical = current_evidence.get("critical", 0)
    current_high = current_evidence.get("high", 0)
    if not isinstance(current_critical, int) or not isinstance(current_high, int):
        raise RemediationExecutionError("current-counts-invalid")
    if current_critical + current_high > 0 and not current_ids:
        raise RemediationExecutionError("current-finding-ids-missing")
    result = scan_image(
        client,
        _target_for_candidate(candidate, service_name),
        platform,
        sleeper=sleeper,
    )
    if result.status == "error":
        raise RemediationExecutionError("candidate-scan-failed", result.error or "")
    counts = severity_counts(result.findings)
    candidate_ids = {finding.identifier for finding in result.findings}
    new_ids = sorted(candidate_ids - current_ids)
    improved = (
        counts["critical"] <= current_critical
        and counts["high"] <= current_high
        and counts["critical"] + counts["high"] < current_critical + current_high
    )
    if new_ids:
        raise RemediationExecutionError("candidate-new-findings", ", ".join(new_ids[:10]))
    if not improved:
        raise RemediationExecutionError("candidate-not-improved")
    return CandidateValidation(
        result.status,
        counts["critical"],
        counts["high"],
        tuple(sorted(candidate_ids)),
        tuple(new_ids),
    )


def inspect_service_image(client: DockerClient, service: str) -> str:
    """Read the exact current image from one live service specification."""

    result = client.run(
        [
            "service",
            "inspect",
            service,
            "--format",
            "{{.Spec.TaskTemplate.ContainerSpec.Image}}",
        ]
    )
    image = result.stdout.strip()
    if result.return_code != 0 or not image:
        detail = sanitize_command_error(result.stderr or result.stdout)
        raise RemediationExecutionError("service-inspect-failed", detail)
    return image


def service_replicas(client: DockerClient, service: str) -> tuple[int, int]:
    """Read one exact service's observed running/desired replica pair."""

    result = client.run(
        [
            "service",
            "ls",
            "--filter",
            f"name={service}",
            "--format",
            "{{.Name}}\t{{.Replicas}}",
        ]
    )
    if result.return_code != 0:
        raise RemediationExecutionError(
            "service-list-failed", sanitize_command_error(result.stderr)
        )
    for line in result.stdout.splitlines():
        name, separator, replicas = line.partition("\t")
        if name != service or not separator or "/" not in replicas:
            continue
        running, desired = replicas.split("/", 1)
        try:
            return int(running), int(desired)
        except ValueError as error:
            raise RemediationExecutionError("service-replicas-invalid", replicas) from error
    raise RemediationExecutionError("service-not-found", service)


def capture_service(client: DockerClient, service: str) -> ServiceSnapshot:
    """Capture pre-action image and replica evidence for rollback verification."""

    running, desired = service_replicas(client, service)
    return ServiceSnapshot(service, inspect_service_image(client, service), running, desired)


def _update_state(client: DockerClient, service: str) -> str:
    """Read Docker's optional service update state."""

    result = client.run(
        [
            "service",
            "inspect",
            service,
            "--format",
            "{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}",
        ]
    )
    return result.stdout.strip().lower() if result.return_code == 0 else ""


def wait_for_candidate(
    client: DockerClient,
    snapshot: ServiceSnapshot,
    candidate: CandidateImage,
    timeout_seconds: int,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Wait until image evidence and the service's prior availability recover."""

    deadline = time.monotonic() + timeout_seconds
    last_detail = ""
    while time.monotonic() < deadline:
        state = _update_state(client, snapshot.name)
        if state in {"paused", "rollback_paused"}:
            raise RemediationExecutionError("service-update-paused", state)
        try:
            image = inspect_service_image(client, snapshot.name)
            running, desired = service_replicas(client, snapshot.name)
            image_ready = image_references_match(candidate.reference, image)
            if snapshot.running == snapshot.desired:
                replicas_ready = running == desired
            else:
                replicas_ready = running >= snapshot.running
            if image_ready and replicas_ready and state not in {"updating", "rollback_started"}:
                return
            last_detail = f"image={image}; replicas={running}/{desired}; state={state or 'none'}"
        except RemediationExecutionError as error:
            last_detail = error.code
        sleeper(2.0)
    raise RemediationExecutionError("service-convergence-timeout", last_detail)


def wait_for_original_image(
    client: DockerClient,
    snapshot: ServiceSnapshot,
    timeout_seconds: int,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Confirm rollback restored the exact prior service image and availability."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            image = inspect_service_image(client, snapshot.name)
            running, desired = service_replicas(client, snapshot.name)
            availability = (
                running == desired
                if snapshot.running == snapshot.desired
                else running >= snapshot.running
            )
            if image_references_match(snapshot.image, image) and availability:
                return
        except RemediationExecutionError:
            pass
        sleeper(2.0)
    raise RemediationExecutionError("rollback-convergence-timeout", snapshot.name)


def restore_service_snapshot(
    client: DockerClient,
    snapshot: ServiceSnapshot,
    timeout_seconds: int,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Confirm rollback, falling back to the exact previous service image."""

    try:
        wait_for_original_image(
            client, snapshot, timeout_seconds, sleeper=sleeper
        )
        return
    except RemediationExecutionError:
        pass
    result = client.run(
        [
            "service",
            "update",
            "--with-registry-auth",
            "--image",
            snapshot.image,
            snapshot.name,
        ]
    )
    if result.return_code != 0:
        raise RemediationExecutionError(
            "rollback-exact-image-failed",
            sanitize_command_error(result.stderr or result.stdout),
        )
    wait_for_original_image(client, snapshot, timeout_seconds, sleeper=sleeper)


def render_stack(client: DockerClient, stack_file: Path) -> bytes:
    """Render Compose YAML without printing its possibly sensitive contents."""

    environment_file = stack_file.parent / ".env"
    arguments = ["compose"]
    if environment_file.is_file() and not environment_file.is_symlink():
        arguments.extend(["--env-file", str(environment_file)])
    arguments.extend(["-f", str(stack_file), "config", "--format", "yaml"])
    result = client.run(arguments)
    if result.return_code != 0 or not result.stdout.strip():
        raise RemediationExecutionError(
            "stack-render-failed",
            sanitize_command_error(result.stderr or result.stdout),
        )
    return result.stdout.encode("utf-8")


def deploy_rendered_stack(
    client: DockerClient, stack_name: str, rendered: bytes, directory: Path
) -> None:
    """Deploy a mode-0600 rendered stack and always remove the temporary file."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".swarm-info-remediation.", suffix=".yml", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        result = client.run(
            [
                "stack",
                "deploy",
                "--with-registry-auth",
                "--resolve-image",
                "always",
                "-c",
                str(temporary),
                stack_name,
            ]
        )
        if result.return_code != 0:
            raise RemediationExecutionError(
                "stack-deploy-failed",
                sanitize_command_error(result.stderr or result.stdout),
            )
    finally:
        temporary.unlink(missing_ok=True)


def deploy_declarative_change(
    client: DockerClient,
    target: PolicyTarget,
    plan_entry: Mapping[str, Any],
    change: SourceChange,
    old_rendered: bytes,
    sleeper: Callable[[float], None] = time.sleep,
    post_validation: Callable[[], object] | None = None,
) -> ActionResult:
    """Deploy one applied source change, restoring source and stack on failure."""

    mapping = plan_entry.get("mapping")
    if not isinstance(mapping, Mapping):
        raise RemediationExecutionError("mapping-missing")
    stack = mapping.get("stack")
    stack_file_value = mapping.get("stack_file")
    if not isinstance(stack, str) or not isinstance(stack_file_value, str):
        raise RemediationExecutionError("stack-evidence-missing")
    stack_file = Path(stack_file_value).resolve()
    snapshot: ServiceSnapshot | None = None
    deployed = False
    try:
        snapshot = capture_service(client, target.service)
        if not image_references_match(str(plan_entry.get("current_image", "")), snapshot.image):
            raise RemediationExecutionError("live-image-changed", snapshot.image)
        rendered = render_stack(client, stack_file)
        deploy_rendered_stack(client, stack, rendered, stack_file.parent)
        deployed = True
        wait_for_candidate(
            client,
            snapshot,
            target.candidate,
            target.timeout_seconds,
            sleeper=sleeper,
        )
        if post_validation is not None:
            post_validation()
    except BaseException as original_error:
        rolled_back = False
        rollback_detail = ""
        try:
            write_source_change(change, replacement=change.original)
            if deployed:
                deploy_rendered_stack(client, stack, old_rendered, stack_file.parent)
                if snapshot is not None:
                    restore_service_snapshot(
                        client, snapshot, target.timeout_seconds, sleeper=sleeper
                    )
            rolled_back = True
        except BaseException as rollback_error:
            rollback_detail = f"; rollback failed: {type(rollback_error).__name__}"
        if isinstance(original_error, RemediationExecutionError):
            detail = f"{original_error.code}: {original_error.detail}{rollback_detail}"
        else:
            detail = f"{type(original_error).__name__}{rollback_detail}"
        raise RemediationExecutionError(
            "declarative-deploy-failed", detail
        ) from original_error
    return ActionResult(
        "deployed",
        target.service,
        target.candidate.reference,
        source_file=str(change.path),
    )


def runtime_update_command(target: PolicyTarget) -> list[str]:
    """Return the exact guarded Docker runtime-override arguments."""

    return service_image_update_command(target.service, target.candidate)


def service_image_update_command(
    service: str, candidate: CandidateImage
) -> list[str]:
    """Return one registry-authenticated update pinned to validated image content."""

    return [
        "service",
        "update",
        "--with-registry-auth",
        "--image",
        candidate.reference,
        service,
    ]


def _execute_service_image_update(
    client: DockerClient,
    service: str,
    candidate: CandidateImage,
    current_image: str,
    timeout_seconds: int,
    *,
    config_drift: bool,
    detail: str,
    sleeper: Callable[[float], None],
    post_validation: Callable[[], object] | None,
) -> ActionResult:
    """Execute one exact image update with shared convergence and rollback guards."""

    snapshot = capture_service(client, service)
    if not image_references_match(current_image, snapshot.image):
        raise RemediationExecutionError("live-image-changed", snapshot.image)
    result = client.run(service_image_update_command(service, candidate))
    if result.return_code != 0:
        raise RemediationExecutionError(
            "runtime-update-failed",
            sanitize_command_error(result.stderr or result.stdout),
        )
    try:
        wait_for_candidate(
            client,
            snapshot,
            candidate,
            timeout_seconds,
            sleeper=sleeper,
        )
        if post_validation is not None:
            post_validation()
    except BaseException as error:
        rollback = client.run(["service", "update", "--rollback", service])
        if rollback.return_code == 0:
            try:
                restore_service_snapshot(
                    client, snapshot, timeout_seconds, sleeper=sleeper
                )
                suffix = "rollback confirmed"
            except RemediationExecutionError:
                suffix = "rollback requested but not confirmed"
        else:
            suffix = "rollback failed"
        error_code = (
            error.code
            if isinstance(error, RemediationExecutionError)
            else type(error).__name__
        )
        raise RemediationExecutionError(
            "runtime-verification-failed", f"{error_code}; {suffix}"
        ) from error
    return ActionResult(
        "deployed",
        service,
        candidate.reference,
        config_drift=config_drift,
        detail=detail,
    )


def execute_latest_refresh(
    client: DockerClient,
    service: str,
    candidate: CandidateImage,
    current_image: str,
    timeout_seconds: int,
    sleeper: Callable[[float], None] = time.sleep,
    post_validation: Callable[[], object] | None = None,
) -> ActionResult:
    """Refresh a verified latest-following service without changing its source intent."""

    return _execute_service_image_update(
        client,
        service,
        candidate,
        current_image,
        timeout_seconds,
        config_drift=False,
        detail="validated latest refresh; declarative source still follows latest",
        sleeper=sleeper,
        post_validation=post_validation,
    )


def execute_runtime_override(
    client: DockerClient,
    target: PolicyTarget,
    plan_entry: Mapping[str, Any],
    sleeper: Callable[[float], None] = time.sleep,
    post_validation: Callable[[], object] | None = None,
) -> ActionResult:
    """Apply an explicit runtime override and rollback the service on failure."""

    return _execute_service_image_update(
        client,
        target.service,
        target.candidate,
        str(plan_entry.get("current_image", "")),
        target.timeout_seconds,
        config_drift=True,
        detail="runtime override; update declarative source promptly",
        sleeper=sleeper,
        post_validation=post_validation,
    )
