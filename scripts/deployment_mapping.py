"""Conservatively map live Swarm services to declarative stack files.

The mapper asks Docker Compose to render candidate YAML and discards every
rendered field except service names and image references. It accepts path
ownership only from an explicit stack identity or a unique consensus of exact
live service/image matches. Source drift and fallback rendering remain visible
and can never authorize automatic declarative edits.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, Sequence

from scripts.vulnerability_models import ServiceRecord, utc_timestamp


EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".github",
        ".venv",
        "__pycache__",
        "backup",
        "backups",
        "node_modules",
        "venv",
    }
)
STACK_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
HISTORICAL_YAML_MARKERS = (
    ".backup.",
    ".bak.",
    ".copy.",
    ".disabled.",
    ".old.",
    ".orig.",
    ".previous.",
    ".temp.",
    ".template.",
)


class DeploymentRootError(ValueError):
    """Describe one rejected deployment root without presentation text."""

    def __init__(self, code: str, path: Path | None = None) -> None:
        """Store a stable localization code and optional rejected path."""

        super().__init__(code)
        self.code = code
        self.path = path


class CommandResultLike(Protocol):
    """Minimal captured-command result required by the mapper."""

    return_code: int
    stdout: str
    stderr: str


class DockerClientLike(Protocol):
    """Docker command boundary used by production and deterministic tests."""

    def run(self, arguments: Sequence[str]) -> CommandResultLike:
        """Run Docker arguments without a shell and return captured output."""


@dataclasses.dataclass(frozen=True)
class StackCandidate:
    """One successfully rendered stack-file candidate.

    Attributes:
        deploy_root: Configured search root containing the candidate.
        directory: Directory that owns the sibling ``.env`` file.
        stack_file: Rendered YAML file.
        stack_name: Explicit or uniquely inferred live stack namespace.
        stack_name_source: ``dotenv`` or ``live-service-consensus``.
        render_source: ``sibling-env`` or the fail-closed ``defaults-only``.
        services: Rendered Compose service keys mapped to image references.
    """

    deploy_root: Path
    directory: Path
    stack_file: Path
    stack_name: str
    stack_name_source: str
    render_source: str
    services: Mapping[str, str]


@dataclasses.dataclass(frozen=True)
class ServiceDeployment:
    """High-confidence deployment evidence for one live service."""

    name: str
    stack: str | None
    image: str
    status: str
    reason: str
    deploy_root: str | None = None
    directory: str | None = None
    stack_file: str | None = None
    compose_service: str | None = None
    declared_image: str | None = None
    source_image_matches_live: bool | None = None
    source_verified: bool = False
    stack_name_source: str | None = None
    render_source: str | None = None
    candidate_files: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the mapping without exposing Compose environment values."""

        return {
            "name": self.name,
            "stack": self.stack,
            "image": self.image,
            "status": self.status,
            "reason": self.reason,
            "deploy_root": self.deploy_root,
            "directory": self.directory,
            "stack_file": self.stack_file,
            "compose_service": self.compose_service,
            "declared_image": self.declared_image,
            "source_image_matches_live": self.source_image_matches_live,
            "source_verified": self.source_verified,
            "stack_name_source": self.stack_name_source,
            "render_source": self.render_source,
            "candidate_files": list(self.candidate_files),
        }


def validated_deploy_roots(values: Sequence[Path]) -> tuple[Path, ...]:
    """Resolve distinct absolute deployment roots and require directories.

    Args:
        values: Operator-selected roots.

    Returns:
        Stable tuple of resolved directories.

    Raises:
        DeploymentRootError: If no usable absolute directory is supplied.
    """

    roots: list[Path] = []
    for value in values:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise DeploymentRootError("notAbsolute", value)
        try:
            resolved = expanded.resolve(strict=True)
        except OSError as error:
            raise DeploymentRootError("unavailable", value) from error
        if not resolved.is_dir():
            raise DeploymentRootError("notDirectory", value)
        if resolved not in roots:
            roots.append(resolved)
    if not roots:
        raise DeploymentRootError("required")
    return tuple(roots)


def read_stack_name(environment_file: Path) -> str | None:
    """Read only a validated ``STACK_NAME`` assignment from one dotenv file."""

    try:
        lines = environment_file.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() != "STACK_NAME":
            continue
        candidate = value.strip()
        if (
            len(candidate) >= 2
            and candidate[0] == candidate[-1]
            and candidate[0] in {"'", '"'}
        ):
            candidate = candidate[1:-1]
        return candidate if STACK_NAME_PATTERN.fullmatch(candidate) else None
    return None


def candidate_yaml_files(root: Path) -> list[Path]:
    """Find active YAML files without following symlinks or backup aliases."""

    candidates: list[Path] = []
    for current_directory, directory_names, filenames in os.walk(
        root, followlinks=False
    ):
        current = Path(current_directory)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in EXCLUDED_DIRECTORY_NAMES
            and not name.startswith(".")
            and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            lowered = filename.lower()
            if not lowered.endswith((".yml", ".yaml")):
                continue
            if lowered.startswith(".") or any(
                marker in lowered for marker in HISTORICAL_YAML_MARKERS
            ):
                continue
            candidate = current / filename
            if candidate.is_symlink() or not (current / ".env").is_file():
                continue
            candidates.append(candidate)
    return candidates


def rendered_services(
    client: DockerClientLike,
    stack_file: Path,
    environment_file: Path,
) -> dict[str, str] | None:
    """Render one candidate and retain only image-bearing Compose services."""

    result = client.run(
        [
            "compose",
            "--env-file",
            str(environment_file),
            "-f",
            str(stack_file),
            "config",
            "--format",
            "json",
        ]
    )
    if result.return_code != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return None
    raw_services = payload.get("services") if isinstance(payload, Mapping) else None
    if not isinstance(raw_services, Mapping):
        return None
    services: dict[str, str] = {}
    for service_name, service in raw_services.items():
        image = service.get("image") if isinstance(service, Mapping) else None
        if (
            isinstance(service_name, str)
            and service_name
            and isinstance(image, str)
            and image
        ):
            services[service_name] = image
    return services or None


def inferred_stack_name(
    services: Mapping[str, str],
    live_services: Sequence[ServiceRecord],
) -> str | None:
    """Infer one stack only from exact live service names and image matches."""

    matching_stacks = {
        live.stack
        for live in live_services
        for compose_service, declared_image in services.items()
        if isinstance(live.stack, str)
        and live.name == f"{live.stack}_{compose_service}"
        and image_references_match(declared_image, live.image)
    }
    return next(iter(matching_stacks)) if len(matching_stacks) == 1 else None


def render_stack_candidate(
    client: DockerClientLike,
    root: Path,
    stack_file: Path,
    live_services: Sequence[ServiceRecord],
) -> StackCandidate | None:
    """Render and identify one candidate without trusting weak path heuristics."""

    environment_file = stack_file.parent / ".env"
    if environment_file.is_symlink():
        return None
    explicit_stack_name = read_stack_name(environment_file)
    live_stack_names = {
        service.stack for service in live_services if isinstance(service.stack, str)
    }
    if (
        explicit_stack_name is not None
        and explicit_stack_name not in live_stack_names
    ):
        return None

    services = rendered_services(client, stack_file, environment_file)
    render_source = "sibling-env"
    if services is None and explicit_stack_name is not None:
        services = rendered_services(client, stack_file, Path(os.devnull))
        render_source = "defaults-only"
    if services is None:
        return None
    stack_name = explicit_stack_name or inferred_stack_name(services, live_services)
    if stack_name is None:
        return None
    return StackCandidate(
        deploy_root=root,
        directory=stack_file.parent,
        stack_file=stack_file,
        stack_name=stack_name,
        stack_name_source=(
            "dotenv" if explicit_stack_name is not None else "live-service-consensus"
        ),
        render_source=render_source,
        services=services,
    )


def normalized_image_reference(reference: str) -> tuple[str, str | None]:
    """Normalize an image name while retaining any immutable digest evidence."""

    raw_name, separator, raw_digest = reference.strip().lower().partition("@")
    components = raw_name.split("/")
    if len(components) == 1:
        components = ["docker.io", "library", components[0]]
    elif not (
        "." in components[0]
        or ":" in components[0]
        or components[0] == "localhost"
    ):
        components.insert(0, "docker.io")
    if components[0] in {"index.docker.io", "registry-1.docker.io"}:
        components[0] = "docker.io"
    if components[0] == "docker.io" and len(components) == 2:
        components.insert(1, "library")
    normalized_name = "/".join(components)
    if not separator and ":" not in components[-1]:
        normalized_name = f"{normalized_name}:latest"
    return normalized_name, raw_digest if separator and raw_digest else None


def canonical_image_reference(reference: str) -> str:
    """Return a normalized image name for diagnostics and compatibility tests."""

    return normalized_image_reference(reference)[0]


def image_references_match(declared: str, deployed: str) -> bool:
    """Compare tag declarations safely against Docker's resolved references.

    A declared tag may match the same live tag with an appended digest. When a
    stack explicitly declares a digest, however, the live digest must exist and
    match exactly; discarding it would permit a stale stack-file false positive.
    """

    declared_name, declared_digest = normalized_image_reference(declared)
    deployed_name, deployed_digest = normalized_image_reference(deployed)
    if declared_name != deployed_name:
        return False
    if declared_digest is not None:
        return declared_digest == deployed_digest
    return True


def mapped_service(
    service: ServiceRecord,
    candidates: Sequence[StackCandidate],
) -> ServiceDeployment:
    """Resolve one unique owning file while retaining source-drift evidence."""

    if not service.stack:
        return ServiceDeployment(
            service.name, service.stack, service.image, "unknown", "no-stack-label"
        )
    stack_candidates = [
        candidate for candidate in candidates if candidate.stack_name == service.stack
    ]
    if not stack_candidates:
        return ServiceDeployment(
            service.name, service.stack, service.image, "unknown", "no-stack-candidate"
        )
    name_matches = [
        (candidate, compose_service, declared_image)
        for candidate in stack_candidates
        for compose_service, declared_image in candidate.services.items()
        if f"{candidate.stack_name}_{compose_service}" == service.name
    ]
    if not name_matches:
        return ServiceDeployment(
            service.name,
            service.stack,
            service.image,
            "unknown",
            "service-not-in-rendered-stack",
            candidate_files=tuple(
                sorted({str(candidate.stack_file) for candidate in stack_candidates})
            ),
        )
    image_matches = [
        (candidate, compose_service, declared_image)
        for candidate, compose_service, declared_image in name_matches
        if image_references_match(declared_image, service.image)
    ]
    preferred_matches = image_matches or name_matches
    directories = {candidate.directory for candidate, _, _ in preferred_matches}
    candidate_files = tuple(
        sorted({str(candidate.stack_file) for candidate, _, _ in preferred_matches})
    )
    if len(directories) != 1:
        return ServiceDeployment(
            service.name,
            service.stack,
            service.image,
            "ambiguous",
            "multiple-deployment-directories",
            candidate_files=candidate_files,
        )
    if len(preferred_matches) != 1:
        return ServiceDeployment(
            service.name,
            service.stack,
            service.image,
            "ambiguous",
            "multiple-stack-files",
            candidate_files=candidate_files,
        )
    candidate, compose_service, declared_image = preferred_matches[0]
    image_matches_live = bool(image_matches)
    source_verified = (
        image_matches_live and candidate.render_source == "sibling-env"
    )
    if source_verified:
        reason = "matched-stack-service-image"
    elif image_matches_live:
        reason = "matched-stack-service-fallback-render"
    else:
        reason = "matched-stack-service-source-drift"
    return ServiceDeployment(
        service.name,
        service.stack,
        service.image,
        "mapped",
        reason,
        deploy_root=str(candidate.deploy_root),
        directory=str(candidate.directory),
        stack_file=str(candidate.stack_file),
        compose_service=compose_service,
        declared_image=declared_image,
        source_image_matches_live=image_matches_live,
        source_verified=source_verified,
        stack_name_source=candidate.stack_name_source,
        render_source=candidate.render_source,
        candidate_files=candidate_files,
    )


def build_deployment_map(
    client: DockerClientLike,
    services: Sequence[ServiceRecord],
    deploy_roots: Sequence[Path],
) -> dict[str, Any]:
    """Build a versioned deployment map from live and rendered evidence.

    Args:
        client: Docker command adapter used for Compose rendering.
        services: Trusted live Swarm service inventory.
        deploy_roots: Absolute directories to inspect recursively.

    Returns:
        JSON-compatible mapping report. Unproven services remain unknown.

    Raises:
        DeploymentRootError: If a configured deployment root is unusable.
    """

    roots = validated_deploy_roots(deploy_roots)
    compose_version = client.run(["compose", "version"])
    renderer_available = compose_version.return_code == 0
    yaml_files_by_path: dict[Path, tuple[Path, Path]] = {}
    for root in roots:
        for path in candidate_yaml_files(root):
            yaml_files_by_path.setdefault(path.resolve(), (root, path))
    yaml_files = list(yaml_files_by_path.values())

    candidates: list[StackCandidate] = []
    if renderer_available:
        for root, stack_file in yaml_files:
            rendered = render_stack_candidate(
                client, root, stack_file, services
            )
            if rendered is not None:
                candidates.append(rendered)

    mappings = (
        [mapped_service(service, candidates) for service in services]
        if renderer_available
        else [
            ServiceDeployment(
                service.name,
                service.stack,
                service.image,
                "unknown",
                "compose-unavailable",
            )
            for service in services
        ]
    )
    mappings.sort(key=lambda item: item.name)
    counts = {
        status: sum(mapping.status == status for mapping in mappings)
        for status in ("mapped", "unknown", "ambiguous")
    }
    source_unverified = sum(
        mapping.status == "mapped" and not mapping.source_verified
        for mapping in mappings
    )
    return {
        "schema_version": 2,
        "generated_at": utc_timestamp(),
        "deploy_roots": [str(root) for root in roots],
        "renderer": {
            "name": "docker-compose-config-json",
            "available": renderer_available,
        },
        "summary": {
            "service_count": len(mappings),
            **counts,
            "source_unverified": source_unverified,
            "yaml_files_considered": len(yaml_files),
            "rendered_stack_files": len(candidates),
        },
        "services": [mapping.to_dict() for mapping in mappings],
    }
