"""Collect and focus exact local-container image inventory.

The module owns Docker Compose label interpretation for standalone Docker and
QNAP Container Station. It performs no scans and never changes containers or
deployment files; callers decide which selected records enter Docker Scout.
"""

from __future__ import annotations

import json
import re
from typing import Sequence

from scripts.vulnerability_models import ServiceRecord
from scripts.vulnerability_scan import DockerClient, InventoryError
from scripts.vulnerability_scout import sanitize_command_error


FULL_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-fA-F]{64}")
SUPPORTED_CONTAINER_FOCUS_KINDS = ("container", "image-id")


class ContainerFocusError(ValueError):
    """Describe an unsafe or unresolved local-container focus selector."""

    def __init__(
        self, code: str, selector: str, matches: Sequence[str] = ()
    ) -> None:
        """Store a stable error code and bounded selection evidence."""

        super().__init__(code)
        self.code = code
        self.selector = selector
        self.matches = tuple(matches[:10])


def _optional_label(labels: object, key: str) -> str | None:
    """Return one non-empty Compose label without trusting its input type."""

    if not isinstance(labels, dict):
        return None
    value = labels.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _compose_config_files(labels: object) -> tuple[str, ...]:
    """Normalize Compose's comma-separated source-file label."""

    value = _optional_label(labels, "com.docker.compose.project.config_files")
    if value is None:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def parse_container_inspect(container_id: str, raw_json: str) -> ServiceRecord:
    """Parse one local ``docker container inspect`` response.

    Args:
        container_id: Requested container identifier.
        raw_json: Docker JSON response.

    Returns:
        Exact image identity plus optional Compose ownership evidence.

    Raises:
        InventoryError: If required container fields are absent.
    """

    try:
        payload = json.loads(raw_json)[0]
        name = payload["Name"]
        image_id = payload["Image"]
        configuration = payload["Config"]
        image_reference = configuration["Image"]
        labels = configuration.get("Labels") or {}
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise InventoryError(
            f"Container {container_id} returned invalid inspect JSON."
        ) from error
    if not all(
        isinstance(value, str) and value.strip()
        for value in (name, image_id, image_reference)
    ):
        raise InventoryError(
            f"Container {container_id} has no valid name, image, or local image ID."
        )
    project = _optional_label(labels, "com.docker.compose.project")
    return ServiceRecord(
        service_id=container_id,
        name=name.lstrip("/"),
        image=image_reference,
        stack=project,
        local_image_id=image_id,
        compose_service=_optional_label(labels, "com.docker.compose.service"),
        compose_working_dir=_optional_label(
            labels, "com.docker.compose.project.working_dir"
        ),
        compose_config_files=_compose_config_files(labels),
    )


def collect_containers(
    client: DockerClient, scope: str = "all"
) -> list[ServiceRecord]:
    """Collect exact images behind local Docker containers.

    Args:
        client: Docker command client.
        scope: ``all`` includes stopped containers; ``running`` does not.

    Returns:
        Container records sorted by name.

    Raises:
        InventoryError: If listing or inspecting any selected container fails.
    """

    arguments = ["container", "ls"]
    if scope == "all":
        arguments.append("--all")
    arguments.extend(("--quiet", "--no-trunc"))
    listed = client.run(arguments)
    if listed.return_code != 0:
        detail = sanitize_command_error(listed.stderr or listed.stdout)
        raise InventoryError(f"Docker container inventory failed: {detail}")
    containers = []
    for container_id in (line.strip() for line in listed.stdout.splitlines()):
        if not container_id:
            continue
        inspected = client.run(["container", "inspect", container_id])
        if inspected.return_code != 0:
            detail = sanitize_command_error(inspected.stderr or inspected.stdout)
            raise InventoryError(f"Could not inspect container {container_id}: {detail}")
        containers.append(parse_container_inspect(container_id, inspected.stdout))
    return sorted(containers, key=lambda container: container.name)


def _selector_examples(
    containers: Sequence[ServiceRecord], kind: str
) -> tuple[str, ...]:
    """Return bounded exact selectors for one failed focus request."""

    if kind == "container":
        return tuple(sorted(container.name for container in containers)[:10])
    return tuple(
        sorted(
            {
                container.local_image_id
                for container in containers
                if container.local_image_id
            }
        )[:10]
    )


def select_containers(
    containers: Sequence[ServiceRecord], kind: str, selector: str
) -> list[ServiceRecord]:
    """Select one exact container or every container using one exact image ID.

    Args:
        containers: Current inventory in the requested all/running scope.
        kind: ``container`` or ``image-id``.
        selector: Exact container name/ID or full content-addressed image ID.

    Returns:
        Matching records sorted by container name.

    Raises:
        ContainerFocusError: If validation or exact resolution fails.
    """

    selected = selector.strip()
    if (
        not selected
        or len(selected) > 512
        or any(character.isspace() or ord(character) < 32 for character in selected)
    ):
        raise ContainerFocusError("invalid-selector", selector)
    if kind not in SUPPORTED_CONTAINER_FOCUS_KINDS:
        raise ContainerFocusError("unsupported-kind", selected)
    if kind == "image-id" and FULL_IMAGE_ID_PATTERN.fullmatch(selected) is None:
        raise ContainerFocusError("invalid-image-id", selected)
    matches = [
        container
        for container in containers
        if (
            selected in {container.name, container.service_id}
            if kind == "container"
            else selected.lower() == (container.local_image_id or "").lower()
        )
    ]
    if not matches:
        raise ContainerFocusError(
            f"{kind}-not-found", selected, _selector_examples(containers, kind)
        )
    return sorted(matches, key=lambda container: container.name)
