"""Safely inventory and remove unused images from one Docker node.

The cleanup boundary is deliberately local. Images referenced by any local
container are protected. On a Swarm manager, images declared by any service are
also protected, including scaled-to-zero services. Swarm workers cannot provide
that manager-wide declaration inventory, so deletion is refused there.

Dependencies:
    - Python 3.10 or newer.
    - Docker CLI access to the local Docker daemon.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from scripts.vulnerability_models import utc_timestamp, write_json_atomic
from scripts.vulnerability_scan import CommandResult, DockerClient
from scripts.vulnerability_scout import sanitize_command_error


@dataclasses.dataclass(frozen=True)
class LocalImage:
    """One exact image artifact currently stored by the local Docker daemon."""

    image_id: str
    references: tuple[str, ...]
    size: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the image for an operator report."""

        return {
            "image_id": self.image_id,
            "references": list(self.references),
            "virtual_size_bytes": self.size,
        }


@dataclasses.dataclass(frozen=True)
class CleanupInventory:
    """Local image inventory plus every protection decision."""

    runtime: str
    images: tuple[LocalImage, ...]
    protected_image_ids: frozenset[str]
    candidates: tuple[LocalImage, ...]
    service_references: tuple[str, ...]
    apply_allowed: bool
    blockers: tuple[str, ...] = ()


class ImageCleanupError(RuntimeError):
    """Raised when Docker cannot provide a trustworthy cleanup inventory."""


def command_error(result: CommandResult) -> str:
    """Return one sanitized Docker error suitable for terminal output."""

    return sanitize_command_error(result.stderr or result.stdout)


def require_command(
    client: DockerClient, arguments: Sequence[str], description: str
) -> CommandResult:
    """Run a Docker command and fail with sanitized context on error."""

    result = client.run(arguments)
    if result.return_code != 0:
        raise ImageCleanupError(f"{description}: {command_error(result)}")
    return result


def parse_inspect_object(raw_json: str, description: str) -> Mapping[str, Any]:
    """Parse the first object returned by a Docker inspect operation."""

    try:
        payload = json.loads(raw_json)
        value = payload[0]
    except (IndexError, TypeError, ValueError) as error:
        raise ImageCleanupError(f"{description} returned invalid JSON.") from error
    if not isinstance(value, dict):
        raise ImageCleanupError(f"{description} returned an invalid object.")
    return value


def list_identifiers(
    client: DockerClient, arguments: Sequence[str], description: str
) -> list[str]:
    """Read a unique ordered identifier list from a Docker command."""

    result = require_command(client, arguments, description)
    identifiers = (
        line.strip() for line in result.stdout.splitlines() if line.strip()
    )
    return list(dict.fromkeys(identifiers))


def parse_local_image(raw_json: str, requested_id: str) -> LocalImage:
    """Normalize one ``docker image inspect`` response."""

    payload = parse_inspect_object(raw_json, f"Image {requested_id}")
    image_id = payload.get("Id")
    size = payload.get("Size")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise ImageCleanupError(f"Image {requested_id} has no exact image ID.")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ImageCleanupError(f"Image {requested_id} has no valid size.")
    references = sorted(
        {
            reference
            for field in ("RepoTags", "RepoDigests")
            for reference in (payload.get(field) or [])
            if isinstance(reference, str) and "<none>" not in reference
        }
    )
    return LocalImage(image_id, tuple(references), size)


def collect_local_images(client: DockerClient) -> tuple[LocalImage, ...]:
    """Inspect every exact image stored by the local Docker daemon."""

    image_ids = list_identifiers(
        client,
        ["image", "ls", "--all", "--no-trunc", "--quiet"],
        "Docker image inventory failed",
    )
    images = []
    for image_id in image_ids:
        inspected = require_command(
            client,
            ["image", "inspect", image_id],
            f"Could not inspect image {image_id}",
        )
        images.append(parse_local_image(inspected.stdout, image_id))
    return tuple(sorted(images, key=lambda image: image.image_id))


def collect_container_image_ids(client: DockerClient) -> frozenset[str]:
    """Protect exact image IDs referenced by running or stopped containers."""

    container_ids = list_identifiers(
        client,
        ["container", "ls", "--all", "--quiet", "--no-trunc"],
        "Docker container inventory failed",
    )
    image_ids: set[str] = set()
    for container_id in container_ids:
        inspected = require_command(
            client,
            ["container", "inspect", container_id],
            f"Could not inspect container {container_id}",
        )
        payload = parse_inspect_object(inspected.stdout, f"Container {container_id}")
        image_id = payload.get("Image")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise ImageCleanupError(
                f"Container {container_id} has no exact local image ID."
            )
        image_ids.add(image_id)
    return frozenset(image_ids)


def detect_runtime(client: DockerClient) -> tuple[str, bool]:
    """Return runtime type and whether Swarm service protection is available."""

    result = require_command(
        client,
        ["info", "--format", "{{.Swarm.LocalNodeState}}\t{{.Swarm.ControlAvailable}}"],
        "Docker runtime detection failed",
    )
    fields = result.stdout.strip().lower().split("\t")
    if len(fields) != 2:
        raise ImageCleanupError("Docker returned an invalid Swarm capability response.")
    swarm_state, control_available = fields
    if swarm_state == "active" and control_available == "true":
        return "swarm-manager", True
    if swarm_state == "active":
        return "swarm-worker", False
    return "standalone", True


def collect_service_references(client: DockerClient) -> tuple[str, ...]:
    """Collect every manager-visible Swarm service image declaration."""

    service_ids = list_identifiers(
        client,
        ["service", "ls", "--quiet", "--no-trunc"],
        "Docker service inventory failed",
    )
    references: set[str] = set()
    for service_id in service_ids:
        inspected = require_command(
            client,
            ["service", "inspect", service_id],
            f"Could not inspect service {service_id}",
        )
        payload = parse_inspect_object(inspected.stdout, f"Service {service_id}")
        try:
            reference = payload["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"]
        except (KeyError, TypeError) as error:
            raise ImageCleanupError(
                f"Service {service_id} has no valid container image declaration."
            ) from error
        if not isinstance(reference, str) or not reference.strip():
            raise ImageCleanupError(
                f"Service {service_id} has no valid container image declaration."
            )
        references.add(reference.strip())
    return tuple(sorted(references))


def resolve_local_service_images(
    client: DockerClient, references: Sequence[str]
) -> frozenset[str]:
    """Resolve locally cached images declared by Swarm services without pulling."""

    protected: set[str] = set()
    for reference in references:
        inspected = client.run(["image", "inspect", reference])
        if inspected.return_code != 0:
            continue
        payload = parse_inspect_object(inspected.stdout, f"Service image {reference}")
        image_id = payload.get("Id")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise ImageCleanupError(
                f"Service image {reference} resolved without an exact image ID."
            )
        protected.add(image_id)
    return frozenset(protected)


def discover_cleanup_inventory(client: DockerClient) -> CleanupInventory:
    """Build one fail-closed local image cleanup inventory."""

    runtime, manager_visibility_available = detect_runtime(client)
    images = collect_local_images(client)
    protected = set(collect_container_image_ids(client))
    service_references: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    if runtime == "swarm-manager":
        service_references = collect_service_references(client)
        protected.update(resolve_local_service_images(client, service_references))
    elif runtime == "swarm-worker":
        blockers = (
            "This node is a Swarm worker and cannot inventory all service image "
            "declarations. Run cleanup from a manager or inspect this node manually.",
        )
    candidates = tuple(image for image in images if image.image_id not in protected)
    return CleanupInventory(
        runtime=runtime,
        images=images,
        protected_image_ids=frozenset(protected),
        candidates=candidates,
        service_references=service_references,
        apply_allowed=manager_visibility_available,
        blockers=blockers,
    )


def format_bytes(value: int) -> str:
    """Format a byte count with binary units."""

    amount = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def build_cleanup_report(
    inventory: CleanupInventory,
    removed: Sequence[str] = (),
    removal_errors: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Serialize cleanup evidence and optional apply results."""

    errors = dict(removal_errors or {})
    return {
        "schema_version": 1,
        "generated_at": utc_timestamp(),
        "coverage": "current-docker-node-only",
        "runtime": inventory.runtime,
        "apply_allowed": inventory.apply_allowed,
        "blockers": list(inventory.blockers),
        "summary": {
            "local_images": len(inventory.images),
            "protected_images": len(inventory.protected_image_ids),
            "candidate_images": len(inventory.candidates),
            "candidate_virtual_size_upper_bound_bytes": sum(
                image.size for image in inventory.candidates
            ),
            "removed_images": len(removed),
            "failed_removals": len(errors),
        },
        "service_references": list(inventory.service_references),
        "candidates": [image.to_dict() for image in inventory.candidates],
        "action": {
            "removed_image_ids": list(removed),
            "removal_errors": errors,
        },
    }


def display_inventory(inventory: CleanupInventory) -> None:
    """Render a concise cleanup candidate report."""

    print("Unused local Docker image review")
    print("=" * 32)
    print("Coverage: current Docker node only")
    print(f"Runtime: {inventory.runtime}")
    print(
        f"Images: {len(inventory.images)} local | "
        f"{len(inventory.protected_image_ids)} protected | "
        f"{len(inventory.candidates)} cleanup candidate(s)"
    )
    for blocker in inventory.blockers:
        print(f"[ERROR] {blocker}", file=sys.stderr)
    if not inventory.candidates:
        print("[OK] No unused local images were found.")
        return
    upper_bound = sum(image.size for image in inventory.candidates)
    print(
        "Candidate virtual-size upper bound: "
        f"{format_bytes(upper_bound)} (shared layers make actual recovery smaller)"
    )
    print()
    for index, image in enumerate(inventory.candidates, start=1):
        references = ", ".join(image.references) or "<untagged>"
        print(
            f"{index:>3}) {image.image_id[:19]} | {format_bytes(image.size)} | "
            f"{references}"
        )
    print()
    print("Protected images include all running/stopped container images.")
    if inventory.runtime == "swarm-manager":
        print("Manager protection also includes every locally cached service image.")
    print(
        "Dangling build images may appear as candidates and may need rebuilding later."
    )


def confirm_removal(candidate_count: int) -> bool:
    """Request default-No confirmation before removing candidate images."""

    try:
        response = input(
            f"Remove these {candidate_count} exact image artifact(s)? [y/N]: "
        )
    except EOFError:
        return False
    return response.strip().lower() in {"y", "yes"}


def remove_approved_candidates(
    client: DockerClient,
    inventory: CleanupInventory,
    approved_image_ids: frozenset[str],
) -> tuple[list[str], dict[str, str]]:
    """Remove still-unused approved images without force and retain failures."""

    removed: list[str] = []
    failures: dict[str, str] = {}
    for image in inventory.candidates:
        if image.image_id not in approved_image_ids:
            continue
        print(f"[INFO] Removing {image.image_id[:19]}...")
        result = client.run(["image", "rm", image.image_id])
        if result.return_code == 0:
            removed.append(image.image_id)
            print(f"[OK] Removed {image.image_id[:19]}.")
        else:
            failures[image.image_id] = command_error(result)
            print(
                f"[WARN] Could not remove {image.image_id[:19]}: "
                f"{failures[image.image_id]}",
                file=sys.stderr,
            )
    return removed, failures


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse cleanup reporting and explicit apply options."""

    parser = argparse.ArgumentParser(
        description="Review or remove images unused on the current Docker node."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Remove reviewed candidates after a default-No confirmation.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="With --apply, confirm non-interactively.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Optional atomic JSON cleanup report destination.",
    )
    options = parser.parse_args(arguments)
    if options.yes and not options.apply:
        parser.error("--yes requires --apply")
    return options


def publish_report(path: Path, report: Mapping[str, Any]) -> bool:
    """Atomically publish a report and render a concise failure on error."""

    try:
        write_json_atomic(path, report)
    except (OSError, TypeError, ValueError) as error:
        print(
            f"[ERROR] Could not write cleanup report {path}: {error}",
            file=sys.stderr,
        )
        return False
    print(f"Report written to {path}")
    return True


def main(arguments: Sequence[str] | None = None) -> int:
    """Run a dry review or explicitly confirmed cleanup operation."""

    options = parse_arguments(arguments)
    client = DockerClient()
    try:
        inventory = discover_cleanup_inventory(client)
    except ImageCleanupError as error:
        print(f"[ERROR] Image cleanup inventory failed: {error}", file=sys.stderr)
        return 3
    display_inventory(inventory)
    report = build_cleanup_report(inventory)
    if not options.apply or not inventory.candidates:
        if options.output_file and not publish_report(options.output_file, report):
            return 3
        if inventory.candidates:
            print("Dry run only. To remove reviewed candidates:")
            print("  swarm-info -i --apply")
        if options.apply and not inventory.apply_allowed:
            return 3
        return 0
    if not inventory.apply_allowed:
        return 3
    if not options.yes and not confirm_removal(len(inventory.candidates)):
        print("[INFO] Cleanup cancelled; no images were removed.")
        return 0

    approved_ids = frozenset(image.image_id for image in inventory.candidates)
    try:
        refreshed = discover_cleanup_inventory(client)
    except ImageCleanupError as error:
        print(
            f"[ERROR] Safety recheck failed; no images were removed: {error}",
            file=sys.stderr,
        )
        return 3
    if not refreshed.apply_allowed:
        print("[ERROR] Safety recheck no longer permits cleanup.", file=sys.stderr)
        return 3
    still_approved = approved_ids.intersection(
        image.image_id for image in refreshed.candidates
    )
    skipped = len(approved_ids) - len(still_approved)
    if skipped:
        print(f"[INFO] Safety recheck protected or removed {skipped} candidate(s).")
    removed, failures = remove_approved_candidates(
        client, refreshed, frozenset(still_approved)
    )
    report = build_cleanup_report(refreshed, removed, failures)
    if options.output_file and not publish_report(options.output_file, report):
        return 3
    print(f"Cleanup complete: {len(removed)} removed, {len(failures)} failed.")
    return 3 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
