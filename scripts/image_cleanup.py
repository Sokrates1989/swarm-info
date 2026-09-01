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

from scripts.image_cleanup_removal import remove_candidates
from scripts.vulnerability_models import utc_timestamp, write_json_atomic
from scripts.vulnerability_scan import CommandResult, DockerClient
from scripts.vulnerability_scout import sanitize_command_error


CLEANUP_HISTORY_LIMIT = 20


@dataclasses.dataclass(frozen=True)
class LocalImage:
    """One exact image artifact currently stored by the local Docker daemon."""

    image_id: str
    repo_tags: tuple[str, ...]
    repo_digests: tuple[str, ...]
    size: int
    parent_id: str | None = None

    @property
    def references(self) -> tuple[str, ...]:
        """Return every human-readable repository reference."""

        return tuple(sorted({*self.repo_tags, *self.repo_digests}))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the image for an operator report."""

        return {
            "image_id": self.image_id,
            "references": list(self.references),
            "repo_tags": list(self.repo_tags),
            "repo_digests": list(self.repo_digests),
            "parent_image_id": self.parent_id,
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
    parent_id = payload.get("Parent") or None
    if parent_id is not None and (
        not isinstance(parent_id, str) or not parent_id.startswith("sha256:")
    ):
        raise ImageCleanupError(f"Image {requested_id} has an invalid parent ID.")

    def repository_references(field: str) -> tuple[str, ...]:
        values = payload.get(field) or []
        if not isinstance(values, list):
            raise ImageCleanupError(
                f"Image {requested_id} has invalid {field} metadata."
            )
        return tuple(
            sorted(
                {
                    reference
                    for reference in values
                    if isinstance(reference, str) and "<none>" not in reference
                }
            )
        )

    return LocalImage(
        image_id=image_id,
        repo_tags=repository_references("RepoTags"),
        repo_digests=repository_references("RepoDigests"),
        size=size,
        parent_id=parent_id,
    )


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
        ["service", "ls", "--quiet"],
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


def protect_required_ancestors(
    images: Sequence[LocalImage], protected_image_ids: set[str]
) -> frozenset[str]:
    """Protect every inventoried parent required by a protected child image."""

    images_by_id = {image.image_id: image for image in images}
    protected = set(protected_image_ids)
    pending = list(protected)
    while pending:
        image = images_by_id.get(pending.pop())
        if image is None or image.parent_id is None:
            continue
        if image.parent_id not in protected:
            protected.add(image.parent_id)
            pending.append(image.parent_id)
    return frozenset(protected)


def removal_depth(image: LocalImage, images_by_id: Mapping[str, LocalImage]) -> int:
    """Count known ancestors so children can be removed before their parents."""

    depth = 0
    visited = {image.image_id}
    parent_id = image.parent_id
    while parent_id and parent_id in images_by_id:
        if parent_id in visited:
            raise ImageCleanupError(
                f"Image ancestry contains a cycle at {parent_id}."
            )
        visited.add(parent_id)
        depth += 1
        parent_id = images_by_id[parent_id].parent_id
    return depth


def order_candidates_for_removal(
    images: Sequence[LocalImage], protected_image_ids: frozenset[str]
) -> tuple[LocalImage, ...]:
    """Return unused images in deterministic child-before-parent order."""

    images_by_id = {image.image_id: image for image in images}
    candidates = [
        image for image in images if image.image_id not in protected_image_ids
    ]
    return tuple(
        sorted(
            candidates,
            key=lambda image: (
                -removal_depth(image, images_by_id),
                image.image_id,
            ),
        )
    )


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
    protected_with_ancestors = protect_required_ancestors(images, protected)
    candidates = order_candidates_for_removal(images, protected_with_ancestors)
    return CleanupInventory(
        runtime=runtime,
        images=images,
        protected_image_ids=protected_with_ancestors,
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
    already_absent: Sequence[str] = (),
    removal_errors: Mapping[str, str] | None = None,
    *,
    mode: str = "preview",
    status: str = "preview",
    previous_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize cleanup preview, latest result, and bounded prior history."""

    errors = dict(removal_errors or {})
    generated_at = utc_timestamp()
    summary = {
        "local_images": len(inventory.images),
        "protected_images": len(inventory.protected_image_ids),
        "candidate_images": len(inventory.candidates),
        "candidate_virtual_size_upper_bound_bytes": sum(
            image.size for image in inventory.candidates
        ),
        "removed_images": len(removed),
        "already_absent_images": len(already_absent),
        "failed_removals": len(errors),
    }
    last_result = {
        "completed_at": generated_at,
        "mode": mode,
        "status": status,
        "candidate_images": summary["candidate_images"],
        "candidate_virtual_size_upper_bound_bytes": summary[
            "candidate_virtual_size_upper_bound_bytes"
        ],
        "removed_images": summary["removed_images"],
        "already_absent_images": summary["already_absent_images"],
        "failed_removals": summary["failed_removals"],
    }
    history = cleanup_history(previous_report)
    history.append(last_result)
    history = history[-CLEANUP_HISTORY_LIMIT:]
    return {
        "schema_version": 2,
        "generated_at": generated_at,
        "coverage": "current-docker-node-only",
        "runtime": inventory.runtime,
        "apply_allowed": inventory.apply_allowed,
        "blockers": list(inventory.blockers),
        "summary": summary,
        "service_references": list(inventory.service_references),
        "candidates": [image.to_dict() for image in inventory.candidates],
        "action": {
            "removed_image_ids": list(removed),
            "already_absent_image_ids": list(already_absent),
            "removal_errors": errors,
        },
        "last_result": last_result,
        "history": history,
    }


def cleanup_history(
    previous_report: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Recover only count-only result entries from one previous report."""

    if not isinstance(previous_report, Mapping):
        return []
    raw_history = previous_report.get("history")
    if not isinstance(raw_history, list):
        raw_last_result = previous_report.get("last_result")
        raw_history = [raw_last_result] if isinstance(raw_last_result, Mapping) else []
    history: list[dict[str, Any]] = []
    for raw in raw_history[-CLEANUP_HISTORY_LIMIT:]:
        if not isinstance(raw, Mapping):
            continue
        completed_at = raw.get("completed_at")
        mode = raw.get("mode")
        status = raw.get("status")
        counts = {
            key: raw.get(key)
            for key in (
                "candidate_images",
                "candidate_virtual_size_upper_bound_bytes",
                "removed_images",
                "already_absent_images",
                "failed_removals",
            )
        }
        if (
            not isinstance(completed_at, str)
            or mode not in {"preview", "apply"}
            or status
            not in {
                "preview",
                "no-candidates",
                "cancelled",
                "blocked",
                "applied",
                "partial",
            }
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counts.values()
            )
        ):
            continue
        history.append(
            {
                "completed_at": completed_at[:64],
                "mode": mode,
                "status": status,
                **counts,
            }
        )
    return history


def load_previous_report(path: Path | None) -> Mapping[str, Any] | None:
    """Read a prior cleanup report only for bounded result-history retention."""

    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


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
) -> tuple[list[str], list[str], dict[str, str]]:
    """Delegate approved removal to the isolated mutation adapter."""

    return remove_candidates(client, inventory.candidates, approved_image_ids)


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
    previous_report = load_previous_report(options.output_file)
    try:
        inventory = discover_cleanup_inventory(client)
    except ImageCleanupError as error:
        print(f"[ERROR] Image cleanup inventory failed: {error}", file=sys.stderr)
        return 3
    display_inventory(inventory)
    if not options.apply or not inventory.candidates:
        report = build_cleanup_report(
            inventory,
            mode="apply" if options.apply else "preview",
            status=(
                "blocked"
                if options.apply and not inventory.apply_allowed
                else "no-candidates"
                if not inventory.candidates
                else "preview"
            ),
            previous_report=previous_report,
        )
        if options.output_file and not publish_report(options.output_file, report):
            return 3
        if inventory.candidates:
            print("Dry run only. To remove reviewed candidates:")
            print("  swarm-info -i --apply")
        if options.apply and not inventory.apply_allowed:
            return 3
        return 0
    if not inventory.apply_allowed:
        report = build_cleanup_report(
            inventory,
            mode="apply",
            status="blocked",
            previous_report=previous_report,
        )
        if options.output_file and not publish_report(options.output_file, report):
            return 3
        return 3
    if not options.yes and not confirm_removal(len(inventory.candidates)):
        print("[INFO] Cleanup cancelled; no images were removed.")
        report = build_cleanup_report(
            inventory,
            mode="apply",
            status="cancelled",
            previous_report=previous_report,
        )
        if options.output_file and not publish_report(options.output_file, report):
            return 3
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
    removed, already_absent, failures = remove_approved_candidates(
        client, refreshed, frozenset(still_approved)
    )
    report = build_cleanup_report(
        refreshed,
        removed=removed,
        already_absent=already_absent,
        removal_errors=failures,
        mode="apply",
        status="partial" if failures else "applied",
        previous_report=previous_report,
    )
    if options.output_file and not publish_report(options.output_file, report):
        return 3
    print(
        f"Cleanup complete: {len(removed)} removed, "
        f"{len(already_absent)} already absent, {len(failures)} failed."
    )
    return 3 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
