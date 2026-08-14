"""Remove approved Docker images without force and retain audit outcomes.

The caller owns inventory, workload protection, operator confirmation, and the
fresh safety recheck. This module handles only deterministic deletion of that
approved candidate set, including QNAP parent-image behavior and Docker's
multi-repository conflict.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Protocol, Sequence

from scripts.vulnerability_scout import CommandClient, sanitize_command_error


MISSING_IMAGE_PATTERN = re.compile(r"(?i)(no such image|image.*not found)")
DEPENDENT_IMAGE_PATTERN = re.compile(r"(?i)dependent child images")
MULTIPLE_REPOSITORY_PATTERN = re.compile(r"(?i)multiple repositories")


class CleanupImage(Protocol):
    """Describe the immutable image fields required during removal."""

    image_id: str
    repo_tags: tuple[str, ...]


def command_error(response: object) -> str:
    """Return one sanitized Docker diagnostic from a command response."""

    stderr = getattr(response, "stderr", "")
    stdout = getattr(response, "stdout", "")
    return sanitize_command_error(stderr or stdout)


def inspected_image_id(raw_json: str, description: str) -> str:
    """Parse one exact image ID from Docker inspect JSON."""

    try:
        payload = json.loads(raw_json)[0]
        image_id = payload["Id"]
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"{description} returned invalid inspect JSON.") from error
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise ValueError(f"{description} returned no exact image ID.")
    return image_id


def verify_repository_tags(
    client: CommandClient, image: CleanupImage
) -> str | None:
    """Verify each mutable tag still resolves to the approved exact image ID."""

    if len(image.repo_tags) < 2:
        return "Docker reported multiple repositories without multiple image tags."
    for reference in image.repo_tags:
        inspected = client.run(["image", "inspect", reference])
        if inspected.return_code != 0:
            return (
                f"Could not recheck repository tag {reference}: "
                f"{command_error(inspected)}"
            )
        try:
            resolved_id = inspected_image_id(
                inspected.stdout,
                f"Repository tag {reference}",
            )
        except ValueError as error:
            return str(error)
        if resolved_id != image.image_id:
            return (
                f"Repository tag {reference} moved after cleanup approval; "
                "no tags were removed."
            )
    return None


def remove_one_candidate(
    client: CommandClient, image: CleanupImage
) -> tuple[str, str | None]:
    """Attempt one exact removal, safely untagging verified multi-tag images."""

    result = client.run(["image", "rm", image.image_id])
    if result.return_code == 0:
        return "removed", None
    error = command_error(result)
    if MISSING_IMAGE_PATTERN.search(error):
        return "already-absent", None
    if DEPENDENT_IMAGE_PATTERN.search(error):
        return "deferred", error
    if not MULTIPLE_REPOSITORY_PATTERN.search(error):
        return "failed", error

    verification_error = verify_repository_tags(client, image)
    if verification_error:
        return "failed", verification_error
    for reference in image.repo_tags:
        untagged = client.run(["image", "rm", reference])
        if untagged.return_code != 0:
            untag_error = command_error(untagged)
            if not MISSING_IMAGE_PATTERN.search(untag_error):
                return (
                    "failed",
                    f"Could not remove verified tag {reference}: {untag_error}",
                )

    retry = client.run(["image", "rm", image.image_id])
    if retry.return_code == 0:
        return "removed", None
    retry_error = command_error(retry)
    if MISSING_IMAGE_PATTERN.search(retry_error):
        return "removed", None
    if DEPENDENT_IMAGE_PATTERN.search(retry_error):
        return "deferred", retry_error
    return "failed", retry_error


def remove_candidates(
    client: CommandClient,
    candidates: Sequence[CleanupImage],
    approved_image_ids: frozenset[str],
) -> tuple[list[str], list[str], dict[str, str]]:
    """Remove approved images child-first and retry dependency conflicts."""

    removed: list[str] = []
    already_absent: list[str] = []
    failures: dict[str, str] = {}
    pending = [
        image for image in candidates if image.image_id in approved_image_ids
    ]
    round_number = 0
    while pending:
        round_number += 1
        deferred: list[tuple[CleanupImage, str]] = []
        progress = False
        for image in pending:
            print(f"[INFO] Removing {image.image_id[:19]}...")
            outcome, error = remove_one_candidate(client, image)
            if outcome == "removed":
                removed.append(image.image_id)
                progress = True
                print(f"[OK] Removed {image.image_id[:19]}.")
                continue
            if outcome == "already-absent":
                already_absent.append(image.image_id)
                progress = True
                print(
                    f"[OK] {image.image_id[:19]} was already removed "
                    "with a child image."
                )
            elif outcome == "deferred" and error:
                deferred.append((image, error))
            else:
                failure = error or "Image removal failed without details."
                failures[image.image_id] = failure
                print(
                    f"[WARN] Could not remove {image.image_id[:19]}: {failure}",
                    file=sys.stderr,
                )

        if not deferred:
            break
        if not progress:
            for image, error in deferred:
                failures[image.image_id] = error
                print(
                    f"[WARN] Retained {image.image_id[:19]} after "
                    f"{round_number} dependency-safe removal round(s): {error}",
                    file=sys.stderr,
                )
            break
        print(
            f"[INFO] Retrying {len(deferred)} parent image(s) after child removal."
        )
        pending = [image for image, _ in deferred]
    return removed, already_absent, failures
