"""Select conservative stable SemVer and reviewed image successor tracks."""

from __future__ import annotations

import dataclasses
import re
from typing import Sequence

from scripts.image_update_registry import RegistryTag, TagListing
from scripts.remediation_policy import SuccessorRule


SEMVER_PATTERN = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


@dataclasses.dataclass(frozen=True, order=True)
class SemanticVersion:
    """Strict stable semantic version used only for ordered tag tracks."""

    major: int
    minor: int
    patch: int

    def text(self) -> str:
        """Return the normalized numeric semantic version."""

        return f"{self.major}.{self.minor}.{self.patch}"


@dataclasses.dataclass(frozen=True)
class CandidateSelection:
    """One tag selected for one or more update tracks before digest resolution."""

    repository: str
    tag: RegistryTag
    version: SemanticVersion | None
    tracks: tuple[str, ...]
    source: str
    successor: SuccessorRule | None = None


def parse_semver(value: object) -> SemanticVersion | None:
    """Parse only stable ``X.Y.Z`` or ``vX.Y.Z`` values without guessing."""

    if not isinstance(value, str):
        return None
    match = SEMVER_PATTERN.fullmatch(value.strip())
    if not match:
        return None
    return SemanticVersion(*(int(component) for component in match.groups()))


def stable_tags(listing: TagListing) -> list[tuple[SemanticVersion, RegistryTag]]:
    """Return all strict stable semantic tags ordered by version and tag."""

    parsed = [
        (version, tag)
        for tag in listing.tags
        if (version := parse_semver(tag.name)) is not None
    ]
    return sorted(parsed, key=lambda item: (item[0], item[1].name))


def select_semver_candidates(
    current_version: SemanticVersion | None,
    listing: TagListing,
) -> tuple[CandidateSelection, ...]:
    """Select same-minor, same-major, and newest stable tags without aliases."""

    if not listing.complete:
        return ()
    stable = stable_tags(listing)
    if not stable:
        return ()
    selected: dict[str, set[str]] = {}
    versions = {tag.name: version for version, tag in stable}
    tag_by_name = {tag.name: tag for _, tag in stable}

    def add(track: str, eligible: Sequence[tuple[SemanticVersion, RegistryTag]]) -> None:
        if eligible:
            _, tag = max(eligible, key=lambda item: (item[0], item[1].name))
            selected.setdefault(tag.name, set()).add(track)

    if current_version is not None:
        newer = [item for item in stable if item[0] > current_version]
        add(
            "same-minor",
            [
                item
                for item in newer
                if item[0].major == current_version.major
                and item[0].minor == current_version.minor
            ],
        )
        add(
            "same-major",
            [item for item in newer if item[0].major == current_version.major],
        )
        add("newest-stable", newer)
    else:
        add("newest-stable-unordered", stable)
    return tuple(
        CandidateSelection(
            listing.repository.canonical,
            tag_by_name[tag_name],
            versions[tag_name],
            tuple(sorted(tracks)),
            "registry-semver",
        )
        for tag_name, tracks in sorted(selected.items())
    )


def latest_selection(
    listing: TagListing,
    track: str,
    successor: SuccessorRule | None = None,
) -> CandidateSelection | None:
    """Select an existing latest channel without inferring its application version."""

    latest = next((tag for tag in listing.tags if tag.name.lower() == "latest"), None)
    if latest is None or not listing.complete:
        return None
    return CandidateSelection(
        listing.repository.canonical,
        latest,
        None,
        (track,),
        "policy-successor" if successor is not None else "registry-channel",
        successor,
    )


def successor_selections(
    rule: SuccessorRule,
    listing: TagListing,
) -> tuple[CandidateSelection, ...]:
    """Select successor releases while keeping compatibility as manual review."""

    selections = [
        dataclasses.replace(
            item,
            tracks=("successor-newest-stable",),
            source="policy-successor",
            successor=rule,
        )
        for item in select_semver_candidates(None, listing)
    ]
    latest = latest_selection(listing, "successor-latest-channel", rule)
    if latest is not None:
        selections.append(latest)
    return tuple(selections)
