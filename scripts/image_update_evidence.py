"""Compare fixable vulnerability evidence between two image artifacts."""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Sequence

from scripts.vulnerability_models import Finding, severity_counts


VERIFIED_UPDATE_STATES = ("verified-clean", "verified-improvement")


@dataclasses.dataclass(frozen=True)
class ImageUpdateEvidence:
    """Security delta proven by scanning one current and one candidate image."""

    status: str
    current_critical: int
    current_high: int
    candidate_critical: int
    candidate_high: int
    removed_critical: int
    removed_high: int
    current_finding_ids: tuple[str, ...]
    candidate_finding_ids: tuple[str, ...]
    removed_finding_ids: tuple[str, ...]
    remaining_finding_ids: tuple[str, ...]
    new_finding_ids: tuple[str, ...]

    @property
    def current_total(self) -> int:
        """Return the current critical/high result count."""

        return self.current_critical + self.current_high

    @property
    def candidate_total(self) -> int:
        """Return the candidate critical/high result count."""

        return self.candidate_critical + self.candidate_high

    @property
    def removed_total(self) -> int:
        """Return the net reduction in critical/high result count."""

        return max(0, self.current_total - self.candidate_total)

    @property
    def is_verified_improvement(self) -> bool:
        """Return whether the candidate passed the shared safe-update gate."""

        return self.status in VERIFIED_UPDATE_STATES

    def to_dict(self) -> dict[str, Any]:
        """Serialize the comparison for an atomic operator evidence report."""

        return {
            "status": self.status,
            "current": {
                "critical": self.current_critical,
                "high": self.current_high,
                "total": self.current_total,
                "finding_ids": list(self.current_finding_ids),
            },
            "candidate": {
                "critical": self.candidate_critical,
                "high": self.candidate_high,
                "total": self.candidate_total,
                "finding_ids": list(self.candidate_finding_ids),
            },
            "removed": {
                "critical": self.removed_critical,
                "high": self.removed_high,
                "total": self.removed_total,
                "finding_ids": list(self.removed_finding_ids),
            },
            "remaining_finding_ids": list(self.remaining_finding_ids),
            "new_finding_ids": list(self.new_finding_ids),
        }


def _normalized_identifiers(values: Iterable[object]) -> set[str]:
    """Return non-empty normalized finding identifiers."""

    return {value.strip() for value in values if isinstance(value, str) and value.strip()}


def compare_candidate_evidence(
    current_critical: int,
    current_high: int,
    current_finding_ids: Iterable[object],
    candidate_findings: Sequence[Finding],
) -> ImageUpdateEvidence:
    """Compare a candidate scan with current critical/high evidence.

    The verdict intentionally requires both lower severity counts and no new
    finding identifiers. This is the same fail-closed rule used before an
    automatic remediation candidate can be accepted.
    """

    if (
        isinstance(current_critical, bool)
        or not isinstance(current_critical, int)
        or current_critical < 0
        or isinstance(current_high, bool)
        or not isinstance(current_high, int)
        or current_high < 0
    ):
        raise ValueError("current critical/high counts must be non-negative integers")

    current_ids = _normalized_identifiers(current_finding_ids)
    candidate_ids = _normalized_identifiers(
        finding.identifier for finding in candidate_findings
    )
    counts = severity_counts(candidate_findings)
    candidate_critical = counts["critical"]
    candidate_high = counts["high"]
    current_total = current_critical + current_high
    candidate_total = candidate_critical + candidate_high
    new_ids = candidate_ids - current_ids
    severity_regression = (
        candidate_critical > current_critical or candidate_high > current_high
    )

    count_reduction = candidate_total < current_total
    severity_reduction = (
        candidate_critical <= current_critical and candidate_high <= current_high
    )

    if current_total == 0 and candidate_total == 0:
        status = "already-clean"
    elif candidate_total == 0:
        status = "verified-clean"
    elif count_reduction and severity_reduction and not new_ids:
        status = "verified-improvement"
    elif count_reduction:
        status = "mixed-improvement"
    elif new_ids or severity_regression:
        status = "regression"
    else:
        status = "not-improved"

    return ImageUpdateEvidence(
        status=status,
        current_critical=current_critical,
        current_high=current_high,
        candidate_critical=candidate_critical,
        candidate_high=candidate_high,
        removed_critical=max(0, current_critical - candidate_critical),
        removed_high=max(0, current_high - candidate_high),
        current_finding_ids=tuple(sorted(current_ids)),
        candidate_finding_ids=tuple(sorted(candidate_ids)),
        removed_finding_ids=tuple(sorted(current_ids - candidate_ids)),
        remaining_finding_ids=tuple(sorted(current_ids & candidate_ids)),
        new_finding_ids=tuple(sorted(new_ids)),
    )
