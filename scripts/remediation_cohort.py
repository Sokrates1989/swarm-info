"""Prepare explicit host policy targets from verified fleet candidate evidence.

This module never deploys or edits stack sources. Its output remains subject to
the existing option-4 candidate scan, per-action confirmation, convergence,
post-validation, and rollback gates. Unproved candidates and sources are
reported as skips instead of becoming policy authority.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence

from scripts.deployment_mapping import image_references_match
from scripts.remediation_engine import (
    RemediationExecutionError,
    preview_yaml_image_change,
)
from scripts.remediation_policy import (
    PolicyTarget,
    RemediationPolicy,
    SourceEdit,
    build_plan,
    image_repository,
    parse_candidate_image,
    vulnerable_items,
)
from scripts.remediation_source import SourceEditError, prepare_source_change
from scripts.vulnerability_models import ServiceRecord, digest_from_reference
from scripts.vulnerability_scan import DockerClient


VERIFIED_STATES = frozenset({"verified-clean", "verified-improvement"})
FULL_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ID_CHARACTER = re.compile(r"[^A-Za-z0-9_.-]")


@dataclasses.dataclass(frozen=True)
class CohortDecision:
    """One accepted or skipped workload without environment or secret values."""

    service: str
    status: str
    reason: str
    current_image: str = ""
    candidate_image: str = ""
    action: str = ""
    critical_removed: int = 0
    high_removed: int = 0


@dataclasses.dataclass(frozen=True)
class Cohort:
    """Inert policy additions and their per-service decision record."""

    targets: tuple[dict[str, Any], ...]
    decisions: tuple[CohortDecision, ...]


def _exact_image_matches(left: str, right: str) -> bool:
    """Require identical tagged references and identical immutable digests."""

    left_digest = digest_from_reference(left)
    right_digest = digest_from_reference(right)
    return bool(
        left_digest
        and right_digest
        and FULL_DIGEST.fullmatch(left_digest)
        and left_digest == right_digest
        and image_references_match(left, right)
        and image_references_match(right, left)
    )


def _replica_counts(client: DockerClient) -> dict[str, tuple[int, int]]:
    """Read current/desired service counts without inspecting environment values."""

    result = client.run(["service", "ls", "--format", "{{.Name}}|{{.Replicas}}"])
    if result.return_code != 0:
        raise RemediationExecutionError("cohort-service-list-failed")
    counts: dict[str, tuple[int, int]] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("|")
        match = re.fullmatch(r"(\d+)/(\d+)", value)
        if not separator or not match:
            continue
        counts[name] = (int(match.group(1)), int(match.group(2)))
    return counts


def _mapping_index(deployment_map: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Index only valid exact service mapping records."""

    records = deployment_map.get("services")
    if not isinstance(records, list):
        return {}
    return {
        record["name"]: record
        for record in records
        if isinstance(record, Mapping) and isinstance(record.get("name"), str)
    }


def _policy_id(service: str, digest: str) -> str:
    """Create one stable, bounded identifier for a reviewed candidate."""

    normalized = SAFE_ID_CHARACTER.sub("-", service)[:100].strip("-._")
    return f"cohort-{normalized or 'service'}-{digest[7:19]}"


def _target_document(target: PolicyTarget) -> dict[str, Any]:
    """Serialize one strict policy target without leaking source contents."""

    document: dict[str, Any] = {
        "id": target.identifier,
        "enabled": True,
        "match": {"service": target.service, "repository": target.repository},
        "candidate_image": target.candidate.reference,
        "backup": {"status": target.backup_status, "reason": target.backup_reason},
        "auto_eligible": True,
        "verification": {
            "timeout_seconds": target.timeout_seconds,
            "stability_seconds": target.stability_seconds,
        },
    }
    if target.source is not None:
        document["source"] = {
            "type": target.source.edit_type,
            "file": target.source.file,
        }
    return document


def _review_literal_source(
    client: DockerClient,
    target: PolicyTarget,
    mapping: Mapping[str, Any],
    current_image: str,
) -> bool:
    """Prove a YAML edit changes only the selected rendered service image."""

    stack_file_value = mapping.get("stack_file")
    compose_service = mapping.get("compose_service")
    if not isinstance(stack_file_value, str) or not isinstance(compose_service, str):
        return False
    stack_file = Path(stack_file_value)
    try:
        change = prepare_source_change(
            target, {"mapping": mapping, "current_image": current_image}
        )
        preview_yaml_image_change(
            client, change, stack_file, compose_service, current_image, target.candidate
        )
    except (OSError, RemediationExecutionError, SourceEditError):
        return False
    return True


def _declarative_target(
    client: DockerClient,
    target: PolicyTarget,
    mapping: Mapping[str, Any],
    current_image: str,
) -> PolicyTarget | None:
    """Return a mapped literal-YAML target only after a complete render proof."""

    directory_value = mapping.get("directory")
    stack_file_value = mapping.get("stack_file")
    if (
        mapping.get("status") != "mapped"
        or mapping.get("source_verified") is not True
        or not isinstance(directory_value, str)
        or not isinstance(stack_file_value, str)
    ):
        return None
    directory = Path(directory_value).resolve()
    stack_file = Path(stack_file_value).resolve()
    if stack_file.parent != directory:
        return None
    reviewed = dataclasses.replace(
        target, source=SourceEdit("yaml_image", stack_file.name)
    )
    return reviewed if _review_literal_source(client, reviewed, mapping, current_image) else None


def prepare_cohort(
    assessment: Mapping[str, Any],
    report: Mapping[str, Any],
    deployment_map: Mapping[str, Any],
    services: Sequence[ServiceRecord],
    existing_policy: Mapping[str, Any],
    backup_reason: str,
    client: DockerClient,
    *,
    include_runtime_overrides: bool = False,
    timeout_seconds: int = 300,
    stability_seconds: int = 0,
    progress: Callable[[int, int, str], None] | None = None,
) -> Cohort:
    """Stage every exact, verified candidate the current host can safely address.

    The caller owns the operator's explicit data-loss acceptance. Runtime
    overrides are staged only after a separate opt-in; option 4 still requires
    its own explicit runtime-override flag and per-service confirmation.
    """

    assessment_policy = assessment.get("policy")
    if (
        assessment.get("schema_version") != 1
        or not isinstance(assessment_policy, Mapping)
        or assessment_policy.get("resource_type") != "service"
    ):
        raise RemediationExecutionError("cohort-assessment-invalid")
    if (report.get("summary") or {}).get("complete") is not True:
        raise RemediationExecutionError("cohort-report-incomplete")
    if not backup_reason.strip() or len(backup_reason) > 500:
        raise RemediationExecutionError("cohort-backup-reason-invalid")
    rows = assessment.get("services")
    if not isinstance(rows, list):
        raise RemediationExecutionError("cohort-services-invalid")
    configured = {
        item.get("match", {}).get("service")
        for item in existing_policy.get("targets", [])
        if isinstance(item, Mapping) and isinstance(item.get("match"), Mapping)
    }
    current = {item["service"]: item for item in vulnerable_items(report)}
    live = {service.name: service for service in services}
    mappings = _mapping_index(deployment_map)
    counts = _replica_counts(client)
    decisions: list[CohortDecision] = []
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()

    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping) or not isinstance(row.get("service"), str):
            continue
        name = row["service"]
        if progress is not None:
            progress(index, len(rows), name)
        if name in seen:
            raise RemediationExecutionError("cohort-duplicate-service", name)
        seen.add(name)
        reason = ""
        item = current.get(name)
        live_service = live.get(name)
        candidate_reference = row.get("best_candidate")
        assessed_current = row.get("current_reference")
        removed = row.get("deployable_fixable")
        if name in configured:
            reason = "existing-policy-target"
        elif row.get("status") not in VERIFIED_STATES:
            reason = "candidate-not-verified"
        elif not isinstance(candidate_reference, str) or not isinstance(assessed_current, str):
            reason = "candidate-identity-missing"
        elif not isinstance(removed, Mapping) or not (
            isinstance(removed.get("critical"), int)
            and isinstance(removed.get("high"), int)
            and (removed["critical"] > 0 or removed["high"] > 0)
        ):
            reason = "candidate-not-improved"
        elif item is None or live_service is None or not (
            _exact_image_matches(assessed_current, str(item["image"]))
            and _exact_image_matches(str(item["image"]), live_service.image)
        ):
            reason = "current-image-changed"
        elif counts.get(name, (0, 0))[1] == 0 or (
            counts.get(name, (0, 0))[0] != counts.get(name, (0, 0))[1]
        ):
            reason = "service-not-converged"
        if reason:
            decisions.append(CohortDecision(name, "skipped", reason))
            continue
        try:
            candidate = parse_candidate_image(candidate_reference)
        except ValueError:
            decisions.append(CohortDecision(name, "skipped", "candidate-invalid"))
            continue
        if candidate.repository != image_repository(live_service.image):
            decisions.append(CohortDecision(name, "skipped", "repository-changed"))
            continue
        target = PolicyTarget(
            identifier=_policy_id(name, candidate.digest),
            enabled=True,
            service=name,
            repository=candidate.repository,
            candidate=candidate,
            backup_status="not_required",
            backup_reason=backup_reason.strip(),
            auto_eligible=True,
            source=None,
            timeout_seconds=timeout_seconds,
            stability_seconds=stability_seconds,
        )
        mapping = mappings.get(name, {})
        mapped = _declarative_target(client, target, mapping, live_service.image)
        if mapped is not None:
            target = mapped
            action = "declarative"
        elif (
            include_runtime_overrides
            and not (
                mapping.get("status") == "mapped"
                and mapping.get("source_verified") is True
            )
        ):
            action = "runtime-override"
        else:
            decisions.append(CohortDecision(name, "skipped", "source-not-proven"))
            continue
        # One blocked target must not prevent unrelated verified workloads from
        # entering a best-effort cohort. Reuse the option-4 plan gate per row.
        single_plan = build_plan(
            report,
            deployment_map,
            RemediationPolicy(
                Path("/cohort-preview/remediation-policy.json"), (target,)
            ),
        )
        entries = single_plan["entries"]
        if len(entries) != 1 or entries[0]["eligible"] is not True:
            decisions.append(CohortDecision(name, "skipped", "plan-not-eligible"))
            continue
        targets.append(_target_document(target))
        decisions.append(
            CohortDecision(
                name, "staged", "verified-candidate", live_service.image,
                candidate.reference, action, removed["critical"], removed["high"]
            )
        )

    for name in sorted(current.keys() - seen):
        decisions.append(CohortDecision(name, "skipped", "assessment-missing"))

    return Cohort(tuple(targets), tuple(decisions))
