"""Conservative no-policy assessment and installation review-queue storage.

The generated review section is inert evidence.  It may suggest strict target
values, but only entries an operator moves into ``targets`` can authorize the
normal auto-remediation executor.  The one built-in executable action is a
validated same-major refresh of a source that already follows ``latest``; it
still requires two default-No confirmations in the current terminal.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence

from scripts.remediation_advice import ImageAdvice, ScoutBaseAdvice, analyze_image
from scripts.remediation_engine import CandidateValidation
from scripts.remediation_policy import (
    POLICY_SCHEMA_VERSION,
    CandidateImage,
    PolicyTarget,
    RemediationPolicy,
    RemediationPolicyError,
    image_repository,
    is_mutable_latest,
    load_policy,
    vulnerable_items,
)
from scripts.vulnerability_models import digest_from_reference, utc_timestamp, write_json_atomic
from scripts.vulnerability_scan import DockerClient


REVIEW_SCHEMA_VERSION = 1
DEFAULT_POLICY_NAME = "remediation-policy.json"
SAFE_IDENTIFIER_CHARACTERS = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclasses.dataclass(frozen=True)
class SafeLatestAction:
    """One candidate eligible for a confirmed, source-aligned latest refresh."""

    service: str
    current_image: str
    candidate: CandidateImage
    validation: CandidateValidation
    mapping: Mapping[str, Any]
    critical: int
    high: int
    finding_ids: tuple[str, ...]
    current_version: str
    candidate_version: str
    timeout_seconds: int = 300

    def to_plan_dict(self) -> dict[str, Any]:
        """Serialize the reviewed action without granting persisted authority."""

        return {
            "service": self.service,
            "action": "latest-refresh",
            "current_image": self.current_image,
            "candidate_image": self.candidate.reference,
            "critical": self.critical,
            "high": self.high,
            "finding_ids": list(self.finding_ids),
            "mapping": dict(self.mapping),
            "compatibility": "same-major",
            "current_version": self.current_version,
            "candidate_version": self.candidate_version,
            "validation": {
                "status": self.validation.status,
                "critical": self.validation.critical,
                "high": self.validation.high,
                "finding_ids": list(self.validation.finding_ids),
                "new_finding_ids": list(self.validation.new_finding_ids),
                "comparison": self.validation.comparison.to_dict(),
            },
            "verification": {"timeout_seconds": self.timeout_seconds},
            "required_confirmations": [
                "backup-and-compatibility",
                "service-update",
            ],
        }


@dataclasses.dataclass(frozen=True)
class ReviewAssessment:
    """Generated non-authorizing review evidence and one-run safe actions."""

    review: Mapping[str, Any]
    safe_actions: tuple[SafeLatestAction, ...]


def attach_safe_actions(
    plan: dict[str, Any], assessment: ReviewAssessment
) -> None:
    """Add one-run actions to the audited plan and refresh its stable identity."""

    actions = [action.to_plan_dict() for action in assessment.safe_actions]
    plan["default_safe_actions"] = actions
    summary = plan.get("summary")
    if not isinstance(summary, dict):
        raise RemediationPolicyError("planSummary")
    summary["default_safe_actions"] = len(actions)
    identity = {
        "schema_version": plan.get("schema_version"),
        "report_completed_at": plan.get("report_completed_at"),
        "report_fingerprint": plan.get("report_fingerprint"),
        "force_attempt": plan.get("force_attempt"),
        "entries": plan.get("entries"),
        "default_safe_actions": actions,
    }
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    plan["plan_id"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def policy_output_path(
    explicit: Path | None,
    environment: Mapping[str, str] | None = None,
    current_directory: Path | None = None,
    home_directory: Path | None = None,
) -> Path:
    """Choose an explicit, deployment-owned, or user-scoped policy destination."""

    if explicit is not None:
        return explicit.expanduser()
    values = os.environ if environment is None else environment
    configured = values.get("SWARM_INFO_REMEDIATION_POLICY", "").strip()
    if configured:
        return Path(configured).expanduser()
    current = Path.cwd() if current_directory is None else current_directory
    deployment_policy = current / "configs" / DEFAULT_POLICY_NAME
    if deployment_policy.is_file() or (
        (current / ".git").exists() and deployment_policy.parent.is_dir()
    ):
        return deployment_policy
    xdg_value = values.get("XDG_CONFIG_HOME", "").strip()
    if xdg_value:
        config_home = Path(xdg_value).expanduser()
    else:
        home = Path.home() if home_directory is None else home_directory
        config_home = home / ".config"
    return config_home / "swarm-info" / DEFAULT_POLICY_NAME


def ensure_policy(path: Path) -> bool:
    """Create an empty current-schema policy atomically, or validate one."""

    if path.exists():
        load_policy(path)
        return False
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_json_atomic(
        path,
        {
            "schema_version": POLICY_SCHEMA_VERSION,
            "targets": [],
        },
    )
    return True


def _read_policy_document(path: Path) -> dict[str, Any]:
    """Read a policy already validated by the strict authorization parser."""

    load_policy(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RemediationPolicyError("policyUnreadable", str(path)) from error
    if not isinstance(payload, dict):
        raise RemediationPolicyError("policyObject")
    return payload


def write_review(
    path: Path,
    assessment: ReviewAssessment,
    localized_guidance: Mapping[str, Sequence[str]],
) -> None:
    """Refresh generated evidence while preserving sanitized attempt outcomes."""

    payload = _read_policy_document(path)
    prior_attempts: dict[str, dict[str, str]] = {}
    previous_review = payload.get("generated_review")
    previous_entries = (
        previous_review.get("entries")
        if isinstance(previous_review, Mapping)
        else None
    )
    if isinstance(previous_entries, Sequence) and not isinstance(
        previous_entries, (str, bytes)
    ):
        for entry in previous_entries:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("service"), str):
                continue
            attempt = entry.get("last_attempt")
            if isinstance(attempt, Mapping):
                prior_attempts[entry["service"]] = _sanitized_attempt(attempt)

    review = dict(assessment.review)
    entries = review.get("entries")
    if isinstance(entries, Sequence) and not isinstance(entries, (str, bytes)):
        refreshed_entries: list[Any] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                refreshed_entries.append(entry)
                continue
            refreshed = dict(entry)
            service = refreshed.get("service")
            if isinstance(service, str) and service in prior_attempts:
                refreshed["last_attempt"] = prior_attempts[service]
            refreshed_entries.append(refreshed)
        review["entries"] = refreshed_entries

    payload["schema_version"] = POLICY_SCHEMA_VERSION
    payload["generated_review"] = {
        **review,
        "_guidance": {
            locale: list(lines) for locale, lines in localized_guidance.items()
        },
    }
    write_json_atomic(path, payload)


def _single_line(value: object, limit: int) -> str:
    """Return bounded, NUL-free diagnostic text safe for generated JSON."""

    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("\x00", "").split())[:limit]


def _sanitized_attempt(attempt: Mapping[str, Any]) -> dict[str, str]:
    """Keep only bounded attempt fields; never preserve arbitrary generated data."""

    return {
        "at": _single_line(attempt.get("at"), 64),
        "outcome": _single_line(attempt.get("outcome"), 64),
        "reason": _single_line(attempt.get("reason"), 128),
        "detail": _single_line(attempt.get("detail"), 500),
    }


def record_review_outcome(
    path: Path,
    service: str,
    outcome: str,
    reason: str = "",
    detail: str = "",
) -> None:
    """Record one sanitized attempt outcome in the machine-owned review queue."""

    attempt = _sanitized_attempt(
        {
            "at": utc_timestamp(),
            "outcome": outcome,
            "reason": reason,
            "detail": detail,
        }
    )
    payload = _read_policy_document(path)
    review = payload.get("generated_review")
    if not isinstance(review, dict):
        return
    entries = review.get("entries")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if isinstance(entry, dict) and entry.get("service") == service:
            entry["last_attempt"] = attempt
            write_json_atomic(path, payload)
            return
    entries.append(
        {
            "service": service,
            "default_decision": "execution-record",
            "reasons": [],
            "suggested_target": None,
            "last_attempt": attempt,
        }
    )
    summary = review.get("summary")
    if isinstance(summary, dict):
        summary["entries"] = len(entries)
    write_json_atomic(path, payload)


def _mapping_by_service(
    deployment_map: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Index sanitized mapping evidence by exact service name."""

    services = deployment_map.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        return {}
    return {
        str(record["name"]): record
        for record in services
        if isinstance(record, Mapping) and isinstance(record.get("name"), str)
    }


def _mapping_evidence(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Retain only non-secret mapper fields needed for operator review."""

    fields = (
        "status",
        "reason",
        "stack",
        "directory",
        "stack_file",
        "compose_service",
        "declared_image",
        "source_verified",
    )
    return {field: mapping.get(field) for field in fields if field in mapping}


def _review_identifier(service: str) -> str:
    """Create a stable disabled-target identifier from a Docker service name."""

    normalized = SAFE_IDENTIFIER_CHARACTERS.sub("-", service).strip("-._")
    return f"{normalized[:100] or 'service'}-reviewed-update"


def _reference_tag(reference: str) -> str:
    """Return a Docker reference tag while ignoring its immutable digest."""

    name = reference.split("@", 1)[0]
    final_slash = name.rfind("/")
    final_colon = name.rfind(":")
    return name[final_colon + 1 :] if final_colon > final_slash else "latest"


def _suggested_target(
    item: Mapping[str, Any], advice: ImageAdvice
) -> dict[str, Any]:
    """Build an inert target template that remains invalid for auto execution."""

    candidate = advice.validated_candidate
    return {
        "id": _review_identifier(str(item["service"])),
        "enabled": False,
        "match": {
            "service": str(item["service"]),
            "repository": image_repository(str(item["image"])),
        },
        "candidate_image": candidate.reference if candidate is not None else None,
        "backup": {
            "status": "review_required",
            "reason": "",
        },
        "auto_eligible": False,
        "source": None,
        "verification": {"timeout_seconds": 300},
    }


def _safe_latest_action(
    item: Mapping[str, Any],
    mapping: Mapping[str, Any],
    advice: ImageAdvice,
) -> SafeLatestAction | None:
    """Return the one built-in action whose source intent and version are proven."""

    candidate = advice.validated_candidate
    validation = advice.validation
    if (
        candidate is None
        or validation is None
        or advice.candidate_source != "latest-refresh"
        or advice.compatibility != "same-major"
        or not advice.current_version
        or not advice.candidate_version
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest_from_reference(str(item["image"])) or "")
        or mapping.get("status") != "mapped"
        or mapping.get("source_verified") is not True
        or not is_mutable_latest(mapping.get("declared_image"))
    ):
        return None
    return SafeLatestAction(
        service=str(item["service"]),
        current_image=str(item["image"]),
        candidate=candidate,
        validation=validation,
        mapping=_mapping_evidence(mapping),
        critical=int(item["critical"]),
        high=int(item["high"]),
        finding_ids=tuple(str(value) for value in item.get("finding_ids", [])),
        current_version=advice.current_version,
        candidate_version=advice.candidate_version,
    )


def _default_blocked_reasons(
    item: Mapping[str, Any],
    mapping: Mapping[str, Any],
    advice: ImageAdvice,
) -> list[str]:
    """Explain why built-in rules cannot mutate one unconfigured service."""

    reasons = ["policy-target-missing", "backup-classification-required"]
    if not re.fullmatch(
        r"sha256:[0-9a-f]{64}", digest_from_reference(str(item["image"])) or ""
    ):
        reasons.append("current-image-mutable")
    if advice.validated_candidate is None:
        candidate_reason = {
            "manual-review": "candidate-not-discovered",
            "latest-current": "latest-current",
            "latest-unresolved": "latest-unresolved",
            "candidate-rejected": advice.validation_error or "candidate-rejected",
        }.get(advice.proposal_state, "candidate-not-discovered")
        reasons.append(candidate_reason)
    elif advice.candidate_source != "latest-refresh":
        reasons.append("candidate-not-built-in-latest-refresh")
    elif advice.compatibility != "same-major":
        reasons.append("same-major-version-not-proven")
    if mapping.get("status") != "mapped":
        reasons.append("deployment-source-unresolved")
    elif mapping.get("source_verified") is not True:
        reasons.append("deployment-source-unverified")
    elif not is_mutable_latest(mapping.get("declared_image")):
        reasons.append("source-does-not-follow-latest")
    return list(dict.fromkeys(reasons))


def _unconfigured_review_entry(
    item: Mapping[str, Any],
    mapping: Mapping[str, Any],
    advice: ImageAdvice,
    action: SafeLatestAction | None,
) -> dict[str, Any]:
    """Describe one absent override without turning the suggestion into authority."""

    reasons = (
        ["one-run-backup-confirmation-required", "one-run-update-confirmation-required"]
        if action is not None
        else _default_blocked_reasons(item, mapping, advice)
    )
    return {
        "service": str(item["service"]),
        "repository": str(item["repository"]),
        "current_image": str(item["image"]),
        "risk": {
            "critical": int(item["critical"]),
            "high": int(item["high"]),
            "shared_service_count": int(item["shared_service_count"]),
        },
        "candidate_state": advice.proposal_state,
        "candidate_source": advice.candidate_source,
        "candidate_image": (
            advice.validated_candidate.reference
            if advice.validated_candidate is not None
            else None
        ),
        "current_version": advice.current_version,
        "candidate_version": advice.candidate_version,
        "compatibility": advice.compatibility,
        "default_decision": (
            "ready-with-confirmations" if action is not None else "blocked"
        ),
        "reasons": reasons,
        "deployment": _mapping_evidence(mapping),
        "suggested_target": _suggested_target(item, advice),
    }


def _policy_review_entries(
    policy: RemediationPolicy,
    plan: Mapping[str, Any],
    allow_runtime_override: bool,
) -> list[dict[str, Any]]:
    """Convert blocked configured targets into editable review-queue evidence."""

    targets = {target.identifier: target for target in policy.targets}
    entries: list[dict[str, Any]] = []
    for plan_entry in plan.get("entries", []):
        if not isinstance(plan_entry, Mapping):
            continue
        reasons = list(plan_entry.get("blocked_reasons", []))
        if (
            plan_entry.get("eligible") is True
            and plan_entry.get("action") == "runtime-override"
            and not allow_runtime_override
        ):
            reasons.append("runtime-override-flag-required")
        if not reasons:
            continue
        target = targets.get(str(plan_entry.get("policy_id")))
        entries.append(
            {
                "service": str(plan_entry.get("service", "")),
                "repository": target.repository if target else None,
                "current_image": plan_entry.get("current_image"),
                "candidate_image": plan_entry.get("candidate_image"),
                "default_decision": "blocked",
                "reasons": reasons,
                "deployment": _mapping_evidence(plan_entry.get("mapping", {})),
                "existing_target_id": plan_entry.get("policy_id"),
                "suggested_target": None,
            }
        )
    return entries


def assess_review_queue(
    report: Mapping[str, Any],
    deployment_map: Mapping[str, Any],
    policy: RemediationPolicy,
    plan: Mapping[str, Any],
    client: DockerClient,
    platform: str,
    allow_runtime_override: bool,
    progress: Callable[[int, int, str], None] | None = None,
) -> ReviewAssessment:
    """Assess uncovered images once and build inert per-service review entries."""

    items = vulnerable_items(report)
    configured_services = {target.service for target in policy.targets}
    mappings = _mapping_by_service(deployment_map)
    representatives: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if item["service"] not in configured_services:
            key = str(item.get("scan_reference") or item["image"])
            representatives.setdefault(key, item)
    advice_by_image: dict[str, ImageAdvice] = {}
    total = len(representatives)
    for index, (key, item) in enumerate(representatives.items(), start=1):
        if progress is not None:
            progress(index, total, str(item["image"]))
        current_image = str(item["image"])
        current_tag = _reference_tag(current_image)
        if current_tag.lower() != "latest":
            advice_by_image[key] = ImageAdvice(
                current_tag=current_tag,
                current_digest=digest_from_reference(current_image),
                current_version=current_tag,
                current_version_source="configured-tag",
                scout=ScoutBaseAdvice("skipped"),
                proposal_state="manual-review",
            )
        else:
            advice_by_image[key] = analyze_image(
                client,
                item,
                platform,
                include_scout_recommendations=False,
            )

    review_entries = _policy_review_entries(
        policy, plan, allow_runtime_override
    )
    safe_actions: list[SafeLatestAction] = []
    for item in items:
        if item["service"] in configured_services:
            continue
        key = str(item.get("scan_reference") or item["image"])
        advice = advice_by_image[key]
        mapping = mappings.get(str(item["service"]), {})
        action = _safe_latest_action(item, mapping, advice)
        if action is not None:
            safe_actions.append(action)
        review_entries.append(
            _unconfigured_review_entry(item, mapping, advice, action)
        )
    review_entries.sort(
        key=lambda entry: (
            -int((entry.get("risk") or {}).get("critical", 0)),
            -int((entry.get("risk") or {}).get("high", 0)),
            str(entry.get("service", "")),
        )
    )
    safe_actions.sort(key=lambda action: (-action.critical, -action.high, action.service))
    return ReviewAssessment(
        review={
            "schema_version": REVIEW_SCHEMA_VERSION,
            "generated_at": utc_timestamp(),
            "report_completed_at": report.get("completed_at"),
            "report_fingerprint": (
                (report.get("scope") or {}).get("image_fingerprint")
                if isinstance(report.get("scope"), Mapping)
                else None
            ),
            "summary": {
                "entries": len(review_entries),
                "safe_latest_actions": len(safe_actions),
                "blocked": sum(
                    entry.get("default_decision") == "blocked"
                    for entry in review_entries
                ),
            },
            "entries": review_entries,
        },
        safe_actions=tuple(safe_actions),
    )
