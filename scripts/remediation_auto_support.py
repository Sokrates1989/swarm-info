"""Review preparation and conservative one-run auto-remediation execution."""

from __future__ import annotations

import argparse
from pathlib import Path
import shlex
from typing import Any, Callable, Mapping, TextIO

from scripts.operator_report import load_messages, message, safe_text
from scripts.remediation_engine import (
    ActionResult,
    RemediationExecutionError,
    execute_latest_refresh,
    service_image_update_command,
    validate_candidate_reference,
)
from scripts.remediation_policy import RemediationPolicy
from scripts.remediation_review import (
    ReviewAssessment,
    assess_review_queue,
    attach_safe_actions,
    record_review_outcome,
    write_review,
)
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DockerClient


def _ask(
    prompt: str,
    input_function: Callable[[str], str],
) -> bool:
    """Read one explicit default-No answer without propagating terminal aborts."""

    try:
        answer = input_function(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes", "j", "ja"}


def _review_guidance() -> dict[str, list[str]]:
    """Return complete localized instructions stored beside generated evidence."""

    keys = (
        "remediation.reviewGuidanceGenerated",
        "remediation.reviewGuidanceTargets",
        "remediation.reviewGuidanceCandidate",
        "remediation.reviewGuidanceBackup",
        "remediation.reviewGuidanceSource",
        "remediation.reviewGuidanceForce",
    )
    return {
        locale: [message(load_messages(locale), key) for key in keys]
        for locale in ("en", "de")
    }


def prepare_review(
    report: Mapping[str, Any],
    deployment_map: Mapping[str, Any],
    policy: RemediationPolicy,
    plan: dict[str, Any],
    options: argparse.Namespace,
    client: DockerClient,
    catalog: Mapping[str, str],
    output: TextIO,
    policy_created: bool,
) -> ReviewAssessment:
    """Assess defaults, persist the inert queue, and attach safe plan actions."""

    platform = safe_text((report.get("policy") or {}).get("platform", "linux/amd64"))
    print(message(catalog, "remediation.reviewStarting"), file=output)

    def show_progress(index: int, total: int, image: str) -> None:
        """Render one localized read-only assessment progress line."""

        print(
            message(
                catalog,
                "remediation.reviewProgress",
                index=index,
                total=total,
                image=image,
            ),
            file=output,
        )

    assessment = assess_review_queue(
        report,
        deployment_map,
        policy,
        plan,
        client,
        platform,
        options.allow_runtime_override,
        progress=show_progress,
    )
    attach_safe_actions(plan, assessment)
    write_review(policy.path, assessment, _review_guidance())
    key = "remediation.reviewCreated" if policy_created else "remediation.reviewUpdated"
    print(
        message(
            catalog,
            key,
            path=policy.path,
            entries=assessment.review["summary"]["entries"],
        ),
        file=output,
    )
    print(
        message(
            catalog,
            "remediation.reviewSummary",
            safe=assessment.review["summary"]["safe_latest_actions"],
            blocked=assessment.review["summary"]["blocked"],
        ),
        file=output,
    )
    print(message(catalog, "remediation.reviewInert"), file=output)
    print(
        message(catalog, "remediation.reviewEdit", path=policy.path),
        file=output,
    )
    return assessment


def _record_result(
    plan: dict[str, Any], result: ActionResult, plan_output: Path
) -> None:
    """Atomically append one safe-action result to the reviewed plan."""

    execution = plan.setdefault("execution", [])
    if not isinstance(execution, list):
        raise RemediationExecutionError("plan-execution-invalid")
    execution.append(result.to_dict())
    write_json_atomic(plan_output, plan)


def run_safe_latest_actions(
    assessment: ReviewAssessment,
    plan: dict[str, Any],
    plan_output: Path,
    policy_path: Path,
    platform: str,
    client: DockerClient,
    catalog: Mapping[str, str],
    context_name: str,
    input_function: Callable[[str], str],
    output: TextIO,
) -> int:
    """Execute only confirmed same-major refreshes already intended as latest."""

    deployed = 0
    for action in assessment.safe_actions:
        print("", file=output)
        print(
            message(
                catalog,
                "remediation.safeLatestReady",
                service=action.service,
                current=action.current_version,
                candidate=action.candidate_version,
                image=action.candidate.reference,
            ),
            file=output,
        )
        directory = safe_text(action.mapping.get("directory"))
        print(
            message(catalog, "remediation.safeLatestSource", directory=directory),
            file=output,
        )
        command = shlex.join(
            ["docker", *service_image_update_command(action.service, action.candidate)]
        )
        print(f"  {command}", file=output)
        print(
            f"  {shlex.join(['docker', 'service', 'update', '--rollback', action.service])}",
            file=output,
        )
        if not _ask(
            message(
                catalog,
                "remediation.safeLatestBackupConfirm",
                service=action.service,
            ),
            input_function,
        ):
            record_review_outcome(
                policy_path,
                action.service,
                "declined",
                "backup-and-compatibility-not-confirmed",
            )
            print(message(catalog, "remediation.skipped"), file=output)
            continue
        if not _ask(
            message(
                catalog,
                "remediation.safeLatestUpdateConfirm",
                service=action.service,
                context=context_name,
            ),
            input_function,
        ):
            record_review_outcome(
                policy_path,
                action.service,
                "declined",
                "service-update-not-confirmed",
            )
            print(message(catalog, "remediation.skipped"), file=output)
            continue
        try:
            result = execute_latest_refresh(
                client,
                action.service,
                action.candidate,
                action.current_image,
                action.timeout_seconds,
                post_validation=lambda current=action: validate_candidate_reference(
                    client,
                    current.candidate,
                    current.service,
                    current.to_plan_dict(),
                    platform,
                ),
            )
        except RemediationExecutionError as error:
            record_review_outcome(
                policy_path,
                action.service,
                "failed",
                error.code,
                error.detail,
            )
            raise
        _record_result(plan, result, plan_output)
        record_review_outcome(policy_path, action.service, "deployed")
        deployed += 1
        print(message(catalog, "remediation.deployed", service=action.service), file=output)
    return deployed
