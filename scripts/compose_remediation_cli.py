"""Operator CLI for guarded standalone Compose image remediation."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, Sequence

from scripts.compose_remediation_engine import (
    ComposeRemediationError,
    PreparedComposeRemediation,
    inspect_compose_container,
    pull_candidate,
    recreate_compose_service,
    restore_source_from_backup,
    validate_current_config,
    wait_for_image,
    write_source_backup,
)
from scripts.compose_remediation_plan import (
    load_compose_evidence,
    prepare_compose_remediation,
)
from scripts.compose_remediation_record import (
    append_event,
    backup_path,
    load_transaction_plan,
    post_check_path,
    rollback_evidence,
    write_plan,
)
from scripts.compose_remediation_verification import run_focused_post_check
from scripts.compose_remediation_policy import (
    ComposePolicyError,
    load_compose_policy,
    select_compose_target,
)
from scripts.deployment_mapping import image_references_match
from scripts.operator_report import load_messages, message, selected_locale
from scripts.remediation_source import SourceEditError, write_source_change
from scripts.vulnerability_models import utc_timestamp
from scripts.vulnerability_scan import DockerClient


Prompt = Callable[[str], bool]
PostCheck = Callable[[DockerClient, PreparedComposeRemediation, Path], Mapping[str, Any]]


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the standalone remediation command line."""

    catalog = load_messages(selected_locale())
    parser = argparse.ArgumentParser(
        description=message(catalog, "composeRemediation.description")
    )
    parser.add_argument("--report-file", type=Path)
    parser.add_argument("--remediation-policy", type=Path)
    parser.add_argument("--compose-service")
    parser.add_argument("--plan-output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--os", choices=("auto", "qnap", "linux"), default="auto")
    parser.add_argument("--scout-timeout-minutes", type=float, default=45.0)
    options = parser.parse_args(arguments)
    if options.apply and options.rollback:
        parser.error(message(catalog, "composeRemediation.error.mutuallyExclusive"))
    if not options.rollback and (
        options.report_file is None
        or options.remediation_policy is None
        or not options.compose_service
    ):
        parser.error(message(catalog, "composeRemediation.error.required"))
    if options.scout_timeout_minutes <= 0:
        parser.error(message(catalog, "composeRemediation.error.timeout"))
    return options


def default_no_prompt(message: str) -> bool:
    """Return true only for an explicit affirmative interactive answer."""

    try:
        catalog = load_messages(selected_locale())
        answer = input(message + catalog["composeRemediation.promptSuffix"])
    except EOFError:
        return False
    affirmative = {
        value.strip()
        for value in catalog["composeRemediation.affirmative"].split(",")
    }
    return answer.strip().lower() in affirmative


def _pre_apply_snapshot(
    client: DockerClient, prepared: PreparedComposeRemediation
) -> None:
    """Reject drift between focused evidence, source review, and live Docker."""

    snapshot = inspect_compose_container(client, prepared.evidence)
    if snapshot.image_id != prepared.evidence.current_image_id:
        raise ComposeRemediationError("liveImageChanged", snapshot.image_id)
    if not image_references_match(
        snapshot.configured_image, prepared.evidence.current_reference
    ):
        raise ComposeRemediationError("liveReferenceChanged", snapshot.configured_image)


def apply_prepared_remediation(
    client: DockerClient,
    prepared: PreparedComposeRemediation,
    plan_path: Path,
    *,
    prompt: Prompt = default_no_prompt,
    post_check: PostCheck = run_focused_post_check,
) -> int:
    """Apply one reviewed source change or restore it after any failed check."""

    plan = prepared.plan
    source_backup = backup_path(plan_path)
    post_path = post_check_path(plan_path)
    plan["backup"]["source_file"] = str(source_backup)
    write_plan(plan_path, plan)
    if not prompt(
        message(
            load_messages(selected_locale()),
            "composeRemediation.confirm.backup",
        )
    ):
        plan["status"] = "cancelled"
        append_event(plan, "operator-cancelled", stage="backup-confirmation")
        write_plan(plan_path, plan)
        return 4
    if not prompt(
        message(
            load_messages(selected_locale()),
            "composeRemediation.confirm.apply",
            selector=prepared.evidence.selector,
        )
    ):
        plan["status"] = "cancelled"
        append_event(plan, "operator-cancelled", stage="apply-confirmation")
        write_plan(plan_path, plan)
        return 4

    source_written = False
    candidate_image_id: str | None = None
    rolled_back = False
    try:
        _pre_apply_snapshot(client, prepared)
        write_source_backup(source_backup, prepared.source_change.original)
        append_event(plan, "source-backup-created")
        candidate_image_id = pull_candidate(client, prepared.target)
        plan["candidate"]["local_image_id"] = candidate_image_id
        write_source_change(prepared.source_change)
        source_written = True
        append_event(plan, "source-updated")
        config_files = tuple(
            Path(value) for value in plan["source"]["config_files"]
        )
        validate_current_config(client, prepared.evidence, config_files)
        append_event(plan, "compose-render-validated")
        recreate_compose_service(client, prepared.evidence, config_files)
        snapshot = wait_for_image(
            client,
            prepared.evidence,
            candidate_image_id,
            prepared.target.timeout_seconds,
        )
        append_event(plan, "candidate-converged", container_id=snapshot.container_id)
        post_check(client, prepared, post_path)
        append_event(plan, "focused-post-check-passed")
    except BaseException as error:
        rollback_error = ""
        if source_written:
            try:
                write_source_change(
                    prepared.source_change,
                    replacement=prepared.source_change.original,
                )
                config_files = tuple(
                    Path(value) for value in plan["source"]["config_files"]
                )
                validate_current_config(client, prepared.evidence, config_files)
                recreate_compose_service(client, prepared.evidence, config_files)
                wait_for_image(
                    client,
                    prepared.evidence,
                    prepared.evidence.current_image_id,
                    prepared.target.timeout_seconds,
                )
                rolled_back = True
                append_event(plan, "automatic-rollback-confirmed")
            except BaseException as rollback_failure:
                rollback_error = getattr(
                    rollback_failure, "code", type(rollback_failure).__name__
                )
                append_event(plan, "automatic-rollback-failed", code=rollback_error)
        code = getattr(error, "code", type(error).__name__)
        plan["status"] = "failed"
        plan["execution"] = {
            "error": code,
            "rolled_back": rolled_back,
            "rollback_error": rollback_error or None,
            "candidate_local_image_id": candidate_image_id,
        }
        append_event(plan, "apply-failed", code=code)
        write_plan(plan_path, plan)
        if isinstance(error, ComposeRemediationError):
            raise
        if isinstance(error, SourceEditError):
            raise ComposeRemediationError(error.code, error.detail) from error
        raise ComposeRemediationError("applyFailed", code) from error

    plan["status"] = "deployed"
    plan["execution"] = {
        "candidate_local_image_id": candidate_image_id,
        "post_check_file": str(post_path),
        "rolled_back": False,
    }
    append_event(plan, "apply-complete")
    write_plan(plan_path, plan)
    return 0


def rollback_transaction(
    client: DockerClient,
    plan_path: Path,
    *,
    prompt: Prompt = default_no_prompt,
) -> int:
    """Restore source and exact prior artifact from a successful transaction."""

    plan = load_transaction_plan(plan_path)
    if plan["status"] == "rolled-back":
        return 0
    if not prompt(
        message(
            load_messages(selected_locale()),
            "composeRemediation.confirm.rollback",
            selector=plan.get("compose_service", "Compose service"),
        )
    ):
        append_event(plan, "operator-cancelled", stage="rollback-confirmation")
        write_plan(plan_path, plan)
        return 4
    evidence = rollback_evidence(plan)
    source = plan["source"]
    backup = plan["backup"]
    timeout = plan.get("verification", {}).get("timeout_seconds")
    if not isinstance(timeout, int):
        raise ComposeRemediationError("planFields")
    source_path = Path(source["file"])
    backup_path = Path(backup["source_file"])
    restore_source_from_backup(
        source_path,
        backup_path,
        source["replacement_sha256"],
        source["original_sha256"],
    )
    try:
        validate_current_config(client, evidence, evidence.config_files)
        recreate_compose_service(client, evidence, evidence.config_files)
        snapshot = wait_for_image(
            client, evidence, evidence.current_image_id, timeout
        )
    except BaseException as error:
        code = getattr(error, "code", type(error).__name__)
        plan["status"] = "rollback-failed"
        append_event(plan, "operator-rollback-failed", code=code)
        write_plan(plan_path, plan)
        if isinstance(error, ComposeRemediationError):
            raise
        raise ComposeRemediationError("rollbackFailed", code) from error
    plan["status"] = "rolled-back"
    plan["rollback"] = {
        "completed_at": utc_timestamp(),
        "container_id": snapshot.container_id,
        "restored_image_id": snapshot.image_id,
        "backup_sha256": hashlib.sha256(backup_path.read_bytes()).hexdigest(),
    }
    append_event(plan, "operator-rollback-confirmed")
    write_plan(plan_path, plan)
    return 0


def run(arguments: Sequence[str] | None = None) -> int:
    """Run dry-run, explicitly confirmed apply, or explicit rollback."""

    options = parse_arguments(arguments)
    catalog = load_messages(selected_locale())
    client = DockerClient(scout_timeout_seconds=options.scout_timeout_minutes * 60)
    try:
        if options.rollback:
            result = rollback_transaction(client, options.plan_output)
            if result == 0:
                print(
                    message(
                        catalog,
                        "composeRemediation.rollbackPassed",
                        path=options.plan_output,
                    )
                )
            return result
        policy = load_compose_policy(options.remediation_policy)
        target = select_compose_target(policy, options.compose_service)
        evidence = load_compose_evidence(options.report_file, options.compose_service)
        prepared = prepare_compose_remediation(client, target, evidence)
        prepared.plan["backup"]["source_file"] = str(backup_path(options.plan_output))
        write_plan(options.plan_output, prepared.plan)
        print(f"\n=== {message(catalog, 'composeRemediation.diffTitle')} ===")
        print(prepared.source_change.diff.rstrip())
        print(
            "\n"
            + message(
                catalog,
                "composeRemediation.dryRunPassed",
                path=options.plan_output,
            )
        )
        if not options.apply:
            print(message(catalog, "composeRemediation.noChange"))
            return 0
        post_check = lambda active_client, active_prepared, output: run_focused_post_check(
            active_client,
            active_prepared,
            output,
            host_os=options.os,
        )
        result = apply_prepared_remediation(
            client,
            prepared,
            options.plan_output,
            post_check=post_check,
        )
        if result == 0:
            print(
                message(
                    catalog,
                    "composeRemediation.updatePassed",
                    path=options.plan_output,
                )
            )
            print(
                message(
                    catalog,
                    "composeRemediation.rollbackAvailable",
                    path=options.plan_output,
                )
            )
        else:
            print(message(catalog, "composeRemediation.noUpdate"))
        return result
    except (ComposePolicyError, ComposeRemediationError, SourceEditError) as error:
        code = getattr(error, "code", type(error).__name__)
        detail = getattr(error, "detail", "")
        suffix = f": {detail}" if detail else ""
        print(
            message(
                catalog,
                "composeRemediation.error",
                code=code,
                detail=suffix,
            ),
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(run())
