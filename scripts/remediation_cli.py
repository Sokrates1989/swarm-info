"""Interactive guided and guarded vulnerability remediation for Swarm images."""

from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import shlex
import sys
from typing import Any, Callable, Mapping, Sequence, TextIO

from scripts.deployment_mapper import default_deploy_roots
from scripts.deployment_mapping import DeploymentRootError, build_deployment_map
from scripts.operator_report import (
    load_messages,
    message,
    read_mapping,
    safe_text,
    selected_locale,
    vulnerability_state,
)
from scripts.remediation_auto_support import prepare_review, run_safe_latest_actions
from scripts.remediation_guidance import run_targeted
from scripts.remediation_engine import (
    ActionResult,
    RemediationExecutionError,
    deploy_declarative_change,
    execute_latest_refresh,
    execute_runtime_override,
    render_stack,
    runtime_update_command,
    service_image_update_command,
    validate_candidate,
)
from scripts.remediation_policy import (
    PolicyTarget,
    RemediationPolicy,
    RemediationPolicyError,
    build_plan,
    load_policy,
    vulnerable_items,
)
from scripts.remediation_review import (
    ensure_policy,
    policy_output_path,
    record_review_outcome,
)
from scripts.remediation_source import (
    SourceEditError,
    prepare_source_change,
    write_source_change,
)
from scripts.vulnerability_job import (
    DEFAULT_HISTORY_DAYS,
    read_report,
    run_locked_job,
)
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import (
    DockerClient,
    InventoryError,
    collect_services,
)


DEFAULT_REPORT = Path("/info_json/vulnerability_scan.json")
DEFAULT_PLAN = Path("/info_json/vulnerability_remediation_plan.json")
SUPPORTED_MODES = ("menu", "service", "image", "guided", "auto")


def default_policy_path(environment: Mapping[str, str] | None = None) -> Path | None:
    """Find an explicit or current-installation remediation policy."""

    candidate = policy_output_path(None, environment=environment)
    return candidate if candidate.is_file() else None


def default_plan_path() -> Path:
    """Choose the shared report directory when writable, else local state."""

    if DEFAULT_PLAN.parent.is_dir() and os.access(DEFAULT_PLAN.parent, os.W_OK):
        return DEFAULT_PLAN
    return Path(__file__).resolve().parent.parent / "swarm_info" / DEFAULT_PLAN.name


def parse_arguments(
    arguments: Sequence[str] | None, catalog: Mapping[str, str]
) -> argparse.Namespace:
    """Parse internal remediation arguments with localized help text."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "remediation.description")
    )
    parser.add_argument("--report-file", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--deployment-map-file", type=Path)
    parser.add_argument("--deploy-root", action="append", type=Path, dest="deploy_roots")
    parser.add_argument("--remediation-policy", type=Path)
    parser.add_argument("--plan-output", type=Path)
    parser.add_argument("--max-age-hours", type=float, default=30.0)
    parser.add_argument("--history-days", type=int, default=DEFAULT_HISTORY_DAYS)
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--mode", choices=SUPPORTED_MODES, default="menu")
    parser.add_argument("--force-auto-remedy-attempt", action="store_true")
    parser.add_argument("--allow-runtime-override", action="store_true")
    return parser.parse_args(arguments)


def _read_required_mapping(path: Path, code: str) -> Mapping[str, Any]:
    """Read one required JSON object or raise a stable execution error."""

    payload = read_mapping(path)
    if payload is None:
        raise RemediationExecutionError(code, str(path))
    return payload


def _load_deployment_map(
    options: argparse.Namespace, client: DockerClient
) -> Mapping[str, Any]:
    """Load accepted mapping evidence or generate it from the current Swarm."""

    if options.deployment_map_file:
        return _read_required_mapping(options.deployment_map_file, "deployment-map-invalid")
    services = collect_services(client)
    return build_deployment_map(
        client, services, options.deploy_roots or default_deploy_roots()
    )


def _mapping_by_service(deployment_map: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Index deployment records by exact service name."""

    services = deployment_map.get("services")
    return {
        record["name"]: record
        for record in services or []
        if isinstance(record, Mapping) and isinstance(record.get("name"), str)
    }


def _localized_code(
    catalog: Mapping[str, str], prefix: str, code: object
) -> str:
    """Translate one stable domain code with a localized unknown fallback."""

    key = f"{prefix}.{safe_text(code)}"
    return catalog.get(key, catalog[f"{prefix}.unknown"])


def _ask(
    prompt: str,
    input_function: Callable[[str], str],
    default_yes: bool = False,
) -> bool:
    """Read one explicit yes/no answer with a documented default."""

    try:
        answer = input_function(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not answer:
        return default_yes
    return answer in {"y", "yes", "j", "ja"}


def _policy_targets(policy: RemediationPolicy) -> dict[str, PolicyTarget]:
    """Index validated policy entries by their unique identifier."""

    return {target.identifier: target for target in policy.targets}


def _render_plan(plan: Mapping[str, Any], catalog: Mapping[str, str], output: TextIO) -> None:
    """Render eligible and blocked entries before any candidate scan or edit."""

    summary = plan["summary"]
    print("", file=output)
    print(message(catalog, "remediation.planTitle", plan_id=plan["plan_id"]), file=output)
    print(
        message(
            catalog,
            "remediation.planSummary",
            eligible=summary["eligible"],
            blocked=summary["blocked"],
            declarative=summary["declarative"],
            runtime=summary["runtime_overrides"],
            latest=(
                summary.get("latest_refreshes", 0)
                + summary.get("default_safe_actions", 0)
            ),
        ),
        file=output,
    )
    for entry in plan["entries"]:
        if entry["eligible"]:
            status = message(catalog, "remediation.planEligible")
        else:
            status = message(
                catalog,
                "remediation.planBlocked",
                reasons=", ".join(
                    _localized_code(catalog, "remediation.reason", reason)
                    for reason in entry["blocked_reasons"]
                ),
            )
        action = _localized_code(catalog, "remediation.action", entry["action"])
        print(
            message(
                catalog,
                "remediation.planEntry",
                service=entry["service"],
                action=action,
                candidate=entry["candidate_image"],
                status=status,
            ),
            file=output,
        )
    for entry in plan.get("default_safe_actions", []):
        print(
            message(
                catalog,
                "remediation.planEntry",
                service=entry["service"],
                action=_localized_code(
                    catalog, "remediation.action", entry["action"]
                ),
                candidate=entry["candidate_image"],
                status=message(catalog, "remediation.planSafeReady"),
            ),
            file=output,
        )


def _record_result(
    plan: dict[str, Any], result: ActionResult, plan_output: Path
) -> None:
    """Atomically append one sanitized action result to the reviewed plan."""

    execution = plan.setdefault("execution", [])
    if not isinstance(execution, list):
        raise RemediationExecutionError("plan-execution-invalid")
    execution.append(result.to_dict())
    write_json_atomic(plan_output, plan)


def _run_auto(
    report: Mapping[str, Any],
    deployment_map: Mapping[str, Any],
    policy: RemediationPolicy,
    options: argparse.Namespace,
    client: DockerClient,
    catalog: Mapping[str, str],
    input_function: Callable[[str], str],
    output: TextIO,
    policy_created: bool = False,
) -> int:
    """Plan, validate, review, and optionally execute explicitly safe entries."""

    if options.deployment_map_file is not None:
        print(message(catalog, "remediation.refreshingMap"), file=output)
        deployment_map = build_deployment_map(
            client,
            collect_services(client),
            options.deploy_roots or default_deploy_roots(),
        )
    plan = build_plan(report, deployment_map, policy, options.force_auto_remedy_attempt)
    assessment = prepare_review(
        report,
        deployment_map,
        policy,
        plan,
        options,
        client,
        catalog,
        output,
        policy_created,
    )
    renderer = deployment_map.get("renderer")
    if plan["summary"]["declarative"] and (
        not isinstance(renderer, Mapping) or renderer.get("available") is not True
    ):
        raise RemediationExecutionError("compose-renderer-unavailable")
    plan_output = options.plan_output or default_plan_path()
    write_json_atomic(plan_output, plan)
    _render_plan(plan, catalog, output)
    print(message(catalog, "remediation.planSaved", path=plan_output), file=output)
    if (
        plan["summary"]["eligible"] == 0
        and plan["summary"]["default_safe_actions"] == 0
    ):
        return 2
    if not os.access(options.report_file.parent, os.W_OK):
        raise RemediationExecutionError(
            "confirmation-report-not-writable", str(options.report_file)
        )
    context = client.run(["context", "show"])
    if context.return_code != 0:
        raise RemediationExecutionError("docker-context-unavailable")
    context_name = context.stdout.strip()
    print(message(catalog, "remediation.context", context=context_name), file=output)
    targets = _policy_targets(policy)
    platform = safe_text((report.get("policy") or {}).get("platform", "linux/amd64"))
    deployed_count = run_safe_latest_actions(
        assessment,
        plan,
        plan_output,
        policy.path,
        platform,
        client,
        catalog,
        context_name,
        input_function,
        output,
    )
    for entry in plan["entries"]:
        if not entry["eligible"]:
            continue
        target = targets[entry["policy_id"]]
        print("", file=output)
        print(message(catalog, "remediation.validating", service=target.service), file=output)
        try:
            validation = validate_candidate(client, target, entry, platform)
        except RemediationExecutionError as error:
            record_review_outcome(
                policy.path,
                target.service,
                "failed",
                error.code,
                error.detail,
            )
            raise
        print(
            message(
                catalog,
                "remediation.candidateAccepted",
                critical=validation.critical,
                high=validation.high,
            ),
            file=output,
        )
        if entry["action"] == "runtime-override":
            command = shlex.join(["docker", *runtime_update_command(target)])
            print(message(catalog, "remediation.runtimeDrift"), file=output)
            print(f"  {command}", file=output)
            print(
                f"  {shlex.join(['docker', 'service', 'update', '--rollback', target.service])}",
                file=output,
            )
            if not options.allow_runtime_override:
                print(message(catalog, "remediation.runtimeDisabled"), file=output)
                continue
            if not _ask(
                message(
                    catalog,
                    "remediation.runtimeConfirm",
                    service=target.service,
                    context=context_name,
                ),
                input_function,
            ):
                print(message(catalog, "remediation.skipped"), file=output)
                continue
            try:
                result = execute_runtime_override(
                    client,
                    target,
                    entry,
                    post_validation=lambda: validate_candidate(
                        client, target, entry, platform
                    ),
                )
            except RemediationExecutionError as error:
                record_review_outcome(
                    policy.path,
                    target.service,
                    "failed",
                    error.code,
                    error.detail,
                )
                raise
            _record_result(plan, result, plan_output)
            record_review_outcome(policy.path, target.service, "deployed")
            deployed_count += 1
            print(message(catalog, "remediation.deployed", service=target.service), file=output)
            continue
        if entry["action"] == "latest-refresh":
            command = shlex.join(
                ["docker", *service_image_update_command(target.service, target.candidate)]
            )
            print(message(catalog, "remediation.policyLatestRefresh"), file=output)
            print(f"  {command}", file=output)
            print(
                f"  {shlex.join(['docker', 'service', 'update', '--rollback', target.service])}",
                file=output,
            )
            if not _ask(
                message(
                    catalog,
                    "remediation.policyLatestConfirm",
                    service=target.service,
                    context=context_name,
                ),
                input_function,
            ):
                print(message(catalog, "remediation.skipped"), file=output)
                continue
            try:
                result = execute_latest_refresh(
                    client,
                    target.service,
                    target.candidate,
                    str(entry["current_image"]),
                    target.timeout_seconds,
                    post_validation=lambda: validate_candidate(
                        client, target, entry, platform
                    ),
                )
            except RemediationExecutionError as error:
                record_review_outcome(
                    policy.path,
                    target.service,
                    "failed",
                    error.code,
                    error.detail,
                )
                raise
            _record_result(plan, result, plan_output)
            record_review_outcome(policy.path, target.service, "deployed")
            deployed_count += 1
            print(message(catalog, "remediation.deployed", service=target.service), file=output)
            continue
        try:
            change = prepare_source_change(target, entry)
            mapping = entry["mapping"]
            old_rendered = render_stack(client, Path(mapping["stack_file"]))
        except (RemediationExecutionError, SourceEditError) as error:
            record_review_outcome(
                policy.path,
                target.service,
                "failed",
                error.code,
                error.detail,
            )
            raise
        print(message(catalog, "remediation.reviewDiff"), file=output)
        print(change.diff, file=output, end="" if change.diff.endswith("\n") else "\n")
        if not _ask(
            message(catalog, "remediation.applyConfirm", path=change.path),
            input_function,
        ):
            print(message(catalog, "remediation.skipped"), file=output)
            continue
        write_source_change(change)
        if not _ask(
            message(
                catalog,
                "remediation.deployConfirm",
                stack=mapping["stack"],
                context=context_name,
                service=target.service,
            ),
            input_function,
            default_yes=True,
        ):
            result = ActionResult(
                "source-updated-not-deployed",
                target.service,
                target.candidate.reference,
                source_file=str(change.path),
                detail="operator declined deployment",
            )
            _record_result(plan, result, plan_output)
            print(
                message(
                    catalog,
                    "remediation.manualDeploy",
                    directory=mapping["directory"],
                    stack_file=mapping["stack_file"],
                    stack=mapping["stack"],
                ),
                file=output,
            )
            continue
        try:
            result = deploy_declarative_change(
                client,
                target,
                entry,
                change,
                old_rendered,
                post_validation=lambda: validate_candidate(
                    client, target, entry, platform
                ),
            )
        except RemediationExecutionError as error:
            record_review_outcome(
                policy.path,
                target.service,
                "failed",
                error.code,
                error.detail,
            )
            raise
        _record_result(plan, result, plan_output)
        record_review_outcome(policy.path, target.service, "deployed")
        deployed_count += 1
        print(message(catalog, "remediation.deployed", service=target.service), file=output)
    if deployed_count:
        print(message(catalog, "remediation.fullRescanStarting"), file=output)
        confirmation_code = run_locked_job(
            options.report_file,
            platform,
            options.max_age_hours,
            options.history_days,
            True,
            lock_file=options.lock_file,
            client=client,
        )
        confirmation = read_report(options.report_file)
        if confirmation is None:
            raise RemediationExecutionError("full-confirmation-report-missing")
        if confirmation.get("completed_at") == report.get("completed_at"):
            raise RemediationExecutionError("full-confirmation-scan-not-refreshed")
        plan["confirmation"] = {
            "report_file": str(options.report_file),
            "completed_at": confirmation.get("completed_at"),
            "status": (confirmation.get("summary") or {}).get("status"),
            "complete": (confirmation.get("summary") or {}).get("complete"),
        }
        write_json_atomic(plan_output, plan)
        if confirmation_code == 3:
            raise RemediationExecutionError("full-confirmation-scan-incomplete")
        summary = confirmation.get("summary") or {}
        print(
            message(
                catalog,
                "remediation.fullRescanComplete",
                critical=summary.get("critical", 0),
                high=summary.get("high", 0),
                services=summary.get("affected_service_count", 0),
            ),
            file=output,
        )
    else:
        print(message(catalog, "remediation.rescan"), file=output)
    return 0


def run(
    options: argparse.Namespace,
    catalog: Mapping[str, str],
    client: DockerClient,
    input_function: Callable[[str], str] = input,
    output: TextIO = sys.stdout,
) -> int:
    """Run one interactive remediation mode against fresh evidence."""

    report = _read_required_mapping(options.report_file, "report-invalid")
    state, _ = vulnerability_state(
        report, dt.datetime.now(dt.timezone.utc), options.max_age_hours
    )
    if state != "vulnerable":
        print(
            message(
                catalog,
                "remediation.reportNotActionable",
                state=_localized_code(catalog, "remediation.state", state),
            ),
            file=output,
        )
        return 3 if state not in {"clean"} else 0
    print(message(catalog, "remediation.mapping"), file=output)
    deployment_map = _load_deployment_map(options, client)
    items = vulnerable_items(report)
    mappings = _mapping_by_service(deployment_map)
    mode = options.mode
    if mode == "menu":
        print(message(catalog, "remediation.menuTitle"), file=output)
        print(f"1) {message(catalog, 'remediation.menuService')}", file=output)
        print(f"2) {message(catalog, 'remediation.menuImage')}", file=output)
        print(f"3) {message(catalog, 'remediation.menuGuided')}", file=output)
        print(f"4) {message(catalog, 'remediation.menuAuto')}", file=output)
        print(f"q) {message(catalog, 'remediation.cancel')}", file=output)
        selected = input_function(message(catalog, "remediation.selectPrompt")).strip().lower()
        mode = {"1": "service", "2": "image", "3": "guided", "4": "auto"}.get(selected, "cancel")
    if mode == "cancel":
        return 0
    policy_path = options.remediation_policy or default_policy_path()
    policy = (
        load_policy(policy_path)
        if policy_path is not None and policy_path.is_file()
        else None
    )
    if mode in {"service", "image", "guided"}:
        if options.remediation_policy is not None and policy is None:
            policy = load_policy(options.remediation_policy)
        platform = safe_text(
            (report.get("policy") or {}).get("platform", "linux/amd64")
        )
        run_targeted(
            mode,
            items,
            mappings,
            catalog,
            input_function,
            output,
            client=client,
            platform=platform,
            policy=policy,
        )
        return 0
    policy_created = False
    if policy is None:
        print(message(catalog, "remediation.policyMissing"), file=output)
        policy_path = policy_output_path(options.remediation_policy)
        policy_created = ensure_policy(policy_path)
        policy = load_policy(policy_path)
    return _run_auto(
        report,
        deployment_map,
        policy,
        options,
        client,
        catalog,
        input_function,
        output,
        policy_created,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Load localized configuration and execute the remediation workflow."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, catalog)
    if not sys.stdin.isatty():
        print(message(catalog, "remediation.ttyRequired"), file=sys.stderr)
        return 3
    try:
        return run(options, catalog, DockerClient())
    except (
        DeploymentRootError,
        InventoryError,
        OSError,
        RemediationExecutionError,
        RemediationPolicyError,
        SourceEditError,
    ) as error:
        code = getattr(error, "code", type(error).__name__)
        detail = getattr(error, "detail", "")
        print(
            message(
                catalog,
                "remediation.error",
                code=safe_text(code),
                detail=safe_text(detail),
            ),
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
