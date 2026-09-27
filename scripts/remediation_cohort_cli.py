"""Stage a reviewed best-effort fleet cohort in the host-owned policy.

The command edits no stack and deploys no service. It requires an explicit
operator loss disposition before writing exact targets for the existing
interactive option-4 engine.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping, Sequence

from scripts.deployment_mapper import default_deploy_roots
from scripts.deployment_mapping import DeploymentRootError, build_deployment_map
from scripts.operator_report import (
    load_messages,
    message,
    safe_text,
    selected_locale,
    vulnerability_state,
)
from scripts.remediation_cohort import Cohort, prepare_cohort
from scripts.remediation_engine import RemediationExecutionError
from scripts.remediation_policy import RemediationPolicyError, load_policy
from scripts.vulnerability_models import utc_timestamp, write_json_atomic
from scripts.vulnerability_scan import DockerClient, InventoryError, collect_services


DEFAULT_ASSESSMENT = Path("/info_json/image_update_assessment.json")
DEFAULT_REPORT = Path("/info_json/vulnerability_scan.json")
DEFAULT_PLAN = Path("/info_json/remediation_cohort_plan.json")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse an explicit, opt-in host-policy preparation command."""

    catalog = load_messages(selected_locale())
    parser = argparse.ArgumentParser(description=message(catalog, "cohort.description"))
    parser.add_argument("--assessment-file", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--report-file", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--remediation-policy", type=Path, required=True)
    parser.add_argument("--deploy-root", action="append", type=Path)
    parser.add_argument("--plan-output", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--backup-reason", required=True)
    parser.add_argument("--accept-data-loss", action="store_true")
    parser.add_argument("--allow-runtime-override", action="store_true")
    parser.add_argument("--max-age-hours", type=float, default=30.0)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--stability-seconds", type=int, default=0)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(arguments)


def _read_object(path: Path, code: str) -> dict[str, Any]:
    """Load one required report without trusting arbitrary JSON structures."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RemediationExecutionError(code, str(path)) from error
    if not isinstance(payload, dict):
        raise RemediationExecutionError(code, str(path))
    return payload


def _active_manager(client: DockerClient) -> str:
    """Require one active manager context and return its visible name."""

    context = client.run(["context", "show"])
    state = client.run(
        ["info", "--format", "{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}"]
    )
    if context.return_code != 0 or state.return_code != 0 or state.stdout.strip() != "active|true":
        raise RemediationExecutionError("cohort-manager-required")
    return context.stdout.strip()


def _policy_payload(path: Path) -> dict[str, Any]:
    """Preserve an existing strict policy or start an empty host-owned one."""

    if not path.exists():
        return {"schema_version": 3, "targets": []}
    load_policy(path)
    return _read_object(path, "cohort-policy-unreadable")


def _validate_payload(payload: Mapping[str, Any]) -> None:
    """Run the existing strict policy parser before touching the live file."""

    with tempfile.TemporaryDirectory(prefix="swarm-info-cohort-") as directory:
        temporary = Path(directory) / "remediation-policy.json"
        write_json_atomic(temporary, payload)
        load_policy(temporary)


def _backup_policy(path: Path) -> Path | None:
    """Save exact original policy bytes with private permissions before apply."""

    if not path.is_file():
        return None
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.before-cohort-{stamp}")
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(path.read_bytes())
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def _present(cohort: Cohort, catalog: Mapping[str, str]) -> None:
    """Show every decision, without environment values or mount sources."""

    print(message(catalog, "cohort.title"))
    print("-" * 70)
    for decision in cohort.decisions:
        if decision.status == "staged":
            print(
                message(
                    catalog,
                    "cohort.staged",
                    service=decision.service,
                    action=decision.action,
                    critical=decision.critical_removed,
                    high=decision.high_removed,
                )
            )
            print(f"  {decision.candidate_image}")
        else:
            reason_key = f"cohort.reason.{decision.reason}"
            print(
                message(
                    catalog,
                    "cohort.skipped",
                    service=decision.service,
                    reason=catalog.get(reason_key, decision.reason),
                )
            )
    print(
        message(
            catalog,
            "cohort.summary",
            staged=len(cohort.targets),
            skipped=sum(item.status == "skipped" for item in cohort.decisions),
        )
    )


def run(options: argparse.Namespace) -> int:
    """Build a bounded cohort and optionally persist exact host-local rules."""

    catalog = load_messages(selected_locale())
    if options.apply and not options.accept_data_loss:
        raise RemediationExecutionError("cohort-risk-acceptance-required")
    if (
        not 30 <= options.timeout_seconds <= 1800
        or not 0 <= options.stability_seconds < options.timeout_seconds
        or options.stability_seconds > 600
    ):
        raise RemediationExecutionError("cohort-verification-invalid")
    selected_paths = (
        options.assessment_file,
        options.report_file,
        options.remediation_policy,
        options.plan_output,
    )
    if any(not path.expanduser().is_absolute() for path in selected_paths):
        raise RemediationExecutionError("cohort-absolute-path-required")
    if options.remediation_policy.expanduser().is_symlink():
        raise RemediationExecutionError("cohort-policy-symlink")
    client = DockerClient()
    context = _active_manager(client)
    report = _read_object(options.report_file, "cohort-report-unreadable")
    state, _ = vulnerability_state(
        report, dt.datetime.now(dt.timezone.utc), options.max_age_hours
    )
    if state != "vulnerable":
        raise RemediationExecutionError("cohort-report-not-actionable", state)
    assessment = _read_object(options.assessment_file, "cohort-assessment-unreadable")
    policy_path = options.remediation_policy.expanduser().absolute()
    existing = _policy_payload(policy_path)
    services = collect_services(client)
    mapping = build_deployment_map(
        client, services, options.deploy_root or default_deploy_roots()
    )
    cohort = prepare_cohort(
        assessment,
        report,
        mapping,
        services,
        existing,
        options.backup_reason,
        client,
        include_runtime_overrides=options.allow_runtime_override,
        timeout_seconds=options.timeout_seconds,
        stability_seconds=options.stability_seconds,
        progress=lambda index, total, service: print(
            message(
                catalog,
                "cohort.progress",
                index=index,
                total=total,
                service=service,
            ),
            flush=True,
        ),
    )
    payload = dict(existing)
    payload["schema_version"] = 3
    payload["targets"] = [*existing.get("targets", []), *cohort.targets]
    _validate_payload(payload)
    plan = {
        "schema_version": 1,
        "generated_at": utc_timestamp(),
        "docker_context": context,
        "assessment_file": str(options.assessment_file),
        "assessment_complete": assessment.get("complete") is True,
        "report_file": str(options.report_file),
        "policy_file": str(policy_path),
        "apply_requested": bool(options.apply),
        "runtime_override_requested": bool(options.allow_runtime_override),
        "targets": list(cohort.targets),
        "decisions": [dataclasses.asdict(item) for item in cohort.decisions],
    }
    write_json_atomic(options.plan_output, plan)
    _present(cohort, catalog)
    print(message(catalog, "cohort.plan", path=options.plan_output))
    if not options.apply:
        print(message(catalog, "cohort.dryRun"))
        return 0
    if not cohort.targets:
        print(message(catalog, "cohort.none"))
        return 0
    policy_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = _backup_policy(policy_path)
    write_json_atomic(policy_path, payload)
    if backup is not None:
        print(message(catalog, "cohort.backup", path=backup))
    print(message(catalog, "cohort.applied", count=len(cohort.targets), path=policy_path))
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    """Translate cohort preparation failures into bounded CLI diagnostics."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    options = parse_arguments(arguments)
    try:
        return run(options)
    except (
        DeploymentRootError,
        InventoryError,
        OSError,
        RemediationExecutionError,
        RemediationPolicyError,
        TypeError,
        ValueError,
    ) as error:
        catalog = load_messages(selected_locale())
        code = safe_text(getattr(error, "code", type(error).__name__))
        detail = safe_text(getattr(error, "detail", ""))
        print(message(catalog, "remediation.error", code=code, detail=detail), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
