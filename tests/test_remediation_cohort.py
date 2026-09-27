"""Verify bulk policy staging keeps unproved workloads outside option 4."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import dataclasses
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts.remediation_cohort import prepare_cohort
from scripts.remediation_cohort_cli import _backup_policy, run
from scripts.remediation_engine import RemediationExecutionError
from scripts.remediation_policy import SourceEdit, build_plan, load_policy
from scripts.vulnerability_models import ServiceRecord
from scripts.vulnerability_models import utc_timestamp
from tests.test_remediation_policy import (
    NEW_IMAGE,
    OLD_IMAGE,
    deployment_map,
    policy_payload,
    vulnerability_report,
)


class ReplicaClient:
    """Return bounded Swarm replica evidence without a real Docker daemon."""

    def __init__(self, counts: str = "demo_api|1/1\ndemo_worker|1/1\n") -> None:
        """Store the fake service listing for one planner invocation."""

        self.counts = counts

    def run(self, arguments: list[str]) -> SimpleNamespace:
        """Support only the Docker service listing used by cohort planning."""

        if arguments[:2] != ["service", "ls"]:
            raise AssertionError(arguments)
        return SimpleNamespace(return_code=0, stdout=self.counts, stderr="")


def assessment() -> dict[str, object]:
    """Return individually verified candidates for two live image consumers."""

    return {
        "schema_version": 1,
        "complete": False,
        "policy": {"resource_type": "service"},
        "services": [
            {
                "service": name,
                "status": "verified-clean",
                "current_reference": OLD_IMAGE,
                "best_candidate": NEW_IMAGE,
                "deployable_fixable": {"critical": 2, "high": 4},
            }
            for name in ("demo_api", "demo_worker")
        ],
    }


def report() -> dict[str, object]:
    """Add the complete status required by the cohort's current report gate."""

    payload = vulnerability_report()
    payload["summary"] = {"complete": True, "status": "vulnerable"}
    return payload


def live_services() -> list[ServiceRecord]:
    """Return exact current images for both fake Swarm services."""

    return [
        ServiceRecord(name, name, OLD_IMAGE, "demo")
        for name in ("demo_api", "demo_worker")
    ]


class CohortPolicyTests(unittest.TestCase):
    """Keep bulk staging exact, explicit, and idempotent."""

    def test_stages_mapped_target_and_explicit_runtime_fallback(self) -> None:
        """One partial assessment may stage only individually verified rows."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mapping = deployment_map(root, root / "swarm-stack.yml")

            def source_for_api(client, target, mapped, current):
                """Provide one already-render-verified source in this isolated test."""

                if target.service == "demo_api":
                    return dataclasses.replace(
                        target, source=SourceEdit("yaml_image", "swarm-stack.yml")
                    )
                return None

            with patch(
                "scripts.remediation_cohort._declarative_target",
                side_effect=source_for_api,
            ):
                cohort = prepare_cohort(
                    assessment(), report(), mapping, live_services(),
                    {"schema_version": 3, "targets": []},
                    "Operator accepts pre-alpha data loss.", ReplicaClient(),
                    include_runtime_overrides=True,
                )

        self.assertEqual(len(cohort.targets), 2)
        self.assertEqual(
            [decision.action for decision in cohort.decisions],
            ["declarative", "runtime-override"],
        )
        self.assertTrue(all(target["auto_eligible"] for target in cohort.targets))
        self.assertEqual(cohort.targets[0]["candidate_image"], NEW_IMAGE)
        self.assertEqual(cohort.targets[0]["source"]["file"], "swarm-stack.yml")
        self.assertNotIn("source", cohort.targets[1])

    def test_unmapped_source_needs_separate_runtime_opt_in(self) -> None:
        """Never silently convert an ambiguous mapping to runtime mutation."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("scripts.remediation_cohort._declarative_target", return_value=None):
                cohort = prepare_cohort(
                    assessment(), report(), deployment_map(root, root / "stack.yml"),
                    live_services(), {"schema_version": 3, "targets": []},
                    "Operator accepts pre-alpha data loss.", ReplicaClient(),
                )

        self.assertEqual(cohort.targets, ())
        self.assertEqual(
            [decision.reason for decision in cohort.decisions],
            ["source-not-proven", "source-not-proven"],
        )

    def test_unsupported_mapped_source_cannot_fall_back_to_runtime(self) -> None:
        """A verified declarative owner must not acquire an override by accident."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mapping = deployment_map(root, root / "stack.yml")
            mapping["services"][0]["source_verified"] = True
            with patch("scripts.remediation_cohort._declarative_target", return_value=None):
                cohort = prepare_cohort(
                    assessment(), report(), mapping, live_services(),
                    {"schema_version": 3, "targets": []},
                    "Operator accepts pre-alpha data loss.", ReplicaClient(),
                    include_runtime_overrides=True,
                )

        self.assertEqual([item["match"]["service"] for item in cohort.targets], ["demo_worker"])
        self.assertEqual(cohort.decisions[0].reason, "source-not-proven")
        self.assertEqual(cohort.decisions[1].action, "runtime-override")

    def test_stale_image_nonconverged_and_existing_rules_are_skipped(self) -> None:
        """An assessment alone never overrides live drift or an existing rule."""

        stale = assessment()
        stale["services"][0]["current_reference"] = NEW_IMAGE
        existing = {"schema_version": 3, "targets": policy_payload()["targets"]}
        cohort = prepare_cohort(
            stale, report(), {"services": []}, live_services(), existing,
            "Operator accepts pre-alpha data loss.",
            ReplicaClient("demo_api|1/1\ndemo_worker|0/1\n"),
            include_runtime_overrides=True,
        )

        self.assertEqual(cohort.targets, ())
        self.assertEqual(
            [decision.reason for decision in cohort.decisions],
            ["existing-policy-target", "service-not-converged"],
        )

    def test_invalid_candidate_never_enters_policy(self) -> None:
        """Reject a non-digest candidate even after a fabricated verified status."""

        evidence = assessment()
        evidence["services"][0]["best_candidate"] = "registry.example/team/app:1.1.0"
        cohort = prepare_cohort(
            evidence, report(), {"services": []}, live_services(),
            {"schema_version": 3, "targets": []},
            "Operator accepts pre-alpha data loss.", ReplicaClient(),
            include_runtime_overrides=True,
        )

        self.assertEqual(cohort.decisions[0].reason, "candidate-invalid")
        self.assertEqual(len(cohort.targets), 1)

    def test_progress_reports_each_reviewed_service(self) -> None:
        """Show regular progress while source proofs render a larger cohort."""

        events: list[tuple[int, int, str]] = []
        prepare_cohort(
            assessment(), report(), {"services": []}, live_services(),
            {"schema_version": 3, "targets": []},
            "Operator accepts pre-alpha data loss.", ReplicaClient(),
            include_runtime_overrides=True,
            progress=lambda index, total, name: events.append((index, total, name)),
        )
        self.assertEqual(
            events, [(1, 2, "demo_api"), (2, 2, "demo_worker")]
        )

    def test_partial_assessment_names_uncovered_vulnerable_service(self) -> None:
        """A missing assessment row is visible rather than silently forgotten."""

        current = report()
        current["images"][0]["services"].append(
            {"name": "demo_unassessed", "stack": "demo"}
        )
        cohort = prepare_cohort(
            assessment(), current, {"services": []}, live_services(),
            {"schema_version": 3, "targets": []},
            "Operator accepts pre-alpha data loss.", ReplicaClient(),
            include_runtime_overrides=True,
        )
        self.assertEqual(cohort.decisions[-1].service, "demo_unassessed")
        self.assertEqual(cohort.decisions[-1].reason, "assessment-missing")

    def test_one_ineligible_plan_entry_does_not_abort_other_services(self) -> None:
        """A single option-4 blocker must leave independently eligible rows usable."""

        def plan_with_one_blocker(report, mapping, policy):
            """Inject one planner rejection while retaining the real plan contract."""

            plan = build_plan(report, mapping, policy)
            if policy.targets[0].service == "demo_api":
                plan["entries"][0]["eligible"] = False
                plan["entries"][0]["blocked_reasons"] = ["test-blocker"]
            return plan

        with patch(
            "scripts.remediation_cohort.build_plan", side_effect=plan_with_one_blocker
        ):
            cohort = prepare_cohort(
                assessment(), report(), {"services": []}, live_services(),
                {"schema_version": 3, "targets": []},
                "Operator accepts pre-alpha data loss.", ReplicaClient(),
                include_runtime_overrides=True,
            )

        self.assertEqual([target["match"]["service"] for target in cohort.targets], ["demo_worker"])
        self.assertEqual(cohort.decisions[0].reason, "plan-not-eligible")
        self.assertEqual(cohort.decisions[1].status, "staged")

    def test_apply_needs_explicit_loss_acceptance(self) -> None:
        """Fail before Docker or file access when an apply lacks risk consent."""

        options = argparse.Namespace(apply=True, accept_data_loss=False)
        with self.assertRaises(RemediationExecutionError) as context:
            run(options)
        self.assertEqual(context.exception.code, "cohort-risk-acceptance-required")

    def test_private_backup_preserves_exact_prior_policy(self) -> None:
        """Keep a mode-private recovery copy before replacing host rules."""

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "remediation-policy.json"
            original = {"schema_version": 3, "targets": []}
            path.write_text(json.dumps(original), encoding="utf-8")
            backup = _backup_policy(path)
            self.assertIsNotNone(backup)
            self.assertEqual(backup.read_bytes(), path.read_bytes())
            self.assertEqual(load_policy(backup).targets, ())

    def test_dry_run_then_apply_preserves_host_policy_and_writes_exact_rules(self) -> None:
        """Only an explicit apply mutates the policy, retaining a recovery copy."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = root / "remediation-policy.json"
            original = {"schema_version": 3, "targets": []}
            policy_path.write_text(json.dumps(original), encoding="utf-8")
            report_path = root / "vulnerability_scan.json"
            current = report()
            current["completed_at"] = utc_timestamp()
            report_path.write_text(json.dumps(current), encoding="utf-8")
            assessment_path = root / "image_update_assessment.json"
            assessment_path.write_text(json.dumps(assessment()), encoding="utf-8")
            options = argparse.Namespace(
                apply=False,
                accept_data_loss=False,
                assessment_file=assessment_path,
                report_file=report_path,
                remediation_policy=policy_path,
                deploy_root=[root],
                plan_output=root / "cohort_plan.json",
                backup_reason="Operator accepts pre-alpha data loss.",
                allow_runtime_override=True,
                max_age_hours=30.0,
                timeout_seconds=300,
                stability_seconds=0,
            )
            with (
                patch("scripts.remediation_cohort_cli.DockerClient", return_value=ReplicaClient()),
                patch("scripts.remediation_cohort_cli._active_manager", return_value="default"),
                patch("scripts.remediation_cohort_cli.collect_services", return_value=live_services()),
                patch("scripts.remediation_cohort_cli.build_deployment_map", return_value={"services": []}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(run(options), 0)
                self.assertEqual(json.loads(policy_path.read_text()), original)
                options.apply = True
                options.accept_data_loss = True
                self.assertEqual(run(options), 0)

            policy = load_policy(policy_path)
            backups = list(root.glob("remediation-policy.json.before-cohort-*"))
            self.assertEqual(len(policy.targets), 2)
            self.assertTrue(all(target.auto_eligible for target in policy.targets))
            self.assertEqual(len(backups), 1)
            self.assertEqual(json.loads(backups[0].read_text()), original)
            self.assertEqual(
                len(json.loads(options.plan_output.read_text())["targets"]), 2
            )


if __name__ == "__main__":
    unittest.main()
