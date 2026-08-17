"""Verify conservative defaults and inert installation review-queue behavior."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.operator_report import load_messages
from scripts.remediation_cli import _run_auto, run
from scripts.remediation_policy import build_plan, load_policy
from scripts.remediation_review import (
    ReviewAssessment,
    assess_review_queue,
    ensure_policy,
    policy_output_path,
    record_review_outcome,
    write_review,
)
from scripts.vulnerability_scan import CommandResult

from tests.test_remediation_advice import (
    AdviceClient,
    NEW_IMAGE,
    OLD_IMAGE,
)
from tests.test_remediation_policy import (
    deployment_map,
    policy_payload,
    vulnerability_report,
    write_policy,
)


def latest_report() -> dict[str, object]:
    """Return fresh shared-service evidence for a moved latest digest."""

    return {
        "completed_at": dt.datetime.now(dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "scope": {"image_fingerprint": "latest-scope"},
        "policy": {"platform": "linux/amd64"},
        "summary": {"status": "vulnerable", "complete": True},
        "images": [
            {
                "reference": OLD_IMAGE,
                "status": "vulnerable",
                "counts": {"critical": 2, "high": 4},
                "findings": [
                    {"id": "CVE-OLD-1", "severity": "critical"},
                    {"id": "CVE-OLD-2", "severity": "high"},
                ],
                "services": [
                    {"name": "demo_browser", "image": OLD_IMAGE},
                    {"name": "demo_worker", "image": OLD_IMAGE},
                ],
            }
        ],
    }


def latest_deployment_map(root: Path) -> dict[str, object]:
    """Return verified latest-following source evidence for both consumers."""

    stack_file = root / "swarm-stack.yml"
    stack_file.write_text("services: {}\n", encoding="utf-8")
    return {
        "generated_at": "2026-08-15T10:01:00Z",
        "renderer": {"available": True},
        "services": [
            {
                "name": service,
                "stack": "demo",
                "status": "mapped",
                "reason": "matched-stack-service-image",
                "image": OLD_IMAGE,
                "directory": str(root),
                "stack_file": str(stack_file),
                "compose_service": service.removeprefix("demo_"),
                "declared_image": "browserless/chrome:latest",
                "source_verified": True,
            }
            for service in ("demo_browser", "demo_worker")
        ],
    }


class SafeAutoClient(AdviceClient):
    """Add live-service update behavior to deterministic latest evidence."""

    def __init__(self) -> None:
        """Start the service at the exact vulnerable image."""

        super().__init__()
        self.live_image = OLD_IMAGE

    def run(self, arguments: list[str]) -> CommandResult:
        """Serve the additional Docker commands used by safe execution."""

        command = list(arguments)
        if command == ["context", "show"]:
            self.commands.append(command)
            return CommandResult(0, "production\n", "")
        if command[:2] == ["service", "ls"]:
            self.commands.append(command)
            service = command[command.index("--filter") + 1].split("=", 1)[1]
            return CommandResult(0, f"{service}\t1/1\n", "")
        if command[:2] == ["service", "inspect"] and "ContainerSpec.Image" in command[-1]:
            self.commands.append(command)
            return CommandResult(0, self.live_image + "\n", "")
        if command[:2] == ["service", "inspect"]:
            self.commands.append(command)
            return CommandResult(0, "completed\n", "")
        if command[:2] == ["service", "update"] and "--image" in command:
            self.commands.append(command)
            self.live_image = command[command.index("--image") + 1]
            return CommandResult(0, "updated\n", "")
        return super().run(arguments)


class RemediationReviewTests(unittest.TestCase):
    """Keep generated suggestions informative but incapable of authorization."""

    def test_user_config_path_is_used_outside_a_deployment_repository(self) -> None:
        """Avoid writing an unexplained configs directory in an arbitrary shell path."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = policy_output_path(
                None,
                environment={},
                current_directory=root / "shell",
                home_directory=root / "home",
            )

        self.assertEqual(
            path,
            root / "home" / ".config" / "swarm-info" / "remediation-policy.json",
        )

    def test_review_update_promotes_legacy_schema_and_preserves_targets(self) -> None:
        """Own only generated_review while retaining an operator's strict targets."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = write_policy(root, policy_payload())
            policy = load_policy(policy_path)
            plan = build_plan(
                vulnerability_report(),
                deployment_map(root, root / "swarm-stack.yml"),
                policy,
            )
            assessment = assess_review_queue(
                vulnerability_report(),
                deployment_map(root, root / "swarm-stack.yml"),
                policy,
                plan,
                AdviceClient(),
                "linux/amd64",
                False,
            )
            write_review(policy_path, assessment, {"en": ["help"], "de": ["hilfe"]})
            stored = json.loads(policy_path.read_text(encoding="utf-8"))
            reloaded = load_policy(policy_path)

        self.assertEqual(stored["schema_version"], 3)
        self.assertEqual(stored["targets"][0]["id"], "demo-api-update")
        self.assertIn("generated_review", stored)
        self.assertEqual(reloaded.targets[0].identifier, "demo-api-update")

    def test_moved_same_major_latest_is_the_only_built_in_action(self) -> None:
        """Reuse candidate validation while requiring verified latest source intent."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = root / "policy.json"
            ensure_policy(policy_path)
            policy = load_policy(policy_path)
            deployment = latest_deployment_map(root)
            plan = build_plan(latest_report(), deployment, policy)
            client = AdviceClient()
            assessment = assess_review_queue(
                latest_report(),
                deployment,
                policy,
                plan,
                client,
                "linux/amd64",
                False,
            )

        self.assertEqual(len(assessment.safe_actions), 2)
        self.assertEqual(
            assessment.safe_actions[0].candidate.reference,
            NEW_IMAGE,
        )
        self.assertTrue(
            all(
                entry["default_decision"] == "ready-with-confirmations"
                for entry in assessment.review["entries"]
            )
        )
        self.assertFalse(
            any(command[:2] == ["scout", "recommendations"] for command in client.commands)
        )

    def test_missing_policy_runs_safe_assessment_and_creates_review_queue(self) -> None:
        """Replace the old prerequisite error with a successful inert assessment."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = vulnerability_report()
            report["completed_at"] = (
                dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            )
            report["summary"] = {"status": "vulnerable", "complete": True}
            report["policy"] = {"platform": "linux/amd64"}
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            policy_path = root / "config" / "remediation-policy.json"
            plan_path = root / "plan.json"
            options = argparse.Namespace(
                report_file=report_path,
                deployment_map_file=None,
                deploy_roots=None,
                remediation_policy=policy_path,
                plan_output=plan_path,
                max_age_hours=30.0,
                history_days=14,
                lock_file=root / "scan.lock",
                mode="auto",
                force_auto_remedy_attempt=False,
                allow_runtime_override=False,
            )
            output = io.StringIO()
            with patch(
                "scripts.remediation_cli._load_deployment_map",
                return_value=deployment_map(root, root / "swarm-stack.yml"),
            ):
                result = run(
                    options,
                    load_messages("en"),
                    AdviceClient(),
                    input_function=lambda _: "",
                    output=output,
                )
            stored = json.loads(policy_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 2)
        self.assertEqual(stored["targets"], [])
        self.assertEqual(stored["generated_review"]["summary"]["entries"], 2)
        self.assertIn("evidence only", output.getvalue())

    def test_confirmed_safe_latest_action_executes_and_publishes_rescan(self) -> None:
        """Allow no-policy mutation only after both confirmations and rollback proof."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = latest_report()
            report["images"][0]["services"] = [
                {"name": "demo_browser", "image": OLD_IMAGE}
            ]
            deployment = latest_deployment_map(root)
            deployment["services"] = [deployment["services"][0]]
            policy_path = root / "policy.json"
            ensure_policy(policy_path)
            policy = load_policy(policy_path)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_path,
                deployment_map_file=None,
                deploy_roots=None,
                remediation_policy=policy_path,
                plan_output=root / "plan.json",
                max_age_hours=30.0,
                history_days=14,
                lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False,
                allow_runtime_override=False,
            )
            confirmation = {
                "completed_at": "2026-08-15T12:00:00Z",
                "summary": {
                    "status": "vulnerable",
                    "complete": True,
                    "critical": 1,
                    "high": 2,
                    "affected_service_count": 1,
                },
            }

            def publish_confirmation(*_: object, **__: object) -> int:
                """Publish deterministic fresh evidence for the final scan."""

                report_path.write_text(json.dumps(confirmation), encoding="utf-8")
                return 2

            client = SafeAutoClient()
            with patch(
                "scripts.remediation_cli.run_locked_job",
                side_effect=publish_confirmation,
            ):
                result = _run_auto(
                    report,
                    deployment,
                    policy,
                    options,
                    client,
                    load_messages("en"),
                    input_function=lambda _: "y",
                    output=io.StringIO(),
                )
            stored_policy = json.loads(policy_path.read_text(encoding="utf-8"))
            stored_plan = json.loads(options.plan_output.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(client.live_image, NEW_IMAGE)
        self.assertEqual(stored_plan["execution"][0]["status"], "deployed")
        self.assertEqual(
            stored_policy["generated_review"]["entries"][0]["last_attempt"]["outcome"],
            "deployed",
        )

    def test_attempt_outcome_updates_or_appends_a_review_entry(self) -> None:
        """Keep runtime failures available for later policy and default analysis."""

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            ensure_policy(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["generated_review"] = {
                "schema_version": 1,
                "entries": [],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            record_review_outcome(
                path,
                "demo_api",
                "failed",
                "candidate-scan-failed",
                "Scout\x00 failed\n after 30 seconds",
            )
            assessment = ReviewAssessment(
                review={
                    "schema_version": 1,
                    "summary": {"entries": 1},
                    "entries": [
                        {
                            "service": "demo_api",
                            "default_decision": "blocked",
                            "reasons": ["candidate-scan-failed"],
                        }
                    ],
                },
                safe_actions=(),
            )
            write_review(path, assessment, {"en": ["help"], "de": ["hilfe"]})
            stored = json.loads(path.read_text(encoding="utf-8"))

        attempt = stored["generated_review"]["entries"][0]["last_attempt"]
        self.assertEqual(attempt["outcome"], "failed")
        self.assertEqual(attempt["reason"], "candidate-scan-failed")
        self.assertEqual(attempt["detail"], "Scout failed after 30 seconds")


if __name__ == "__main__":
    unittest.main()
