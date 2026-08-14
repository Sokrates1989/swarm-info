"""Verify candidate comparison, rollback, and interactive guidance contracts."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.remediation_cli import _run_auto, run
from scripts.remediation_engine import (
    RemediationExecutionError,
    deploy_declarative_change,
    execute_runtime_override,
    runtime_update_command,
    validate_candidate,
)
from scripts.remediation_guidance import _images
from scripts.remediation_policy import build_plan, load_policy, vulnerable_items
from scripts.remediation_source import SourceChange
from scripts.operator_report import load_messages
from scripts.vulnerability_scan import CommandResult

from tests.test_remediation_policy import (
    NEW_DIGEST,
    NEW_IMAGE,
    OLD_DIGEST,
    OLD_IMAGE,
    deployment_map,
    policy_payload,
    vulnerability_report,
    write_policy,
)


def sarif(findings: list[tuple[str, str]]) -> str:
    """Build minimal Scout-compatible SARIF for deterministic candidate scans."""

    rules = []
    results = []
    for identifier, severity in findings:
        rules.append(
            {
                "id": identifier,
                "shortDescription": {"text": identifier},
                "properties": {"tags": [severity]},
            }
        )
        results.append(
            {
                "ruleId": identifier,
                "level": "error",
                "message": {"text": identifier},
            }
        )
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"rules": rules}}, "results": results}],
        }
    )


class ScoutClient:
    """Return one configured local Scout result."""

    def __init__(self, findings: list[tuple[str, str]]) -> None:
        """Store normalized candidate findings and invoked commands."""

        self.findings = findings
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Respond to the immutable local Scout command only."""

        self.commands.append(list(arguments))
        return CommandResult(2 if self.findings else 0, sarif(self.findings), "")


class RollbackClient:
    """Model a deploy followed by a post-validation rollback."""

    def __init__(self, old_image: str, candidate: str) -> None:
        """Start with the old live image and record deployed temp content."""

        self.image = old_image
        self.candidate = candidate
        self.deployments: list[str] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Serve the command subset used by declarative deployment."""

        command = list(arguments)
        if command[:2] == ["service", "inspect"] and "TaskTemplate" in command[-1]:
            return CommandResult(0, self.image + "\n", "")
        if command[:2] == ["service", "inspect"]:
            return CommandResult(0, "completed\n", "")
        if command[:2] == ["service", "ls"]:
            return CommandResult(0, "demo_api\t1/1\n", "")
        if command[:2] == ["compose", "--env-file"]:
            return CommandResult(0, f"services:\n  api:\n    image: {self.candidate}\n", "")
        if command[:2] == ["stack", "deploy"]:
            rendered = Path(command[command.index("-c") + 1]).read_text(encoding="utf-8")
            self.deployments.append(rendered)
            self.image = self.candidate if self.candidate in rendered else OLD_IMAGE
            return CommandResult(0, "deployed", "")
        return CommandResult(1, "", "unexpected")


class AutoRuntimeClient:
    """Model one accepted runtime override and immediate convergence."""

    def __init__(self) -> None:
        """Start on the old image and retain every requested Docker command."""

        self.image = OLD_IMAGE
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Serve context, Scout, inspection, and update commands."""

        command = list(arguments)
        self.commands.append(command)
        if command == ["context", "show"]:
            return CommandResult(0, "production\n", "")
        if command[:2] == ["scout", "cves"]:
            return CommandResult(0, sarif([]), "")
        if command[:2] == ["service", "ls"]:
            return CommandResult(0, "demo_worker\t1/1\n", "")
        if command[:2] == ["service", "inspect"] and "ContainerSpec.Image" in command[-1]:
            return CommandResult(0, self.image + "\n", "")
        if command[:2] == ["service", "inspect"]:
            return CommandResult(0, "completed\n", "")
        if command == ["service", "update", "--rollback", "demo_worker"]:
            self.image = OLD_IMAGE
            return CommandResult(0, "rolled back\n", "")
        if command[:2] == ["service", "update"] and "--image" in command:
            self.image = command[command.index("--image") + 1]
            return CommandResult(0, "updated\n", "")
        return CommandResult(1, "", "unexpected command")


class RemediationEngineTests(unittest.TestCase):
    """Require candidate improvement and confirmed rollback on later failure."""

    def _target_and_entry(self, root: Path) -> tuple[object, dict[str, object]]:
        """Create one valid declarative policy target and its plan entry."""

        stack_file = root / "swarm-stack.yml"
        stack_file.write_text("services: {}\n", encoding="utf-8")
        policy = load_policy(
            write_policy(
                root,
                policy_payload(
                    source={
                        "type": "dotenv",
                        "file": ".env",
                        "name_key": "IMAGE_NAME",
                        "version_key": "IMAGE_VERSION",
                    }
                ),
            )
        )
        entry = build_plan(
            vulnerability_report(), deployment_map(root, stack_file), policy
        )["entries"][0]
        return policy.targets[0], entry

    def test_clean_candidate_is_accepted_as_an_improvement(self) -> None:
        """Require exact immutable scanning before any edit is prepared."""

        with tempfile.TemporaryDirectory() as temporary:
            target, entry = self._target_and_entry(Path(temporary))
            client = ScoutClient([])
            validation = validate_candidate(
                client, target, entry, "linux/amd64", sleeper=lambda _: None
            )

        self.assertEqual(validation.status, "clean")
        self.assertEqual(validation.critical, 0)
        self.assertIn(f"local://{NEW_IMAGE}", client.commands[0])

    def test_candidate_with_new_finding_is_rejected(self) -> None:
        """Block a lower-count candidate that introduces a different CVE."""

        with tempfile.TemporaryDirectory() as temporary:
            target, entry = self._target_and_entry(Path(temporary))
            with self.assertRaises(RemediationExecutionError) as context:
                validate_candidate(
                    ScoutClient([("CVE-NEW", "high")]),
                    target,
                    entry,
                    "linux/amd64",
                    sleeper=lambda _: None,
                )

        self.assertEqual(context.exception.code, "candidate-new-findings")

    def test_post_validation_failure_restores_source_and_old_stack(self) -> None:
        """Rollback both declarative source and deployed image after regression."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / ".env"
            original = b"IMAGE_VERSION=1.0.0\n"
            replacement = b"IMAGE_VERSION=1.1.0\n"
            environment.write_bytes(replacement)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        source={
                            "type": "dotenv",
                            "file": ".env",
                            "name_key": "IMAGE_NAME",
                            "version_key": "IMAGE_VERSION",
                        }
                    ),
                )
            )
            entry = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )["entries"][0]
            change = SourceChange(environment, original, replacement, "diff", 0o600)
            client = RollbackClient(OLD_IMAGE, NEW_IMAGE)

            with self.assertRaises(RemediationExecutionError):
                deploy_declarative_change(
                    client,
                    policy.targets[0],
                    entry,
                    change,
                    f"services:\n  api:\n    image: {OLD_IMAGE}\n".encode(),
                    sleeper=lambda _: None,
                    post_validation=lambda: (_ for _ in ()).throw(
                        RemediationExecutionError("post-scan-regression")
                    ),
                )

            self.assertEqual(environment.read_bytes(), original)
            self.assertEqual(client.image, OLD_IMAGE)
            self.assertEqual(len(client.deployments), 2)

    def test_runtime_command_is_digest_pinned_and_has_registry_auth(self) -> None:
        """Keep the unknown-path fallback explicit and rollback-compatible."""

        with tempfile.TemporaryDirectory() as temporary:
            target, _ = self._target_and_entry(Path(temporary))
            command = runtime_update_command(target)

        self.assertIn("--with-registry-auth", command)
        self.assertIn(NEW_DIGEST, " ".join(command))
        self.assertEqual(command[-1], "demo_api")

    def test_runtime_interrupt_restores_exact_previous_image(self) -> None:
        """Rollback a confirmed runtime update when the operator interrupts it."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(
                write_policy(root, policy_payload(service="demo_worker"))
            )
            entry = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )["entries"][0]
            client = AutoRuntimeClient()

            with self.assertRaises(RemediationExecutionError) as context:
                execute_runtime_override(
                    client,
                    policy.targets[0],
                    entry,
                    sleeper=lambda _: None,
                    post_validation=lambda: (_ for _ in ()).throw(
                        KeyboardInterrupt()
                    ),
                )

        self.assertEqual(context.exception.code, "runtime-verification-failed")
        self.assertIn("KeyboardInterrupt", context.exception.detail)
        self.assertEqual(client.image, OLD_IMAGE)


class RemediationCliTests(unittest.TestCase):
    """Expose every affected service and shared-image count in guided mode."""

    def test_image_mode_groups_service_aliases_by_scanned_image(self) -> None:
        """Offer one image choice for one deduplicated report image."""

        report = vulnerability_report()
        report["images"][0]["services"][0]["image"] = OLD_IMAGE
        report["images"][0]["services"][1]["image"] = (
            f"registry.example/team/app:stable@{OLD_DIGEST}"
        )
        grouped = _images(vulnerable_items(report))

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["image"], OLD_IMAGE)
        self.assertEqual(grouped[0]["shared_service_count"], 2)

    def test_service_mode_lists_every_consumer_and_mapping_guidance(self) -> None:
        """Select one of the shared-image services without Docker mutation."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = vulnerability_report()
            now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            report["completed_at"] = now
            report["summary"] = {"status": "vulnerable", "complete": True}
            report["policy"] = {"platform": "linux/amd64"}
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            map_path = root / "map.json"
            map_path.write_text(
                json.dumps(deployment_map(root, stack_file)), encoding="utf-8"
            )
            options = argparse.Namespace(
                report_file=report_path,
                deployment_map_file=map_path,
                deploy_roots=None,
                remediation_policy=None,
                plan_output=None,
                max_age_hours=30.0,
                mode="service",
                force_auto_remedy_attempt=False,
                allow_runtime_override=False,
            )
            answers = iter(["1", ""])
            output = io.StringIO()
            result = run(
                options,
                load_messages("en"),
                ScoutClient([]),
                input_function=lambda _: next(answers),
                output=output,
            )

        rendered = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("demo_api", rendered)
        self.assertIn("demo_worker", rendered)
        self.assertIn("shared by 2 service", rendered)
        self.assertIn(str(stack_file), rendered)
        self.assertNotIn(
            "docker service update --with-registry-auth --image " + NEW_IMAGE,
            rendered,
        )

    def test_auto_runtime_override_publishes_full_confirmation_report(self) -> None:
        """Replace stale evidence atomically after a confirmed automatic action."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            mapping = deployment_map(root, stack_file)
            mapping["renderer"] = {"available": False}
            policy = load_policy(
                write_policy(root, policy_payload(service="demo_worker"))
            )
            report_file = root / "vulnerability_scan.json"
            plan_file = root / "remediation_plan.json"
            options = argparse.Namespace(
                report_file=report_file,
                deployment_map_file=None,
                deploy_roots=None,
                plan_output=plan_file,
                max_age_hours=30.0,
                history_days=14,
                lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False,
                allow_runtime_override=True,
            )
            confirmation = {
                "completed_at": "2026-08-14T11:00:00Z",
                "summary": {
                    "status": "vulnerable",
                    "complete": True,
                    "critical": 1,
                    "high": 2,
                    "affected_service_count": 1,
                },
            }
            output = io.StringIO()
            client = AutoRuntimeClient()

            def publish_confirmation(*_: object, **__: object) -> int:
                """Model the locked job's atomic report publication."""

                report_file.write_text(json.dumps(confirmation), encoding="utf-8")
                return 2

            with patch(
                "scripts.remediation_cli.run_locked_job",
                side_effect=publish_confirmation,
            ) as full_scan:
                result = _run_auto(
                    vulnerability_report(),
                    mapping,
                    policy,
                    options,
                    client,
                    load_messages("en"),
                    input_function=lambda _: "y",
                    output=output,
                )

            published_report = json.loads(report_file.read_text(encoding="utf-8"))
            published_plan = json.loads(plan_file.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(published_report, confirmation)
        self.assertEqual(published_plan["confirmation"]["status"], "vulnerable")
        self.assertEqual(published_plan["execution"][0]["status"], "deployed")
        self.assertEqual(client.image, NEW_IMAGE)
        full_scan.assert_called_once_with(
            report_file,
            "linux/amd64",
            30.0,
            14,
            True,
            lock_file=root / "scan.lock",
            client=client,
        )
        self.assertIn("All-image confirmation scan is starting", output.getvalue())


if __name__ == "__main__":
    unittest.main()
