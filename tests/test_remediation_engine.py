"""Verify candidate comparison, rollback, and interactive guidance contracts."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.remediation_cli import _run_auto, run
from scripts.remediation_engine import (
    RemediationExecutionError,
    ServiceSnapshot,
    capture_service,
    deploy_declarative_change,
    execute_latest_refresh,
    execute_runtime_override,
    preview_yaml_image_change,
    render_stack,
    service_image_update_command,
    runtime_update_command,
    validate_candidate,
    wait_for_candidate,
    wait_for_original_image,
    verify_rendered_service_topology,
)
from scripts.remediation_progress import run_visible_action
from scripts.remediation_guidance import _images
from scripts.remediation_policy import (
    build_plan,
    load_policy,
    parse_candidate_image,
    vulnerable_items,
)
from scripts.remediation_source import SourceChange
from scripts.operator_report import load_messages
from scripts.vulnerability_scan import CommandResult, DockerClient

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
        if command[:2] == ["service", "inspect"] and "Spec.Mode" in command[-1]:
            return CommandResult(0, '{"Replicated":{"Replicas":1}}\n', "")
        if command[:2] == ["service", "inspect"]:
            return CommandResult(0, "completed\n", "")
        if command[:2] == ["service", "ls"]:
            return CommandResult(0, "demo_api\t1/1\n", "")
        if command[:2] == ["compose", "--env-file"]:
            if command[-1] == "json":
                return CommandResult(
                    0, json.dumps({"services": {"api": {"image": self.candidate}}}), ""
                )
            return CommandResult(0, f"services:\n  api:\n    image: {self.candidate}\n", "")
        if command[:2] == ["stack", "deploy"]:
            rendered = Path(command[command.index("-c") + 1]).read_text(encoding="utf-8")
            self.deployments.append(rendered)
            self.image = self.candidate if self.candidate in rendered else OLD_IMAGE
            return CommandResult(0, "deployed", "")
        return CommandResult(1, "", "unexpected")


class FailedStackDeployClient(RollbackClient):
    """Reject a stack deployment before the live service image changes."""

    def run(self, arguments: list[str]) -> CommandResult:
        """Return a parser failure for deployment and delegate other commands."""

        if arguments[:2] == ["stack", "deploy"]:
            return CommandResult(1, "", "(root) Additional property name is not allowed")
        return super().run(arguments)


class ComposeModelClient:
    """Render a deterministic Compose model without exposing its secret values."""

    def __init__(
        self, other_change_on_candidate: bool = False,
        stack_config_error: bool = False,
    ) -> None:
        """Optionally model rendered drift or a rejected Swarm stack."""

        self.other_change_on_candidate = other_change_on_candidate
        self.stack_config_error = stack_config_error
        self.deployments = 0

    def run(self, arguments: list[str]) -> CommandResult:
        """Serve Compose rendering and the pre-deployment service snapshot."""

        command = list(arguments)
        if command[:1] == ["compose"] and "-f" in command:
            stack_file = Path(command[command.index("-f") + 1])
            contents = stack_file.read_text(encoding="utf-8")
            if command[-1] == "json":
                new_image = NEW_IMAGE in contents
                model = {
                    "services": {
                        "api": {
                            "image": NEW_IMAGE if new_image else OLD_IMAGE.split("@")[0],
                            "environment": {"PASSWORD": "never-print-me"},
                        },
                        "worker": {
                            "image": (
                                "redis:8-alpine"
                                if new_image and self.other_change_on_candidate
                                else "redis:7-alpine"
                            )
                        },
                    }
                }
                return CommandResult(0, json.dumps(model), "")
            return CommandResult(0, contents, "")
        if command[:2] == ["service", "ls"]:
            return CommandResult(0, "demo_api\t1/1\n", "")
        if command[:2] == ["service", "inspect"]:
            return CommandResult(0, OLD_IMAGE + "\n", "")
        if command[:2] == ["stack", "config"]:
            return CommandResult(
                1 if self.stack_config_error else 0,
                "",
                "invalid rendered stack" if self.stack_config_error else "",
            )
        if command[:2] == ["stack", "deploy"]:
            self.deployments += 1
            return CommandResult(0, "deployed", "")
        return CommandResult(1, "", "unexpected command")


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
        if command[:2] == ["service", "inspect"] and "Spec.Mode" in command[-1]:
            return CommandResult(0, '{"Replicated":{"Replicas":1}}\n', "")
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

    def test_visible_action_reports_immediate_and_periodic_progress(self) -> None:
        """Do not leave a blocking deploy silent after operator confirmation."""

        for locale in ("en", "de"):
            with self.subTest(locale=locale):
                output = io.StringIO()

                def complete_with_heartbeat(operation, progress, _message, _interval):
                    """Emit one deterministic heartbeat without sleeping."""

                    progress("internal scanner formatting must remain hidden")
                    return operation()

                with patch(
                    "scripts.remediation_progress.run_with_progress_heartbeat",
                    side_effect=complete_with_heartbeat,
                ):
                    result = run_visible_action(
                        lambda: "complete", "demo_api", load_messages(locale), output
                    )

                self.assertEqual(result, "complete")
                self.assertEqual(output.getvalue().count("demo_api"), 2)
                self.assertNotIn("internal scanner formatting", output.getvalue())

    def test_capture_requires_fully_running_service(self) -> None:
        """Do not mark a scaled-zero or already-down workload remediated."""

        class UnavailableClient(AutoRuntimeClient):
            """Return one unavailable replica state from Docker service ls."""

            def __init__(self, replicas: str) -> None:
                super().__init__()
                self.replicas = replicas

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    return CommandResult(0, f"demo_worker\t{self.replicas}\n", "")
                return super().run(arguments)

        for replicas in ("0/0", "0/1", "1/2"):
            with self.subTest(replicas=replicas):
                with self.assertRaises(RemediationExecutionError) as context:
                    capture_service(UnavailableClient(replicas), "demo_worker")
                self.assertEqual(context.exception.code, "service-not-converged")

    def test_capture_records_global_mode(self) -> None:
        """Recognize a converged global service before starting an image action."""

        class GlobalClient(AutoRuntimeClient):
            """Provide Docker's global-mode inspection response."""

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "inspect"] and "Spec.Mode" in arguments[-1]:
                    return CommandResult(0, '{"Global":{}}\n', "")
                return super().run(arguments)

        snapshot = capture_service(GlobalClient(), "demo_worker")
        self.assertEqual(snapshot.mode, "global")
        self.assertEqual((snapshot.running, snapshot.desired), (1, 1))

    def test_candidate_must_remain_converged_for_stability_window(self) -> None:
        """Reset the healthy timer when replicas briefly disappear."""

        class SequencedClient:
            """Model a new image whose replicas flap and later stabilize."""

            def __init__(self) -> None:
                self.states = ("1/1", "0/1", "1/1", "1/1", "1/1", "1/1")
                self.index = 0

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    state = self.states[min(self.index, len(self.states) - 1)]
                    self.index += 1
                    return CommandResult(0, f"demo_api\t{state}\n", "")
                if arguments[:2] == ["service", "inspect"]:
                    if "Spec.Mode" in arguments[-1]:
                        return CommandResult(0, '{"Replicated":{"Replicas":1}}\n', "")
                    value = NEW_IMAGE if "ContainerSpec.Image" in arguments[-1] else "completed"
                    return CommandResult(0, value + "\n", "")
                return CommandResult(1, "", "unexpected command")

        elapsed = [0.0]

        def advance(seconds: float) -> None:
            """Move a deterministic test clock by one polling interval."""

            elapsed[0] += seconds

        client = SequencedClient()
        wait_for_candidate(
            client,
            ServiceSnapshot("demo_api", OLD_IMAGE, 1, 1),
            parse_candidate_image(NEW_IMAGE),
            20,
            sleeper=advance,
            stability_seconds=5,
            clock=lambda: elapsed[0],
        )

        self.assertEqual(elapsed[0], 10.0)
        self.assertEqual(client.index, 6)

    def test_candidate_stability_timeout_is_not_a_success(self) -> None:
        """A repeating task failure must trigger the caller's rollback path."""

        class FlappingClient:
            """Alternate one ready sample with one missing replica."""

            def __init__(self) -> None:
                self.index = 0

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    replicas = "1/1" if self.index % 2 == 0 else "0/1"
                    self.index += 1
                    return CommandResult(0, f"demo_api\t{replicas}\n", "")
                if arguments[:2] == ["service", "inspect"]:
                    if "Spec.Mode" in arguments[-1]:
                        return CommandResult(0, '{"Replicated":{"Replicas":1}}\n', "")
                    value = NEW_IMAGE if "ContainerSpec.Image" in arguments[-1] else "completed"
                    return CommandResult(0, value + "\n", "")
                return CommandResult(1, "", "unexpected command")

        elapsed = [0.0]

        def advance(seconds: float) -> None:
            """Advance past the timeout without a real wait."""

            elapsed[0] += seconds

        with self.assertRaises(RemediationExecutionError) as context:
            wait_for_candidate(
                FlappingClient(),
                ServiceSnapshot("demo_api", OLD_IMAGE, 1, 1),
                parse_candidate_image(NEW_IMAGE),
                8,
                sleeper=advance,
                stability_seconds=4,
                clock=lambda: elapsed[0],
            )

        self.assertEqual(context.exception.code, "service-convergence-timeout")

    def test_global_rollout_tolerates_temporary_scheduler_target_change(self) -> None:
        """Global desired task counts may briefly fall to zero during replacement."""

        class GlobalRolloutClient:
            """Expose the observed Traefik-like 1/0 state before convergence."""

            def __init__(self) -> None:
                self.states = ("1/0", "0/1", "1/1", "1/1")
                self.index = 0

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    state = self.states[min(self.index, len(self.states) - 1)]
                    self.index += 1
                    return CommandResult(0, f"traefik_traefik\t{state}\n", "")
                if "Spec.Mode" in arguments[-1]:
                    return CommandResult(0, '{"Global":{}}\n', "")
                if "ContainerSpec.Image" in arguments[-1]:
                    return CommandResult(0, NEW_IMAGE + "\n", "")
                return CommandResult(0, "completed\n", "")

        elapsed = [0.0]

        def advance(seconds: float) -> None:
            """Advance the polling clock without sleeping."""

            elapsed[0] += seconds

        client = GlobalRolloutClient()
        wait_for_candidate(
            client,
            ServiceSnapshot("traefik_traefik", OLD_IMAGE, 1, 1, "global"),
            parse_candidate_image(NEW_IMAGE),
            12,
            sleeper=advance,
            stability_seconds=2,
            clock=lambda: elapsed[0],
        )

        self.assertEqual(client.index, 4)

    def test_replicated_rollout_rejects_changed_replica_target(self) -> None:
        """Keep the fixed-target guard for ordinary replicated services."""

        class ChangedTargetClient:
            """Return one undesired scale-to-zero event."""

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    return CommandResult(0, "demo_api\t1/0\n", "")
                if "Spec.Mode" in arguments[-1]:
                    return CommandResult(0, '{"Replicated":{"Replicas":0}}\n', "")
                if "ContainerSpec.Image" in arguments[-1]:
                    return CommandResult(0, NEW_IMAGE + "\n", "")
                return CommandResult(0, "completed\n", "")

        with self.assertRaises(RemediationExecutionError) as context:
            wait_for_candidate(
                ChangedTargetClient(),
                ServiceSnapshot("demo_api", OLD_IMAGE, 1, 1),
                parse_candidate_image(NEW_IMAGE),
                10,
            )

        self.assertEqual(context.exception.code, "service-replica-target-changed")

    def test_rollback_does_not_accept_zero_global_availability(self) -> None:
        """Restoring an image at 0/0 is not a confirmed rollback of a 1/1 service."""

        class UnavailableGlobalClient:
            """Report the original image but no desired or running task."""

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:2] == ["service", "ls"]:
                    return CommandResult(0, "traefik_traefik\t0/0\n", "")
                if "Spec.Mode" in arguments[-1]:
                    return CommandResult(0, '{"Global":{}}\n', "")
                return CommandResult(0, OLD_IMAGE + "\n", "")

        with patch("scripts.remediation_engine.time.monotonic", side_effect=[0, 0, 2]):
            with self.assertRaises(RemediationExecutionError) as context:
                wait_for_original_image(
                    UnavailableGlobalClient(),
                    ServiceSnapshot("traefik_traefik", OLD_IMAGE, 1, 1, "global"),
                    1,
                    sleeper=lambda _: None,
                )

        self.assertEqual(context.exception.code, "rollback-convergence-timeout")

    def test_rendered_source_must_match_live_service_topology(self) -> None:
        """Do not reconcile stale source scaling or mode in an image-only deploy."""

        global_snapshot = ServiceSnapshot("traefik_traefik", OLD_IMAGE, 1, 1, "global")
        verify_rendered_service_topology(
            {"services": {"traefik": {"deploy": {"mode": "global"}}}},
            "traefik", global_snapshot,
        )

        with self.assertRaises(RemediationExecutionError) as context:
            verify_rendered_service_topology(
                {"services": {"traefik": {"deploy": {"replicas": 1}}}},
                "traefik", global_snapshot,
            )
        self.assertEqual(context.exception.code, "source-service-mode-drift")

        with self.assertRaises(RemediationExecutionError) as context:
            verify_rendered_service_topology(
                {"services": {"api": {"deploy": {"replicas": 0}}}},
                "api", ServiceSnapshot("demo_api", OLD_IMAGE, 1, 1),
            )
        self.assertEqual(context.exception.code, "source-service-replica-drift")

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

    def test_stability_failure_restores_source_and_old_stack(self) -> None:
        """A service that never stays available must not keep the new source."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / ".env"
            original = b"IMAGE_VERSION=1.0.0\n"
            replacement = b"IMAGE_VERSION=1.1.0\n"
            environment.write_bytes(replacement)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            payload = policy_payload(
                source={
                    "type": "dotenv", "file": ".env",
                    "name_key": "IMAGE_NAME", "version_key": "IMAGE_VERSION",
                }
            )
            payload["targets"][0]["verification"] = {
                "timeout_seconds": 60, "stability_seconds": 10,
            }
            policy = load_policy(write_policy(root, payload))
            entry = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )["entries"][0]
            change = SourceChange(environment, original, replacement, "diff", 0o600)
            client = RollbackClient(OLD_IMAGE, NEW_IMAGE)

            with patch(
                "scripts.remediation_engine.wait_for_candidate",
                side_effect=RemediationExecutionError("service-convergence-timeout"),
            ) as wait:
                with self.assertRaises(RemediationExecutionError) as context:
                    deploy_declarative_change(
                        client, policy.targets[0], entry, change,
                        f"services:\n  api:\n    image: {OLD_IMAGE}\n".encode(),
                        sleeper=lambda _: None,
                    )

            self.assertEqual(environment.read_bytes(), original)
            self.assertEqual(client.image, OLD_IMAGE)
            self.assertEqual(len(client.deployments), 2)

        self.assertEqual(context.exception.code, "declarative-deploy-failed")
        self.assertIn("service-convergence-timeout", context.exception.detail)
        self.assertEqual(wait.call_args.kwargs["stability_seconds"], 10)

    def test_rejected_stack_deploy_restores_source(self) -> None:
        """Keep an unsuccessful parser attempt from leaving a source-only update."""

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
            client = FailedStackDeployClient(OLD_IMAGE, NEW_IMAGE)

            with self.assertRaises(RemediationExecutionError) as context:
                deploy_declarative_change(
                    client,
                    policy.targets[0],
                    entry,
                    change,
                    b"services: {}\n",
                )

            self.assertEqual(context.exception.code, "declarative-deploy-failed")
            self.assertEqual(environment.read_bytes(), original)
            self.assertEqual(client.image, OLD_IMAGE)

    def test_source_replica_drift_restores_edit_without_deploying(self) -> None:
        """Reject stale declarative scaling before any live stack mutation."""

        class DriftedSourceClient(RollbackClient):
            """Render a zero-replica source while the live target remains 1/1."""

            def run(self, arguments: list[str]) -> CommandResult:
                if arguments[:1] == ["compose"] and arguments[-1] == "json":
                    return CommandResult(
                        0,
                        json.dumps({
                            "services": {
                                "api": {
                                    "image": NEW_IMAGE,
                                    "deploy": {"replicas": 0},
                                }
                            }
                        }),
                        "",
                    )
                return super().run(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / ".env"
            original = b"IMAGE_VERSION=1.0.0\n"
            replacement = b"IMAGE_VERSION=1.1.0\n"
            environment.write_bytes(replacement)
            target, entry = self._target_and_entry(root)
            change = SourceChange(environment, original, replacement, "diff", 0o600)
            client = DriftedSourceClient(OLD_IMAGE, NEW_IMAGE)

            with self.assertRaises(RemediationExecutionError) as context:
                deploy_declarative_change(
                    client, target, entry, change,
                    f"services:\n  api:\n    image: {OLD_IMAGE}\n".encode(),
                )

            self.assertEqual(environment.read_bytes(), original)
            self.assertEqual(client.deployments, [])

        self.assertEqual(context.exception.code, "declarative-deploy-failed")
        self.assertIn("source-service-replica-drift", context.exception.detail)

    def test_yaml_preview_allows_only_target_image_render_change(self) -> None:
        """Validate a proposal privately and remove its temporary source."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            original = b"services:\n  api:\n    image: registry.example/team/app:1.0.0\n"
            replacement = original.replace(
                b"registry.example/team/app:1.0.0", NEW_IMAGE.encode("utf-8")
            )
            stack_file.write_bytes(original)
            change = SourceChange(stack_file, original, replacement, "diff", 0o600)
            model = preview_yaml_image_change(
                ComposeModelClient(), change, stack_file, "api", OLD_IMAGE,
                parse_candidate_image(NEW_IMAGE),
            )

            self.assertEqual(model["services"]["api"]["image"], OLD_IMAGE.split("@")[0])
            self.assertEqual(stack_file.read_bytes(), original)
            self.assertEqual(list(root.glob(".swarm-info-remediation-preview.*")), [])

    def test_yaml_preview_with_real_compose_ignores_unrelated_advanced_yaml(self) -> None:
        """Exercise the source guard against Compose's actual rendered model."""

        if shutil.which("docker") is None:
            self.skipTest("Docker Compose is unavailable")
        version = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, check=False, text=True, timeout=10,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose is unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            original = (
                "services:\n"
                "  api:\n"
                "    image: registry.example/team/app:1.0.0\n"
                "  worker:\n"
                "    image: ${WORKER_IMAGE:-redis:7-alpine}\n"
                "    environment:\n"
                "      SHARED: &worker_value example\n"
                "      ALIAS: *worker_value\n"
            ).encode("utf-8")
            replacement = original.replace(
                b"registry.example/team/app:1.0.0", NEW_IMAGE.encode("utf-8")
            )
            stack_file.write_bytes(original)
            change = SourceChange(stack_file, original, replacement, "diff", 0o600)
            model = preview_yaml_image_change(
                DockerClient(), change, stack_file, "api", OLD_IMAGE,
                parse_candidate_image(NEW_IMAGE),
            )

            self.assertEqual(model["services"]["api"]["image"], OLD_IMAGE.split("@")[0])
            self.assertEqual(model["services"]["worker"]["image"], "redis:7-alpine")
            self.assertEqual(stack_file.read_bytes(), original)
            self.assertEqual(list(root.glob(".swarm-info-remediation-preview.*")), [])

    def test_yaml_preview_rejects_invalid_swarm_stack_before_source_edit(self) -> None:
        """A Compose-valid but Swarm-invalid stack cannot enter deployment review."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            original = b"services:\n  api:\n    image: registry.example/team/app:1.0.0\n"
            replacement = original.replace(
                b"registry.example/team/app:1.0.0", NEW_IMAGE.encode("utf-8")
            )
            stack_file.write_bytes(original)
            change = SourceChange(stack_file, original, replacement, "diff", 0o600)
            client = ComposeModelClient(stack_config_error=True)

            with self.assertRaises(RemediationExecutionError) as context:
                preview_yaml_image_change(
                    client, change, stack_file, "api", OLD_IMAGE,
                    parse_candidate_image(NEW_IMAGE),
                )

            self.assertEqual(context.exception.code, "stack-config-invalid")
            self.assertEqual(stack_file.read_bytes(), original)
            self.assertEqual(client.deployments, 0)
            self.assertEqual(list(root.glob(".swarm-info-remediation-*")), [])

    def test_rendered_compose_stack_is_accepted_by_swarm_parser(self) -> None:
        """Remove Compose-only project identity from transient deployment YAML."""

        if shutil.which("docker") is None:
            self.skipTest("Docker Compose is unavailable")
        version = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, check=False, text=True, timeout=10,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose is unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text(
                "services:\n"
                "  redis:\n"
                "    image: redis:7-alpine\n"
                "    ports:\n"
                "      - target: 6379\n"
                "        published: 16379\n"
                "        mode: host\n",
                encoding="utf-8",
            )
            rendered = render_stack(DockerClient(), stack_file)
            deployment_file = root / "rendered-stack.yml"
            deployment_file.write_bytes(rendered)
            result = subprocess.run(
                ["docker", "stack", "config", "-c", str(deployment_file)],
                capture_output=True, check=False, text=True, timeout=10,
            )

            self.assertFalse(rendered.startswith(b"name:"))
            self.assertIn(b"published: 16379", rendered)
            self.assertNotIn(b'published: "16379"', rendered)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("redis:7-alpine", result.stdout)

    def test_render_stack_changes_only_decimal_service_published_ports(self) -> None:
        """Keep other quoted values and nondecimal port expressions untouched."""

        class PublishedPortClient:
            """Supply Compose-normalized YAML without a Docker daemon."""

            def run(self, arguments: list[str]) -> CommandResult:
                """Return one rendered stack for the YAML request."""

                return CommandResult(
                    0,
                    "name: example\n"
                    "services:\n"
                    "  proxy:\n"
                    "    environment:\n"
                    '      PUBLISHED: "80"\n'
                    "    ports:\n"
                    "      - mode: host\n"
                    '        published: "80"\n'
                    "        target: 80\n"
                    "  app:\n"
                    "    ports:\n"
                    "      - mode: ingress\n"
                    '        published: "8000-8002"\n'
                    "        target: 8000\n",
                    "",
                )

        rendered = render_stack(PublishedPortClient(), Path("stack.yml"))

        self.assertIn(b"        published: 80\n", rendered)
        self.assertIn(b'      PUBLISHED: "80"\n', rendered)
        self.assertIn(b'        published: "8000-8002"\n', rendered)
        self.assertNotIn(b"name: example", rendered)

    def test_render_stack_rejects_ambiguous_project_name(self) -> None:
        """Fail closed rather than silently dropping multiple root keys."""

        class AmbiguousComposeClient:
            """Return an invalid rendered model without invoking Docker."""

            def run(self, arguments: list[str]) -> CommandResult:
                """Supply duplicate Compose project names for the guard."""

                return CommandResult(
                    0, "name: first\nname: second\nservices: {}\n", ""
                )

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(RemediationExecutionError) as context:
                render_stack(
                    AmbiguousComposeClient(), Path(temporary) / "swarm-stack.yml"
                )

        self.assertEqual(context.exception.code, "stack-render-project-name-invalid")

    def test_yaml_preview_rejects_other_rendered_change_without_leaking_secrets(self) -> None:
        """Block unrelated stack changes before the actual source is edited."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            original = b"services:\n  api:\n    image: registry.example/team/app:1.0.0\n"
            replacement = original.replace(
                b"registry.example/team/app:1.0.0", NEW_IMAGE.encode("utf-8")
            )
            stack_file.write_bytes(original)
            change = SourceChange(stack_file, original, replacement, "diff", 0o600)
            with self.assertRaises(RemediationExecutionError) as context:
                preview_yaml_image_change(
                    ComposeModelClient(other_change_on_candidate=True),
                    change, stack_file, "api", OLD_IMAGE,
                    parse_candidate_image(NEW_IMAGE),
                )

            self.assertEqual(context.exception.code, "rendered-stack-other-change")
            self.assertNotIn("never-print-me", context.exception.detail)
            self.assertEqual(stack_file.read_bytes(), original)
            self.assertEqual(list(root.glob(".swarm-info-remediation-preview.*")), [])

    def test_yaml_actual_render_drift_restores_source_before_deployment(self) -> None:
        """Recheck the rendered model after the confirmed source write."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            original = b"services:\n  api:\n    image: registry.example/team/app:1.0.0\n"
            replacement = original.replace(
                b"registry.example/team/app:1.0.0", NEW_IMAGE.encode("utf-8")
            )
            stack_file.write_bytes(replacement)
            change = SourceChange(stack_file, original, replacement, "diff", 0o600)
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        source={"type": "yaml_image", "file": "swarm-stack.yml"}
                    ),
                )
            )
            entry = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )["entries"][0]
            client = ComposeModelClient(other_change_on_candidate=True)
            old_model = {
                "services": {
                    "api": {
                        "image": OLD_IMAGE.split("@")[0],
                        "environment": {"PASSWORD": "never-print-me"},
                    },
                    "worker": {"image": "redis:7-alpine"},
                }
            }

            with self.assertRaises(RemediationExecutionError) as context:
                deploy_declarative_change(
                    client, policy.targets[0], entry, change, original,
                    expected_rendered_model=old_model,
                )

            self.assertEqual(context.exception.code, "declarative-deploy-failed")
            self.assertEqual(stack_file.read_bytes(), original)
            self.assertEqual(client.deployments, 0)

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

    def test_latest_refresh_uses_exact_candidate_without_configuration_drift(self) -> None:
        """Keep verified latest source intent while updating only one live service."""

        with tempfile.TemporaryDirectory() as temporary:
            target, _ = self._target_and_entry(Path(temporary))
            client = AutoRuntimeClient()
            result = execute_latest_refresh(
                client,
                "demo_worker",
                target.candidate,
                OLD_IMAGE,
                30,
                sleeper=lambda _: None,
            )

        self.assertEqual(result.status, "deployed")
        self.assertFalse(result.config_drift)
        self.assertEqual(client.image, NEW_IMAGE)
        self.assertEqual(
            service_image_update_command("demo_worker", target.candidate)[-1],
            "demo_worker",
        )

    def test_latest_stability_failure_requests_and_confirms_rollback(self) -> None:
        """Restore the prior image when the opt-in stability check fails."""

        client = AutoRuntimeClient()
        with patch(
            "scripts.remediation_engine.wait_for_candidate",
            side_effect=RemediationExecutionError("service-convergence-timeout"),
        ) as wait:
            with self.assertRaises(RemediationExecutionError) as context:
                execute_latest_refresh(
                    client, "demo_worker", parse_candidate_image(NEW_IMAGE),
                    OLD_IMAGE, 60, sleeper=lambda _: None, stability_seconds=10,
                )

        self.assertEqual(context.exception.code, "runtime-verification-failed")
        self.assertIn("rollback confirmed", context.exception.detail)
        self.assertEqual(client.image, OLD_IMAGE)
        self.assertEqual(wait.call_args.kwargs["stability_seconds"], 10)


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
        self.assertIn(
            "Remediation task for demo_worker is running", output.getvalue()
        )


if __name__ == "__main__":
    unittest.main()
