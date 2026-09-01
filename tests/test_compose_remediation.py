"""Validate SCWP-03C Compose planning, confirmation, and rollback."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.compose_remediation_cli import (
    apply_prepared_remediation,
    rollback_transaction,
)
from scripts.compose_remediation_engine import (
    ComposeRemediationError,
)
from scripts.compose_remediation_plan import (
    load_compose_evidence,
    prepare_compose_remediation,
)
from scripts.compose_remediation_policy import (
    ComposePolicyError,
    load_compose_policy,
    select_compose_target,
)
from scripts.compose_remediation_verification import run_focused_post_check
from scripts.vulnerability_scan import CommandResult

from tests.test_remediation_engine import sarif


OLD_DIGEST = "sha256:" + "1" * 64
NEW_DIGEST = "sha256:" + "2" * 64
OLD_LOCAL_ID = "sha256:" + "a" * 64
NEW_LOCAL_ID = "sha256:" + "b" * 64
OLD_IMAGE = f"registry.example/demo/app:1.0.0@{OLD_DIGEST}"
NEW_IMAGE = f"registry.example/demo/app:1.1.0@{NEW_DIGEST}"


def policy_payload(source_file: str = "compose.yml") -> dict[str, object]:
    """Return one exact standalone Compose remediation target."""

    return {
        "schema_version": 1,
        "targets": [
            {
                "id": "fixture-web-update",
                "match": {
                    "compose_service": "scwp03c/web",
                    "repository": "registry.example/demo/app",
                },
                "candidate_image": NEW_IMAGE,
                "backup": {
                    "status": "not_required",
                    "reason": "Disposable stateless acceptance fixture.",
                },
                "source": {"type": "yaml_image", "file": source_file},
                "verification": {"timeout_seconds": 30},
            }
        ],
    }


def focused_report(root: Path, config_files: list[Path]) -> dict[str, object]:
    """Return complete focused evidence for one digest-pinned container."""

    return {
        "schema_version": 2,
        "completed_at": "2026-09-01T10:00:00Z",
        "policy": {"platform": "linux/amd64"},
        "scope": {
            "resource_type": "container",
            "resource_count": 1,
            "coverage": "focused",
            "selector": {
                "type": "compose-service",
                "value": "scwp03c/web",
            },
        },
        "images": [
            {
                "reference": OLD_LOCAL_ID,
                "local_image_id": OLD_LOCAL_ID,
                "platform": "linux/amd64",
                "status": "vulnerable",
                "counts": {"critical": 1, "high": 1},
                "findings": [
                    {"id": "CVE-OLD-1", "severity": "critical"},
                    {"id": "CVE-OLD-2", "severity": "high"},
                ],
                "services": [
                    {
                        "name": "scwp03c-web-1",
                        "stack": "scwp03c",
                        "compose_service": "web",
                        "compose_working_dir": str(root),
                        "compose_config_files": [str(path) for path in config_files],
                        "image": OLD_IMAGE,
                    }
                ],
            }
        ],
        "errors": [],
    }


def write_json(path: Path, payload: object) -> Path:
    """Write deterministic JSON fixture data."""

    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class ComposeClient:
    """Model the Docker subset used by one Compose transaction."""

    def __init__(self, source: Path, validation_fails: bool = False) -> None:
        """Start on the old artifact and retain invoked Docker arguments."""

        self.source = source
        self.validation_fails = validation_fails
        self.image_id = OLD_LOCAL_ID
        self.configured_image = OLD_IMAGE
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Return deterministic scan, Compose, and inspect results."""

        command = list(arguments)
        self.commands.append(command)
        if command[:2] == ["scout", "cves"]:
            return CommandResult(0, sarif([]), "")
        if command[:2] == ["compose", "--project-name"] and "config" in command:
            return CommandResult(1, "", "invalid fixture") if self.validation_fails else CommandResult(0, "", "")
        if command[:2] == ["compose", "--project-name"] and "up" in command:
            text = self.source.read_text(encoding="utf-8")
            if NEW_IMAGE in text:
                self.image_id = NEW_LOCAL_ID
                self.configured_image = NEW_IMAGE
            else:
                self.image_id = OLD_LOCAL_ID
                self.configured_image = OLD_IMAGE
            return CommandResult(0, "", "")
        if command[:2] == ["container", "ls"]:
            return CommandResult(0, "container-1\n", "")
        if command[:2] == ["container", "inspect"]:
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Id": "container-1",
                            "Name": "/scwp03c-web-1",
                            "Image": self.image_id,
                            "Config": {
                                "Image": self.configured_image,
                                "Labels": {
                                    "com.docker.compose.project": "scwp03c",
                                    "com.docker.compose.service": "web",
                                },
                            },
                            "State": {"Running": True, "Health": {"Status": "healthy"}},
                        }
                    ]
                ),
                "",
            )
        if command[:2] == ["image", "pull"]:
            return CommandResult(0, "pulled\n", "")
        if command[:2] == ["image", "inspect"]:
            return CommandResult(0, NEW_LOCAL_ID + "\n", "")
        return CommandResult(127, "", f"unexpected command: {command}")


class ComposeFixture:
    """Own one temporary exact Compose source, policy, and focused report."""

    def __init__(self, root: Path, *, multiple_files: bool = False) -> None:
        """Create a digest-pinned service and optional Compose base file."""

        self.root = root
        self.source = root / "compose.yml"
        self.source.write_text(
            "services:\n  web:\n    image: " + OLD_IMAGE + "\n",
            encoding="utf-8",
        )
        config_files = [self.source]
        if multiple_files:
            base = root / "base.yml"
            base.write_text("services: {}\n", encoding="utf-8")
            config_files = [base, self.source]
        self.policy = write_json(root / "policy.json", policy_payload())
        self.report = write_json(
            root / "focused.json", focused_report(root, config_files)
        )

    def prepare(self, client: ComposeClient):
        """Load and prepare the fixture transaction."""

        policy = load_compose_policy(self.policy)
        target = select_compose_target(policy, "scwp03c/web")
        evidence = load_compose_evidence(self.report, "scwp03c/web")
        return prepare_compose_remediation(
            client, target, evidence, sleeper=lambda _seconds: None
        )


class ComposePolicyTests(unittest.TestCase):
    """Require immutable candidates and explicit backup classification."""

    def test_mutable_candidate_is_rejected(self) -> None:
        """Reject a candidate without an exact registry digest."""

        payload = policy_payload()
        payload["targets"][0]["candidate_image"] = "registry.example/demo/app:1.1.0"
        with tempfile.TemporaryDirectory() as temporary:
            path = write_json(Path(temporary) / "policy.json", payload)
            with self.assertRaises(ComposePolicyError) as context:
                load_compose_policy(path)

        self.assertEqual(context.exception.code, "candidateDigest")

    def test_unknown_backup_state_is_rejected(self) -> None:
        """Do not treat arbitrary policy prose as backup readiness."""

        payload = policy_payload()
        payload["targets"][0]["backup"]["status"] = "probably"
        with tempfile.TemporaryDirectory() as temporary:
            path = write_json(Path(temporary) / "policy.json", payload)
            with self.assertRaises(ComposePolicyError) as context:
                load_compose_policy(path)

        self.assertEqual(context.exception.code, "backupStatus")


class ComposePlanningTests(unittest.TestCase):
    """Require exact ownership, dry-run diff, and rendered validation."""

    def test_dry_run_uses_exact_file_from_multiple_config_labels(self) -> None:
        """Edit only the policy source when Compose retained multiple files."""

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ComposeFixture(Path(temporary), multiple_files=True)
            client = ComposeClient(fixture.source)
            prepared = fixture.prepare(client)

            self.assertIn(NEW_IMAGE, prepared.source_change.diff)
            self.assertIn(OLD_IMAGE, fixture.source.read_text(encoding="utf-8"))
            config_commands = [command for command in client.commands if "config" in command]
            self.assertEqual(len(config_commands), 1)
            self.assertNotIn(str(fixture.source), config_commands[0])

    def test_missing_mapped_source_is_rejected(self) -> None:
        """Never guess a Compose file absent from retained Docker labels."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ComposeFixture(root)
            write_json(fixture.policy, policy_payload("other.yml"))
            policy = load_compose_policy(fixture.policy)
            target = select_compose_target(policy, "scwp03c/web")
            evidence = load_compose_evidence(fixture.report, "scwp03c/web")
            with self.assertRaises(ComposeRemediationError) as context:
                prepare_compose_remediation(
                    ComposeClient(fixture.source),
                    target,
                    evidence,
                    sleeper=lambda _seconds: None,
                )

        self.assertEqual(context.exception.code, "sourceNotMappedConfig")

    def test_render_failure_blocks_before_source_change(self) -> None:
        """Fail the dry-run when the replacement does not render."""

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ComposeFixture(Path(temporary))
            with self.assertRaises(ComposeRemediationError) as context:
                fixture.prepare(ComposeClient(fixture.source, validation_fails=True))

            self.assertIn(OLD_IMAGE, fixture.source.read_text(encoding="utf-8"))

        self.assertEqual(context.exception.code, "composeValidationFailed")


class ComposeExecutionTests(unittest.TestCase):
    """Require default-No confirmation, rollback, and exact post-check hooks."""

    def test_default_no_cancels_without_source_or_container_change(self) -> None:
        """Stop before backup or mutation when the first answer is not affirmative."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ComposeFixture(root)
            client = ComposeClient(fixture.source)
            prepared = fixture.prepare(client)
            plan = root / "plan.json"
            result = apply_prepared_remediation(
                client, prepared, plan, prompt=lambda _message: False
            )

            self.assertEqual(result, 4)
            self.assertEqual(client.image_id, OLD_LOCAL_ID)
            self.assertIn(OLD_IMAGE, fixture.source.read_text(encoding="utf-8"))
            self.assertFalse(Path(str(plan) + ".source-backup").exists())
            self.assertEqual(json.loads(plan.read_text())["status"], "cancelled")

    def test_apply_and_explicit_rollback_restore_exact_artifact(self) -> None:
        """Retain backup evidence and restore source plus prior image identity."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ComposeFixture(root)
            client = ComposeClient(fixture.source)
            prepared = fixture.prepare(client)
            plan = root / "plan.json"
            post_checks: list[str] = []

            result = apply_prepared_remediation(
                client,
                prepared,
                plan,
                prompt=lambda _message: True,
                post_check=lambda _client, _prepared, path: post_checks.append(str(path)) or {},
            )

            self.assertEqual(result, 0)
            self.assertEqual(client.image_id, NEW_LOCAL_ID)
            self.assertIn(NEW_IMAGE, fixture.source.read_text(encoding="utf-8"))
            self.assertEqual(len(post_checks), 1)
            self.assertTrue(Path(str(plan) + ".source-backup").is_file())

            rollback_result = rollback_transaction(
                client, plan, prompt=lambda _message: True
            )

            self.assertEqual(rollback_result, 0)
            self.assertEqual(client.image_id, OLD_LOCAL_ID)
            self.assertIn(OLD_IMAGE, fixture.source.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(plan.read_text())["status"], "rolled-back")

    def test_failed_post_check_automatically_rolls_back(self) -> None:
        """Restore exact source and image when the focused verification fails."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ComposeFixture(root)
            client = ComposeClient(fixture.source)
            prepared = fixture.prepare(client)
            plan = root / "plan.json"

            def fail_post_check(
                _client: ComposeClient, _prepared: object, _path: Path
            ) -> dict[str, object]:
                raise ComposeRemediationError("postCheckIncomplete")

            with self.assertRaises(ComposeRemediationError):
                apply_prepared_remediation(
                    client,
                    prepared,
                    plan,
                    prompt=lambda _message: True,
                    post_check=fail_post_check,
                )

            result = json.loads(plan.read_text(encoding="utf-8"))
            self.assertTrue(result["execution"]["rolled_back"])
            self.assertEqual(client.image_id, OLD_LOCAL_ID)
            self.assertIn(OLD_IMAGE, fixture.source.read_text(encoding="utf-8"))

    def test_post_check_rejects_a_different_local_image_artifact(self) -> None:
        """Require the fresh report to identify the exact planned image ID."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ComposeFixture(root)
            client = ComposeClient(fixture.source)
            prepared = fixture.prepare(client)
            report = {
                "images": [
                    {
                        "local_image_id": OLD_LOCAL_ID,
                        "counts": {"critical": 0, "high": 0},
                        "findings": [],
                    }
                ],
                "errors": [],
            }
            output_path = root / "post-check.json"

            with patch(
                "scripts.compose_remediation_verification.run_security_check",
                return_value=(report, 0),
            ):
                with self.assertRaises(ComposeRemediationError) as context:
                    run_focused_post_check(client, prepared, output_path)

            self.assertEqual(context.exception.code, "postCheckImageChanged")
            self.assertTrue(output_path.is_file())


class ComposePublicCliTests(unittest.TestCase):
    """Keep the guarded transaction reachable only through the host CLI."""

    def test_public_cli_exposes_plan_apply_and_rollback_without_yes(self) -> None:
        """Route both actions while reserving non-interactive yes for cleanup."""

        root = Path(__file__).resolve().parents[1]
        entrypoint = (root / "get_info.sh").read_text(encoding="utf-8")
        bridge = (root / "res" / "compose_remediation_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--compose-remediation)", entrypoint)
        self.assertIn("--rollback-compose-remediation)", entrypoint)
        self.assertIn('echo "$OP_COMPOSE_YES_SCOPE"', entrypoint)
        self.assertIn("-m scripts.compose_remediation_cli", bridge)
        self.assertIn("arguments+=(--apply)", bridge)
        self.assertNotIn("--yes", bridge)


if __name__ == "__main__":
    unittest.main()
