"""Behavioral tests for fail-closed local Docker image cleanup."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.image_cleanup import (
    discover_cleanup_inventory,
    main,
    remove_approved_candidates,
)
from scripts.vulnerability_scan import CommandResult


IMAGE_A = "sha256:" + ("a" * 64)
IMAGE_B = "sha256:" + ("b" * 64)
IMAGE_C = "sha256:" + ("c" * 64)


class FakeCleanupClient:
    """Provide deterministic Docker inventory and removal behavior."""

    def __init__(self, runtime: str = "manager", fail_removal: bool = False) -> None:
        self.runtime = runtime
        self.fail_removal = fail_removal
        self.commands: list[list[str]] = []

    @staticmethod
    def image_payload(image_id: str) -> str:
        """Return one Docker image-inspect JSON response."""

        details = {
            IMAGE_A: {
                "Id": IMAGE_A,
                "RepoTags": ["acme/active:1"],
                "RepoDigests": [f"acme/active@sha256:{'1' * 64}"],
                "Size": 100,
            },
            IMAGE_B: {
                "Id": IMAGE_B,
                "RepoTags": ["acme/scaled:1"],
                "RepoDigests": [f"acme/scaled@sha256:{'2' * 64}"],
                "Size": 200,
            },
            IMAGE_C: {
                "Id": IMAGE_C,
                "RepoTags": [],
                "RepoDigests": [],
                "Size": 300,
            },
        }
        return json.dumps([details[image_id]])

    def run(self, arguments: list[str]) -> CommandResult:
        """Return one fake command response and retain the exact invocation."""

        command = list(arguments)
        self.commands.append(command)
        if command[:2] == ["info", "--format"]:
            states = {
                "manager": "active\ttrue\n",
                "worker": "active\tfalse\n",
                "standalone": "inactive\tfalse\n",
            }
            return CommandResult(0, states[self.runtime], "")
        if command == ["image", "ls", "--all", "--no-trunc", "--quiet"]:
            return CommandResult(0, f"{IMAGE_A}\n{IMAGE_B}\n{IMAGE_C}\n{IMAGE_C}\n", "")
        if command[:2] == ["image", "inspect"]:
            requested = command[2]
            aliases = {"acme/scaled:1": IMAGE_B}
            image_id = aliases.get(requested, requested)
            if image_id in {IMAGE_A, IMAGE_B, IMAGE_C}:
                return CommandResult(0, self.image_payload(image_id), "")
            return CommandResult(1, "", "No such image")
        if command == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
            return CommandResult(0, "container-a\n", "")
        if command == ["container", "inspect", "container-a"]:
            return CommandResult(0, json.dumps([{"Image": IMAGE_A}]), "")
        if command == ["service", "ls", "--quiet", "--no-trunc"]:
            return CommandResult(0, "service-scaled\n", "")
        if command == ["service", "inspect", "service-scaled"]:
            payload = {
                "Spec": {
                    "TaskTemplate": {
                        "ContainerSpec": {"Image": "acme/scaled:1"}
                    }
                }
            }
            return CommandResult(0, json.dumps([payload]), "")
        if command[:2] == ["image", "rm"]:
            if self.fail_removal:
                return CommandResult(1, "", "image is being used")
            return CommandResult(0, f"Deleted: {command[2]}\n", "")
        return CommandResult(1, "", f"Unsupported fake command: {command}")


class ImageCleanupTests(unittest.TestCase):
    """Verify protection, review, confirmation, and exact-ID deletion."""

    def test_manager_protects_container_and_scaled_service_images(self) -> None:
        """Keep a service image even when no local container currently uses it."""

        client = FakeCleanupClient("manager")
        inventory = discover_cleanup_inventory(client)

        self.assertTrue(inventory.apply_allowed)
        self.assertEqual(inventory.runtime, "swarm-manager")
        self.assertEqual(inventory.protected_image_ids, {IMAGE_A, IMAGE_B})
        self.assertEqual(
            [image.image_id for image in inventory.candidates], [IMAGE_C]
        )

    def test_standalone_protects_all_container_images(self) -> None:
        """Use all local containers, not only running containers, as protection."""

        inventory = discover_cleanup_inventory(FakeCleanupClient("standalone"))

        self.assertTrue(inventory.apply_allowed)
        self.assertEqual(inventory.runtime, "standalone")
        self.assertEqual(inventory.protected_image_ids, {IMAGE_A})
        self.assertEqual(
            [image.image_id for image in inventory.candidates], [IMAGE_B, IMAGE_C]
        )

    def test_swarm_worker_refuses_deletion_without_service_visibility(self) -> None:
        """Fail closed when the current node cannot inventory Swarm services."""

        inventory = discover_cleanup_inventory(FakeCleanupClient("worker"))

        self.assertFalse(inventory.apply_allowed)
        self.assertEqual(inventory.runtime, "swarm-worker")
        self.assertIn("cannot inventory", inventory.blockers[0])

    def test_swarm_worker_review_succeeds_but_apply_is_refused(self) -> None:
        """Allow diagnostics on a worker while preserving the mutation gate."""

        review_client = FakeCleanupClient("worker")
        apply_client = FakeCleanupClient("worker")
        with patch(
            "scripts.image_cleanup.DockerClient", return_value=review_client
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                review_exit_code = main([])
        with patch(
            "scripts.image_cleanup.DockerClient", return_value=apply_client
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                apply_exit_code = main(["--apply", "--yes"])

        self.assertEqual(review_exit_code, 0)
        self.assertEqual(apply_exit_code, 3)
        self.assertFalse(
            any(command[:2] == ["image", "rm"] for command in apply_client.commands)
        )

    def test_removal_uses_exact_reviewed_id_without_force(self) -> None:
        """Delete only approved candidates and never add Docker's force flag."""

        client = FakeCleanupClient("manager")
        inventory = discover_cleanup_inventory(client)
        removed, failures = remove_approved_candidates(
            client, inventory, frozenset({IMAGE_C})
        )

        self.assertEqual(removed, [IMAGE_C])
        self.assertEqual(failures, {})
        removal_commands = [
            command for command in client.commands if command[:2] == ["image", "rm"]
        ]
        self.assertEqual(removal_commands, [["image", "rm", IMAGE_C]])

    def test_default_cli_is_a_read_only_review(self) -> None:
        """Require --apply before any image removal command can be issued."""

        client = FakeCleanupClient("standalone")
        with patch("scripts.image_cleanup.DockerClient", return_value=client):
            with redirect_stdout(io.StringIO()) as output:
                exit_code = main([])

        self.assertEqual(exit_code, 0)
        self.assertIn("Dry run only", output.getvalue())
        self.assertFalse(
            any(command[:2] == ["image", "rm"] for command in client.commands)
        )

    def test_automated_apply_rechecks_and_writes_audit_report(self) -> None:
        """Support explicit automation with a second complete safety inventory."""

        client = FakeCleanupClient("manager")
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "cleanup.json"
            with patch("scripts.image_cleanup.DockerClient", return_value=client):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    exit_code = main(
                        ["--apply", "--yes", "--output-file", str(report_path)]
                    )
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["action"]["removed_image_ids"], [IMAGE_C])
        self.assertEqual(report["summary"]["removed_images"], 1)
        self.assertEqual(
            sum(
                command == ["image", "ls", "--all", "--no-trunc", "--quiet"]
                for command in client.commands
            ),
            2,
        )

    def test_failed_removal_is_sanitized_and_incomplete(self) -> None:
        """Retain a failed exact deletion without attempting force recovery."""

        client = FakeCleanupClient("manager", fail_removal=True)
        with patch("scripts.image_cleanup.DockerClient", return_value=client):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main(["--apply", "--yes"])

        self.assertEqual(exit_code, 3)
        self.assertFalse(any("--force" in command for command in client.commands))

    def test_public_cli_and_menu_expose_safe_cleanup_shortcut(self) -> None:
        """Keep reporting, confirmed apply, and menu navigation discoverable."""

        repository_root = Path(__file__).resolve().parents[1]
        entrypoint = (repository_root / "get_info.sh").read_text(encoding="utf-8")
        menu = (repository_root / "res" / "menu.sh").read_text(encoding="utf-8")
        bridge = (repository_root / "res" / "image_cleanup_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('-i|--image-cleanup)', entrypoint)
        self.assertIn('selected_action="image-cleanup"', entrypoint)
        self.assertIn('"image-cleanup")', entrypoint)
        self.assertIn("--apply and --yes are valid only", entrypoint)
        self.assertIn("i) Review / clean unused local images", menu)
        self.assertIn('bash "$MAIN_DIR/get_info.sh" -i --apply', menu)
        self.assertIn("-m scripts.image_cleanup", bridge)


if __name__ == "__main__":
    unittest.main()
