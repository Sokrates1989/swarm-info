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
    CleanupInventory,
    LocalImage,
    discover_cleanup_inventory,
    main,
    order_candidates_for_removal,
    remove_approved_candidates,
)
from scripts.vulnerability_scan import CommandResult


IMAGE_A = "sha256:" + ("a" * 64)
IMAGE_B = "sha256:" + ("b" * 64)
IMAGE_C = "sha256:" + ("c" * 64)
IMAGE_D = "sha256:" + ("d" * 64)


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
                "Parent": IMAGE_D,
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
            IMAGE_D: {
                "Id": IMAGE_D,
                "RepoTags": [],
                "RepoDigests": [],
                "Size": 50,
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
            return CommandResult(
                0,
                f"{IMAGE_A}\n{IMAGE_B}\n{IMAGE_C}\n{IMAGE_C}\n{IMAGE_D}\n",
                "",
            )
        if command[:2] == ["image", "inspect"]:
            requested = command[2]
            aliases = {"acme/scaled:1": IMAGE_B}
            image_id = aliases.get(requested, requested)
            if image_id in {IMAGE_A, IMAGE_B, IMAGE_C, IMAGE_D}:
                return CommandResult(0, self.image_payload(image_id), "")
            return CommandResult(1, "", "No such image")
        if command == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
            return CommandResult(0, "container-a\n", "")
        if command == ["container", "inspect", "container-a"]:
            return CommandResult(0, json.dumps([{"Image": IMAGE_A}]), "")
        if command == ["service", "ls", "--quiet"]:
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


class DependencyCleanupClient:
    """Model QNAP parent conflicts and implicit parent-image deletion."""

    def __init__(self, implicit_parent_removal: bool = False) -> None:
        self.implicit_parent_removal = implicit_parent_removal
        self.present = {IMAGE_C, IMAGE_D}
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Remove a child first or return Docker's dependency conflict."""

        command = list(arguments)
        self.commands.append(command)
        if command[:2] != ["image", "rm"]:
            return CommandResult(1, "", "unsupported command")
        image_id = command[2]
        if image_id not in self.present:
            return CommandResult(1, "", f"No such image: {image_id}")
        if image_id == IMAGE_D and IMAGE_C in self.present:
            return CommandResult(
                1,
                "",
                "conflict: image has dependent child images",
            )
        self.present.remove(image_id)
        if image_id == IMAGE_C and self.implicit_parent_removal:
            self.present.discard(IMAGE_D)
        return CommandResult(0, f"Deleted: {image_id}\n", "")


class MultipleReferenceCleanupClient:
    """Model Docker requiring verified tag removal before exact-ID deletion."""

    def __init__(self, moved_tag: str | None = None) -> None:
        self.tags = {"acme/old:1", "archive/old:1"}
        self.moved_tag = moved_tag
        self.present = True
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Return a multiple-repository conflict until both tags are removed."""

        command = list(arguments)
        self.commands.append(command)
        if command[:2] == ["image", "inspect"] and command[2] in self.tags:
            resolved_id = IMAGE_B if command[2] == self.moved_tag else IMAGE_C
            payload = [{"Id": resolved_id}]
            return CommandResult(0, json.dumps(payload), "")
        if command[:2] != ["image", "rm"]:
            return CommandResult(1, "", "unsupported command")
        target = command[2]
        if target in self.tags:
            self.tags.remove(target)
            if not self.tags:
                self.present = False
            return CommandResult(0, f"Untagged: {target}\n", "")
        if target == IMAGE_C and not self.present:
            return CommandResult(1, "", f"No such image: {IMAGE_C}")
        if target == IMAGE_C:
            return CommandResult(
                1,
                "",
                "conflict: image is referenced in multiple repositories",
            )
        return CommandResult(1, "", "No such image")


def dependency_inventory(parent_first: bool) -> CleanupInventory:
    """Build a focused approved parent/child removal inventory."""

    parent = LocalImage(IMAGE_D, (), (), 50)
    child = LocalImage(IMAGE_C, (), (), 100, IMAGE_D)
    candidates = (parent, child) if parent_first else (child, parent)
    return CleanupInventory(
        runtime="standalone",
        images=(parent, child),
        protected_image_ids=frozenset(),
        candidates=candidates,
        service_references=(),
        apply_allowed=True,
    )


def multiple_reference_inventory() -> CleanupInventory:
    """Build one approved unused image with two mutable repository tags."""

    image = LocalImage(
        IMAGE_C,
        ("acme/old:1", "archive/old:1"),
        (),
        100,
    )
    return CleanupInventory(
        runtime="standalone",
        images=(image,),
        protected_image_ids=frozenset(),
        candidates=(image,),
        service_references=(),
        apply_allowed=True,
    )


class ImageCleanupTests(unittest.TestCase):
    """Verify protection, review, confirmation, and exact-ID deletion."""

    def test_manager_protects_container_and_scaled_service_images(self) -> None:
        """Keep a service image even when no local container currently uses it."""

        client = FakeCleanupClient("manager")
        inventory = discover_cleanup_inventory(client)

        self.assertTrue(inventory.apply_allowed)
        self.assertEqual(inventory.runtime, "swarm-manager")
        self.assertEqual(
            inventory.protected_image_ids,
            {IMAGE_A, IMAGE_B, IMAGE_D},
        )
        self.assertEqual(
            [image.image_id for image in inventory.candidates], [IMAGE_C]
        )
        self.assertIn(["service", "ls", "--quiet"], client.commands)
        self.assertNotIn(
            ["service", "ls", "--quiet", "--no-trunc"], client.commands
        )

    def test_standalone_protects_all_container_images(self) -> None:
        """Use all local containers, not only running containers, as protection."""

        inventory = discover_cleanup_inventory(FakeCleanupClient("standalone"))

        self.assertTrue(inventory.apply_allowed)
        self.assertEqual(inventory.runtime, "standalone")
        self.assertEqual(inventory.protected_image_ids, {IMAGE_A, IMAGE_D})
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
        removed, already_absent, failures = remove_approved_candidates(
            client, inventory, frozenset({IMAGE_C})
        )

        self.assertEqual(removed, [IMAGE_C])
        self.assertEqual(already_absent, [])
        self.assertEqual(failures, {})
        removal_commands = [
            command for command in client.commands if command[:2] == ["image", "rm"]
        ]
        self.assertEqual(removal_commands, [["image", "rm", IMAGE_C]])

    def test_dependency_conflict_is_retried_after_child_removal(self) -> None:
        """Retry a QNAP parent only after its approved child was deleted."""

        client = DependencyCleanupClient()
        removed, already_absent, failures = remove_approved_candidates(
            client,
            dependency_inventory(parent_first=True),
            frozenset({IMAGE_C, IMAGE_D}),
        )

        self.assertEqual(removed, [IMAGE_C, IMAGE_D])
        self.assertEqual(already_absent, [])
        self.assertEqual(failures, {})
        self.assertEqual(
            client.commands,
            [
                ["image", "rm", IMAGE_D],
                ["image", "rm", IMAGE_C],
                ["image", "rm", IMAGE_D],
            ],
        )

    def test_candidate_inventory_orders_child_before_parent(self) -> None:
        """Prefer a deterministic topological order before retries are needed."""

        inventory = dependency_inventory(parent_first=True)
        ordered = order_candidates_for_removal(
            inventory.images,
            inventory.protected_image_ids,
        )

        self.assertEqual([image.image_id for image in ordered], [IMAGE_C, IMAGE_D])

    def test_implicitly_removed_parent_is_not_reported_as_failure(self) -> None:
        """Treat Docker's automatic dangling-parent cleanup as success."""

        client = DependencyCleanupClient(implicit_parent_removal=True)
        removed, already_absent, failures = remove_approved_candidates(
            client,
            dependency_inventory(parent_first=False),
            frozenset({IMAGE_C, IMAGE_D}),
        )

        self.assertEqual(removed, [IMAGE_C])
        self.assertEqual(already_absent, [IMAGE_D])
        self.assertEqual(failures, {})

    def test_verified_multi_repository_tags_are_removed_without_force(self) -> None:
        """Handle Docker's multi-tag conflict after exact-ID verification."""

        client = MultipleReferenceCleanupClient()
        removed, already_absent, failures = remove_approved_candidates(
            client,
            multiple_reference_inventory(),
            frozenset({IMAGE_C}),
        )

        self.assertEqual(removed, [IMAGE_C])
        self.assertEqual(already_absent, [])
        self.assertEqual(failures, {})
        self.assertFalse(any("--force" in command for command in client.commands))
        self.assertIn(["image", "rm", "acme/old:1"], client.commands)
        self.assertIn(["image", "rm", "archive/old:1"], client.commands)

    def test_moved_repository_tag_stops_before_any_untag(self) -> None:
        """Fail closed when a mutable tag changes after operator approval."""

        client = MultipleReferenceCleanupClient(moved_tag="archive/old:1")
        removed, already_absent, failures = remove_approved_candidates(
            client,
            multiple_reference_inventory(),
            frozenset({IMAGE_C}),
        )

        self.assertEqual(removed, [])
        self.assertEqual(already_absent, [])
        self.assertIn(IMAGE_C, failures)
        self.assertIn("moved after cleanup approval", failures[IMAGE_C])
        self.assertFalse(
            any(command[:2] == ["image", "rm"] and command[2] in client.tags
                for command in client.commands)
        )

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
        self.assertEqual(report["action"]["already_absent_image_ids"], [])
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["summary"]["removed_images"], 1)
        self.assertEqual(report["last_result"]["status"], "applied")
        self.assertEqual(report["history"], [report["last_result"]])
        self.assertEqual(
            sum(
                command == ["image", "ls", "--all", "--no-trunc", "--quiet"]
                for command in client.commands
            ),
            2,
        )

    def test_repeated_previews_retain_bounded_count_only_history(self) -> None:
        """Keep prior operator reviews without retaining old image identities."""

        client = FakeCleanupClient("standalone")
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "cleanup.json"
            with patch("scripts.image_cleanup.DockerClient", return_value=client):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        main(["--output-file", str(report_path)]),
                        0,
                    )
                    self.assertEqual(
                        main(["--output-file", str(report_path)]),
                        0,
                    )
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(len(report["history"]), 2)
        self.assertEqual(report["last_result"]["status"], "preview")
        self.assertTrue(
            all("image_id" not in entry for entry in report["history"])
        )

    def test_cancelled_apply_is_published_without_removal(self) -> None:
        """Record a default-No outcome while keeping Docker unchanged."""

        client = FakeCleanupClient("standalone")
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "cleanup.json"
            with (
                patch("scripts.image_cleanup.DockerClient", return_value=client),
                patch("builtins.input", return_value=""),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    ["--apply", "--output-file", str(report_path)]
                )
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["last_result"]["status"], "cancelled")
        self.assertFalse(
            any(command[:2] == ["image", "rm"] for command in client.commands)
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
        self.assertIn('IMAGE_CLEANUP_APPLY="$REQUEST_APPLY"', entrypoint)
        self.assertIn('echo "$OP_COMPOSE_YES_SCOPE"', entrypoint)
        self.assertIn("i) Review / clean unused local images", menu)
        self.assertIn('bash "$MAIN_DIR/get_info.sh" -i --apply', menu)
        self.assertIn("-m scripts.image_cleanup", bridge)


if __name__ == "__main__":
    unittest.main()
