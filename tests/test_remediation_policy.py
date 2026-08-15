"""Validate remediation policy, planning, and fail-closed source adapters."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.remediation_policy import (
    RemediationPolicyError,
    build_plan,
    load_policy,
    vulnerable_items,
)
from scripts.remediation_source import (
    SourceEditError,
    prepare_source_change,
    write_source_change,
)


OLD_DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64
OLD_IMAGE = f"registry.example/team/app:1.0.0@{OLD_DIGEST}"
NEW_IMAGE = f"registry.example/team/app:1.1.0@{NEW_DIGEST}"


def vulnerability_report() -> dict[str, object]:
    """Return complete per-service evidence with two fixable findings."""

    return {
        "completed_at": "2026-08-14T10:00:00Z",
        "scope": {"image_fingerprint": "scope-1"},
        "images": [
            {
                "reference": OLD_IMAGE,
                "status": "vulnerable",
                "counts": {"critical": 2, "high": 4},
                "findings": [
                    {"id": "CVE-1", "severity": "critical"},
                    {"id": "CVE-2", "severity": "high"},
                ],
                "services": [
                    {"name": "demo_api", "stack": "demo"},
                    {"name": "demo_worker", "stack": "demo"},
                ],
            }
        ],
    }


def deployment_map(directory: Path, stack_file: Path) -> dict[str, object]:
    """Return one exact mapped service and one unresolved consumer."""

    return {
        "generated_at": "2026-08-14T10:01:00Z",
        "services": [
            {
                "name": "demo_api",
                "stack": "demo",
                "status": "mapped",
                "reason": "matched-stack-service-image",
                "image": OLD_IMAGE,
                "directory": str(directory),
                "stack_file": str(stack_file),
                "compose_service": "api",
            },
            {
                "name": "demo_worker",
                "stack": "demo",
                "status": "unknown",
                "reason": "image-mismatch",
                "image": OLD_IMAGE,
            },
        ],
    }


def policy_payload(
    *,
    service: str = "demo_api",
    candidate: str = NEW_IMAGE,
    backup_status: str = "not_required",
    auto_eligible: bool = True,
    source: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build one valid policy target with an optional source adapter."""

    return {
        "schema_version": 1,
        "targets": [
            {
                "id": "demo-api-update",
                "match": {
                    "service": service,
                    "repository": "registry.example/team/app",
                },
                "candidate_image": candidate,
                "backup": {
                    "status": backup_status,
                    "reason": "Stateless test service.",
                },
                "auto_eligible": auto_eligible,
                "source": source,
                "verification": {"timeout_seconds": 30},
            }
        ],
    }


def write_policy(directory: Path, payload: dict[str, object]) -> Path:
    """Write one test policy and return its path."""

    path = directory / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class RemediationPolicyTests(unittest.TestCase):
    """Require explicit immutable candidates and non-bypassable safeguards."""

    def test_candidate_requires_tag_and_complete_digest(self) -> None:
        """Reject a mutable candidate before planning or Docker access."""

        with tempfile.TemporaryDirectory() as temporary:
            path = write_policy(
                Path(temporary),
                policy_payload(candidate="registry.example/team/app:1.1.0"),
            )
            with self.assertRaises(RemediationPolicyError) as context:
                load_policy(path)

        self.assertEqual(context.exception.code, "candidateDigest")

    def test_candidate_cannot_change_repository(self) -> None:
        """Keep automatic replacement within the explicitly matched repository."""

        candidate = f"registry.example/other/app:1.1.0@{NEW_DIGEST}"
        with tempfile.TemporaryDirectory() as temporary:
            path = write_policy(Path(temporary), policy_payload(candidate=candidate))
            with self.assertRaises(RemediationPolicyError) as context:
                load_policy(path)

        self.assertEqual(context.exception.code, "candidateRepository")

    def test_unknown_policy_field_is_rejected(self) -> None:
        """Catch misspelled safety gates instead of accepting unsafe defaults."""

        payload = policy_payload()
        payload["targets"][0]["enable"] = False
        with tempfile.TemporaryDirectory() as temporary:
            path = write_policy(Path(temporary), payload)
            with self.assertRaises(RemediationPolicyError) as context:
                load_policy(path)

        self.assertEqual(context.exception.code, "targetUnknownField")

    def test_plan_is_priority_sorted_and_records_shared_consumers(self) -> None:
        """Expose shared-image blast radius and a stable evidence plan."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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
            plan = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )

        self.assertEqual(plan["summary"]["eligible"], 1)
        self.assertEqual(plan["entries"][0]["shared_service_count"], 2)
        self.assertEqual(plan["entries"][0]["action"], "declarative")
        self.assertEqual(len(plan["plan_id"]), 16)

    def test_force_does_not_bypass_backup_classification(self) -> None:
        """Let force override only auto eligibility, never backup requirements."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        backup_status="required",
                        auto_eligible=False,
                        source={"type": "yaml_image", "file": "swarm-stack.yml"},
                    ),
                )
            )
            plan = build_plan(
                vulnerability_report(),
                deployment_map(root, stack_file),
                policy,
                force_attempt=True,
            )

        self.assertFalse(plan["entries"][0]["eligible"])
        self.assertIn("backup-not-exempt", plan["entries"][0]["blocked_reasons"])

    def test_unresolved_service_becomes_runtime_override_plan(self) -> None:
        """Retain unknown mapper evidence as a distinct configuration-drift path."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(
                write_policy(root, policy_payload(service="demo_worker"))
            )
            plan = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )

        self.assertTrue(plan["entries"][0]["eligible"])
        self.assertEqual(plan["entries"][0]["action"], "runtime-override")
        self.assertEqual(vulnerable_items(vulnerability_report())[0]["critical"], 2)

    def test_unverified_mapped_source_uses_runtime_override(self) -> None:
        """Never auto-edit a path found through drift or fallback rendering."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            mapping = deployment_map(root, stack_file)
            mapping["services"][0]["source_verified"] = False
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        source={"type": "yaml_image", "file": "swarm-stack.yml"}
                    ),
                )
            )

            plan = build_plan(vulnerability_report(), mapping, policy)

        self.assertEqual(plan["entries"][0]["action"], "runtime-override")
        self.assertTrue(plan["entries"][0]["eligible"])

    def test_reviewed_latest_candidate_needs_no_source_edit_adapter(self) -> None:
        """Treat an already latest-following source as a reversible refresh action."""

        latest_candidate = f"registry.example/team/app:latest@{NEW_DIGEST}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            mapping = deployment_map(root, stack_file)
            mapping["services"][0]["declared_image"] = (
                "registry.example/team/app:latest"
            )
            mapping["services"][0]["source_verified"] = True
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(candidate=latest_candidate, source=None),
                )
            )
            plan = build_plan(vulnerability_report(), mapping, policy)

        self.assertEqual(plan["entries"][0]["action"], "latest-refresh")
        self.assertTrue(plan["entries"][0]["eligible"])
        self.assertEqual(plan["summary"]["latest_refreshes"], 1)

    def test_mutable_current_image_blocks_exact_rollback_plan(self) -> None:
        """Refuse automatic mutation when the previous artifact cannot be restored."""

        report = vulnerability_report()
        report["images"][0]["reference"] = "registry.example/team/app:1.0.0"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(write_policy(root, policy_payload()))
            plan = build_plan(report, deployment_map(root, stack_file), policy)

        self.assertIn(
            "current-image-mutable", plan["entries"][0]["blocked_reasons"]
        )

    def test_short_current_digest_blocks_exact_rollback_plan(self) -> None:
        """Reject display-only digest prefixes as rollback identities."""

        report = vulnerability_report()
        report["images"][0]["reference"] = (
            "registry.example/team/app:1.0.0@sha256:abcd1234"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(write_policy(root, policy_payload()))
            plan = build_plan(report, deployment_map(root, stack_file), policy)

        self.assertIn(
            "current-image-mutable", plan["entries"][0]["blocked_reasons"]
        )


class RemediationSourceTests(unittest.TestCase):
    """Apply only exact, reviewable source edits with byte-for-byte rollback."""

    def test_dotenv_name_version_change_applies_and_restores_atomically(self) -> None:
        """Update the mapped tag without discarding the reviewed rollback bytes."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / ".env"
            environment.write_text(
                "STACK_NAME=demo\n"
                "IGNORED_SECRET=never-print-me\n"
                "IMAGE_NAME=registry.example/team/app\n"
                "IMAGE_VERSION=1.0.0\n",
                encoding="utf-8",
            )
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
            plan = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )
            change = prepare_source_change(policy.targets[0], plan["entries"][0])
            write_source_change(change)

            self.assertIn("IMAGE_VERSION=1.1.0", environment.read_text())
            self.assertIn("-IMAGE_VERSION=1.0.0", change.diff)
            self.assertNotIn("never-print-me", change.diff)
            write_source_change(change, replacement=change.original)
            self.assertIn("IMAGE_VERSION=1.0.0", environment.read_text())

    def test_stale_dotenv_value_is_rejected(self) -> None:
        """Do not overwrite source that no longer declares the live image."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text(
                "IMAGE_NAME=registry.example/team/app\nIMAGE_VERSION=9.9.9\n",
                encoding="utf-8",
            )
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
            plan = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )

            with self.assertRaises(SourceEditError) as context:
                prepare_source_change(policy.targets[0], plan["entries"][0])

        self.assertEqual(context.exception.code, "source-image-stale")

    def test_unverified_mapper_source_is_rejected_before_file_read(self) -> None:
        """Enforce the mapper safety flag at the source-edit boundary too."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        source={"type": "yaml_image", "file": "swarm-stack.yml"}
                    ),
                )
            )
            mapping = deployment_map(root, stack_file)
            mapping["services"][0]["source_verified"] = False
            plan = build_plan(vulnerability_report(), mapping, policy)
            plan["entries"][0]["action"] = "declarative"

            with self.assertRaises(SourceEditError) as context:
                prepare_source_change(policy.targets[0], plan["entries"][0])

        self.assertEqual(context.exception.code, "declarative-evidence-required")

    def test_simple_yaml_image_is_pinned_to_candidate_digest(self) -> None:
        """Support an exact scalar image while rejecting generic YAML rewriting."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text(
                "services:\n  api:\n    image: registry.example/team/app:1.0.0\n",
                encoding="utf-8",
            )
            policy = load_policy(
                write_policy(
                    root,
                    policy_payload(
                        source={"type": "yaml_image", "file": "swarm-stack.yml"}
                    ),
                )
            )
            plan = build_plan(
                vulnerability_report(), deployment_map(root, stack_file), policy
            )
            change = prepare_source_change(policy.targets[0], plan["entries"][0])

        self.assertIn(NEW_IMAGE, change.replacement.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
