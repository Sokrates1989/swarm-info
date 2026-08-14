"""Verify conservative service-to-stack deployment mapping."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import deployment_mapper
from scripts.deployment_mapper import default_deploy_roots, render_deployment_map
from scripts.deployment_mapping import (
    build_deployment_map,
    candidate_yaml_files,
    canonical_image_reference,
    image_references_match,
)
from scripts.operator_report import load_messages
from scripts.vulnerability_models import ServiceRecord
from scripts.vulnerability_scan import CommandResult


class FakeComposeClient:
    """Render configured Compose payloads without Docker or filesystem reads."""

    def __init__(
        self,
        payloads: dict[Path, dict[str, object]] | None = None,
        available: bool = True,
        failing_environment_files: set[Path] | None = None,
    ) -> None:
        """Store render output, availability, and rejected dotenv inputs."""

        self.payloads = payloads or {}
        self.available = available
        self.failing_environment_files = failing_environment_files or set()
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Return version or JSON config output for one Docker invocation."""

        command = list(arguments)
        self.commands.append(command)
        if command == ["compose", "version"]:
            return CommandResult(0 if self.available else 1, "v2.39.1", "")
        environment_file = Path(command[command.index("--env-file") + 1])
        if environment_file in self.failing_environment_files:
            return CommandResult(1, "", "dotenv parse failed")
        stack_file = Path(command[command.index("-f") + 1])
        payload = self.payloads.get(stack_file)
        if payload is None:
            return CommandResult(1, "", "render failed")
        return CommandResult(0, json.dumps(payload), "")


def create_candidate(
    root: Path,
    directory_name: str,
    stack_name: str,
    filename: str = "swarm-stack.yml",
) -> Path:
    """Create one minimal candidate and its explicit stack identity."""

    directory = root / directory_name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ".env").write_text(
        f"STACK_NAME={stack_name}\nIGNORED_SECRET=do-not-read\n",
        encoding="utf-8",
    )
    stack_file = directory / filename
    stack_file.write_text("services: {}\n", encoding="utf-8")
    return stack_file


class DeploymentMappingTests(unittest.TestCase):
    """Reject weak matches and preserve auditable unknown evidence."""

    def test_exact_stack_service_and_image_match_maps_deployment(self) -> None:
        """Accept a digest-pinned live image matching a rendered tagged image."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stack_file = create_candidate(
                root, "administration/swarm-info-watchdog", "swarm-info-watchdog"
            )
            client = FakeComposeClient(
                {
                    stack_file: {
                        "services": {
                            "admin-api": {
                                "image": "sokrates1989/swarm-info-watchdog:0.2.1"
                            }
                        }
                    }
                }
            )
            service = ServiceRecord(
                "service-id",
                "swarm-info-watchdog_admin-api",
                "sokrates1989/swarm-info-watchdog:0.2.1@sha256:" + "a" * 64,
                "swarm-info-watchdog",
            )

            report = build_deployment_map(client, [service], [root])
            mapping = report["services"][0]

        self.assertEqual(mapping["status"], "mapped")
        self.assertEqual(mapping["stack_file"], str(stack_file))
        self.assertEqual(mapping["compose_service"], "admin-api")
        self.assertEqual(report["schema_version"], 2)
        self.assertTrue(mapping["source_verified"])
        self.assertEqual(report["summary"]["mapped"], 1)
        self.assertNotIn("do-not-read", json.dumps(report))
        self.assertTrue(
            all(command[:1] == ["compose"] for command in client.commands)
        )

    def test_stale_declared_image_maps_path_but_disables_source_mutation(self) -> None:
        """Identify one owner while preserving live/source image drift."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stack_file = create_candidate(root, "apps/demo", "demo")
            client = FakeComposeClient(
                {stack_file: {"services": {"api": {"image": "example/api:old"}}}}
            )
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:new", "demo"
            )

            report = build_deployment_map(client, [service], [root])
            mapping = report["services"][0]

        self.assertEqual(mapping["status"], "mapped")
        self.assertEqual(mapping["reason"], "matched-stack-service-source-drift")
        self.assertEqual(mapping["candidate_files"], [str(stack_file)])
        self.assertEqual(mapping["declared_image"], "example/api:old")
        self.assertFalse(mapping["source_image_matches_live"])
        self.assertFalse(mapping["source_verified"])
        self.assertEqual(report["summary"]["source_unverified"], 1)

    def test_missing_stack_name_is_inferred_from_unique_live_consensus(self) -> None:
        """Map the Traefik-style layout without requiring a copied STACK_NAME."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            directory = root / "administration/traefik"
            directory.mkdir(parents=True)
            (directory / ".env").write_text(
                "DOMAIN=example.test\nCATAPP_URL=cats.example.test\n",
                encoding="utf-8",
            )
            stack_file = directory / "config-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            payload = {
                "services": {
                    "traefik": {"image": "traefik:3"},
                    "catapp": {"image": "mikesir87/cats:1.0"},
                    "catapp_subdomain": {"image": "mikesir87/cats:1.0"},
                }
            }
            services = [
                ServiceRecord("1", "traefik_traefik", "traefik:3", "traefik"),
                ServiceRecord(
                    "2", "traefik_catapp", "mikesir87/cats:1.0", "traefik"
                ),
                ServiceRecord(
                    "3",
                    "traefik_catapp_subdomain",
                    "mikesir87/cats:1.0",
                    "traefik",
                ),
            ]

            report = build_deployment_map(
                FakeComposeClient({stack_file: payload}), services, [root]
            )

        self.assertEqual(report["summary"]["mapped"], 3)
        self.assertTrue(
            all(
                mapping["stack_name_source"] == "live-service-consensus"
                and mapping["source_verified"] is True
                for mapping in report["services"]
            )
        )

    def test_missing_stack_name_is_not_guessed_across_two_live_stacks(self) -> None:
        """Reject an unnamed file that could own equivalent services twice."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            directory = root / "shared"
            directory.mkdir()
            (directory / ".env").write_text("DOMAIN=example.test\n", encoding="utf-8")
            stack_file = directory / "stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            payload = {"services": {"api": {"image": "example/api:1"}}}
            services = [
                ServiceRecord("1", "alpha_api", "example/api:1", "alpha"),
                ServiceRecord("2", "beta_api", "example/api:1", "beta"),
            ]

            report = build_deployment_map(
                FakeComposeClient({stack_file: payload}), services, [root]
            )

        self.assertEqual(report["summary"]["mapped"], 0)
        self.assertTrue(
            all(
                mapping["reason"] == "no-stack-candidate"
                for mapping in report["services"]
            )
        )

    def test_malformed_dotenv_uses_defaults_only_for_path_evidence(self) -> None:
        """Recover the cron layout without authorizing source-file edits."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stack_file = create_candidate(
                root, "administration/cron", "swarm_cronjob", "swarm-compose.yml"
            )
            environment_file = stack_file.parent / ".env"
            environment_file.write_text(
                "q!# malformed historical prefix\n"
                "STACK_NAME=swarm_cronjob\n",
                encoding="utf-8",
            )
            payload = {
                "services": {
                    "swarm-cronjob": {"image": "crazymax/swarm-cronjob:latest"}
                }
            }
            service = ServiceRecord(
                "1",
                "swarm_cronjob_swarm-cronjob",
                "crazymax/swarm-cronjob:latest",
                "swarm_cronjob",
            )

            report = build_deployment_map(
                FakeComposeClient(
                    {stack_file: payload},
                    failing_environment_files={environment_file},
                ),
                [service],
                [root],
            )
            mapping = report["services"][0]

        self.assertEqual(mapping["status"], "mapped")
        self.assertEqual(mapping["render_source"], "defaults-only")
        self.assertTrue(mapping["source_image_matches_live"])
        self.assertFalse(mapping["source_verified"])
        self.assertEqual(
            mapping["reason"], "matched-stack-service-fallback-render"
        )
        self.assertEqual(report["summary"]["source_unverified"], 1)

    def test_backup_aliases_are_not_stack_candidates(self) -> None:
        """Ignore historical YAML aliases while retaining the active stack."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active = create_candidate(root, "apps/demo", "demo")
            backup = active.parent / "swarm-stack.backup.yml"
            backup.write_text("services: {}\n", encoding="utf-8")
            suffixed_backup = active.parent / "swarm-stack.yml.backup.20251213"
            suffixed_backup.write_text("services: {}\n", encoding="utf-8")

            candidates = candidate_yaml_files(root)

        self.assertEqual(candidates, [active])

    def test_duplicate_matches_in_different_directories_are_ambiguous(self) -> None:
        """Refuse to guess between two independently matching checkouts."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = create_candidate(root, "prod/demo", "demo")
            second = create_candidate(root, "test/demo", "demo")
            payload = {"services": {"api": {"image": "example/api:1"}}}
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )

            report = build_deployment_map(
                FakeComposeClient({first: payload, second: payload}),
                [service],
                [root],
            )
            mapping = report["services"][0]

        self.assertEqual(mapping["status"], "ambiguous")
        self.assertEqual(mapping["reason"], "multiple-deployment-directories")
        self.assertEqual(mapping["candidate_files"], sorted([str(first), str(second)]))

    def test_multiple_matching_files_in_one_directory_are_ambiguous(self) -> None:
        """Refuse to infer which matching YAML file was actually deployed."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            swarm_stack = create_candidate(root, "apps/demo", "demo")
            compose_file = create_candidate(
                root, "apps/demo", "demo", "docker-compose.yml"
            )
            payload = {"services": {"api": {"image": "example/api:1"}}}
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )

            report = build_deployment_map(
                FakeComposeClient({swarm_stack: payload, compose_file: payload}),
                [service],
                [root],
            )

        self.assertEqual(report["services"][0]["status"], "ambiguous")
        self.assertEqual(report["services"][0]["reason"], "multiple-stack-files")
        self.assertEqual(
            report["services"][0]["candidate_files"],
            sorted([str(swarm_stack), str(compose_file)]),
        )

    def test_yaml_without_sibling_stack_identity_is_ignored(self) -> None:
        """Do not match a service from image text in an unrelated YAML file."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            unrelated = root / "notes.yml"
            unrelated.write_text(
                "services:\n  api:\n    image: example/api:1\n", encoding="utf-8"
            )
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )

            report = build_deployment_map(
                FakeComposeClient({unrelated: {}}), [service], [root]
            )

        self.assertEqual(report["summary"]["yaml_files_considered"], 0)
        self.assertEqual(report["services"][0]["reason"], "no-stack-candidate")

    def test_missing_compose_marks_every_service_unknown(self) -> None:
        """Fail closed when YAML cannot be rendered reliably."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )
            report = build_deployment_map(
                FakeComposeClient(available=False), [service], [root]
            )

        self.assertFalse(report["renderer"]["available"])
        self.assertEqual(report["services"][0]["status"], "unknown")
        self.assertEqual(report["services"][0]["reason"], "compose-unavailable")

    def test_overlapping_search_roots_do_not_duplicate_one_stack_file(self) -> None:
        """Deduplicate one physical candidate reached through nested roots."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            nested_root = root / "apps"
            stack_file = create_candidate(nested_root, "demo", "demo")
            payload = {"services": {"api": {"image": "example/api:1"}}}
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )

            report = build_deployment_map(
                FakeComposeClient({stack_file: payload}),
                [service],
                [root, nested_root],
            )

        self.assertEqual(report["services"][0]["status"], "mapped")
        self.assertEqual(report["summary"]["rendered_stack_files"], 1)

    def test_docker_hub_shorthand_normalizes_without_ignoring_tags(self) -> None:
        """Recognize registry aliases while retaining the deployed tag boundary."""

        self.assertEqual(
            canonical_image_reference("mysql:8@sha256:1234"),
            "docker.io/library/mysql:8",
        )
        self.assertEqual(
            canonical_image_reference("index.docker.io/library/mysql:8"),
            "docker.io/library/mysql:8",
        )
        self.assertNotEqual(
            canonical_image_reference("mysql:8"),
            canonical_image_reference("mysql:9"),
        )
        self.assertEqual(
            canonical_image_reference("mysql"),
            canonical_image_reference("docker.io/library/mysql:latest"),
        )

    def test_explicit_digest_must_match_live_digest(self) -> None:
        """Never map two digest-pinned images merely because the repository agrees."""

        old_digest = "example/api@sha256:" + "a" * 64
        new_digest = "example/api@sha256:" + "b" * 64

        self.assertFalse(image_references_match(old_digest, new_digest))
        self.assertTrue(image_references_match(old_digest, old_digest))
        self.assertTrue(
            image_references_match(
                "example/api:1",
                "example/api:1@sha256:" + "a" * 64,
            )
        )

    def test_default_root_can_be_configured_with_path_separated_values(self) -> None:
        """Support setup-provided roots without changing the public command."""

        configured = os.pathsep.join(("/swarm", "/opt/stacks"))

        roots = default_deploy_roots({"SWARM_INFO_DEPLOY_ROOTS": configured})

        self.assertEqual(roots, [Path("/swarm"), Path("/opt/stacks")])

    def test_human_report_lists_mapped_and_unresolved_services(self) -> None:
        """Expose the complete evidence set for operator acceptance testing."""

        report = {
            "deploy_roots": ["/swarm"],
            "renderer": {"available": True},
            "summary": {
                "service_count": 2,
                "mapped": 1,
                "unknown": 1,
                "ambiguous": 0,
            },
            "services": [
                {
                    "name": "demo_api",
                    "status": "mapped",
                    "stack_file": "/swarm/demo/swarm-stack.yml",
                    "compose_service": "api",
                },
                {
                    "name": "manual_service",
                    "status": "unknown",
                    "reason": "no-stack-label",
                    "candidate_files": [],
                },
            ],
        }

        output = render_deployment_map(report, load_messages("en"))

        self.assertIn("Mapped: 1 | Unknown: 1", output)
        self.assertIn("demo_api -> /swarm/demo/swarm-stack.yml", output)
        self.assertIn("[UNKNOWN] manual_service", output)

    def test_human_report_warns_when_only_path_ownership_is_verified(self) -> None:
        """Make source drift visible instead of presenting it as edit-safe."""

        report = {
            "deploy_roots": ["/swarm"],
            "renderer": {"available": True},
            "summary": {
                "service_count": 1,
                "mapped": 1,
                "unknown": 0,
                "ambiguous": 0,
                "source_unverified": 1,
            },
            "services": [
                {
                    "name": "demo_api",
                    "status": "mapped",
                    "reason": "matched-stack-service-source-drift",
                    "stack_file": "/swarm/demo/swarm-stack.yml",
                    "compose_service": "api",
                    "declared_image": "example/api:old",
                    "source_verified": False,
                }
            ],
        }

        output = render_deployment_map(report, load_messages("en"))

        self.assertIn("source is not safe for automatic editing", output)
        self.assertIn("declared image: example/api:old", output)
        self.assertIn("Source unverified: 1", output)

    def test_cli_writes_json_and_returns_success_for_complete_mapping(self) -> None:
        """Exercise the standalone command boundary without a Docker daemon."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stack_file = create_candidate(root, "apps/demo", "demo")
            payload = {"services": {"api": {"image": "example/api:1"}}}
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:1", "demo"
            )
            client = FakeComposeClient({stack_file: payload})
            output_file = root / "deployment-map.json"
            with (
                mock.patch.object(deployment_mapper, "DockerClient", return_value=client),
                mock.patch.object(
                    deployment_mapper, "collect_services", return_value=[service]
                ),
                redirect_stdout(io.StringIO()) as stdout,
            ):
                exit_code = deployment_mapper.main(
                    [
                        "--deploy-root",
                        str(root),
                        "--output-file",
                        str(output_file),
                    ]
                )

            stored = json.loads(output_file.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stored["services"][0]["status"], "mapped")
        self.assertIn("JSON mapping report written", stdout.getvalue())

    def test_cli_returns_review_code_for_unverified_source(self) -> None:
        """Do not let a mapped-but-stale path appear automation-ready."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stack_file = create_candidate(root, "apps/demo", "demo")
            client = FakeComposeClient(
                {stack_file: {"services": {"api": {"image": "example/api:old"}}}}
            )
            service = ServiceRecord(
                "service-id", "demo_api", "example/api:new", "demo"
            )
            with (
                mock.patch.object(deployment_mapper, "DockerClient", return_value=client),
                mock.patch.object(
                    deployment_mapper, "collect_services", return_value=[service]
                ),
                redirect_stdout(io.StringIO()),
            ):
                exit_code = deployment_mapper.main(["--deploy-root", str(root)])

        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
