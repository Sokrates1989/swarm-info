"""Contract tests for concise service and vulnerability operator pages."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import unittest

from scripts.operator_report import (
    load_messages,
    message,
    render_service_health,
    render_vulnerabilities,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIRECTORY = REPOSITORY_ROOT / "example-output"


def load_example(name: str) -> dict[str, object]:
    """Load one checked-in operator report fixture."""

    payload = json.loads((EXAMPLE_DIRECTORY / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{name} must contain a JSON object")
    return payload


class OperatorReportTests(unittest.TestCase):
    """Verify concise evidence, localization, and remediation contracts."""

    def test_locale_catalogs_have_identical_keys(self) -> None:
        """Require complete German and English message catalogs."""

        self.assertEqual(set(load_messages("en")), set(load_messages("de")))

    def test_invalid_image_id_guidance_preserves_docker_template_braces(self) -> None:
        """Render the copy-ready Docker inspect template exactly."""

        rendered = message(
            load_messages("en"),
            "security.focusError.invalid-image-id",
            selector="sha256:short",
        )

        self.assertIn("--format '{{.Image}}'", rendered)

    def test_service_page_lists_only_services_needing_attention(self) -> None:
        """Keep the operational page focused while preserving counts."""

        report = load_example("swarm-info.json")
        output, exit_code = render_service_health(
            report,
            load_messages("en"),
            dt.datetime(2026, 2, 10, 17, tzinfo=dt.timezone.utc),
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("Managed: 4 | Healthy: 2 | Degraded: 2 | Down: 0", output)
        self.assertIn("reminderbot_bot", output)
        self.assertIn("reminderbot_schedulecheck", output)
        self.assertNotIn("reminderbot_db", output)
        self.assertIn("docker service ps <SERVICE> --no-trunc", output)

    def test_vulnerability_page_gives_copy_ready_remediation(self) -> None:
        """Turn valid risk evidence into concrete operator actions."""

        report = load_example("vulnerability-scan.json")
        output, exit_code = render_vulnerabilities(
            report,
            Path("/info_json/vulnerability_scan.json"),
            load_messages("en"),
            dt.datetime(2026, 8, 9, 9, tzinfo=dt.timezone.utc),
            30,
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("How to fix this", output)
        self.assertIn("example_api", output)
        self.assertIn("docker scout recommendations", output)
        self.assertIn("docker scout cves --only-fixed", output)
        self.assertIn("docker stack deploy", output)
        self.assertIn("swarm-info --scan-vulnerabilities", output)

    def test_stale_evidence_offers_warned_scan_instead_of_risk_counts(self) -> None:
        """Never present expired vulnerability evidence as current."""

        report = load_example("vulnerability-scan.json")
        output, exit_code = render_vulnerabilities(
            report,
            Path("/info_json/vulnerability_scan.json"),
            load_messages("en"),
            dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc),
            30,
        )

        self.assertEqual(exit_code, 3)
        self.assertIn("report is stale", output)
        self.assertIn("limit 30h", output)
        self.assertIn("take several minutes", output)
        self.assertIn("swarm-info --scan-vulnerabilities", output)
        self.assertNotIn("Fixable findings:", output)

    def test_container_report_uses_compose_and_local_security_guidance(self) -> None:
        """Render QNAP evidence without leaking Swarm-only commands or wording."""

        image_id = "sha256:" + ("a" * 64)
        report = {
            "completed_at": "2026-08-17T10:00:00Z",
            "environment": {"container_scope": "running"},
            "scope": {"resource_type": "container", "resource_count": 1},
            "policy": {"platform": "linux/amd64"},
            "summary": {
                "complete": True,
                "status": "vulnerable",
                "critical": 1,
                "high": 3,
                "affected_resource_count": 1,
                "vulnerable_images": 1,
            },
            "images": [
                {
                    "reference": "wordpress:latest",
                    "local_image_id": image_id,
                    "status": "vulnerable",
                    "counts": {"critical": 1, "high": 3},
                    "services": [
                        {
                            "name": "telegram_homepage",
                            "stack": "docker-wordpress-nginx",
                            "compose_service": "telegram_homepage",
                            "compose_working_dir": "/share/tools/wordpress",
                            "compose_config_files": [
                                "/share/tools/wordpress/docker-compose.yml"
                            ],
                        }
                    ],
                }
            ],
        }

        output, exit_code = render_vulnerabilities(
            report,
            Path("/share/Public/swarm-info/security_scan-running.json"),
            load_messages("en"),
            dt.datetime(2026, 8, 17, 11, tzinfo=dt.timezone.utc),
            30,
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("affected containers", output)
        self.assertIn("Containers: telegram_homepage", output)
        self.assertIn("/share/tools/wordpress/docker-compose.yml", output)
        self.assertIn(f"local://{image_id}", output)
        self.assertIn("swarm-info --security-check --container-mode", output)
        self.assertNotIn("docker stack deploy", output)
        self.assertNotIn("affected services", output)

    def test_incomplete_container_report_explains_missing_image_recovery(self) -> None:
        """Turn an unavailable exact local image into guarded Compose recovery."""

        image_id = "sha256:" + ("b" * 64)
        report = {
            "completed_at": "2026-08-17T10:00:00Z",
            "environment": {"container_scope": "running"},
            "scope": {"resource_type": "container", "resource_count": 1},
            "summary": {"complete": False, "status": "incomplete"},
            "images": [
                {
                    "reference": "wordpress:latest",
                    "local_image_id": image_id,
                    "status": "error",
                    "error_code": "local-image-unavailable",
                    "services": [
                        {
                            "name": "telegram_homepage",
                            "stack": "wordpress",
                            "compose_service": "web",
                            "compose_working_dir": "/share/wordpress",
                            "compose_config_files": ["/share/wordpress/compose.yml"],
                        }
                    ],
                }
            ],
        }

        output, exit_code = render_vulnerabilities(
            report,
            Path("/share/Public/swarm-info/security_scan-running.json"),
            load_messages("en"),
            dt.datetime(2026, 8, 17, 11, tzinfo=dt.timezone.utc),
            30,
        )

        self.assertEqual(exit_code, 3)
        self.assertIn("Exact local-image recovery required", output)
        self.assertIn("verify", output.lower())
        self.assertIn("docker compose -f /share/wordpress/compose.yml pull web", output)
        self.assertIn("Registry fallback is intentionally disabled", output)

    def test_legacy_container_report_never_renders_none_as_compose_evidence(self) -> None:
        """Keep old reports without Compose labels safe and copy-ready."""

        image_id = "sha256:" + ("c" * 64)
        report = {
            "completed_at": "2026-08-17T10:00:00Z",
            "environment": {"container_scope": "all"},
            "scope": {"resource_type": "container", "resource_count": 1},
            "summary": {"complete": False, "status": "incomplete"},
            "images": [
                {
                    "reference": "legacy/image:latest",
                    "local_image_id": image_id,
                    "status": "error",
                    "error_code": "local-image-unavailable",
                    "services": [
                        {
                            "name": "legacy_container",
                            "stack": "legacy-project",
                            "compose_service": None,
                            "compose_working_dir": None,
                        }
                    ],
                }
            ],
        }

        output, exit_code = render_vulnerabilities(
            report,
            Path("/share/Public/swarm-info/security_scan.json"),
            load_messages("en"),
            dt.datetime(2026, 8, 17, 11, tzinfo=dt.timezone.utc),
            30,
        )

        self.assertEqual(exit_code, 3)
        self.assertNotIn("None", output)
        self.assertNotIn("cd None", output)
        self.assertNotIn("Compose: legacy-project", output)
        self.assertIn("cd <COMPOSE_WORKING_DIR>", output)


class CliOperatorContractTests(unittest.TestCase):
    """Lock public navigation, version, manual, and short options together."""

    def test_version_and_manual_are_synchronized(self) -> None:
        """Require the authoritative initial version on every version surface."""

        version = (REPOSITORY_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        manual = (REPOSITORY_ROOT / "docs" / "man" / "swarm-info.1").read_text(
            encoding="utf-8"
        )

        self.assertEqual(version, "1.18.0")
        self.assertIn(f"swarm-info {version}", manual)

    def test_service_page_flows_directly_to_vulnerability_page(self) -> None:
        """Keep health and security evidence adjacent in the default tour."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        services = (REPOSITORY_ROOT / "res" / "services_info.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("total_pages=7", entrypoint)
        self.assertIn('-d|--service-health)', entrypoint)
        self.assertIn('-v|--vulnerabilities)', entrypoint)
        self.assertIn('-V|--version|version)', entrypoint)
        self.assertIn('"$SCRIPT_DIR/vulnerability_info.sh"', services)
        self.assertIn('--service-health', services)
        self.assertIn('SWARM_INFO_DEPLOY_ROOTS="$deployment_root_value"', entrypoint)
        self.assertIn('REMEDIATION_POLICY_FILE="$REMEDIATION_POLICY_FILE"', entrypoint)
        vulnerability_page = (
            REPOSITORY_ROOT / "res" / "vulnerability_info.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'read -r -a DEPLOYMENT_ROOTS <<< "$SWARM_INFO_DEPLOY_ROOTS"',
            vulnerability_page,
        )

    def test_deployment_mapper_is_wired_as_a_read_only_public_action(self) -> None:
        """Keep the standalone acceptance command connected to its Python CLI."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res" / "operator_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('selected_action="map-service-deployments"', entrypoint)
        self.assertIn('"map-service-deployments")', entrypoint)
        self.assertIn("-m scripts.deployment_mapper", bridge)
        self.assertNotIn("docker service update", bridge)

    def test_remediation_wrapper_can_create_policy_in_invoking_deployment_repo(self) -> None:
        """Keep policy ownership with the deployment checkout despite internal cd."""

        bridge = (REPOSITORY_ROOT / "res" / "operator_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('local invocation_directory="$PWD"', bridge)
        self.assertIn('[ -d "$invocation_directory/.git" ]', bridge)
        self.assertIn('[ -d "$invocation_directory/configs" ]', bridge)
        self.assertIn(
            'selected_policy_file="$invocation_directory/configs/remediation-policy.json"',
            bridge,
        )

    def test_candidate_discovery_reuses_invoking_repository_policy(self) -> None:
        """Find reviewed successor evidence before the bridge changes directory."""

        bridge = (REPOSITORY_ROOT / "res" / "vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("run_image_update_discovery()", bridge)
        self.assertIn("-m scripts.image_update_cli", bridge)
        self.assertIn('local invocation_directory="$PWD"', bridge)
        self.assertIn(
            '[ -r "$invocation_directory/configs/remediation-policy.json" ]',
            bridge,
        )
        self.assertIn("--allow-registry-host", bridge)

    def test_help_and_manual_cover_new_public_commands(self) -> None:
        """Prevent drift between help routing and the installed manual."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        manual = (REPOSITORY_ROOT / "docs" / "man" / "swarm-info.1").read_text(
            encoding="utf-8"
        )

        for command in (
            "--service-health",
            "--vulnerabilities",
            "--map-service-deployments",
            "--deploy-root",
            "--remediate-vulnerabilities",
            "--remediation-policy",
            "--remediation-plan-file",
            "--deployment-map-file",
            "--force-auto-remedy-attempt",
            "--allow-runtime-override",
            "--service",
            "--image",
            "--stack",
            "--compare-image-update",
            "--discover-image-updates",
            "--assess-image-updates",
            "--allow-registry-host",
            "--vulnerability-report-file",
            "--candidate-report-file",
            "--max-registry-tags",
            "--current-image",
            "--candidate-image",
            "--security-check",
            "--runtime-mode",
            "--container-mode",
            "--container-scope",
            "--container",
            "--image-id",
            "--os",
            "--version",
        ):
            self.assertIn(command, entrypoint)
            self.assertIn(command.replace("--", r"\-\-"), manual)

    def test_batch_image_assessment_is_wired_to_the_python_boundary(self) -> None:
        """Keep candidate and source reports connected to the batch scanner."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res" / "vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('selected_action="assess-image-updates"', entrypoint)
        self.assertIn('"assess-image-updates")', entrypoint)
        self.assertIn("run_image_update_assessment()", bridge)
        self.assertIn("-m scripts.image_update_assessment_cli", bridge)
        self.assertIn("--candidate-report-file", bridge)
        self.assertIn("--vulnerability-report-file", bridge)
        self.assertIn('--os "$SECURITY_HOST_OS"', bridge)

    def test_qnap_report_discovery_and_page_routing_are_mode_aware(self) -> None:
        """Prefer QNAP evidence and never open Swarm remediation for containers."""

        bridge = (REPOSITORY_ROOT / "res" / "operator_cli.sh").read_text(
            encoding="utf-8"
        )
        page = (REPOSITORY_ROOT / "res" / "vulnerability_info.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("security_scan-running.json", bridge)
        self.assertIn("SWARM_INFO_SECURITY_REPORT_FILE", bridge)
        self.assertIn("report-context", bridge)
        self.assertIn('[ "$report_resource_type" = "container" ]', page)
        self.assertIn('[ "$report_resource_type" = "service" ]', page)
        self.assertIn("--security-check", page)


if __name__ == "__main__":
    unittest.main()
