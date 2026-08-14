"""Contract tests for concise service and vulnerability operator pages."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import unittest

from scripts.operator_report import (
    load_messages,
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


class CliOperatorContractTests(unittest.TestCase):
    """Lock public navigation, version, manual, and short options together."""

    def test_version_and_manual_are_synchronized(self) -> None:
        """Require the authoritative initial version on every version surface."""

        version = (REPOSITORY_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        manual = (REPOSITORY_ROOT / "docs" / "man" / "swarm-info.1").read_text(
            encoding="utf-8"
        )

        self.assertEqual(version, "1.6.0")
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
            "--security-check",
            "--runtime-mode",
            "--container-mode",
            "--container-scope",
            "--os",
            "--version",
        ):
            self.assertIn(command, entrypoint)
            self.assertIn(command.replace("--", r"\-\-"), manual)


if __name__ == "__main__":
    unittest.main()
