"""Behavioral tests for scheduled QNAP/local-container security operation."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from scripts.operator_report import load_messages
from scripts.security_cron import (
    BLOCK_BEGIN,
    BLOCK_END,
    QnapSystemCrontabClient,
    SecurityCronSettings,
    cron_command,
    install_schedule,
    remove_schedule,
)
from scripts.security_job import (
    execute_security_job,
    security_cache_is_fresh,
    validate_security_job_policy,
)
from scripts.vulnerability_cron import CommandResult as CronCommandResult
from scripts.vulnerability_job import parse_utc_timestamp
from tests.test_vulnerability_scan import FakeDockerHarness


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class MemoryCrontabClient:
    """Store a complete current-user crontab without operating-system changes."""

    def __init__(self, content: str = "") -> None:
        """Initialize the fake with optional unrelated crontab content."""

        self.content = content
        self.writes = 0

    def run(
        self, arguments: list[str], input_text: str | None = None
    ) -> CronCommandResult:
        """Emulate crontab listing and atomic replacement operations."""

        if arguments == ["-l"]:
            return CronCommandResult(0, self.content, "")
        if arguments == ["-"] and input_text is not None:
            self.content = input_text
            self.writes += 1
            return CronCommandResult(0, "", "")
        return CronCommandResult(64, "", "unsupported")


class SecurityJobTests(unittest.TestCase):
    """Verify running scope, bounded policy, and exact-scope cache reuse."""

    def test_running_job_publishes_policy_and_reuses_matching_evidence(self) -> None:
        """Scan once, retain timing evidence, then avoid repeat Scout work."""

        harness = FakeDockerHarness("local-containers")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                output = root / "security_scan-running.json"
                environment = {"HOME": str(root), "PATH": ""}
                reference_time = dt.datetime.now(dt.timezone.utc)

                first_status = execute_security_job(
                    output,
                    "auto",
                    "qnap",
                    "running",
                    96,
                    14,
                    True,
                    harness.client().with_scout_timeout(2700),
                    environment,
                    reference_time,
                    72,
                    45,
                    240,
                )
                report = json.loads(output.read_text(encoding="utf-8"))
                completed_at = parse_utc_timestamp(report["completed_at"])
                self.assertIsNotNone(completed_at)
                scans_before = sum(
                    command[:2] == ["scout", "cves"]
                    for command in harness.commands()
                )

                second_status = execute_security_job(
                    output,
                    "auto",
                    "qnap",
                    "running",
                    96,
                    14,
                    False,
                    harness.client().with_scout_timeout(2700),
                    environment,
                    completed_at + dt.timedelta(hours=1),
                    72,
                    45,
                    240,
                )
                scans_after = sum(
                    command[:2] == ["scout", "cves"]
                    for command in harness.commands()
                )

            self.assertEqual(first_status, 2)
            self.assertEqual(second_status, 2)
            self.assertEqual(report["environment"]["container_scope"], "running")
            self.assertEqual(report["scope"]["resource_count"], 2)
            self.assertEqual(report["policy"]["scout_timeout_minutes"], 45)
            self.assertEqual(report["policy"]["scan_budget_minutes"], 240)
            self.assertEqual(report["freshness"]["max_age_hours"], 96)
            self.assertTrue(
                all("duration_seconds" in image for image in report["images"])
            )
            self.assertEqual(scans_before, scans_after)
            self.assertEqual(scans_before, 2)
        finally:
            harness.close()

    def test_cache_rejects_evidence_without_matching_execution_bounds(self) -> None:
        """Never reuse reports created before or outside scheduled limits."""

        now = dt.datetime.now(dt.timezone.utc)
        report = {
            "completed_at": now.isoformat().replace("+00:00", "Z"),
            "summary": {"complete": True},
            "scope": {"image_fingerprint": "scope-1", "coverage": "full"},
            "environment": {
                "container_scope": "running",
                "docker": {"inventory_mode": "containers"},
            },
            "policy": {
                "platform": "linux/amd64",
                "scout_timeout_minutes": 45,
                "scan_budget_minutes": 240,
            },
        }

        self.assertTrue(
            security_cache_is_fresh(
                report, "scope-1", "linux/amd64", "running", 72, 45, 240, now
            )
        )
        report["policy"].pop("scan_budget_minutes")
        self.assertFalse(
            security_cache_is_fresh(
                report, "scope-1", "linux/amd64", "running", 72, 45, 240, now
            )
        )

    def test_policy_rejects_stale_gaps_and_impossible_budgets(self) -> None:
        """Keep direct job invocations as safe as cron installation."""

        catalog = load_messages("en")
        validate_security_job_policy(72, 96, 45, 240, catalog)
        with self.assertRaisesRegex(ValueError, "lower than"):
            validate_security_job_policy(96, 96, 45, 240, catalog)
        with self.assertRaisesRegex(ValueError, "at least"):
            validate_security_job_policy(72, 96, 45, 30, catalog)


class SecurityCronTests(unittest.TestCase):
    """Verify separate, idempotent current-user cron block ownership."""

    def settings(self) -> SecurityCronSettings:
        """Return deterministic QNAP schedule settings."""

        return SecurityCronSettings(
            command_path=Path("/share/homes/Patrick/.local/bin/swarm-info"),
            output_file=Path(
                "/share/Public/swarm-info/security_scan-running.json"
            ),
            platform="auto",
            host_os="qnap",
            container_scope="running",
            hour=3,
            minute=17,
            cache_age_hours=72,
            max_age_hours=96,
            history_days=14,
            scout_timeout_minutes=45,
            scan_budget_minutes=240,
            log_file=Path("/share/Public/swarm-info/security_scan-running.log"),
        )

    def test_install_is_idempotent_and_preserves_other_managed_workflows(self) -> None:
        """Replace only this block while retaining health and Swarm schedules."""

        existing = (
            "*/5 * * * * /usr/local/bin/health\n"
            "# BEGIN swarm-info managed vulnerability scan\n"
            "17 3 * * * /root/.local/bin/swarm-info --scheduled-vulnerability-scan\n"
            "# END swarm-info managed vulnerability scan\n"
        )
        client = MemoryCrontabClient(existing)

        install_schedule(self.settings(), client)
        install_schedule(self.settings(), client)

        self.assertIn("/usr/local/bin/health", client.content)
        self.assertIn("--scheduled-vulnerability-scan", client.content)
        self.assertEqual(client.content.count(BLOCK_BEGIN), 1)
        self.assertEqual(client.content.count(BLOCK_END), 1)
        self.assertEqual(client.writes, 2)

    def test_rendered_command_uses_running_scope_and_bounded_defaults(self) -> None:
        """Keep expensive all-container scans out of the scheduled path."""

        rendered = cron_command(self.settings())

        self.assertIn("--scheduled-security-check", rendered)
        self.assertIn("PATH=/share/homes/Patrick/.local/bin:$PATH", rendered)
        self.assertIn("--container-scope running", rendered)
        self.assertIn("--cache-age-hours 72", rendered)
        self.assertIn("--max-age-hours 96", rendered)
        self.assertIn("--scout-timeout-minutes 45", rendered)
        self.assertIn("--scan-budget-minutes 240", rendered)
        self.assertIn(">>", rendered)

    def test_qnap_command_switches_back_to_non_root_runtime_user(self) -> None:
        """Use root only for persistence, never for the long Scout workload."""

        settings = dataclasses.replace(
            self.settings(),
            runtime_user="Patrick",
            runtime_home=Path("/share/homes/Patrick"),
        )

        rendered = cron_command(settings)

        self.assertTrue(rendered.startswith("/bin/su - Patrick -c "))
        self.assertIn("HOME=/share/homes/Patrick", rendered)
        self.assertIn("PATH=/share/homes/Patrick/.local/bin:$PATH", rendered)

    def test_qnap_system_table_writer_replaces_content_atomically(self) -> None:
        """Preserve an exact persistent table while avoiding partial writes."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            crontab = Path(temporary_directory) / "crontab"
            crontab.write_text("old\n", encoding="utf-8")
            client = QnapSystemCrontabClient(
                crontab, Path(temporary_directory) / "crond.sh"
            )

            client._write_atomic("new\n")

            self.assertEqual(crontab.read_text(encoding="utf-8"), "new\n")
            self.assertEqual(list(crontab.parent.glob(".swarm-info-*")), [])

    def test_remove_preserves_unrelated_entries(self) -> None:
        """Remove only this workflow's marked block."""

        client = MemoryCrontabClient(
            "0 1 * * * /usr/local/bin/backup\n\n"
        )
        install_schedule(self.settings(), client)

        changed = remove_schedule(client)

        self.assertTrue(changed)
        self.assertNotIn(BLOCK_BEGIN, client.content)
        self.assertIn("/usr/local/bin/backup", client.content)

    def test_shell_entrypoint_exposes_security_schedule_actions(self) -> None:
        """Keep installation, execution, status, and removal publicly wired."""

        source = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")

        self.assertIn("--install-security-cron", source)
        self.assertIn("--scheduled-security-check", source)
        self.assertIn("--security-status", source)
        self.assertIn("--remove-security-cron", source)

    def test_locale_catalogs_keep_security_job_keys_in_sync(self) -> None:
        """Require complete English and German scheduled-job translations."""

        self.assertEqual(set(load_messages("en")), set(load_messages("de")))


if __name__ == "__main__":
    unittest.main()
