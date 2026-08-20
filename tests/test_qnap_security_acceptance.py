"""Regression tests for the repository-owned QNAP acceptance workflow."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.qnap_security_schedule_acceptance import (
    hold_lock,
    report_contract_errors,
    semantic_version,
    validate_report,
    validate_version,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ACCEPTANCE_SCRIPT = REPOSITORY_ROOT / "tests" / "qnap_security_schedule_acceptance.sh"


def valid_report() -> dict[str, object]:
    """Return the smallest complete bounded running-container report."""

    return {
        "schema_version": 2,
        "completed_at": "2026-08-20T12:17:07Z",
        "summary": {
            "complete": True,
            "status": "vulnerable",
            "failed_images": 0,
            "scanned_images": 1,
            "vulnerable_images": 1,
            "clean_images": 0,
        },
        "scope": {
            "resource_type": "container",
            "coverage": "full",
            "inventory_failure_count": 0,
            "resource_count": 1,
        },
        "environment": {
            "container_scope": "running",
            "docker": {"inventory_mode": "containers"},
        },
        "policy": {
            "scout_timeout_minutes": 45,
            "scan_budget_minutes": 240,
        },
        "freshness": {
            "max_age_hours": 96,
            "last_successful_at": "2026-08-20T12:17:07Z",
            "fresh_until": "2026-08-24T12:17:07Z",
        },
        "images": [
            {
                "reference": "example/image:1",
                "duration_seconds": 2,
            }
        ],
    }


class QnapSecurityAcceptanceTests(unittest.TestCase):
    """Verify report checks and prevent another fragile pasted heredoc."""

    def test_version_requires_the_repository_owned_acceptance_release(self) -> None:
        """Accept future patch releases but reject the pasted-script release."""

        self.assertEqual(semantic_version("1.14.2"), (1, 14, 2))
        validate_version("1.14.2")
        validate_version("1.15.0")
        with self.assertRaisesRegex(ValueError, "1.14.2"):
            validate_version("1.14.1")

    def test_complete_running_container_report_passes(self) -> None:
        """Accept clean or vulnerable evidence only when execution completed."""

        report = valid_report()
        self.assertEqual(report_contract_errors(report), [])
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                validate_report(path)

    def test_incomplete_report_lists_actionable_contract_failures(self) -> None:
        """Reject scanner and inventory failures instead of accepting partial data."""

        report = valid_report()
        report["summary"]["complete"] = False
        report["summary"]["failed_images"] = 1
        report["scope"]["inventory_failure_count"] = 1

        errors = report_contract_errors(report)

        self.assertIn("summary.complete must be true", errors)
        self.assertIn("failed_images must be zero", errors)
        self.assertIn("inventory_failure_count must be zero", errors)

    def test_shell_workflow_has_no_inline_heredoc_or_direct_scout_call(self) -> None:
        """Keep paste-sensitive parsing out and reuse the centralized Scout adapter."""

        source = ACCEPTANCE_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("<<", source)
        self.assertNotIn("docker scout", source)
        self.assertIn("--check-dependencies", source)
        self.assertIn("--install-security-cron", source)
        self.assertIn("--scheduled-security-check", source)
        self.assertIn("hold-lock", source)

    @unittest.skipUnless(os.name == "posix", "Advisory locking requires POSIX.")
    def test_lock_helper_waits_for_an_explicit_release_marker(self) -> None:
        """Avoid timing races when the QNAP dependency preflight is slow."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lock_path = root / "report.json.lock"
            ready_path = root / "ready"
            release_path = root / "release"
            release_path.write_text("release\n", encoding="utf-8")

            hold_lock(lock_path, ready_path, release_path, 1)

            self.assertEqual(ready_path.read_text(encoding="utf-8"), "ready\n")

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("bash"),
        "Bash syntax check requires a POSIX Bash runtime.",
    )
    def test_shell_workflow_parses_before_qnap_execution(self) -> None:
        """Catch unmatched quotes before the acceptance command is published."""

        completed = subprocess.run(
            ["bash", "-n", str(ACCEPTANCE_SCRIPT)],
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
