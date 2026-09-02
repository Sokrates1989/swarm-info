"""Tests for the two-phase SCWP-01 QNAP cron lifecycle gate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from tests.acceptance.scwp_01_qnap_lifecycle import (
    BLOCK_BEGIN,
    BLOCK_END,
    read_state,
    unmanaged_hash,
    write_state,
)


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tests/acceptance/scwp_01_qnap_lifecycle.sh"


class Scwp01QnapLifecycleTests(unittest.TestCase):
    """Keep the reboot gate secret-safe, resumable, and cron-preserving."""

    def test_unmanaged_hash_excludes_only_the_complete_owned_block(self) -> None:
        """Hash normalized unrelated entries without retaining managed content."""

        source = (
            "# unrelated\n"
            "17 2 * * * /share/private/job\n"
            f"{BLOCK_BEGIN}\n"
            "*/5 * * * * managed operational command\n"
            "17 3 * * * managed security command\n"
            f"{BLOCK_END}\n\n"
        )
        expected = hashlib.sha256(
            b"# unrelated\n17 2 * * * /share/private/job\n"
        ).hexdigest()

        self.assertEqual(unmanaged_hash(source), expected)

    def test_unmanaged_hash_rejects_incomplete_markers(self) -> None:
        """Never guess which cron content is owned when markers are damaged."""

        with self.assertRaisesRegex(ValueError, "markers are incomplete"):
            unmanaged_hash(f"unrelated\n{BLOCK_BEGIN}\nmanaged\n")
        with self.assertRaisesRegex(ValueError, "out of order"):
            unmanaged_hash(f"unrelated\n{BLOCK_END}\n{BLOCK_BEGIN}\n")

    def test_state_is_private_atomic_and_bound_to_commit_and_user(self) -> None:
        """Persist no cron contents and reject a different post-reboot checkout."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.json"
            write_state(path, "commit-a", "Patrick")

            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(read_state(path, "Patrick"), "commit-a")
            self.assertNotIn("17 2 * * *", path.read_text(encoding="utf-8"))
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["unmanaged_crontab_sha256"] = "a" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(read_state(path, "Patrick"), "commit-a")
            with self.assertRaisesRegex(ValueError, "runtime_user"):
                read_state(path, "SomeoneElse")

    def test_gate_is_two_phase_and_never_reboots_or_prints_crontab(self) -> None:
        """Require operator reboot while checking removal recovery and reinstall."""

        source = GATE.read_text(encoding="utf-8")
        for fragment in (
            'prepare|verify',
            '"$crond_restart" restart',
            'write-state',
            'read-state',
            '--remove-security-cron',
            'restore_schedule_on_failure',
            '[PASS] SCWP-01 QNAP reboot lifecycle passed',
            '--scheduled-container-state',
            '--scheduled-security-check',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn("sudo reboot", source)
        self.assertNotIn("run_privileged reboot", source)
        self.assertNotIn('cat "$crontab_path"', source)
        self.assertNotIn(
            "Unrelated persistent cron entries changed across reboot.", source
        )
        self.assertIn('baseline_hash=$(unmanaged_hash)', source)
        self.assertIn('merge-base --is-ancestor', source)

    @unittest.skipUnless(
        os.name == "posix" and Path("/bin/bash").exists(),
        "Bash syntax check requires POSIX Bash.",
    )
    def test_gate_parses_before_qnap_execution(self) -> None:
        """Catch shell syntax errors before publishing the host command."""

        completed = subprocess.run(
            ["/bin/bash", "-n", str(GATE)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
