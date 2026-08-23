"""Tests for machine-readable security scan progress evidence."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import tempfile
import time
import unittest

from scripts.scan_status import ScanStatusSession, next_daily_run, status_path_for


class ScanStatusTests(unittest.TestCase):
    """Verify paths, heartbeat progress, and terminal state publication."""

    def test_status_path_matches_contract(self) -> None:
        self.assertEqual(
            status_path_for(Path("/evidence/security_scan-running.json")),
            Path("/evidence/security_scan-running.status.json"),
        )

    def test_next_daily_run_rolls_to_tomorrow_after_schedule(self) -> None:
        now = dt.datetime(2026, 8, 23, 4, 0, tzinfo=dt.timezone.utc)

        next_run = next_daily_run(3, 17, now)

        self.assertEqual(
            next_run,
            dt.datetime(2026, 8, 24, 3, 17, tzinfo=dt.timezone.utc),
        )

    def test_running_progress_and_terminal_state_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "security_scan-running.json"
            report.write_text(
                json.dumps({"completed_at": "2026-08-22T03:20:00Z"}),
                encoding="utf-8",
            )
            session = ScanStatusSession(
                report,
                next_run_at="2026-08-24T03:17:00Z",
                heartbeat_seconds=0.01,
            )

            session.start()
            session.progress(
                {
                    "phase": "scanning",
                    "current": 1,
                    "total": 3,
                    "image": "demo:1",
                }
            )
            first = json.loads(session.path.read_text(encoding="utf-8"))
            time.sleep(0.02)
            second = json.loads(session.path.read_text(encoding="utf-8"))
            session.finish("complete")
            terminal = json.loads(session.path.read_text(encoding="utf-8"))

            self.assertEqual(first["status"], "running")
            self.assertEqual(first["progress"]["current"], 1)
            self.assertGreaterEqual(second["heartbeat_at"], first["heartbeat_at"])
            self.assertEqual(terminal["status"], "complete")
            self.assertEqual(
                terminal["last_complete_report_at"],
                "2026-08-22T03:20:00Z",
            )


if __name__ == "__main__":
    unittest.main()
