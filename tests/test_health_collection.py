"""Verify lifecycle-aware Docker Swarm health collection."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_dependency_check import BASH_AVAILABLE


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEALTH_SCRIPT = REPOSITORY_ROOT / "res" / "json_info.sh"
FAKE_DOCKER = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_docker.py"
FAKE_GIT = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_git.py"


class HealthCollectionContractTests(unittest.TestCase):
    """Protect lifecycle fields even when native Bash is unavailable."""

    def test_collector_exposes_monitoring_lifecycle_contract(self) -> None:
        """Keep Docker desired replicas separate from monitoring policy."""

        source = HEALTH_SCRIPT.read_text(encoding="utf-8")

        self.assertIn('"monitoring_expected_replicas"', source)
        self.assertIn('"lifecycle"', source)
        self.assertIn('"latest_task_state"', source)
        self.assertIn('swarm.cronjob.enable', source)
        self.assertIn('swarm-info.monitoring.lifecycle', source)
        self.assertIn("${svc_replicas%% *}", source)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_completed_jobs_are_idle_while_failed_jobs_alert(self) -> None:
        """Classify completed scheduled and one-shot work without false outages."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            fake_bin = temporary_root / "bin"
            fake_bin.mkdir()
            for source, name in ((FAKE_DOCKER, "docker"), (FAKE_GIT, "git")):
                target = fake_bin / name
                shutil.copy2(source, target)
                target.chmod(0o755)

            report_path = temporary_root / "swarm_info.json"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["FAKE_DOCKER_SCENARIO"] = "health-lifecycle"
            environment["FAKE_GIT_SCENARIO"] = "current"
            result = subprocess.run(
                [
                    "bash",
                    str(HEALTH_SCRIPT),
                    "--json",
                    "--output-file",
                    str(report_path),
                ],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            services = {service["name"]: service for service in report["services"]}

        self.assertEqual(report["summary"], {
            "total_services": 5,
            "healthy": 4,
            "degraded": 1,
            "down": 0,
        })
        self.assertEqual(services["demo_schedule"]["status"], "completed")
        self.assertEqual(services["demo_schedule"]["replicas_desired"], 1)
        self.assertEqual(
            services["demo_schedule"]["monitoring_expected_replicas"], 0
        )
        self.assertEqual(services["demo_migration"]["lifecycle"], "one-shot")
        self.assertEqual(services["demo_native_job"]["lifecycle"], "job")
        self.assertEqual(services["demo_failed_schedule"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
