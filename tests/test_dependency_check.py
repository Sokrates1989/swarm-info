"""Tests for swarm-info installation and runtime dependency preflights.

The executable checks use the existing deterministic Docker fake and never
contact a Docker daemon, registry, or network service. They are skipped when a
native Bash executable is unavailable, while static wiring tests still run.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_SCRIPT = REPOSITORY_ROOT / "res" / "dependency_check.sh"
FAKE_DOCKER = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_docker.py"


def native_bash_is_available() -> bool:
    """Return whether Bash can execute directly in the current environment.

    Returns:
        ``True`` when ``bash --version`` starts and succeeds; otherwise
        ``False``. Windows installations that expose only an inaccessible WSL
        launcher therefore skip native shell checks.
    """

    bash_command = shutil.which("bash")
    if bash_command is None:
        return False
    try:
        result = subprocess.run(
            [bash_command, "--version"],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


BASH_AVAILABLE = native_bash_is_available()


class DependencyCheckTests(unittest.TestCase):
    """Verify readiness exit codes, guidance, and entry-point integration."""

    def run_dependency_check(self, scenario: str, mode: str) -> subprocess.CompletedProcess[str]:
        """Run the dependency checker with a fake Docker executable.

        Args:
            scenario: Behavior selected through ``FAKE_DOCKER_SCENARIO``.
            mode: Dependency-check mode without the leading double dash.

        Returns:
            Completed Bash process with captured text output.
        """

        with tempfile.TemporaryDirectory() as temporary_directory:
            fake_bin = Path(temporary_directory)
            fake_docker = fake_bin / "docker"
            shutil.copy2(FAKE_DOCKER, fake_docker)
            fake_docker.chmod(0o755)

            # Git is a deterministic core dependency; no repository access is needed.
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\necho 'git version 2.45.0-fake'\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)

            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["FAKE_DOCKER_SCENARIO"] = scenario
            return subprocess.run(
                ["bash", str(DEPENDENCY_SCRIPT), f"--{mode}"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=15,
            )

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_all_dependencies_ready(self) -> None:
        """Return success when manager, Python, and Scout checks pass.

        Returns:
            Nothing.
        """

        result = self.run_dependency_check("default", "all")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All selected swarm-info dependencies are ready", result.stdout)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_missing_scout_has_distinct_status_and_install_help(self) -> None:
        """Keep optional scanner absence distinct from a core setup failure.

        Returns:
            Nothing.
        """

        result = self.run_dependency_check("missing-scout", "all")
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2, output)
        self.assertIn("docker/scout-cli/main/install.sh", output)
        self.assertIn("docker scout version", output)
        self.assertIn("https://docs.docker.com/scout/", output)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_non_manager_is_a_core_failure(self) -> None:
        """Reject a Docker node that cannot inventory all Swarm services.

        Returns:
            Nothing.
        """

        result = self.run_dependency_check("not-manager", "core")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Swarm is not active", result.stderr)

    def test_installer_runs_shared_full_preflight(self) -> None:
        """Ensure installation validates the checked-out runtime dependencies.

        Returns:
            Nothing.
        """

        source = (REPOSITORY_ROOT / "setup" / "linux-cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('bash "$dependency_script" --all', source)
        self.assertIn("Core swarm-info is installed", source)
        self.assertIn("chmod +x \"${INSTALL_DIRECTORY}/res/dependency_check.sh\"", source)

    def test_cli_exposes_explicit_and_initial_preflight(self) -> None:
        """Keep dependency checks accessible and automatic for interactive use.

        Returns:
            Nothing.
        """

        source = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")

        self.assertIn("--check-dependencies", source)
        self.assertIn('selected_action="check-dependencies"', source)
        self.assertIn("check_swarm_info_dependencies all", source)
        self.assertIn("check_swarm_info_dependencies scan", source)
        self.assertIn("sys.version_info < (3, 10)", source)


if __name__ == "__main__":
    unittest.main()
