"""Tests for swarm-info installation and runtime dependency preflights.

The executable checks use the existing deterministic Docker fake and never
contact a Docker daemon, registry, or network service. They are skipped when a
native Bash executable is unavailable, while static wiring tests still run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_SCRIPT = REPOSITORY_ROOT / "res" / "dependency_check.sh"
UPDATE_SCRIPT = REPOSITORY_ROOT / "res" / "update_tool.sh"
FAKE_DOCKER = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_docker.py"
FAKE_GIT = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_git.py"


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

    def run_dependency_check(
        self, scenario: str, mode: str, standalone_scout: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """Run the dependency checker with a fake Docker executable.

        Args:
            scenario: Behavior selected through ``FAKE_DOCKER_SCENARIO``.
            mode: Dependency-check mode without the leading double dash.
            standalone_scout: Provide a working direct Scout executable while
                Docker's plugin dispatcher remains unavailable.

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

            # The dependency contract checks presence only; keep this fixture
            # independent from the host/container package set.
            fake_bc = fake_bin / "bc"
            fake_bc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bc.chmod(0o755)

            if standalone_scout:
                fake_scout = fake_bin / "docker-scout"
                fake_scout.write_text(
                    "#!/bin/sh\n"
                    "[ \"$1\" = version ] || exit 1\n"
                    "echo 'version: v1.24.0 (linux/amd64)'\n",
                    encoding="utf-8",
                )
                fake_scout.chmod(0o755)

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
    def test_standalone_scout_satisfies_qnap_security_preflight(self) -> None:
        """Accept a valid direct binary when vendor Docker ignores plugins."""

        result = self.run_dependency_check(
            "missing-scout", "security", standalone_scout=True
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("via ", result.stdout)
        self.assertIn("docker-scout", result.stdout)

    @unittest.skipUnless(
        BASH_AVAILABLE, "Native Bash is required for shell execution."
    )
    def test_missing_compose_explains_declarative_remediation_dependency(
        self,
    ) -> None:
        """Keep mapping unavailable instead of silently guessing stack source."""

        result = self.run_dependency_check("missing-compose", "all")
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2, output)
        self.assertIn("docker-compose-plugin", output)
        self.assertIn("docker compose version", output)
        self.assertIn("declarative remediation", output)

    @unittest.skipUnless(
        BASH_AVAILABLE, "Native Bash is required for shell execution."
    )
    def test_missing_compose_does_not_block_scan_only_mode(self) -> None:
        """Keep Docker Compose independent from the all-image Scout scan."""

        result = self.run_dependency_check("missing-compose", "scan")
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertNotIn("docker-compose-plugin", output)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_non_manager_is_a_core_failure(self) -> None:
        """Reject a Docker node that cannot inventory all Swarm services.

        Returns:
            Nothing.
        """

        result = self.run_dependency_check("not-manager", "core")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Swarm is not active", result.stderr)

    def test_installer_runs_shared_capability_preflight(self) -> None:
        """Ensure installation validates the applicable checked-out runtime.

        Returns:
            Nothing.
        """

        source = (REPOSITORY_ROOT / "setup" / "linux-cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('local check_mode="all"', source)
        self.assertIn('check_mode="security"', source)
        self.assertIn('bash "$dependency_script" "--$check_mode"', source)
        self.assertIn("swarm-info is installed", source)
        self.assertNotIn(
            'chmod 0755 "${INSTALL_DIRECTORY}/res/dependency_check.sh"', source
        )

    def test_cli_exposes_explicit_and_initial_preflight(self) -> None:
        """Keep dependency checks accessible and automatic for interactive use.

        Returns:
            Nothing.
        """

        source = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res" / "vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--check-dependencies", source)
        self.assertIn('selected_action="check-dependencies"', source)
        self.assertIn("check_swarm_info_dependencies all", source)
        self.assertIn("check_swarm_info_dependencies scan", bridge)
        self.assertIn("sys.version_info < (3, 10)", bridge)

    def test_core_preflight_requires_restart_rate_calculator(self) -> None:
        """Keep the JSON producer's ``bc`` dependency explicit.

        Returns:
            Nothing.
        """

        source = DEPENDENCY_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("command -v bc", source)
        self.assertIn("apt-get install -y bc", source)
        self.assertIn("accurate restart-rate calculations", source)
        self.assertIn("docker compose version", source)
        self.assertIn("docker-compose-plugin", source)

    def test_portable_security_preflight_excludes_swarm_only_dependencies(self) -> None:
        """Keep standalone/QNAP readiness separate from manager operations."""

        dependency_source = DEPENDENCY_SCRIPT.read_text(encoding="utf-8")
        bridge_source = (
            REPOSITORY_ROOT / "res" / "vulnerability_cli.sh"
        ).read_text(encoding="utf-8")
        installer_source = (
            REPOSITORY_ROOT / "setup" / "linux-cli.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("check_security_core_dependencies", dependency_source)
        self.assertIn('CHECK_MODE="security"', dependency_source)
        self.assertIn("Docker daemon access is available for local inventory", dependency_source)
        self.assertIn("getcfg Python3 Install_Path", dependency_source)
        self.assertIn("opt/python3/bin/python3", dependency_source)
        self.assertIn("getcfg Python3 Install_Path", bridge_source)
        self.assertIn("opt/python3/bin/python3", bridge_source)
        self.assertIn(".tmp-scout", dependency_source)
        self.assertIn("getcfg QGit Install_Path", installer_source)
        self.assertIn('"$GIT_COMMAND" clone', installer_source)
        self.assertIn('check_mode="security"', installer_source)
        self.assertIn('touch "${HOME}/.profile"', installer_source)
        self.assertIn("--check-only", installer_source)
        self.assertIn("--install-missing", installer_source)
        self.assertIn("pacman", installer_source)
        self.assertIn("apk", installer_source)
        self.assertIn("zypper install", dependency_source)
        self.assertIn("pacman -S --needed", dependency_source)
        self.assertIn("apk add", dependency_source)


class SelfUpdateTests(unittest.TestCase):
    """Verify that self-update accepts only safe fast-forward states."""

    def run_self_update(
        self, scenario: str
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        """Run the updater with a deterministic fake Git executable.

        Args:
            scenario: Git state selected through ``FAKE_GIT_SCENARIO``.

        Returns:
            Completed updater process and normalized Git invocation arrays.
        """

        with tempfile.TemporaryDirectory() as temporary_directory:
            fake_bin = Path(temporary_directory)
            fake_git = fake_bin / "git"
            git_log = fake_bin / "git-calls.jsonl"
            shutil.copy2(FAKE_GIT, fake_git)
            fake_git.chmod(0o755)

            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["FAKE_GIT_SCENARIO"] = scenario
            environment["FAKE_GIT_LOG"] = str(git_log)
            result = subprocess.run(
                ["bash", str(UPDATE_SCRIPT)],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=15,
            )
            commands = [
                json.loads(line)
                for line in git_log.read_text(encoding="utf-8").splitlines()
            ]
            return result, commands

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_current_checkout_succeeds_without_merge(self) -> None:
        """Report an up-to-date checkout without changing Git history.

        Returns:
            Nothing.
        """

        result, commands = self.run_self_update("current")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already up to date", result.stdout)
        self.assertFalse(any(command[:1] == ["merge"] for command in commands))

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_behind_checkout_uses_fast_forward_merge(self) -> None:
        """Apply a strictly behind upstream through `git merge --ff-only`.

        Returns:
            Nothing.
        """

        result, commands = self.run_self_update("behind")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["merge", "--ff-only", "origin/main"], commands)
        self.assertIn("swarm-info updated", result.stdout)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_dirty_checkout_is_preserved(self) -> None:
        """Refuse update before fetch when tracked work is modified.

        Returns:
            Nothing.
        """

        result, commands = self.run_self_update("dirty")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("local changes", result.stderr)
        self.assertIn(f"swarm-info checkout: {REPOSITORY_ROOT}", result.stdout)
        self.assertIn(f'cd "{REPOSITORY_ROOT}"', result.stdout)
        self.assertIn("git status", result.stdout)
        self.assertFalse(any(command[:1] == ["fetch"] for command in commands))
        self.assertFalse(any(command[:1] == ["merge"] for command in commands))

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for shell execution.")
    def test_divergent_checkout_is_preserved(self) -> None:
        """Refuse update when local and upstream commits have diverged.

        Returns:
            Nothing.
        """

        result, commands = self.run_self_update("diverged")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("local branch is 1 commit(s) ahead", result.stderr)
        self.assertFalse(any(command[:1] == ["merge"] for command in commands))

    def test_entrypoint_exposes_short_update_option(self) -> None:
        """Keep `swarm-info -u` wired to the guarded updater.

        Returns:
            Nothing.
        """

        source = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")

        self.assertIn("-u|--update", source)
        self.assertIn('selected_action="update"', source)
        self.assertIn('bash "$SCRIPT_DIR/update_tool.sh"', source)


if __name__ == "__main__":
    unittest.main()
