"""Behavioral tests for the standalone Linux and QNAP bootstrap installer."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
INSTALLER = REPOSITORY_ROOT / "setup" / "linux-cli.sh"
FAKE_DOCKER = REPOSITORY_ROOT / "tests" / "fixtures" / "fake_docker.py"
CURRENT_VERSION = (REPOSITORY_ROOT / "VERSION").read_text(encoding="utf-8").strip()


def native_bash_is_available() -> bool:
    """Return whether a native Bash executable can run tests."""

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


class LinuxInstallerTests(unittest.TestCase):
    """Verify read-only preflight outcomes and cross-distribution wiring."""

    def run_preflight(
        self, scenario: str = "default"
    ) -> subprocess.CompletedProcess[str]:
        """Run the bootstrap preflight with deterministic host commands."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_bin = temporary_path / "bin"
            fake_home = temporary_path / "home"
            fake_bin.mkdir()
            fake_home.mkdir()

            fake_docker = fake_bin / "docker"
            shutil.copy2(FAKE_DOCKER, fake_docker)
            fake_docker.chmod(0o755)

            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\necho 'git version 2.45.0-fake'\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)

            fake_bc = fake_bin / "bc"
            fake_bc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bc.chmod(0o755)

            environment = os.environ.copy()
            environment["HOME"] = str(fake_home)
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["FAKE_DOCKER_SCENARIO"] = scenario
            result = subprocess.run(
                ["bash", str(INSTALLER), "--check-only"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=20,
            )
            self.assertFalse((fake_home / ".profile").exists())
            self.assertFalse((fake_home / "tools").exists())
            return result

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_disposable_full_install_verifies_command_and_profiles(self) -> None:
        """Install into a disposable HOME without package or network access."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_bin = temporary_path / "bin"
            fake_home = temporary_path / "home"
            fake_bin.mkdir()
            fake_home.mkdir()

            fake_docker = fake_bin / "docker"
            shutil.copy2(FAKE_DOCKER, fake_docker)
            fake_docker.chmod(0o755)

            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = --version ]; then\n"
                "  echo 'git version 2.45.0-fake'\n"
                "elif [ \"$1\" = clone ]; then\n"
                "  mkdir -p \"$3\"\n"
                "  cp -R \"$FAKE_INSTALLER_SOURCE/.\" \"$3\"\n"
                "elif [ \"$1\" = -C ] && [ \"$3\" = remote ]; then\n"
                "  echo 'https://github.com/Sokrates1989/swarm-info.git'\n"
                "else\n"
                "  exit 1\n"
                "fi\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)

            fake_bc = fake_bin / "bc"
            fake_bc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bc.chmod(0o755)

            environment = os.environ.copy()
            environment["HOME"] = str(fake_home)
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["FAKE_DOCKER_SCENARIO"] = "default"
            environment["FAKE_INSTALLER_SOURCE"] = str(REPOSITORY_ROOT)
            result = subprocess.run(
                ["bash", str(INSTALLER), "--non-interactive"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=30,
            )

            installed_command = fake_home / ".local" / "bin" / "swarm-info"
            installed_manual = (
                fake_home / ".local" / "share" / "man" / "man1" / "swarm-info.1"
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(installed_command.is_symlink())
            self.assertTrue(installed_manual.is_file())
            self.assertIn(
                'export PATH="$HOME/.local/bin:$PATH"',
                (fake_home / ".profile").read_text(encoding="utf-8"),
            )
            self.assertIn(
                f"Installed command verified: swarm-info {CURRENT_VERSION}",
                result.stdout,
            )

            repeated = subprocess.run(
                ["bash", str(INSTALLER), "--non-interactive"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                repeated.returncode, 0, repeated.stdout + repeated.stderr
            )
            self.assertIn("Existing checkout found; preserving it", repeated.stdout)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_ready_preflight_is_read_only(self) -> None:
        """Report readiness without creating checkout or profile state."""

        result = self.run_preflight()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("This host is ready", result.stdout)
        self.assertIn("Docker Scout is available", result.stdout)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_optional_scan_dependency_uses_distinct_status(self) -> None:
        """Keep missing Scout distinct from a required installer failure."""

        result = self.run_preflight("missing-scout")

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Optional features have 1 issue", result.stderr)
        self.assertIn("Scout is never installed automatically", result.stderr)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_unavailable_daemon_blocks_installation_preflight(self) -> None:
        """Fail before filesystem writes when Docker cannot be inspected."""

        result = self.run_preflight("daemon-unavailable")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Docker daemon access could not be verified", result.stderr)
        self.assertIn("required issues", result.stderr)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_invalid_option_is_rejected_before_mutation(self) -> None:
        """Return usage status for unsupported installer arguments."""

        result = subprocess.run(
            ["bash", str(INSTALLER), "--unknown-option"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 64)
        self.assertIn("Unsupported installer option", result.stderr)

    @unittest.skipUnless(BASH_AVAILABLE, "Native Bash is required for execution.")
    def test_help_documents_safe_installer_modes(self) -> None:
        """Keep read-only and explicit package-mutation modes discoverable."""

        result = subprocess.run(
            ["bash", str(INSTALLER), "--help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--check-only", result.stdout)
        self.assertIn("--install-missing", result.stdout)
        self.assertIn("QNAP QPKGs are never", result.stdout)
        self.assertIn("installed automatically", result.stdout)

    def test_installer_contains_supported_platform_adapters(self) -> None:
        """Keep documented package families and QNAP fallbacks wired."""

        source = INSTALLER.read_text(encoding="utf-8")

        for package_manager in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk"):
            self.assertIn(package_manager, source)
        self.assertIn("getcfg QGit Install_Path", source)
        self.assertIn("getcfg Python3 Install_Path", source)
        self.assertIn("getcfg container-station Install_Path", source)
        self.assertIn("--check-only", source)
        self.assertIn("--install-missing", source)
        self.assertIn('touch "${HOME}/.profile"', source)
        self.assertIn("verify_installed_command", source)


if __name__ == "__main__":
    unittest.main()
