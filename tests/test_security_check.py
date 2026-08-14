"""Tests for capability-aware Swarm and local-container security checks."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.security_check import (
    detect_host_os,
    main,
    run_security_check,
)
from tests.test_vulnerability_scan import FakeDockerHarness


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class HostCompatibilityTests(unittest.TestCase):
    """Verify host and Docker capability decisions without real hardware."""

    def test_qnap_release_file_is_detected_without_vendor_commands(self) -> None:
        """Recognize a QNAP release file and retain only sanitized identity."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            release_file = Path(temporary_directory) / "uLinux.conf"
            release_file.write_text(
                "[System]\nModel = TS-464\nVersion = 5.2.4\n",
                encoding="utf-8",
            )

            profile = detect_host_os(
                "auto",
                qnap_release_paths=(release_file,),
                os_release_path=Path(temporary_directory) / "missing-os-release",
            )

        self.assertEqual(profile.family, "qnap")
        self.assertEqual(profile.version, "5.2.4")
        self.assertEqual(profile.model, "TS-464")
        self.assertIn("release-file", profile.detection)

    def test_explicit_qnap_hint_is_auditable_override(self) -> None:
        """Support the requested ``--os=qnap`` form without false detection."""

        profile = detect_host_os("qnap", qnap_release_paths=())

        self.assertEqual(profile.family, "qnap")
        self.assertEqual(profile.detection, "operator-override")

    def test_qts_os_release_is_qnap_when_vendor_file_is_unavailable(self) -> None:
        """Use the real QNAP ``ID=qts`` fallback found in diagnostics."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text(
                'NAME="QTS"\nID=qts\nPRETTY_NAME="QTS 5.2.10"\nVERSION_ID="5.2.10"\n',
                encoding="utf-8",
            )
            profile = detect_host_os(
                "auto", qnap_release_paths=(), os_release_path=os_release
            )

        self.assertEqual(profile.family, "qnap")
        self.assertEqual(profile.name, "QTS 5.2.10")


class ContainerSecurityCheckTests(unittest.TestCase):
    """Exercise exact local image scanning and Swarm compatibility."""

    def test_auto_mode_scans_all_local_container_image_ids_once(self) -> None:
        """Deduplicate by installed image ID and never contact a registry."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(), host_os_mode="qnap"
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["environment"]["docker"]["inventory_mode"], "containers")
        self.assertEqual(report["environment"]["container_scope"], "all")
        self.assertEqual(report["policy"]["platform"], "linux/amd64")
        self.assertEqual(report["policy"]["source"], "exact-local-image-only")
        self.assertEqual(report["scope"]["resource_type"], "container")
        self.assertEqual(report["scope"]["resource_count"], 3)
        self.assertEqual(report["scope"]["unique_image_count"], 2)
        self.assertEqual(report["summary"]["local_images"], 2)
        self.assertEqual(report["summary"]["registry_images"], 0)
        self.assertEqual(report["affected_resources"], ["qnap_gateway"])
        scans = [command for command in commands if command[:2] == ["scout", "cves"]]
        self.assertEqual(len(scans), 2)
        self.assertTrue(all(command[-1].startswith("local://sha256:") for command in scans))
        self.assertFalse(
            any(command[-1].startswith("registry://") for command in scans)
        )
        shared = next(image for image in report["images"] if len(image["services"]) == 2)
        self.assertEqual(
            [item["name"] for item in shared["services"]],
            ["qnap_web", "qnap_worker"],
        )
        self.assertIn("local_image_id", shared)
        self.assertTrue(shared["immutable"])

    def test_running_scope_excludes_stopped_containers(self) -> None:
        """Honor an explicit narrower local inventory scope."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(),
                host_os_mode="qnap",
                container_scope="running",
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["scope"]["resource_count"], 2)
        list_command = next(
            command for command in commands if command[:2] == ["container", "ls"]
        )
        self.assertNotIn("--all", list_command)

    def test_missing_local_image_never_falls_back_to_registry(self) -> None:
        """Fail incomplete when exact installed evidence cannot be opened."""

        harness = FakeDockerHarness("local-containers-local-failure")
        try:
            report, exit_code = run_security_check(
                harness.client(), host_os_mode="qnap"
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 3)
        self.assertEqual(report["summary"]["failed_images"], 1)
        self.assertIn("Local image scan failed", " ".join(report["errors"]))
        self.assertFalse(
            any(
                command[-1].startswith("registry://")
                for command in commands
                if command[:2] == ["scout", "cves"]
            )
        )

    def test_auto_mode_retains_swarm_wide_behavior_on_manager(self) -> None:
        """Select the established service scanner when manager control exists."""

        harness = FakeDockerHarness()
        try:
            report, exit_code = run_security_check(
                harness.client(), host_os_mode="linux"
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["environment"]["docker"]["inventory_mode"], "swarm")
        self.assertEqual(report["scope"]["resource_type"], "service")
        self.assertEqual(report["policy"]["source"], "local-first-registry-fallback")
        self.assertTrue(any(command[:2] == ["service", "ls"] for command in commands))
        self.assertFalse(any(command[:2] == ["container", "ls"] for command in commands))

    def test_forced_swarm_mode_fails_closed_without_manager(self) -> None:
        """Never mislabel local-node coverage as Swarm-wide coverage."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(), runtime_mode="swarm", host_os_mode="qnap"
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 3)
        self.assertEqual(report["summary"]["status"], "incomplete")
        self.assertIn("manager control", " ".join(report["errors"]))
        self.assertFalse(any(command[:2] == ["container", "ls"] for command in commands))

    def test_cli_writes_separate_security_report(self) -> None:
        """Keep compatibility evidence separate from the watchdog report."""

        harness = FakeDockerHarness("local-containers")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                output = Path(temporary_directory) / "security.json"
                with patch(
                    "scripts.security_check.DockerClient",
                    return_value=harness.client(),
                ):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        exit_code = main(
                            [
                                "--container-mode",
                                "--os=qnap",
                                "--output-file",
                                str(output),
                            ]
                        )
                report = json.loads(output.read_text(encoding="utf-8"))
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["environment"]["host_os"]["family"], "qnap")
        self.assertEqual(report["environment"]["docker"]["inventory_mode"], "containers")

    def test_public_shell_command_is_wired_to_portable_preflight(self) -> None:
        """Lock the documented compatibility action into the Bash dispatcher."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res" / "vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )
        dependencies = (
            REPOSITORY_ROOT / "res" / "dependency_check.sh"
        ).read_text(encoding="utf-8")

        self.assertIn('selected_action="security-check"', entrypoint)
        self.assertIn('"security-check")', entrypoint)
        self.assertIn("select_default_action_for_docker_capability", entrypoint)
        self.assertIn('ORIGINAL_ARGUMENT_COUNT="$#"', entrypoint)
        self.assertIn('SECURITY_RUNTIME_MODE="containers"', entrypoint)
        self.assertIn("--container-mode", entrypoint)
        self.assertIn("--os=*", entrypoint)
        self.assertIn("-m scripts.security_check", bridge)
        self.assertIn("check_swarm_info_dependencies security", bridge)
        self.assertIn("--security)", dependencies)


if __name__ == "__main__":
    unittest.main()
