"""Tests for capability-aware Swarm and local-container security checks."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.security_check import (
    HostOsProfile,
    detect_host_os,
    main,
    prepare_qnap_scout_client,
    run_security_check,
)
from scripts.vulnerability_scan import DockerClient, InventoryError
from tests.fixtures.fake_docker import DIGEST_A
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

    def test_qnap_scout_uses_private_home_storage_by_default(self) -> None:
        """Keep Scout extraction away from QNAP's capacity-limited `/tmp`."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            environment = {"HOME": temporary_directory, "PATH": ""}
            client = DockerClient(("fake-docker",), {"FAKE_DOCKER": "1"})
            configured, metadata = prepare_qnap_scout_client(
                client,
                HostOsProfile("qnap", "QNAP", None, None, "test"),
                environment,
            )

            expected_root = (
                Path(temporary_directory) / ".cache" / "swarm-info" / "docker-scout"
            )
            self.assertEqual(configured.environment["TMPDIR"], str(expected_root / "tmp"))
            self.assertEqual(
                configured.environment["DOCKER_SCOUT_CACHE_DIR"],
                str(expected_root / "cache"),
            )
            self.assertTrue((expected_root / "tmp").is_dir())
            self.assertTrue((expected_root / "cache").is_dir())
            self.assertEqual(metadata["selection"], "qnap-home-default")

    def test_qnap_scout_preserves_operator_storage_overrides(self) -> None:
        """Never replace explicitly selected Scout temporary and cache paths."""

        client = DockerClient(("fake-docker",), {"FAKE_DOCKER": "1"})
        configured, metadata = prepare_qnap_scout_client(
            client,
            HostOsProfile("qnap", "QNAP", None, None, "test"),
            {
                "HOME": "/unused",
                "TMPDIR": "/share/custom/tmp",
                "DOCKER_SCOUT_CACHE_DIR": "/share/custom/cache",
            },
        )

        self.assertIsNot(configured, client)
        self.assertEqual(configured.environment["TMPDIR"], "/share/custom/tmp")
        self.assertEqual(
            configured.environment["DOCKER_SCOUT_CACHE_DIR"],
            "/share/custom/cache",
        )
        self.assertEqual(metadata["temporary_directory"], "/share/custom/tmp")
        self.assertEqual(metadata["cache_directory"], "/share/custom/cache")
        self.assertEqual(metadata["selection"], "operator-environment")

    def test_qnap_scout_storage_failure_is_localized(self) -> None:
        """Give German operators an actionable work-directory failure."""

        client = DockerClient(("fake-docker",), {"FAKE_DOCKER": "1"})
        with patch(
            "scripts.security_check.Path.mkdir",
            side_effect=OSError("permission denied"),
        ):
            with self.assertRaisesRegex(
                InventoryError,
                "Docker-Scout-Arbeitsbereich",
            ):
                prepare_qnap_scout_client(
                    client,
                    HostOsProfile("qnap", "QNAP", None, None, "test"),
                    {
                        "HOME": "/share/homes/operator",
                        "SWARM_INFO_LOCALE": "de",
                    },
                )


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
        compose_web = next(
            item for item in shared["services"] if item["name"] == "qnap_web"
        )
        self.assertEqual(compose_web["compose_service"], "web")
        self.assertEqual(
            compose_web["compose_working_dir"], "/share/Container/qnap-app"
        )
        self.assertEqual(
            compose_web["compose_config_files"],
            ["/share/Container/qnap-app/docker-compose.yml"],
        )

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
        failed = next(image for image in report["images"] if image["status"] == "error")
        self.assertEqual(failed["error_code"], "local-image-unavailable")
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

    def test_container_focus_scans_only_the_exact_selected_container(self) -> None:
        """Keep one-container verification local, exact, and separately marked."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(),
                host_os_mode="qnap",
                focus_kind="container",
                focus_selector="qnap_gateway",
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["scope"]["coverage"], "focused")
        self.assertEqual(
            report["scope"]["selector"],
            {"type": "container", "value": "qnap_gateway"},
        )
        self.assertEqual(report["scope"]["inventory_resource_count"], 3)
        self.assertEqual(report["scope"]["resource_count"], 1)
        self.assertEqual(report["affected_resources"], ["qnap_gateway"])
        scans = [command for command in commands if command[:2] == ["scout", "cves"]]
        self.assertEqual(len(scans), 1)

    def test_image_id_focus_scans_shared_exact_artifact_once(self) -> None:
        """Select all containers sharing one full ID while deduplicating Scout."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(),
                host_os_mode="qnap",
                focus_kind="image-id",
                focus_selector=DIGEST_A,
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["scope"]["resource_count"], 2)
        self.assertEqual(report["scope"]["unique_image_count"], 1)
        scans = [command for command in commands if command[:2] == ["scout", "cves"]]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0][-1], f"local://{DIGEST_A}")

    def test_unknown_container_focus_is_incomplete_without_scout(self) -> None:
        """Never turn a stale container name into clean focused evidence."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(),
                host_os_mode="qnap",
                focus_kind="container",
                focus_selector="missing_container",
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 3)
        self.assertEqual(report["summary"]["status"], "incomplete")
        self.assertEqual(report["focus_error"]["code"], "container-not-found")
        self.assertFalse(any(command[:1] == ["scout"] for command in commands))

    def test_abbreviated_image_id_focus_is_rejected_without_scout(self) -> None:
        """Require the full artifact identity before calling Docker Scout."""

        harness = FakeDockerHarness("local-containers")
        try:
            report, exit_code = run_security_check(
                harness.client(),
                host_os_mode="qnap",
                focus_kind="image-id",
                focus_selector="sha256:abc123",
            )
            commands = harness.commands()
        finally:
            harness.close()

        self.assertEqual(exit_code, 3)
        self.assertEqual(report["focus_error"]["code"], "invalid-image-id")
        self.assertFalse(any(command[:1] == ["scout"] for command in commands))

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
                ), patch.dict(
                    os.environ,
                    {
                        "HOME": temporary_directory,
                        "TMPDIR": "",
                        "DOCKER_SCOUT_CACHE_DIR": "",
                    },
                ):
                    standard_output = io.StringIO()
                    with redirect_stdout(standard_output), redirect_stderr(
                        io.StringIO()
                    ):
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
        output_text = standard_output.getvalue()
        self.assertIn("Collecting all local-container image inventory", output_text)
        self.assertIn("[INFO] [1/2] Scanning", output_text)
        self.assertIn("[OK] [1/2] Completed clean", output_text)

    def test_focused_cli_uses_a_separate_default_report(self) -> None:
        """Do not overwrite full-host evidence during one-container verification."""

        harness = FakeDockerHarness("local-containers")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                full_output = Path(temporary_directory) / "security_scan.json"
                focused_output = (
                    Path(temporary_directory) / "security_scan_focused.json"
                )
                full_output.write_text('{"preserved": true}\n', encoding="utf-8")
                with patch(
                    "scripts.security_check.DockerClient",
                    return_value=harness.client(),
                ), patch(
                    "scripts.security_check.DEFAULT_FOCUSED_OUTPUT_FILE",
                    focused_output,
                ), patch.dict(
                    os.environ,
                    {
                        "HOME": temporary_directory,
                        "TMPDIR": "",
                        "DOCKER_SCOUT_CACHE_DIR": "",
                    },
                ):
                    with redirect_stdout(io.StringIO()), redirect_stderr(
                        io.StringIO()
                    ):
                        exit_code = main(
                            ["--container", "qnap_gateway", "--os=qnap"]
                        )
                focused_report = json.loads(
                    focused_output.read_text(encoding="utf-8")
                )
                preserved_report = json.loads(
                    full_output.read_text(encoding="utf-8")
                )
        finally:
            harness.close()

        self.assertEqual(exit_code, 2)
        self.assertEqual(focused_report["scope"]["coverage"], "focused")
        self.assertEqual(preserved_report, {"preserved": True})

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
        self.assertIn("--container)", entrypoint)
        self.assertIn("--image-id)", entrypoint)
        self.assertIn("--os=*", entrypoint)
        self.assertIn("-m scripts.security_check", bridge)
        self.assertIn("check_swarm_info_dependencies security", bridge)
        self.assertIn("--security)", dependencies)


if __name__ == "__main__":
    unittest.main()
