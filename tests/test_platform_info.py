"""Deterministic tests for the SCWP-01 host platform capability contract."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.platform_info import main
from scripts.platforms import (
    detect_host_os,
    detect_platform_profile,
    platform_adapter_for,
)
from tests.test_vulnerability_scan import FakeDockerHarness

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PlatformDetectionTests(unittest.TestCase):
    """Cover supported adapters and safe fallback metadata without real hosts."""

    def write_release(self, directory: Path, content: str) -> Path:
        """Write one isolated release fixture and return its path."""

        release_file = directory / "os-release"
        release_file.write_text(content, encoding="utf-8")
        return release_file

    def test_qnap_vendor_release_selects_qnap_adapter(self) -> None:
        """Recognize sanitized QNAP metadata without executing getcfg."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            vendor_release = root / "uLinux.conf"
            vendor_release.write_text(
                "[System]\nModel = TS-464\nVersion = 5.2.4\n", encoding="utf-8"
            )
            profile = detect_host_os(
                qnap_release_paths=(vendor_release,),
                os_release_path=root / "missing",
            )

        self.assertEqual(profile.platform_adapter, "qnap")
        self.assertEqual(profile.family, "qnap")
        self.assertEqual(profile.os_id, "qts")
        self.assertEqual(profile.model, "TS-464")

    def test_debian_and_ubuntu_share_standard_linux_adapter(self) -> None:
        """Map package guidance to Debian without creating a runtime fork."""

        fixtures = {
            "debian": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12"\nVERSION_ID=12\n',
            "ubuntu": 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04"\nVERSION_ID=24.04\n',
        }
        for expected_id, content in fixtures.items():
            with self.subTest(expected_id=expected_id):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    profile = detect_host_os(
                        qnap_release_paths=(),
                        os_release_path=self.write_release(root, content),
                    )
                self.assertEqual(profile.os_id, expected_id)
                self.assertEqual(profile.family, "debian")
                self.assertEqual(profile.platform_adapter, "standard-linux")

    def test_unknown_missing_and_malformed_release_data_is_bounded(self) -> None:
        """Return generic metadata without copying unsafe release contents."""

        fixtures = (None, "not-an-assignment\nTOKEN=secret\x00\nID=custom\n")
        for content in fixtures:
            with self.subTest(content=content):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    release_file = root / "missing"
                    if content is not None:
                        release_file = self.write_release(root, content)
                    profile = detect_host_os(
                        qnap_release_paths=(), os_release_path=release_file
                    )
                self.assertEqual(profile.platform_adapter, "standard-linux")
                self.assertEqual(profile.family, "generic-linux")
                self.assertNotIn("secret", json.dumps(profile.to_dict()).lower())

    def test_missing_scout_and_compose_are_explicit_capabilities(self) -> None:
        """Never convert unavailable tooling into a healthy-looking profile."""

        harness = FakeDockerHarness("missing-scout")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                release_file = self.write_release(root, "ID=debian\n")
                profile = detect_platform_profile(
                    harness.client(),
                    qnap_release_paths=(),
                    os_release_path=release_file,
                    detected_at="2026-08-22T00:00:00Z",
                )
        finally:
            harness.close()

        payload = profile.to_dict()
        self.assertEqual(payload["schema_version"], 1)
        self.assertFalse(payload["capabilities"]["image_vulnerability_scan"])
        self.assertTrue(payload["docker"]["compose_available"])
        self.assertFalse(payload["capabilities"]["runtime_hardening"])
        self.assertEqual(payload["capabilities"]["scheduler"], "user-crontab")
        self.assertNotIn("environment", json.dumps(payload).lower())

    def test_container_runtime_enables_read_only_hardening(self) -> None:
        """Publish hardening only where local-container semantics apply."""

        harness = FakeDockerHarness("local-containers")
        try:
            profile = detect_platform_profile(
                harness.client(),
                requested_os="qnap",
                detected_at="2026-08-22T00:00:00Z",
            )
        finally:
            harness.close()

        payload = profile.to_dict()
        self.assertEqual(payload["docker"]["runtime_mode"], "containers")
        self.assertTrue(payload["capabilities"]["runtime_hardening"])

    def test_unavailable_docker_daemon_produces_explicit_profile(self) -> None:
        """Keep platform diagnostics available while returning no safe actions."""

        harness = FakeDockerHarness("daemon-unavailable")
        try:
            profile = detect_platform_profile(
                harness.client(),
                requested_os="qnap",
                detected_at="2026-08-22T00:00:00Z",
            )
        finally:
            harness.close()

        payload = profile.to_dict()
        self.assertFalse(payload["docker"]["daemon_available"])
        self.assertFalse(payload["capabilities"]["image_cleanup"])
        self.assertFalse(payload["capabilities"]["runtime_hardening"])
        self.assertEqual(
            payload["capabilities"]["scheduler"], "qnap-persistent-crontab"
        )

    def test_adapters_own_evidence_paths_and_qnap_root_gate(self) -> None:
        """Keep XDG/QNAP path and persistence differences out of common jobs."""

        standard = platform_adapter_for(
            detect_host_os(
                "linux",
                qnap_release_paths=(),
                os_release_path=Path("/missing-os-release"),
            )
        )
        qnap = platform_adapter_for(detect_host_os("qnap"))

        self.assertEqual(
            standard.default_evidence_directory(
                {"HOME": "/home/operator", "XDG_STATE_HOME": "/srv/state"}
            ),
            Path("/srv/state/swarm-info"),
        )
        self.assertEqual(
            qnap.default_evidence_directory({}),
            Path("/share/Public/swarm-info"),
        )
        with patch("scripts.platforms.qnap.os.geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                qnap.crontab_client()


class PlatformInfoCommandTests(unittest.TestCase):
    """Verify human, machine, and private atomic publication behavior."""

    def test_machine_output_matches_private_written_profile(self) -> None:
        """Publish one stable JSON object without environment or secret values."""

        harness = FakeDockerHarness("local-containers")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                output_file = Path(temporary_directory) / "platform_info.json"
                standard_output = io.StringIO()
                with (
                    patch(
                        "scripts.platform_info.DockerClient",
                        return_value=harness.client(),
                    ),
                    patch.dict(
                        os.environ,
                        {"HOME": temporary_directory, "SCWP_TEST_SECRET": "hidden"},
                        clear=False,
                    ),
                    redirect_stdout(standard_output),
                ):
                    exit_code = main(
                        [
                            "--json",
                            "--os",
                            "linux",
                            "--output-file",
                            str(output_file),
                        ]
                    )
                printed = json.loads(standard_output.getvalue())
                written = json.loads(output_file.read_text(encoding="utf-8"))
        finally:
            harness.close()

        self.assertEqual(exit_code, 0)
        self.assertEqual(printed, written)
        self.assertEqual(printed["platform_adapter"], "standard-linux")
        self.assertEqual(printed["docker"]["runtime_mode"], "containers")
        self.assertNotIn("hidden", json.dumps(printed))


class PlatformShellContractTests(unittest.TestCase):
    """Lock the public CLI, adapter sourcing, and host gates together."""

    def test_public_cli_exposes_human_and_json_platform_info(self) -> None:
        """Route one action through localization and the Python command."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res/vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--platform-info", entrypoint)
        self.assertIn('selected_action="platform-info"', entrypoint)
        self.assertIn("run_platform_info", entrypoint)
        self.assertIn("-m scripts.platform_info", bridge)
        self.assertIn("platform_arguments+=(--json)", bridge)
        self.assertIn("XDG_STATE_HOME", bridge)

    def test_qpkg_discovery_is_owned_by_the_shell_adapter(self) -> None:
        """Keep getcfg out of common dependency and command bridges."""

        adapter = (REPOSITORY_ROOT / "res/platforms/qnap.sh").read_text(
            encoding="utf-8"
        )
        dependency = (REPOSITORY_ROOT / "res/dependency_check.sh").read_text(
            encoding="utf-8"
        )
        scheduler = (REPOSITORY_ROOT / "scripts/security_cron.py").read_text(
            encoding="utf-8"
        )
        bridge = (REPOSITORY_ROOT / "res/vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("getcfg", adapter)
        self.assertIn("qnap_python_command_candidates", adapter)
        self.assertNotIn("getcfg Python3 Install_Path", dependency)
        self.assertNotIn("getcfg Python3 Install_Path", bridge)
        self.assertNotIn("scripts.platforms.qnap", scheduler)
        self.assertIn("adapter.default_evidence_directory", scheduler)

    def test_real_host_entry_points_are_platform_scoped(self) -> None:
        """Require clean checkouts, exact profiles, and explicit PASS lines."""

        acceptance_directory = REPOSITORY_ROOT / "tests/acceptance"
        expectations = {
            "scwp_01_qnap.sh": "SCWP-01 QNAP producer checks passed",
            "scwp_01_standard_linux.sh": "SCWP-01 standard-Linux pre-reboot checks passed",
            "scwp_01_swarm.sh": "SCWP-01 Swarm producer regression passed",
        }
        for name, pass_text in expectations.items():
            with self.subTest(name=name):
                source = (acceptance_directory / name).read_text(encoding="utf-8")
                self.assertIn("acceptance_require_clean_checkout", source)
                self.assertIn("acceptance_validate_profile", source)
                self.assertIn(f"[PASS] {pass_text}", source)

if __name__ == "__main__":
    unittest.main()
