"""Behavioral tests for secret-free local-container hardening evidence."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts.runtime_hardening import (
    build_report,
    collect_runtime_hardening,
    main,
    parse_container_inspect,
)
from scripts.vulnerability_scan import CommandResult


class HardeningDockerClient:
    """Provide one risky, one compliant, and one unreadable container."""

    def run(self, arguments: list[str]) -> CommandResult:
        """Return deterministic Docker CLI responses."""

        if arguments == [
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
        ]:
            return CommandResult(0, "risky\nsafe\nmissing\n", "")
        if arguments == ["container", "inspect", "risky"]:
            return CommandResult(0, risky_inspect(), "")
        if arguments == ["container", "inspect", "safe"]:
            return CommandResult(0, safe_inspect(), "")
        if arguments == ["container", "inspect", "missing"]:
            return CommandResult(
                1,
                "",
                "cannot inspect token=hidden-value /var/lib/private/source",
            )
        return CommandResult(1, "", f"unsupported command: {arguments}")


def base_payload() -> dict[str, object]:
    """Return a complete safe Docker inspect fixture."""

    return {
        "Name": "/safe-app-1",
        "Config": {
            "Image": "acme/safe:1",
            "User": "1000:1000",
            "Env": ["DATABASE_PASSWORD=super-secret"],
            "Labels": {
                "com.docker.compose.project": "safe-app",
                "com.docker.compose.service": "app",
                "private.token": "label-secret",
            },
            "Healthcheck": {"Test": ["CMD", "true"]},
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "ReadonlyRootfs": True,
            "Memory": 134217728,
            "NanoCpus": 500000000,
            "CpuQuota": 0,
            "PortBindings": {},
        },
        "State": {"Running": True},
        "Mounts": [],
    }


def safe_inspect() -> str:
    """Serialize the compliant fixture."""

    return json.dumps([base_payload()])


def risky_inspect() -> str:
    """Serialize one fixture that triggers every planned hardening category."""

    payload = base_payload()
    payload["Name"] = "/risky-app-1"
    payload["Config"].update(
        {
            "Image": "acme/risky:1",
            "User": "",
            "Healthcheck": None,
        }
    )
    payload["HostConfig"].update(
        {
            "Privileged": True,
            "NetworkMode": "host",
            "PidMode": "host",
            "CapAdd": ["SYS_ADMIN", "NET_ADMIN", "CHOWN"],
            "SecurityOpt": ["seccomp=unconfined"],
            "ReadonlyRootfs": False,
            "Memory": 0,
            "NanoCpus": 0,
            "CpuQuota": 0,
            "PortBindings": {"8080/tcp": [{"HostPort": "18080"}]},
        }
    )
    payload["Mounts"] = [
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
        },
        {
            "Type": "bind",
            "Source": "/share/private/secret-config",
            "Destination": "/etc/host-config",
        },
    ]
    return json.dumps([payload])


class RuntimeHardeningTests(unittest.TestCase):
    """Cover every 03B finding, sanitization, publication, and CLI wiring."""

    def test_risky_container_triggers_every_planned_finding(self) -> None:
        """Classify each explicitly required runtime-hardening category."""

        container = parse_container_inspect("risky", risky_inspect())

        self.assertEqual(
            {finding.code for finding in container.findings},
            {
                "privileged",
                "host-network",
                "host-pid",
                "docker-socket-mounted",
                "risky-host-bind-mount",
                "dangerous-capabilities",
                "root-user",
                "no-new-privileges-missing",
                "writable-root-filesystem",
                "healthcheck-missing",
                "resource-limits-missing",
                "ports-published",
            },
        )
        self.assertEqual(container.status, "critical")

    def test_report_never_serializes_environment_labels_or_host_sources(self) -> None:
        """Retain only known Compose labels and container-side mount targets."""

        container = parse_container_inspect("risky", risky_inspect())
        serialized = json.dumps(build_report([container], [], "all"))

        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("label-secret", serialized)
        self.assertNotIn("/share/private/secret-config", serialized)
        self.assertNotIn("DATABASE_PASSWORD", serialized)
        self.assertIn('"compose_project": "safe-app"', serialized)
        self.assertIn('"targets": ["/etc/host-config"]', serialized)

    def test_compliant_container_has_no_findings(self) -> None:
        """Avoid manufacturing risks when every audited control is present."""

        container = parse_container_inspect("safe", safe_inspect())

        self.assertEqual(container.status, "ok")
        self.assertEqual(container.findings, ())

    def test_inspect_failure_is_sanitized_and_marks_report_incomplete(self) -> None:
        """Keep readable containers while making partial coverage explicit."""

        containers, failures = collect_runtime_hardening(
            HardeningDockerClient(), "all"
        )
        report = build_report(containers, failures, "all")
        serialized = json.dumps(report)

        self.assertFalse(report["complete"])
        self.assertEqual(report["summary"]["listed_containers"], 3)
        self.assertEqual(report["summary"]["audited_containers"], 2)
        self.assertNotIn("hidden-value", serialized)
        self.assertNotIn("/var/lib/private/source", serialized)

    def test_cli_publishes_private_atomic_evidence(self) -> None:
        """Write one mode-0600 report and return incomplete status honestly."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "runtime_hardening.json"
            with (
                patch(
                    "scripts.runtime_hardening.DockerClient",
                    return_value=HardeningDockerClient(),
                ),
                redirect_stdout(io.StringIO()),
            ):
                exit_code = main(["--output-file", str(report_path)])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(os.stat(report_path).st_mode)

        self.assertEqual(exit_code, 3)
        self.assertEqual(report["schema_version"], 1)
        if os.name != "nt":
            self.assertEqual(mode & 0o077, 0)

    def test_public_cli_routes_the_read_only_hardening_action(self) -> None:
        """Keep the command discoverable without adding mutation flags."""

        root = Path(__file__).resolve().parents[1]
        entrypoint = (root / "get_info.sh").read_text(encoding="utf-8")
        bridge = (root / "res" / "runtime_hardening_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--runtime-hardening)", entrypoint)
        self.assertIn('selected_action="runtime-hardening"', entrypoint)
        self.assertIn('"runtime-hardening")', entrypoint)
        self.assertIn("-m scripts.runtime_hardening", bridge)
        self.assertNotIn("--apply", bridge)


if __name__ == "__main__":
    unittest.main()
