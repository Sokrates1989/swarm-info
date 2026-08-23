"""Tests for cheap local-container operational evidence."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import stat
import time
import tempfile
import unittest

from scripts.container_state import (
    collect,
    load_previous,
    parse_inspect,
    restart_sample,
)
from scripts.vulnerability_job import ScanLock
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import CommandResult

NOW = dt.datetime(2026, 8, 23, 10, 0, tzinfo=dt.timezone.utc)


def inspect_payload(
    *,
    container_id: str = "container-alpha",
    name: str = "/demo_api",
    running: bool = True,
    status: str = "running",
    restart_count: int = 2,
    health: str | None = "healthy",
) -> str:
    """Build one representative Docker container inspect payload."""

    state: dict[str, object] = {
        "Running": running,
        "Status": status,
        "ExitCode": 0 if running else 1,
        "StartedAt": "2026-08-23T09:00:00Z",
        "FinishedAt": "0001-01-01T00:00:00Z",
    }
    if health is not None:
        state["Health"] = {"Status": health}
    return json.dumps(
        [
            {
                "Id": container_id,
                "Name": name,
                "Image": "sha256:" + ("a" * 64),
                "RestartCount": restart_count,
                "State": state,
                "Config": {
                    "Image": "example/api:1",
                    "Labels": {
                        "com.docker.compose.project": "demo",
                        "com.docker.compose.service": "api",
                    },
                },
                "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
                "NetworkSettings": {
                    "Ports": {
                        "8080/tcp": [{"HostIp": "192.0.2.10", "HostPort": "18080"}],
                        "9090/tcp": None,
                    }
                },
            }
        ]
    )


class FakeClient:
    """Return deterministic list and inspect responses."""

    def __init__(self, payloads: dict[str, str], list_error: str | None = None) -> None:
        self.payloads = payloads
        self.list_error = list_error

    def run(self, arguments: list[str]) -> CommandResult:
        """Implement the DockerClient subset used by the collector."""

        if arguments[:2] == ["container", "ls"]:
            if self.list_error:
                return CommandResult(1, "", self.list_error)
            return CommandResult(0, "\n".join(self.payloads), "")
        payload = self.payloads.get(arguments[-1])
        return (
            CommandResult(0, payload, "")
            if payload is not None
            else CommandResult(1, "", "No such container token=secret")
        )


class ContainerStateTests(unittest.TestCase):
    """Verify schema, privacy, completeness, and restart sampling."""

    def test_inspect_normalizes_selectors_health_policy_and_ports(self) -> None:
        row = parse_inspect("container-alpha", inspect_payload())

        self.assertEqual(row["name"], "demo_api")
        self.assertEqual(row["selectors"]["container"], "container:demo_api")
        self.assertEqual(row["selectors"]["compose"], "compose:demo/api")
        self.assertEqual(row["docker_health"], "healthy")
        self.assertEqual(row["restart_policy"], "unless-stopped")
        self.assertEqual(
            row["ports"],
            [
                {"container": "8080/tcp", "published": ["18080"]},
                {"container": "9090/tcp", "published": []},
            ],
        )
        self.assertNotIn("192.0.2.10", json.dumps(row))

    def test_first_sample_has_null_restart_rate(self) -> None:
        report = collect(
            FakeClient({"container-alpha": inspect_payload()}),
            NOW,
        )

        self.assertTrue(report["collection"]["complete"])
        self.assertEqual(report["freshness"]["generated_at"], "2026-08-23T10:00:00Z")
        self.assertEqual(report["freshness"]["fresh_until"], "2026-08-23T10:15:00Z")
        self.assertEqual(report["summary"]["running"], 1)
        self.assertIsNone(report["containers"][0]["restart_rate_per_hour"])

    def test_second_continuous_sample_calculates_restart_rate(self) -> None:
        previous = collect(
            FakeClient({"container-alpha": inspect_payload(restart_count=2)}),
            NOW,
        )
        current = collect(
            FakeClient({"container-alpha": inspect_payload(restart_count=3)}),
            NOW + dt.timedelta(minutes=5),
            previous,
        )

        row = current["containers"][0]
        self.assertEqual(row["restart_delta"], 1)
        self.assertEqual(row["sample_duration_seconds"], 300.0)
        self.assertEqual(row["restart_rate_per_hour"], 12.0)

    def test_restart_counter_reset_is_discontinuous(self) -> None:
        current = {
            "restart_count": 1,
            "started_at": "2026-08-23T09:00:00Z",
        }
        previous = {
            "restart_count": 2,
            "started_at": "2026-08-23T09:00:00Z",
        }

        sample = restart_sample(current, previous, NOW + dt.timedelta(minutes=5), NOW)

        self.assertIsNone(sample["restart_rate_per_hour"])

    def test_inventory_failure_publishes_sanitized_incomplete_evidence(self) -> None:
        report = collect(FakeClient({}, "daemon token=secret"), NOW)

        self.assertFalse(report["collection"]["complete"])
        self.assertEqual(report["collection"]["error_count"], 1)
        self.assertNotIn("secret", json.dumps(report))

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not stable on Windows")
    def test_atomic_report_is_private_and_reloadable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "container_state.json"
            report = collect(FakeClient({"container-alpha": inspect_payload()}), NOW)

            write_json_atomic(path, report)

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertIsNotNone(load_previous(path))

    @unittest.skipUnless(os.name == "posix", "POSIX advisory lock required")
    def test_long_security_lock_does_not_block_operational_collection(self) -> None:
        """Collect immediately while a simulated multi-hour scan owns its lock."""

        with tempfile.TemporaryDirectory() as directory:
            lock = ScanLock(Path(directory) / "security_scan-running.json.lock")
            self.assertTrue(lock.acquire())
            try:
                started = time.monotonic()
                report = collect(
                    FakeClient({"container-alpha": inspect_payload()}),
                    NOW,
                )
                elapsed = time.monotonic() - started
            finally:
                lock.release()

        self.assertTrue(report["collection"]["complete"])
        self.assertLess(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
