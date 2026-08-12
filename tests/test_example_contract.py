"""Validate checked-in health and vulnerability example report contracts.

The examples are public, sanitized inputs for documentation and downstream
local UI tests. These tests prevent count drift and accidental schema changes.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIRECTORY = REPOSITORY_ROOT / "example-output"


def load_example(name: str) -> dict[str, object]:
    """Load one JSON example as an object.

    Args:
        name: Filename within ``example-output``.

    Returns:
        Parsed top-level JSON object.

    Raises:
        AssertionError: If the example is not a JSON object.
        OSError: If the example cannot be read.
        json.JSONDecodeError: If it is malformed.
    """

    payload = json.loads((EXAMPLE_DIRECTORY / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{name} must contain a JSON object")
    return payload


class HealthExampleTests(unittest.TestCase):
    """Verify health summary values agree with individual services."""

    def test_summary_matches_service_entries(self) -> None:
        """Count service states and compare them with the summary.

        Returns:
            Nothing.
        """

        report = load_example("swarm-info.json")
        services = report["services"]
        summary = report["summary"]

        self.assertIsInstance(services, list)
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["total_services"], len(services))
        self.assertEqual(
            summary["healthy"],
            sum(service["healthy"] for service in services),
        )
        for state in ("degraded", "down"):
            self.assertEqual(
                summary[state],
                sum(service["status"] == state for service in services),
            )
        unhealthy = sorted(
            service["name"] for service in services if not service["healthy"]
        )
        self.assertEqual(sorted(report["unhealthy_services"]), unhealthy)


class VulnerabilityExampleTests(unittest.TestCase):
    """Verify the downstream-facing schema-version-2 example."""

    def test_summary_matches_images_and_findings(self) -> None:
        """Recalculate key scan aggregates from per-image evidence.

        Returns:
            Nothing.
        """

        report = load_example("vulnerability-scan.json")
        summary = report["summary"]
        images = report["images"]
        findings = [finding for image in images for finding in image["findings"]]

        self.assertEqual(report["schema_version"], 2)
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["finding_count"], len(findings))
        self.assertEqual(
            summary["vulnerable_images"],
            sum(image["status"] == "vulnerable" for image in images),
        )
        self.assertEqual(
            summary["affected_service_count"], len(report["affected_services"])
        )
        self.assertEqual(
            summary["critical"],
            sum(finding["severity"] == "critical" for finding in findings),
        )
        self.assertEqual(
            summary["high"],
            sum(finding["severity"] == "high" for finding in findings),
        )


if __name__ == "__main__":
    unittest.main()
