"""Verify deduplicated batch candidate scans and deployable-fix evidence."""

from __future__ import annotations

from pathlib import Path
import unittest

from scripts.image_update_assessment import (
    ImageUpdateAssessmentError,
    assess_image_updates,
)
from scripts.vulnerability_models import ImageScanResult


CURRENT_ONE_DIGEST = "sha256:" + "1" * 64
CURRENT_TWO_DIGEST = "sha256:" + "2" * 64
CANDIDATE_DIGEST = "sha256:" + "3" * 64
CANDIDATE_REFERENCE = (
    "docker.io/example/app:2.0.0@" + CANDIDATE_DIGEST
)


class NoopClient:
    """Marker client used because deterministic scanner callbacks do no I/O."""


def _findings(critical: int, high: int) -> list[dict[str, str]]:
    """Build normalized source-report finding records."""

    return [
        {
            "id": f"CVE-CRITICAL-{index}",
            "severity": "critical",
            "title": "critical",
        }
        for index in range(critical)
    ] + [
        {
            "id": f"CVE-HIGH-{index}",
            "severity": "high",
            "title": "high",
        }
        for index in range(high)
    ]


def vulnerability_report() -> dict[str, object]:
    """Return complete current evidence for two image groups."""

    return {
        "schema_version": 2,
        "completed_at": "2026-08-17T10:00:00Z",
        "scope": {"image_fingerprint": "scope-1"},
        "summary": {
            "complete": True,
            "critical": 3,
            "high": 5,
        },
        "images": [
            {
                "reference": "example/app:1.0.0",
                "digest": CURRENT_ONE_DIGEST,
                "counts": {"critical": 2, "high": 3},
                "findings": _findings(2, 3),
            },
            {
                "reference": "example/app:1.1.0",
                "digest": CURRENT_TWO_DIGEST,
                "counts": {"critical": 1, "high": 2},
                "findings": _findings(1, 2),
            },
        ],
    }


def _candidate() -> dict[str, object]:
    """Return one immutable candidate shared by both current images."""

    return {
        "reference": "docker.io/example/app:2.0.0",
        "repository": "docker.io/example/app",
        "tag": "2.0.0",
        "digest": CANDIDATE_DIGEST,
        "immutable_reference": CANDIDATE_REFERENCE,
        "platform": "linux/amd64",
        "tracks": ["newest-stable"],
        "compatibility": "major-change",
        "security_comparison": "not-scanned",
        "deployment_authorized": False,
    }


def candidate_report(complete: bool = True) -> dict[str, object]:
    """Return Slice 1 evidence with one candidate reused by two images."""

    return {
        "schema_version": 1,
        "completed_at": "2026-08-17T11:00:00Z",
        "complete": complete,
        "source_report": {
            "completed_at": "2026-08-17T10:00:00Z",
            "image_fingerprint": "scope-1",
        },
        "policy": {"platform": "linux/amd64"},
        "images": [
            {
                "current": {
                    "reference": "example/app:1.0.0",
                    "digest": CURRENT_ONE_DIGEST,
                    "services": ["demo_api", "demo_worker"],
                },
                "discovery": {"complete": complete, "status": "ok"},
                "candidates": [_candidate()],
            },
            {
                "current": {
                    "reference": "example/app:1.1.0",
                    "digest": CURRENT_TWO_DIGEST,
                    "services": ["other_api"],
                },
                "discovery": {"complete": complete, "status": "ok"},
                "candidates": [_candidate()],
            },
        ],
        "errors": [] if complete else [{"status": "rate-limited"}],
        "required_registry_hosts": [] if complete else ["quay.io"],
    }


class ImageUpdateAssessmentTests(unittest.TestCase):
    """Keep batch evidence deduplicated, useful, and non-authorizing."""

    def test_shared_candidate_is_scanned_once_and_projected_to_services(self) -> None:
        """Reuse an exact candidate scan across all consuming current images."""

        scanned: list[str] = []

        def scanner(client, target, platform):
            scanned.append(target.display_reference)
            return ImageScanResult(
                target=target,
                status="clean",
                scanner_exit_code=0,
                scan_source="registry",
                scan_attempts=1,
            )

        outcome = assess_image_updates(
            candidate_report(),
            Path("candidates.json"),
            vulnerability_report(),
            Path("vulnerabilities.json"),
            NoopClient(),
            "linux/amd64",
            scanner=scanner,
            version_reader=lambda client: "v1.24.0",
        )

        summary = outcome.report["summary"]
        self.assertEqual(outcome.exit_code, 2)
        self.assertTrue(outcome.report["complete"])
        self.assertEqual(scanned, [CANDIDATE_REFERENCE])
        self.assertEqual(summary["candidate_count"], 2)
        self.assertEqual(summary["unique_candidate_count"], 1)
        self.assertEqual(
            summary["deployable_fixable"],
            {
                "critical": 3,
                "high": 5,
                "total": 8,
                "definition": "removed-by-exact-candidate-scan",
                "deployment_authorized": False,
            },
        )
        self.assertEqual(summary["services_with_verified_candidate"], 3)
        self.assertTrue(
            all(
                service["deployment_authorized"] is False
                for service in outcome.report["services"]
            )
        )

    def test_incomplete_discovery_retains_partial_assessment(self) -> None:
        """Publish useful scans but return incomplete when Slice 1 was partial."""

        def scanner(client, target, platform):
            return ImageScanResult(target=target, status="clean", scanner_exit_code=0)

        outcome = assess_image_updates(
            candidate_report(complete=False),
            Path("candidates.json"),
            vulnerability_report(),
            Path("vulnerabilities.json"),
            NoopClient(),
            "linux/amd64",
            scanner=scanner,
            version_reader=lambda client: "v1.24.0",
        )

        self.assertEqual(outcome.exit_code, 3)
        self.assertFalse(outcome.report["complete"])
        self.assertEqual(outcome.report["required_registry_hosts"], ["quay.io"])
        self.assertEqual(outcome.report["summary"]["scanned_candidate_count"], 1)

    def test_candidate_scan_failure_never_becomes_clean_or_authorized(self) -> None:
        """Retain one Scout failure as incomplete non-authorizing evidence."""

        def scanner(client, target, platform):
            return ImageScanResult(
                target=target,
                status="error",
                error="temporary registry failure",
                error_code="registry-failed",
                scanner_exit_code=1,
            )

        outcome = assess_image_updates(
            candidate_report(),
            Path("candidates.json"),
            vulnerability_report(),
            Path("vulnerabilities.json"),
            NoopClient(),
            "linux/amd64",
            scanner=scanner,
            version_reader=lambda client: "v1.24.0",
        )

        self.assertEqual(outcome.exit_code, 3)
        self.assertFalse(outcome.report["complete"])
        self.assertEqual(outcome.report["summary"]["failed_candidate_count"], 1)
        self.assertEqual(outcome.report["summary"]["deployable_fixable"]["total"], 0)
        self.assertTrue(
            all(
                candidate["deployment_authorized"] is False
                for image in outcome.report["images"]
                for candidate in image["candidates"]
            )
        )

    def test_mismatched_source_report_fails_before_scanning(self) -> None:
        """Reject candidate evidence after the live vulnerability scope changed."""

        source = vulnerability_report()
        source["scope"]["image_fingerprint"] = "different-scope"

        with self.assertRaises(ImageUpdateAssessmentError) as raised:
            assess_image_updates(
                candidate_report(),
                Path("candidates.json"),
                source,
                Path("vulnerabilities.json"),
                NoopClient(),
                "linux/amd64",
                scanner=lambda client, target, platform: ImageScanResult(
                    target=target,
                    status="clean",
                ),
                version_reader=lambda client: "v1.24.0",
            )

        self.assertEqual(raised.exception.code, "source-fingerprint-mismatch")


if __name__ == "__main__":
    unittest.main()
