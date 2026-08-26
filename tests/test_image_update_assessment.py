"""Verify deduplicated batch candidate scans and deployable-fix evidence."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.image_update_assessment import (
    ImageUpdateAssessmentError,
    assess_image_updates,
)
from scripts.image_update_assessment_cli import _source_vulnerability_report_path
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
        self.assertEqual(outcome.report["scope"]["resource_type"], "service")
        self.assertEqual(outcome.report["scope"]["resource_count"], 3)
        self.assertEqual(summary["resources_with_verified_candidate"], 3)

    def test_container_assessment_projects_compose_lineage_and_host_commands(
        self,
    ) -> None:
        """Publish exact Compose guidance without authorizing browser mutation."""

        candidates = candidate_report()
        resources = [
            ("demo_api", "api"),
            ("demo_worker", "worker"),
            ("other_api", "other"),
        ]
        resource_index = 0
        for image in candidates["images"]:
            current = image["current"]
            count = len(current["services"])
            current["resource_type"] = "container"
            current["local_image_id"] = current["digest"]
            current["resources"] = []
            for name, service in resources[resource_index : resource_index + count]:
                current["resources"].append(
                    {
                        "type": "container",
                        "name": name,
                        "selectors": {
                            "container": name,
                            "image_id": current["digest"],
                            "compose_project": "demo",
                            "compose_service": f"demo/{service}",
                        },
                        "ownership": {
                            "compose_project": "demo",
                            "compose_service": service,
                            "working_directory": "/srv/demo",
                            "config_files": [
                                "/srv/demo/compose.yml",
                                "/srv/demo/compose.override.yml",
                            ],
                            "complete": True,
                        },
                    }
                )
            resource_index += count

        outcome = assess_image_updates(
            candidates,
            Path("candidates.json"),
            vulnerability_report(),
            Path("vulnerabilities.json"),
            NoopClient(),
            "linux/amd64",
            scanner=lambda client, target, platform: ImageScanResult(
                target=target,
                status="clean",
                scanner_exit_code=0,
                scan_source="registry",
            ),
            version_reader=lambda client: "v1.24.0",
        )

        self.assertEqual(outcome.report["scope"], {
            "resource_type": "container",
            "resource_count": 3,
        })
        row = next(
            item
            for item in outcome.report["resources"]
            if item["resource"] == "demo_api"
        )
        self.assertEqual(row["resource_type"], "container")
        self.assertEqual(
            row["ownership"]["config_files"],
            ["/srv/demo/compose.yml", "/srv/demo/compose.override.yml"],
        )
        self.assertEqual(
            row["candidate_lineage"]["immutable_reference"],
            CANDIDATE_REFERENCE,
        )
        self.assertEqual(
            row["commands"]["focused_rescan"],
            "swarm-info --security-check --compose-service demo/api --os auto",
        )
        self.assertEqual(
            row["commands"]["compose_validate"],
            "docker compose --project-name demo --project-directory /srv/demo "
            "--file /srv/demo/compose.yml --file "
            "/srv/demo/compose.override.yml config --quiet",
        )
        self.assertEqual(
            row["commands"]["candidate_pull"],
            f"docker pull {CANDIDATE_REFERENCE}",
        )
        self.assertEqual(len(row["commands"]["source_backup"]), 2)
        self.assertIn(
            "/srv/demo/compose.yml.swarm-info.bak.$(date -u +%Y%m%dT%H%M%SZ)",
            row["commands"]["source_backup"][0],
        )
        self.assertFalse(row["deployment_authorized"])
        self.assertEqual(
            outcome.report["summary"]["resources_with_verified_candidate"],
            3,
        )

    def test_container_assessment_joins_exact_local_artifact_identity(self) -> None:
        """Match current evidence by local image ID when no registry digest exists."""

        candidates = candidate_report()
        candidates["images"] = [candidates["images"][0]]
        current = candidates["images"][0]["current"]
        current["digest"] = None
        current["source_artifact"] = CURRENT_ONE_DIGEST
        current["local_image_id"] = CURRENT_ONE_DIGEST
        current["resource_type"] = "container"
        current["resources"] = [
            {
                "type": "container",
                "name": "demo_api",
                "selectors": {
                    "container": "demo_api",
                    "image_id": CURRENT_ONE_DIGEST,
                },
                "ownership": {
                    "compose_project": None,
                    "compose_service": None,
                    "working_directory": None,
                    "config_files": [],
                    "complete": False,
                },
            }
        ]
        source = vulnerability_report()
        source["images"][0]["digest"] = None
        source["images"][0]["local_image_id"] = CURRENT_ONE_DIGEST

        outcome = assess_image_updates(
            candidates,
            Path("candidates.json"),
            source,
            Path("security_scan-running.json"),
            NoopClient(),
            "linux/amd64",
            scanner=lambda client, target, platform: ImageScanResult(
                target=target,
                status="clean",
                scanner_exit_code=0,
            ),
            version_reader=lambda client: "v1.24.0",
        )

        self.assertEqual(outcome.exit_code, 2)
        self.assertEqual(outcome.report["scope"]["resource_type"], "container")
        self.assertEqual(
            outcome.report["resources"][0]["current_lineage"]["local_image_id"],
            CURRENT_ONE_DIGEST,
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

    def test_recorded_source_report_is_selected_beside_candidate_evidence(self) -> None:
        """Keep a copied Slice 1 evidence directory self-contained by default."""

        with TemporaryDirectory() as directory:
            evidence = Path(directory)
            candidate_path = evidence / "image_update_candidates.json"
            source_path = evidence / "vulnerability_scan.json"
            source_path.write_text("{}", encoding="utf-8")
            report = {"source_report": {"path": source_path.name}}

            selected = _source_vulnerability_report_path(
                report,
                candidate_path,
                None,
            )

            self.assertEqual(selected, source_path)

    def test_explicit_source_report_overrides_recorded_path(self) -> None:
        """Retain an operator override for deliberately relocated evidence."""

        selected = _source_vulnerability_report_path(
            {"source_report": {"path": "recorded.json"}},
            Path("candidates.json"),
            Path("selected.json"),
        )

        self.assertEqual(selected, Path("selected.json"))

    def test_missing_recorded_source_path_fails_closed(self) -> None:
        """Never silently compare candidates with an unrelated mutable report."""

        with self.assertRaises(ImageUpdateAssessmentError) as raised:
            _source_vulnerability_report_path({}, Path("candidates.json"), None)

        self.assertEqual(raised.exception.code, "source-path-missing")


if __name__ == "__main__":
    unittest.main()
