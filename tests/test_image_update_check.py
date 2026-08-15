"""Verify exact current-versus-candidate image security comparisons."""

from __future__ import annotations

import io
import json
from pathlib import Path
import unittest

from scripts.image_update_check import render_outcome, run_image_update_check
from scripts.image_update_evidence import compare_candidate_evidence
from scripts.operator_report import load_messages
from scripts.vulnerability_models import Finding
from scripts.vulnerability_scan import CommandResult


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CURRENT_ID = "sha256:" + "a" * 64
CANDIDATE_ID = "sha256:" + "b" * 64


def sarif(findings: list[tuple[str, str]]) -> str:
    """Build minimal Docker Scout SARIF for deterministic comparison tests."""

    rules = [
        {
            "id": identifier,
            "shortDescription": {"text": identifier},
            "properties": {"tags": [severity]},
        }
        for identifier, severity in findings
    ]
    results = [
        {
            "ruleId": identifier,
            "level": "error",
            "message": {"text": identifier},
        }
        for identifier, _ in findings
    ]
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"rules": rules}}, "results": results}],
        }
    )


class LocalComparisonClient:
    """Model two exact local images and image-specific Scout findings."""

    def __init__(self, candidate_findings: list[tuple[str, str]]) -> None:
        """Store candidate findings and every Docker command invocation."""

        self.candidate_findings = candidate_findings
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Return local identity, version, and SARIF evidence."""

        command = list(arguments)
        self.commands.append(command)
        if command == ["scout", "version"]:
            return CommandResult(0, "version: v1.24.0\n", "")
        if command[:2] == ["image", "inspect"]:
            reference = command[-1]
            candidate = reference.startswith("ghcr.io/")
            image_id = CANDIDATE_ID if candidate else CURRENT_ID
            version = "2.55.1" if candidate else "1.61.1"
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Id": image_id,
                            "RepoDigests": [],
                            "Config": {
                                "Labels": {
                                    "org.opencontainers.image.version": version
                                }
                            },
                        }
                    ]
                ),
                "",
            )
        if command[:2] == ["scout", "cves"]:
            current_findings = [
                ("CVE-OLD-C1", "critical"),
                ("CVE-OLD-C2", "critical"),
                ("CVE-OLD-H1", "high"),
                ("CVE-OLD-H2", "high"),
            ]
            findings = (
                self.candidate_findings
                if CANDIDATE_ID in command[-1]
                else current_findings
            )
            return CommandResult(2 if findings else 0, sarif(findings), "")
        return CommandResult(64, "", f"unexpected command: {command}")


class ImageUpdateEvidenceTests(unittest.TestCase):
    """Lock the fail-closed security-delta classification."""

    def test_candidate_reduction_is_quantified(self) -> None:
        """Distinguish a partial improvement from a fully clean replacement."""

        candidate = (
            Finding("CVE-OLD-C1", "critical", "critical", None),
            Finding("CVE-OLD-H1", "high", "high", None),
        )
        evidence = compare_candidate_evidence(
            2,
            2,
            ["CVE-OLD-C1", "CVE-OLD-C2", "CVE-OLD-H1", "CVE-OLD-H2"],
            candidate,
        )

        self.assertEqual(evidence.status, "verified-improvement")
        self.assertEqual(evidence.removed_total, 2)
        self.assertEqual(evidence.candidate_total, 2)
        self.assertEqual(evidence.removed_finding_ids, ("CVE-OLD-C2", "CVE-OLD-H2"))

    def test_lower_count_with_new_finding_is_mixed_not_auto_safe(self) -> None:
        """Report a real reduction without accepting a newly introduced CVE."""

        evidence = compare_candidate_evidence(
            2,
            2,
            ["CVE-OLD-C1", "CVE-OLD-C2", "CVE-OLD-H1", "CVE-OLD-H2"],
            (Finding("CVE-NEW", "high", "new", None),),
        )

        self.assertEqual(evidence.status, "mixed-improvement")
        self.assertEqual(evidence.new_finding_ids, ("CVE-NEW",))
        self.assertEqual(evidence.removed_total, 3)
        self.assertFalse(evidence.is_verified_improvement)

    def test_higher_candidate_risk_is_a_regression(self) -> None:
        """Classify a candidate with increased critical risk as a regression."""

        evidence = compare_candidate_evidence(
            0,
            1,
            ["CVE-OLD-H1"],
            (
                Finding("CVE-OLD-H1", "high", "old", None),
                Finding("CVE-NEW-C1", "critical", "new", None),
            ),
        )

        self.assertEqual(evidence.status, "regression")
        self.assertFalse(evidence.is_verified_improvement)


class ImageUpdateCheckTests(unittest.TestCase):
    """Require exact local scans, cross-repository warnings, and clear verdicts."""

    def test_cross_repository_candidate_is_compared_but_not_authorized(self) -> None:
        """Permit read-only Browserless-style migration evidence without deployment."""

        client = LocalComparisonClient([("CVE-OLD-H1", "high")])
        outcome = run_image_update_check(
            client,
            "linux/amd64",
            "ghcr.io/browserless/chromium:v2.55.1",
            current_image="browserless/chrome:latest",
            heartbeat_interval_seconds=0,
        )

        self.assertEqual(outcome.exit_code, 2)
        self.assertEqual(
            outcome.report["comparison"]["status"], "verified-improvement"
        )
        self.assertEqual(outcome.report["comparison"]["removed"]["total"], 3)
        self.assertEqual(outcome.report["comparison"]["candidate"]["total"], 1)
        self.assertTrue(outcome.report["safety"]["repository_changed"])
        self.assertFalse(outcome.report["safety"]["deployment_authorized"])
        scan_references = [
            command[-1]
            for command in client.commands
            if command[:2] == ["scout", "cves"]
        ]
        self.assertEqual(
            scan_references,
            [f"local://{CURRENT_ID}", f"local://{CANDIDATE_ID}"],
        )

    def test_clean_locally_built_candidate_returns_clean_status(self) -> None:
        """Support private first-party candidate tags without a registry push."""

        outcome = run_image_update_check(
            LocalComparisonClient([]),
            "linux/amd64",
            "ghcr.io/browserless/chromium:v2.55.1",
            current_image="browserless/chrome:latest",
            heartbeat_interval_seconds=0,
        )

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.report["comparison"]["status"], "verified-clean")

    def test_render_explains_fixable_and_compatibility_boundaries(self) -> None:
        """Keep the terminal verdict understandable without reading JSON."""

        outcome = run_image_update_check(
            LocalComparisonClient([("CVE-OLD-H1", "high")]),
            "linux/amd64",
            "ghcr.io/browserless/chromium:v2.55.1",
            current_image="browserless/chrome:latest",
            heartbeat_interval_seconds=0,
        )
        output = io.StringIO()
        render_outcome(
            outcome,
            Path("/tmp/image-update.json"),
            load_messages("en"),
            output,
        )

        rendered = output.getvalue()
        self.assertIn("Scout knows a patched package version", rendered)
        self.assertIn("removes 3", rendered)
        self.assertIn("1 remain", rendered)
        self.assertIn("Removed finding IDs", rendered)
        self.assertIn("Remaining finding IDs", rendered)
        self.assertIn("Compatibility is NOT verified", rendered)
        self.assertIn("Images you build are supported", rendered)

    def test_public_cli_routes_comparison_without_expanding_auto_remediation(self) -> None:
        """Expose the read-only comparator while keeping mutation in its own workflow."""

        entrypoint = (REPOSITORY_ROOT / "get_info.sh").read_text(encoding="utf-8")
        bridge = (REPOSITORY_ROOT / "res" / "vulnerability_cli.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('selected_action="compare-image-update"', entrypoint)
        self.assertIn('"compare-image-update")', entrypoint)
        self.assertIn("-m scripts.image_update_check", bridge)
        comparison_source = (
            REPOSITORY_ROOT / "scripts" / "image_update_check.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("service update", comparison_source)


if __name__ == "__main__":
    unittest.main()
