"""Verify evidence-backed image proposals and TTY styling."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.remediation_advice import (
    _parse_imagetools,
    _parse_manifest_inspect,
    analyze_image,
    parse_scout_base_advice,
)
from scripts.remediation_guidance import render_detail
from scripts.operator_report import load_messages
from scripts.remediation_policy import load_policy
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_scan import CommandResult


OLD_DIGEST = "sha256:" + "1" * 64
NEW_DIGEST = "sha256:" + "2" * 64
OLD_IMAGE = f"browserless/chrome:latest@{OLD_DIGEST}"
NEW_IMAGE = f"docker.io/browserless/chrome:latest@{NEW_DIGEST}"


def sarif(findings: list[tuple[str, str]]) -> str:
    """Return deterministic SARIF for a candidate Scout response."""

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


def vulnerable_item() -> dict[str, object]:
    """Return one latest-pinned image with safe comparison evidence."""

    return {
        "service": "demo_browser",
        "services": ["demo_browser", "demo_worker"],
        "image": OLD_IMAGE,
        "critical": 2,
        "high": 4,
        "shared_service_count": 2,
        "finding_ids": ["CVE-OLD-1", "CVE-OLD-2"],
    }


class AdviceClient:
    """Model local metadata, current latest registry metadata, and Scout."""

    def __init__(
        self,
        *,
        latest_digest: str = NEW_DIGEST,
        candidate_findings: list[tuple[str, str]] | None = None,
    ) -> None:
        """Store registry state and candidate findings."""

        self.latest_digest = latest_digest
        self.candidate_findings = candidate_findings or []
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Return command-specific deterministic evidence."""

        command = list(arguments)
        self.commands.append(command)
        if command[:2] == ["image", "inspect"]:
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Config": {
                                "Labels": {"org.opencontainers.image.version": "5.1.0"}
                            },
                            "RepoDigests": [
                                f"browserless/chrome@{OLD_DIGEST}"
                            ],
                        }
                    ]
                ),
                "",
            )
        if command[:3] == ["buildx", "imagetools", "inspect"]:
            reference = command[-1]
            digest = OLD_DIGEST if "@sha256:" in reference else self.latest_digest
            version = "5.1.0" if "@sha256:" in reference else "5.2.0"
            return CommandResult(
                0,
                json.dumps(
                    {
                        "manifest": {"digest": digest},
                        "image": {
                            "config": {
                                "Labels": {
                                    "org.opencontainers.image.version": version
                                }
                            }
                        },
                    }
                ),
                "",
            )
        if command[:2] == ["scout", "recommendations"]:
            return CommandResult(
                0,
                "Base image is debian:12-slim\n"
                "Refresh base image\n"
                "Tag │ Details\n"
                "12-slim │ Newer image for same tag\n",
                "",
            )
        if command[:2] == ["scout", "cves"]:
            return CommandResult(
                2 if self.candidate_findings else 0,
                sarif(self.candidate_findings),
                "",
            )
        return CommandResult(1, "", "unexpected command")


class RemediationAdviceTests(unittest.TestCase):
    """Keep proposals immutable, version-aware, and validator-backed."""

    def test_scout_refresh_is_parsed_as_base_image_advice(self) -> None:
        """Do not confuse Scout's base tag with an application image tag."""

        advice = parse_scout_base_advice(
            0,
            "Base image is debian:11-slim\n"
            "Refresh base image\n"
            "Tag │ Details\n"
            "11-slim │ Newer image for same tag\n",
        )

        self.assertEqual(advice.status, "available")
        self.assertEqual(advice.base_image, "debian:11-slim")
        self.assertEqual(advice.refresh_tag, "11-slim")

    def test_multi_platform_registry_metadata_uses_requested_oci_version(self) -> None:
        """Read version annotations from the selected platform descriptor."""

        metadata = _parse_imagetools(
            json.dumps(
                {
                    "manifest": {
                        "digest": NEW_DIGEST,
                        "manifests": [
                            {
                                "digest": "sha256:" + "3" * 64,
                                "platform": {"os": "linux", "architecture": "amd64"},
                                "annotations": {
                                    "org.opencontainers.image.version": "6.0.1"
                                },
                            },
                            {
                                "digest": "sha256:" + "4" * 64,
                                "platform": {"os": "linux", "architecture": "arm64"},
                                "annotations": {
                                    "org.opencontainers.image.version": "6.0.2"
                                },
                            },
                        ],
                    },
                    "linux/amd64": {"config": {}},
                }
            ),
            "latest",
            "linux/amd64",
        )

        self.assertEqual(metadata.digest, NEW_DIGEST)
        self.assertEqual(metadata.version, "6.0.1")
        self.assertEqual(
            metadata.version_source,
            "org.opencontainers.image.version",
        )

    def test_manifest_fallback_selects_requested_platform_digest(self) -> None:
        """Keep latest resolution available when Docker Buildx is absent."""

        metadata = _parse_manifest_inspect(
            json.dumps(
                [
                    {
                        "Digest": "sha256:" + "3" * 64,
                        "Platform": {"os": "linux", "architecture": "arm64"},
                    },
                    {
                        "Digest": NEW_DIGEST,
                        "Platform": {"os": "linux", "architecture": "amd64"},
                    },
                ]
            ),
            "latest",
            "linux/amd64",
        )

        self.assertEqual(metadata.digest, NEW_DIGEST)
        self.assertIsNone(metadata.version)

    def test_moved_latest_is_proposed_only_after_candidate_scan(self) -> None:
        """Resolve, version, and validate a new latest digest before suggesting it."""

        client = AdviceClient()
        advice = analyze_image(client, vulnerable_item(), "linux/amd64")

        self.assertEqual(advice.current_version, "5.1.0")
        self.assertEqual(advice.candidate_version, "5.2.0")
        self.assertEqual(advice.compatibility, "same-major")
        self.assertEqual(advice.proposal_state, "candidate-validated")
        self.assertEqual(advice.validated_candidate.reference, NEW_IMAGE)
        self.assertTrue(
            any(
                command[:2] == ["scout", "cves"]
                and f"local://{NEW_IMAGE}" in command
                for command in client.commands
            )
        )

    def test_unchanged_latest_does_not_trigger_a_candidate_scan(self) -> None:
        """Tell operators that redeploying an unchanged digest cannot help."""

        client = AdviceClient(latest_digest=OLD_DIGEST)
        advice = analyze_image(client, vulnerable_item(), "linux/amd64")

        self.assertEqual(advice.proposal_state, "latest-current")
        self.assertIsNone(advice.validated_candidate)
        self.assertFalse(
            any(command[:2] == ["scout", "cves"] for command in client.commands)
        )

    def test_candidate_with_new_finding_is_not_placed_in_commands(self) -> None:
        """Use the same no-new-findings gate as automatic remediation."""

        advice = analyze_image(
            AdviceClient(candidate_findings=[("CVE-NEW", "high")]),
            vulnerable_item(),
            "linux/amd64",
        )

        self.assertEqual(advice.proposal_state, "candidate-rejected")
        self.assertEqual(advice.validation_error, "candidate-new-findings")
        self.assertIsNone(advice.validated_candidate)

    def test_policy_candidate_is_reused_by_manual_guidance(self) -> None:
        """Share the installation-owned candidate and validator with auto-remedy."""

        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "targets": [
                            {
                                "id": "browser-refresh",
                                "enabled": True,
                                "match": {
                                    "service": "demo_browser",
                                    "repository": "docker.io/browserless/chrome",
                                },
                                "candidate_image": NEW_IMAGE,
                                "backup": {
                                    "status": "not_required",
                                    "reason": "Stateless browser worker.",
                                },
                                "auto_eligible": True,
                                "source": None,
                                "verification": {"timeout_seconds": 30},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            advice = analyze_image(
                AdviceClient(),
                vulnerable_item(),
                "linux/amd64",
                load_policy(policy_path),
            )

        self.assertEqual(advice.candidate_source, "policy")
        self.assertEqual(advice.policy_service_count, 1)
        self.assertIsNotNone(advice.validated_candidate)

    def test_detail_starts_with_second_terminal_and_reuses_validated_latest(self) -> None:
        """Render the safe candidate in redeploy guidance without a fake source edit."""

        output = io.StringIO()
        render_detail(
            vulnerable_item(),
            {
                "status": "mapped",
                "directory": "/swarm/demo",
                "stack_file": "/swarm/demo/swarm-stack.yml",
                "stack": "demo",
                "declared_image": "browserless/chrome:latest",
                "source_verified": True,
            },
            load_messages("en"),
            output,
            input_function=lambda _: "",
            client=AdviceClient(),
            platform="linux/amd64",
        )
        rendered = output.getvalue()

        self.assertLess(
            rendered.index("0) Open a second terminal"),
            rendered.index("1) Analyze"),
        )
        self.assertLess(rendered.index("1) Analyze"), rendered.index("2) demo_browser"))
        self.assertIn(NEW_IMAGE, rendered)
        self.assertIn("source already follows latest", rendered)
        self.assertIn("--resolve-image always", rendered)
        self.assertIn(
            "swarm-info --scan-vulnerabilities --service demo_browser",
            rendered,
        )
        self.assertIn(
            "swarm-info --scan-vulnerabilities --output-file "
            "/info_json/vulnerability_scan.json",
            rendered,
        )
        self.assertNotIn("git diff", rendered)


class TtyBuffer(io.StringIO):
    """String buffer that models an interactive terminal."""

    def isatty(self) -> bool:
        """Report interactive output for styling tests."""

        return True


class TerminalStyleTests(unittest.TestCase):
    """Keep color useful in terminals and absent from redirected output."""

    def test_commands_are_colored_only_for_tty_without_no_color(self) -> None:
        """Honor both TTY detection and the standard NO_COLOR opt-out."""

        colored = TerminalStyle(TtyBuffer(), {}).command("docker scout cves image")
        disabled = TerminalStyle(TtyBuffer(), {"NO_COLOR": "1"}).command(
            "docker scout cves image"
        )
        redirected = TerminalStyle(io.StringIO(), {}).command("docker scout cves image")

        self.assertIn("\033[", colored)
        self.assertEqual(disabled, "docker scout cves image")
        self.assertEqual(redirected, "docker scout cves image")


if __name__ == "__main__":
    unittest.main()
