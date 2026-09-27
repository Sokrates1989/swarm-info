"""Verify that option-4 batching never deploys an unapproved source change."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.operator_report import load_messages
from scripts.remediation_cli import _run_auto
from scripts.remediation_policy import load_policy
from scripts.remediation_source import SourceChange
from tests.test_remediation_engine import AutoRuntimeClient
from tests.test_remediation_policy import (
    deployment_map,
    policy_payload,
    vulnerability_report,
    write_policy,
)


class RemediationBatchTests(unittest.TestCase):
    """Protect sequential policy targets that share a declarative stack."""

    def test_declined_deploy_stops_later_targets_in_same_stack(self) -> None:
        """Do not let a later target indirectly deploy a pending source edit."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            source_file = root / ".env"
            source_file.write_bytes(b"IMAGE_VERSION=1.0.0\n")
            payload = policy_payload(
                source={"type": "dotenv", "file": ".env", "image_key": "IMAGE"}
            )
            second = json.loads(json.dumps(payload["targets"][0]))
            second["id"] = "demo-worker-update"
            second["match"]["service"] = "demo_worker"
            payload["targets"].append(second)
            policy = load_policy(write_policy(root, payload))
            mapping = deployment_map(root, stack_file)
            mapping["services"][1].update(
                status="mapped", reason="matched-stack-service-image",
                directory=str(root), stack_file=str(stack_file), compose_service="worker",
            )
            mapping["renderer"] = {"available": True}
            report_file = root / "vulnerability_scan.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file,
                deployment_map_file=None,
                deploy_roots=None,
                plan_output=root / "plan.json",
                max_age_hours=30.0,
                history_days=14,
                lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False,
                allow_runtime_override=False,
            )
            change = SourceChange(
                source_file, b"IMAGE_VERSION=1.0.0\n",
                b"IMAGE_VERSION=1.1.0\n", "reviewed diff\n", 0o600,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            answers = iter(("y", "n"))
            output = io.StringIO()
            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation) as scan,
                patch("scripts.remediation_cli.prepare_source_change", return_value=change),
                patch("scripts.remediation_cli.render_stack", return_value=b"services: {}\n"),
            ):
                result = _run_auto(
                    vulnerability_report(), mapping, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=lambda _: next(answers), output=output,
                )

            plan = json.loads(options.plan_output.read_text(encoding="utf-8"))
            self.assertEqual(source_file.read_bytes(), change.replacement)

        self.assertEqual(result, 0)
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(len(plan["execution"]), 1)
        self.assertEqual(plan["execution"][0]["status"], "source-updated-not-deployed")
        self.assertIn("option-4 run stops here", output.getvalue())
