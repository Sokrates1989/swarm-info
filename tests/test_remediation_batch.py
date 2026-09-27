"""Verify that option-4 batching never deploys an unapproved source change."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from string import Formatter
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.operator_report import load_messages
from scripts.remediation_cli import (
    _request_batch_confirmation,
    _run_auto,
    parse_arguments,
    run,
)
from scripts.remediation_engine import ActionResult, RemediationExecutionError
from scripts.remediation_policy import load_policy
from scripts.remediation_source import SourceChange
from tests.test_remediation_engine import AutoRuntimeClient
from tests.test_remediation_policy import (
    NEW_DIGEST,
    deployment_map,
    policy_payload,
    vulnerability_report,
    write_policy,
)


class RemediationBatchTests(unittest.TestCase):
    """Protect sequential policy targets that share a declarative stack."""

    def test_batch_flag_is_explicit_and_rejected_outside_option_four(self) -> None:
        """The opt-in must not change guided modes or their confirmations."""

        catalog = load_messages("en")
        parsed = parse_arguments(["--auto-confirm-policy-targets"], catalog)
        self.assertTrue(parsed.auto_confirm_policy_targets)
        with tempfile.TemporaryDirectory() as temporary:
            report_file = Path(temporary) / "report.json"
            report_file.write_text(json.dumps(vulnerability_report()), encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, max_age_hours=30.0,
                mode="service", auto_confirm_policy_targets=True,
            )
            output = io.StringIO()
            with (
                patch("scripts.remediation_cli.vulnerability_state", return_value=("vulnerable", "")),
                patch("scripts.remediation_cli._load_deployment_map", return_value={"services": []}),
                patch("scripts.remediation_cli.run_targeted") as guided,
            ):
                result = run(options, catalog, AutoRuntimeClient(), output=output)

        self.assertEqual(result, 3)
        guided.assert_not_called()
        self.assertIn("applies only to option 4", output.getvalue())

    def test_batch_acknowledgement_is_localized_with_matching_placeholders(self) -> None:
        """Keep both interactive warning languages complete and renderable."""

        en = load_messages("en")
        de = load_messages("de")
        for key in (
            "remediation.batchModePrompt",
            "remediation.batchManualSelected",
            "remediation.batchModeInterrupted",
            "remediation.batchConsentPhrase",
            "remediation.batchConsentPrompt",
            "remediation.batchConsentRejected",
            "remediation.batchConsentAccepted",
        ):
            self.assertIn(key, en)
            self.assertIn(key, de)
            placeholders = lambda value: {
                field for _, field, _, _ in Formatter().parse(value) if field
            }
            self.assertEqual(placeholders(en[key]), placeholders(de[key]))
        self.assertNotEqual(
            en["remediation.batchConsentPhrase"],
            de["remediation.batchConsentPhrase"],
        )

    def test_wrong_batch_sentence_stops_before_any_action(self) -> None:
        """A y answer or almost-correct phrase cannot authorize a fleet run."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            mapping = deployment_map(root, stack_file)
            mapping["renderer"] = {"available": True}
            policy = load_policy(write_policy(
                root, policy_payload(source={"type": "yaml_image", "file": stack_file.name})
            ))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False, allow_runtime_override=False,
                auto_confirm_policy_targets=True,
            )
            output = io.StringIO()
            for answer in ("y", load_messages("en")["remediation.batchConsentPhrase"] + " "):
                with self.subTest(answer=answer):
                    answers = iter(("y", answer))
                    with (
                        patch("scripts.remediation_cli.prepare_review", return_value=object()),
                        patch("scripts.remediation_cli.run_safe_latest_actions") as safe,
                        patch("scripts.remediation_cli.validate_candidate") as scan,
                    ):
                        result = _run_auto(
                            vulnerability_report(), mapping, policy, options,
                            AutoRuntimeClient(), load_messages("en"),
                            input_function=lambda _: next(answers), output=output,
                        )
                        safe.assert_not_called()
                        scan.assert_not_called()
                        self.assertEqual(result, 3)
            plan = json.loads(options.plan_output.read_text(encoding="utf-8"))
            self.assertNotIn("batch_confirmation", plan)
            self.assertEqual(stack_file.read_text(encoding="utf-8"), "services: {}\n")

    def test_exact_sentence_confirms_source_and_deploy_once(self) -> None:
        """A reviewed declarative target needs no extra yes/no answers."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            source_file = root / ".env"
            source_file.write_bytes(b"IMAGE_VERSION=1.0.0\n")
            mapping = deployment_map(root, stack_file)
            mapping["renderer"] = {"available": True}
            policy = load_policy(write_policy(
                root, policy_payload(source={"type": "dotenv", "file": ".env", "image_key": "IMAGE"})
            ))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False, allow_runtime_override=False,
                auto_confirm_policy_targets=True,
            )
            change = SourceChange(
                source_file, b"IMAGE_VERSION=1.0.0\n",
                b"IMAGE_VERSION=1.1.0\n", "reviewed diff\n", 0o600,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            phrase = load_messages("en")["remediation.batchConsentPhrase"]
            prompts: list[str] = []

            def acknowledge(prompt: str) -> str:
                """Allow the opt-in and sentence, but no later target prompts."""

                prompts.append(prompt)
                self.assertLessEqual(len(prompts), 2)
                return "y" if len(prompts) == 1 else phrase

            def publish_confirmation(*_: object, **__: object) -> int:
                """Publish a new complete report without contacting Docker."""

                report_file.write_text(json.dumps({
                    "completed_at": "2026-08-15T12:00:00Z",
                    "summary": {"complete": True, "status": "vulnerable"},
                }), encoding="utf-8")
                return 2

            output = io.StringIO()
            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation) as scan,
                patch("scripts.remediation_cli.prepare_source_change", return_value=change),
                patch("scripts.remediation_cli.render_stack", return_value=b"services: {}\n"),
                patch("scripts.remediation_cli.deploy_declarative_change", return_value=ActionResult(
                    "deployed", "demo_api", policy.targets[0].candidate.reference,
                )) as deploy,
                patch("scripts.remediation_cli.run_locked_job", side_effect=publish_confirmation),
            ):
                result = _run_auto(
                    vulnerability_report(), mapping, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=acknowledge, output=output,
                )
            plan = json.loads(options.plan_output.read_text(encoding="utf-8"))

            self.assertEqual(result, 0)
            self.assertEqual(source_file.read_bytes(), change.replacement)
            self.assertEqual(plan["batch_confirmation"]["policy_ids"], ["demo-api-update"])
            self.assertNotIn(phrase, options.plan_output.read_text(encoding="utf-8"))
            self.assertEqual(len(prompts), 2)
            self.assertIn("Source edit for demo_api", output.getvalue())
            self.assertIn("Stack deployment for demo_api", output.getvalue())
            scan.assert_called_once()
            deploy.assert_called_once()

    def test_default_no_keeps_individual_source_and_deploy_prompts(self) -> None:
        """Declining the optional batch mode must continue the reviewed manual flow."""

        for mode_answer in ("", "n"):
            with (
                self.subTest(mode_answer=mode_answer),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                stack_file = root / "swarm-stack.yml"
                stack_file.write_text("services: {}\n", encoding="utf-8")
                source_file = root / ".env"
                source_file.write_bytes(b"IMAGE_VERSION=1.0.0\n")
                mapping = deployment_map(root, stack_file)
                mapping["renderer"] = {"available": True}
                policy = load_policy(write_policy(
                    root, policy_payload(
                        source={"type": "dotenv", "file": ".env", "image_key": "IMAGE"}
                    )
                ))
                report_file = root / "report.json"
                report_file.write_text("{}", encoding="utf-8")
                options = argparse.Namespace(
                    report_file=report_file, deployment_map_file=None, deploy_roots=None,
                    plan_output=root / "plan.json", max_age_hours=30.0,
                    history_days=14, lock_file=root / "scan.lock",
                    force_auto_remedy_attempt=False, allow_runtime_override=False,
                    auto_confirm_policy_targets=True,
                )
                change = SourceChange(
                    source_file, b"IMAGE_VERSION=1.0.0\n",
                    b"IMAGE_VERSION=1.1.0\n", "reviewed diff\n", 0o600,
                )
                validation = SimpleNamespace(
                    critical=0, high=0,
                    comparison=SimpleNamespace(removed_total=2, candidate_total=0),
                )
                answers = iter((mode_answer, "y", "y"))
                prompts: list[str] = []

                def publish_confirmation(*_: object, **__: object) -> int:
                    """Publish a complete mocked report after the manual deployment."""

                    report_file.write_text(json.dumps({
                        "completed_at": "2026-08-15T12:00:00Z",
                        "summary": {"complete": True, "status": "vulnerable"},
                    }), encoding="utf-8")
                    return 2

                output = io.StringIO()
                with (
                    patch("scripts.remediation_cli.prepare_review", return_value=object()),
                    patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                    patch("scripts.remediation_cli.validate_candidate", return_value=validation),
                    patch("scripts.remediation_cli.prepare_source_change", return_value=change),
                    patch("scripts.remediation_cli.render_stack", return_value=b"services: {}\n"),
                    patch("scripts.remediation_cli.deploy_declarative_change", return_value=ActionResult(
                        "deployed", "demo_api", policy.targets[0].candidate.reference,
                    )) as deploy,
                    patch("scripts.remediation_cli.run_locked_job", side_effect=publish_confirmation),
                ):
                    result = _run_auto(
                        vulnerability_report(), mapping, policy, options,
                        AutoRuntimeClient(), load_messages("en"),
                        input_function=lambda prompt: prompts.append(prompt) or next(answers),
                        output=output,
                    )

                self.assertEqual(result, 0)
                self.assertEqual(source_file.read_bytes(), change.replacement)
                self.assertEqual(len(prompts), 3)
                self.assertIn("auto-confirm", prompts[0])
                self.assertIn("Apply the reviewed change", prompts[1])
                self.assertIn("Deploy stack", prompts[2])
                self.assertIn("individual source and deployment prompts", output.getvalue())
                self.assertNotIn(
                    "batch_confirmation",
                    json.loads(options.plan_output.read_text(encoding="utf-8")),
                )
                deploy.assert_called_once()

    def test_interrupted_batch_choice_aborts_before_actions(self) -> None:
        """An interrupted opt-in must not silently continue into mutations."""

        output = io.StringIO()
        for interruption in (EOFError, KeyboardInterrupt):

            def interrupt(_: str) -> str:
                raise interruption()

            result = _request_batch_confirmation(
                frozenset({"reviewed-target"}), "default", load_messages("en"),
                interrupt, output,
            )
            self.assertIsNone(result)
        self.assertIn("choice was interrupted", output.getvalue())

    def test_force_attempted_target_keeps_its_own_confirmation(self) -> None:
        """The batch sentence cannot silently approve auto_eligible=false."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = load_policy(write_policy(
                root, policy_payload(auto_eligible=False, source=None)
            ))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=True, allow_runtime_override=True,
                auto_confirm_policy_targets=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            prompts: list[str] = []

            def decline(prompt: str) -> str:
                """Decline the ordinary runtime prompt for a forced target."""

                prompts.append(prompt)
                return "n"

            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation),
                patch("scripts.remediation_cli.execute_runtime_override") as deploy,
            ):
                result = _run_auto(
                    vulnerability_report(), {"services": []}, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=decline, output=io.StringIO(),
                )

            self.assertEqual(result, 0)
            self.assertEqual(len(prompts), 1)
            self.assertIn("Temporarily update service", prompts[0])
            deploy.assert_not_called()
            self.assertNotIn(
                "batch_confirmation",
                json.loads(options.plan_output.read_text(encoding="utf-8")),
            )

    def test_runtime_override_needs_separate_flag_even_with_batch_option(self) -> None:
        """The batch switch does not itself enable configuration drift."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = load_policy(write_policy(root, policy_payload(source=None)))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False, allow_runtime_override=False,
                auto_confirm_policy_targets=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            prompts: list[str] = []
            output = io.StringIO()
            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation),
                patch("scripts.remediation_cli.execute_runtime_override") as deploy,
            ):
                result = _run_auto(
                    vulnerability_report(), {"services": []}, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=lambda prompt: prompts.append(prompt) or "y",
                    output=output,
                )

            self.assertEqual(result, 0)
            self.assertEqual(prompts, [])
            deploy.assert_not_called()
            self.assertIn("Runtime execution is disabled", output.getvalue())
            self.assertNotIn(
                "batch_confirmation",
                json.loads(options.plan_output.read_text(encoding="utf-8")),
            )

    def test_runtime_override_uses_sentence_only_with_separate_flag(self) -> None:
        """An eligible, explicitly enabled override uses the same one-run consent."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = load_policy(write_policy(root, policy_payload(source=None)))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False, allow_runtime_override=True,
                auto_confirm_policy_targets=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            phrase = load_messages("en")["remediation.batchConsentPhrase"]
            prompts: list[str] = []
            output = io.StringIO()

            def acknowledge(prompt: str) -> str:
                """Allow only the opt-in and sentence for this runtime action."""

                prompts.append(prompt)
                self.assertLessEqual(len(prompts), 2)
                return "y" if len(prompts) == 1 else phrase

            def publish_confirmation(*_: object, **__: object) -> int:
                """Write fresh, complete evidence for the mocked final scan."""

                report_file.write_text(json.dumps({
                    "completed_at": "2026-08-15T12:00:00Z",
                    "summary": {"complete": True, "status": "vulnerable"},
                }), encoding="utf-8")
                return 2

            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation),
                patch("scripts.remediation_cli.execute_runtime_override", return_value=ActionResult(
                    "deployed", "demo_api", policy.targets[0].candidate.reference,
                    config_drift=True,
                )) as deploy,
                patch("scripts.remediation_cli.run_locked_job", side_effect=publish_confirmation),
            ):
                result = _run_auto(
                    vulnerability_report(), {"services": []}, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=acknowledge, output=output,
                )

            self.assertEqual(result, 0)
            self.assertEqual(len(prompts), 2)
            self.assertIn("runtime override for demo_api", output.getvalue())
            deploy.assert_called_once()

    def test_policy_latest_refresh_uses_one_typed_acknowledgement(self) -> None:
        """Policy-authorized latest refresh is covered without changing built-ins."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stack_file = root / "swarm-stack.yml"
            stack_file.write_text("services: {}\n", encoding="utf-8")
            mapping = deployment_map(root, stack_file)
            mapping["services"][0]["declared_image"] = "registry.example/team/app:latest"
            candidate = f"registry.example/team/app:latest@{NEW_DIGEST}"
            policy = load_policy(write_policy(
                root, policy_payload(candidate=candidate, source=None)
            ))
            report_file = root / "report.json"
            report_file.write_text("{}", encoding="utf-8")
            options = argparse.Namespace(
                report_file=report_file, deployment_map_file=None, deploy_roots=None,
                plan_output=root / "plan.json", max_age_hours=30.0,
                history_days=14, lock_file=root / "scan.lock",
                force_auto_remedy_attempt=False, allow_runtime_override=False,
                auto_confirm_policy_targets=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            phrase = load_messages("en")["remediation.batchConsentPhrase"]
            prompts: list[str] = []
            output = io.StringIO()

            def acknowledge(prompt: str) -> str:
                """Allow opt-in and sentence, but no per-target confirmation."""

                prompts.append(prompt)
                self.assertLessEqual(len(prompts), 2)
                return "y" if len(prompts) == 1 else phrase

            def publish_confirmation(*_: object, **__: object) -> int:
                """Write a fresh complete report without a live image scan."""

                report_file.write_text(json.dumps({
                    "completed_at": "2026-08-15T12:00:00Z",
                    "summary": {"complete": True, "status": "vulnerable"},
                }), encoding="utf-8")
                return 2

            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation),
                patch("scripts.remediation_cli.execute_latest_refresh", return_value=ActionResult(
                    "deployed", "demo_api", candidate,
                )) as deploy,
                patch("scripts.remediation_cli.run_locked_job", side_effect=publish_confirmation),
            ):
                result = _run_auto(
                    vulnerability_report(), mapping, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=acknowledge, output=output,
                )

            self.assertEqual(result, 0)
            self.assertEqual(len(prompts), 2)
            self.assertIn("Policy latest refresh for demo_api", output.getvalue())
            deploy.assert_called_once()

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

    def test_opt_in_continues_only_after_candidate_rejection(self) -> None:
        """A non-mutating Scout verdict may be skipped without losing the cohort."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = policy_payload(source=None)
            second = json.loads(json.dumps(payload["targets"][0]))
            second["id"] = "demo-worker-update"
            second["match"]["service"] = "demo_worker"
            payload["targets"].append(second)
            policy = load_policy(write_policy(root, payload))
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
                continue_on_safe_error=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            output = io.StringIO()
            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch(
                    "scripts.remediation_cli.validate_candidate",
                    side_effect=[
                        RemediationExecutionError("candidate-not-improved"),
                        validation,
                    ],
                ) as scan,
            ):
                result = _run_auto(
                    vulnerability_report(), {"services": []}, policy, options,
                    AutoRuntimeClient(), load_messages("en"),
                    input_function=lambda _: "n", output=output,
                )
            plan = json.loads(options.plan_output.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(plan["execution"][0]["status"], "skipped-safe-error")
        self.assertEqual(plan["execution"][0]["detail"], "candidate-not-improved")
        self.assertIn("Continuing to the next target", output.getvalue())

    def test_invalid_stack_preflight_is_skippable_only_with_opt_in(self) -> None:
        """Continue past a rejected temporary stack without editing real source."""

        for allow_continue in (False, True):
            with self.subTest(allow_continue=allow_continue):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    stack_file = root / "swarm-stack.yml"
                    original = b"services:\n  api:\n    image: old\n"
                    stack_file.write_bytes(original)
                    payload = policy_payload(
                        source={"type": "yaml_image", "file": stack_file.name}
                    )
                    second = json.loads(json.dumps(payload["targets"][0]))
                    second["id"] = "demo-worker-update"
                    second["match"]["service"] = "demo_worker"
                    payload["targets"].append(second)
                    policy = load_policy(write_policy(root, payload))
                    mapping = deployment_map(root, stack_file)
                    mapping["services"][1].update(
                        status="mapped", reason="matched-stack-service-image",
                        directory=str(root), stack_file=str(stack_file),
                        compose_service="worker",
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
                        continue_on_safe_error=allow_continue,
                    )
                    change = SourceChange(
                        stack_file, original, b"services: {}\n", "reviewed diff\n", 0o600
                    )
                    validation = SimpleNamespace(
                        critical=0, high=0,
                        comparison=SimpleNamespace(removed_total=2, candidate_total=0),
                    )
                    output = io.StringIO()
                    with (
                        patch("scripts.remediation_cli.prepare_review", return_value=object()),
                        patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                        patch(
                            "scripts.remediation_cli.validate_candidate",
                            side_effect=[
                                validation,
                                RemediationExecutionError("candidate-not-improved"),
                            ],
                        ) as scan,
                        patch("scripts.remediation_cli.prepare_source_change", return_value=change),
                        patch(
                            "scripts.remediation_cli.preview_yaml_image_change",
                            side_effect=RemediationExecutionError("stack-config-invalid"),
                        ),
                    ):
                        if allow_continue:
                            result = _run_auto(
                                vulnerability_report(), mapping, policy, options,
                                AutoRuntimeClient(), load_messages("en"),
                                input_function=lambda _: "n", output=output,
                            )
                            self.assertEqual(result, 0)
                        else:
                            with self.assertRaises(RemediationExecutionError) as context:
                                _run_auto(
                                    vulnerability_report(), mapping, policy, options,
                                    AutoRuntimeClient(), load_messages("en"),
                                    input_function=lambda _: "n", output=output,
                                )
                            self.assertEqual(context.exception.code, "stack-config-invalid")
                    plan = json.loads(options.plan_output.read_text(encoding="utf-8"))
                    self.assertEqual(stack_file.read_bytes(), original)

                self.assertEqual(scan.call_count, 2 if allow_continue else 1)
                self.assertEqual(
                    [item["detail"] for item in plan.get("execution", [])],
                    ["stack-config-invalid", "candidate-not-improved"]
                    if allow_continue else [],
                )

    def test_opt_in_still_stops_after_rollout_error(self) -> None:
        """Never start another target when deployment effects may be uncertain."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = policy_payload(source=None)
            second = json.loads(json.dumps(payload["targets"][0]))
            second["id"] = "demo-worker-update"
            second["match"]["service"] = "demo_worker"
            payload["targets"].append(second)
            policy = load_policy(write_policy(root, payload))
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
                allow_runtime_override=True,
                continue_on_safe_error=True,
            )
            validation = SimpleNamespace(
                critical=0, high=0,
                comparison=SimpleNamespace(removed_total=2, candidate_total=0),
            )
            with (
                patch("scripts.remediation_cli.prepare_review", return_value=object()),
                patch("scripts.remediation_cli.run_safe_latest_actions", return_value=0),
                patch("scripts.remediation_cli.validate_candidate", return_value=validation) as scan,
                patch(
                    "scripts.remediation_cli.execute_runtime_override",
                    side_effect=RemediationExecutionError("runtime-rollback-uncertain"),
                ),
            ):
                with self.assertRaises(RemediationExecutionError):
                    _run_auto(
                        vulnerability_report(), {"services": []}, policy, options,
                        AutoRuntimeClient(), load_messages("en"),
                        input_function=lambda _: "y", output=io.StringIO(),
                    )

        self.assertEqual(scan.call_count, 1)
