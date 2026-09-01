"""Contract checks for the SCWP-03C QNAP and Swarm operator gates."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
QNAP = ROOT / "tests/acceptance/scwp_03c_qnap.sh"
SWARM = ROOT / "tests/acceptance/scwp_03c_swarm.sh"


class Scwp03cAcceptanceTests(unittest.TestCase):
    """Keep mutation disposable on QNAP and absent from the Swarm gate."""

    def test_qnap_gate_exercises_every_guarded_transaction_state(self) -> None:
        """Cover dry-run, cancellation, apply, post-check, and rollback evidence."""

        source = QNAP.read_text(encoding="utf-8")
        for fragment in (
            'project="swarm-info-scwp03c"',
            "--security-check",
            "--compose-remediation",
            "--rollback-compose-remediation",
            "validate_plan_status planned",
            "validate_plan_status cancelled",
            "validate_plan_status deployed",
            "validate_plan_status rolled-back",
            "exact prior image ID",
            "no Compose apply/rollback button",
        ):
            self.assertIn(fragment, source)

    def test_qnap_gate_never_targets_an_existing_project(self) -> None:
        """Refuse a namespace collision and avoid forceful Docker cleanup."""

        source = QNAP.read_text(encoding="utf-8")
        self.assertIn("Disposable fixture project already exists", source)
        self.assertNotIn("docker container rm --force", source)
        self.assertNotIn("docker image rm", source)
        self.assertNotIn("docker system prune", source)

    def test_swarm_gate_reuses_complete_read_only_regression(self) -> None:
        """Retain the accepted Swarm behavior without adding manager mutation."""

        source = SWARM.read_text(encoding="utf-8")
        self.assertIn("scwp_03b_swarm.sh", source)
        self.assertIn("SCWP-03C Ubuntu/Swarm regression passed", source)
        for mutation in ("docker stack deploy", "docker service update"):
            self.assertNotIn(mutation, source)


if __name__ == "__main__":
    unittest.main()
