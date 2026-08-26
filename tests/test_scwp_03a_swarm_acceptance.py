"""Contract checks for the operator-confirmed SCWP-03A Swarm regression."""

from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = REPOSITORY_ROOT / "tests/acceptance/scwp_03a_swarm.sh"


class Scwp03aSwarmAcceptanceTests(unittest.TestCase):
    """Keep the Ubuntu gate read-only and tied to the deployed release."""

    def test_gate_verifies_images_evidence_api_ui_and_telegram(self) -> None:
        """Cover the meaningful Swarm regression without deploying from the gate."""

        source = ACCEPTANCE.read_text(encoding="utf-8")
        for fragment in (
            "SCWP_WATCHDOG_VERSION",
            "docker service ls",
            "docker service inspect",
            'swarm.cronjob.enable',
            '{"0/0", "0/1", "1/1"}',
            "--platform-info",
            "--service-health",
            "--vulnerability-status",
            "image_update_assessment.json",
            "/image-update-assessment",
            "X-Watchdog-Admin-Token",
            "Send one Telegram Info test",
        ):
            self.assertIn(fragment, source)

    def test_gate_never_deploys_or_updates_services(self) -> None:
        """Leave image publication and deployment to the operator's existing tools."""

        source = ACCEPTANCE.read_text(encoding="utf-8")
        for mutation in (
            "docker stack deploy",
            "docker service update",
            "docker compose up",
            "docker secret rm",
        ):
            self.assertNotIn(mutation, source)


if __name__ == "__main__":
    unittest.main()
