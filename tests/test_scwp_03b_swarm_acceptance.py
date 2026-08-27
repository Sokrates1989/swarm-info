"""Contract checks for the operator-confirmed SCWP-03B Swarm regression."""

from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = REPOSITORY_ROOT / "tests/acceptance/scwp_03b_swarm.sh"


class Scwp03bSwarmAcceptanceTests(unittest.TestCase):
    """Keep the manager gate preview-only and tied to the deployed release."""

    def test_gate_verifies_capabilities_cleanup_regressions_and_ui(self) -> None:
        """Cover all meaningful SCWP-03B Swarm regression boundaries."""

        source = ACCEPTANCE.read_text(encoding="utf-8")
        for fragment in (
            "SCWP_WATCHDOG_VERSION",
            "--platform-info",
            'capabilities.get("runtime_hardening") is False',
            'capabilities.get("image_cleanup") is True',
            "--image-cleanup",
            "docker image ls --all",
            "cmp -s",
            "unittest discover -s tests -v",
            "Telegram Info test",
            "cards are not shown in Swarm mode",
        ):
            self.assertIn(fragment, source)

    def test_gate_never_deploys_or_applies_cleanup(self) -> None:
        """Leave image publication, deployment, and cleanup apply to operators."""

        source = ACCEPTANCE.read_text(encoding="utf-8")
        for mutation in (
            "--image-cleanup --apply",
            "docker image rm",
            "docker system prune",
            "docker stack deploy",
            "docker service update",
        ):
            self.assertNotIn(mutation, source)


if __name__ == "__main__":
    unittest.main()
