"""Contract checks for the SCWP-01 producer gate on a real Swarm manager."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tests/acceptance/scwp_01_swarm.sh"


class Scwp01SwarmAcceptanceTests(unittest.TestCase):
    """Keep the gate aligned with the deployed host evidence path."""

    def test_gate_reads_deployed_report_with_an_explicit_override(self) -> None:
        """Avoid falling back to a checkout-local report absent in production."""

        source = GATE.read_text(encoding="utf-8")

        self.assertIn(
            "SCWP_VULNERABILITY_REPORT:-/info_json/vulnerability_scan.json",
            source,
        )
        self.assertIn('--output-file "$vulnerability_report"', source)


if __name__ == "__main__":
    unittest.main()
