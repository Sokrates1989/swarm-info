# Command and Docker Scout test fixtures

This directory contains deterministic, sanitized inputs used by the
vulnerability scanner, dependency preflight, and self-update unit tests.

## Files

- `fake_docker.py` emulates the small Docker, Docker Scout, and Compose-version
  command surface used by the security workflows. Its behavior is selected
  with `FAKE_DOCKER_SCENARIO`, including exact local success,
  registry-fallback, missing-plugin, and unavailable-daemon coverage.
- `fake_git.py` emulates clean, dirty, behind, divergent, and failing Git
  states used by the guarded `swarm-info -u` self-update tests.
- `scout-clean.sarif.json` represents a successful Scout SARIF 2.1.0 scan with
  no policy findings.
- `scout-vulnerable.sarif.json` represents one fixable CRITICAL and one fixable
  HIGH finding. Identifiers and descriptions are intentionally fictional.

## Ownership and safe editing

These fixtures are maintained with their command adapters. They contain no
registry credentials, production image names, real packages, or production
scan output. Keep the SARIF structure representative of Docker Scout, retain
schema version `2.1.0`, and update parser expectations in the same change.

The JSON files are hand-maintained test data; they are not generated at test
runtime. The fake executable writes invocation logs only to a test-provided
temporary path.
