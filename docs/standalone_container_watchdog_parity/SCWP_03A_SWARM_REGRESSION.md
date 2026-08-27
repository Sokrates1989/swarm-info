# SCWP-03A Swarm Regression Evidence

- Date: 2026-08-27
- Operator: Repository owner
- Host class and architecture: Ubuntu 24.04 Docker Swarm manager, `linux/amd64`
- Repository commits: producer `ac630a5`; watchdog image source `a1db7ca`;
  deployment repository `4966aa0`
- Deployed images: `swarm-info-watchdog:0.5.1` and
  `swarm-info-watchdog-web:0.5.1`
- Report paths and schema versions: existing Swarm vulnerability, assessment,
  and health evidence under `/info_json`; no standalone container-state evidence
  or Compose ownership was introduced into Swarm API rows
- Commands executed: operator-controlled image build and publication, deployment
  image bump, repository fast-forward, stack regeneration, readiness-aware
  health check, authenticated UI review, and Telegram notification test
- Automated result: producer, watchdog, and Swarm deployment regression suites
  passed before the live operator review
- Manual result: the authenticated UI retained service-native assessment,
  health, threshold, expectation, and notification behavior; standalone
  container/Compose ownership did not leak into Swarm rows; deployment readiness
  was reported accurately after the deployment repository update; the GUI
  Telegram test was delivered
- Documented skips and reasons: the available Ubuntu host is a Swarm manager and
  therefore does not satisfy standalone standard-Linux acceptance; no service,
  image, or deployment source was mutated by the acceptance gate
- Sanitization performed: chat identifiers, bot and admin tokens, private
  routing, registry credentials, and sensitive configuration values are omitted
- Final verdict: PASS

The accepted regression retains Docker control in the manager-side operator
workflow. The watchdog, admin API, and web services received no Docker socket or
mutation endpoint.
