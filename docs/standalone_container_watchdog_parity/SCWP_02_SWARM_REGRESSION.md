# SCWP-02 Swarm Regression Evidence

- Date: 2026-08-26
- Operator: Repository owner
- Host class and architecture: Ubuntu 24.04 Docker Swarm manager, `linux/amd64`
- Repository commits: producer baseline `5255be3`; watchdog image source
  `5b88624`; deployment contract `6675ac5`
- Deployed images: `swarm-info-watchdog:0.4.0` and
  `swarm-info-watchdog-web:0.4.0`
- Report paths and schema versions: existing Swarm reports under `/info_json`;
  no standalone operational report was mounted into the Swarm stack
- Commands executed: operator-controlled paired image build and publication,
  deployment image bump, deployment-contract fast-forward, stack regeneration,
  and authenticated notification tests
- Automated result: the deployment repository's complete Linux test suite ran
  33 tests successfully, including stack rendering and Telegram-secret wiring
- Manual result: the authenticated UI loaded version `0.4.0`; existing Swarm
  vulnerability, image-assessment, service-health, threshold, expectation, and
  notification panels remained available; the CLI/API verification delivered
  one Telegram test and the GUI delivered a second Telegram test
- Documented skips and reasons: standalone standard-Linux behavior was not
  exercised because the available Ubuntu host is a Swarm manager; a helper
  wrapper reported failure after its notification had already been delivered,
  and the operator accepted the directly observed API, UI, and Telegram result
- Sanitization performed: chat identifiers, bot token, admin token, private
  routing details, and sensitive configuration values are omitted
- Final verdict: PASS

The accepted deployment keeps Docker control on the manager-side workflow. The
watchdog, admin API, and web services received no Docker socket or mutation API.
