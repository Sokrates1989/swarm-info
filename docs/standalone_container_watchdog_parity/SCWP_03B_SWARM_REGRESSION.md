# SCWP-03B Swarm Regression Evidence

- Date: 2026-09-01
- Operator: Repository owner
- Host class and architecture: Ubuntu 24.04 single-manager Docker Swarm,
  `linux/amd64`
- Repository commits: producer `7a8e6d84d56567d177273fb230ba049b18d1736f`;
  deployment repository `9c05aea4bafdadbae9e9dac7f854343564197bc1`
- Deployed images: `swarm-info-watchdog:0.6.0` and
  `swarm-info-watchdog-web:0.6.0`
- Report paths and schema versions: temporary platform profile schema 1 and
  image-cleanup schema 2 evidence created by the acceptance gate; existing
  Swarm vulnerability, assessment, health, and configuration evidence retained
  its deployed contracts
- Commands executed: clean fast-forward updates followed by
  `bash /tools/swarm-info/tests/acceptance/scwp_03b_swarm.sh`
- Automated result: the manager profile retained Swarm mode, standalone runtime
  hardening remained disabled, cleanup preview protected 134 images without
  removing any image, all 46 deployment-repository tests passed, the public
  health endpoint succeeded, and the web bundle reported version `0.6.0`
- Manual result: standalone runtime-hardening and cleanup cards were absent;
  existing vulnerability, verified update assessment, service health, Swarm
  settings, notifications, thresholds, image-security thresholds, and service
  expectations rendered; one Telegram Info test produced exactly one message;
  no browser control could run Docker, deploy, or remove an image
- Documented skips and reasons: the Ubuntu host is a Swarm manager and does not
  satisfy standalone standard-Linux Tier 1 acceptance; cleanup apply and any
  production service mutation were outside this regression
- Sanitization performed: private routing, registry data, credentials, tokens,
  chat identifiers, and sensitive configuration values are omitted
- Final verdict: PASS

The accepted regression keeps manager-side Docker control in the existing host
operator workflow. No Docker socket, standalone report mount, or mutation route
was added to the watchdog, admin API, web service, or reverse proxy.
