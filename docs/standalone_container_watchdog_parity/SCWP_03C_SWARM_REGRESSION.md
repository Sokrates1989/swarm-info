# SCWP-03C Swarm Regression Evidence

- Date: 2026-09-02
- Operator: Repository owner
- Host class and architecture: Ubuntu 24.04 single-manager Docker Swarm,
  `linux/amd64`
- Repository commits: producer
  `7cf56795489e287b3e4f68bb591055ffe6f9e822`; deployment repository
  `9c05aea4bafdadbae9e9dac7f854343564197bc1`
- Deployed images: `swarm-info-watchdog:0.6.0` and
  `swarm-info-watchdog-web:0.6.0`
- Report paths and schema versions: the delegated SCWP-03B gate generated
  temporary platform-profile schema 1 and image-cleanup schema 2 evidence while
  retaining the existing Swarm vulnerability, assessment, health, and
  configuration contracts
- Commands executed: clean producer fast-forward followed by
  `bash /tools/swarm-info/tests/acceptance/scwp_03c_swarm.sh`
- Automated result: the complete accepted read-only SCWP-03B manager regression
  was repeated at the SCWP-03C producer commit; manager cleanup protected 134
  images without removal, all 46 deployment-repository tests passed, and the
  public web bundle retained version `0.6.0`
- Manual result: the operator accepted all five browser checks; standalone
  hardening and cleanup cards remained absent in Swarm mode, existing image,
  service-health, settings, and threshold views rendered, exactly one Telegram
  Info test was delivered, and no browser action could run Docker, deploy, or
  remove an image
- Documented skips and reasons: the manager gate intentionally performed no
  Compose or service mutation because SCWP-03C adds only a standalone host CLI
  transaction. The available Ubuntu host does not satisfy standalone
  standard-Linux Tier 1 acceptance
- Sanitization performed: private routing, registry data, credentials, tokens,
  chat identifiers, and sensitive configuration values are omitted
- Final verdict: PASS

The accepted regression keeps every Swarm mutation in the existing
manager-side operator workflow and adds no Docker socket or mutation route to a
public-facing service.
