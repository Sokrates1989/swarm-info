# SCWP-01 Swarm Regression Evidence

- Date: 2026-09-04
- Operator: Repository owner
- Host class and architecture: Ubuntu 24.04.4 LTS single-manager Docker Swarm,
  `linux/amd64`
- Repository commits: producer
  `684108bd2654c6ad99f93a13ef2b06f0baf028e8`; deployment repository
  `305a0943bd0cb9e62e5bfdd8fa0ee41484ce43b1`
- Report paths and schema versions: temporary platform-profile schema 1; existing
  vulnerability evidence at `/info_json/vulnerability_scan.json` (the gate did
  not print its schema version)
- Commands executed: clean fast-forward updates followed by
  `bash /tools/swarm-info/tests/acceptance/scwp_01_swarm.sh` and
  `SWARM_INFO_COMMAND=/tools/swarm-info/get_info.sh bash
  /swarm/administration/swarm-info-watchdog/tests/acceptance/scwp_01_swarm.sh`
- Automated result: the producer selected the standard-Linux adapter in Swarm
  mode and passed manager dependency, service-health, and vulnerability-status
  checks; all 46 deployment-repository tests passed before the deployment gate
  repeated the same manager-side evidence checks
- Manual result: both tracked real-host gates ended in `PASS`; the vulnerability
  report was fresh at 7.50 hours, covered 62 images, and contained zero failed
  scans
- Operational state observed: service-health evidence remained readable and
  accurately reported 85 managed services, including 1 degraded and 35 down;
  this regression accepts correct unhealthy-state reporting and does not certify
  the workloads themselves as healthy
- Documented skips and reasons: no standalone Debian/Ubuntu lifecycle was run
  because the available Ubuntu host is a Swarm manager; both gates are
  intentionally read-only and performed no stack or service mutation
- Sanitization performed: private routing, registry data, credentials, tokens,
  detailed workload names, and sensitive configuration values are omitted
- Final verdict: PASS

The accepted regression confirms that SCWP-01 preserves the existing Swarm
manager capability, report, deployment, mount, secret, and Docker-access
boundaries. Public-facing services receive no Docker socket or mutation path.
