# SCWP-03B QNAP Evidence

- Date: 2026-09-01
- Operator: Repository owner
- Host class and architecture: QNAP Container Station host, `linux/amd64`
- Repository commits: producer `7a8e6d84d56567d177273fb230ba049b18d1736f`;
  watchdog `e7f8e1f374811cd11e6048add75f42dec38d18c3`
- Deployed UI version: `0.6.0`
- Report paths and schema versions: platform profile schema 1 at
  `/share/Public/swarm-info/platform_info.json`, runtime-hardening schema 1 at
  `/share/Public/swarm-info/runtime_hardening.json`, and image-cleanup schema 2
  at `/share/Public/swarm-info/image_cleanup.json`
- Commands executed: clean fast-forward updates followed by
  `bash "$HOME/tools/swarm-info-watchdog/tests/acceptance/scwp_03b_qnap.sh"`
- Automated result: the gate identified the QNAP container runtime and both
  required capabilities, audited 45 containers with 242 findings, protected
  every running or stopped container image, confirmed one finding through live
  sanitized Docker inspection, detected no preview-time image inventory change,
  rebuilt the persistent UI, and passed its authenticated API checks
- Manual result: the runtime-hardening card showed 45 audited and 45 affected
  containers with 3 critical, 11 high, and 228 warning findings; the cleanup
  card showed 142 local images, 39 protected images, 103 candidates, a 44.6 GiB
  virtual-size upper bound, and preview-only history; both cards were current,
  collapsible, and contained no Docker mutation control
- Documented skips and reasons: standalone Debian/Ubuntu remains Tier 2 because
  no non-Swarm host is available; cleanup apply was intentionally excluded from
  this read-only checkpoint
- Sanitization performed: environment and arbitrary label values, host-mount
  sources, credentials, tokens, chat identifiers, and raw private configuration
  are omitted
- Final verdict: PASS

The accepted evidence is diagnostic, not a declaration that the audited
containers are unsafe to operate. Findings remain operator review inputs, and
the browser cannot change Docker.
