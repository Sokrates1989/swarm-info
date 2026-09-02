# SCWP-01 QNAP Evidence

- Date: 2026-09-02
- Operator: Repository owner
- Host class and architecture: QNAP Container Station host, `linux/amd64`
- Repository commits: producer prepare `b165f627a7df5fbf5e28fe11d3a4e6a44db6c910`;
  accepted producer verify `fed14d5b5168232f44de0848315bc403c70b0a87`;
  accepted standalone watchdog `e7f8e1f374811cd11e6048add75f42dec38d18c3`
- Report paths and schema versions: private platform profile schema 1,
  vulnerability report schema 2, container-state schema 1, and lifecycle state
  schema 1 under `/share/Public/swarm-info`
- Commands executed: clean fast-forward update,
  `scwp_01_qnap_lifecycle.sh prepare`, normal QNAP reboot, forward-only gate
  fixes, and `scwp_01_qnap_lifecycle.sh verify`
- Automated result: the final producer suite passed 294 tests on Linux; focused
  lifecycle tests verified the private resumable state, complete managed-block
  checks, recovery path, POSIX syntax, and absence of automatic reboot or cron
  disclosure; scheduler unit tests proved unrelated entries are preserved by
  the owned-block transformation
- Manual scan result: the real host selected the QNAP adapter and local-container
  runtime, passed dependency detection, completed exact focused and running-scope
  scans, and published complete evidence for 25 containers and 19 unique images
  with zero failed image scans
- Manual schedule result: the existing QNAP schedule acceptance passed, immediate
  cache reuse completed in 2 seconds, and the non-overlap lock skipped a
  concurrent invocation without replacing evidence
- Reboot lifecycle result: the complete operational and security commands
  survived the NAS reboot; the managed block was absent after removal and
  complete after reinstall; fresh evidence remained readable throughout
- Related API/UI/notification evidence: authenticated standalone UI and Telegram
  delivery were accepted in [SCWP-02](SCWP_02_QNAP_EVIDENCE.md), while current
  private host evidence and the read-only Docker boundary were reconfirmed in
  [SCWP-03B](SCWP_03B_QNAP_EVIDENCE.md)
- Documented skips and reasons: non-Swarm Debian/Ubuntu remains Tier 2 because no
  suitable live host is available; QNAP vendor-owned cron entries are regenerated
  asynchronously, so the live gate checks only the complete owned block while
  deterministic tests cover unrelated-entry preservation
- Sanitization performed: credentials, tokens, chat identifiers, private
  hostnames, local addresses, unrelated cron commands, and sensitive host paths
  are omitted
- Final verdict: PASS

The accepted schedule runs as the normal QNAP account, remains rooted in
QNAP's persistent system crontab, and keeps Docker access outside the watchdog,
admin API, and browser containers.
