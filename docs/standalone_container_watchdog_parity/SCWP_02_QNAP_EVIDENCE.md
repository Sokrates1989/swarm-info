# SCWP-02 QNAP Evidence

- Date: 2026-08-25
- Operator: Repository owner
- Host class and architecture: QNAP Container Station host, `linux/amd64`
- Repository commits: producer `5255be3`; watchdog `5b88624`
- Report paths and schema versions: private operational and vulnerability
  evidence under `/share/Public/swarm-info`; container-state schema version 1
- Commands executed: lightweight container-state collection, isolated SCWP-02
  acceptance, persistent deployment cleanup and update, and authenticated UI
  notification testing
- Automated result: producer and watchdog SCWP-02 contract, evaluator, API,
  frontend, fixture-isolation, and deployment tests passed before the host run
- Manual result: the production UI presented collapsed capability-aware cards,
  operational state, expected-state selectors, vulnerability progress, and the
  grouped notification controls; current evidence suppressed the refresh
  guidance; a GUI Telegram test was delivered to the configured destination
- Documented skips and reasons: standard-Linux persistence was not inferred from
  the QNAP host; no production container mutation was exercised
- Sanitization performed: chat identifiers, tokens, private hostnames, local IP
  addresses, and sensitive mount-source details are omitted
- Final verdict: PASS

The accepted deployment retained its root-owned persistent collector schedule,
private evidence permissions, and host-side Docker boundary. The browser and
admin API remained read-only with respect to Docker.
