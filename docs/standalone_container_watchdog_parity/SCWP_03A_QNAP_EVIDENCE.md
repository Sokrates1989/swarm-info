# SCWP-03A QNAP Evidence

- Date: 2026-08-28
- Operator: Repository owner
- Host class and architecture: QNAP Container Station host, `linux/amd64`
- Repository commits: producer `b58dfd7`; watchdog `a1db7ca`
- Report paths and schema versions: private schema-version-2 focused evidence at
  `/share/Public/swarm-info/scwp_03a_project_security.json`; schema-version-1
  discovery and assessment evidence under `/share/Public/swarm-info`
- Commands executed: exact Compose-project scan, explicitly approved anonymous
  Docker Hub metadata discovery, immutable candidate assessment, QNAP deployment
  setup and rebuild, authenticated API inspection, browser review, and Telegram
  notification test
- Automated result: the producer's complete Linux suite passed 267 tests; the
  watchdog contract, API, frontend, and acceptance tests passed before the host
  run
- Manual result: `docker-nginx-proxy-manager` retained exact container and
  Compose ownership; both immutable candidates completed scanning with no scan
  failures; the best verified candidate reduced high findings by two; the API
  returned one sanitized container row; the UI presented current/candidate
  lineage, remaining findings, age, affected container, and copy-ready host
  guidance without a Docker execution control; the Telegram test was delivered
- Documented skips and reasons: no production image or container was changed;
  the selected project did not contain a locally built image; source evidence
  remained explicitly incomplete because four unrelated stale QNAP Docker layer
  records could not be inspected, while selected-project ownership and both
  candidate scans were complete
- Sanitization performed: registry credentials, bot and admin tokens, chat
  identifiers, private configuration, and unrelated container details are
  omitted
- Final verdict: PASS

The accepted incomplete label is intentional and fail-closed: it describes the
broader source-inventory warnings, not a candidate-scan failure. The verified
candidate evidence remains visible but does not authorize deployment.
