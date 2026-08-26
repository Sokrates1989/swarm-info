# Platform Acceptance Matrix

## Evidence rules

- Record evidence only after the command or manual check actually ran.
- Include date, host class, architecture, sanitized command output, exact commit,
  report schema, and result.
- Redact tokens, chat IDs, credentials, registry details, private domain names,
  environment values, and sensitive mount source paths.
- Do not weaken a private report from `0600` merely to make a container read it;
  fix container identity or group mapping instead.
- A cached vulnerability report is acceptable only when it is complete, fresh,
  and bound to the exact tested scope.
- A fixture proves deterministic behavior, not real cron persistence, Docker
  permissions, bind-mount ownership, browser routing, or notification delivery.
- Failure, recovery, recreation, mutation, and rollback checks use a
  repository-owned, namespaced disposable Compose fixture with isolated data,
  networks, and host ports. Acceptance records fixture cleanup. Production
  workloads are out of scope without separate explicit operator authorization.
- Mark skipped checks with a reason. A silent blank cell is not accepted evidence.
- Tier 1 requires every mandatory row for that platform.

## Required environments

| Environment ID | Required host | Purpose |
| --- | --- | --- |
| `QNAP-REAL` | Existing QNAP Container Station host, current accepted user and private report path | Vendor adapter, QPKG discovery, persistent cron, permissions, API/UI/Telegram, and runtime behavior |
| `DEBIAN-REAL` | Debian or Ubuntu host/VM with Docker Engine and Compose v2 | Standard-Linux adapter, installer, user cron, reboot persistence, API/UI/Telegram, and runtime behavior |
| `SWARM-REAL` | Existing Docker Swarm manager | Regression for service inventory, reports, notifications, UI, mapping, and deployment |
| `FIXTURES` | Deterministic automated test environment | Unsupported/malformed platform data and edge-state coverage |

A containerized Debian test is useful under `FIXTURES`, but it does not replace
`DEBIAN-REAL`.

## Reproducible validation entry points

Run the complete automated baseline from each repository root:

```text
# D:\Development\Code\swarm-info
python -B -m unittest discover -s tests -v

# D:\Development\Code\python\swarm-info-watchdog
python -B -m unittest discover -s tests -v

# D:\Development\Code\swarm\swarm-swarm-info-watchdog
python -B -m unittest discover -s tests -v
```

Windows dependency/POSIX skips must be followed by a Linux container or real-host
run for the affected suites. Every slice adds repository-owned, copy-ready host
entry points before manual acceptance:

```text
/bin/bash tests/acceptance/scwp_01_qnap.sh
/bin/bash tests/acceptance/scwp_01_standard_linux.sh
/bin/bash tests/acceptance/scwp_01_swarm.sh
```

Replace `01` with `02` or `03` for later slices. These scripts print the exact
commit, stop on dirty checkouts or wrong platform capability, reuse valid cached
Scout evidence when permitted, redact secrets, and end with one unambiguous
`[PASS]` or `[FAIL]` line. The scripts are implementation deliverables; this
planning change does not create placeholder executables.

For the common watchdog deployment, the accepted host script additionally calls
the repository-owned `container-deployment/acceptance.sh` entry point. Existing
`qnap-deployment/acceptance.sh` remains callable through the compatibility path.

## Slice status

| Slice | Automated | QNAP real host | Debian/Ubuntu real host | Swarm regression | Accepted |
| --- | --- | --- | --- | --- | --- |
| `SCWP-01` | Pending | Pending | Pending | Pending | No |
| `SCWP-02` | Complete | [Passed (2026-08-25)](SCWP_02_QNAP_EVIDENCE.md) | Pending | [Passed (2026-08-26)](SCWP_02_SWARM_REGRESSION.md) | Conditional |
| `SCWP-03` | Pending | Pending | Pending | Pending | No |

## SCWP-01 checkpoints

### Automated

- [ ] QNAP, Debian, Ubuntu, generic Linux, missing-release, and malformed-release
  fixtures select the expected adapter and sanitized metadata.
- [ ] Capability output is stable, versioned, and contains no secrets.
- [ ] The standalone installer remains self-contained.
- [ ] QNAP and standard-Linux deployment profiles render completely.
- [ ] Old QNAP commands and variables remain compatible.
- [ ] All changed-repository test suites pass with documented skips only.

### QNAP real host

- [ ] Clean update and platform/dependency output.
- [ ] Exact local-image full and focused scans.
- [ ] Persistent schedule install/status/remove without changing unrelated cron.
- [ ] Private report readable by the configured containers without permission
  widening.
- [ ] Authenticated API/UI and Telegram test delivery.
- [ ] Existing QNAP acceptance workflow still passes.
- [ ] Ordered lifecycle succeeds: update → platform/dependency status → schedule
  status → cron restart → status → NAS reboot → status → managed removal →
  unrelated-cron verification → reinstall.

### Debian/Ubuntu real host

- [ ] Clean install and self-update through the standard-Linux adapter.
- [ ] Docker, Compose, Python, and Scout dependency detection.
- [ ] Manual running-container and exact focused scan.
- [ ] User-crontab install/status/remove, daemon restart, and reboot persistence.
- [ ] Common standalone API/UI starts with standard paths and ownership.
- [ ] Authenticated API/UI and Telegram test delivery.
- [ ] Ordered lifecycle succeeds: install → platform/dependency status → schedule
  install → cron daemon restart → status → host reboot → status → managed
  removal → unrelated-cron verification → reinstall.

### Swarm regression

- [ ] Manager dependency and capability detection remains Swarm mode.
- [ ] Service-health and vulnerability status remain readable.
- [ ] Existing vulnerability schedule and deployment preflight pass.
- [ ] No stack mount, secret, routing, or image contract changed unexpectedly.

## SCWP-02 checkpoints

### Automated

- [x] Running, healthy, unhealthy, restarting, successful one-shot, failed exit,
  intentionally stopped, unknown, stale, partial, missing, and recovered fixtures.
- [x] Expected-state validation and precedence.
- [x] API/UI/Telegram aggregate parity.
- [x] Transition suppression and failed-delivery retry.
- [x] Operational collection remains responsive during a simulated long scan.
- [x] English and German UI contract checks.

### QNAP and Debian/Ubuntu real hosts

- [ ] One healthy `must-run` container.
- [ ] One stopped successful `may-stop` job.
- [ ] One failed `must-run` container and one recovery transition.
- [ ] One unset stopped container shown as unknown/idle, not down.
- [ ] Expected-state save and reload through the authenticated UI.
- [ ] UI, API, report, and Telegram counts match.
- [ ] Vulnerability progress and last complete evidence remain simultaneously
  visible.
- [ ] Lightweight collector schedule survives the platform's persistence test.

### Swarm regression

- [x] Existing service expectations and health totals remain unchanged.
- [x] Existing Telegram transition semantics remain unchanged.
- [x] Existing admin API and UI service cards remain available.
- [x] No standalone Docker evidence mount or daemon access appears in the stack.

The operator accepted the QNAP and Swarm results and authorized `SCWP-03A` to
start. This does not promote standard Linux to Tier 1: its real-host row remains
pending until a non-Swarm Debian or Ubuntu Docker host is available.

## SCWP-03 checkpoints

### SCWP-03A automated checkpoint

- [x] Exact container, image ID, Compose project, and Compose service selectors.
- [x] Container-native candidate discovery and assessment retain exact local
  artifact, Compose ownership, lineage, reductions, remaining findings, age,
  and affected workloads.
- [x] The sanitized watchdog API and UI expose container/Compose evidence and
  copy-ready host guidance while preserving legacy Swarm service rows.
- [x] Contract tests prove that no API mutation route or Docker socket
  dependency was added.

The QNAP and Swarm operator gates for `SCWP-03A` remain pending. The broader
`SCWP-03B` and `SCWP-03C` checkpoints below remain open.

### Automated

- [ ] Container, image, Compose project, and Compose service focused selectors.
- [ ] Candidate upgrade, downgrade, mutable tag, digest, architecture, unavailable,
  and remaining-finding cases.
- [ ] Exact, ambiguous, missing, and backup-file Compose mapping.
- [ ] All runtime-hardening findings and secret-redaction cases.
- [ ] Cleanup protection and history.
- [ ] Dry-run, diff, default-No confirmation, validation failure, rollback, and
  focused post-check.
- [ ] No API mutation route or Docker socket dependency.

### QNAP and Debian/Ubuntu real hosts

- [ ] One first-party/local and one third-party image assessment.
- [ ] Correct Compose ownership and affected-container mapping.
- [ ] Copy-ready backup, update, recreate, and focused verification commands.
- [ ] One hardening finding independently confirmed with sanitized Docker inspect
  evidence.
- [ ] Cleanup preview protects all container-owned images.
- [ ] One policy-approved dry-run is cancelled safely.
- [ ] One accepted test update records backup, diff, post-check, and rollback.
- [ ] UI remains read-only while presenting all resulting evidence.

### Swarm regression

- [ ] Existing deployment mapping and candidate assessment.
- [ ] Existing guided remedy and policy behavior.
- [ ] Existing cleanup preview protection.
- [ ] Existing API/UI/Telegram behavior.
- [ ] Existing no-socket/no-secret-output contracts.

## Evidence document names

Create only after a completed run:

- `SCWP_01_QNAP_EVIDENCE.md`
- `SCWP_01_DEBIAN_EVIDENCE.md`
- `SCWP_01_SWARM_REGRESSION.md`
- Repeat the same pattern for `SCWP_02` and `SCWP_03`.

## Result record template

```markdown
# SCWP-XX <PLATFORM> Evidence

- Date:
- Operator:
- Host class and architecture:
- Repository commits:
- Report paths and schema versions:
- Commands executed:
- Automated result:
- Manual result:
- Documented skips and reasons:
- Sanitization performed:
- Final verdict: PASS | FAIL | CONDITIONAL
```

## Final acceptance

The roadmap is accepted only when:

- all three slice rows are accepted;
- QNAP and Debian/Ubuntu satisfy every mandatory Tier 1 checkpoint;
- Swarm regression is green for every slice;
- capability-unavailable states remain explicit;
- no secret, credential, or Docker daemon control was added to public-facing
  services; and
- the operator signs off on the exact commits recorded in the evidence.
