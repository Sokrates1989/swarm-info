# Implementation Slices

## Shared delivery protocol

Each slice is a reviewable vertical outcome. It may require coordinated commits
in more than one repository, but every repository commit must pass its own tests
and remain independently revertible.

For every slice:

1. Confirm all involved worktrees are clean and record their starting commits.
2. Re-read repository-specific instructions before editing that repository.
3. Add or update deterministic fixtures before relying on a real host.
4. Keep changes additive until both QNAP and standard-Linux migrations pass.
5. Run automated tests in every changed repository.
6. Run the listed real-host checks and record sanitized outputs.
7. Update the acceptance matrix with evidence links.
8. Commit every coherent internal checkpoint with the shared slice ID. Multiple
   commits per repository are allowed when that keeps a large slice reviewable.
9. Do not start the next slice until the operator accepts the current result.

Slow Docker Scout evidence may be reused only when the existing report is
complete, fresh under its published policy, and matches the exact tested scope.

The three slice IDs are operator acceptance boundaries, not a requirement to
compress six to ten implementation sessions into three oversized commits.

All disruptive real-host checks use a repository-owned, namespaced disposable
Compose fixture with isolated volumes, networks, and host ports. Acceptance
scripts verify the namespace before mutation and remove the fixture afterward.
A production target requires separate explicit operator authorization.

## SCWP-01 — Portable platform and deployment foundation

The Debian/Ubuntu real-host steps retained in this document describe a future
Tier 2 promotion path. For the current implementation, only QNAP live gates and
the single-manager Ubuntu Swarm regressions are required; automated fixtures
keep the shared standard-Linux adapter flexible meanwhile.

### Outcome

QNAP and standard Linux use one versioned platform/capability contract. QNAP's
special behavior is isolated behind an adapter, the common standalone deployment
can be configured for Debian/Ubuntu, and no existing scanning or scheduling
behavior changes.

### Internal checkpoints

- `SCWP-01A`: producer platform model, detectors, and adapter extraction.
- `SCWP-01B`: common standalone deployment and compatibility wrappers.
- `SCWP-01C`: cross-repository regression and real-host acceptance.

### `swarm-info` ownership

- Add pure host-profile and capability types.
- Add deterministic detector fixtures for QNAP, Debian, Ubuntu, unknown standard
  Linux, and malformed/missing release metadata.
- Extract QPKG/getcfg, QNAP Scout work-directory, and persistent-cron behavior
  behind the QNAP adapter.
- Put normal PATH/XDG/home and user-crontab behavior behind the standard-Linux
  adapter.
- Keep the common scan, job, cache, report, and lock implementations adapter-free.
- Add a machine-readable platform-info command and human-readable summary.
- Preserve the self-contained installer boundary and current command aliases.
- Keep Debian/Ubuntu package guidance separate from runtime behavior.

### `swarm-info-watchdog` ownership

- Introduce a common standalone-container deployment contract and profile
  defaults for QNAP and standard Linux.
- Preserve `qnap-deployment/` as a compatibility entry point.
- Generalize environment names additively while accepting existing QNAP names.
- Expose the producer capability profile through an authenticated API response.
- Do not enable new health or remediation panels in this slice.

### `swarm-swarm-info-watchdog` ownership

- No standalone deployment code is added.
- Run static and rendered-stack regression checks to prove the platform work did
  not change Swarm secrets, mounts, routing, or service behavior.

### Automated gate

- Detector and adapter tests cover QNAP, Debian, Ubuntu, unknown Linux, missing
  tools, and scheduler selection.
- Installer tests prove it remains standalone and package-family aware.
- QNAP and standard-Linux Compose profiles render without unresolved variables.
- Compatibility tests prove old QNAP variables and commands still work.
- API tests prove capability data is sanitized and authentication-protected.
- Full existing producer, watchdog, and Swarm deployment suites pass, except
  documented environment skips.

### Manual gate

On the existing QNAP host:

- Update from the clean checkout.
- Verify platform detection, dependency checks, exact local-image scan, focused
  scan, security-status, persistent schedule status, API, UI, and Telegram test.
- Verify the existing report remains private and readable by the configured
  container identity.

On a real Debian/Ubuntu Docker host:

- Run install, update, dependency, platform-info, manual running-container scan,
  focused scan, schedule install/status/remove, API, UI, and Telegram test.
- Verify user-crontab ownership and persistence after cron daemon restart. Reboot
  persistence is required before Tier 1 is claimed.

On the Swarm manager:

- Run dependency, service-health, vulnerability-status, and deployment smoke
  checks without changing existing report or secret contracts.

### Commit and evidence gate

- Commit subjects begin with the repository version contract and include
  `SCWP-01` in the descriptive portion.
- Add separate QNAP and Debian evidence documents only after their real runs.
- Mark Debian/Ubuntu Tier 1 only when the complete real-host row passes.

### Non-goals

- No new container-health classifications.
- No runtime-hardening audit.
- No automatic remediation.

## SCWP-02 — Local-container observability parity

### Outcome

Standalone hosts publish cheap operational evidence and receive container-native
health, expected-state configuration, UI summaries, and Telegram transitions
without waiting for Docker Scout.

### Internal checkpoints

- `SCWP-02A`: raw operational report, progress schema, and scheduling.
- `SCWP-02B`: canonical watchdog policy/evaluator and API contract.
- `SCWP-02C`: UI, Telegram transitions, regressions, and host acceptance.

### Fixed evidence contract

- Setup resolves one evidence directory. Defaults are
  `/share/Public/swarm-info` on QNAP and
  `${XDG_STATE_HOME:-$HOME/.local/state}/swarm-info` on standard Linux.
- The raw operational report is `container_state.json`, mode `0600`, atomic, and
  generated every five minutes by default.
- It publishes `freshness.generated_at` and `freshness.fresh_until`; the default
  freshness window is fifteen minutes.
- `security_scan-running.status.json` receives a 30-second heartbeat and one of
  `idle`, `running`, `complete`, `failed`, `cancelled`, or `timed_out`. A running
  heartbeat older than two minutes is interrupted/stalled.
- Restart rate is derived from two valid samples. The first or discontinuous
  sample publishes `null`, not a healthy-looking zero.
- `swarm-info` publishes observed Docker state only. The watchdog owns
  `WATCHDOG_CONTAINER_EXPECTATIONS_JSON` and the only policy evaluator.
- Stable selectors are `compose:<project>/<service>` and
  `container:<exact-name>`; ephemeral container IDs are rejected.

### `swarm-info` ownership

- Add an atomic lightweight `container_state.json` collector.
- Collect observed state, Docker health, exit code, restart count and policy,
  started/finished timestamps, image identity, sanitized ports, and Compose
  ownership.
- Add an adapter-backed frequent schedule for the lightweight collector.
- Add a machine-readable vulnerability-scan status/heartbeat document with
  current/total progress and next-run information.
- Keep operational collection independent of Scout availability and timeout.

### `swarm-info-watchdog` ownership

- Read and validate container operational evidence separately from the
  vulnerability report.
- Add the canonical `must-run`, `may-stop`, and `ignore` policy schema,
  validation, persistence, precedence, and evaluator.
- Preserve stopped-without-policy as unknown/idle rather than down.
- Use that one evaluator for API, UI, and Telegram aggregate state.
- Add transition alerts for newly unhealthy, recovered, stale, missing, and
  incomplete container evidence; suppress unchanged repeats.
- Add container-native summary, attention list, expected-state editor, scan
  progress, last/next scan, and evidence freshness panels.
- Retain vulnerability, configuration, login, and test-notification behavior.
- Update English and German text together.

### `swarm-swarm-info-watchdog` ownership

- Run service-health, expectation-policy, Telegram, API, UI contract, and
  deployment regression tests.
- Do not add container operational mounts or Docker access to the Swarm stack.

### Automated gate

- Fixtures cover running, healthy, unhealthy, restarting, successful one-shot,
  failed exit, intentionally stopped, unknown, stale, partial, missing, and
  recovered states.
- Policy precedence, ambiguity, validation, and aggregate counts are tested.
- First-sample and subsequent-sample restart-rate calculations are tested.
- Freshness boundaries, stale heartbeats, every terminal progress state, and
  interruption before atomic publication are tested.
- Telegram transition tests cover new, unchanged, regressed, recovered, stale,
  and failed-delivery retry behavior.
- API/UI tests prove resource nouns and panels follow capabilities rather than
  distribution names.
- A simulated multi-hour vulnerability scan does not block operational evidence.
- Existing Swarm state and notification tests remain unchanged and green.

### Manual gate

On QNAP and Debian/Ubuntu, using the disposable acceptance fixture:

- Demonstrate one `must-run` healthy container, one stopped `may-stop` job, one
  failed `must-run` container, and one unset stopped container.
- Verify only the failed `must-run` resource is down; the one-shot is allowed and
  the unset stopped resource remains unknown/idle.
- Verify UI, API, and Telegram use the same counts and resource names.
- Recover the failed resource and receive exactly one recovery transition.
- Save and reload expected-state policy through the authenticated UI.
- Observe live scan progress while the last complete vulnerability report remains
  available.

### Commit and evidence gate

- Record screenshots or sanitized API output, Telegram transitions, report
  permissions, schedule output, and the exact accepted commits.
- The operator must accept QNAP and Debian behavior before `SCWP-03` begins.

### Non-goals

- The UI does not start, stop, restart, or recreate containers.
- No automated image update is introduced.

## SCWP-03 — Security intelligence and guarded remediation parity

### Outcome

Standalone operators can understand image risk, deployment ownership, update
quality, cleanup opportunities, and runtime-hardening findings, then use a safe
host-side guided workflow. The browser remains read-only guidance.

### Internal checkpoints

- `SCWP-03A`: Compose selectors, ownership, and candidate assessment.
- `SCWP-03B`: runtime-hardening, cleanup evidence, and read-only UI.
- `SCWP-03C`: guarded host mutation, rollback, regressions, and acceptance.

`SCWP-03A` has passed its automated implementation gate and its QNAP and Swarm
operator gates. See the [QNAP evidence](SCWP_03A_QNAP_EVIDENCE.md) and
[Swarm regression evidence](SCWP_03A_SWARM_REGRESSION.md). `SCWP-03B` has also
passed its automated, [QNAP](SCWP_03B_QNAP_EVIDENCE.md), and
[single-manager Swarm](SCWP_03B_SWARM_REGRESSION.md) gates. `SCWP-03C` has not
started. Standalone Debian/Ubuntu remains a fixture-tested Tier 2 target until
a host is available.

### `swarm-info` ownership

- Add focused selectors for Compose project and Compose service.
- Generalize image-update discovery and assessment to container resources while
  retaining exact local-artifact verification.
- Show current versus candidate version lineage, compatibility risk, fixable
  finding reduction, remaining findings, image age, and all affected containers.
- Add prioritized container/image/Compose guided remedy modes with copy-ready
  backup, pull/build, recreate, verify, and focused-rescan commands.
- Add runtime-hardening checks for privileged mode, host network/PID namespaces,
  Docker socket mounts, dangerous capabilities, root execution, missing
  `no-new-privileges`, writable root filesystem, risky mounts, missing health
  checks, absent resource limits, and exposed ports.
- Integrate safe image-cleanup preview, last result, and history into operator
  evidence.
- Add optional policy-gated Compose source mutation only when source mapping is
  exact, backup requirements are satisfied, a dry-run diff and rendered Compose
  validation pass, the operator confirms, and rollback plus focused post-check
  are available.
- Never fall back to guessing a Compose path or silently running `docker update`.

### `swarm-info-watchdog` ownership

- Add read-only per-image, per-container, and per-Compose ownership views.
- Show assessed candidate quality and exact host CLI commands.
- Add runtime-hardening and cleanup summaries with explicit unknown/unsupported
  states.
- Keep mutation controls out of the API and browser.
- Use capability flags to hide only genuinely unavailable actions.

### `swarm-swarm-info-watchdog` ownership

- Run existing Swarm mapping, assessment, remediation-plan, secret, routing, and
  UI regression suites.
- Ensure standalone vocabulary and reports do not change Swarm action semantics.

### Automated gate

- Candidate tests cover upgrades, downgrades, mutable `latest`, same-version new
  digest, architecture mismatch, private/unavailable candidate, remaining CVEs,
  and no-safe-candidate outcomes.
- Compose mapping tests cover exact labels, multiple config files, missing source,
  duplicate matches, backup files, and sanitized paths.
- Hardening tests cover every finding and prove environment/secret values are
  never serialized.
- Mutation planning is dry-run by default and tests diff, validation, default-No
  confirmation, failure rollback, and focused post-check.
- API and frontend contract tests prove no Docker control endpoint or socket
  dependency was added.
- Existing Swarm remediation and cleanup suites remain green.

### Manual gate

On QNAP, using the repository-owned acceptance workflow and a disposable
fixture wherever mutation is tested:

- Select one vulnerable first-party or locally built image and one third-party
  image.
- Verify ownership mapping, candidate assessment, backup advice, update commands,
  and exact focused post-update scan.
- Review one hardening finding against `docker inspect` evidence.
- Run cleanup preview without applying it; verify protected running and stopped
  container images are not candidates.
- Exercise one policy-approved Compose update in dry-run, cancel it once, then
  perform an accepted test update with backup, post-check, and rollback evidence.
- Confirm API/UI expose results but cannot invoke Docker mutations.

The same host-side evidence commands and standard-Linux adapter remain covered
by automated fixtures for a future non-Swarm Debian/Ubuntu acceptance run, but
that unavailable host is not a checkpoint for the current implementation.

On the Swarm manager:

- Repeat the established mapping, image-assessment, guided remedy, cleanup
  preview, UI, and notification regression workflow.

### Commit and evidence gate

- Final evidence links QNAP and Swarm accepted commits and sanitized outputs.
- The final matrix must have no unexplained pending Tier 1 rows.
- Any unsupported capability remains explicit rather than being counted clean.

### Non-goals

- Automatic operating-system or NAS firmware updates.
- Unattended mutation of deployments without an installation-owned policy.
- Docker daemon access from the watchdog, API, web UI, or reverse proxy.
