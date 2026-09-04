# Standalone Container Watchdog Parity

**Plan ID:** `SCWP`

**Status:** Accepted on 2026-09-04; all SCWP-01, SCWP-02, and SCWP-03 automated,
QNAP Tier 1, and single-manager Swarm gates are complete

**Scope:** `swarm-info`, `swarm-info-watchdog`, and their standalone-container
deployment contract

## Purpose

This directory is the source of truth for bringing the accepted QNAP
container-security implementation closer to the operational outcome of the
Docker Swarm watchdog while keeping future standard-Linux support inexpensive.

The target is **capability parity**, not a copy of Swarm concepts. A standalone
Docker host has containers and Compose ownership, but it does not have Swarm
nodes, services, desired replicas, overlay secrets, task history, or stack
rollback. The UI and notifications must describe the resources that actually
exist on the selected runtime.

## Baseline decision

The later QNAP-only initiative was a separate three-slice implementation. Its
scanner, persistent scheduler, watchdog/API integration, private-report access,
authenticated UI, and Telegram test path were manually accepted. This plan
starts from that accepted baseline; it does not reopen or rename those slices.

An older frozen Swarm vulnerability draft described a few mechanisms that were
later deliberately replaced, such as per-image Telegram messages. The current
tested aggregate transition behavior is the baseline for this roadmap. This
plan does not claim that obsolete draft wording was implemented line for line.

## Recommendation and expected cost

Proceed with this plan. QNAP and Debian/Ubuntu are two real deployment targets,
and the current CLI already shares most Docker inventory and image-security
behavior. Establishing the adapter boundary now is more economical than adding
more QNAP conditions and extracting them after another platform depends on the
same files.

The implementation is a moderate evolution rather than a rewrite: three
substantial reviewable slices, expected to require roughly six to ten focused
implementation/review sessions plus real-host acceptance windows. Multi-hour
Scout runs can extend elapsed acceptance time without increasing implementation
scope. The platform seam is expected to add about 15–25 percent compared with a
QNAP-only change, but should make most later standard-Linux additions an adapter
fixture, package-guidance entry, and host acceptance row instead of a code fork.

This investment would be wasteful only if QNAP remained the sole standalone
target, or if parity meant copying Swarm-only nodes, stacks, task history, and
replica controls into an environment that cannot provide them.

## Start here

1. Read [Current state and evidence gaps](CURRENT_STATE_AND_EVIDENCE_GAPS.md).
2. Review the [architecture and platform contract](ARCHITECTURE_AND_PLATFORM_CONTRACT.md).
3. Implement the fixed order in [implementation slices](IMPLEMENTATION_SLICES.md).
4. Record real-host results in the [platform acceptance matrix](PLATFORM_ACCEPTANCE_MATRIX.md).

Evidence documents are added only after the corresponding manual run has
actually completed. Empty or predictive evidence files are not permitted.

## Support tiers

| Tier | Meaning | Initial platforms |
| --- | --- | --- |
| Tier 1 | Automated tests plus accepted real-host installation, scheduling, runtime, API, UI, and notification evidence | QNAP |
| Tier 2 | Automated fixtures and best-effort compatibility, without a complete real-host acceptance record | Debian/Ubuntu and other standard Linux distributions |
| Unsupported | The runtime or required dependencies cannot satisfy the published capability contract | Non-Linux hosts and Docker environments without local daemon access |

Passing an `/etc/os-release` fixture does not promote a platform to Tier 1.
Docker-daemon access, cron persistence, reboot behavior, permissions, and the
real browser/API path require host acceptance.

## Fixed execution rules

- Implement slices in order: `SCWP-01`, `SCWP-02`, then `SCWP-03`.
- Keep common inventory, evidence, policy, UI, and notification logic independent
  of distribution names.
- Put only genuine operating-system differences in platform adapters: executable
  discovery, filesystem defaults, package guidance, and scheduler persistence.
- Do not create a scanner, report schema, or frontend fork per distribution.
- Keep `setup/linux-cli.sh` self-contained because it is downloaded before a
  repository checkout exists.
- Preserve existing QNAP commands, variables, report paths, and deployment
  workflows through additive compatibility during migration.
- Never mount `docker.sock` into the watchdog, admin API, or web container.
- Keep Docker mutations in an explicitly confirmed host CLI workflow. The
  browser remains evidence and guidance only.
- Use a repository-owned, namespaced disposable Compose fixture with isolated
  data and ports for every failure, recovery, recreation, mutation, and rollback
  acceptance test. Production containers require separate explicit operator
  authorization and are never the default test target.
- Keep lightweight container-health collection independent of long Docker Scout
  scans.
- Keep container expectation policy and health evaluation in the watchdog; the
  producer publishes raw observed Docker state only.
- Make every clean result distinguishable from missing, stale, partial, or
  unsupported evidence.
- A slice is not complete until automated tests, applicable real-host checks,
  documentation, and repository-specific commits are complete.

## Repository ownership

| Repository | Responsibility in this plan |
| --- | --- |
| `swarm-info` | Platform detection, local-container inventory, scheduled evidence, image intelligence, runtime-hardening inspection, and host CLI workflows |
| `swarm-info-watchdog` | Capability-aware API, state evaluation, Telegram transitions, UI presentation, and common standalone deployment assets |
| `swarm-swarm-info-watchdog` | Swarm regression contract and production deployment compatibility; it must not absorb standalone host privileges |

Cross-repository work uses the same slice ID in every commit message and result
record. A slice may contain multiple coherent internal checkpoints and commits;
each repository remains independently buildable, testable, and revertible.

## Definition of complete

The currently available-host plan is complete when all of the following are
true:

- QNAP passes the standalone acceptance matrix and the single-manager Ubuntu
  Swarm deployment passes every regression checkpoint.
- One shared capability contract drives CLI, API, UI, and notifications.
- QNAP-specific QPKG, Scout-storage, and persistent-cron behavior lives behind
  a thin adapter rather than being spread through the shared workflow.
- Standalone hosts publish lightweight container-health evidence separately
  from image-vulnerability evidence.
- Operators can explicitly configure whether a container or Compose service
  must run, may stop, or is ignored.
- The UI and Telegram report container-native health without presenting Swarm
  nodes, services, stacks, or replica semantics.
- Image assessment, focused verification, cleanup evidence, and runtime
  hardening guidance are available for standalone containers.
- No public-facing container receives Docker daemon control.
- Existing Swarm scanner, watchdog, deployment, and notification behavior pass
  their regression gates.
- Every Tier 1 claim links to completed, sanitized evidence.

Debian/Ubuntu standalone Docker support remains implemented through the shared
standard-Linux adapter and automated fixtures. It is not a current acceptance
or completion gate because no non-Swarm host is available; a future real-host
run can promote it from Tier 2 without creating a platform-specific fork.

## Explicit non-goals

- Pretending that Docker Compose provides Swarm desired replicas or task history.
- Automatic QTS, Debian, Docker Engine, or operating-system package upgrades.
- Generic unattended container replacement without an installation-owned policy,
  verified source mapping, backup gate, rollback plan, and explicit confirmation.
- Storing environment variables, registry credentials, tokens, or container
  secret values in reports.
- Claiming support for every Linux distribution from one detector fixture.
