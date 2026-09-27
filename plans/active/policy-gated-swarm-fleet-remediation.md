# Policy-gated Swarm fleet remediation

Status: active. The operator requested visible option-4 progress and a path to
remediate as many Ubuntu Swarm services as can be reviewed safely. The first
Redis source edit and image update succeeded technically on 2026-09-27; its
dependent API smoke test remains pending. No fleet-wide policy authorization
has been granted by that pilot.

Milestone 1 is implemented locally and validated with 316 offline WSL tests on
2026-09-27. The changes have not been published or tested on Ubuntu Swarm.

## Proposed approach and decision boundary

Keep option 4's existing installation-owned, exact-service allow list. Extend
generic execution safety without guessing candidate versions or backup
dispositions. Process reviewed targets sequentially with a visible heartbeat,
bounded Swarm convergence/stability check, post-scan, and fail-stop behavior.
Continue requiring confirmation for each proposed source diff and deployment.
Do not equate Scout's vulnerability reduction with application compatibility.

The alternative is to promote every generated suggestion or discovered newer
tag into an executable target. That could cross major-version and data-format
boundaries without backups or smoke checks. It is not approved. A runtime-only
override is also not a durable substitute for a mapped stack source.

## Milestones

1. **Generic safety and operator feedback.** Add immediate/periodic progress
   around every option-4 image action, preserve per-target confirmations, stop
   when an accepted source edit is not deployed, and support an opt-in bounded
   Swarm stability window that uses existing rollback on failure. Update
   policy documentation and focused offline tests; run the complete local
   suite. No server is changed in this milestone.
2. **Installation evidence and target review.** After the operator manually
   publishes the code, collect a redacted Ubuntu inventory of the remaining
   affected services: live digest, exact declarative source, candidate digest
   and proven CVE reduction, mounts/data classification, backup/restore proof,
   and an application-specific smoke check. Create one reviewed host-local
   policy target per independent source. `/swarm/test` Redis data may be
   classified disposable as the operator stated; do not extend that exemption
   to other paths or production services. Validate the first remaining target
   end-to-end before enabling the next risk group.
3. **Staged fleet execution and guided-mode regression.** Run option 4 against
   reviewed targets one at a time, monitor convergence and dependent app
   behavior, stop on error or uncertain rollback, and refresh complete scan
   evidence. After the first accepted option-4 pilot, exercise guided modes
   1, 2, and 3 separately without authorizing unintended mutations.

## Required operator decisions and acceptance

- The operator must confirm backup disposition and compatibility/smoke-test
  criteria for each stateful or major-version target. A previous image digest
  is not a data rollback. Host-specific policy changes require their own
  review and each CLI deployment confirmation.
- Manual acceptance of Redis 8 requires one successful Redis-dependent API
  operation after the update. Swarm replicas and a clean Scout scan alone do
  not satisfy this acceptance check.
- Success for milestone 1 is local tests and documentation, not a claim of
  Ubuntu rollout. Success for a fleet target requires source/live identity,
  healthy Swarm state, dependent behavior, and fresh security evidence.

Rollback: source-based actions restore the previous source and rendered stack
after a confirmed deploy that later fails. Runtime/latest actions request
Docker service rollback. Any failed or unconfirmed rollback stops the batch
for operator investigation. No automatic action here removes images, volumes,
secrets, or persistent data.

Known limitation: the convergence timeout begins after `docker stack deploy`
returns; a Docker daemon/client call that never returns is currently reported
by progress heartbeats but not terminated by that policy timeout. A
non-zero stack-deploy exit may have partially modified a stack, so it requires
operator review even when the previous source bytes were restored.
