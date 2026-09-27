# Policy-gated Swarm fleet remediation

Status: active. The operator requested visible option-4 progress and a path to
attempt all available Ubuntu Swarm image remediations in one policy-driven run.
On 2026-09-27 the operator confirmed that Redis data and pre-alpha website data
may be lost, with backups and repositories available, and prioritized reducing
exposure over individual browser acceptance. Five Redis deployments had passed
exact-image security checks and dependent-client checks in operator output;
manual guided modes 1–3 remain untested. Fleet deployment has not occurred.

Milestone 1 was implemented and the operator exercised its visible progress,
guarded rollout, and rollback boundary on Ubuntu Swarm. The current change
adds an opt-in bulk policy-preparation command; its local tests and Ubuntu
acceptance are separate from those earlier results.

## Proposed approach and decision boundary

Keep option 4's installation-owned, exact-service allow list. Build many
explicit targets at once from previously verified immutable candidates, fresh
live/report identity, the operator's stated loss disposition, and source-edit
proof where possible. Use an explicit, separately confirmed runtime-override
path for unresolved sources if the operator selects it. Option 4 still runs
targets sequentially with progress, candidate rescans, confirmation, bounded
convergence, post-validation, rollback, and a final all-image scan. An opt-in
best-effort flag skips only non-mutating candidate rejection; source and
rollout failures still stop for investigation. Do not
equate Scout's vulnerability reduction with application compatibility.

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
2. **Bulk host-policy preparation.** From the existing assessed candidates and
   fresh manager inventory, stage exact targets only for individually verified
   improvements with unchanged live images. Prove literal YAML image edits by
   private Compose rendering; label unresolved sources as skipped unless the
   operator explicitly opts into runtime drift. Record every decision, preserve
   previous host policy bytes, and use the operator's explicit fleet-wide
   data-loss disposition only for that host policy. No service changes in this
   milestone.
3. **Sequential fleet execution and guided-mode regression.** After the
   operator publishes and reviews the prepared policy, run option 4 once to
   attempt its eligible targets sequentially. Monitor convergence and
   application behavior, stop on error or uncertain rollback, and refresh the
   complete scan. Exercise guided modes 1, 2, and 3 separately without
   authorizing unintended mutations.

## Required operator decisions and acceptance

- The operator has accepted possible fleet data loss for this pre-alpha
  installation; that acceptance must be passed explicitly to the host-policy
  preparer. A previous image digest is not a data rollback. Each CLI source
  edit/deployment still requires confirmation, and runtime-only overrides
  remain visibly distinct from durable source edits.
- The operator-provided Redis 8 client and feature probes satisfy the
  Redis-dependent acceptance criterion for those completed updates. The
  fleet-wide run will use a shorter best-effort acceptance cycle; untested
  application behavior must be reported rather than called verified.
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
