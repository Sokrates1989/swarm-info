# Guarded Swarm image source edits

Status: operator requested installation-specific allow rules and a safe
`swarm-info -v` option-4 path. The operator published the implementation and
ran the Ubuntu Redis pilot on 2026-09-27. Exact image deployment, 1/1 Swarm
convergence, Swarm-wide confirmation, and a clean focused Redis rescan passed.
The Redis-dependent API smoke test remains open, so application compatibility
and final pilot acceptance remain pending.

## Decision

Extend `yaml_image` only for a literal `image:` scalar in the exact, verified
Compose service. Unrelated YAML anchors, aliases, or interpolation elsewhere in
the stack should not block that edit. Keep target-service anchors, aliases,
interpolated image values, duplicate service/image declarations, stale images,
unverified mapping, and source path escapes blocked. Before showing an apply
prompt, render the original and proposed Compose configurations and require
their parsed models to differ only in the target service's image reference.

Alternative: use `docker service update --image` as a guarded runtime override.
It could remediate a test service sooner, but the stack source would retain the
old image and a later stack deployment could silently undo the remediation.
The source-edit approach is preferred for durable, repeatable option-4 use.

Operator decisions: installation-specific policy-based remediation was
requested in chat. Separately authorize any push to `origin/main`. No local
implementation or commit authorizes a server rollout. The operator must
explicitly confirm any candidate diff and deployment in the Ubuntu CLI.

## Milestones and acceptance

1. Implement the bounded YAML source selector and a secret-silent rendered-model
   comparison. Update the policy documentation and add focused tests for
   unrelated advanced YAML, target aliases/interpolation, ambiguous layouts,
   non-image render changes, and rollback. Validate with focused and complete
   repository tests. The existing digest, backup, mapping, confirmation, and
   rollback gates remain in force.
2. After an authorized push, rerun the `/swarm/test` Redis option-4 pilot on
   `ubuntu-mini`. Verify the proposed source diff names exactly one test Redis
   image, confirm the immutable candidate and 1/1 convergence, and smoke-test
   its dependent application. If any check fails, use the CLI rollback evidence
   and do not proceed to other services.
3. Use the pilot outcome to review other services individually. Classify
   persistent data, source ownership, candidate security improvement, and
   application compatibility before enabling additional policy targets.
   Option 4 should automate eligible reviewed targets, not bypass these gates
   for every service merely to achieve full coverage.

Implementation completion, local test results, publication, and live acceptance
must be reported separately. The image-security and Swarm-availability parts
of milestone 2 passed; dependent application behavior is not yet verified.

## Local validation

- `python3 -B -m unittest discover -s tests -q` in WSL Ubuntu 24.04:
  316 tests passed on 2026-09-27, including a real Docker Compose render.
- Windows-native full-suite invocation failed in POSIX shell/platform
  tests; use the Linux result for this Bash-oriented repository.
