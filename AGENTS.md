# Repository instructions for coding agents

Follow the operator's global `AGENTS.md` and the local `coding-guidelines`
router before changing this repository. This file adds `swarm-info`-specific
behavior; it does not replace those rules.

## Remediation ownership

- `swarm-info -v` displays vulnerability evidence and offers guided modes
  1–3 and option 4, **Fast secure auto-remediation**. Option 4 is not a blanket
  permission to upgrade every service.
- The installation-owned `remediation-policy.json` is the per-service allow
  list. Only enabled top-level `targets` can authorize a fixed-tag candidate,
  backup classification, and source edit. `generated_review` and its
  `suggested_target` entries are evidence, never authorization. See
  [the policy contract](config/remediation-policy.example.json.md).
- Option 4 loads the selected policy on each run. The operator may select it
  with `SWARM_INFO_REMEDIATION_POLICY` or `--remediation-policy`; otherwise the
  CLI uses its documented host-local default. The intended loop is: assess a
  service, review and persist one exact target, rerun `swarm-info -v` option 4,
  confirm its proposed source diff/deployment, and verify the workload. No
  separate one-off deploy script should be required for a supported source.
- A target must identify the exact live Swarm service and image repository,
  an immutable tagged candidate digest, the reviewed backup disposition, and
  an exact source adapter where the service is declaratively mapped. The
  mapped stack directory bounds the allowed source file. `auto_eligible` is
  set only after those facts have been reviewed for that installation.
- Host-specific policy decisions (including disposable-data classifications,
  candidate digests, and `/swarm` source paths) belong to the operator's
  installation policy, not to this repository's example policy or generic
  defaults. Never infer a backup exemption or application compatibility from
  Docker Scout findings alone.
- Docker Scout improvement proves a security difference between exact image
  artifacts, not application compatibility or permission to deploy. Preserve
  the CLI's candidate scan, source diff, confirmation, convergence,
  post-validation, and rollback gates. Run a workload-specific smoke check
  before accepting a major-version update.
- If a source cannot be edited unambiguously, report the blocker. Do not
  fabricate mapping evidence or silently substitute `docker service update`:
  a runtime override causes drift and requires its explicit CLI flag and
  confirmation. Make a source adapter more capable only with focused negative
  tests and a rendered-stack non-target-change guard.

For a live remediation, first confirm the exact host, Docker context, service,
source file, current digest, candidate digest, and backup disposition. Change
one reviewed target at a time, then verify its dependent application and the
refreshed vulnerability report. Keep Ubuntu Swarm and QNAP standalone Docker
acceptance separate. Do not claim that all services can be remediated
automatically; unsupported or unsafe targets must remain blocked for review.
After the first accepted option-4 image remediation, also exercise and review
the manual guided modes 1, 2, and 3; an option-4 success does not test them.
