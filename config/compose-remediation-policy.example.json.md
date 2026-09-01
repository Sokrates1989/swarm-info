# Standalone Compose remediation policy

This installation-owned JSON policy is the only authorization source for
`swarm-info --compose-remediation`. Copy the example to a private host path,
review every value, and enable a target only after its backup and compatibility
requirements are satisfied. Do not store credentials, tokens, passwords, or
Docker secrets in the policy.

The schema is intentionally narrow:

- `schema_version` must be `1`.
- `id` is a unique audit identifier.
- `enabled` must be `true` before the target can be selected.
- `match.compose_service` is the exact `PROJECT/SERVICE` pair retained in
  Docker Compose labels.
- `match.repository` is the only repository from which a candidate is allowed.
- `candidate_image` must include both a tag and a complete `sha256` registry
  digest and must remain in the matched repository.
- `backup.status` is `ready` when workload recovery has been verified or
  `not_required` for a reviewed stateless/disposable service. A concrete reason
  is always required; apply still asks the operator to confirm readiness.
- `source.type` is currently only `yaml_image`.
- `source.file` is relative to the exact Compose working directory and must
  resolve to one of the config files retained in
  `com.docker.compose.project.config_files`.
- `verification.timeout_seconds` is between 30 and 1800 seconds.

The current source image must also be pinned to a complete registry digest.
That restriction ensures source restoration recreates the exact prior artifact
instead of following a tag that may have moved.

The default invocation is a dry-run. It scans the candidate, prepares a
zero-context diff, validates a temporary replacement through Docker Compose,
and writes a private transaction plan without changing source or containers.
`--apply` requires two default-No confirmations. The browser, watchdog, and
admin API cannot invoke this command and never receive the Docker socket.
