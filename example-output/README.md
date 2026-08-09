# Example report contracts

`swarm-info.json` is a sanitized health report containing two healthy and two
degraded services. Its summary counts must always equal the service entries.

`vulnerability-scan.json` is a complete schema-version-2 report produced by the
manual or scheduled vulnerability workflow. It is intentionally static and is
used as source data by local UI tests; consumers that need fresh evidence must
copy it and refresh `started_at`, `completed_at`, and `freshness` timestamps.

Neither file contains credentials, registry responses, or raw Docker Scout
errors. Update the matching contract tests whenever the producer schema changes.
