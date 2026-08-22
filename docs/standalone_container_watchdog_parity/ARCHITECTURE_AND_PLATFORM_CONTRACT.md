# Architecture and Platform Contract

## Architecture decision

Use a capability-first shared core with small platform adapters. Distribution
identity is diagnostic metadata; it is not the primary branch for scanner,
report, API, UI, or notification behavior.

```text
Installer and host command
        |
        v
Platform detector ----> Host profile and capabilities
        |                       |
        |                       +----> common inventory and reports
        |                       +----> common scheduler workflow
        |                       +----> common watchdog/API/UI contract
        |
        +---- standard-linux adapter
        |       +---- package-family metadata (debian, rhel, ...)
        |
        +---- qnap adapter
                +---- QPKG/getcfg discovery
                +---- persistent QNAP cron
                +---- data-volume Scout work paths
```

The adapter answers platform questions. It does not implement vulnerability
parsing, container health, notification policy, or frontend rendering.

## Host profile

`SCWP-01` introduces one versioned, non-secret host profile. The exact Python
types may evolve during implementation, but the published fields must retain
these semantics:

```json
{
  "schema_version": 1,
  "detected_at": "RFC3339 timestamp",
  "platform_adapter": "standard-linux | qnap",
  "os": {
    "id": "qts | debian | ubuntu | ...",
    "family": "qnap | debian | rhel | suse | arch | alpine | generic-linux",
    "version": "sanitized version or unknown",
    "pretty_name": "sanitized display name"
  },
  "docker": {
    "runtime_mode": "swarm | containers",
    "platform": "linux/amd64",
    "compose_available": true
  },
  "capabilities": {
    "image_vulnerability_scan": true,
    "focused_container_scan": true,
    "container_health": false,
    "expected_state_policy": false,
    "scan_progress": false,
    "runtime_hardening": false,
    "guided_remediation": "read-only | guarded | unavailable",
    "image_cleanup": true,
    "scheduler": "user-crontab | qnap-persistent-crontab | unavailable"
  }
}
```

Rules:

- Capabilities describe available evidence and safe actions, not marketing tiers.
- Missing or unsupported capabilities are explicit.
- The profile contains paths only when a consumer needs a sanitized operational
  location; it never contains credentials or environment values.
- UI/API behavior branches on capabilities and runtime resource type, never on
  `os.id == "qts"` or a hard-coded distribution name.
- Auto-detection is the default. An explicit `--os` option remains a diagnostic
  and test override, not a way to bypass capability checks.
- Standard Linux records `family=debian` for Debian/Ubuntu while selecting the
  shared `standard-linux` behavior unless a proven behavioral difference needs
  a narrower adapter.

## Planned module boundaries

### Python host runtime

The intended structure in `swarm-info` is:

```text
scripts/platforms/
  model.py             host profile and capability types
  detect.py            pure detection and adapter selection
  standard_linux.py    PATH/XDG/home paths and user-crontab behavior
  qnap.py              QPKG/getcfg, Scout storage, vendor cron behavior
```

Existing public command behavior remains stable while QNAP-specific helpers are
moved out of shared `security_check`, `security_job`, and `security_cron` paths.
The common job and report logic accepts an adapter interface rather than
importing QNAP constants.

### Shell runtime

Runtime shell helpers may use a corresponding `res/platforms/` boundary when
that reduces duplication. `setup/linux-cli.sh` is the exception: it is downloaded
before a checkout exists and must remain executable by itself.

The installer can keep small bundled adapter functions or be generated and
verified from owned sources, but it must not source files that have not been
cloned yet.

### Watchdog and deployment

The standalone deployment becomes a shared contract, for example:

```text
container-deployment/
  docker-compose.yml
  setup.sh
  acceptance.sh
  profiles/
    standard-linux.env.template
    qnap.env.template
```

The existing `qnap-deployment/` entry points remain as compatibility wrappers or
documented aliases until a migration release has been accepted. Existing QNAP
variables receive generic replacements additively, with deprecated-name fallback
during the migration window.

The Swarm deployment repository remains a separate production target and a
regression consumer. Standalone deployment logic is not copied into its stack.

## Evidence documents

Three producer documents have different performance and freshness contracts:

### Host profile

- Cheap and regenerated whenever setup, status, or evidence collection needs it.
- Describes platform and capabilities.
- Does not describe health or vulnerability findings.

### Container operational report

- Proposed default name: `container_state.json`.
- Lightweight and suitable for frequent scheduling.
- Includes container identity, running/exited/restarting state, Docker health,
  exit code, restart count and policy, start/finish times, image, sanitized port
  summary, and Compose project/service/config ownership.
- Publishes raw observed Docker facts only. It does not read or apply watchdog
  expectation policy.
- Publishes atomically and distinguishes collection failure from a healthy host.
- Does not run Docker Scout.

### Image vulnerability report

- Continues using the existing schema-v2 compatible security report.
- Remains bounded, cached, serial, and potentially long-running.
- `SCWP-02` adds a small adjacent status document with phase, current/total,
  current image label, start/heartbeat time, last completed time, next scheduled
  time, and sanitized failure category.
- A status document is not vulnerability evidence and cannot make an old result
  fresh.

### Fixed paths, cadence, and freshness

The standalone deployment resolves one host evidence directory during setup.
QNAP keeps its accepted `/share/Public/swarm-info` default. Standard Linux uses
`${XDG_STATE_HOME:-$HOME/.local/state}/swarm-info` unless the operator selects
another persistent directory.

Within that directory:

| Document | Default name | Permissions | Writer cadence |
| --- | --- | --- | --- |
| Platform profile | `platform_info.json` | `0600` | Setup/status and when platform evidence changes |
| Container operational report | `container_state.json` | `0600` | Every five minutes by default |
| Vulnerability report | `security_scan-running.json` | `0600` | Existing bounded security schedule |
| Vulnerability progress | `security_scan-running.status.json` | `0600` | Start, every 30-second heartbeat, image completion, and terminal state |

For a custom vulnerability output filename, the progress filename is the same
path with `.status.json` appended after removing the final `.json`. Setup records
the resolved evidence directory and filenames in deployment configuration rather
than making API or frontend code rediscover host paths.

The operational report owns a `freshness` object containing `generated_at` and
`fresh_until`. With the default five-minute cadence, `fresh_until` is fifteen
minutes after generation. The consumer classifies the document stale strictly
when the current time is later than `fresh_until`; missing, invalid, and partial
remain separate states. Schedule and freshness values may be configured, but
the producer always publishes the resulting timestamps so every consumer makes
the same decision.

The operational report schema contains:

- a version, generation/freshness metadata, platform profile reference, scope,
  collection completeness, and sanitized collection errors;
- one stable resource row per observed container with container name, observed
  ID for correlation, image reference and ID, state, Docker health, exit code,
  restart count and policy, timestamps, ports, and Compose ownership;
- previous-sample metadata, `restart_delta`, sample duration, and
  `restart_rate_per_hour`. When no valid previous sample exists, derived restart
  values are `null`, never zero;
- raw aggregate observed-state counts only. Policy-aware health totals belong to
  the watchdog evaluator.

The progress document uses `idle`, `running`, `complete`, `failed`, `cancelled`,
or `timed_out` as terminal/status values and records phase, start time, heartbeat
time, current/total images, current sanitized image label, last completion, next
scheduled time, and sanitized failure category. A `running` document whose
heartbeat is more than two minutes old is presented as interrupted/stalled. A
new run atomically replaces that state; an interrupted process cannot be shown
as complete.

## Expected-state policy

Standalone Docker has no authoritative desired-running replica count. The
watchdog owns one canonical policy in its writable configuration and one
evaluator shared by API, UI, and Telegram. The producer never evaluates this
policy.

The versioned `WATCHDOG_CONTAINER_EXPECTATIONS_JSON` value is stored in the
existing writable watchdog configuration and uses this schema:

```json
{
  "schema_version": 1,
  "rules": [
    {
      "selector": "compose:paperless/webserver",
      "expected_state": "must-run"
    },
    {
      "selector": "container:nightly-backup",
      "expected_state": "may-stop"
    }
  ]
}
```

Allowed stable selectors are:

- `compose:<project>/<service>` for Compose-managed resources;
- `container:<exact-name>` for non-Compose or explicitly overridden resources.

Ephemeral container IDs are not valid selectors. When both selectors match, the
exact container-name rule wins; otherwise the Compose project/service rule is
preferred across container recreation. Duplicate or ambiguous selectors fail
configuration validation.

The policy uses explicit operator intent:

| Policy | Meaning |
| --- | --- |
| `must-run` | A stopped, exited, dead, restarting beyond threshold, or Docker-unhealthy resource needs attention |
| `may-stop` | A stopped or successfully exited resource is allowed; failures and restart loops still need attention |
| `ignore` | Availability is excluded from health totals, while security evidence remains visible |
| Unset | Preserve observed state as `unknown`/`idle`; do not silently classify a stopped container as down |

The policy changes monitoring only. It never starts, stops, scales, recreates,
or removes a container.

## API and UI contract

- API responses include resource terminology and the capability profile.
- Swarm responses continue using services and replicas.
- Standalone responses use containers, Compose projects/services, observed
  state, Docker health, and expected-state policy.
- Unavailable panels are replaced by useful supported panels or a concise
  capability explanation; the frontend does not leave misleading empty Swarm
  controls.
- English and German user-facing strings are updated together.
- A capability absent from the producer cannot be enabled by a frontend flag.
- Telegram transition logic consumes the same evaluated state used by the UI.

## Security boundary

- Docker access remains in the host-side `swarm-info` process.
- The watchdog, admin API, web UI, and reverse proxy receive read-only evidence
  files and writable application configuration only where already required.
- `docker.sock`, Docker TLS client keys, QNAP administrator credentials, and
  registry credentials are never mounted into public-facing services.
- Runtime-hardening reports record booleans, names, and sanitized destinations;
  they never copy environment values, secret contents, or full sensitive mount
  source paths into Telegram messages.
- Mutating remediation requires a local interactive CLI, an installation-owned
  policy, a rendered diff, default-No destructive confirmation where applicable,
  and post-change verification.

## Backward compatibility

- Existing QNAP commands and report discovery paths remain functional.
- Existing `--os=qnap|linux|auto` values remain accepted during the plan. Debian
  does not require `--os=debian`; auto-detection records its family.
- Existing vulnerability schema-v2 readers keep working.
- New report fields are additive and versioned.
- Existing QNAP deployment variables remain supported for at least one migration
  cycle after generic names are introduced.
- Existing Swarm JSON, UI, Telegram transition, and remediation contracts are
  regression gates for every slice.

## Adding another Linux platform

A new distribution should normally require only:

1. An `/etc/os-release` fixture and package-family mapping.
2. Dependency-install guidance for an already supported package manager.
3. Confirmation that standard paths, Compose, and user crontab work.
4. A real-host acceptance row before Tier 1 is claimed.

Create a new platform adapter only when the host has a genuine behavioral
difference comparable to QNAP's QPKG or persistent-cron model. Do not create an
adapter merely because `ID` has a new value.
