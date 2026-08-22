# Current State and Evidence Gaps

## Evidence basis

This baseline is based on the current implementations in all three repositories,
their automated suites, and the completed operator acceptance runs for the QNAP
scanner, scheduled job, API, authenticated UI, private `0600` report access,
and Telegram test delivery.

The accepted QNAP work proves the current compatibility mode. It does not prove
the capabilities proposed by this plan, and it is not reused as future-slice
evidence.

## Current capability matrix

| Capability | Swarm manager | QNAP local Docker | Standard Linux local Docker | Gap carried into this plan |
| --- | --- | --- | --- | --- |
| Runtime auto-detection | Implemented | Implemented | Implemented at Docker-capability level | Platform behavior is not yet represented by one stable capability profile |
| Distribution detection | Generic Linux host data | QNAP/uLinux detection | `/etc/os-release` and package-family detection | QNAP branches remain mixed into shared modules |
| Installation and update | Manager workflow | QGit/Python QPKG-aware | Package-manager-aware installer | Standard-Linux watchdog deployment lacks a first-class profile and real-host proof |
| Full image vulnerability scan | Swarm services, local-first with registry fallback | Exact local image IDs | Exact local image IDs | Equivalent security outcome exists, but resource ownership and UI depth differ |
| Focused verification | Service, image, and stack | Container and exact image ID | Container and exact image ID | Compose-project/service targeting is missing |
| Scan progress | Interactive heartbeat and result report | Interactive heartbeat and scheduled log | Same shared implementation | No machine-readable in-progress status for the UI |
| Scheduled image scan | Managed cron with history and lock | Persistent QNAP cron, cache, history, and lock | User crontab path exists | Adapter ownership and real Debian persistence acceptance are missing |
| Lightweight runtime health | Service replicas, failures, and restart rate | Not implemented | Not implemented | Primary parity gap |
| Expected availability policy | Service expectation overrides | Not implemented for containers | Not implemented for containers | A stopped container cannot safely be called down without explicit policy |
| Health Telegram transitions | Implemented for services | Vulnerability transitions only | Vulnerability transitions only | Container-health transitions are missing |
| Vulnerability UI | Implemented | Implemented from the same report schema | Technically portable | Container mode hides Swarm-only cards instead of replacing them with container-native evidence |
| Operational UI | Service summary, thresholds, and expectations | Not implemented | Not implemented | Primary UI gap |
| Read-only remediation guidance | Service/image/stack guidance and mapping | Compose ownership and copy-ready commands | Same shared path | No targeted Compose-project flow or priority workflow |
| Guarded remediation | Policy-gated Swarm path | Not implemented | Not implemented | Must remain host-side and confirmation-gated |
| Runtime-hardening audit | Not part of current image scan | Not implemented | Not implemented | Image CVEs do not reveal unsafe container configuration |
| Safe unused-image cleanup | Implemented | Implemented | Implemented | UI/status integration and history presentation are missing |

## What is already portable

- `setup/linux-cli.sh` recognizes Debian/Ubuntu, RHEL/Fedora, SUSE, Arch,
  Alpine, generic Linux, and QNAP package layouts.
- Runtime selection is based on Docker capability: a Swarm manager uses the
  manager-wide workflow, and other Docker hosts use exact local-container image
  evidence.
- Local-container scans use `local://` image IDs and never replace the running
  artifact with a similarly tagged registry image.
- The vulnerability report is already resource-aware and can identify affected
  containers and Compose ownership.
- Scan locking, atomic publication, history, caching, focused verification, and
  unused-image cleanup are shared rather than QNAP-only algorithms.

Debian support is therefore an extension and acceptance task, not a second
scanner implementation.

## Structural gaps

### Platform behavior is interleaved

QNAP-specific release detection, QPKG discovery, Docker Scout cache preparation,
and persistent cron behavior currently appear inside otherwise generic installer,
security-check, dependency-check, and scheduling modules. Adding another vendor
exception in those same files would increase branching and make tests less clear.

### There is no standalone operational report

The Swarm health report includes running and desired replicas, recent failures,
restart rate, service image, and lifecycle information. The local-container
inventory currently exists to support image scanning and retains only a small
subset of operational state. There is no independently scheduled, inexpensive
container-health document for the watchdog.

### The UI can only hide unavailable Swarm cards

Container mode can render vulnerability evidence, but it cannot replace hidden
Swarm service cards with container state, Docker health, restart behavior,
Compose ownership, or expected-state configuration because those facts are not
published by the producer.

### Standalone remediation stops at guidance

Compose labels provide useful ownership evidence and current guidance includes
focused rescans, but the prioritized image workflow, candidate assessment,
deployment-source mapping, review diff, post-check, and rollback controls are
not generalized for standalone Compose deployments.

### Image security is not runtime security

Docker Scout identifies vulnerable packages in an image. It does not determine
whether the running container is privileged, mounts the Docker socket, uses host
network/PID namespaces, adds dangerous capabilities, runs as root, exposes
unexpected ports, lacks a health check, or has unsafe writable mounts.

## Evidence gaps to close

| Evidence | QNAP | Debian/Ubuntu | Swarm regression |
| --- | --- | --- | --- |
| Platform profile and capability JSON | Pending `SCWP-01` | Pending `SCWP-01` | Pending regression fixture |
| Installer/update/dependency smoke | Existing baseline; rerun after extraction | No Tier 1 evidence | Existing baseline; rerun after extraction |
| Scheduler install/status/remove and persistence | Existing baseline; rerun after adapter extraction | No real-host persistence evidence | Existing vulnerability-cron regression required |
| Lightweight operational report | Pending `SCWP-02` | Pending `SCWP-02` | Existing service report must remain unchanged |
| Container-health API/UI/Telegram | Pending `SCWP-02` | Pending `SCWP-02` | Existing service UI/alerts must remain unchanged |
| Runtime-hardening and guided remediation | Pending `SCWP-03` | Pending `SCWP-03` | Existing Swarm remediation regression required |

## Fixed boundaries

- A stopped container without an explicit expectation is `unknown` or `idle`,
  not automatically `down`.
- Expected state is monitoring policy only; the web UI does not scale or restart
  containers.
- Compose labels are evidence when Docker provides them. Missing labels never
  justify guessing a deployment directory.
- A long vulnerability scan cannot block or age out the lightweight operational
  collector.
- Report readers must accept older supported reports during additive migration.
- A partial inventory, stale report, failed scanner, or unsupported capability
  cannot be presented as clean.
- No report contains environment values, secret contents, registry credentials,
  or raw command output that may reveal them.

## Primary risks

- QNAP Bash 3.2 and its vendor filesystem/cron behavior differ from standard
  Linux even when both run the same Docker API.
- `setup/linux-cli.sh` is a bootstrap artifact and cannot depend on modules that
  exist only after cloning.
- Multi-hour Docker Scout runs make manual Tier 1 acceptance expensive; cached
  complete evidence should be reused when the tested scope is unchanged.
- QNAP `amd64` acceptance does not prove QNAP `arm64` image availability.
- Compose labels and working-directory paths can disappear after manual container
  creation or migration.
- A Debian container fixture cannot prove host Docker permissions, cron restart,
  reboot persistence, bind-mount ownership, or browser networking.
- Translating Swarm nouns directly into container mode would produce misleading
  states and operator actions.
