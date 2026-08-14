# swarm-info
Docker Swarm status, remediation guidance, and portable container-image
security checks for Linux hosts including QNAP Container Station.

# Backlog
Stuff that just could not be finished in time:
 - Headings of individual scripts: Add bash command how to call them directly
 - Context menus 
   - Add context menu every time there is a context
   - Broaden context of context menus

# Prerequisites

Core swarm inventory requires:

- Linux with Bash 4 or newer.
- Git for installation and update checks.
- Docker Engine with access to its daemon.
- An active Docker Swarm manager node. Worker nodes cannot inventory all
  services.

Portable local-container security mode requires only:

- Linux with Bash 3 or newer.
- Docker CLI access to the local daemon (QNAP: Container Station plus SSH).
- Python 3.10 or newer and Docker Scout.

Git is still required by the repository installer and guarded self-update.
Local-container mode does not require Swarm, `bc`, or Docker Compose.

Install Bash and Git on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y bash git
```

On RHEL/Fedora:

```bash
sudo dnf install -y bash git
```

Install Docker Engine using the official platform instructions:
[Docker Engine installation](https://docs.docker.com/engine/install/).

Image vulnerability scanning additionally requires Python 3.10+ and the
Docker Scout CLI plugin. Install Python on Debian/Ubuntu with:

```bash
sudo apt-get update
sudo apt-get install -y python3 curl
python3 --version
```

Install Docker Scout for the operating-system user that will run `swarm-info`.
Download and inspect Docker's official installer before executing it:

```bash
curl -fsSL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh -o install-scout.sh
sed -n '1,240p' install-scout.sh
sh install-scout.sh
docker scout version
# Needed only for private-registry or Swarm registry-fallback scans:
docker login
```

The install command follows Docker's documented
[Docker Scout installation](https://docs.docker.com/scout/install/). QNAP
systems for which the convenience installer is unsuitable can use Docker's
architecture-matched manual CLI-plugin instructions on that page. See
[Docker Scout documentation](https://docs.docker.com/scout/) for supported
registries and authentication. Installing as `root` places the plugin in
root's Docker configuration; a non-root cron or shell will not see that copy.

# 🧰 First Setup

Install `swarm-info` under `~/tools/swarm-info`, create a global command
`swarm-info`, and make it permanently available. The capability-driven
installer supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch/Manjaro, Alpine,
generic Linux, and QNAP. It detects the package manager or QPKG layout, checks
the Docker runtime before cloning, and verifies the installed command and the
repository-owned dependency contract afterwards.

On another Linux distribution, setup remains usable when the required commands
are already present. If they are missing, it stops with a generic package list
instead of guessing an unsafe package-manager command.

Missing Git, Python, Bash, or `bc` packages can be installed from the host's
already-configured distribution repositories after one explicit confirmation.
Docker, Docker Scout, registry credentials, and QNAP QPKGs are never installed
automatically.

### 🚀 Simply run the following block in terminal:
```bash
curl -fsSLo /tmp/swarm-info-install.sh \
  https://raw.githubusercontent.com/Sokrates1989/swarm-info/main/setup/linux-cli.sh

# Recommended before the first execution: inspect the complete downloaded script.
sed -n '1,9999p' /tmp/swarm-info-install.sh

# Optional read-only inspection. Exit 2 means only optional scan tooling is missing.
bash /tmp/swarm-info-install.sh --check-only

# Interactive installation; missing repository packages are offered once.
bash /tmp/swarm-info-install.sh

# Apply PATH update in current shell (if not already applied)
. "$HOME/.profile"
hash -r
```

For unattended provisioning, choose package mutation explicitly:

```bash
# Install supported missing repository packages without prompting.
bash /tmp/swarm-info-install.sh --install-missing --non-interactive

# Never change distribution packages; stop with exact recovery guidance.
bash /tmp/swarm-info-install.sh --non-interactive
```

An existing Git checkout is preserved and never replaced. Use `swarm-info -u`
for its guarded fast-forward update. If the configured install target exists
but is not a Git checkout, setup stops instead of cloning into or overwriting
that directory.

The installer detects manager capability. It validates the full Swarm runtime
on a manager and the portable security runtime on a standalone Docker/QNAP
host. Missing scan tooling is reported as a warning.
After installing any missing dependency, rerun the complete check:

```bash
swarm-info --check-dependencies
```

That command auto-selects full Swarm-manager readiness or the narrower
standalone/QNAP security readiness from the local Docker capability.

Dependency-check exit codes are:

| Exit code | Meaning |
|-----------|---------|
| `0` | Core and vulnerability-scanning dependencies are ready. |
| `1` | A core dependency, Docker daemon, Swarm, or manager check failed. |
| `2` | Core commands are ready, but Python or Docker Scout is unavailable. |
| `64` | The dependency checker received invalid arguments. |

The no-option run opens the established tour on a Swarm manager and selects
the local-container security check on a standalone Docker host. Automated
`--json` collection remains Swarm-specific, while image scan commands always
enforce their applicable preflight.

---

# 🚀 Usage

### ✨ Simple call from anywhere in terminal:
```bash
swarm-info
```

The default tour keeps the operational signal together: the Docker service
list includes a concise down/degraded summary and the next page shows the
latest vulnerability evidence. A missing or older-than-30-hours scan is never
presented as clean; the page offers an explicit scan and warns that it can take
several minutes.

Open either page directly:

```bash
# Down/degraded services only, with investigation commands
swarm-info -d
swarm-info --service-health

# Latest vulnerability report, affected images, and remediation commands
swarm-info -v
swarm-info --vulnerabilities
```

## QNAP and standalone Docker security mode

Use the explicit compatibility command on QNAP or any Linux host with a local
Docker daemon:

```bash
# Auto-select Swarm-wide service coverage on a manager; otherwise local containers
swarm-info --security-check

# Equivalent explicit QNAP/local-container form
swarm-info --security-check --container-mode --os=qnap

# Scan only currently running containers instead of all defined containers
swarm-info --security-check \
  --runtime-mode containers \
  --container-scope running \
  --os qnap \
  --output-file /share/Public/swarm-info/security_scan.json
```

Auto mode reads Docker capability rather than guessing from a distribution:

- With no arguments, a manager opens the established Swarm tour while a
  standalone host starts the compatible local-container security check and
  warns that it may take several minutes.
- A manager scans every Swarm service image with the established exact-digest
  local-first and registry-fallback policy.
- Any other Docker host scans the exact content-addressed image IDs attached to
  local containers. The default scope is `all`, including stopped containers;
  use `--container-scope running` for a narrower check.
- Local-container mode uses Docker Scout `local://` only. It never substitutes
  a registry tag, so the report cannot silently describe a different image.
- Interactive scans print inventory totals, a current/total image counter,
  per-image results and elapsed time. While one Docker Scout process remains
  active, a heartbeat is printed every 30 seconds so a slow scan is visible.
- QNAP is detected from `/etc/config/uLinux.conf` or `ID=qts` in
  `/etc/os-release`. `--os=qnap` is an auditable hint, not a way to bypass
  Docker capability checks.
- `--platform` defaults to the Docker daemon platform in this mode, supporting
  common QNAP `amd64` and `arm64` systems.
- The Python3 QPKG is discovered from `/etc/config/qpkg.conf` even when QNAP
  exposes only the unrelated Python 2.7 command on `PATH`. The supported QNAP
  layout includes `<Install_Path>/opt/python3/bin/python3`.
- The installer and guarded updater likewise discover the QGit QPKG when its
  `git` executable is not on `PATH`.
- Docker Scout may be used through `docker scout` or directly from
  `~/.docker/cli-plugins/docker-scout`. This supports vendor Docker builds that
  do not expose an otherwise valid user plugin.
- On QNAP, security checks automatically place Docker Scout extraction and
  cache data under the private, data-volume-backed directory
  `~/.cache/swarm-info/docker-scout`. Existing `TMPDIR` and
  `DOCKER_SCOUT_CACHE_DIR` values remain authoritative. The selected paths are
  recorded under `environment.docker_scout_work` in the JSON report.

QNAP's `/tmp` is commonly small. Docker Scout installation itself still needs
an explicit data-volume temporary directory because `swarm-info` is not yet
running while the plugin is installed:

```bash
mkdir -p "$HOME/.tmp-scout"
TMPDIR="$HOME/.tmp-scout" sh install-scout.sh
"$HOME/.docker/cli-plugins/docker-scout" version
```

Without `--output-file`, compatibility evidence is atomically written to
`swarm_info/security_scan.json`, separate from the Swarm watchdog's
`vulnerability_scan.json`. Exit code `0` means clean, `2` means fixable HIGH or
CRITICAL findings, and `3` means incomplete evidence.

This first compatibility mode is deliberately read-only. It scans images used
by defined containers; it does not patch QTS, change containers, inspect unused
images, audit Docker runtime hardening (privileged mode, mounts, ports), or run
Swarm deployment mapping/remediation on a standalone host.

## Safe unused-image cleanup

Review cleanup candidates on QNAP, standalone Docker, or a Swarm manager:

```bash
# Read-only review; no image is removed
swarm-info -i

# Review, then request default-No confirmation before removal
swarm-info -i --apply

# Explicit non-interactive automation
swarm-info -i --apply --yes \
  --output-file /share/Public/swarm-info/image_cleanup.json
```

Cleanup always covers only the current Docker node. It protects images used by
running or stopped local containers. On a manager it additionally protects
every locally available image declared by a Swarm service, including
scaled-to-zero services. Deletion is refused on Swarm workers because they
cannot inventory all service declarations. Run the command separately on each
node when node-local cleanup is intended.

The `i` shortcut in either interactive menu opens the same review and then
offers the default-No removal confirmation. Direct `swarm-info -i` remains a
read-only command.

The candidate size is an upper bound based on virtual image sizes; shared layers
mean actual recovered storage is normally smaller. Before an approved cleanup,
swarm-info repeats the complete safety inventory and removes only image IDs that
were both reviewed and remain unused. Parent images required by protected
workloads are protected as well. Unused branches are removed child-first;
dependency conflicts are retried only after a child was actually removed, and
parents removed implicitly by Docker are recorded separately instead of being
reported as failures. When Docker refuses an unused image with multiple tags,
every tag must still resolve to the approved exact image ID before the tags are
removed. Tag drift stops that image without mutation. The workflow never uses
`--force`, never pulls from a registry, and never schedules cleanup
automatically.

When a fresh vulnerable report is shown in an interactive terminal,
`swarm-info -v` continues directly into the remediation menu. It offers:

1. A complete service list, including how many services share each image.
2. A complete vulnerable-image list, including all consuming services.
3. Priority guidance ordered by critical findings and then high findings.
4. Policy-gated auto-remediation with a dry-run plan, candidate scan, diff,
   confirmations, convergence checks, post-validation, and rollback.

`swarm-info -v --menu` additionally offers an immediate all-image scan. The
scan remains explicit because it can be network- and CPU-intensive. Open the
same remediation workflow directly with:

```bash
swarm-info --remediate-vulnerabilities --deploy-root /swarm
```

View the version-matched command reference with `swarm-info --help` or
`man swarm-info`.

## Verify service deployment paths

Before guided remediation uses local deployment paths, verify the conservative
service mapper independently. It renders candidate YAML through Docker Compose
but never changes Docker, stack files, or environment files:

```bash
swarm-info --map-service-deployments \
  --deploy-root /swarm \
  --output-file /info_json/service_deployment_map.json
```

`--deploy-root` is repeatable and defaults to `/swarm`. A path-separated
`SWARM_INFO_DEPLOY_ROOTS` environment value can provide a different default.
Legacy locations are never added implicitly. For example, inspect an old
Gluster deployment only when you intend to include it:

```bash
swarm-info --map-service-deployments \
  --deploy-root /swarm \
  --deploy-root /gluster_storage/swarm
```

Docker Compose receives each candidate's sibling `.env`; rendered environment
data is discarded except for service names and image references. `STACK_NAME`
is preferred. When it is absent, swarm-info accepts the stack identity only if
exact live service names and images identify one unique Swarm stack. If a
malformed `.env` prevents rendering but an explicit `STACK_NAME` exists,
Compose defaults may identify the path while the source remains unverified.

A unique stack/service match with a stale declared image is reported as mapped
path ownership with `source_verified=false`, not as a safe source match. Guided
mode can show that directory, but automatic declarative editing is disabled and
the guarded runtime-override path is used instead. Competing files or
directories remain `ambiguous`; missing Compose support and insufficient
evidence remain `unknown`. Historical YAML aliases containing markers such as
`.backup.`, `.old.`, or `.disabled.` and backup directories are ignored.

Deployment-map schema version 2 records every service, candidate files involved
in unresolved results, declared/live image agreement, stack-name evidence,
render source, and the `source_verified` mutation gate. Review all mapped paths
on the manager before allowing guided remediation to use them. You can pass an
accepted report with `--deployment-map-file`; auto-remediation still regenerates
live mapping evidence before planning a mutation. The mapper returns exit code
`2` while any path is unknown, ambiguous, or backed by an unverified source.

## Guided and safe auto-remediation

Docker Scout's `--only-fixed` result means a package-level fix exists. It does
not guarantee that a ready replacement image tag exists. A durable fix normally
requires one of the following:

- First-party image: update its base image and dependencies, rebuild it, push
  it, and scan the exact candidate digest.
- Third-party image: choose a maintained patched upstream tag and scan its exact
  digest.
- False-positive/not-exploitable finding: document a reviewed VEX exception;
  do not silently suppress it.

The targeted and guided modes explain these steps and show the verified
deployment directory, owning stack file, Scout commands, deployment command,
service verification, and final full scan. They never change Docker or files.

Auto-remediation requires an installation-owned policy. Keep this file in the
Git repository that owns the deployment configuration:

```bash
cd /swarm/administration/swarm-info-watchdog
swarm_info_dir="$(dirname "$(readlink -f "$(command -v swarm-info)")")"
install -d -m 0750 configs
install -m 0640 \
  "$swarm_info_dir/config/remediation-policy.example.json" \
  configs/remediation-policy.json

# Edit and review explicit targets using the companion documentation.
${EDITOR:-nano} configs/remediation-policy.json
git diff -- configs/remediation-policy.json

swarm-info --remediate-vulnerabilities \
  --deploy-root /swarm \
  --remediation-policy "$PWD/configs/remediation-policy.json" \
  --remediation-plan-file /info_json/vulnerability_remediation_plan.json
```

See
[`config/remediation-policy.example.json.md`](config/remediation-policy.example.json.md)
for the complete schema and an example target. Never place credentials, Docker
secrets, passwords, or tokens in this policy.

Configure one target per distinct stack/source-key image update. If several
services in one stack share that source, one representative service is enough;
use separate targets for consumers owned by different stacks or keys. The final
all-image scan verifies the complete consumer set.

The auto-remediation sequence is intentionally strict:

1. Require fresh, complete scan evidence and live manager access.
2. Regenerate conservative service-to-stack mappings.
3. Merge scan, mapping, and policy into an atomic plan with a stable plan ID.
4. Require both an immutable current image for exact rollback and a tagged
   candidate pinned to a full SHA-256 digest in the same image repository, plus
   an explicit `backup.status=not_required` justification.
5. Scan the candidate and reject it unless critical/high counts improve and no
   new critical/high CVE identifier appears.
6. For a mapped source, recheck the old value, show a unified diff, and ask
   before writing. Ambiguous YAML, aliases, interpolation, duplicate keys,
   symlinks, path escapes, and stale values fail closed.
7. Ask separately before deployment (default `Y` only after the source change
   was explicitly accepted), wait for the service to converge, and scan the
   immutable candidate again.
8. Restore the original source and previous rendered stack when deployment or
   post-validation fails, then verify rollback convergence.
9. After any successful deployment, run and atomically publish a locked,
   complete all-image confirmation scan with the normal freshness/history
   metadata so the next CLI/UI/watchdog view uses fresh Swarm-wide evidence.

`--force-auto-remedy-attempt` overrides only `auto_eligible=false`. It cannot
bypass a disabled entry, backup classification, immutable digest, repository
match, candidate scan, source precondition, review prompt, convergence check,
post-validation, or rollback.

When deployment source remains unknown, the workflow prints the exact guarded
`docker service update` and rollback commands. Execution requires both
`--allow-runtime-override` and a separate default-No confirmation. This is a
temporary runtime override and therefore configuration drift; update the
declarative stack source as soon as it is found.

## Safe self-update

Update the installed checkout through swarm-info itself:

```bash
swarm-info -u
# Equivalent long option:
swarm-info --update
```

The updater fetches the current branch's configured upstream and accepts only
a clean, strictly fast-forward update. It refuses to overwrite uncommitted
files, untracked files, local commits, or a divergent branch. Resolve those
states manually and rerun `swarm-info -u`; the updater never stashes, resets,
or force-checks out user work. Every update attempt prints the absolute
checkout directory and copy-ready `cd` / `git status` guidance, including when
the update is refused.

---

# 📄 JSON Output for messaging / automation

Collects Docker Swarm service health data and writes structured JSON. This data can be consumed by a watchdog (e.g. `swarm-info-watchdog`) to alert on unhealthy or crash-looping services via Telegram, email, or other messaging tools.

### 🔧 Default json output file
Writes output to `path/to/swarm-info/swarm_info/swarm_info.json`
```bash
swarm-info --json
```

### 📝 Custom file
You can also provide a custom file where to write the json file to
```bash
# Ensure custom dir exists.
mkdir -p /custom/path

# Command option short.
swarm-info --json -o /custom/path/file.json
# Command option long.
swarm-info --json --output-file /custom/path/file.json
```

### 📊 JSON Structure
See `example-output/swarm-info.json` for a full example. Key fields per service:

| Field | Description |
|-------|-------------|
| `name` | Docker service name (e.g. `reminderbot_bot`) |
| `replicas_running` / `replicas_desired` | Current tasks vs Docker Swarm's desired task count |
| `monitoring_expected_replicas` | Expected continuously running tasks after lifecycle detection |
| `service_mode` | Docker service mode reported by Swarm |
| `lifecycle` | `daemon`, `scheduled`, `one-shot`, `job`, or `ignored` |
| `lifecycle_source` | Whether lifecycle came from Docker mode, swarm-cronjob, or an explicit label |
| `latest_task_state` | Normalized latest terminal task state used for job health |
| `status` | Availability/execution status such as `healthy`, `degraded`, `down`, `idle`, `completed`, or `failed` |
| `total_failures` | Total failed tasks (all time, as retained by Docker) |
| `recent_failures` | Failed tasks within the last hour |
| `restart_rate_per_hour` | Failures per hour (for crash-loop detection) |
| `last_failure_ago_seconds` | How recently the last failure occurred |

The `summary` section provides totals:
```json
"summary": {
  "total_services": 4,
  "healthy": 2,
  "degraded": 2,
  "down": 0
}
```

The `unhealthy_services` array lists names of all non-healthy services for quick alerting.

Services carrying `swarm.cronjob.enable=true` and native Docker jobs are
recognized automatically. Other one-shot services can declare their intent
without changing Docker's replica target:

```yaml
deploy:
  labels:
    - "swarm-info.monitoring.lifecycle=one-shot"
  restart_policy:
    condition: none
```

A completed or idle job is healthy while its latest failed execution remains
degraded. Unknown lifecycle label values fall back to daemon behavior so a typo
cannot suppress a real availability alert.

---

# Image vulnerability scanning

`swarm-info` can manually scan every current Docker Swarm service image from a
manager node. Images that share the same registry digest are scanned once and
the report maps the result back to every consuming service and stack.

The Slice 1 policy matches the Python API template:

- Scanner: Docker Scout.
- Source: exact local digest first, with registry fallback when it is absent.
- Platform: `linux/amd64` by default.
- Findings: fixable `HIGH` and `CRITICAL` CVEs.
- Output: a separate, atomically replaced JSON report.

This is a policy scan rather than a complete inventory of all severities and
unfixed vulnerabilities.

For the latest evidence and copy-ready remediation commands, run:

```bash
swarm-info -v
```

Digest-pinned images are first scanned through Docker Scout's `local://`
source. This avoids redundant registry access when the exact deployed artifact
is present on the manager. A missing or unreadable local artifact falls back to
`registry://`, which keeps multi-node and zero-replica service coverage intact.
Mutable tag-only references remain registry-only because a local tag may have
moved independently of the service specification.

Registry fallback uses at most three attempts with short backoff for transient
failures. Authentication, authorization, and permanent manifest errors stop
immediately. Scout progress animation is removed from stored errors so the
report retains the final actionable, credential-redacted diagnostic.

## Scanner prerequisites

Run the scan as the same operating-system user that owns the Docker Scout
installation and registry credentials. Use the installation commands in
[Prerequisites](#prerequisites) when Scout is unavailable.

```bash
docker info --format 'swarm={{.Swarm.LocalNodeState}} manager={{.Swarm.ControlAvailable}}'
docker scout version
```

Private registries must already be available through that user's Docker
credential store. The command does not install Scout, run `docker login`, or
write credentials into its report.

## Run the scan

```bash
swarm-info --scan-vulnerabilities \
  --platform linux/amd64 \
  --output-file /info_json/vulnerability_scan.json
scan_status=$?
echo "scan exit code: $scan_status"
```

Use the installed `swarm-info` command for normal operation. If a damaged or
legacy checkout reports `Permission denied` with exit code `126`, invoke the
tracked script through Bash once and run the guarded updater:

```bash
cd ~/tools/swarm-info
bash ./get_info.sh -u
```

Current releases track `get_info.sh` as executable, so a successful update
repairs direct `./get_info.sh` and symlink execution without a local mode-only
Git modification.

Without `--output-file`, the report is written to
`swarm_info/vulnerability_scan.json` in the installed repository.

Exit codes are deliberately automation-friendly:

| Exit code | Meaning |
|-----------|---------|
| `0` | Every unique image was scanned and no policy findings exist. |
| `2` | Every unique image was scanned and at least one finding exists. |
| `3` | Inventory, one or more image scans, or report publication was incomplete. |

Exit code `2` is an expected vulnerability result, not an execution failure.
When one image fails, the command continues scanning the remaining images,
publishes their findings, marks the report `incomplete`, and exits `3`.

## Inspect and reconcile the result

```bash
python3 -m json.tool /info_json/vulnerability_scan.json | less

docker service ls --format '{{.Name}}\t{{.Image}}'

python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(Path('/info_json/vulnerability_scan.json').read_text())
print(json.dumps(report['summary'], indent=2))
print('\nServices represented in the report:')
names = {
    service['name']
    for image in report['images']
    for service in image['services']
}
print('\n'.join(sorted(names)))
PY
```

Confirm that `scope.service_count` matches `docker service ls -q | wc -l`.
Check every image entry with `status: "error"`; authentication or registry
failures are never treated as clean results.

Vulnerability report schema version 2 adds per-image `scan_source`,
`scan_attempts`, and `registry_fallback` fields. The summary also reports
`local_images`, `registry_images`, `retried_images`, and
`registry_fallback_images`, making registry use directly auditable.

## Developer verification

The tests use deterministic fake Docker/Scout, Git, locking, and crontab
adapters and make no network, registry, or Docker daemon calls.

```bash
python3 -B -m unittest discover -s tests -v
bash -n get_info.sh res/*.sh setup/*.sh
```

## Slice 2: locked daily operation

Manual `--scan-vulnerabilities` remains a forced scan, but now uses the same
non-blocking lock, atomic report publication, and history retention as the
scheduled job. The default lock is beside the report as
`vulnerability_scan.json.lock`; overlapping invocations exit successfully
after logging that the active job owns the lock.

Install an idempotent current-user daily cron entry at 03:17:

```bash
swarm-info --install-vulnerability-cron \
  --output-file /info_json/vulnerability_scan.json \
  --platform linux/amd64 \
  --cron-hour 3 \
  --cron-minute 17 \
  --cache-age-hours 20 \
  --max-age-hours 30 \
  --history-days 14

crontab -l
```

The installer preserves unrelated cron entries and replaces only the block
between `BEGIN/END swarm-info managed vulnerability scan` markers. Remove only
that managed block with:

```bash
swarm-info --remove-vulnerability-cron
```

The scheduled command inventories current service specifications first. It
reuses a complete report only when its normalized image/service fingerprint,
platform, and 20-hour rescan interval still match. An image, service mapping,
stack, or alias change therefore scans immediately; unchanged repeated triggers
within 20 hours reuse evidence. The separate 30-hour freshness limit gives a
daily scan enough scheduling margin without suppressing the next daily Scout
database refresh.

Replaced valid reports are atomically archived under
`/info_json/vulnerability_history/` and pruned after the configured retention
period. Incomplete scans preserve the prior success time in
`freshness.last_successful_at` while remaining explicitly incomplete.

Inspect current evidence without contacting Docker or Scout:

```bash
swarm-info --vulnerability-status \
  --output-file /info_json/vulnerability_scan.json \
  --max-age-hours 30
```

Status exit codes retain the scan contract: `0` fresh clean, `2` fresh with
findings, and `3` missing, stale, or incomplete. Keep this workload daily; do
not add Docker Scout to the five-minute health collection cron.

---

# ⏰ Automation via Cronjob

Setup cron to get periodic swarm info.

### Open crontab in edit mode:
```bash
crontab -e
```

### Example – every 5 minutes (recommended for health monitoring):
```bash
# Check swarm health every 5 minutes.
*/5 * * * * /root/.local/bin/swarm-info --json --output-file /info_json/swarm_info.json
```

### Example – hourly at minute 59:
```bash
59 * * * * /root/.local/bin/swarm-info --json --output-file /info_json/swarm_info.json
```


