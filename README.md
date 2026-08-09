# swarm-info
Quick info about swarm status and helpful commands collection

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

Install Docker Scout for the operating-system user that will run `swarm-info`:

```bash
curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
docker scout version
docker login
```

The install command follows Docker's documented
[CLI-plugin installation](https://github.com/docker/scout-cli#cli-plugin-installation).
See [Docker Scout documentation](https://docs.docker.com/scout/) for supported
registries and authentication. Installing as `root` places the plugin in
root's Docker configuration; a non-root cron or shell will not see that copy.

# 🧰 First Setup

Install `swarm-info` under `~/tools/swarm-info`, create a global command
`swarm-info`, and make it permanently available. The installer verifies core
readiness and explains any missing Python or Docker Scout dependency. It does
not install Docker, Python, Scout, or registry credentials automatically.

### 🚀 Simply run the following block in terminal:
```bash
ORIGINAL_DIR=$(pwd)
mkdir -p /tmp/swarm-info-setup && cd /tmp/swarm-info-setup
curl -sO https://raw.githubusercontent.com/Sokrates1989/swarm-info/main/setup/linux-cli.sh
bash linux-cli.sh
cd "$ORIGINAL_DIR"
rm -rf /tmp/swarm-info-setup

# Apply PATH update in current shell (if not already applied)
export PATH="$HOME/.local/bin:$PATH"
hash -r
```

The installer fails when core Docker/manager readiness is unavailable. Missing
scan tooling is reported as a warning so inventory-only use remains available.
After installing any missing dependency, rerun the complete check:

```bash
swarm-info --check-dependencies
```

Dependency-check exit codes are:

| Exit code | Meaning |
|-----------|---------|
| `0` | Core and vulnerability-scanning dependencies are ready. |
| `1` | A core dependency, Docker daemon, Swarm, or manager check failed. |
| `2` | Core commands are ready, but Python or Docker Scout is unavailable. |
| `64` | The dependency checker received invalid arguments. |

The interactive no-option run performs the same full check before opening the
tour. Automated `--json` collection avoids this optional Scout warning, while
`--scan-vulnerabilities` always enforces the scan-specific preflight.

---

# 🚀 Usage

### ✨ Simple call from anywhere in terminal:
```bash
swarm-info
```

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
or force-checks out user work.

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
| `replicas_running` / `replicas_desired` | Current vs expected replica count |
| `status` | `healthy`, `degraded`, or `down` |
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


