# swarm-info
Quick info about swarm status and helpful commands collection

# Backlog
Stuff that just could not be finished in time:
 - Headings of individual scripts: Add bash command how to call them directly
 - Context menus 
   - Add context menu every time there is a context
   - Broaden context of context menus

# Prerequisities
### Bash
Debian-based systems like Ubuntu
```bash
sudo apt update
sudo apt install bash
```

Red Hat-based system
```bash
sudo yum update
sudo yum install bash
```

### Python

Python 3.10 or newer is required for image vulnerability scanning.

```bash
python3 --version
```

# 🧰 First Setup

Install `swarm-info` under `~/tools/swarm-info`, create a global command `swarm-info`, and make it permanently available:

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

---

# 🚀 Usage

### ✨ Simple call from anywhere in terminal:
```bash
swarm-info
```

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
  "total_services": 12,
  "healthy": 10,
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
- Source: exact service reference from the registry.
- Platform: `linux/amd64` by default.
- Findings: fixable `HIGH` and `CRITICAL` CVEs.
- Output: a separate, atomically replaced JSON report.

This is a policy scan rather than a complete inventory of all severities and
unfixed vulnerabilities.

## Scanner prerequisites

Run the scan as the same operating-system user that owns the Docker Scout
installation and registry credentials.

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

## Developer verification

The tests use a deterministic fake Docker/Scout executable and make no network
or Docker calls.

```bash
python3 -B -m unittest discover -s tests -v
bash -n get_info.sh res/*.sh setup/*.sh
```

Slice 1 is manual only. Do not add it to the existing five-minute health cron;
locked daily scheduling and stale-evidence handling belong to Slice 2.

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
*/5 * * * * /usr/local/bin/swarm-info --json --output-file /info_json/swarm_info.json
```

### Example – hourly at minute 59:
```bash
59 * * * * /usr/local/bin/swarm-info --json --output-file /info_json/swarm_info.json
```


