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


