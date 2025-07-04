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

Also writes percentages of server usage into files so that they can be mapped into docker images. These files can be used to monitor the server state and send server state infos via Telegram, email or other messaging tools.

### 🔧 Default json output file
Writes output to path/to/swarm-info/service_info.json
```bash
swarm-info --json
```

### 📝 Custom file
You can also provide a custom file where to write the json file to
```bash
# Ensure custom file exists.
mkdir -p /custom/path
touch /custom/path/file.json

# Command option short.
swarm-info --json -o /custom/path/file.json
# Command option long.
swarm-info --json --output-file /custom/path/file.json
```

---

# ⏰ Automation via Cronjob

Setup cron to get periodic swarm info.

### Open crontab in edit mode:
```bash
crontab -e
```

### Example 1 – hourly at minute 59:
```bash
# Execute command every hour at :59 min .
59 * * * * /usr/local/bin/swarm-info --json --output-file /custom/path/file.json

# Second Example as used on prod servers.
59 * * * * /usr/local/bin/swarm-info --json --output-file /info_json/service_info.json
```



