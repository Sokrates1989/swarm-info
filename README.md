# swarm-info
Quick info about swarm status and helpful commands collection

# Backlog
Stuff that just could not be finished in time:
 - Choosing quit in menus should always ultimately finish the program just like pressing CTRL+c would
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

# First Setup

### Quick Option 1 (few people are expected to log into server)
```bash
sudo mkdir -p /tools/swarm-info
cd /tools/swarm-info
sudo git clone https://github.com/Sokrates1989/swarm-info.git .
```

### Quick Option 2 (default location for administrative installations)
```bash
sudo mkdir -p /usr/local/swarm-info
cd /usr/local/swarm-info
sudo git clone https://github.com/Sokrates1989/swarm-info.git .
```

### Custom location
```bash
# Choose location on server (replace desired destintation with /desired/destination).
mkdir -p /desired/destination/swarm-info
cd /desired/destination/swarm-info
git clone https://github.com/Sokrates1989/swarm-info.git .
```


# Usage

### Quick Option 1
```bash
bash /tools/swarm-info/get_info.sh
```
### Quick Option 2
```bash
bash /usr/local/swarm-info/get_info.sh
```
### Custom dir 
```bash
bash /desired/destination/swarm-info/get_info.sh
```


# Output Files for messaging.
Also writes percentages of server usage into files so that they can be mapped into docker images. These files can be used to monitor the server state and send server state infos via Telegram, email or other messaging tools.

## Json

#### Default json output file
Writes output to path/to/swarm-info/service_info.json
```bash
bash /path/to/get_info.sh --json
```

#### Custom file
You can also provide a custom file where to write the json file to
```bash
# Ensure custom file exists.
mkdir -p /custom/path
touch /custom/path/file.json

# Command option short.
bash /path/to/get_info.sh --json -o /custom/path/file.json
# Command option long.
bash /path/to/get_info.sh --json --output-file /custom/path/file.json
```


### Cronjob
Setup cron to get periodic swarm info.

```bash
# Open crontab in edit mode.
crontab -e
```

```bash
# Execute command every hour at :59 min .
59 * * * * /bin/bash /path/to/get_info.sh --json --output-file /custom/path/file.json

# Second Example as used on prod servers.
59 * * * * /bin/bash /swarm-status/get_info.sh --json --output-file /info_json/service_info.json
```



