#!/bin/bash
# Run SCWP-01 producer and user-crontab checks on real Debian or Ubuntu.

set -u

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
acceptance_require_clean_checkout "$repository_root"
python_command=$(acceptance_python) \
    || acceptance_fail "Python 3.10+ is unavailable."

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/scwp-01-linux.XXXXXX") \
    || acceptance_fail "Cannot create the private acceptance directory."
trap 'rm -rf -- "$temporary_root"' EXIT HUP INT TERM
profile_file="$temporary_root/platform_info.json"
focus_file="$temporary_root/security_scan_focused.json"
report_file="${XDG_STATE_HOME:-${HOME}/.local/state}/swarm-info/security_scan-running.json"

"$repository_root/get_info.sh" --platform-info --json --os linux \
    --output-file "$profile_file" \
    || acceptance_fail "Standard-Linux platform detection failed."
acceptance_validate_profile standard-linux containers "$profile_file" "$python_command" \
    || acceptance_fail "Standard-Linux profile validation failed."
"$python_command" - "$profile_file" <<'PY' \
    || acceptance_fail "This entry point requires Debian or Ubuntu."
import json
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(payload.get("os", {}).get("id") not in {"debian", "ubuntu"})
PY
"$repository_root/get_info.sh" --check-dependencies \
    || acceptance_fail "Standard-Linux dependency preflight failed."

"$repository_root/get_info.sh" --security-check --container-scope running \
    --os linux --output-file "$report_file" \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Running-container scan failed."
focus_container=$(docker container ls --format '{{.Names}}' | sed -n '1p')
[ -n "$focus_container" ] || acceptance_fail "No running container is available."
"$repository_root/get_info.sh" --security-check --container "$focus_container" \
    --os linux --output-file "$focus_file" \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Focused standard-Linux scan failed."

"$repository_root/get_info.sh" --install-security-cron --os linux \
    --output-file "$report_file" \
    || acceptance_fail "User-crontab installation failed."
"$repository_root/get_info.sh" --security-status --os linux \
    --output-file "$report_file" \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Scheduled evidence status failed."
"$repository_root/get_info.sh" --remove-security-cron --os linux \
    || acceptance_fail "Managed user-crontab removal failed."
"$repository_root/get_info.sh" --install-security-cron --os linux \
    --output-file "$report_file" \
    || acceptance_fail "Managed user-crontab reinstall failed."

printf '[PASS] SCWP-01 standard-Linux pre-reboot checks passed\n'
