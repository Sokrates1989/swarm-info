#!/bin/bash
# Run SCWP-01 producer checks on the intended real QNAP host.

set -u

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
acceptance_require_clean_checkout "$repository_root"
[ -f /etc/config/uLinux.conf ] \
    || acceptance_fail "This entry point requires a real QNAP host."

# shellcheck source=res/platforms/qnap.sh
source "$repository_root/res/platforms/qnap.sh"
python_command=$(acceptance_python || true)
if [ -z "$python_command" ]; then
    qnap_candidates=$(qnap_python_command_candidates)
    while IFS= read -r candidate; do
        if [ -x "$candidate" ]; then
            python_command=$candidate
            break
        fi
    done <<< "$qnap_candidates"
fi
[ -n "$python_command" ] || acceptance_fail "Python 3.10+ is unavailable."

temporary_root=$(mktemp -d "${TMPDIR:-$HOME/.cache}/scwp-01-qnap.XXXXXX") \
    || acceptance_fail "Cannot create the private acceptance directory."
trap 'rm -rf -- "$temporary_root"' EXIT HUP INT TERM
profile_file="$temporary_root/platform_info.json"
focus_file="$temporary_root/security_scan_focused.json"

"$repository_root/get_info.sh" --platform-info --json --os qnap \
    --output-file "$profile_file" \
    || acceptance_fail "QNAP platform detection failed."
acceptance_validate_profile qnap containers "$profile_file" "$python_command" \
    || acceptance_fail "QNAP platform profile validation failed."
"$repository_root/get_info.sh" --check-dependencies \
    || acceptance_fail "QNAP dependency preflight failed."

focus_container=$(docker container ls --format '{{.Names}}' | sed -n '1p')
[ -n "$focus_container" ] || acceptance_fail "No running container is available."
"$repository_root/get_info.sh" --security-check --container "$focus_container" \
    --os qnap --output-file "$focus_file" \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Focused QNAP scan failed."

SWARM_INFO_COMMAND="$repository_root/get_info.sh" \
    /bin/bash "$repository_root/tests/qnap_security_schedule_acceptance.sh" \
    || acceptance_fail "Persistent QNAP schedule acceptance failed."
"$repository_root/get_info.sh" --security-status --os qnap \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Scheduled QNAP evidence is unavailable."

printf '[PASS] SCWP-01 QNAP producer checks passed\n'
