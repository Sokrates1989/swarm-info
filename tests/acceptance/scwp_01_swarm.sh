#!/bin/bash
# Run the non-mutating SCWP-01 producer regression on a real Swarm manager.

set -u

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
acceptance_require_clean_checkout "$repository_root"
python_command=$(acceptance_python) \
    || acceptance_fail "Python 3.10+ is unavailable."
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/scwp-01-swarm.XXXXXX") \
    || acceptance_fail "Cannot create the private acceptance directory."
trap 'rm -rf -- "$temporary_root"' EXIT HUP INT TERM
profile_file="$temporary_root/platform_info.json"

"$repository_root/get_info.sh" --platform-info --json \
    --output-file "$profile_file" \
    || acceptance_fail "Swarm platform detection failed."
acceptance_validate_profile standard-linux swarm "$profile_file" "$python_command" \
    || acceptance_fail "Swarm platform profile validation failed."
"$repository_root/get_info.sh" --check-dependencies \
    || acceptance_fail "Swarm dependency preflight failed."
"$repository_root/get_info.sh" --service-health \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Service-health regression failed."
"$repository_root/get_info.sh" --vulnerability-status \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Vulnerability-status regression failed."

printf '[PASS] SCWP-01 Swarm producer regression passed\n'
