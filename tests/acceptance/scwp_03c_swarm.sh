#!/usr/bin/env bash
# Repeat the complete read-only Swarm regression after SCWP-03C producer changes.

set -Eeuo pipefail
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

printf '\n=== SCWP-03C Swarm regression delegates to the accepted SCWP-03B gate ===\n'
bash "$script_directory/scwp_03b_swarm.sh"

printf '\n============================================================\n'
printf '[PASS] SCWP-03C Ubuntu/Swarm regression passed\n'
printf '============================================================\n'
