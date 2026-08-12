#!/bin/bash

# Display cached or live service-health evidence with optional navigation.

source "$(dirname "$0")/functions.sh"

SCRIPT_DIR="$(get_script_dir)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CUSTOM_OUTPUT_FILE="NONE"
VULNERABILITY_MAX_AGE_HOURS="30"

source "$SCRIPT_DIR/vulnerability_cli.sh"
source "$SCRIPT_DIR/operator_cli.sh"

show_menu="false"
while getopts ":mo:" option; do
    case "$option" in
        m) show_menu="true" ;;
        o) CUSTOM_OUTPUT_FILE="$OPTARG" ;;
        :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 1 ;;
        \?) printf 'Invalid option: -%s\n' "$OPTARG" >&2; exit 1 ;;
    esac
done

display_service_health_guidance
health_status=$?

if [ "$show_menu" = "true" ]; then
    echo
    echo "$OP_CONTEXT_HEADING"
    echo "----------------------------------------------------------------------"
    echo "1) $OP_SERVICE_LIST       swarm-info --services --menu"
    echo "v) $OP_VULNERABILITIES   swarm-info -v --menu"
    echo "m) $OP_MAIN_MENU         swarm-info --menu"
    echo
    read -r -n 1 -p "$OP_PROMPT" choice
    echo
    case "$choice" in
        1) bash "$MAIN_DIR/get_info.sh" --services --menu ;;
        v) bash "$MAIN_DIR/get_info.sh" -v --menu ;;
        m) bash "$MAIN_DIR/get_info.sh" --menu ;;
        *) : ;;
    esac
fi

exit "$health_status"
