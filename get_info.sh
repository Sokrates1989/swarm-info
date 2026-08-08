#!/bin/bash

# =============================================================================
# Module: get_info.sh
#
# Description:
#     Main command dispatcher for Docker Swarm status, inventory, diagnostics,
#     JSON health collection, and manual image vulnerability scanning.
#
# Dependencies:
#     - Bash 4+
#     - Docker CLI
#     - Python 3 and Docker Scout for --scan-vulnerabilities
# =============================================================================

# Get the directory of the script, handling symlinks properly.
# 🔧 Robust: Resolve actual script directory, even if called via symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")/res" >/dev/null 2>&1 && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

# Global functions.
source "$SCRIPT_DIR/functions.sh"

# Define the number of pages when showing all information.
total_pages=6
# Current pages belonging to info tour (in order of appearance).
# basic_swarm_info.sh.
# services_info.sh.
# stack_info.
# network_info.sh.
# secrets_info.sh.
# check_tool_state.sh.


# -----------------------------------------------------------------------------
# Display the full Swarm information tour without waiting between pages.
#
# Returns:
#     Exit status from the delegated basic information script.
# -----------------------------------------------------------------------------
display_all_swarm_info_fast() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -f
}

# -----------------------------------------------------------------------------
# Display the full Swarm information tour with interactive page waits.
#
# Returns:
#     Exit status from the delegated basic information script.
# -----------------------------------------------------------------------------
display_all_swarm_info_waiting() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -w
}


# -----------------------------------------------------------------------------
# Display basic Swarm information and optionally reopen its menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the basic information script.
# -----------------------------------------------------------------------------
show_basic_swarm_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/basic_swarm_info.sh" -m
    else
        bash "$SCRIPT_DIR/basic_swarm_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display manager-visible node labels and optionally reopen the menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the label information script.
# -----------------------------------------------------------------------------
display_node_label_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/label_info.sh" -m
    else
        bash "$SCRIPT_DIR/label_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display which Swarm services run on each node.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the node information script.
# -----------------------------------------------------------------------------
display_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/node_info.sh" -m
    else
        bash "$SCRIPT_DIR/node_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Docker resources belonging to the current local node.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the local-node information script.
# -----------------------------------------------------------------------------
display_local_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/local_node_info.sh" -m
    else
        bash "$SCRIPT_DIR/local_node_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Docker stack inventory and optionally reopen the stack menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the stack information script.
# -----------------------------------------------------------------------------
display_stack_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display services grouped by their Docker stack.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the stack-service information script.
# -----------------------------------------------------------------------------
display_stack_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_services_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_services_info.sh"
    fi
}
# -----------------------------------------------------------------------------
# Display Swarm network inventory and optionally reopen the network menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the network information script.
# -----------------------------------------------------------------------------
display_network_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/network_info.sh" -m
    else
        bash "$SCRIPT_DIR/network_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Swarm secret metadata without exposing secret values.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the secrets information script.
# -----------------------------------------------------------------------------
display_secrets_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/secrets_info.sh" -m
    else
        bash "$SCRIPT_DIR/secrets_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Swarm service inventory and optionally reopen the service menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the service information script.
# -----------------------------------------------------------------------------
display_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -m
    else
        bash "$SCRIPT_DIR/services_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display the curated Docker and Swarm command reference.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the helpful-commands script.
# -----------------------------------------------------------------------------
display_helpful_commands() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/helpful_commands.sh" -m
    else
        bash "$SCRIPT_DIR/helpful_commands.sh"
    fi
}

# -----------------------------------------------------------------------------
# Check whether the local swarm-info checkout is current and modified.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the tool-state script.
# -----------------------------------------------------------------------------
check_tool_state() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/check_tool_state.sh" -m
    else
        bash "$SCRIPT_DIR/check_tool_state.sh"
    fi
}

#
# Health-report output configuration.
# A caller-provided destination replaces the repository-local default.
#
CUSTOM_OUTPUT_FILE="NONE"
swarm_info_dir="$SCRIPT_DIR/swarm_info"
swarm_info_json_file="$swarm_info_dir/swarm_info.json"

# -----------------------------------------------------------------------------
# Collect Swarm health information and publish it as JSON.
#
# Global state:
#     CUSTOM_OUTPUT_FILE selects a custom destination when it is not `NONE`.
#     swarm_info_json_file supplies the repository-local default destination.
#
# Returns:
#     Exit status from the JSON collection script.
# -----------------------------------------------------------------------------
swarm_info_json() {
    # Use the repository-local destination when no override was provided.
    if [ "$CUSTOM_OUTPUT_FILE" = "NONE" ]; then
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$swarm_info_json_file"
    else
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$CUSTOM_OUTPUT_FILE"
    fi
}

# -----------------------------------------------------------------------------
# Scan all current Swarm service images for fixable HIGH/CRITICAL CVEs.
#
# The scanner runs as a Python module from the repository root so its internal
# package imports remain stable when this entry point is called through a
# symlink. A custom output path and platform are forwarded when configured.
#
# Global state:
#     VULNERABILITY_PLATFORM selects the requested Docker platform.
#     CUSTOM_OUTPUT_FILE optionally selects the report destination.
#
# Returns:
#     0 when the complete scan is clean.
#     2 when the complete scan contains policy findings.
#     3 when inventory, scanning, or report publication is incomplete.
#
# Side effects:
#     Runs Docker Scout through Python and atomically publishes a JSON report.
# -----------------------------------------------------------------------------
scan_service_image_vulnerabilities() {
    local python_command=""
    local scanner_arguments=(
        -m scripts.vulnerability_scan
        --platform "$VULNERABILITY_PLATFORM"
    )

    if command -v python3 >/dev/null 2>&1; then
        python_command="python3"
    elif command -v python >/dev/null 2>&1; then
        python_command="python"
    else
        echo "[ERROR] Python 3 is required for vulnerability scanning." >&2
        return 3
    fi

    if [ "$CUSTOM_OUTPUT_FILE" != "NONE" ]; then
        scanner_arguments+=(--output-file "$CUSTOM_OUTPUT_FILE")
    fi

    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${scanner_arguments[@]}"
    )
}

# -----------------------------------------------------------------------------
# Display command-line help, wait for acknowledgement, and reopen the menu.
#
# Returns:
#     Exit status from the menu dispatcher after the user acknowledges help.
#
# Side effects:
#     Writes usage text and waits for terminal input.
# -----------------------------------------------------------------------------
display_help() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  -b                Alias for --basic"
    echo -e "  --basic           Basic swarm info"
    echo -e "  -c                Alias for --commands"
    echo -e "  --commands        Display helpful commands"
    echo -e "  -f                Alias for --fast"
    echo -e "  --fast            Do not wait for keypress and display all information"
    echo -e "  -h                Alias for --help"
    echo -e "  --help            Display this help message"
    echo -e "  --json            Save and display info in json format"
    echo -e "  --local           Display local docker information (docker on this node)"
    echo -e "  --labels          Display Node label info (What labels are set to each node)"
    echo -e "  -m                Alias for --menu"
    echo -e "  --menu            Show menu (after displaying info, if used in combination with any single information option)"
    echo -e "  --net             Display network info"
    echo -e "  --network         Display network info"
    echo -e "  --node-services   Display service node information (What service is running on which node)"
    echo -e "  -o                Alias for --output-file"
    echo -e "  --output-file     JSON destination for --json or --scan-vulnerabilities"
    echo -e "  --platform        Image platform for vulnerability scanning (default: linux/amd64)"
    echo -e "  --scan-vulnerabilities"
    echo -e "                    Scan every Swarm service image with Docker Scout"
    echo -e "  --secrets         Display infos for secrets"
    echo -e "  --services        Display services information"
    echo -e "  --stacks          Display stack information"
    echo -e "  --stack-services  Display services within stacks"
    echo -e "  --state           Check this tool's state"
    echo -e "  -w                Alias for --wait"
    echo -e "  --wait            Show swarm info and wait after outputs to make it easier to read"

    echo
    wait_for_user
    display_menu
}


# Default values for the selected action.
selected_action="none"
is_show_menu_option_selected="false"
use_file_output="false"
file_output_type="json"
VULNERABILITY_PLATFORM="linux/amd64"

# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        -b|--basic)
            selected_action="basic"
            shift
            ;;
        -c|--commands)
            selected_action="commands"
            shift
            ;;
        -f|--fast)
            selected_action="fast"
            shift
            ;;
        -h|--help)
            selected_action="help"
            shift
            ;;
        --json)
            use_file_output="true"
            file_output_type="json"
            shift
            ;;
        --local)
            selected_action="local"
            shift
            ;;
        --labels)
            selected_action="labels"
            shift
            ;;
        -m|--menu)
            is_show_menu_option_selected="true"
            shift
            ;;
        --net|--network)
            selected_action="network"
            shift
            ;;
        --node-services)
            selected_action="nodes"
            shift
            ;;
        -o|--output-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        --platform)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_PLATFORM="$1"
            shift
            ;;
        --scan-vulnerabilities)
            selected_action="scan-vulnerabilities"
            shift
            ;;
        --secrets)
            selected_action="secrets"
            shift
            ;;
        --services)
            selected_action="services"
            shift
            ;;
        --stacks)
            selected_action="stacks"
            shift
            ;;
        --stack-services)
            selected_action="stack-services"
            shift
            ;;
        --state)
            selected_action="state"
            shift
            ;;
        -w|--wait)
            selected_action="wait"
            shift
            ;;
        *)
            echo -e "Invalid option: $1" >&2
            exit 1
            ;;
    esac
done

# Execute the selected action
case "$selected_action" in
    "basic")
        show_basic_swarm_info
        ;;
    "commands")
        display_helpful_commands
        ;;
    "fast")
        display_all_swarm_info_fast
        ;;
    "help")
        display_help
        ;;
    "local")
        display_local_node_info
        ;;
    "labels")
        display_node_label_info
        ;;
    "network")
        display_network_info
        ;;
    "nodes")
        display_node_info
        ;;
    "secrets")
        display_secrets_info
        ;;
    "services")
        display_services_info
        ;;
    "stacks")
        display_stack_info
        ;;
    "stack-services")
        display_stack_services_info
        ;;
    "state")
        check_tool_state
        ;;
    "scan-vulnerabilities")
        scan_service_image_vulnerabilities
        ;;
    "wait")
        display_all_swarm_info_waiting
        ;;
    *)
        if [ "$use_file_output" = "true" ]; then
            if [ "$file_output_type" = "json" ]; then
                swarm_info_json
            else
                # File output type is invalid.
                echo -e "invalid file_output_type: $file_output_type"
            fi
        else
            # If no option is specified or an invalid option is provided, display menu or start tour.
            if [ "$is_show_menu_option_selected" = "true" ]; then
                display_menu
            else
                display_all_swarm_info_waiting
            fi
        fi
        ;;
esac
