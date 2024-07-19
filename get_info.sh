#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")/res" && pwd)"

# Global functions.
source "$SCRIPT_DIR/functions.sh"

# Define the number of pages when showing all information.
total_pages=7

# Function to display all swarm information quickly.
display_all_swarm_info_fast() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -f
}

# Display all swarm information waiting for keypress.
display_all_swarm_info_waiting() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -w
}

# Function to display service node information (What service is running on which node).
display_node_info() {
    bash "$SCRIPT_DIR/node_info.sh"
}

# Basic swarm info.
show_basic_swarm_info() {
    bash "$SCRIPT_DIR/basic_swarm_info.sh"
}

# Local node info.
display_local_node_info() {
    bash "$SCRIPT_DIR/local_node_info.sh"
}

# Stack info.
display_stack_info() {
    bash "$SCRIPT_DIR/stack_info.sh"
}

# Network info.
display_network_info() {
    bash "$SCRIPT_DIR/network_info.sh"
}

# Secrets info.
display_secrets_info() {
    bash "$SCRIPT_DIR/secrets_info.sh"
}

# Services info.
display_services_info() {
    bash "$SCRIPT_DIR/services_info.sh"
}

# Node label info.
display_node_label_info() {
    bash "$SCRIPT_DIR/label_info.sh"
}

# Helpful commands.
display_helpful_commands() {
    bash "$SCRIPT_DIR/helpful_commands.sh"
}

# Function to check tool state.
check_tool_state() {
    bash "$SCRIPT_DIR/check_tool_state.sh"
}

# Function to display and save system information as json.
CUSTOM_OUTPUT_FILE="NONE"
swarm_info_dir="$SCRIPT_DIR/swarm_info"
swarm_info_json_file="$swarm_info_dir/swarm_info.json"
swarm_info_json() {
    # Check if CUSTOM_OUTPUT_FILE is still in its default value
    if [ "$CUSTOM_OUTPUT_FILE" = "NONE" ]; then
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$swarm_info_json_file"
    else
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$CUSTOM_OUTPUT_FILE"
    fi
}

# Function to display help information.
display_help() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  -b             Alias for --basic"
    echo -e "  --basic        Basic swarm info"
    echo -e "  -c             Alias for --commands"
    echo -e "  --commands     Display helpful commands"
    echo -e "  -f             Alias for --fast"
    echo -e "  --fast         Do not wait for keypress and display all information"
    echo -e "  -h             Alias for --help"
    echo -e "  --help         Display this help message"
    echo -e "  --json         Save and display info in json format"
    echo -e "  --local        Display local docker information (docker on this node)"
    echo -e "  --labels       Display Node label info (What labels are set to each node)"
    echo -e "  --net          Display network info"
    echo -e "  --network      Display network info"
    echo -e "  --nodes        Display service node information (What service is running on which node)"
    echo -e "  -o             Alias for --output-file"
    echo -e "  --output-file  Where to save the swarm info output (only in combination with --json)"
    echo -e "  --secrets      Display infos for secrets"
    echo -e "  --services     Display services information"
    echo -e "  --stacks       Display stack information"
    echo -e "  --state        Check this tool's state"
    echo -e "  -w             Alias for --wait"
    echo -e "  --wait         Show swarm info and wait after outputs to make it easier to read"

    echo
    wait_for_user
    display_menu
}


# Default values.
use_file_output="false"
file_output_type="json"

# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        -b|--basic)
            show_basic_swarm_info
            exit 0
            ;;
        -c|--commands)
            display_helpful_commands
            exit 0
            ;;
        -f|--fast)
            display_all_swarm_info_fast
            exit 0
            ;;
        -h|--help)
            display_help
            exit 0
            ;;
        --json)
            use_file_output="true"
            file_output_type="json"
            shift
            ;;
        --local)
            display_local_node_info
            exit 0
            ;;
        --labels)
            display_node_label_info
            exit 0
            ;;
        --net|--network)
            display_network_info
            exit 0
            ;;
        --nodes)
            display_node_info
            exit 0
            ;;
        -o|--output-file)
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        --secrets)
            display_secrets_info
            exit 0
            ;;
        --services)
            display_services_info
            exit 0
            ;;
        --stacks)
            display_stack_info
            exit 0
            ;;
        --state)
            check_tool_state
            exit 0
            ;;
        -w|--wait)
            display_all_swarm_info_waiting
            exit 0
            ;;
        *)
            echo -e "Invalid option: $1" >&2
            exit 1
            ;;
    esac
done

# Use file output?
if [ "$use_file_output" = "true" ]; then
    if [ "$file_output_type" = "json" ]; then
        swarm_info_json
    else
        # File output type is invalid.
        echo -e "invalid file_output_type: $file_output_type"
    fi
else
    # If no option is specified or an invalid option is provided, display menu.
    display_menu
fi
