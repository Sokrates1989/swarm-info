#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Function to display service information.
display_short_info() {
    bash "$SCRIPT_DIR/res/short_info.sh"
}

# Function to display service node information (What service is running on which node).
display_node_info() {
    bash "$SCRIPT_DIR/res/node_info.sh"
}

# Local node info.
display_local_node_info() {
    bash "$SCRIPT_DIR/res/local_node_info.sh"
}

# Stack info.
display_stack_info() {
    bash "$SCRIPT_DIR/res/stack_info.sh"
}

# Network info.
display_network_info() {
    bash "$SCRIPT_DIR/res/network_info.sh"
}

# Helpful comamnds.
display_helpful_commands() {
    bash "$SCRIPT_DIR/res/helpful_commands.sh"
}

# Function to display and save system information as json.
CUSTOM_OUTPUT_FILE="NONE"
swarm_info_dir="$SCRIPT_DIR/swarm_info"
swarm_info_json_file="$swarm_info_dir/swarm_info.json"
swarm_info_json() {
    # Check if CUSTOM_OUTPUT_FILE is still in its default value
    if [ "$CUSTOM_OUTPUT_FILE" = "NONE" ]; then
        bash "$SCRIPT_DIR/res/json_info.sh" --json --output-file "$swarm_info_json_file"
    else
        bash "$SCRIPT_DIR/res/json_info.sh" --json --output-file "$CUSTOM_OUTPUT_FILE"
    fi
}

# Function to display help information.
display_help() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  -c             Display helpful commands"
    echo -e "  -f, --full     Display full system information"
    echo -e "  -h             Display this help message"
    echo -e "  --help         Display this help message"
    echo -e "  --json         Save and display info in json format"
    echo -e "  -l             Alias for --local"
    echo -e "  --local        Display local docker information (docker on this node)"
    echo -e "  -n             Alias for --node"
    echo -e "  --net          Display network info"
    echo -e "  --nodes        Display service node information (What service is running on which node)"
    echo -e "  -o             Alias for --output-file"
    echo -e "  --output-file  Where to save the swarm info output (only in combination with --json)"
    echo -e "  --stacks       Display stack information"
}


# Default values.
use_file_output="false"
file_output_type="json"

# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        -c)
            display_helpful_commands
            exit 0
            ;;
        -f)
            display_short_info
            exit 0
            ;;
        --full)
            display_short_info
            exit 0
            ;;
        -h)
            display_help
            exit 0
            ;;
        --help)
            display_help
            exit 0
            ;;
        --json)
            use_file_output="true"
            file_output_type="json"
            shift
            ;;
        -l)
            display_local_node_info
            exit 0
            ;;
        --local)
            display_local_node_info
            exit 0
            ;;
        -n)
            display_node_info
            exit 0
            ;;
        --net)
            display_network_info
            exit 0
            ;;
        --nodes)
            display_node_info
            exit 0
            ;;
        -o)
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        --output-file)
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        --stacks)
            display_stack_info
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
    # If no option is specified or an invalid option is provided, display short info.
    display_short_info
fi

