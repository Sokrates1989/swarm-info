#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Function to display service information.
display_service_info() {
    bash "$SCRIPT_DIR/res/service_info.sh"
}

# Function to display and save system information as json.
CUSTOM_OUTPUT_FILE="NONE"
swarm_info_dir="$SCRIPT_DIR/swarm_info"
swarm_info_json_file="$swarm_info_dir/service_info.json"
service_info_json() {
    # Check if CUSTOM_OUTPUT_FILE is still in its default value
    if [ "$CUSTOM_OUTPUT_FILE" = "NONE" ]; then
        bash "$SCRIPT_DIR/res/service_info.sh" --json --output-file "$swarm_info_json_file"
    else
        bash "$SCRIPT_DIR/res/service_info.sh" --json --output-file "$CUSTOM_OUTPUT_FILE"
    fi
}

# Function to display help information.
display_help() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  -f, --full     Display full system information"
    echo -e "  -l             Alias for --full"
    echo -e "  -s             Display service information"
    echo -e "  --help         Display this help message"
    echo -e "  --json         Save and display info in json format"
    echo -e "  --output-file  Where to save the system info output (only in combination with --json)"
    echo -e "  -o             Alias for --output-file"
}


# Default values.
use_file_output="false"
file_output_type="json"

# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        -f)
            display_service_info
            exit 0
            ;;
        -l)
            display_service_info
            exit 0
            ;;
        -s)
            display_service_info
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
        --output-file)
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        -o)
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
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
        service_info_json
    else
        # If no option is specified or an invalid option is provided, display short info.
        echo -e "invalid file_output_type: $file_output_type"
    fi
else
    # If no option is specified or an invalid option is provided, display short info.
    display_service_info
fi

