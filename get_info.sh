#!/bin/bash

# Get the directory of the script, handling symlinks properly.
# 🔧 Robust: Resolve actual script directory, even if called via symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")/res" >/dev/null 2>&1 && pwd)"

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


# Function to display Basic swarm info.
show_basic_swarm_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/basic_swarm_info.sh" -m
    else
        bash "$SCRIPT_DIR/basic_swarm_info.sh"
    fi
}

# Function to display Node label info.
display_node_label_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/label_info.sh" -m
    else
        bash "$SCRIPT_DIR/label_info.sh"
    fi
}

# Function to display service node information (What service is running on which node).
display_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/node_info.sh" -m
    else
        bash "$SCRIPT_DIR/node_info.sh"
    fi
}

# Function to display Local node info.
display_local_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/local_node_info.sh" -m
    else
        bash "$SCRIPT_DIR/local_node_info.sh"
    fi
}

# Function to display Stack info.
display_stack_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_info.sh"
    fi
}

# Function to display services within stacks.
display_stack_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_services_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_services_info.sh"
    fi
}



# Function to display Network info.
display_network_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/network_info.sh" -m
    else
        bash "$SCRIPT_DIR/network_info.sh"
    fi
}

# Function to display Secrets info.
display_secrets_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/secrets_info.sh" -m
    else
        bash "$SCRIPT_DIR/secrets_info.sh"
    fi
}

# Function to display Services info.
display_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -m
    else
        bash "$SCRIPT_DIR/services_info.sh"
    fi
}

# Function to display Helpful commands.
display_helpful_commands() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/helpful_commands.sh" -m
    else
        bash "$SCRIPT_DIR/helpful_commands.sh"
    fi
}

# Function to check tool state.
check_tool_state() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/check_tool_state.sh" -m
    else
        bash "$SCRIPT_DIR/check_tool_state.sh"
    fi
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
    echo -e "  --output-file     Where to save the swarm info output (only in combination with --json)"
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
            shift
            CUSTOM_OUTPUT_FILE="$1"
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
