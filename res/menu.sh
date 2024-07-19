#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Menu options.
show_menu_options() {
    echo "1) Display whole swarm info waiting for keypress after output"
    echo "2) Display whole swarm info at once"
    echo "3) Show menu with individual information options"
    echo "4) All options to call this script directly"
    echo "h) Help"
    echo "q) Quit"
}


# Function to display the main menu.
show_menu() {
    # Main loop
    while true; do
        show_menu_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input
        echo    # Add spacer for readibility

        case $choice in
            1)
                show_swarm_info_waiting
                echo
                break
                ;;
            2)
                show_swarm_info_fast
                echo
                break
                ;;
            3)
                show_individual_info_menu
                echo
                break
                ;;
            4)
                show_help
                echo
                break
                ;;
            h)
                show_help
                echo
                break
                ;;
            q)
                echo "Thanks for using swarm-info!"
                echo "Have a great day :)"
                echo
                break
                ;;
            *)
                echo "Invalid option, please try again."
                ;;
        esac
    done
}


# Function to show whole swarm info waiting fior user to press a button after outputs to improve readability.
show_swarm_info_waiting() {
    bash "$SCRIPT_DIR/get_info.sh" --wait
}

# Function to show whole swarm info all at once.
show_swarm_info_fast() {
    bash "$SCRIPT_DIR/get_info.sh" --fast
}

# Function to show help.
show_help() {
    bash "$SCRIPT_DIR/get_info.sh" --help
}



# Individual information options.
show_individual_info_options() {
    echo "1) Basic swarm info               (bash $SCRIPT_DIR/get_info.sh --basic)"
    echo "2) Services                       (bash $SCRIPT_DIR/get_info.sh --services)"
    echo "3) Stacks                         (bash $SCRIPT_DIR/get_info.sh --stacks)"
    echo "4) Node label info                (bash $SCRIPT_DIR/get_info.sh --labels)"
    echo "5) This local node                (bash $SCRIPT_DIR/get_info.sh --local)"
    echo "6) Networks                       (bash $SCRIPT_DIR/get_info.sh --network)"
    echo "7) Secrets                        (bash $SCRIPT_DIR/get_info.sh --secrets)"
    echo "8) Show helpful docker commands   (bash $SCRIPT_DIR/get_info.sh --commands)"
    echo "9) Check this tool's state        (bash $SCRIPT_DIR/get_info.sh --state)"
    echo "b) Back to main menu"
    echo "q) Quit"
}

# Function to display the individual option menu.
show_individual_info_menu() {
    # Main loop
    while true; do
        show_individual_info_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input
        echo    # Add spacer for readibility

        case $choice in
            1)
                show_basic_swarm_info
                echo
                break
                ;;
            2)
                show_services_info
                echo
                break
                ;;
            3)
                show_stacks_info
                echo
                break
                ;;
            4)
                show_node_label_info
                echo
                break
                ;;
            5)
                show_local_node_info
                echo
                break
                ;;
            6)
                show_network_info
                echo
                break
                ;;
            7)
                show_secrets_info
                echo
                break
                ;;
            8)
                show_helpful_docker_commands
                echo
                break
                ;;
            9)
                check_tool_state
                echo
                break
                ;;
            b)
                show_menu
                echo
                break
                ;;
            q)
                echo "Thanks for using swarm-info!"
                echo "Have a great day :)"
                echo
                break
                ;;
            *)
                echo "Invalid option, please try again."
                ;;
        esac
    done
}

# Function to show basic swarm info .
show_basic_swarm_info() {
    bash "$SCRIPT_DIR/get_info.sh" --basic
}

# Function to show services info.
show_services_info() {
    bash "$SCRIPT_DIR/get_info.sh" --services
}

# Function to show stacks info.
show_stacks_info() {
    bash "$SCRIPT_DIR/get_info.sh" --stacks
}

# Function to show node label info.
show_node_label_info() {
    bash "$SCRIPT_DIR/get_info.sh" --labels
}

# Function to show this local node info.
show_local_node_info() {
    bash "$SCRIPT_DIR/get_info.sh" --local
}

# Function to show network info.
show_network_info() {
    bash "$SCRIPT_DIR/get_info.sh" --network
}

# Function to show secrets info.
show_secrets_info() {
    bash "$SCRIPT_DIR/get_info.sh" --secrets
}

# Function to show helpful docker commands.
show_helpful_docker_commands() {
    bash "$SCRIPT_DIR/get_info.sh" --commands
}

# Function to check this tool's state.
check_tool_state() {
    bash "$SCRIPT_DIR/get_info.sh" --state
}


# Actually show menu with options.
show_menu
