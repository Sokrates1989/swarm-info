#!/bin/bash

# Global functions.
source "$(dirname "$0")/functions.sh"

# Get the directory of the script, handling symlinks properly.
SCRIPT_DIR="$(get_script_dir)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Menu options.
show_menu_options() {
    echo "Main menu"
    echo "----------------------------------------------------------------------"
    echo "1) Display whole swarm info waiting for keypress after output"
    echo "2) Display whole swarm info at once"
    echo "3) Show menu with individual information options"
    echo "4) Show all options to call this script directly ( --help )"
    echo "5) List of helpful docker (swarm) commands ( --commands )"
    echo
    echo "s) Check this tool's state ( --state )"
    echo "h) Help"
    echo "q) Quit"
    echo
}


# Function to display the main menu.
show_menu() {
    # Flag to indicate, if a valid menu selection has been chosen by the user.
    valid_menu_selection_chosen=false

    # Get input from user until a valid selection has been chosen.
    while ! $valid_menu_selection_chosen; do
        show_menu_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input
        echo    # Add spacer for readibility
        
        # Indicate that a valid menu selection has been chosen, only reverse flag, if not.
        valid_menu_selection_chosen=true
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
            5)
                show_helpful_docker_commands
                echo
                break
                ;;
            s)
                check_tool_state
                echo
                break
                ;;
            h)
                show_help
                echo
                break
                ;;
            q)
                quit_script
                break
                ;;
            *)
                echo "Invalid option, please try again."
                valid_menu_selection_chosen=false
                ;;
        esac
    done
}


# Function to show all swarm info waiting for keypress.
show_swarm_info_waiting() {
    bash "$MAIN_DIR/get_info.sh" --wait
}

# Function to show all swarm info fast.
show_swarm_info_fast() {
    bash "$MAIN_DIR/get_info.sh" --fast
}

# Function to show help.
show_help() {
    bash "$MAIN_DIR/get_info.sh" --help
}

# Function to show helpful docker commands.
show_helpful_docker_commands() {
    bash "$MAIN_DIR/get_info.sh" --commands --menu
}

# Function to handle quitting the script.
quit_script() {
    echo "Thanks for using swarm-info!"
    echo "Have a great day :)"
    echo
}



# Individual information options.
show_individual_info_options() {
    echo "Individual information menu"
    echo "----------------------------------------------------------------------"
    echo "1) Basic swarm info               (swarm-info --basic (--menu) )"
    echo "2) Services                       (swarm-info --services (--menu) )"
    echo "3) Stacks                         (swarm-info --stacks (--menu) )"
    echo "4) Node Service info              (swarm-info --node-services (--menu) )"
    echo "5) Node label info                (swarm-info --labels (--menu) )"
    echo "6) This local node                (swarm-info --local (--menu) )"
    echo "7) Networks                       (swarm-info --network (--menu) )"
    echo "8) Secrets                        (swarm-info --secrets (--menu) )"
    echo "9) Show helpful docker commands   (swarm-info --commands (--menu) )"
    echo "0) Check this tool's state        (swarm-info --state (--menu) )"
    echo
    echo "b) Back to main menu"
    echo "q) Quit"
    echo
}

# Function to display the individual option menu.
show_individual_info_menu() {

    # Flag to indicate, if a valid menu selection has been chosen by the user.
    valid_menu_selection_chosen=false

    # Get input from user until a valid selection has been chosen.
    while ! $valid_menu_selection_chosen; do
        show_individual_info_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input
        echo    # Add spacer for readibility

        # Indicate that a valid menu selection has been chosen, only reverse flag, if not.
        valid_menu_selection_chosen=true
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
                show_nodes_info
                echo
                break
                ;;
            5)
                show_node_label_info
                echo
                break
                ;;
            6)
                show_local_node_info
                echo
                break
                ;;
            7)
                show_network_info
                echo
                break
                ;;
            8)
                show_secrets_info
                echo
                break
                ;;
            9)
                show_helpful_docker_commands
                echo
                break
                ;;
            0)
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
                quit_script
                break
                ;;
            *)
                echo "Invalid option, please try again."
                valid_menu_selection_chosen=false
                ;;
        esac
    done
}

# Function to show basic swarm info .
show_basic_swarm_info() {
    bash "$MAIN_DIR/get_info.sh" --basic --menu
}

# Function to show services info.
show_services_info() {
    bash "$MAIN_DIR/get_info.sh" --services --menu
}

# Function to show stacks info.
show_stacks_info() {
    bash "$MAIN_DIR/get_info.sh" --stacks --menu
}

# Function to show node label info.
show_nodes_info() {
    bash "$MAIN_DIR/get_info.sh" --node-services --menu
}

# Function to show node label info.
show_node_label_info() {
    bash "$MAIN_DIR/get_info.sh" --labels --menu
}

# Function to show local node info.
show_local_node_info() {
    bash "$MAIN_DIR/get_info.sh" --local --menu
}

# Function to show network info.
show_network_info() {
    bash "$MAIN_DIR/get_info.sh" --network --menu
}

# Function to show secrets info.
show_secrets_info() {
    bash "$MAIN_DIR/get_info.sh" --secrets --menu
}

# Function to show tool state.
show_tool_state() {
    bash "$MAIN_DIR/get_info.sh" --state --menu
}

# Function to show helpful docker commands.
show_helpful_docker_commands() {
    bash "$MAIN_DIR/get_info.sh" --commands --menu
}

# Function to check this tool's state.
check_tool_state() {
    bash "$MAIN_DIR/get_info.sh" --state --menu
}


# Actually show menu with options.
show_menu
