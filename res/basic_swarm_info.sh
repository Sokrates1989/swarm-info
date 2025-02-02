#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_type" = "part_of_whole_info_fast" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -f
    fi 
}

# Parse command-line options.
total_pages=0
current_page=0
output_type="single_without_menu"
while getopts ":fwmt:c:" opt; do
  case $opt in
    f)
      output_type="part_of_whole_info_fast"
      ;;
    w)
      output_type="part_of_whole_info_wait"
      ;;
    m)
      output_type="single_with_menu"
      ;;
    t)
      total_pages=$OPTARG
      ;;
    c)
      current_page=$OPTARG
      ;;
    \?)
      echo -e "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo -e "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done


# Swarm Status
echo
echo
echo
echo "Basic Swarm information (bash $MAIN_DIR/get_info.sh --basic (--menu) ) "
echo
echo
swarm_status=$(docker info --format '{{.Swarm.LocalNodeState}}')
printf "%-${output_tab_space}s: %s\n" "Swarm Status" "$swarm_status"
echo
echo


## List of Nodes ##
echo "List of Nodes in the Swarm (docker node ls):"
echo
node_output=$(docker node ls)
echo "$node_output"
echo

# Only display context info as text, if the context menu does not open.
if [[ "$output_type" != "single_with_menu" && "$output_type" != "part_of_whole_info_wait" ]]; then
  echo "More details on nodes:"
  output_tab_space=20
  printf "%-${output_tab_space}s: %s\n" "Services" "bash $MAIN_DIR/get_info.sh --node-services --menu"
  printf "%-${output_tab_space}s: %s\n" "Labels" "bash $MAIN_DIR/get_info.sh --labels --menu"
  printf "%-${output_tab_space}s: %s\n" "This node" "bash $MAIN_DIR/get_info.sh --local --menu"
  echo
  echo
fi


# Function to display context menu options.
show_context_menu_options() {
    echo
    echo "Need context information?"
    echo "1) Services within nodes    bash $MAIN_DIR/get_info.sh --node-services --menu"
    echo "2) Labels                   bash $MAIN_DIR/get_info.sh --labels --menu"
    echo "3) This node                bash $MAIN_DIR/get_info.sh --local --menu"
    echo
    echo "m) Main menu                bash $MAIN_DIR/get_info.sh --menu"
    echo

    # Determine any other key button text.
    if [ "$output_type" = "part_of_whole_info_wait" ]; then
        current_page=$((current_page + 1)) # Increment the current page.
        echo "*) Press any other key to proceed... ($current_page/$total_pages)"
    else
        echo "*) Press any other key to proceed..."
    fi
    echo
}

# Function to display the menu.
show_context_menu() {
    # Flag to indicate, if a valid menu selection has been chosen by the user.
    valid_menu_selection_chosen=false

    # Get input from user until a valid selection has been chosen.
    while ! $valid_menu_selection_chosen; do
        show_context_menu_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input
        echo    # Add spacer for readability

        
        # Indicate that a valid menu selection has been chosen, only reverse flag, if not.
        valid_menu_selection_chosen=true
        case $choice in
            1)
                show_services
                ;;
            2)
                show_labels
                ;;
            3)
                show_this_node
                ;;
            m)
                show_main_menu
                ;;
            *)
                proceed_with_main_task
                break
                ;;
        esac
    done
}

# Function to show services.
show_services() {
    bash "$MAIN_DIR/get_info.sh" --node-services --menu
}

# Function to show labels.
show_labels() {
    bash "$MAIN_DIR/get_info.sh" --labels --menu
}

# Function to show this node.
show_this_node() {
    bash "$MAIN_DIR/get_info.sh" --local --menu
}

# Function to show main menu.
show_main_menu() {
    bash "$MAIN_DIR/get_info.sh" --menu
}


# Function to proceed with after showing desired info based on output type.
proceed_with_main_task() {
    case $output_type in
        single_without_menu)
            : # No operation
            ;;
        single_with_menu)
            display_menu
            ;;
        part_of_whole_info_wait)
            display_next_menu_item
            ;;
        part_of_whole_info_fast)
            display_next_menu_item
            ;;
    esac
}

# Determine menu display.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
        show_context_menu
        ;;
    part_of_whole_info_wait)
        show_context_menu
        ;;
    part_of_whole_info_fast)
        display_next_menu_item
        ;;
esac
