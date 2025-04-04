#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_type" = "part_of_whole_info_fast" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -t "$total_pages" -c "$current_page" -f
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



## Number of services on each node ##
echo
echo "-------------------------------------------------------------------------"
echo "Services (bash $MAIN_DIR/get_info.sh --services (--menu) )"
echo "-------------------------------------------------------------------------"
echo
echo
echo "Running services per node:"
echo "----------------------------------------------------------------------"

# Service Node Count.
declare -A node_service_count

# Iterate through each service.
for service in $(docker service ls --format '{{.Name}}'); do
  # Get running tasks for the service.
  for node in $(docker service ps $service --filter "desired-state=running" --format '{{.Node}}'); do
    # Increment the count for the node.
    ((node_service_count[$node]++))
  done
done

# Count chars of longest values.
max_name_length=0
for node in "${!node_service_count[@]}"; do

    # Get individual values to print out later.
    node_name=${node}
    
    # Calculate the length of these values.
    name_length=${#node_name}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
done

for node in "${!node_service_count[@]}"; do
    print_info "$node" "$max_name_length" "Running Services: ${node_service_count[$node]}" "25" 
done
echo



# Only display context info as text, if the context menu does not open.
if [[ "$output_type" != "single_with_menu" && "$output_type" != "part_of_whole_info_wait" ]]; then
  echo "Which services are running on which node?"
  output_tab_space=18
  printf "%-${output_tab_space}s: %s\n" "Command" "bash $MAIN_DIR/get_info.sh --node-services --menu"
  echo
  echo
fi




## List of Services ##
echo
echo "List of Services (docker service ls):"
echo "----------------------------------------------------------------------"
services_output=$(docker service ls)
echo "$services_output"
echo
echo "Helpful service commands:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICENAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Inspect service" "docker service inspect <SERVICENAME> --pretty"
printf "%-${output_tab_space}s: %s\n" "Remove service" "docker service rm <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Force Service Restart" "docker service update --force <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Scale service (1)" "docker service scale <SERVICENAME>=<AMOUNT_REPLICAS>"
printf "%-${output_tab_space}s: %s\n" "Scale service (2)" "docker service update --replicas=<AMOUNT_REPLICAS> <SERVICENAME>"
echo
echo



# Function to display context menu options.
show_context_menu_options() {
    echo
    echo "Need context information?"
    echo "----------------------------------------------------------------------"
    echo "1) Services across nodes      bash $MAIN_DIR/get_info.sh --node-services --menu"
    echo
    echo "m) Main menu                  bash $MAIN_DIR/get_info.sh --menu"
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
