#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_speed" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_speed" = "part_of_whole_info_fast" ]; then
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
echo "Number of running services per node:"
echo

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
echo "More details on nodes:"
output_tab_space=18
printf "%-${output_tab_space}s: %s\n" "Command" "bash $MAIN_DIR/get_info.sh --nodes --menu"
echo
echo




## List of Services ##
echo "List of Services (docker service ls):"
services_output=$(docker service ls)
echo "$services_output"
echo "Helpful service commands:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICENAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Inspect service" "docker service inspect <SERVICENAME> --pretty"
printf "%-${output_tab_space}s: %s\n" "Remove service" "docker service rm <SERVICENAME>"
echo
echo




# Go on after showing desired info based on output type.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
        wait_for_user
        display_menu
        ;;
    part_of_whole_info_wait)
        current_page=$((current_page + 1)) # Increment the current page.
        wait_for_user $current_page $total_pages # Show wait dialog.
        display_next_menu_item
        ;;
    part_of_whole_info_fast)
        display_next_menu_item
        ;;
esac
