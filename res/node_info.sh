#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# The space until the colon to align all output info to.
output_tab_space=28 

# Global functions.
source "$SCRIPT_DIR/functions.sh"

# Parse command-line options.
output_type="single_without_menu"
while getopts ":m" opt; do
  case $opt in
    m)
      output_type="single_with_menu"
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



# Print info about this menu item and how to navigate here.
echo
echo "-------------------------------------------------------------------------"
echo "On what nodes are running which services?  (bash $MAIN_DIR/get_info.sh --node-services (--menu) )"
echo "-------------------------------------------------------------------------"
echo
echo


# Service Node Count and Node Services.
declare -A node_service_count
declare -A node_services

# Iterate through each service
for service in $(docker service ls --format '{{.Name}}'); do
  # Get running tasks for the service
  while read -r node; do
    # Increment the count for the node
    ((node_service_count[$node]++))

    # Add service to the node_services array
    node_services[$node]+="$service"$'\n'
  done < <(docker service ps $service --filter "desired-state=running" --format '{{.Node}}')
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




## Number of services on each node ##
echo
echo
echo "Number of running services per node:"
echo "----------------------------------------------------------------------"
for node in "${!node_service_count[@]}"; do
    print_info "$node" "$max_name_length" "Running Services: ${node_service_count[$node]}" "25" 
done
echo
echo



# Each Service on and their tasks and their nodes.
echo
echo
echo "Services and their tasks"
echo "----------------------------------------------------------------------"
for service in $(docker service ls --format '{{.Name}}'); do
  service_id=$(docker service ls --filter "name=$service" --format '{{.ID}}')
  echo "Service: $service (ID: $service_id)"
  docker service ps $service --filter "desired-state=running" --format 'Task ID: {{.ID}} | Task Name: {{.Name}} | Node: {{.Node}} | Status: {{.CurrentState}}'
  echo
done



# Print services grouped by node.
echo
echo
echo "Nodes and the services running on them"
echo "----------------------------------------------------------------------"
for node in "${!node_services[@]}"; do
    echo "Node: $node"
    echo "${node_services[$node]}" | sed '/^$/d'  # Remove empty lines
    echo
done



## Number of services on each node ##
echo
echo
echo "Number of running services per node:"
echo "----------------------------------------------------------------------"
for node in "${!node_service_count[@]}"; do
    print_info "$node" "$max_name_length" "Running Services: ${node_service_count[$node]}" "25" 
done
echo
echo
echo "More details on nodes:"
echo "----------------------------------------------------------------------"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Labels" "bash $MAIN_DIR/get_info.sh --labels --menu"
printf "%-${output_tab_space}s: %s\n" "This node" "bash $MAIN_DIR/get_info.sh --local --menu"
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
esac