#!/bin/bash

# Function to print formatted output.
print_info() {
    while [ "$#" -gt 0 ]; do
        local text=$1
        local output_tab_space=$2
        printf "%-${output_tab_space}s" "$text"
        shift 2
        if [ "$#" -gt 0 ]; then
            printf "  | "
        fi
    done
    echo ""  # Print a newline at the end
}


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

# # Service Node Count.
# declare -A node_service_count

# # Iterate through each service
# for service in $(docker service ls --format '{{.Name}}'); do
#   # Get running tasks for the service
#   for node in $(docker service ps $service --filter "desired-state=running" --format '{{.Node}}'); do
#     # Increment the count for the node
#     ((node_service_count[$node]++))
#   done
# done

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
echo "Number of running services per node:"
for node in "${!node_service_count[@]}"; do
    print_info "$node" "$max_name_length" "Running Services: ${node_service_count[$node]}" "25" 
done
echo
echo



# Print services grouped by node.
for node in "${!node_services[@]}"; do
    echo "Node: $node"
    echo "${node_services[$node]}" | sed '/^$/d'  # Remove empty lines
    echo
done



# Each Service on and their tasks and their nodes.
for service in $(docker service ls --format '{{.Name}}'); do
  service_id=$(docker service ls --filter "name=$service" --format '{{.ID}}')
  echo "Service: $service (ID: $service_id)"
  docker service ps $service --filter "desired-state=running" --format 'Task ID: {{.ID}} | Task Name: {{.Name}} | Node: {{.Node}} | Status: {{.CurrentState}}'
  echo
done



## Number of services on each node ##
echo "Number of running services per node:"
for node in "${!node_service_count[@]}"; do
    print_info "$node" "$max_name_length" "Running Services: ${node_service_count[$node]}" "25" 
done
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create <SECRETNAME> secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
printf "%-${output_tab_space}s: %s\n" "Inspect Secret" "docker secret inspect --pretty <SECRETNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Secret" "docker secret rm <SECRETNAME>"
echo
echo