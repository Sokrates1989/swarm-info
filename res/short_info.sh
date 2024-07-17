#!/bin/bash

# Output format like this:
# sampleText1               : sampleText2
# Can be achieved using this:
# printf '%-30s: %s\n' "sampleText1" "sampleText2"
# https://unix.stackexchange.com/questions/396223/bash-shell-script-output-alignment
output_tab_space=28 # The space until the colon to align all output info to
# printf "%-${output_tab_space}s: %s\n" "sampletext1" "sampleText2"


# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to display helpful commands.
display_helpful_commands() {
    bash "$SCRIPT_DIR/helpful_commands.sh"
}

# Check this tool's state.
check_state_of_tool() {
    bash "$SCRIPT_DIR/check_tool_state.sh"
}

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

# Swarm Status
echo
echo "Swarm Status:"
swarm_status=$(docker info --format '{{.Swarm.LocalNodeState}}')
printf "%-${output_tab_space}s: %s\n" "Swarm Status" "$swarm_status"
echo
echo



## List of Nodes ##
echo "List of Nodes in the Swarm:"

# Count chars of longest values.
max_name_length=0
max_id_length=0
max_status_length=0
max_avail_length=0
max_manage_status_length=0
for node in $(docker node ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    node_name=$(docker node ls --filter id=$node --format 'Name: {{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_status=$(docker node ls --filter id=$node --format 'Status: {{.Status}}')
    node_avail=$(docker node ls --filter id=$node --format 'Availability: {{.Availability}}')
    node_manage_status=$(docker node ls --filter id=$node --format 'Manager Status: {{.ManagerStatus}}')
    
    # Calculate the length of these values.
    name_length=${#node_name}
    id_length=${#node_id}
    status_length=${#node_status}
    avail_length=${#node_avail}
    manage_status_length=${#node_manage_status}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( status_length > max_status_length )); then
        max_status_length=$status_length
    fi
    if (( avail_length > max_avail_length )); then
        max_avail_length=$avail_length
    fi
    if (( manage_status_length > max_manage_status_length )); then
        max_manage_status_length=$manage_status_length
    fi
done

for node in $(docker node ls --format '{{.ID}}'); do
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_status=$(docker node ls --filter id=$node --format 'Status: {{.Status}}')
    node_avail=$(docker node ls --filter id=$node --format 'Availability: {{.Availability}}')
    node_manage_status=$(docker node ls --filter id=$node --format 'Manager Status: {{.ManagerStatus}}')
    print_info "$node_name" "$max_name_length" "$node_id" "$max_id_length" "$node_status" "$max_status_length" "$node_avail" "$max_avail_length" "$node_manage_status" "$max_manage_status_length" 
done
echo
echo


## Number of services on each node ##
echo "Number of running services per node:"

# Service Node Count.
declare -A node_service_count

# Iterate through each service.
for service in $(docker service ls --format '{{.Name}}'); do
  # Get running tasks for the service
  for node in $(docker service ps $service --filter "desired-state=running" --format '{{.Node}}'); do
    # Increment the count for the node
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
echo



## List of Services ##
echo "List of Services:"

# Count chars of longest values.
max_name_length=0
max_id_length=0
max_mode_length=0
max_replicas_length=0
max_image_length=0
for service in $(docker service ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    service_id=$(docker service ls --filter id=$service --format 'ID: {{.ID}}')
    service_mode=$(docker service ls --filter id=$service --format 'Mode: {{.Mode}}')
    service_replicas=$(docker service ls --filter id=$service --format 'Replicas: {{.Replicas}}')
    service_image=$(docker service ls --filter id=$service --format 'Image: {{.Image}}')
    
    # Calculate the length of these values.
    name_length=${#service_name}
    id_length=${#service_id}
    mode_length=${#service_mode}
    replicas_length=${#service_replicas}
    image_length=${#service_image}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( mode_length > max_mode_length )); then
        max_mode_length=$mode_length
    fi
    if (( replicas_length > max_replicas_length )); then
        max_replicas_length=$replicas_length
    fi
    if (( image_length > max_image_length )); then
        max_image_length=$image_length
    fi
done

for service in $(docker service ls --format '{{.ID}}'); do
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    service_id=$(docker service ls --filter id=$service --format 'ID: {{.ID}}')
    service_mode=$(docker service ls --filter id=$service --format 'Mode: {{.Mode}}')
    service_replicas=$(docker service ls --filter id=$service --format 'Replicas: {{.Replicas}}')
    service_image=$(docker service ls --filter id=$service --format 'Image: {{.Image}}')
    print_info "$service_name" "$max_name_length" "$service_id" "$max_id_length" "$service_mode" "$max_mode_length" "$service_replicas" "$max_replicas_length" "$service_image" "$max_image_length" 
done
echo
echo



## List of Networks ##
echo "List of Networks:"

# Count chars of longest values.
max_name_length=0
max_id_length=0
max_driver_length=0
for network in $(docker network ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    network_name=$(docker network ls --filter id=$network --format '{{.Name}} ')
    network_id=$(docker network ls --filter id=$network --format 'ID: {{.ID}}')
    network_driver=$(docker network ls --filter id=$network --format 'Driver: {{.Driver}}')

    # Calculate the length of these values.
    name_length=${#network_name}
    id_length=${#network_id}
    driver_length=${#network_driver}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( driver_length > max_driver_length )); then
        max_driver_length=$driver_length
    fi
done

for network in $(docker network ls --format '{{.ID}}'); do
    network_name=$(docker network ls --filter id=$network --format '{{.Name}} ')
    network_id=$(docker network ls --filter id=$network --format 'ID: {{.ID}}')
    network_driver=$(docker network ls --filter id=$network --format 'Driver: {{.Driver}}')
    print_info "$network_name" "$max_name_length" "$network_id" "$max_id_length" "$network_driver" "$max_driver_length"
done
echo
echo






## List of Volumes ##
echo "List of Secrets:"
secrets_output=$(docker secret ls)
echo "$secrets_output"
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create SECRETNAME secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
echo
echo



## List of Volumes ##
echo "List of Volumes:"

# Count chars of longest values.
max_name_length=0
max_driver_length=0
for volume in $(docker volume ls --format '{{.Name}}'); do

    # Get individual values to print out later.
    volume_name=$(docker volume ls --filter name=$volume --format '{{.Name}}')
    volume_driver=$(docker volume ls --filter name=$volume --format 'Driver: {{.Driver}}')

    # Calculate the length of these values.
    name_length=${#volume_name}
    driver_length=${#volume_driver}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( driver_length > max_driver_length )); then
        max_driver_length=$driver_length
    fi
done

for volume in $(docker volume ls --format '{{.Name}}'); do
    volume_name=$(docker volume ls --filter name=$volume --format '{{.Name}}')
    volume_driver=$(docker volume ls --filter name=$volume --format 'Driver: {{.Driver}}')
    print_info "$volume_name" "$max_name_length" "$volume_driver" "$max_driver_length"
done
echo
echo


# Helpful commands.
display_helpful_commands
echo
echo


# This tool's state.
check_state_of_tool


# Spacer.
echo -e "\n"
echo -e "To view all available options use --help -> bash $MAIN_DIR/get_info.sh --help  "
echo -e ""


