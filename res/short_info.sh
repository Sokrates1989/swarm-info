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
echo "List of Nodes in the Swarm (docker node ls):"
node_output=$(docker node ls)
echo "$node_output"
echo
echo


## Node-Lables ##
echo "Labels for each node (docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}'):"
# Count chars of longest values.
max_name_length=0
max_id_length=0
max_labels_length=0
for node in $(docker node ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_labels=$(docker node ls --filter id=$node --format 'Labels: {{.Spec.Labels}}')
    
    # Calculate the length of these values.
    name_length=${#node_name}
    id_length=${#node_id}
    labels_length=${#node_labels}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( labels_length > max_labels_length )); then
        max_labels_length=$labels_length
    fi
done

for node in $(docker node ls --format '{{.ID}}'); do
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_labels=$(docker node ls --filter id=$node --format 'Labels: {{.Spec.Labels}}')
    print_info "$node_name" "$max_name_length" "$node_id" "$max_id_length" "$node_labels" "$max_labels_length"
done
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Set label" "docker node update --label-add <KEY>=<VALUE> <NODE_ID>"
printf "%-${output_tab_space}s: %s\n" "´Remove Label" "docker node update --label-rm <KEY> <NODE_ID>"
echo
echo

## Number of services on each node ##
echo "Number of running services per node:"

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
echo "More details and tasks on each node:"
printf "%-${output_tab_space}s: %s\n" "Command" "bash $MAIN_DIR/get_info.sh --nodes"
echo
echo



## List of Services ##
echo "List of Services (docker service ls):"
services_output=$(docker service ls)
echo "$services_output"
echo
echo "Helpful commands:"
printf "%${output_tab_space}s  %s\n" "Get information" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%${output_tab_space}s  %s\n" "Read logs" "docker service logs <SERVICE_NAME>"
printf "%${output_tab_space}s  %s\n" "Inspect service" "docker service inspect <SERVICE_NAME> --pretty"
printf "%${output_tab_space}s  %s\n" "Remove service" "docker service rm <SERVICE_NAME>"
echo
echo



## List of Stacks ##
echo "List of Stacks (docker stack ls):"
stacks_output=$(docker stack ls)
echo "$stacks_output"
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "More details" "bash $MAIN_DIR/get_info.sh --stack"
printf "%-${output_tab_space}s: %s\n" "Services of stack" "docker stack services <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove stack" "docker stack rm <STACKNAME>"
echo
echo



## List of Networks ##
echo "List of Networks (docker network ls):"
networks_output=$(docker network ls)
echo "$networks_output"
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Create Network" "docker network create --driver overlay --attachable <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Get Info" "docker network inspect <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Network" "docker network rm <NETWORKNAME>"
echo
echo




## List of Secrets ##
echo "List of Secrets (docker secret ls):"
secrets_output=$(docker secret ls)
echo "$secrets_output"
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create <SECRETNAME> secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
printf "%-${output_tab_space}s: %s\n" "Inspect Secret" "docker secret inspect --pretty <SECRETNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Secret" "docker secret rm <SECRETNAME>"
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

    # Get the mountpoint of the volume.
    volume_mountpoint=$(docker volume inspect $volume_name --format '{{ .Mountpoint }}')
    # Check if the mountpoint was retrieved successfully.
    if [ -z "$volume_mountpoint" ]; then
        volume_disk_usage="UNKNOWN MOUNTPOINT"
    else
        # Get the disk usage of the volume.
        volume_disk_usage=$(du -sh $volume_mountpoint 2>/dev/null)
        # Check if the disk usage command succeeded.
        if [ $? -ne 0 ]; then
            volume_disk_usage="UNKNOWN DISK USAGE"
        fi
    fi

    print_info "$volume_name" "$max_name_length" "$volume_driver" "$max_driver_length" "$volume_disk_usage" "15"
done
echo
echo


# This tool's state.
check_state_of_tool


# This tool's options.
echo
echo
echo "This tool's options:"
printf "%-${output_tab_space}s: %s\n" "Swarm commands overview" "bash $MAIN_DIR/get_info.sh -c"
printf "%-${output_tab_space}s: %s\n" "Nodes info" "bash $MAIN_DIR/get_info.sh --nodes"
printf "%-${output_tab_space}s: %s\n" "Stacks info" "bash $MAIN_DIR/get_info.sh --stacks"
printf "%-${output_tab_space}s: %s\n" "All options" "bash $MAIN_DIR/get_info.sh --help"
echo


