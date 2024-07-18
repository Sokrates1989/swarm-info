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
swarm_status=$(docker info --format '{{.Swarm.LocalNodeState}}')
printf "%-${output_tab_space}s: %s\n" "Swarm Status" "$swarm_status"
echo
echo



## List of Nodes ##
echo "List of Nodes in the Swarm (docker node ls):"
sleep 0.1 # Simulate calculation time to allow user to read previous output.
node_output=$(docker node ls)
echo "$node_output"
echo
echo


## Node-Lables ##
echo "Labels for each node (docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}'):"
sleep 1 # Simulate calculation time to allow user to read previous output.
# Count chars of longest values.
max_name_length=0
max_id_length=0
max_labels_length=0
for node in $(docker node ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_labels=$(docker node inspect --format 'Labels: {{.Spec.Labels}}' $node)
    
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
    node_labels=$(docker node inspect --format 'Labels: {{.Spec.Labels}}' $node)
    print_info "$node_name" "$max_name_length" "$node_id" "$max_id_length" "$node_labels" "$max_labels_length"
done
echo
echo "Helpful label commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Set label" "docker node update --label-add <KEY>=<VALUE> <NODE_ID>"
printf "%-${output_tab_space}s: %s\n" "Remove Label" "docker node update --label-rm <KEY> <NODE_ID>"
echo
echo

## Number of services on each node ##
echo "Number of running services per node:"
sleep 0.5 # Simulate calculation time to allow user to read previous output.

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
output_tab_space=18
printf "%-${output_tab_space}s: %s\n" "Command" "bash $MAIN_DIR/get_info.sh --nodes"
echo
echo



## List of Services ##
echo "List of Services (docker service ls):"
sleep 1 # Simulate calculation time to allow user to read previous output.
services_output=$(docker service ls)
echo "$services_output"
echo
echo "Helpful service commands:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICENAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Inspect service" "docker service inspect <SERVICENAME> --pretty"
printf "%-${output_tab_space}s: %s\n" "Remove service" "docker service rm <SERVICENAME>"
echo
echo



## List of Stacks ##
echo "List of Stacks (docker stack ls):"
sleep 2 # Simulate calculation time to allow user to read previous output.
stacks_output=$(docker stack ls)
echo "$stacks_output"
echo
echo "Helpful stack commands:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "More details" "bash $MAIN_DIR/get_info.sh --stack"
printf "%-${output_tab_space}s: %s\n" "Services of stack" "docker stack services <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove stack" "docker stack rm <STACKNAME>"
echo
echo



## List of Networks ##
echo "List of Networks (docker network ls):"
sleep 0.4 # Simulate calculation time to allow user to read previous output.
networks_output=$(docker network ls)
echo "$networks_output"
echo
echo "Helpful network commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Create Network" "docker network create --driver overlay --attachable <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Get Info" "docker network inspect <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Network" "docker network rm <NETWORKNAME>"
echo
echo




## List of Secrets ##
echo "List of Secrets (docker secret ls):"
sleep 0.3 # Simulate calculation time to allow user to read previous output.
secrets_output=$(docker secret ls)
echo "$secrets_output"
echo
echo "Helpful secret commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create <SECRETNAME> secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
printf "%-${output_tab_space}s: %s\n" "Inspect Secret" "docker secret inspect --pretty <SECRETNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Secret" "docker secret rm <SECRETNAME>"
echo
echo


# This tool's state.
check_state_of_tool


# This tool's options.
echo
echo
echo "This tool's options:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "Helpful swarm commands" "bash $MAIN_DIR/get_info.sh -c"
printf "%-${output_tab_space}s: %s\n" "Nodes info" "bash $MAIN_DIR/get_info.sh --nodes"
printf "%-${output_tab_space}s: %s\n" "Local docker info" "bash $MAIN_DIR/get_info.sh --local"
printf "%-${output_tab_space}s: %s\n" "Stacks info" "bash $MAIN_DIR/get_info.sh --stacks"
printf "%-${output_tab_space}s: %s\n" "All options" "bash $MAIN_DIR/get_info.sh --help"
echo


