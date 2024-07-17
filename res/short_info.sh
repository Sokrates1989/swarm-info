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

# Function to print formatted output.
print_info() {
    while [ "$#" -gt 0 ]; do
        local text=$1
        local output_tab_space=$2
        printf "%-${output_tab_space}s" "$text"
        shift 2
        if [ "$#" -gt 0 ]; then
            printf " | "
        fi
    done
    echo ""  # Print a newline at the end
}

# Swarm Status
echo "Swarm Status:"
swarm_status=$(docker info --format '{{.Swarm.LocalNodeState}}')
printf "%-${output_tab_space}s: %s\n" "Swarm Status" "$swarm_status"
echo

# List of Nodes.

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

echo "List of Nodes in the Swarm:"
for node in $(docker node ls --format '{{.ID}}'); do
    node_name=$(docker node ls --filter id=$node --format 'Name: {{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_status=$(docker node ls --filter id=$node --format 'Status: {{.Status}}')
    node_avail=$(docker node ls --filter id=$node --format 'Availability: {{.Availability}}')
    node_manage_status=$(docker node ls --filter id=$node --format 'Manager Status: {{.ManagerStatus}}')
    print_info "$node_name" "$max_name_length" "$node_id" "$max_id_length" "$node_status" "$max_status_length" "$node_avail" "$max_avail_length" "$node_manage_status" "$max_manage_status_length" 
done
echo

# Detailed Node Information.
echo "Detailed Node Information:"
# for node in $(docker node ls --format '{{.ID}}'); do
#     node_detail=$(docker node inspect $node --format '{{json .}}')
#     print_info "Node ID" "$node"
#     echo "$node_detail" | python3 -m json.tool
#     echo
# done


# List of Services.
# Count chars of longest service name.
max_length=0
for service in $(docker service ls --format '{{.ID}}'); do
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    
    # Calculate the length of the service name.
    name_length=${#service_name}
    
    # Update the maximum length and longest name if necessary
    if (( name_length > max_length )); then
        max_length=$name_length
    fi
done
output_tab_space=$((max_length + 1))

echo "List of Services:"
for service in $(docker service ls --format '{{.ID}}'); do
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    service_info=$(docker service ls --filter id=$service --format 'ID: {{.ID}} | Mode: {{.Mode}} | Replicas: {{.Replicas}} | Image: {{.Image}}')
    print_info "$service_name" "$service_info"
done
echo

# Detailed Service Information
echo "Detailed Service Information:"
# for service in $(docker service ls --format '{{.ID}}'); do
#     service_detail=$(docker service inspect $service --format '{{json .}}')
#     print_info "Service ID" "$service"
#     echo "$service_detail" | python3 -m json.tool
#     echo
# done

# Task Details for Each Service
echo "Task Details for Each Service:"
for service in $(docker service ls --format '{{.ID}}'); do
    print_info "Service ID" "$service"
    docker service ps $service --format 'Task ID: {{.ID}} | Node: {{.Node}} | Desired State: {{.DesiredState}} | Current State: {{.CurrentState}} | Error: {{.Error}} | Ports: {{.Ports}}' | while read -r task_info; do
        print_info "Task" "$task_info"
    done
    echo
done

# Node Resource Usage
echo "Node Resource Usage:"
# for node in $(docker node ls --format '{{.Hostname}}'); do
#     print_info "Node" "$node"
#     resource_info=$(docker node inspect $node --format 'CPU: {{.Description.Resources.NanoCPUs}} | Memory: {{.Description.Resources.MemoryBytes}}')
#     print_info "Resources" "$resource_info"
#     echo
# done

# Running Containers on Each Node
echo "Running Containers on Each Node:"
for node in $(docker node ls --format '{{.Hostname}}'); do
    print_info "Node" "$node"
    docker node ps $node --filter "desired-state=running" --format 'Container ID: {{.ID}} | Image: {{.Image}} | Node: {{.Node}} | Status: {{.Status}}' | while read -r container_info; do
        print_info "Container" "$container_info"
    done
    echo
done

# List of Networks
echo "List of Networks:"
for network in $(docker network ls --format '{{.ID}}'); do
    network_info=$(docker network ls --filter id=$network --format 'ID: {{.ID}} | Name: {{.Name}} | Driver: {{.Driver}}')
    print_info "Network" "$network_info"
done
echo

# Detailed Network Information
echo "Detailed Network Information:"
# for network in $(docker network ls --format '{{.ID}}'); do
#     network_detail=$(docker network inspect $network --format '{{json .}}')
#     print_info "Network ID" "$network"
#     echo "$network_detail" | python3 -m json.tool
#     echo
# done

# List of Volumes
echo "List of Volumes:"
for volume in $(docker volume ls --format '{{.Name}}'); do
    volume_info=$(docker volume ls --filter name=$volume --format 'Name: {{.Name}} | Driver: {{.Driver}}')
    print_info "Volume" "$volume_info"
done
echo

# Detailed Volume Information
echo "Detailed Volume Information:"
# for volume in $(docker volume ls --format '{{.Name}}'); do
#     volume_detail=$(docker volume inspect $volume --format '{{json .}}')
#     print_info "Volume Name" "$volume"
#     echo "$volume_detail" | python3 -m json.tool
#     echo
# done


# Helpful commands.
echo
display_helpful_commands



# This tool's state.

# Save the current directory to be able to revert back again to it later.
current_dir=$(pwd)
# Change to the Git repository directory to make git commands work.
cd $MAIN_DIR

echo -e "Fetching state of swarm-info (this tool) ..."
repo_url=https://github.com/Sokrates1989/swarm-info.git
is_healthy=true
repo_issue=false
local_changes=false
available_updates=false

# Check remote connection.
if git ls-remote --exit-code "$repo_url" >/dev/null 2>&1; then

    # Check local changes.
    if [ -n "$(git status --porcelain)" ]; then
        local_changes=true
        is_healthy=false
    fi

    # Check for upstream changes.
    git fetch -q
    behind_count=$(git rev-list HEAD..origin/main --count)
    if [ "$behind_count" -gt 0 ]; then
        available_updates=true
        is_healthy=false
    fi
else
    is_healthy=false
    repo_issue=true
fi


if [ "$is_healthy" = true ]; then
    echo -e "This tool (swarm info) is healthy and up to date"
else
    # print detailed information.
    echo -e "This tool (swarm info) is NOT healthy:"
    
    if [ "$repo_issue" = true ]; then
        echo -e "Remote repository $repo_url is not accessible"
    else
        if [ "$local_changes" = true ]; then
            echo -e "Local repo has uncommitted changes"
        fi 

        if [ "$available_updates" = true ]; then
            echo -e "Remote Repo updateable! $behind_count commits behind. Pull is recommended."

            # Print user info how to update repo.
            echo -e "\nTo Update repo do this:"
            echo -e "cd $MAIN_DIR"
            echo -e "git pull\n"
            
        fi
    fi         
fi

# Revert back to the original directory.
cd "$current_dir"



# Spacer.
echo -e "\n"
echo -e "To view all available options use --help -> bash $MAIN_DIR/get_info.sh --help  "
echo -e ""


