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
    local label=$1
    local value=$2
    printf "%-${output_tab_space}s: %s\n" "$label" "$value"
}


# Swarm Status
echo "Swarm Status:"
swarm_status=$(docker info --format '{{.Swarm.LocalNodeState}}')
print_info "Swarm Status" "$swarm_status"
echo

# List of Nodes
echo "List of Nodes in the Swarm:"
for node in $(docker node ls --format '{{.ID}}'); do
    node_info=$(docker node ls --filter id=$node --format 'ID: {{.ID}} | Hostname: {{.Hostname}} | Status: {{.Status}} | Availability: {{.Availability}} | Manager Status: {{.ManagerStatus}}')
    print_info "Node" "$node_info"
done
echo

# Detailed Node Information
echo "Detailed Node Information:"
for node in $(docker node ls --format '{{.ID}}'); do
    node_detail=$(docker node inspect $node --format '{{json .}}')
    print_info "Node ID" "$node"
    echo "$node_detail" | python3 -m json.tool
    echo
done

# List of Services
echo "List of Services:"
for service in $(docker service ls --format '{{.ID}}'); do
    service_info=$(docker service ls --filter id=$service --format 'ID: {{.ID}} | Name: {{.Name}} | Mode: {{.Mode}} | Replicas: {{.Replicas}} | Image: {{.Image}}')
    print_info "Service" "$service_info"
done
echo

# Detailed Service Information
echo "Detailed Service Information:"
for service in $(docker service ls --format '{{.ID}}'); do
    service_detail=$(docker service inspect $service --format '{{json .}}')
    print_info "Service ID" "$service"
    echo "$service_detail" | python3 -m json.tool
    echo
done

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
for node in $(docker node ls --format '{{.Hostname}}'); do
    print_info "Node" "$node"
    resource_info=$(docker node inspect $node --format 'CPU: {{.Description.Resources.NanoCPUs}} | Memory: {{.Description.Resources.MemoryBytes}}')
    print_info "Resources" "$resource_info"
    echo
done

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
for network in $(docker network ls --format '{{.ID}}'); do
    network_detail=$(docker network inspect $network --format '{{json .}}')
    print_info "Network ID" "$network"
    echo "$network_detail" | python3 -m json.tool
    echo
done

# List of Volumes
echo "List of Volumes:"
for volume in $(docker volume ls --format '{{.Name}}'); do
    volume_info=$(docker volume ls --filter name=$volume --format 'Name: {{.Name}} | Driver: {{.Driver}}')
    print_info "Volume" "$volume_info"
done
echo

# Detailed Volume Information
echo "Detailed Volume Information:"
for volume in $(docker volume ls --format '{{.Name}}'); do
    volume_detail=$(docker volume inspect $volume --format '{{json .}}')
    print_info "Volume Name" "$volume"
    echo "$volume_detail" | python3 -m json.tool
    echo
done


# Helpful commands.
echo
display_helpful_commands



# This tool's state.
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


