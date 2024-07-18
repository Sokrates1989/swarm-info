#!/bin/bash

# The space until the colon to align all output info to.
output_tab_space=35 

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Helpful commands.
echo
echo "Troubleshooting:"
printf "%${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICE_NAME>"
echo "Enter container, if further information is needed:"
printf "%-${output_tab_space}s: %s\n" "Determine Node" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Enter node" "ssh into node (Putty or alike)"
printf "%-${output_tab_space}s: %s\n" "Get container ID" "docker ps"
printf "%-${output_tab_space}s: %s\n" "(Optional) Read container logs" "docker logs <CONTAINER_ID>"
printf "%-${output_tab_space}s: %s\n" "Enter container (shell)" "docker exec -it <CONTAINER_ID> /bin/sh"
printf "%-${output_tab_space}s: %s\n" "Enter container (bash)" "docker exec -it <CONTAINER_ID> /bin/bash"
echo
echo
