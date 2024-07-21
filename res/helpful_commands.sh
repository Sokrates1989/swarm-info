#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# The space until the colon to align all output info to.
output_tab_space=35 

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

# Helpful commands.
echo
echo "Helpful docker commands"
echo
echo
echo "Troubleshooting"
echo
printf "%-${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICE_NAME>"
echo 
echo "Enter container, if further information is needed"
printf "%-${output_tab_space}s: %s\n" "Determine Node" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Enter node" "ssh into node (Putty or alike)"
printf "%-${output_tab_space}s: %s\n" "Get container ID" "docker ps"
printf "%-${output_tab_space}s: %s\n" "(Optional) Read container logs" "docker logs <CONTAINER_ID>"
printf "%-${output_tab_space}s: %s\n" "Enter container (shell)" "docker exec -it <CONTAINER_ID> /bin/sh"
printf "%-${output_tab_space}s: %s\n" "Enter container (bash)" "docker exec -it <CONTAINER_ID> /bin/bash"
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
esac

