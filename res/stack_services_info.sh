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
echo "Stacks and their services (swarm-info --stack-services (--menu) )"
echo "-------------------------------------------------------------------------"
echo
echo



## Stacks and their services ##
echo "Stacks and their services (docker stack services <STACKNAME>):"
echo "----------------------------------------------------------------------"
for stack in $(docker stack ls --format '{{.Name}}'); do
  echo "$stack"
  # Services of stack.
  stacks_output=$(docker stack services $stack)
  echo "$stacks_output"
  echo
done
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
