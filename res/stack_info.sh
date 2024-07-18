#!/bin/bash

output_tab_space=28 # The space until the colon to align all output info to

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

## List of Stacks ##
echo "List of Stacks (docker stack ls):"
stacks_output=$(docker stack ls)
echo "$stacks_output"
echo
echo "Helpful commands:"
printf "%-${output_tab_space}s: %s\n" "Services of stack" "docker stack services <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove stack" "docker stack rm <STACKNAME>"
echo
echo

## Stacks and their services ##
echo "Stacks and their services (docker stack services <STACKNAME>):"
for stack in $(docker stack ls --format '{{.Name}}'); do
  echo "$stack"
  # Services of stack.
  stacks_output=$(docker stack services $stack)
  echo "$stacks_output"
  echo
done