#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_speed" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/network_info.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_speed" = "part_of_whole_info_fast" ]; then
        bash "$SCRIPT_DIR/network_info.sh" -t "$total_pages" -c "$current_page" -f
    fi 
}

# Parse command-line options.
total_pages=0
current_page=0
output_type="single_without_menu"
while getopts ":fwmt:c:" opt; do
  case $opt in
    f)
      output_type="part_of_whole_info_fast"
      ;;
    w)
      output_type="part_of_whole_info_wait"
      ;;
    m)
      output_type="single_with_menu"
      ;;
    t)
      total_pages=$OPTARG
      ;;
    c)
      current_page=$OPTARG
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




## List of Stacks ##
echo "List of Stacks (docker stack ls):"
echo
stacks_output=$(docker stack ls)
echo "$stacks_output"
echo
echo "Helpful stack commands:"
output_tab_space=25
printf "%-${output_tab_space}s: %s\n" "Services of stack" "docker stack services <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove stack" "docker stack rm <STACKNAME>"
echo
echo



## Stacks and their services ##
echo "Stacks and their services (docker stack services <STACKNAME>):"
echo
for stack in $(docker stack ls --format '{{.Name}}'); do
  echo "$stack"
  # Services of stack.
  stacks_output=$(docker stack services $stack)
  echo "$stacks_output"
  echo
done




# Go on after showing desired info based on output type.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
        wait_for_user
        display_menu
        ;;
    part_of_whole_info_wait)
        current_page=$((current_page + 1)) # Increment the current page.
        wait_for_user $current_page $total_pages # Show wait dialog.
        display_next_menu_item
        ;;
    part_of_whole_info_fast)
        display_next_menu_item
        ;;
esac
