#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/res/functions.sh"



# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "menu" ]; then
        if [ "$output_speed" = "wait" ]; then
            bash "$SCRIPT_DIR/res/label_info.sh" -t "$total_pages" -c "$current_page" -w
        elif [ "$output_speed" = "fast" ]; then
            bash "$SCRIPT_DIR/res/label_info.sh" -t "$total_pages" -c "$current_page" -f
        fi
    fi   
}


# Parse command-line options.
total_pages=0
current_page=0
output_type="single"
output_speed="wait"
while getopts ":fwt:c:" opt; do
  case $opt in
    f)
      output_type="menu"
      output_speed="fast"
      ;;
    w)
      output_type="menu"
      output_speed="wait"
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


# Swarm Status
echo
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


# Go on after showing desired info.
if [ "$output_type" = "single" ]; then
    if [ "$output_speed" = "wait" ]; then
        wait_for_user 0 0
    fi
    display_menu
elif [ "$output_type" = "menu" ]; then
    if [ "$output_speed" = "wait" ]; then
        current_page=$((current_page + 1)) # Increment the current page.
        wait_for_user $current_page $total_pages # show wait dialog.
    fi
    display_next_menu_item
fi