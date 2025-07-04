#!/bin/bash

# Global functions.
source "$(dirname "$0")/functions.sh"

# Get the directory of the script, handling symlinks properly.
SCRIPT_DIR="$(get_script_dir)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/check_tool_state.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_type" = "part_of_whole_info_fast" ]; then
        bash "$SCRIPT_DIR/check_tool_state.sh" -t "$total_pages" -c "$current_page" -f
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






## List of Secrets ##
echo
echo "-------------------------------------------------------------------------"
echo "Secrets (swarm-info --secrets (--menu) )"
echo "-------------------------------------------------------------------------"
echo
secrets_output=$(docker secret ls)
echo "$secrets_output"
echo
echo
echo "Helpful secret commands:"
echo "----------------------------------------------------------------------"
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create <SECRETNAME> secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
printf "%-${output_tab_space}s: %s\n" "Inspect Secret" "docker secret inspect --pretty <SECRETNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Secret" "docker secret rm <SECRETNAME>"
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
    part_of_whole_info_wait)
        current_page=$((current_page + 1)) # Increment the current page.
        wait_for_user $current_page $total_pages # Show wait dialog.
        display_next_menu_item
        ;;
    part_of_whole_info_fast)
        display_next_menu_item
        ;;
esac
