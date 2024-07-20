#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    # Is last item -> reshow start menu.
    bash "$MAIN_DIR/get_info.sh"
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


## This tool's state ##

# Save the current directory to be able to revert back again to it later.
current_dir=$(pwd)
# Change to the Git repository directory to make git commands work.
cd $MAIN_DIR

echo -e "Fetching state of swarm-info (this tool) ..."
echo
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




# Go on after showing desired info based on output type.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
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
