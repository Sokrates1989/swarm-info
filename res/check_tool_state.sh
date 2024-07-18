#!/bin/bash

# This tool's state.

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

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