#!/bin/bash

## Global functions ##

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to print formatted output.
print_info() {
    while [ "$#" -gt 0 ]; do
        local text=$1
        local output_tab_space=$2
        printf "%-${output_tab_space}s" "$text"
        shift 2
        if [ "$#" -gt 0 ]; then
            printf "  | "
        fi
    done
    echo ""  # Print a newline at the end
}

# Loading animation.
loading_animation() {
    local duration=3
    local delay=0.1
    if [ "$output_speed" == "fast" ]; then
        delay=0.05
        duration=0
    elif [ "$output_speed" == "normal" ]; then
        delay=0.2
        duration=3
    elif [ "$output_speed" == "slow" ]; then
        delay=0.4
        duration=5
    fi
    local spinstr='|/-\'
    local temp
    SECONDS=0
    while (( SECONDS < duration )); do
        temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}


# Function to show a loading dots animation.
show_loading_dots() {
    local duration=3
    local delay=0.5
    if [ "$output_speed" == "fast" ]; then
        delay=0.05
        duration=0
    elif [ "$output_speed" == "normal" ]; then
        delay=0.2
        duration=3
    elif [ "$output_speed" == "slow" ]; then
        delay=0.4
        duration=5
    fi
    SECONDS=0
    while (( SECONDS < duration )); do
        printf "."
        sleep $delay
        printf "\b\b  \b\b"
        sleep $delay
        printf ".."
        sleep $delay
        printf "\b\b\b   \b\b\b"
        sleep $delay
        printf "..."
        sleep $delay
        printf "\b\b\b    \b\b\b\b"
        sleep $delay
    done
    printf "    \b\b\b\b"
}


# Wait for user to press any key.
wait_for_user() {
    local page=$1
    local total_pages=$2
    if [ "$page" -eq 0 ] && [ "$total_pages" -eq 0 ]; then
        echo "Press any button to continue... "
    else
        echo "Press any button to continue... ($page/$total_pages)"
    fi
    read -n 1 -s
    tput cuu1 # Move cursor up one line
    tput el # Clear the line
    echo
    echo
    echo "($page/$total_pages)"
    echo
}


# Display the main menu.
display_menu() {
    bash "$SCRIPT_DIR/res/menu.sh"
}
