#!/bin/bash

## Global functions ##

# Function to get the script directory, handling symlinks properly.
get_script_dir() {
    # 🔧 Robust: Resolve actual script directory, even if called via symlink
    SOURCE="${BASH_SOURCE[0]}"
    while [ -L "$SOURCE" ]; do
      DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
      SOURCE="$(readlink "$SOURCE")"
      [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
    done
    echo "$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
}

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

    # Speed parameter with default value.
    local speed="normal"
    if [ -n "$1" ]; then
        speed=$1
    fi

    # Prepare default values based on speed.
    local duration=3
    local delay=0.1
    if [ "$speed" == "fast" ]; then
        delay=0.05
        duration=0
    elif [ "$speed" == "normal" ]; then
        delay=0.2
        duration=3
    elif [ "$speed" == "slow" ]; then
        delay=0.4
        duration=5
    fi

    # Show animation.
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

    # Speed parameter with default value.
    local speed="normal"
    if [ -n "$1" ]; then
        speed=$1
    fi

    # Prepare default values based on speed.
    local duration=3
    local delay=0.5
    if [ "$speed" == "fast" ]; then
        delay=0.05
        duration=0
    elif [ "$speed" == "normal" ]; then
        delay=0.2
        duration=3
    elif [ "$speed" == "slow" ]; then
        delay=0.4
        duration=5
    fi

    # Show animation.
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
    # Default values allowing this function to be called without paramters.
    local page=0
    local total_pages=0

    # Check if parameters are passed.
    if [ -n "$1" ]; then
        page=$1
    fi
    if [ -n "$2" ]; then
        total_pages=$2
    fi

    # Wait for user to press any button.
    if [ "$page" -eq 0 ] && [ "$total_pages" -eq 0 ]; then
        echo "Press any button to continue... "
    else
        echo "Press any button to continue... ($page/$total_pages)"
    fi
    read -n 1 -s

    # UI improvements.
    tput cuu1 # Move cursor up one line
    tput el # Clear the line
    if [ "$page" -ne 0 ] || [ "$total_pages" -ne 0 ]; then
        echo
        echo
        echo "($page/$total_pages)"
    fi
    echo
}


# Display the main menu.
display_menu() {
    bash "$SCRIPT_DIR/menu.sh"
}
