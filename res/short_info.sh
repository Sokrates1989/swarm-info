#!/bin/bash

# Output format like this:
# sampleText1               : sampleText2
# Can be achieved using this:
# printf '%-30s: %s\n' "sampleText1" "sampleText2"
# https://unix.stackexchange.com/questions/396223/bash-shell-script-output-alignment
output_tab_space=28 # The space until the colon to align all output info to
# printf "%-${output_tab_space}s: %s\n" "sampletext1" "sampleText2"


# Default values.
output_speed="normal"

# Parse command-line options.
while getopts ":fs" opt; do
  case $opt in
    f)
      output_speed="fast"
      ;;
    s)
      output_speed="slow"
      ;;
    \?)
      echo -e "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done


# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to display helpful commands.
display_helpful_commands() {
    bash "$SCRIPT_DIR/helpful_commands.sh"
}

# Check this tool's state.
check_state_of_tool() {
    bash "$SCRIPT_DIR/check_tool_state.sh"
}


