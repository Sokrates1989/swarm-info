#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"


# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "part_of_whole_info_wait" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -w
    elif [ "$output_type" = "part_of_whole_info_fast" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -f
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



## Node-Lables ##
echo
echo
echo
echo "Labels for each node (docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}'):"
echo
# Count chars of longest values.
max_name_length=0
max_id_length=0
max_labels_length=0
for node in $(docker node ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_labels=$(docker node inspect --format 'Labels: {{.Spec.Labels}}' $node)
    
    # Calculate the length of these values.
    name_length=${#node_name}
    id_length=${#node_id}
    labels_length=${#node_labels}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( labels_length > max_labels_length )); then
        max_labels_length=$labels_length
    fi
done

for node in $(docker node ls --format '{{.ID}}'); do
    node_name=$(docker node ls --filter id=$node --format '{{.Hostname}}')
    node_id=$(docker node ls --filter id=$node --format 'ID: {{.ID}}')
    node_labels=$(docker node inspect --format 'Labels: {{.Spec.Labels}}' $node)
    print_info "$node_name" "$max_name_length" "$node_id" "$max_id_length" "$node_labels" "$max_labels_length"
done
echo
echo "Helpful label commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Set label" "docker node update --label-add <KEY>=<VALUE> <NODE_ID>"
printf "%-${output_tab_space}s: %s\n" "Remove Label" "docker node update --label-rm <KEY> <NODE_ID>"
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
