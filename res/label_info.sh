#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"


# Global functions.
source "$SCRIPT_DIR/functions.sh"



# Display next menu item.
display_next_menu_item() {
    if [ "$output_type" = "menu" ]; then
        if [ "$output_speed" = "wait" ]; then
            bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -w
        elif [ "$output_speed" = "fast" ]; then
            bash "$SCRIPT_DIR/services_info.sh" -t "$total_pages" -c "$current_page" -f
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



## Node-Lables ##
echo "Labels for each node (docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}'):"
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
echo "Helpful label commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "Set label" "docker node update --label-add <KEY>=<VALUE> <NODE_ID>"
printf "%-${output_tab_space}s: %s\n" "Remove Label" "docker node update --label-rm <KEY> <NODE_ID>"
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