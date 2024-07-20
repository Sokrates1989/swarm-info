
#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# The space until the colon to align all output info to.
output_tab_space=28 

# Global functions.
source "$SCRIPT_DIR/functions.sh"

# Parse command-line options.
output_type="single_without_menu"
while getopts ":m" opt; do
  case $opt in
    m)
      output_type="single_with_menu"
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


## Docker version ##
echo
docker_version=$(docker --version)
printf "%-${output_tab_space}s: %s\n" "Docker version" "$docker_version"
echo
echo


## List of local containers ##
echo "List of local containers (docker ps):"
echo
container_output=$(docker ps)
echo "$container_output"
echo
echo


## List of Volumes ##
echo "List of Volumes:"
echo

# Count chars of longest values.
max_name_length=0
max_driver_length=0
for volume in $(docker volume ls --format '{{.Name}}'); do

    # Get individual values to print out later.
    volume_name=$(docker volume ls --filter name=$volume --format '{{.Name}}')
    volume_driver=$(docker volume ls --filter name=$volume --format 'Driver: {{.Driver}}')

    # Calculate the length of these values.
    name_length=${#volume_name}
    driver_length=${#volume_driver}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( driver_length > max_driver_length )); then
        max_driver_length=$driver_length
    fi
done

for volume in $(docker volume ls --format '{{.Name}}'); do
    volume_name=$(docker volume ls --filter name=$volume --format '{{.Name}}')
    volume_driver=$(docker volume ls --filter name=$volume --format 'Driver: {{.Driver}}')

    # Get the mountpoint of the volume.
    volume_mountpoint=$(docker volume inspect $volume_name --format '{{ .Mountpoint }}')
    # Check if the mountpoint was retrieved successfully.
    if [ -z "$volume_mountpoint" ]; then
        volume_disk_usage="UNKNOWN MOUNTPOINT"
    else
        # Get the disk usage of the volume.
        volume_disk_usage="Disk Usage: $(du -sh $volume_mountpoint 2>/dev/null)"
        # Check if the disk usage command succeeded.
        if [ $? -ne 0 ]; then
            volume_disk_usage="UNKNOWN DISK USAGE"
        fi
    fi

    print_info "$volume_name" "$max_name_length" "$volume_driver" "$max_driver_length" "$volume_disk_usage" "15"
done
echo
echo "Helpful volume commands:"
output_tab_space=20
printf "%-${output_tab_space}s: %s\n" "List volumes" "docker volume ls"
printf "%-${output_tab_space}s: %s\n" "Inspect volume" "docker volume inspect <VOLUMENAME>"
echo
echo


# Go on after showing desired info based on output type.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
        display_menu
        ;;
esac
