TODO: Adapt below to work with swarm info

# #!/bin/bash

# # Get the directory of the script.
# SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# # Specify the destination directory of server-state file.
# MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# DESTINATION_DIR="$MAIN_DIR/server-states"


# # Function to display cpu info.
# get_cpu_info() {
#     bash "$SCRIPT_DIR/cpu_info.sh" -p 
# }

# # Function to display network upstream info.
# get_upstream_info() {
#     bash "$SCRIPT_DIR/network_info.sh" -u
# }
# # Function to display network downstream info.
# get_downstream_info() {
#     bash "$SCRIPT_DIR/network_info.sh" -d
# }
# # Function to display total network info.
# get_total_network_info() {
#     bash "$SCRIPT_DIR/network_info.sh" -a
# }
# # Function to display network upstream info.
# get_upstream_info_human() {
#     bash "$SCRIPT_DIR/network_info.sh" -u -h
# }
# # Function to display network downstream info.
# get_downstream_info_human() {
#     bash "$SCRIPT_DIR/network_info.sh" -d -h
# }
# # Function to display total network info.
# get_total_network_info_human() {
#     bash "$SCRIPT_DIR/network_info.sh" -a -h
# }

# # Function to convert seconds to a human-readable format.
# convert_seconds_to_human_readable() {
#     # Parameters of this function.
#     local seconds="$1"

#     # Conversion.
#     local days=$((seconds / 86400))
#     local hours=$(( (seconds % 86400) / 3600 ))
#     local minutes=$(( (seconds % 3600) / 60 ))
#     local seconds=$((seconds % 60))

#     # Concatenate result.
#     local result=""
#     if [ "$days" -gt 0 ]; then
#         result="${days}d "
#     fi
#     result="${result}${hours}h ${minutes}m ${seconds}s"

#     # Return result.
#     echo -e "$result"
# }

# # Function to convert a bash array to json.
# array_to_json() {
    
#     local array=("$@")
#     local array_length=${#array[@]}
#     emptyArrayString="empty"
#     noActiveTasksString="There---are---no---active---volume---tasks---"

#     # Start JSON array.
#     json="["
#     for ((i=0; i<$array_length; i++)); do

#         # Replace empty array string to display empty string.
#         if [ "${array[i]}" = "$emptyArrayString" ] || [ "${array[i]}" = "$noActiveTasksString" ]; then
#           json+="\"\""
#         else
#           # Add element to JSON array.
#           json+="\"${array[i]}\""
#         fi


#         # Add comma for all elements except the last one.
#         if [ $i -lt $((array_length-1)) ]; then
#             json+=","
#         fi
#     done
#     # End JSON array.
#     json+="]"

#     # Return the JSON.
#     echo "$json"
# }


# # Function to convert a fake two dimensional bash array to json.
# two_dim_array_to_json() {

#     local array=("$@")
#     local array_length=${#array[@]}
#     emptyArrayString="empty"
#     spaceReplacement="---"
#     innerArraySeperator="|"
#     noActiveTasksString="There---are---no---active---volume---tasks---"

#     # Start JSON array.
#     json="["

#     for ((i=0; i<$array_length; i++)); do

#         # Inner Array.
#         json+="["

#         # Split array[i] by innerArraySeperator and loop through each individual string part.
#         innerArrayString=$(echo "${array[i]}" | sed "s/,,,/$innerArraySeperator/g")
#         IFS="$innerArraySeperator" read -ra inner_array <<< "$innerArrayString"
#         inner_array_length=${#inner_array[@]}
#         for ((j=0; j<$inner_array_length; j++)); do

#             # Replace empty array string to display an empty string.
#             if [ "${inner_array[j]}" = "$emptyArrayString" ] || [ "${inner_array[j]}" = "$noActiveTasksString" ]; then
#                 json+="\"\""
#             else
#                 # Add element to JSON array.
#                 current_element="${inner_array[j]//$spaceReplacement/ }"
#                 json+="\"$current_element\""
#             fi

#             # Add comma for all elements except the last one.
#             if [ $j -lt $((inner_array_length-1)) ]; then
#                 json+=","
#             fi

#         done

#         # End Inner Array.
#         json+="]"

#         # Add comma for all elements except the last one.
#         if [ $i -lt $((array_length-1)) ]; then
#             json+=","
#         fi

#     done

#     # End JSON array.
#     json+="]"

#     # Return the JSON.
#     echo "$json"
# }

# # Default values.
# output_type="json"
# output_file="$DESTINATION_DIR/system_info.json"

# # Check for command-line options.
# while [ $# -gt 0 ]; do
#     case "$1" in
#         --json)
#             output_type="json"
#             shift
#             ;;
#         --output-file)
#             shift
#             output_file="$1"
#             shift
#             ;;
#         *)
#             echo -e "Invalid option: $1" >&2
#             exit 1
#             ;;
#     esac
# done

# # Get current timestamp in Unix format
# timestamp=$(date +%s)
# # Get human-readable timestamp
# human_readable_timestamp=$(date -d "@$timestamp" "+%Y-%m-%d %H:%M:%S")


# # System name information.
# hostname=$(hostname)
# dist_name=$(lsb_release -ds)
# kernel_ver=$(uname -sr)
# sys_info_from_vars="${dist_name} (${kernel_ver})"
# sys_info="$(lsb_release -ds) ($(uname -sr))"

# # CPU.
# cpu_cores=$(nproc)
# last_15min_cpu_percentage=$(get_cpu_info)

# # Disk usage.
# mount_point="/"
# total_disk_avail=$(df -h "$mount_point" | awk -v mp="$mount_point" 'NR==2 {print $2}')
# disk_usage_amount=$(df -h "$mount_point" | awk -v mp="$mount_point" 'NR==2 {print $3}')
# disk_usage_percentage=$(df -h "$mount_point" | awk -v mp="$mount_point" 'NR==2 {print $5}') # Just percentage string -> 2%

# # Memory Usage.
# total_memory=$(free -m | awk '/Mem:/ {print $2}')
# total_memory_human=$(free -h | awk '/Mem:/ {print $2}')
# used_memory=$(free -m | awk '/Mem:/ {print $3}')
# used_memory_human=$(free -h | awk '/Mem:/ {print $3}')
# memory_usage_percentage=$(echo "scale=2; $used_memory / $total_memory * 100" | bc)

# # Swap Usage.
# swap_info=$(swapon --show)
# swap_info_output=""
# if [ -n "$swap_info" ]; then
#     swap_info_output="On"
# else
#     swap_info_output="Off"
# fi

# # Network Info.
# upstream_avg_bits=$(get_upstream_info)
# downstream_avg_bits=$(get_downstream_info)
# total_network_avg_bits=$(get_total_network_info)
# upstream_avg_human=$(get_upstream_info_human)
# downstream_avg_human=$(get_downstream_info_human)
# total_network_avg_human=$(get_total_network_info_human)
# if [ "$upstream_avg_bits" = "vnstat not installed (apt install vnstat)" ]; then
#   is_vnstab_installed=false
#   has_vnstab_enough_data=false
# elif [ "$upstream_avg_bits" = "There is not enough data yet" ]; then
#   is_vnstab_installed=true
#   has_vnstab_enough_data=false
# else
#   is_vnstab_installed=true
#   has_vnstab_enough_data=true
# fi

# # Gluster Info as vars.
# source "$SCRIPT_DIR/gluster_info.sh" -p
# gluster_peers_json=$(array_to_json "${gluster_peers[@]}")
# gluster_volumes_json=$(array_to_json "${gluster_volumes[@]}")
# all_unhealthy_bricks_json=$(two_dim_array_to_json "${all_unhealthy_bricks[@]}")
# all_unhealthy_processes_json=$(two_dim_array_to_json "${all_unhealthy_processes[@]}")
# all_errors_warnings_json=$(two_dim_array_to_json "${all_errors_warnings[@]}")
# all_active_tasks_json=$(two_dim_array_to_json "${all_active_tasks[@]}")

# # Processes.
# amount_processes=$(ps aux | wc -l)

# # Logged in users.
# logged_in_users=$(who | wc -l)

# # Available updates.
# sudo apt-get update -qq
# updates=$(apt list --upgradable 2>/dev/null)
# amount_of_available_updates=""
# if [ "${#updates}" -gt 10 ]; then
#     amount_of_available_updates=$(apt list --upgradable 2>/dev/null | grep -c '/upgradable')
#     updates_available_output="~$amount_of_available_updates updates available"
# else
#     updates_available_output="no updates available"
#     amount_of_available_updates=0
# fi


# # Check if a system restart is required
# restart_required=""
# restart_required_timestamp=""
# time_elapsed=0
# if [ -f /var/run/reboot-required ]; then
#     restart_required="System restart required"
#     restart_required_timestamp=$(stat -c %Y /var/run/reboot-required)
#     time_elapsed=$((timestamp - restart_required_timestamp))
# else
#     restart_required="No restart required"
# fi

# # Calculate time elapsed since restart required.
# time_elapsed_human_readable=$(convert_seconds_to_human_readable "$time_elapsed")



# # This tools state.

# # Save the current directory to be able to revert back again to it later.
# current_dir=$(pwd)
# # Change to the Git repository directory to make git commands work.
# cd $MAIN_DIR

# repo_url=https://github.com/Sokrates1989/linux-server-status.git
# repo_accessible="unknown"
# local_changes="unknown"
# up_to_date="unknown"
# behind_count="unknown"

# # Check remote connection.
# if git ls-remote --exit-code $repo_url >/dev/null 2>&1; then
#     repo_accessible="true"

#     # Check local changes.
#     if [ -n "$(git status --porcelain)" ]; then
#         local_changes="Yes"
#     else
#         local_changes="None"
#     fi

#     # Check for upstream changes.
#     git fetch -q
#     behind_count=$(git rev-list HEAD..origin/main --count)
#     if [ "$behind_count" -gt 0 ]; then
#         up_to_date="false"
#     else
#         up_to_date="true"
#         behind_count=0
#     fi
# else
#     repo_accessible="false"
# fi

# # Revert back to the original directory.
# cd "$current_dir"


# # Create JSON string
# json_data=$(cat <<EOF
# {
#   "timestamp": {
#     "unix_format": $timestamp,
#     "human_readable_format": "$human_readable_timestamp"
#   },
#   "system_info": {
#     "hostname": "$hostname",
#     "dist_name": "$dist_name",
#     "kernel_ver": "$kernel_ver",
#     "sys_info": "$sys_info"
#   },
#   "cpu": {
#     "cpu_cores": "$cpu_cores",
#     "last_15min_cpu_percentage": "$last_15min_cpu_percentage"
#   },
#   "disk": {
#     "mount_point": "$mount_point",
#     "total_disk_avail": "$total_disk_avail",
#     "disk_usage_amount": "$disk_usage_amount",
#     "disk_usage_percentage": "$disk_usage_percentage"
#   },
#   "memory": {
#     "total_memory": "$total_memory",
#     "total_memory_human": "$total_memory_human",
#     "used_memory": "$used_memory",
#     "used_memory_human": "$used_memory_human",
#     "memory_usage_percentage": "$memory_usage_percentage"
#   },
#   "swap": {
#     "swap_status": "$swap_info_output"
#   },
#   "processes": {
#     "amount_processes": "$amount_processes"
#   },
#   "users": {
#     "logged_in_users": "$logged_in_users"
#   },
#   "network": {
#     "is_vnstab_installed": "$is_vnstab_installed",
#     "has_vnstab_enough_data": "$has_vnstab_enough_data",
#     "upstream_avg_bits": "$upstream_avg_bits",
#     "upstream_avg_human": "$upstream_avg_human",
#     "downstream_avg_bits": "$downstream_avg_bits",
#     "downstream_avg_human": "$downstream_avg_human",
#     "total_network_avg_bits": "$total_network_avg_bits",
#     "total_network_avg_human": "$total_network_avg_human"
#   },
#   "gluster": {
#     "is_gluster_installed": "$is_gluster_installed",
#     "is_peer_state_valid": "$is_peer_state_valid",
#     "gluster_peers": $gluster_peers_json,
#     "number_of_peers": "$number_of_peers",
#     "number_of_healthy_peers": "$number_of_healthy_peers",
#     "gluster_volumes": $gluster_volumes_json,
#     "number_of_volumes": "$number_of_volumes",
#     "number_of_healthy_volumes": "$number_of_healthy_volumes",
#     "all_unhealthy_bricks": $all_unhealthy_bricks_json,
#     "all_unhealthy_processes": $all_unhealthy_processes_json,
#     "all_errors_warnings": $all_errors_warnings_json,
#     "all_active_tasks": $all_active_tasks_json
#   },
#   "updates": {
#     "amount_of_available_updates": "$amount_of_available_updates",
#     "updates_available_output": "$updates_available_output"
#   },
#   "system_restart": {
#     "status": "$restart_required",
#     "time_elapsed_seconds": "$time_elapsed",
#     "time_elapsed_human_readable": "$time_elapsed_human_readable"
#   },
#   "linux_server_state_tool": {
#     "repo_url": "$repo_url",
#     "repo_accessible": "$repo_accessible",
#     "local_changes": "$local_changes",
#     "up_to_date": "$up_to_date",
#     "behind_count": "$behind_count"
#   }
# }
# EOF
# )

# # Write JSON string to file
# echo -e "$json_data" > "$output_file"
# echo -e "$json_data"

# echo -e "System information has been saved to $output_file with timestamp $timestamp"


