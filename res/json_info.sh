#!/bin/bash

# =============================================================================
# Module: json_info.sh
# Author: Sokrates1989
# Date: 2026-02-10
# Version: 1.0.0
#
# Description:
#     Collects Docker Swarm service health data and outputs structured JSON.
#     Queries each service for replica status, recent task failures, restart
#     rates, and produces an overall health summary with per-service details.
#
# Dependencies:
#     - Docker (Swarm mode active, run on a manager node)
#     - bash 4+
#
# Usage:
#     bash json_info.sh --json --output-file /path/to/output.json
# =============================================================================

# Get the directory of the script, handling symlinks properly.
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default output file location.
DESTINATION_DIR="$MAIN_DIR/swarm_info"
output_file="$DESTINATION_DIR/swarm_info.json"


# -----------------------------------------------------------------------------
# Escape a string for safe embedding in JSON values.
#
# Replaces backslashes, double quotes, and newlines with their JSON escape
# sequences so that arbitrary Docker output can be safely included in a
# JSON string literal.
#
# Args:
#     $1 (str): The raw string to escape.
#
# Returns:
#     str: The escaped string, printed to stdout.
# -----------------------------------------------------------------------------
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    echo -n "$s"
}


# -----------------------------------------------------------------------------
# Convert seconds to a human-readable duration string.
#
# Converts a number of seconds into a string like "2d 3h 15m 42s" or
# "0h 5m 12s" for shorter durations.
#
# Args:
#     $1 (int): Duration in seconds.
#
# Returns:
#     str: Human-readable duration, printed to stdout.
# -----------------------------------------------------------------------------
convert_seconds_to_human_readable() {
    local seconds="$1"
    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))

    local result=""
    if [ "$days" -gt 0 ]; then
        result="${days}d "
    fi
    result="${result}${hours}h ${minutes}m ${secs}s"
    echo -n "$result"
}


# -----------------------------------------------------------------------------
# Parse the "ago" duration from docker task state strings into seconds.
#
# Docker reports task ages like "5 minutes ago", "2 hours ago",
# "About an hour ago", etc. This function converts those strings into
# an approximate number of seconds for comparison and rate calculation.
#
# Args:
#     $1 (str): The "current state" string from docker service ps,
#               e.g. "Failed 5 minutes ago".
#
# Returns:
#     int: Approximate age in seconds, printed to stdout.
#          Returns 0 if the string cannot be parsed.
# -----------------------------------------------------------------------------
parse_ago_to_seconds() {
    local state_str="$1"
    local seconds=0

    # Extract the numeric value (if any) from the state string.
    local num
    num=$(echo "$state_str" | grep -oP '\d+' | head -1)

    if echo "$state_str" | grep -qi "second"; then
        seconds="${num:-1}"
    elif echo "$state_str" | grep -qi "minute"; then
        seconds=$(( ${num:-1} * 60 ))
    elif echo "$state_str" | grep -qi "hour"; then
        seconds=$(( ${num:-1} * 3600 ))
    elif echo "$state_str" | grep -qi "day"; then
        seconds=$(( ${num:-1} * 86400 ))
    elif echo "$state_str" | grep -qi "week"; then
        seconds=$(( ${num:-1} * 604800 ))
    elif echo "$state_str" | grep -qi "month"; then
        seconds=$(( ${num:-1} * 2592000 ))
    fi

    echo "$seconds"
}


# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        --json)
            shift
            ;;
        --output-file)
            shift
            output_file="$1"
            shift
            ;;
        *)
            echo "Invalid option: $1" >&2
            exit 1
            ;;
    esac
done

# Ensure the output directory exists.
mkdir -p "$(dirname "$output_file")"


# =============================================================================
# Collect Swarm-level information.
# =============================================================================

# Timestamp.
timestamp=$(date +%s)
human_readable_timestamp=$(date -d "@$timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -r "$timestamp" "+%Y-%m-%d %H:%M:%S")

# Hostname.
hostname=$(hostname)

# Swarm state.
swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo "unknown")

# Node count.
node_count=$(docker node ls --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ')

# Total services.
total_services=$(docker service ls --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ')


# =============================================================================
# Collect per-service health data.
# =============================================================================

# Time window for "recent" failures: 1 hour (3600 seconds).
RECENT_WINDOW_SECONDS=3600

# Arrays to accumulate JSON fragments and unhealthy service names.
services_json_array=()
unhealthy_services=()
total_healthy=0
total_degraded=0
total_down=0

# Iterate through each service in the swarm.
while IFS=$'\t' read -r svc_name svc_image svc_replicas; do

    # Parse desired and running replicas from the "REPLICAS" column (e.g. "1/1").
    replicas_running=$(echo "$svc_replicas" | cut -d'/' -f1 | tr -d ' ')
    replicas_desired=$(echo "$svc_replicas" | cut -d'/' -f2 | tr -d ' ')

    # Count total failed tasks and recent failures within the time window.
    total_failures=0
    recent_failures=0
    last_failure_ago_seconds=0
    oldest_recent_failure_seconds=0

    # Get all shutdown/failed tasks for this service.
    while IFS=$'\t' read -r task_state task_err; do

        # Only count tasks that actually failed (have an error or "Failed" state).
        if echo "$task_state" | grep -qi "failed"; then
            total_failures=$((total_failures + 1))

            # Parse how long ago this failure happened.
            ago_seconds=$(parse_ago_to_seconds "$task_state")

            # Track the most recent failure.
            if [ "$last_failure_ago_seconds" -eq 0 ] || [ "$ago_seconds" -lt "$last_failure_ago_seconds" ]; then
                last_failure_ago_seconds=$ago_seconds
            fi

            # Track oldest recent failure (for rate calculation).
            if [ "$ago_seconds" -le "$RECENT_WINDOW_SECONDS" ]; then
                recent_failures=$((recent_failures + 1))
                if [ "$ago_seconds" -gt "$oldest_recent_failure_seconds" ]; then
                    oldest_recent_failure_seconds=$ago_seconds
                fi
            fi
        fi

    done < <(docker service ps "$svc_name" --filter "desired-state=shutdown" --format '{{.CurrentState}}\t{{.Error}}' 2>/dev/null)

    # Calculate restart rate per hour based on recent failures.
    restart_rate_per_hour="0.00"
    if [ "$recent_failures" -gt 0 ] && [ "$oldest_recent_failure_seconds" -gt 0 ]; then
        # Rate = failures / time_span_hours. Use the window between oldest recent failure and now.
        restart_rate_per_hour=$(echo "scale=2; $recent_failures / ($oldest_recent_failure_seconds / 3600)" | bc 2>/dev/null || echo "0.00")
        # Guard against division by zero if bc produced empty output.
        if [ -z "$restart_rate_per_hour" ]; then
            restart_rate_per_hour="0.00"
        fi
    fi

    # Determine health status.
    # - "healthy":  running == desired AND no recent failures.
    # - "degraded": running == desired BUT recent failures exist (crash-loop recovering).
    #              OR running < desired but > 0.
    # - "down":     running == 0 AND desired > 0.
    svc_healthy="true"
    svc_status="healthy"
    if [ "$replicas_desired" -gt 0 ] && [ "$replicas_running" -eq 0 ]; then
        svc_healthy="false"
        svc_status="down"
        total_down=$((total_down + 1))
        unhealthy_services+=("$svc_name")
    elif [ "$replicas_running" -lt "$replicas_desired" ]; then
        svc_healthy="false"
        svc_status="degraded"
        total_degraded=$((total_degraded + 1))
        unhealthy_services+=("$svc_name")
    elif [ "$recent_failures" -gt 0 ]; then
        svc_healthy="false"
        svc_status="degraded"
        total_degraded=$((total_degraded + 1))
        unhealthy_services+=("$svc_name")
    else
        total_healthy=$((total_healthy + 1))
    fi

    # Convert last_failure_ago to human readable (only if there was a failure).
    last_failure_ago_human=""
    if [ "$last_failure_ago_seconds" -gt 0 ]; then
        last_failure_ago_human=$(convert_seconds_to_human_readable "$last_failure_ago_seconds")
    else
        last_failure_ago_human="none"
    fi

    # Escape image string for JSON safety.
    svc_image_escaped=$(json_escape "$svc_image")

    # Build per-service JSON fragment.
    svc_json=$(cat <<SVCEOF
    {
      "name": "$svc_name",
      "image": "$svc_image_escaped",
      "replicas_running": $replicas_running,
      "replicas_desired": $replicas_desired,
      "status": "$svc_status",
      "healthy": $svc_healthy,
      "total_failures": $total_failures,
      "recent_failures": $recent_failures,
      "recent_failure_window_seconds": $RECENT_WINDOW_SECONDS,
      "last_failure_ago_seconds": $last_failure_ago_seconds,
      "last_failure_ago_human": "$last_failure_ago_human",
      "restart_rate_per_hour": $restart_rate_per_hour
    }
SVCEOF
)
    services_json_array+=("$svc_json")

done < <(docker service ls --format '{{.Name}}\t{{.Image}}\t{{.Replicas}}' 2>/dev/null)


# =============================================================================
# Build unhealthy services JSON array.
# =============================================================================
unhealthy_json="[]"
if [ "${#unhealthy_services[@]}" -gt 0 ]; then
    unhealthy_json="["
    for ((i=0; i<${#unhealthy_services[@]}; i++)); do
        unhealthy_json+="\"${unhealthy_services[i]}\""
        if [ $i -lt $(( ${#unhealthy_services[@]} - 1 )) ]; then
            unhealthy_json+=", "
        fi
    done
    unhealthy_json+="]"
fi


# =============================================================================
# Build services JSON array.
# =============================================================================
services_json="[]"
if [ "${#services_json_array[@]}" -gt 0 ]; then
    services_json="["$'\n'
    for ((i=0; i<${#services_json_array[@]}; i++)); do
        services_json+="${services_json_array[i]}"
        if [ $i -lt $(( ${#services_json_array[@]} - 1 )) ]; then
            services_json+=","
        fi
        services_json+=$'\n'
    done
    services_json+="  ]"
fi


# =============================================================================
# Tool state (is swarm-info itself up to date?).
# =============================================================================
current_dir=$(pwd)
cd "$MAIN_DIR" 2>/dev/null || true

repo_url="https://github.com/Sokrates1989/swarm-info.git"
repo_accessible="unknown"
local_changes="unknown"
tool_up_to_date="unknown"
tool_behind_count="unknown"

if git ls-remote --exit-code "$repo_url" >/dev/null 2>&1; then
    repo_accessible="true"
    if [ -n "$(git status --porcelain)" ]; then
        local_changes="Yes"
    else
        local_changes="None"
    fi
    git fetch -q 2>/dev/null
    tool_behind_count=$(git rev-list HEAD..origin/main --count 2>/dev/null || echo "0")
    if [ "$tool_behind_count" -gt 0 ]; then
        tool_up_to_date="false"
    else
        tool_up_to_date="true"
        tool_behind_count=0
    fi
else
    repo_accessible="false"
fi

cd "$current_dir" 2>/dev/null || true


# =============================================================================
# Assemble final JSON output.
# =============================================================================
json_data=$(cat <<EOF
{
  "timestamp": {
    "unix_format": $timestamp,
    "human_readable_format": "$human_readable_timestamp"
  },
  "swarm": {
    "hostname": "$hostname",
    "state": "$swarm_state",
    "node_count": $node_count
  },
  "summary": {
    "total_services": $total_services,
    "healthy": $total_healthy,
    "degraded": $total_degraded,
    "down": $total_down
  },
  "unhealthy_services": $unhealthy_json,
  "services": $services_json,
  "swarm_info_tool": {
    "repo_url": "$repo_url",
    "repo_accessible": "$repo_accessible",
    "local_changes": "$local_changes",
    "up_to_date": "$tool_up_to_date",
    "behind_count": "$tool_behind_count"
  }
}
EOF
)

# Write JSON string to file.
echo "$json_data" > "$output_file"

# Also print to stdout.
echo "$json_data"

echo ""
echo "Swarm service information has been saved to $output_file"
