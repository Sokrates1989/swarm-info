#!/bin/bash

# =============================================================================
# Module: get_info.sh
#
# Description:
#     Main command dispatcher for Docker Swarm status, inventory, diagnostics,
#     guarded self-updates, JSON health collection, and manual image
#     vulnerability scanning.
#
# Dependencies:
#     - Bash 4+
#     - Docker CLI
#     - Python 3 and Docker Scout for --scan-vulnerabilities
# =============================================================================

# Get the directory of the script, handling symlinks properly.
# 🔧 Robust: Resolve actual script directory, even if called via symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")/res" >/dev/null 2>&1 && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

# Global functions.
source "$SCRIPT_DIR/functions.sh"
source "$SCRIPT_DIR/vulnerability_cli.sh"
source "$SCRIPT_DIR/operator_cli.sh"

# Define the number of pages when showing all information.
total_pages=7
# Current pages belonging to info tour (in order of appearance).
# basic_swarm_info.sh.
# services_info.sh.
# vulnerability_info.sh.
# stack_info.
# network_info.sh.
# secrets_info.sh.
# check_tool_state.sh.


# -----------------------------------------------------------------------------
# Display the full Swarm information tour without waiting between pages.
#
# Returns:
#     Exit status from the delegated basic information script.
# -----------------------------------------------------------------------------
display_all_swarm_info_fast() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -f
}

# -----------------------------------------------------------------------------
# Display the full Swarm information tour with interactive page waits.
#
# Returns:
#     Exit status from the delegated basic information script.
# -----------------------------------------------------------------------------
display_all_swarm_info_waiting() {
    local current_page=0
    bash "$SCRIPT_DIR/basic_swarm_info.sh" -t "$total_pages" -c "$current_page" -w
}


# -----------------------------------------------------------------------------
# Display basic Swarm information and optionally reopen its menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the basic information script.
# -----------------------------------------------------------------------------
show_basic_swarm_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/basic_swarm_info.sh" -m
    else
        bash "$SCRIPT_DIR/basic_swarm_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display manager-visible node labels and optionally reopen the menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the label information script.
# -----------------------------------------------------------------------------
display_node_label_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/label_info.sh" -m
    else
        bash "$SCRIPT_DIR/label_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display which Swarm services run on each node.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the node information script.
# -----------------------------------------------------------------------------
display_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/node_info.sh" -m
    else
        bash "$SCRIPT_DIR/node_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Docker resources belonging to the current local node.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the local-node information script.
# -----------------------------------------------------------------------------
display_local_node_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/local_node_info.sh" -m
    else
        bash "$SCRIPT_DIR/local_node_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Docker stack inventory and optionally reopen the stack menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the stack information script.
# -----------------------------------------------------------------------------
display_stack_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display services grouped by their Docker stack.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the stack-service information script.
# -----------------------------------------------------------------------------
display_stack_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/stack_services_info.sh" -m
    else
        bash "$SCRIPT_DIR/stack_services_info.sh"
    fi
}
# -----------------------------------------------------------------------------
# Display Swarm network inventory and optionally reopen the network menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the network information script.
# -----------------------------------------------------------------------------
display_network_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/network_info.sh" -m
    else
        bash "$SCRIPT_DIR/network_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Swarm secret metadata without exposing secret values.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the secrets information script.
# -----------------------------------------------------------------------------
display_secrets_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/secrets_info.sh" -m
    else
        bash "$SCRIPT_DIR/secrets_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display Swarm service inventory and optionally reopen the service menu.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the service information script.
# -----------------------------------------------------------------------------
display_services_info() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/services_info.sh" -m
    else
        bash "$SCRIPT_DIR/services_info.sh"
    fi
}

# -----------------------------------------------------------------------------
# Display the concise service-health page and optional context navigation.
# -----------------------------------------------------------------------------
display_service_health_info() {
    local arguments=()

    if [ "$is_show_menu_option_selected" = "true" ]; then
        arguments+=(-m)
    fi
    if [ "$CUSTOM_OUTPUT_FILE" != "NONE" ]; then
        arguments+=(-o "$CUSTOM_OUTPUT_FILE")
    fi
    bash "$SCRIPT_DIR/service_health_info.sh" "${arguments[@]}"
}

# -----------------------------------------------------------------------------
# Display vulnerability evidence, remediation commands, and scan navigation.
# -----------------------------------------------------------------------------
display_vulnerability_info() {
    local arguments=()
    local deployment_root_value="${SWARM_INFO_DEPLOY_ROOTS:-}"

    if [ "$is_show_menu_option_selected" = "true" ]; then
        arguments+=(-m)
    fi
    if [ "$CUSTOM_OUTPUT_FILE" != "NONE" ]; then
        arguments+=(-o "$CUSTOM_OUTPUT_FILE")
    fi
    if [ "${#DEPLOYMENT_ROOTS[@]}" -gt 0 ]; then
        deployment_root_value="$(IFS=:; printf '%s' "${DEPLOYMENT_ROOTS[*]}")"
    fi
    SWARM_INFO_DEPLOY_ROOTS="$deployment_root_value" \
        DEPLOYMENT_MAP_FILE="$DEPLOYMENT_MAP_FILE" \
        REMEDIATION_POLICY_FILE="$REMEDIATION_POLICY_FILE" \
        REMEDIATION_PLAN_FILE="$REMEDIATION_PLAN_FILE" \
        FORCE_AUTO_REMEDY_ATTEMPT="$FORCE_AUTO_REMEDY_ATTEMPT" \
        ALLOW_RUNTIME_OVERRIDE="$ALLOW_RUNTIME_OVERRIDE" \
        VULNERABILITY_MAX_AGE_HOURS="$VULNERABILITY_MAX_AGE_HOURS" \
        VULNERABILITY_HISTORY_DAYS="$VULNERABILITY_HISTORY_DAYS" \
        VULNERABILITY_LOCK_FILE="$VULNERABILITY_LOCK_FILE" \
        bash "$SCRIPT_DIR/vulnerability_info.sh" "${arguments[@]}"
}

# -----------------------------------------------------------------------------
# Display the curated Docker and Swarm command reference.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the helpful-commands script.
# -----------------------------------------------------------------------------
display_helpful_commands() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/helpful_commands.sh" -m
    else
        bash "$SCRIPT_DIR/helpful_commands.sh"
    fi
}

# -----------------------------------------------------------------------------
# Check whether the local swarm-info checkout is current and modified.
#
# Global state:
#     is_show_menu_option_selected controls whether `-m` is forwarded.
#
# Returns:
#     Exit status from the tool-state script.
# -----------------------------------------------------------------------------
check_tool_state() {
    if [ "$is_show_menu_option_selected" = "true" ]; then
        bash "$SCRIPT_DIR/check_tool_state.sh" -m
    else
        bash "$SCRIPT_DIR/check_tool_state.sh"
    fi
}

# -----------------------------------------------------------------------------
# Safely fast-forward swarm-info to its configured Git upstream.
#
# Returns:
#     0 when already current or updated successfully.
#     1 when local changes, divergence, Git, or network access block the update.
#
# Side effects:
#     Fetches the configured Git remote and may fast-forward this checkout.
# -----------------------------------------------------------------------------
update_swarm_info_tool() {
    bash "$SCRIPT_DIR/update_tool.sh"
}

#
# Health-report output configuration.
# A caller-provided destination replaces the repository-local default.
#
CUSTOM_OUTPUT_FILE="NONE"
swarm_info_dir="$SCRIPT_DIR/swarm_info"
swarm_info_json_file="$swarm_info_dir/swarm_info.json"

# -----------------------------------------------------------------------------
# Collect Swarm health information and publish it as JSON.
#
# Global state:
#     CUSTOM_OUTPUT_FILE selects a custom destination when it is not `NONE`.
#     swarm_info_json_file supplies the repository-local default destination.
#
# Returns:
#     Exit status from the JSON collection script.
# -----------------------------------------------------------------------------
swarm_info_json() {
    # Use the repository-local destination when no override was provided.
    if [ "$CUSTOM_OUTPUT_FILE" = "NONE" ]; then
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$swarm_info_json_file"
    else
        bash "$SCRIPT_DIR/json_info.sh" --json --output-file "$CUSTOM_OUTPUT_FILE"
    fi
}

# -----------------------------------------------------------------------------
# Verify core and optional host dependencies through the shared checker.
#
# Parameters:
#     $1 - Check mode: core, scan, or all. Defaults to all.
#
# Returns:
#     0 when every selected dependency is ready.
#     1 when a required core dependency is unavailable.
#     2 when core dependencies are ready but scan dependencies are unavailable.
#     64 when the requested mode is invalid.
#
# Side effects:
#     Runs Docker readiness commands and prints installation guidance.
# -----------------------------------------------------------------------------
check_swarm_info_dependencies() {
    local check_mode="${1:-all}"

    bash "$SCRIPT_DIR/dependency_check.sh" "--$check_mode"
}

# -----------------------------------------------------------------------------
# Display command-line help, wait for acknowledgement, and reopen the menu.
#
# Returns:
#     Exit status from the menu dispatcher after the user acknowledges help.
#
# Side effects:
#     Writes usage text and waits for terminal input.
# -----------------------------------------------------------------------------
display_help() {
    local version=""

    version="$(tr -d '[:space:]' < "$MAIN_DIR/VERSION")"
    echo -e "swarm-info $version"
    echo -e "Usage: swarm-info [OPTIONS]"
    echo -e "Options:"
    echo -e "  -b                Alias for --basic"
    echo -e "  --basic           Basic swarm info"
    echo -e "  -c                Alias for --commands"
    echo -e "  --commands        Display helpful commands"
    echo -e "  --check-dependencies"
    echo -e "                    Check core, Python, and Docker Scout readiness"
    echo -e "  --cache-age-hours Vulnerability rescan interval (default: 20)"
    echo -e "  --cron-hour       Daily vulnerability cron hour (default: 3)"
    echo -e "  --cron-log-file   Optional vulnerability cron log destination"
    echo -e "  --cron-minute     Daily vulnerability cron minute (default: 17)"
    echo -e "  --deploy-root     $OP_HELP_DEPLOY_ROOT"
    echo -e "  --deployment-map-file"
    echo -e "                    $OP_HELP_DEPLOYMENT_MAP_FILE"
    echo -e "  -d                Alias for --service-health"
    echo -e "  -f                Alias for --fast"
    echo -e "  --fast            Do not wait for keypress and display all information"
    echo -e "  -h                Alias for --help"
    echo -e "  --help            Display this help message"
    echo -e "  --json            Save and display info in json format"
    echo -e "  --history-days    Vulnerability report retention days (default: 14)"
    echo -e "  --force-auto-remedy-attempt"
    echo -e "                    $OP_HELP_FORCE_REMEDY"
    echo -e "  --install-vulnerability-cron"
    echo -e "                    Install/update the current user's managed daily scan"
    echo -e "  --local           Display local docker information (docker on this node)"
    echo -e "  --lock-file       Optional vulnerability job lock-file destination"
    echo -e "  --labels          Display Node label info (What labels are set to each node)"
    echo -e "  -m                Alias for --menu"
    echo -e "  --map-service-deployments"
    echo -e "                    $OP_HELP_DEPLOYMENT_MAP"
    echo -e "  --menu            Show menu (after displaying info, if used in combination with any single information option)"
    echo -e "  --max-age-hours   Vulnerability freshness limit (default: 30)"
    echo -e "  --net             Display network info"
    echo -e "  --network         Display network info"
    echo -e "  --node-services   Display service node information (What service is running on which node)"
    echo -e "  -o                Alias for --output-file"
    echo -e "  --output-file     Health, vulnerability, or deployment-map JSON destination"
    echo -e "  --platform        Image platform for vulnerability scanning (default: linux/amd64)"
    echo -e "  --scan-vulnerabilities"
    echo -e "                    Force a locked scan of every Swarm service image"
    echo -e "  --scheduled-vulnerability-scan"
    echo -e "                    Run a locked scan unless matching evidence is fresh"
    echo -e "  --secrets         Display infos for secrets"
    echo -e "  --services        Display services information"
    echo -e "  --service-health  $OP_HELP_SERVICE_HEALTH"
    echo -e "  --stacks          Display stack information"
    echo -e "  --stack-services  Display services within stacks"
    echo -e "  --state           Check this tool's state"
    echo -e "  --remove-vulnerability-cron"
    echo -e "                    Remove only the managed daily scan from crontab"
    echo -e "  -u                Alias for --update"
    echo -e "  --update          Safely fast-forward swarm-info to its Git upstream"
    echo -e "  --vulnerability-status"
    echo -e "                    Check report completeness and freshness without Docker"
    echo -e "  -v                Alias for --vulnerabilities"
    echo -e "  --vulnerabilities $OP_HELP_VULNERABILITIES"
    echo -e "  --remediate-vulnerabilities"
    echo -e "                    $OP_HELP_REMEDIATE"
    echo -e "  --remediation-policy"
    echo -e "                    $OP_HELP_REMEDIATION_POLICY"
    echo -e "  --remediation-plan-file"
    echo -e "                    $OP_HELP_REMEDIATION_PLAN"
    echo -e "  --allow-runtime-override"
    echo -e "                    $OP_HELP_RUNTIME_OVERRIDE"
    echo -e "  -V, --version     $OP_HELP_VERSION"
    echo -e "  -w                Alias for --wait"
    echo -e "  --wait            Show swarm info and wait after outputs to make it easier to read"
    echo
    echo "$OP_HELP_DEPLOYMENT_REQUIREMENT"
    echo "$OP_HELP_EXAMPLES"
    echo "  swarm-info --map-service-deployments --deploy-root /swarm"
    echo "  swarm-info -v"
    echo "  swarm-info --remediate-vulnerabilities --deploy-root /swarm"

    if [ "$is_show_menu_option_selected" = "true" ]; then
        echo
        wait_for_user
        display_menu
    fi
}

# -----------------------------------------------------------------------------
# Display the authoritative CLI version.
# -----------------------------------------------------------------------------
display_version() {
    printf 'swarm-info %s\n' "$(tr -d '[:space:]' < "$MAIN_DIR/VERSION")"
}


# Default values for the selected action.
selected_action="none"
is_show_menu_option_selected="false"
use_file_output="false"
file_output_type="json"
VULNERABILITY_PLATFORM="linux/amd64"
VULNERABILITY_CACHE_AGE_HOURS="20"
VULNERABILITY_MAX_AGE_HOURS="30"
VULNERABILITY_HISTORY_DAYS="14"
VULNERABILITY_LOCK_FILE="NONE"
VULNERABILITY_CRON_HOUR="3"
VULNERABILITY_CRON_MINUTE="17"
VULNERABILITY_CRON_LOG_FILE="NONE"
DEPLOYMENT_ROOTS=()
DEPLOYMENT_MAP_FILE="NONE"
REMEDIATION_POLICY_FILE="NONE"
REMEDIATION_PLAN_FILE="NONE"
FORCE_AUTO_REMEDY_ATTEMPT="false"
ALLOW_RUNTIME_OVERRIDE="false"

# Check for command-line options.
while [ $# -gt 0 ]; do
    case "$1" in
        -b|--basic)
            selected_action="basic"
            shift
            ;;
        -c|--commands)
            selected_action="commands"
            shift
            ;;
        -d|--service-health)
            selected_action="service-health"
            shift
            ;;
        --check-dependencies)
            selected_action="check-dependencies"
            shift
            ;;
        --cache-age-hours)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_CACHE_AGE_HOURS="$1"
            shift
            ;;
        --cron-hour)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_CRON_HOUR="$1"
            shift
            ;;
        --cron-log-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_CRON_LOG_FILE="$1"
            shift
            ;;
        --cron-minute)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_CRON_MINUTE="$1"
            shift
            ;;
        --deploy-root)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            DEPLOYMENT_ROOTS+=("$1")
            shift
            ;;
        --deployment-map-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            DEPLOYMENT_MAP_FILE="$1"
            shift
            ;;
        -f|--fast)
            selected_action="fast"
            shift
            ;;
        -h|--help|help)
            selected_action="help"
            shift
            ;;
        --json)
            use_file_output="true"
            file_output_type="json"
            shift
            ;;
        --history-days)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_HISTORY_DAYS="$1"
            shift
            ;;
        --force-auto-remedy-attempt)
            FORCE_AUTO_REMEDY_ATTEMPT="true"
            shift
            ;;
        --install-vulnerability-cron)
            selected_action="install-vulnerability-cron"
            shift
            ;;
        --local)
            selected_action="local"
            shift
            ;;
        --lock-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_LOCK_FILE="$1"
            shift
            ;;
        --labels)
            selected_action="labels"
            shift
            ;;
        -m|--menu)
            is_show_menu_option_selected="true"
            shift
            ;;
        --map-service-deployments)
            selected_action="map-service-deployments"
            shift
            ;;
        --max-age-hours)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_MAX_AGE_HOURS="$1"
            shift
            ;;
        --net|--network)
            selected_action="network"
            shift
            ;;
        --node-services)
            selected_action="nodes"
            shift
            ;;
        -o|--output-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            CUSTOM_OUTPUT_FILE="$1"
            shift
            ;;
        --platform)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_PLATFORM="$1"
            shift
            ;;
        --scan-vulnerabilities)
            selected_action="scan-vulnerabilities"
            shift
            ;;
        --scheduled-vulnerability-scan)
            selected_action="scheduled-vulnerability-scan"
            shift
            ;;
        --remove-vulnerability-cron)
            selected_action="remove-vulnerability-cron"
            shift
            ;;
        --remediate-vulnerabilities)
            selected_action="remediate-vulnerabilities"
            shift
            ;;
        --remediation-policy)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            REMEDIATION_POLICY_FILE="$1"
            shift
            ;;
        --remediation-plan-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            REMEDIATION_PLAN_FILE="$1"
            shift
            ;;
        --allow-runtime-override)
            ALLOW_RUNTIME_OVERRIDE="true"
            shift
            ;;
        --secrets)
            selected_action="secrets"
            shift
            ;;
        --services)
            selected_action="services"
            shift
            ;;
        --stacks)
            selected_action="stacks"
            shift
            ;;
        --stack-services)
            selected_action="stack-services"
            shift
            ;;
        --state)
            selected_action="state"
            shift
            ;;
        -u|--update)
            selected_action="update"
            shift
            ;;
        --vulnerability-status)
            selected_action="vulnerability-status"
            shift
            ;;
        -v|--vulnerabilities)
            selected_action="vulnerabilities"
            shift
            ;;
        -V|--version|version)
            selected_action="version"
            shift
            ;;
        -w|--wait)
            selected_action="wait"
            shift
            ;;
        *)
            echo -e "Invalid option: $1" >&2
            exit 1
            ;;
    esac
done

# Preserve the chosen freshness policy through the script-based tour chain.
export VULNERABILITY_MAX_AGE_HOURS

# Execute the selected action
case "$selected_action" in
    "basic")
        show_basic_swarm_info
        ;;
    "commands")
        display_helpful_commands
        ;;
    "check-dependencies")
        check_swarm_info_dependencies all
        ;;
    "install-vulnerability-cron")
        configure_vulnerability_cron install
        ;;
    "fast")
        display_all_swarm_info_fast
        ;;
    "help")
        display_help
        ;;
    "local")
        display_local_node_info
        ;;
    "labels")
        display_node_label_info
        ;;
    "network")
        display_network_info
        ;;
    "map-service-deployments")
        display_service_deployment_map
        ;;
    "remediate-vulnerabilities")
        run_vulnerability_remediation_menu
        ;;
    "nodes")
        display_node_info
        ;;
    "secrets")
        display_secrets_info
        ;;
    "services")
        display_services_info
        ;;
    "service-health")
        display_service_health_info
        ;;
    "stacks")
        display_stack_info
        ;;
    "stack-services")
        display_stack_services_info
        ;;
    "state")
        check_tool_state
        ;;
    "update")
        update_swarm_info_tool
        ;;
    "scan-vulnerabilities")
        run_service_image_vulnerability_job manual
        ;;
    "scheduled-vulnerability-scan")
        run_service_image_vulnerability_job scheduled
        ;;
    "remove-vulnerability-cron")
        configure_vulnerability_cron remove
        ;;
    "vulnerability-status")
        inspect_vulnerability_report
        ;;
    "vulnerabilities")
        display_vulnerability_info
        ;;
    "version")
        display_version
        ;;
    "wait")
        display_all_swarm_info_waiting
        ;;
    *)
        if [ "$use_file_output" = "true" ]; then
            if [ "$file_output_type" = "json" ]; then
                swarm_info_json
            else
                # File output type is invalid.
                echo -e "invalid file_output_type: $file_output_type"
            fi
        else
            # If no option is specified or an invalid option is provided, display menu or start tour.
            dependency_status=0
            check_swarm_info_dependencies all || dependency_status=$?
            if [ "$dependency_status" -eq 1 ]; then
                echo "[ERROR] Resolve the core dependency issues before running swarm-info." >&2
                exit 1
            fi

            if [ "$is_show_menu_option_selected" = "true" ]; then
                display_menu
            else
                display_all_swarm_info_waiting
            fi
        fi
        ;;
esac
