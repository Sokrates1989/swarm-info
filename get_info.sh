#!/bin/bash

# =============================================================================
# Module: get_info.sh
#
# Description:
#     Main command dispatcher for Docker Swarm status, inventory, diagnostics,
#     guarded self-updates, JSON health collection, and manual image
#     vulnerability scanning, update-candidate discovery, portable security
#     checks, and safe image cleanup.
#
# Dependencies:
#     - Bash 4+ for Swarm operations; Bash 3+ for --security-check
#     - Docker CLI
#     - Python 3.10+ for cleanup; Docker Scout additionally for security checks
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
source "$SCRIPT_DIR/image_cleanup_cli.sh"
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
#     $1 - Check mode: core, scan, security, remediation, or all.
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
# Check full Swarm readiness on a manager, otherwise portable security readiness.
# -----------------------------------------------------------------------------
check_applicable_swarm_info_dependencies() {
    local docker_state=""

    docker_state="$(docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' 2>/dev/null || true)"
    if [ "$docker_state" = "active|true" ]; then
        check_swarm_info_dependencies all
    else
        check_swarm_info_dependencies security
    fi
}

# -----------------------------------------------------------------------------
# Select the only safe default tour for the detected Docker capability.
# -----------------------------------------------------------------------------
select_default_action_for_docker_capability() {
    local docker_state=""

    docker_state="$(docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' 2>/dev/null || true)"
    if [ "$docker_state" = "active|true" ]; then
        return 0
    fi
    selected_action="security-check"
    SECURITY_RUNTIME_MODE="containers"
    echo "[INFO] No Swarm manager detected; running the compatible local-container security check."
    echo "[INFO] Scanning all referenced images can take several minutes."
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
    echo -e "                    Auto-check full Swarm or portable security readiness"
    echo -e "  --cache-age-hours $OP_HELP_CACHE_AGE"
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
    echo -e "  -i                Alias for --image-cleanup"
    echo -e "  --image-cleanup   Review unused local images without deleting by default"
    echo -e "  --apply           With --image-cleanup, request confirmed removal"
    echo -e "  --yes             With --image-cleanup --apply, confirm non-interactively"
    echo -e "  --force-auto-remedy-attempt"
    echo -e "                    $OP_HELP_FORCE_REMEDY"
    echo -e "  --install-vulnerability-cron"
    echo -e "                    Install/update the current user's managed daily scan"
    echo -e "  --install-security-cron"
    echo -e "                    $OP_HELP_INSTALL_SECURITY_CRON"
    echo -e "  --local           Display local docker information (docker on this node)"
    echo -e "  --lock-file       Optional vulnerability job lock-file destination"
    echo -e "  --labels          Display Node label info (What labels are set to each node)"
    echo -e "  -m                Alias for --menu"
    echo -e "  --map-service-deployments"
    echo -e "                    $OP_HELP_DEPLOYMENT_MAP"
    echo -e "  --menu            Show menu (after displaying info, if used in combination with any single information option)"
    echo -e "  --max-age-hours   $OP_HELP_MAX_AGE"
    echo -e "  --net             Display network info"
    echo -e "  --network         Display network info"
    echo -e "  --node-services   Display service node information (What service is running on which node)"
    echo -e "  -o                Alias for --output-file"
    echo -e "  --output-file     Health, scan, image-candidate/comparison, map, or cleanup JSON destination"
    echo -e "  --platform        Swarm default: linux/amd64; security-check default: auto"
    echo -e "  --platform-info   $OP_HELP_PLATFORM_INFO"
    echo -e "  --container-state Publish all local-container operational evidence"
    echo -e "  --freshness-minutes Container-state freshness window (default: 15)"
    echo -e "  --scan-vulnerabilities"
    echo -e "                    Force a locked scan of all images, or one selected live scope"
    echo -e "  --compare-image-update"
    echo -e "                    $OP_HELP_COMPARE_IMAGE"
    echo -e "  --discover-image-updates"
    echo -e "                    $OP_HELP_DISCOVER_IMAGE_UPDATES"
    echo -e "  --assess-image-updates"
    echo -e "                    $OP_HELP_ASSESS_IMAGE_UPDATES"
    echo -e "  --allow-registry-host HOST"
    echo -e "                    $OP_HELP_ALLOW_REGISTRY_HOST"
    echo -e "  --vulnerability-report-file FILE"
    echo -e "                    $OP_HELP_VULNERABILITY_REPORT_FILE"
    echo -e "  --candidate-report-file FILE"
    echo -e "                    $OP_HELP_CANDIDATE_REPORT_FILE"
    echo -e "  --max-registry-tags COUNT"
    echo -e "                    $OP_HELP_MAX_REGISTRY_TAGS"
    echo -e "  --current-image IMAGE"
    echo -e "                    $OP_HELP_CURRENT_IMAGE"
    echo -e "  --candidate-image IMAGE"
    echo -e "                    $OP_HELP_CANDIDATE_IMAGE"
    echo -e "  --service NAME    $OP_HELP_FOCUSED_SERVICE"
    echo -e "  --image IMAGE     $OP_HELP_FOCUSED_IMAGE"
    echo -e "  --stack STACK     $OP_HELP_FOCUSED_STACK"
    echo -e "  --security-check  Auto-detect Swarm manager or local-container image scanning"
    echo -e "  --runtime-mode    Security inventory: auto, swarm, or containers (default: auto)"
    echo -e "  --container-mode  Alias for --runtime-mode containers"
    echo -e "  --container-scope $OP_HELP_CONTAINER_SCOPE"
    echo -e "  --container NAME  $OP_HELP_FOCUSED_CONTAINER"
    echo -e "  --image-id ID     $OP_HELP_FOCUSED_IMAGE_ID"
    echo -e "  --os              Host hint: auto, qnap, or linux (default: auto)"
    echo -e "  --scheduled-vulnerability-scan"
    echo -e "                    Run a locked scan unless matching evidence is fresh"
    echo -e "  --scheduled-security-check"
    echo -e "                    $OP_HELP_SCHEDULED_SECURITY"
    echo -e "  --scheduled-container-state"
    echo -e "                    Run the cheap cron-compatible state collector"
    echo -e "  --scout-timeout-minutes"
    echo -e "                    $OP_HELP_SCOUT_TIMEOUT"
    echo -e "  --scan-budget-minutes"
    echo -e "                    $OP_HELP_SCAN_BUDGET"
    echo -e "  --cron-runtime-user"
    echo -e "                    $OP_HELP_CRON_RUNTIME_USER"
    echo -e "  --secrets         Display infos for secrets"
    echo -e "  --services        Display services information"
    echo -e "  --service-health  $OP_HELP_SERVICE_HEALTH"
    echo -e "  --stacks          Display stack information"
    echo -e "  --stack-services  Display services within stacks"
    echo -e "  --state           Check this tool's state"
    echo -e "  --remove-vulnerability-cron"
    echo -e "                    Remove only the managed daily scan from crontab"
    echo -e "  --remove-security-cron"
    echo -e "                    $OP_HELP_REMOVE_SECURITY_CRON"
    echo -e "  -u                Alias for --update"
    echo -e "  --update          Safely fast-forward swarm-info to its Git upstream"
    echo -e "  --vulnerability-status"
    echo -e "                    Check report completeness and freshness without Docker"
    echo -e "  --security-status $OP_HELP_SECURITY_STATUS"
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
    echo "  swarm-info --security-check"
    echo "  swarm-info --security-check --container-mode --os=qnap"
    echo "  swarm-info --security-check --container qnap_web --os=qnap"
    echo "  swarm-info --security-check --image-id sha256:<64-HEX-DIGITS> --os=qnap"
    echo "  swarm-info -i"
    echo "  swarm-info -i --apply"
    echo "  swarm-info --map-service-deployments --deploy-root /swarm"
    echo "  swarm-info --scan-vulnerabilities --service my-stack_api"
    echo "  swarm-info --scan-vulnerabilities --image nginx:1.27"
    echo "  swarm-info --scan-vulnerabilities --stack my-stack"
    echo "  swarm-info --compare-image-update --service my-stack_api --candidate-image my/app:2.0"
    echo "  swarm-info --compare-image-update --current-image my/app:1.0 --candidate-image my/app:2.0"
    echo "  swarm-info --discover-image-updates --allow-registry-host docker.io"
    echo "  swarm-info --assess-image-updates --output-file /info_json/image_update_assessment.json"
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
ORIGINAL_ARGUMENT_COUNT="$#"
selected_action="none"
is_show_menu_option_selected="false"
use_file_output="false"
file_output_type="json"
VULNERABILITY_PLATFORM="linux/amd64"
VULNERABILITY_SCOPE_KIND="all"
VULNERABILITY_SCOPE_VALUE=""
SECURITY_PLATFORM="auto"
SECURITY_RUNTIME_MODE="auto"
SECURITY_HOST_OS="auto"
SECURITY_CONTAINER_SCOPE="all"
SECURITY_CONTAINER_SCOPE_EXPLICIT="false"
SECURITY_FOCUS_KIND="all"
SECURITY_FOCUS_VALUE=""
VULNERABILITY_CACHE_AGE_HOURS="20"
VULNERABILITY_MAX_AGE_HOURS="30"
SECURITY_CACHE_AGE_HOURS="72"
SECURITY_MAX_AGE_HOURS="96"
SECURITY_SCOUT_TIMEOUT_MINUTES="45"
SECURITY_SCAN_BUDGET_MINUTES="240"
CONTAINER_STATE_FRESHNESS_MINUTES="15"
SECURITY_CRON_RUNTIME_USER="NONE"
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
IMAGE_CLEANUP_APPLY="false"
IMAGE_CLEANUP_ASSUME_YES="false"
IMAGE_UPDATE_CURRENT_IMAGE=""
IMAGE_UPDATE_CANDIDATE_IMAGE=""
IMAGE_UPDATE_REPORT_FILE="NONE"
IMAGE_UPDATE_CANDIDATE_REPORT_FILE="NONE"
IMAGE_UPDATE_MAX_REGISTRY_TAGS="10000"
IMAGE_UPDATE_ALLOWED_REGISTRY_HOSTS=()

# Select exactly one live Swarm scope for a focused vulnerability scan.
set_vulnerability_scope() {
    local kind="$1"
    local value="$2"

    if [ "$VULNERABILITY_SCOPE_KIND" != "all" ]; then
        echo "$OP_FOCUS_CONFLICT" >&2
        return 64
    fi
    VULNERABILITY_SCOPE_KIND="$kind"
    VULNERABILITY_SCOPE_VALUE="$value"
}

# Select exactly one local-container scope for a focused security check.
set_security_focus() {
    local kind="$1"
    local value="$2"

    if [ "$SECURITY_FOCUS_KIND" != "all" ]; then
        echo "$OP_SECURITY_FOCUS_CONFLICT" >&2
        return 64
    fi
    SECURITY_FOCUS_KIND="$kind"
    SECURITY_FOCUS_VALUE="$value"
}

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
            SECURITY_CACHE_AGE_HOURS="$1"
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
        -i|--image-cleanup)
            selected_action="image-cleanup"
            shift
            ;;
        --apply)
            IMAGE_CLEANUP_APPLY="true"
            shift
            ;;
        --yes)
            IMAGE_CLEANUP_ASSUME_YES="true"
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
        --install-security-cron)
            selected_action="install-security-cron"
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
            SECURITY_MAX_AGE_HOURS="$1"
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
        --platform-info)
            selected_action="platform-info"
            shift
            ;;
        --platform)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            VULNERABILITY_PLATFORM="$1"
            SECURITY_PLATFORM="$1"
            shift
            ;;
        --security-check)
            selected_action="security-check"
            shift
            ;;
        --runtime-mode)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_RUNTIME_MODE="$1"
            shift
            ;;
        --runtime-mode=*)
            SECURITY_RUNTIME_MODE="${1#--runtime-mode=}"
            shift
            ;;
        --container-mode)
            SECURITY_RUNTIME_MODE="containers"
            shift
            ;;
        --container)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            set_security_focus "container" "$1" || exit 64
            shift
            ;;
        --container-scope)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_CONTAINER_SCOPE="$1"
            SECURITY_CONTAINER_SCOPE_EXPLICIT="true"
            shift
            ;;
        --container-scope=*)
            SECURITY_CONTAINER_SCOPE="${1#--container-scope=}"
            SECURITY_CONTAINER_SCOPE_EXPLICIT="true"
            shift
            ;;
        --os)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_HOST_OS="$1"
            shift
            ;;
        --os=*)
            SECURITY_HOST_OS="${1#--os=}"
            shift
            ;;
        --scan-vulnerabilities)
            selected_action="scan-vulnerabilities"
            shift
            ;;
        --compare-image-update)
            selected_action="compare-image-update"
            shift
            ;;
        --discover-image-updates)
            selected_action="discover-image-updates"
            shift
            ;;
        --assess-image-updates)
            selected_action="assess-image-updates"
            shift
            ;;
        --allow-registry-host)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_ALLOWED_REGISTRY_HOSTS+=("$1")
            shift
            ;;
        --vulnerability-report-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_REPORT_FILE="$1"
            shift
            ;;
        --candidate-report-file)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_CANDIDATE_REPORT_FILE="$1"
            shift
            ;;
        --max-registry-tags)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_MAX_REGISTRY_TAGS="$1"
            shift
            ;;
        --current-image)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_CURRENT_IMAGE="$1"
            shift
            ;;
        --candidate-image)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            IMAGE_UPDATE_CANDIDATE_IMAGE="$1"
            shift
            ;;
        --service)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            set_vulnerability_scope "service" "$1" || exit 64
            shift
            ;;
        --image)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            set_vulnerability_scope "image" "$1" || exit 64
            shift
            ;;
        --image-id)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            set_security_focus "image-id" "$1" || exit 64
            shift
            ;;
        --stack)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            set_vulnerability_scope "stack" "$1" || exit 64
            shift
            ;;
        --scheduled-vulnerability-scan)
            selected_action="scheduled-vulnerability-scan"
            shift
            ;;
        --scheduled-security-check)
            selected_action="scheduled-security-check"
            shift
            ;;
        --container-state)
            selected_action="container-state"
            shift
            ;;
        --scheduled-container-state)
            selected_action="scheduled-container-state"
            shift
            ;;
        --freshness-minutes)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            CONTAINER_STATE_FRESHNESS_MINUTES="$1"
            shift
            ;;
        --scout-timeout-minutes)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_SCOUT_TIMEOUT_MINUTES="$1"
            shift
            ;;
        --scan-budget-minutes)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_SCAN_BUDGET_MINUTES="$1"
            shift
            ;;
        --cron-runtime-user)
            if [ "$#" -lt 2 ]; then
                echo -e "Missing value for $1" >&2
                exit 1
            fi
            shift
            SECURITY_CRON_RUNTIME_USER="$1"
            shift
            ;;
        --remove-vulnerability-cron)
            selected_action="remove-vulnerability-cron"
            shift
            ;;
        --remove-security-cron)
            selected_action="remove-security-cron"
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
        --security-status)
            selected_action="security-status"
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

if [ "$IMAGE_CLEANUP_ASSUME_YES" = "true" ] && [ "$IMAGE_CLEANUP_APPLY" != "true" ]; then
    echo "[ERROR] --yes requires --apply." >&2
    exit 64
fi
if { [ "$IMAGE_CLEANUP_APPLY" = "true" ] || [ "$IMAGE_CLEANUP_ASSUME_YES" = "true" ]; } \
    && [ "$selected_action" != "image-cleanup" ]; then
    echo "[ERROR] --apply and --yes are valid only with --image-cleanup." >&2
    exit 64
fi
if [ "$SECURITY_CRON_RUNTIME_USER" != "NONE" ] \
    && [ "$selected_action" != "install-security-cron" ]; then
    echo "$OP_SECURITY_CRON_USER_SCOPE" >&2
    exit 64
fi
if [ "$selected_action" = "compare-image-update" ]; then
    if [ "$VULNERABILITY_SCOPE_KIND" != "all" ] \
        && [ "$VULNERABILITY_SCOPE_KIND" != "service" ]; then
        echo "$OP_COMPARE_SCOPE" >&2
        exit 64
    fi
    if [ -z "$IMAGE_UPDATE_CANDIDATE_IMAGE" ] \
        || { [ "$VULNERABILITY_SCOPE_KIND" = "service" ] \
            && [ -n "$IMAGE_UPDATE_CURRENT_IMAGE" ]; } \
        || { [ "$VULNERABILITY_SCOPE_KIND" = "all" ] \
            && [ -z "$IMAGE_UPDATE_CURRENT_IMAGE" ]; }; then
        echo "$OP_COMPARE_SELECTOR" >&2
        exit 64
    fi
elif [ -n "$IMAGE_UPDATE_CURRENT_IMAGE" ] || [ -n "$IMAGE_UPDATE_CANDIDATE_IMAGE" ]; then
    echo "$OP_COMPARE_OPTION_SCOPE" >&2
    exit 64
elif { [ "${#IMAGE_UPDATE_ALLOWED_REGISTRY_HOSTS[@]}" -gt 0 ] \
    || [ "$IMAGE_UPDATE_MAX_REGISTRY_TAGS" != "10000" ]; } \
    && [ "$selected_action" != "discover-image-updates" ]; then
    echo "$OP_DISCOVERY_OPTION_SCOPE" >&2
    exit 64
elif [ "$IMAGE_UPDATE_REPORT_FILE" != "NONE" ] \
    && [ "$selected_action" != "discover-image-updates" ] \
    && [ "$selected_action" != "assess-image-updates" ]; then
    echo "$OP_IMAGE_REPORT_OPTION_SCOPE" >&2
    exit 64
elif [ "$IMAGE_UPDATE_CANDIDATE_REPORT_FILE" != "NONE" ] \
    && [ "$selected_action" != "assess-image-updates" ]; then
    echo "$OP_ASSESSMENT_OPTION_SCOPE" >&2
    exit 64
elif [ "$VULNERABILITY_SCOPE_KIND" != "all" ] \
    && [ "$selected_action" != "scan-vulnerabilities" ]; then
    echo "$OP_FOCUS_REQUIRES_SCAN" >&2
    exit 64
fi
if [ "$SECURITY_FOCUS_KIND" != "all" ]; then
    if [ "$selected_action" != "security-check" ]; then
        echo "$OP_SECURITY_FOCUS_REQUIRES_CHECK" >&2
        exit 64
    fi
    if [ "$SECURITY_RUNTIME_MODE" = "swarm" ]; then
        echo "$OP_SECURITY_FOCUS_REQUIRES_CONTAINER_MODE" >&2
        exit 64
    fi
    SECURITY_RUNTIME_MODE="containers"
fi

if [ "$SECURITY_CONTAINER_SCOPE_EXPLICIT" != "true" ] \
    && { [ "$selected_action" = "install-security-cron" ] \
        || [ "$selected_action" = "scheduled-security-check" ]; }; then
    SECURITY_CONTAINER_SCOPE="running"
fi

# Preserve the chosen freshness policy through the script-based tour chain.
export VULNERABILITY_MAX_AGE_HOURS

if [ "$ORIGINAL_ARGUMENT_COUNT" -eq 0 ]; then
    select_default_action_for_docker_capability
fi

# Execute the selected action
case "$selected_action" in
    "basic")
        show_basic_swarm_info
        ;;
    "commands")
        display_helpful_commands
        ;;
    "check-dependencies")
        check_applicable_swarm_info_dependencies
        ;;
    "install-vulnerability-cron")
        configure_vulnerability_cron install
        ;;
    "install-security-cron")
        configure_container_security_cron install
        ;;
    "image-cleanup")
        run_image_cleanup
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
    "compare-image-update")
        run_image_update_comparison
        ;;
    "discover-image-updates")
        run_image_update_discovery
        ;;
    "assess-image-updates")
        run_image_update_assessment
        ;;
    "security-check")
        run_compatibility_security_check
        ;;
    "platform-info")
        run_platform_info
        ;;
    "scheduled-vulnerability-scan")
        run_service_image_vulnerability_job scheduled
        ;;
    "scheduled-security-check")
        run_scheduled_container_security_job
        ;;
    "container-state"|"scheduled-container-state")
        run_scheduled_container_state_job
        ;;
    "remove-vulnerability-cron")
        configure_vulnerability_cron remove
        ;;
    "remove-security-cron")
        configure_container_security_cron remove
        ;;
    "vulnerability-status")
        inspect_vulnerability_report
        ;;
    "security-status")
        inspect_container_security_report
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
