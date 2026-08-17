#!/bin/bash

# =============================================================================
# Module: operator_cli.sh
#
# Description:
#     Resolves current health and vulnerability evidence for human-facing CLI
#     pages, then delegates read-only formatting to scripts.operator_report.
# =============================================================================

# -----------------------------------------------------------------------------
# Load localized workflow prompts from the process locale.
#
# Global state:
#     Requires SCRIPT_DIR and sources one trusted repository locale file.
# -----------------------------------------------------------------------------
load_operator_locale() {
    local locale_file="$SCRIPT_DIR/locales/operator_en.sh"

    if [[ "${SWARM_INFO_LOCALE:-${LANG:-en}}" == de* ]]; then
        locale_file="$SCRIPT_DIR/locales/operator_de.sh"
    fi
    # shellcheck source=/dev/null
    source "$locale_file"
}

# -----------------------------------------------------------------------------
# Select the newest readable report from supplied candidates.
#
# Parameters:
#     Remaining arguments - Candidate report paths.
#
# Output:
#     Newest readable path, or nothing when no candidate exists.
# -----------------------------------------------------------------------------
newest_operator_report() {
    local candidate=""
    local selected=""

    for candidate in "$@"; do
        if [ -r "$candidate" ] && { [ -z "$selected" ] || [ "$candidate" -nt "$selected" ]; }; then
            selected="$candidate"
        fi
    done
    printf '%s' "$selected"
}

# -----------------------------------------------------------------------------
# Resolve health evidence, preferring the explicit output and production path.
#
# Output:
#     Existing health report path, or nothing when no report exists.
# -----------------------------------------------------------------------------
resolve_health_report_for_operator() {
    if [ "${CUSTOM_OUTPUT_FILE:-NONE}" != "NONE" ]; then
        printf '%s' "$CUSTOM_OUTPUT_FILE"
        return
    fi
    newest_operator_report \
        "/info_json/swarm_info.json" \
        "$MAIN_DIR/swarm_info/swarm_info.json" \
        "$SCRIPT_DIR/swarm_info/swarm_info.json"
}

# -----------------------------------------------------------------------------
# Resolve the current vulnerability report or its preferred scan destination.
#
# Output:
#     Explicit, newest existing, or environment-appropriate report path.
# -----------------------------------------------------------------------------
resolve_vulnerability_report_for_operator() {
    local selected=""
    local swarm_capability=""

    if [ "${CUSTOM_OUTPUT_FILE:-NONE}" != "NONE" ]; then
        printf '%s' "$CUSTOM_OUTPUT_FILE"
        return
    fi
    if [ -n "${SWARM_INFO_SECURITY_REPORT_FILE:-}" ]; then
        printf '%s' "$SWARM_INFO_SECURITY_REPORT_FILE"
        return
    fi
    if command -v docker >/dev/null 2>&1; then
        swarm_capability="$(docker info --format '{{.Swarm.ControlAvailable}}' 2>/dev/null || true)"
    fi
    if [ "$swarm_capability" = "false" ]; then
        selected="$(newest_operator_report \
            "/share/Public/swarm-info/security_scan-running.json" \
            "/share/Public/swarm-info/security_scan.json" \
            "$MAIN_DIR/swarm_info/security_scan.json")"
        if [ -n "$selected" ]; then
            printf '%s' "$selected"
        elif [ -d "/share/Public/swarm-info" ] && [ -w "/share/Public/swarm-info" ]; then
            printf '%s' "/share/Public/swarm-info/security_scan-running.json"
        else
            printf '%s' "$MAIN_DIR/swarm_info/security_scan.json"
        fi
        return
    fi
    selected="$(newest_operator_report \
        "/info_json/vulnerability_scan.json" \
        "$MAIN_DIR/swarm_info/vulnerability_scan.json")"
    if [ -n "$selected" ]; then
        printf '%s' "$selected"
    elif [ -d "/info_json" ] && [ -w "/info_json" ]; then
        printf '%s' "/info_json/vulnerability_scan.json"
    else
        printf '%s' "$MAIN_DIR/swarm_info/vulnerability_scan.json"
    fi
}

# -----------------------------------------------------------------------------
# Return the report workload type and local-container scope for page routing.
#
# Output:
#     A tab-separated ``service|container`` and ``all|running`` pair.
# -----------------------------------------------------------------------------
resolve_vulnerability_report_context() {
    local python_command=""
    local report_file=""

    python_command="$(resolve_vulnerability_python)" || return 3
    report_file="$(resolve_vulnerability_report_for_operator)"
    if [ ! -r "$report_file" ]; then
        case "$(basename "$report_file")" in
            security_scan*.json) printf 'container\trunning\n' ;;
            *) printf 'service\trunning\n' ;;
        esac
        return 0
    fi
    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" -m scripts.operator_report \
            report-context --report-file "$report_file"
    )
}

# -----------------------------------------------------------------------------
# Render service health, collecting temporary live evidence only when absent.
#
# Returns:
#     0 healthy, 2 service attention required, or 3 unavailable/invalid.
# -----------------------------------------------------------------------------
display_service_health_guidance() {
    local python_command=""
    local report_file=""
    local temporary_report=""
    local result=0

    load_operator_locale
    python_command="$(resolve_vulnerability_python)" || return 3
    report_file="$(resolve_health_report_for_operator)"
    if [ -z "$report_file" ] || [ ! -r "$report_file" ]; then
        printf '%s\n' "$OP_COLLECTING_HEALTH"
        temporary_report="$(mktemp "${TMPDIR:-/tmp}/swarm-info-health.XXXXXX.json")" || return 3
        if ! bash "$SCRIPT_DIR/json_info.sh" \
            --json --quiet --output-file "$temporary_report" >/dev/null; then
            rm -f -- "$temporary_report"
            return 3
        fi
        report_file="$temporary_report"
    fi
    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" -m scripts.operator_report \
            service-health --report-file "$report_file"
    ) || result=$?
    if [ -n "$temporary_report" ]; then
        rm -f -- "$temporary_report"
    fi
    return "$result"
}

# -----------------------------------------------------------------------------
# Render vulnerability evidence with image-specific remediation commands.
#
# Returns:
#     0 fresh clean, 2 fresh vulnerabilities, or 3 unavailable evidence.
# -----------------------------------------------------------------------------
display_vulnerability_guidance() {
    local python_command=""
    local report_file=""
    local result=0

    python_command="$(resolve_vulnerability_python)" || return 3
    report_file="$(resolve_vulnerability_report_for_operator)"
    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" -m scripts.operator_report \
            vulnerabilities \
            --report-file "$report_file" \
            --max-age-hours "$VULNERABILITY_MAX_AGE_HOURS"
    ) || result=$?
    return "$result"
}

# -----------------------------------------------------------------------------
# Map live services to conservatively verified local stack-file candidates.
#
# Global state:
#     Reads DEPLOYMENT_ROOTS and CUSTOM_OUTPUT_FILE from the public dispatcher.
#
# Returns:
#     0 when every service maps, 2 for unknown/ambiguous services, or 3 when
#     inventory or report generation fails.
# -----------------------------------------------------------------------------
display_service_deployment_map() {
    local deploy_root=""
    local python_command=""
    local mapper_arguments=(-m scripts.deployment_mapper)

    python_command="$(resolve_vulnerability_python)" || return 3
    for deploy_root in "${DEPLOYMENT_ROOTS[@]}"; do
        mapper_arguments+=(--deploy-root "$deploy_root")
    done
    if [ "${CUSTOM_OUTPUT_FILE:-NONE}" != "NONE" ]; then
        mapper_arguments+=(--output-file "$CUSTOM_OUTPUT_FILE")
    fi
    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${mapper_arguments[@]}"
    )
}

# -----------------------------------------------------------------------------
# Open the localized interactive remediation workflow.
#
# Global state:
#     Reads deployment roots, report freshness, optional accepted mapping,
#     installation policy, plan output, and the two independent override gates.
#
# Returns:
#     0 completed/cancelled, 2 no built-in or policy action is currently
#     executable, or 3 when evidence or a safety precondition blocks the
#     workflow.
# -----------------------------------------------------------------------------
run_vulnerability_remediation_menu() {
    local deploy_root=""
    local invocation_directory="$PWD"
    local selected_map_file="${DEPLOYMENT_MAP_FILE:-NONE}"
    local selected_plan_file="${REMEDIATION_PLAN_FILE:-NONE}"
    local selected_policy_file="${REMEDIATION_POLICY_FILE:-NONE}"
    local python_command=""
    local remediation_arguments=(-m scripts.remediation_cli)

    python_command="$(resolve_vulnerability_python)" || return 3
    remediation_arguments+=(
        --report-file "$(resolve_vulnerability_report_for_operator)"
        --max-age-hours "$VULNERABILITY_MAX_AGE_HOURS"
        --history-days "${VULNERABILITY_HISTORY_DAYS:-14}"
    )
    if [ "${VULNERABILITY_LOCK_FILE:-NONE}" != "NONE" ]; then
        remediation_arguments+=(--lock-file "$VULNERABILITY_LOCK_FILE")
    fi
    for deploy_root in "${DEPLOYMENT_ROOTS[@]}"; do
        remediation_arguments+=(--deploy-root "$deploy_root")
    done
    if [ "$selected_map_file" != "NONE" ]; then
        case "$selected_map_file" in
            /*) ;;
            *) selected_map_file="$invocation_directory/$selected_map_file" ;;
        esac
        remediation_arguments+=(--deployment-map-file "$selected_map_file")
    fi
    if [ "$selected_policy_file" = "NONE" ] && [ -r "$invocation_directory/configs/remediation-policy.json" ]; then
        selected_policy_file="$invocation_directory/configs/remediation-policy.json"
    fi
    if [ "$selected_policy_file" = "NONE" ] \
        && [ -d "$invocation_directory/.git" ] \
        && [ -d "$invocation_directory/configs" ]; then
        selected_policy_file="$invocation_directory/configs/remediation-policy.json"
    fi
    if [ "$selected_policy_file" != "NONE" ]; then
        case "$selected_policy_file" in
            /*) ;;
            *) selected_policy_file="$invocation_directory/$selected_policy_file" ;;
        esac
        remediation_arguments+=(--remediation-policy "$selected_policy_file")
    fi
    if [ "$selected_plan_file" != "NONE" ]; then
        case "$selected_plan_file" in
            /*) ;;
            *) selected_plan_file="$invocation_directory/$selected_plan_file" ;;
        esac
        remediation_arguments+=(--plan-output "$selected_plan_file")
    fi
    if [ "${FORCE_AUTO_REMEDY_ATTEMPT:-false}" = "true" ]; then
        remediation_arguments+=(--force-auto-remedy-attempt)
    fi
    if [ "${ALLOW_RUNTIME_OVERRIDE:-false}" = "true" ]; then
        remediation_arguments+=(--allow-runtime-override)
    fi
    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${remediation_arguments[@]}"
    )
}

load_operator_locale
