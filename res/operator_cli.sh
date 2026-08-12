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

    if [ "${CUSTOM_OUTPUT_FILE:-NONE}" != "NONE" ]; then
        printf '%s' "$CUSTOM_OUTPUT_FILE"
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

load_operator_locale
