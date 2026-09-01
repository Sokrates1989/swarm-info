#!/bin/bash

# =============================================================================
# Module: compose_remediation_cli.sh
#
# Description:
#     Bridges public Bash options to guarded standalone Compose remediation.
# =============================================================================

# Plan, explicitly apply, or explicitly roll back one Compose transaction.
run_compose_remediation() {
    local arguments=(-m scripts.compose_remediation_cli)
    local plan_file="$REMEDIATION_PLAN_FILE"
    local python_command=""

    python_command="$(resolve_vulnerability_python)" || return 3
    if [ "$plan_file" = "NONE" ]; then
        plan_file="${XDG_STATE_HOME:-${HOME}/.local/state}/swarm-info/compose-remediation.json"
    fi
    arguments+=(--plan-output "$plan_file")
    if [ "$selected_action" = "rollback-compose-remediation" ]; then
        arguments+=(--rollback)
    else
        arguments+=(
            --report-file "$IMAGE_UPDATE_REPORT_FILE"
            --remediation-policy "$REMEDIATION_POLICY_FILE"
            --compose-service "$SECURITY_FOCUS_VALUE"
            --os "$SECURITY_HOST_OS"
            --scout-timeout-minutes "$SECURITY_SCOUT_TIMEOUT_MINUTES"
        )
        if [ "$REQUEST_APPLY" = "true" ]; then
            arguments+=(--apply)
        fi
    fi

    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${arguments[@]}"
    )
}
