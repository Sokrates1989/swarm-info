#!/bin/bash

# =============================================================================
# Module: runtime_hardening_cli.sh
#
# Description:
#     Bridges the public Bash action to the read-only Python hardening auditor.
# =============================================================================

# Audit local containers and publish secret-free hardening evidence.
run_runtime_hardening() {
    local arguments=(-m scripts.runtime_hardening)
    local python_command=""

    python_command="$(resolve_vulnerability_python)" || return 3
    arguments+=(--scope "$SECURITY_CONTAINER_SCOPE")
    arguments+=(--os "$SECURITY_HOST_OS")
    if [ "$CUSTOM_OUTPUT_FILE" != "NONE" ]; then
        arguments+=(--output-file "$CUSTOM_OUTPUT_FILE")
    fi

    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${arguments[@]}"
    )
}
