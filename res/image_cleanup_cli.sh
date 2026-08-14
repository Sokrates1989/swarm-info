#!/bin/bash

# =============================================================================
# Module: image_cleanup_cli.sh
#
# Description:
#     Bridges public Bash options to the fail-closed Python image cleanup tool.
# =============================================================================

# Run a read-only cleanup review or an explicitly confirmed deletion.
run_image_cleanup() {
    local arguments=(-m scripts.image_cleanup)
    local python_command=""

    python_command="$(resolve_vulnerability_python)" || return 3
    if [ "$IMAGE_CLEANUP_APPLY" = "true" ]; then
        arguments+=(--apply)
    fi
    if [ "$IMAGE_CLEANUP_ASSUME_YES" = "true" ]; then
        arguments+=(--yes)
    fi
    if [ "$CUSTOM_OUTPUT_FILE" != "NONE" ]; then
        arguments+=(--output-file "$CUSTOM_OUTPUT_FILE")
    fi

    (
        cd "$MAIN_DIR" || exit 3
        "$python_command" "${arguments[@]}"
    )
}
