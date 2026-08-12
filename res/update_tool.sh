#!/bin/bash

# =============================================================================
# Module: update_tool.sh
#
# Description:
#     Safely updates the installed swarm-info checkout from its configured Git
#     upstream. Only a clean branch that is strictly behind its upstream may be
#     fast-forwarded. Local modifications, local commits, and divergence are
#     preserved and reported instead of being overwritten.
#
# Dependencies:
#     - Bash 4+
#     - Git with network access to the configured upstream remote
# =============================================================================

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIRECTORY}/.." >/dev/null 2>&1 && pwd)"
ENTRYPOINT_PATH="${REPOSITORY_ROOT}/get_info.sh"

if [[ "${SWARM_INFO_LOCALE:-${LANG:-en}}" == de* ]]; then
    source "${SCRIPT_DIRECTORY}/locales/operator_de.sh"
else
    source "${SCRIPT_DIRECTORY}/locales/operator_en.sh"
fi

# -----------------------------------------------------------------------------
# Read the authoritative version, allowing upgrades from legacy checkouts.
# -----------------------------------------------------------------------------
read_tool_version() {
    if [ -f "${REPOSITORY_ROOT}/VERSION" ]; then
        tr -d '[:space:]' < "${REPOSITORY_ROOT}/VERSION"
    else
        printf '%s' "$OP_UNVERSIONED"
    fi
}

# -----------------------------------------------------------------------------
# Run Git against the swarm-info repository regardless of caller location.
#
# Parameters:
#     All arguments are forwarded unchanged to Git after `-C REPOSITORY_ROOT`.
#
# Output:
#     Git standard output and standard error.
#
# Returns:
#     Exit status from Git.
# -----------------------------------------------------------------------------
repository_git() {
    git -C "$REPOSITORY_ROOT" "$@"
}

# -----------------------------------------------------------------------------
# Verify that the updater is running from a clean Git checkout.
#
# Output:
#     An actionable error listing local changes when the checkout is dirty.
#
# Returns:
#     0 for a clean checkout; otherwise 1.
# -----------------------------------------------------------------------------
verify_clean_checkout() {
    local changes=""

    if ! repository_git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "[ERROR] ${REPOSITORY_ROOT} is not a Git working tree." >&2
        return 1
    fi

    if ! changes="$(repository_git status --porcelain --untracked-files=normal)"; then
        echo "[ERROR] Git could not inspect the swarm-info working tree." >&2
        return 1
    fi
    if [ -n "$changes" ]; then
        echo "[ERROR] Self-update refused because the checkout has local changes:" >&2
        echo "$changes" >&2
        echo "[INFO] Commit, stash, or deliberately discard them before retrying." >&2
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Resolve the current branch's configured upstream reference.
#
# Output:
#     Upstream reference such as `origin/main`.
#
# Returns:
#     0 when an upstream exists; otherwise 1 with configuration guidance.
# -----------------------------------------------------------------------------
resolve_upstream() {
    local upstream=""

    upstream="$(
        repository_git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' \
            2>/dev/null
    )"
    if [ -z "$upstream" ]; then
        echo "[ERROR] The current branch has no configured upstream." >&2
        echo "[INFO] Configure one with: git branch --set-upstream-to origin/main" >&2
        return 1
    fi
    printf '%s' "$upstream"
}

# -----------------------------------------------------------------------------
# Split an upstream reference into its configured remote name.
#
# Parameters:
#     $1 - Upstream reference in `remote/branch` form.
#
# Output:
#     Remote name before the first slash.
#
# Returns:
#     0 when the reference contains a remote and branch; otherwise 1.
# -----------------------------------------------------------------------------
upstream_remote() {
    local upstream="$1"

    if [[ "$upstream" != */* ]]; then
        echo "[ERROR] Unsupported upstream reference: $upstream" >&2
        return 1
    fi
    printf '%s' "${upstream%%/*}"
}

# -----------------------------------------------------------------------------
# Read local-ahead and remote-behind counts relative to the upstream.
#
# Parameters:
#     $1 - Fully qualified upstream reference.
#
# Output:
#     Two whitespace-separated integers: local-ahead then remote-behind.
#
# Returns:
#     Exit status from `git rev-list`.
# -----------------------------------------------------------------------------
read_divergence_counts() {
    local upstream="$1"

    repository_git rev-list --left-right --count "HEAD...${upstream}"
}

# -----------------------------------------------------------------------------
# Restore executable access to the public command after a successful update.
#
# Side effects:
#     Adds user/group/other execute bits to get_info.sh.
#
# Returns:
#     0 when the entry point exists and chmod succeeds; otherwise 1.
# -----------------------------------------------------------------------------
ensure_entrypoint_executable() {
    if [ ! -f "$ENTRYPOINT_PATH" ]; then
        echo "[ERROR] Updated checkout does not contain get_info.sh." >&2
        return 1
    fi
    chmod +x "$ENTRYPOINT_PATH"
}

# -----------------------------------------------------------------------------
# Fast-forward a clean checkout to its configured upstream.
#
# Returns:
#     0 when already current or updated successfully; otherwise 1.
#
# Side effects:
#     Fetches the configured remote and may fast-forward the current branch.
# -----------------------------------------------------------------------------
update_swarm_info() {
    local ahead_count=0
    local before_revision=""
    local before_version=""
    local behind_count=0
    local divergence=""
    local remote=""
    local upstream=""

    if ! command -v git >/dev/null 2>&1; then
        echo "[ERROR] Git is required for swarm-info self-update." >&2
        return 1
    fi
    verify_clean_checkout || return 1
    before_version="$(read_tool_version)"
    upstream="$(resolve_upstream)" || return 1
    remote="$(upstream_remote "$upstream")" || return 1

    echo "[INFO] Fetching $upstream..."
    if ! repository_git fetch --quiet --prune "$remote"; then
        echo "[ERROR] Could not fetch updates from remote '$remote'." >&2
        return 1
    fi

    divergence="$(read_divergence_counts "$upstream")" || {
        echo "[ERROR] Could not compare HEAD with $upstream." >&2
        return 1
    }
    read -r ahead_count behind_count <<< "$divergence"
    if ! [[ "$ahead_count" =~ ^[0-9]+$ && "$behind_count" =~ ^[0-9]+$ ]]; then
        echo "[ERROR] Git returned invalid divergence counts: $divergence" >&2
        return 1
    fi

    if [ "$ahead_count" -gt 0 ]; then
        echo "[ERROR] Self-update refused: the local branch is $ahead_count commit(s) ahead" \
            "and $behind_count commit(s) behind $upstream." >&2
        echo "[INFO] Reconcile the local commits manually before retrying." >&2
        return 1
    fi
    if [ "$behind_count" -eq 0 ]; then
        ensure_entrypoint_executable
        echo "[OK] $OP_UPDATE_CURRENT $(read_tool_version)."
        return 0
    fi

    before_revision="$(repository_git rev-parse --short HEAD)"
    echo "[INFO] Applying $behind_count update commit(s) with a fast-forward merge..."
    if ! repository_git merge --ff-only "$upstream"; then
        echo "[ERROR] Fast-forward update failed; no destructive recovery was attempted." >&2
        return 1
    fi
    ensure_entrypoint_executable || return 1

    echo "[OK] swarm-info updated: $before_revision -> $(repository_git rev-parse --short HEAD)"
    echo "[OK] $OP_UPDATE_FINISHED: $before_version -> $(read_tool_version)"
    echo "[INFO] Rerun your swarm-info command to use the updated code."
    return 0
}

# -----------------------------------------------------------------------------
# Execute the self-update operation.
#
# Parameters:
#     No command-line arguments are accepted.
#
# Returns:
#     Status from update_swarm_info, or 64 for invalid arguments.
# -----------------------------------------------------------------------------
main() {
    if [ "$#" -ne 0 ]; then
        echo "Usage: swarm-info -u" >&2
        return 64
    fi
    update_swarm_info
}

main "$@"
