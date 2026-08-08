#!/bin/bash

# =============================================================================
# Module: linux-cli.sh
#
# Description:
#     Installs swarm-info under the current user's tools directory, exposes the
#     command through ~/.local/bin, and verifies both core and optional image-
#     scanning dependencies. Missing Docker Scout is explained but never
#     installed automatically.
#
# Dependencies:
#     - Bash 4+
#     - Git for cloning the repository
# =============================================================================

set -e

# Installation paths and repository source.
INSTALL_DIRECTORY="${HOME}/tools/swarm-info"
LOCAL_BIN_DIRECTORY="${HOME}/.local/bin"
REPOSITORY_URL="https://github.com/Sokrates1989/swarm-info.git"
EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'

# -----------------------------------------------------------------------------
# Select the privilege prefix used in package-installation guidance.
#
# Output:
#     Empty text for root and "sudo " for an unprivileged user.
#
# Returns:
#     Always 0.
# -----------------------------------------------------------------------------
installer_privilege_prefix() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s' 'sudo '
    fi
}

# -----------------------------------------------------------------------------
# Verify dependencies needed before the repository can be cloned.
#
# Returns:
#     0 when Bash and Git are ready; otherwise 1.
#
# Side effects:
#     Prints actionable package-installation guidance when a check fails.
# -----------------------------------------------------------------------------
check_installer_dependencies() {
    local privilege_prefix=""

    if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        echo "[ERROR] Bash 4 or newer is required; found ${BASH_VERSION}." >&2
        return 1
    fi

    if command -v git >/dev/null 2>&1; then
        echo "[OK] $(git --version 2>/dev/null)"
        return 0
    fi

    privilege_prefix="$(installer_privilege_prefix)"
    echo "[ERROR] Git is required to install swarm-info." >&2
    echo "        Debian/Ubuntu: ${privilege_prefix}apt-get install -y git" >&2
    echo "        RHEL/Fedora:   ${privilege_prefix}dnf install -y git" >&2
    return 1
}

# -----------------------------------------------------------------------------
# Clone swarm-info unless the configured checkout already exists.
#
# Side effects:
#     Creates INSTALL_DIRECTORY and downloads the Git repository when absent.
#
# Returns:
#     0 when a usable checkout exists; otherwise the failing Git status.
# -----------------------------------------------------------------------------
prepare_checkout() {
    if [ ! -d "${INSTALL_DIRECTORY}/.git" ]; then
        echo "[INFO] Cloning swarm-info into ${INSTALL_DIRECTORY}..."
        mkdir -p "$INSTALL_DIRECTORY"
        git clone "$REPOSITORY_URL" "$INSTALL_DIRECTORY"
        return
    fi

    echo "[INFO] Existing checkout found; skipping clone."
    echo "[INFO] Update it independently with: git -C ${INSTALL_DIRECTORY} pull --ff-only"
}

# -----------------------------------------------------------------------------
# Append the local-bin PATH export to one existing shell profile.
#
# Parameters:
#     $1 - Absolute shell-profile path.
#
# Side effects:
#     Appends EXPORT_LINE exactly once when the target file exists.
#
# Returns:
#     Always 0.
# -----------------------------------------------------------------------------
append_export_line() {
    local profile_file="$1"

    if [ ! -f "$profile_file" ]; then
        return 0
    fi
    if grep -Fxq "$EXPORT_LINE" "$profile_file"; then
        echo "[INFO] PATH is already configured in $profile_file"
        return 0
    fi

    echo "$EXPORT_LINE" >> "$profile_file"
    echo "[OK] Added the local command directory to $profile_file"
}

# -----------------------------------------------------------------------------
# Publish the command symlink and persist its directory in common profiles.
#
# Side effects:
#     Changes executable bits, creates a symlink, edits existing user profiles,
#     and updates PATH for the installer process.
#
# Returns:
#     0 when all filesystem operations succeed; otherwise a command status.
# -----------------------------------------------------------------------------
configure_command() {
    chmod +x "${INSTALL_DIRECTORY}/get_info.sh"
    chmod +x "${INSTALL_DIRECTORY}/res/dependency_check.sh"
    mkdir -p "$LOCAL_BIN_DIRECTORY"
    ln -sf "${INSTALL_DIRECTORY}/get_info.sh" "${LOCAL_BIN_DIRECTORY}/swarm-info"
    echo "[OK] Command created at ${LOCAL_BIN_DIRECTORY}/swarm-info"

    # Guarantee at least one persistent shell profile for minimal Linux users.
    if [ ! -f "${HOME}/.bashrc" ] && [ ! -f "${HOME}/.profile" ]; then
        touch "${HOME}/.profile"
    fi
    append_export_line "${HOME}/.bashrc"
    append_export_line "${HOME}/.profile"

    export PATH="${LOCAL_BIN_DIRECTORY}:$PATH"
}

# -----------------------------------------------------------------------------
# Run the repository-owned full dependency preflight after installation.
#
# Docker Scout and Python are optional for core inventory commands, so a scan-
# readiness status of 2 is reported without failing installation. Core status
# 1 remains fatal because the tool cannot inspect the Swarm correctly.
#
# Returns:
#     0 when core dependencies are ready, including when scanning is optional.
#     1 when core dependencies are unavailable or the checker cannot run.
#
# Side effects:
#     Queries Docker and prints installation and authentication guidance.
# -----------------------------------------------------------------------------
verify_runtime_dependencies() {
    local dependency_status=0
    local dependency_script="${INSTALL_DIRECTORY}/res/dependency_check.sh"

    if [ ! -f "$dependency_script" ]; then
        echo "[ERROR] Dependency checker is missing from the checkout." >&2
        echo "        Update first: git -C ${INSTALL_DIRECTORY} pull --ff-only" >&2
        return 1
    fi

    bash "$dependency_script" --all || dependency_status=$?
    case "$dependency_status" in
        0)
            return 0
            ;;
        2)
            echo
            echo "[WARN] Core swarm-info is installed, but vulnerability scanning is not ready."
            echo "[WARN] Follow the Python/Docker Scout instructions above, then run:"
            echo "       swarm-info --check-dependencies"
            return 0
            ;;
        *)
            echo
            echo "[ERROR] swarm-info was installed, but core runtime checks failed." >&2
            echo "[ERROR] Resolve the issues above and rerun this installer." >&2
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Install the command and validate the complete host setup.
#
# Returns:
#     0 when installation and core readiness succeed; otherwise 1.
#
# Side effects:
#     Creates the checkout/symlink, updates shell profiles, and queries Docker.
# -----------------------------------------------------------------------------
main() {
    echo
    echo "Installing swarm-info (Docker Swarm Information CLI)"
    echo "===================================================="

    check_installer_dependencies
    prepare_checkout
    configure_command

    echo
    verify_runtime_dependencies

    echo
    echo "[OK] Installation complete. Launch the tool with:"
    echo "     swarm-info"
    echo
    echo "If the command is not visible in the parent shell yet, run:"
    echo '     export PATH="$HOME/.local/bin:$PATH"; hash -r'
}

main "$@"
