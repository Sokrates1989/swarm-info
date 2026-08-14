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
#     - Bash 3+ (Bash 4+ remains required for Swarm inventory operations)
#     - Git for cloning the repository
# =============================================================================

set -e

# Installation paths and repository source.
INSTALL_DIRECTORY="${HOME}/tools/swarm-info"
LOCAL_BIN_DIRECTORY="${HOME}/.local/bin"
LOCAL_MAN_DIRECTORY="${HOME}/.local/share/man/man1"
REPOSITORY_URL="https://github.com/Sokrates1989/swarm-info.git"
EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'
GIT_COMMAND="git"

# -----------------------------------------------------------------------------
# Resolve Git from PATH or the QNAP QGit package installation.
# -----------------------------------------------------------------------------
resolve_installer_git() {
    local candidate=""
    local qgit_root=""

    if command -v git >/dev/null 2>&1; then
        printf '%s' 'git'
        return 0
    fi
    if command -v getcfg >/dev/null 2>&1; then
        qgit_root="$(getcfg QGit Install_Path -f /etc/config/qpkg.conf 2>/dev/null || true)"
    fi
    for candidate in "$qgit_root/bin/git" "$qgit_root/usr/bin/git"; do
        if [ -n "$qgit_root" ] && [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

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

    if [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
        echo "[ERROR] Bash 3 or newer is required; found ${BASH_VERSION}." >&2
        return 1
    fi
    if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        echo "[INFO] Bash ${BASH_VERSION} supports portable security checks; Swarm operations require Bash 4+."
    fi

    if GIT_COMMAND="$(resolve_installer_git)"; then
        echo "[OK] $($GIT_COMMAND --version 2>/dev/null)"
        return 0
    fi

    privilege_prefix="$(installer_privilege_prefix)"
    echo "[ERROR] Git is required to install swarm-info." >&2
    echo "        Debian/Ubuntu: ${privilege_prefix}apt-get install -y git" >&2
    echo "        RHEL/Fedora:   ${privilege_prefix}dnf install -y git" >&2
    echo "        QNAP: install/enable the QGit QPKG." >&2
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
        "$GIT_COMMAND" clone "$REPOSITORY_URL" "$INSTALL_DIRECTORY"
        return
    fi

    echo "[INFO] Existing checkout found; skipping clone."
    echo "[INFO] After installation, update it safely with: swarm-info -u"
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
# Install the version-matched manual page in the current user's man path.
# -----------------------------------------------------------------------------
configure_manual() {
    local manual_source="${INSTALL_DIRECTORY}/docs/man/swarm-info.1"

    if [ ! -f "$manual_source" ]; then
        echo "[ERROR] Manual page is missing from the checkout." >&2
        return 1
    fi
    mkdir -p "$LOCAL_MAN_DIRECTORY"
    if command -v install >/dev/null 2>&1; then
        install -m 0644 "$manual_source" "${LOCAL_MAN_DIRECTORY}/swarm-info.1"
    else
        cp "$manual_source" "${LOCAL_MAN_DIRECTORY}/swarm-info.1"
        chmod 0644 "${LOCAL_MAN_DIRECTORY}/swarm-info.1"
    fi
    if command -v mandb >/dev/null 2>&1; then
        mandb -q "${HOME}/.local/share/man" >/dev/null 2>&1 || true
    fi
    echo "[OK] Manual installed at ${LOCAL_MAN_DIRECTORY}/swarm-info.1"
}

# -----------------------------------------------------------------------------
# Run the repository-owned full dependency preflight after installation.
#
# Docker Scout and Python are optional for core inventory commands, so a scan-
# readiness status of 2 is reported without failing installation. Core status
# 1 remains fatal because the tool cannot inspect the Swarm correctly.
#
# Returns:
#     0 when core dependencies are ready, including when optional security
#     workflows still need tools.
#     1 when core dependencies are unavailable or the checker cannot run.
#
# Side effects:
#     Queries Docker and prints installation and authentication guidance.
# -----------------------------------------------------------------------------
verify_runtime_dependencies() {
    local dependency_status=0
    local dependency_script="${INSTALL_DIRECTORY}/res/dependency_check.sh"
    local docker_state=""
    local check_mode="all"

    if [ ! -f "$dependency_script" ]; then
        echo "[ERROR] Dependency checker is missing from the checkout." >&2
        echo "        Rerun the latest setup/linux-cli.sh bootstrap installer." >&2
        return 1
    fi

    docker_state="$(docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' 2>/dev/null || true)"
    if [ "$docker_state" != "active|true" ]; then
        check_mode="security"
        echo "[INFO] Swarm manager control was not detected; validating portable container-security mode."
    fi
    bash "$dependency_script" "--$check_mode" || dependency_status=$?
    case "$dependency_status" in
        0)
            return 0
            ;;
        2)
            echo
            echo "[WARN] swarm-info is installed, but one or more security workflows are not ready."
            echo "[WARN] Follow the Python/Docker Scout/Compose instructions above, then run:"
            echo "       swarm-info --check-dependencies"
            return 0
            ;;
        *)
            echo
            echo "[ERROR] swarm-info was installed, but the selected runtime checks failed." >&2
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
    local locale_file=""
    local installed_version=""

    echo
    echo "Installing swarm-info (Docker Swarm Information CLI)"
    echo "===================================================="

    check_installer_dependencies
    prepare_checkout
    locale_file="${INSTALL_DIRECTORY}/res/locales/operator_en.sh"
    if [[ "${SWARM_INFO_LOCALE:-${LANG:-en}}" == de* ]]; then
        locale_file="${INSTALL_DIRECTORY}/res/locales/operator_de.sh"
    fi
    # shellcheck source=/dev/null
    source "$locale_file"
    installed_version="$(tr -d '[:space:]' < "${INSTALL_DIRECTORY}/VERSION")"
    configure_command
    configure_manual

    echo
    verify_runtime_dependencies

    echo
    echo "[OK] $OP_INSTALL_COMPLETE $installed_version"
    echo "     Launch the tool with:"
    echo "     swarm-info"
    echo
    echo "Optional daily vulnerability scan scheduling:"
    echo "     swarm-info --install-vulnerability-cron"
    echo
    echo "If the command is not visible in the parent shell yet, run:"
    echo '     export PATH="$HOME/.local/bin:$PATH"; hash -r'
}

main "$@"
