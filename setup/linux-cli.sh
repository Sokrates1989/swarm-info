#!/bin/bash

# =============================================================================
# Module: linux-cli.sh
#
# Description:
#     Detects Linux/QNAP capabilities, optionally installs supported repository
#     packages after consent, installs swarm-info under the current user, and
#     verifies both the command and applicable runtime dependencies. Docker,
#     Docker Scout, credentials, and QNAP QPKGs remain operator-managed.
#
# Dependencies:
#     - Bash 3+ (Bash 4+ remains required for Swarm inventory operations)
#     - Git for cloning the repository and a supported Docker runtime
# =============================================================================

set -e

# Installation paths and repository source. Environment overrides keep the
# standalone bootstrap testable and allow deliberate non-default locations.
INSTALL_DIRECTORY="${SWARM_INFO_INSTALL_DIRECTORY:-${HOME}/tools/swarm-info}"
LOCAL_BIN_DIRECTORY="${SWARM_INFO_LOCAL_BIN_DIRECTORY:-${HOME}/.local/bin}"
LOCAL_MAN_DIRECTORY="${SWARM_INFO_LOCAL_MAN_DIRECTORY:-${HOME}/.local/share/man/man1}"
REPOSITORY_URL="${SWARM_INFO_REPOSITORY_URL:-https://github.com/Sokrates1989/swarm-info.git}"
EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'
CHECK_ONLY="false"
INSTALL_MISSING="false"
NON_INTERACTIVE="false"
HOST_FAMILY="generic"
HOST_DESCRIPTION="Linux"
PACKAGE_MANAGER="none"
GIT_COMMAND=""
DOCKER_COMMAND=""
INSTALLER_FAILURES=0
OPTIONAL_FAILURES=0
NON_PACKAGE_FAILURES=0
MISSING_PACKAGES=()

# -----------------------------------------------------------------------------
# Print and parse the mutation-safe bootstrap interface.
# -----------------------------------------------------------------------------
show_installer_help() {
    echo "Usage: bash linux-cli.sh [options]"
    echo
    echo "  --check-only       Inspect installer requirements without changing the host."
    echo "  --install-missing  Install supported repository packages without prompting."
    echo "  --non-interactive  Never prompt; print recovery commands when blocked."
    echo "  -h, --help         Show this help."
    echo
    echo "Docker, Docker Scout, registry credentials, and QNAP QPKGs are never"
    echo "installed automatically."
}

parse_installer_arguments() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --check-only) CHECK_ONLY="true" ;;
            --install-missing) INSTALL_MISSING="true" ;;
            --non-interactive) NON_INTERACTIVE="true" ;;
            -h|--help)
                show_installer_help
                exit 0
                ;;
            *)
                echo "[ERROR] Unsupported installer option: $1" >&2
                show_installer_help >&2
                exit 64
                ;;
        esac
        shift
    done
}

# -----------------------------------------------------------------------------
# Detect QNAP or a standard Linux package-manager family.
# -----------------------------------------------------------------------------
detect_host_platform() {
    local detected_id=""
    local detected_like=""

    if [ -f /etc/config/uLinux.conf ] ||
        { command -v getcfg >/dev/null 2>&1 && [ -f /etc/config/qpkg.conf ]; }; then
        HOST_FAMILY="qnap"
        HOST_DESCRIPTION="QNAP"
        PACKAGE_MANAGER="qpkg"
        return 0
    fi
    if [ -r /etc/os-release ]; then
        detected_id="$(. /etc/os-release; printf '%s' "${ID:-linux}")"
        detected_like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
        HOST_DESCRIPTION="$(
            . /etc/os-release
            printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}"
        )"
    fi
    case "${detected_id} ${detected_like}" in
        *debian*|*ubuntu*) HOST_FAMILY="debian" ;;
        *fedora*|*rhel*|*centos*|*rocky*|*almalinux*) HOST_FAMILY="rhel" ;;
        *suse*) HOST_FAMILY="suse" ;;
        *arch*|*manjaro*) HOST_FAMILY="arch" ;;
        *alpine*) HOST_FAMILY="alpine" ;;
        *) HOST_FAMILY="generic" ;;
    esac
    for PACKAGE_MANAGER in apt-get dnf yum zypper pacman apk; do
        command -v "$PACKAGE_MANAGER" >/dev/null 2>&1 && return 0
    done
    PACKAGE_MANAGER="none"
}

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
# Resolve Docker from PATH or QNAP Container Station.
# -----------------------------------------------------------------------------
resolve_installer_docker() {
    local candidate=""
    local container_station_root=""

    if command -v docker >/dev/null 2>&1; then
        command -v docker
        return 0
    fi
    if command -v getcfg >/dev/null 2>&1; then
        container_station_root="$(
            getcfg container-station Install_Path -f /etc/config/qpkg.conf \
                2>/dev/null || true
        )"
    fi
    for candidate in \
        "$container_station_root/bin/docker" \
        "$container_station_root/usr/bin/docker"; do
        if [ -n "$container_station_root" ] && [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# -----------------------------------------------------------------------------
# Resolve Python 3.10+ from PATH or the verified QNAP QPKG layout.
# -----------------------------------------------------------------------------
resolve_installer_python() {
    local candidate=""
    local qnap_python_root=""
    local candidates=(python3 python)

    if command -v getcfg >/dev/null 2>&1; then
        qnap_python_root="$(
            getcfg Python3 Install_Path -f /etc/config/qpkg.conf 2>/dev/null || true
        )"
        if [ -n "$qnap_python_root" ]; then
            candidates+=(
                "$qnap_python_root/bin/python3"
                "$qnap_python_root/bin/python"
                "$qnap_python_root/opt/python3/bin/python3"
                "$qnap_python_root/opt/python3/bin/python"
            )
        fi
    fi
    for candidate in "${candidates[@]}"; do
        if { command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; } &&
            "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' \
                >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# -----------------------------------------------------------------------------
# Resolve Scout through Docker or a directly executable user plugin.
# -----------------------------------------------------------------------------
resolve_installer_scout() {
    local candidate=""
    local candidates=(
        "${SWARM_INFO_DOCKER_SCOUT_COMMAND:-}"
        "$(command -v docker-scout 2>/dev/null || true)"
        "$HOME/.docker/cli-plugins/docker-scout"
        "$HOME/.docker/scout/docker-scout"
    )

    if [ -n "$DOCKER_COMMAND" ] &&
        "$DOCKER_COMMAND" scout version >/dev/null 2>&1; then
        printf '%s' "$DOCKER_COMMAND scout"
        return 0
    fi
    for candidate in "${candidates[@]}"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ] &&
            "$candidate" version >/dev/null 2>&1; then
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
# Add a distribution package to the installation plan exactly once.
# -----------------------------------------------------------------------------
add_missing_package() {
    local existing=""
    local package_name="$1"

    [ -n "$package_name" ] || return 0
    for existing in "${MISSING_PACKAGES[@]}"; do
        [ "$existing" = "$package_name" ] && return 0
    done
    MISSING_PACKAGES+=("$package_name")
}

# -----------------------------------------------------------------------------
# Return the package name for one portable capability.
# -----------------------------------------------------------------------------
package_for_capability() {
    case "$1" in
        git|bash|bc) printf '%s' "$1" ;;
        python)
            if [ "$PACKAGE_MANAGER" = "pacman" ]; then
                printf '%s' 'python'
            else
                printf '%s' 'python3'
            fi
            ;;
        *) return 1 ;;
    esac
}

# -----------------------------------------------------------------------------
# Print the exact package-manager command without executing it.
# -----------------------------------------------------------------------------
show_package_install_command() {
    local privilege_prefix=""

    privilege_prefix="$(installer_privilege_prefix)"
    case "$PACKAGE_MANAGER" in
        apt-get)
            echo "        ${privilege_prefix}apt-get update" >&2
            echo "        ${privilege_prefix}apt-get install -y ${MISSING_PACKAGES[*]}" >&2
            ;;
        dnf)
            echo "        ${privilege_prefix}dnf install -y ${MISSING_PACKAGES[*]}" >&2
            ;;
        yum)
            echo "        ${privilege_prefix}yum install -y ${MISSING_PACKAGES[*]}" >&2
            ;;
        zypper)
            printf '        %szypper --non-interactive install \\\n' \
                "$privilege_prefix" >&2
            echo "          ${MISSING_PACKAGES[*]}" >&2
            ;;
        pacman)
            printf '        %spacman -S --needed --noconfirm \\\n' \
                "$privilege_prefix" >&2
            echo "          ${MISSING_PACKAGES[*]}" >&2
            ;;
        apk)
            echo "        ${privilege_prefix}apk add ${MISSING_PACKAGES[*]}" >&2
            ;;
        qpkg)
            echo "        QNAP: install/enable QGit and Python3 from App Center." >&2
            ;;
        *)
            echo "        Install with your distribution tools: ${MISSING_PACKAGES[*]}" >&2
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Execute a package-manager command as root or through sudo.
# -----------------------------------------------------------------------------
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[ERROR] Root access or sudo is required to install packages." >&2
        return 1
    fi
    sudo "$@"
}

# -----------------------------------------------------------------------------
# Install only known repository packages; never install Docker or remote tools.
# -----------------------------------------------------------------------------
install_missing_packages() {
    echo "[INFO] Installing distribution packages: ${MISSING_PACKAGES[*]}"
    case "$PACKAGE_MANAGER" in
        apt-get)
            run_privileged apt-get update
            run_privileged apt-get install -y "${MISSING_PACKAGES[@]}"
            ;;
        dnf) run_privileged dnf install -y "${MISSING_PACKAGES[@]}" ;;
        yum) run_privileged yum install -y "${MISSING_PACKAGES[@]}" ;;
        zypper)
            run_privileged zypper --non-interactive install "${MISSING_PACKAGES[@]}"
            ;;
        pacman)
            run_privileged pacman -S --needed --noconfirm "${MISSING_PACKAGES[@]}"
            ;;
        apk) run_privileged apk add "${MISSING_PACKAGES[@]}" ;;
        *)
            echo "[ERROR] Automatic package installation is unavailable on $HOST_DESCRIPTION." >&2
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Ask once before installing packages from configured distribution repositories.
# -----------------------------------------------------------------------------
should_install_packages() {
    local answer=""

    [ "${#MISSING_PACKAGES[@]}" -gt 0 ] || return 1
    [ "$NON_PACKAGE_FAILURES" -eq 0 ] || return 1
    [ "$PACKAGE_MANAGER" != "none" ] && [ "$PACKAGE_MANAGER" != "qpkg" ] || return 1
    [ "$INSTALL_MISSING" = "true" ] && return 0
    [ "$NON_INTERACTIVE" = "false" ] && [ -t 0 ] || return 1
    echo
    read -r -p "Install the supported repository packages now? [Y/n]: " answer
    case "${answer:-Y}" in
        Y|y|Yes|yes) return 0 ;;
        *) return 1 ;;
    esac
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
check_bootstrap_requirements() {
    echo "Installer requirements:"
    if [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
        echo "[ERROR] Bash 3 or newer is required; found ${BASH_VERSION}." >&2
        INSTALLER_FAILURES=$((INSTALLER_FAILURES + 1))
        NON_PACKAGE_FAILURES=$((NON_PACKAGE_FAILURES + 1))
        add_missing_package "$(package_for_capability bash 2>/dev/null || true)"
    elif [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        echo "[INFO] Bash ${BASH_VERSION} supports portable security checks."
        echo "[INFO] Swarm inventory operations require Bash 4+."
    else
        echo "[OK] Bash ${BASH_VERSION}"
    fi

    if GIT_COMMAND="$(resolve_installer_git)"; then
        echo "[OK] $($GIT_COMMAND --version 2>/dev/null)"
        return 0
    fi
    echo "[ERROR] Git is required to clone and update swarm-info." >&2
    INSTALLER_FAILURES=$((INSTALLER_FAILURES + 1))
    if [ "$HOST_FAMILY" != "qnap" ]; then
        add_missing_package "$(package_for_capability git 2>/dev/null || true)"
    fi
}

check_swarm_runtime_requirements() {
    if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        echo "[ERROR] Bash 4+ is required for Swarm inventory." >&2
        INSTALLER_FAILURES=$((INSTALLER_FAILURES + 1))
        NON_PACKAGE_FAILURES=$((NON_PACKAGE_FAILURES + 1))
        add_missing_package "$(package_for_capability bash 2>/dev/null || true)"
    fi
    if ! command -v bc >/dev/null 2>&1; then
        echo "[WARN] bc is missing; restart-rate calculations are unavailable." >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
        add_missing_package "$(package_for_capability bc 2>/dev/null || true)"
    fi
    if ! "$DOCKER_COMMAND" compose version >/dev/null 2>&1; then
        echo "[WARN] Docker Compose v2 is missing." >&2
        echo "[WARN] Deployment remediation is unavailable." >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
        echo "        https://docs.docker.com/compose/install/linux/" >&2
    fi
}

check_docker_requirements() {
    local docker_state=""

    echo
    echo "Runtime requirements:"
    if ! DOCKER_COMMAND="$(resolve_installer_docker)"; then
        echo "[ERROR] Docker CLI is required." >&2
        echo "        Docker Engine: https://docs.docker.com/engine/install/" >&2
        echo "        QNAP: install/start Container Station from App Center." >&2
        INSTALLER_FAILURES=$((INSTALLER_FAILURES + 1))
        NON_PACKAGE_FAILURES=$((NON_PACKAGE_FAILURES + 1))
        return 0
    fi
    echo "[OK] Docker CLI found at $DOCKER_COMMAND"
    docker_state="$(
        "$DOCKER_COMMAND" info \
            --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' \
            2>/dev/null || true
    )"
    if [ -z "$docker_state" ]; then
        echo "[ERROR] Docker daemon access could not be verified." >&2
        INSTALLER_FAILURES=$((INSTALLER_FAILURES + 1))
        NON_PACKAGE_FAILURES=$((NON_PACKAGE_FAILURES + 1))
        return 0
    fi
    echo "[OK] Docker daemon access is available."
    if [ "$docker_state" = "active|true" ]; then
        echo "[OK] Active Docker Swarm manager detected."
        check_swarm_runtime_requirements
    else
        echo "[OK] Standalone Docker detected; local-container mode applies."
    fi
}

show_qnap_scout_recovery() {
    local qnap_tmp_kb=""

    if [ -e "$HOME/.docker/cli-plugins/docker-scout" ]; then
        echo "[WARN] The existing Scout plugin failed validation." >&2
    fi
    if command -v df >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
        qnap_tmp_kb="$(df -Pk /tmp 2>/dev/null | awk 'END {print $4}')"
    fi
    case "$qnap_tmp_kb" in
        ''|*[!0-9]*) ;;
        *)
            if [ "$qnap_tmp_kb" -lt 262144 ]; then
                echo "[WARN] QNAP /tmp has less than 256 MiB available." >&2
                echo "[WARN] Use a HOME-backed TMPDIR for Scout extraction." >&2
            fi
            ;;
    esac
    echo '        mkdir -p "$HOME/.tmp-scout"' >&2
    echo '        TMPDIR="$HOME/.tmp-scout" sh install-scout.sh' >&2
}

check_scanning_requirements() {
    local python_command=""
    local scout_command=""

    if python_command="$(resolve_installer_python)"; then
        echo "[OK] $($python_command --version 2>&1)"
    else
        echo "[WARN] Python 3.10+ is missing; scans will be unavailable." >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
        if [ "$HOST_FAMILY" != "qnap" ]; then
            add_missing_package "$(package_for_capability python 2>/dev/null || true)"
        else
            echo "        QNAP: install/enable the Python3 QPKG from App Center." >&2
            echo "        Expected path: <Install_Path>/opt/python3/bin/python3" >&2
        fi
    fi

    if scout_command="$(resolve_installer_scout)"; then
        echo "[OK] Docker Scout is available via $scout_command."
        return 0
    fi
    echo "[WARN] Docker Scout is missing; scans will be unavailable." >&2
    OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
    echo "        https://docs.docker.com/scout/install/" >&2
    echo "        Scout is never installed automatically by swarm-info." >&2
    if [ "$HOST_FAMILY" = "qnap" ]; then
        show_qnap_scout_recovery
    fi
}

check_installer_dependencies() {
    INSTALLER_FAILURES=0
    OPTIONAL_FAILURES=0
    NON_PACKAGE_FAILURES=0
    MISSING_PACKAGES=()
    GIT_COMMAND=""
    DOCKER_COMMAND=""

    echo "Detected host: $HOST_DESCRIPTION"
    echo "Package manager: $PACKAGE_MANAGER"
    echo
    check_bootstrap_requirements
    check_docker_requirements
    echo
    echo "Vulnerability-scanning dependencies:"
    check_scanning_requirements

    if [ "${#MISSING_PACKAGES[@]}" -gt 0 ]; then
        echo
        echo "[INFO] Supported repository packages: ${MISSING_PACKAGES[*]}"
        show_package_install_command
    fi
    if [ "$HOST_FAMILY" = "qnap" ] && [ -z "$GIT_COMMAND" ]; then
        echo "        QNAP: install/enable the QGit QPKG from App Center." >&2
    fi
    [ "$INSTALLER_FAILURES" -eq 0 ]
}

# -----------------------------------------------------------------------------
# Normalize HTTPS and SSH GitHub remotes for existing-checkout verification.
# -----------------------------------------------------------------------------
normalize_repository_identity() {
    local value="$1"

    value="${value%.git}"
    value="${value#https://}"
    value="${value#http://}"
    value="${value#ssh://git@}"
    value="${value#git@}"
    value="${value/:/\/}"
    printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

# -----------------------------------------------------------------------------
# Clone swarm-info unless the verified configured checkout already exists.
#
# Side effects:
#     Creates INSTALL_DIRECTORY and downloads the Git repository when absent.
#
# Returns:
#     0 when a usable checkout exists; otherwise the failing Git status.
# -----------------------------------------------------------------------------
prepare_checkout() {
    local configured_identity=""
    local existing_identity=""
    local existing_remote=""
    local install_parent=""

    if [ -d "${INSTALL_DIRECTORY}/.git" ]; then
        existing_remote="$(
            "$GIT_COMMAND" -C "$INSTALL_DIRECTORY" remote get-url origin \
                2>/dev/null || true
        )"
        configured_identity="$(normalize_repository_identity "$REPOSITORY_URL")"
        existing_identity="$(normalize_repository_identity "$existing_remote")"
        if [ -z "$existing_remote" ] || [ "$existing_identity" != "$configured_identity" ]; then
            echo "[ERROR] Existing checkout origin does not match $REPOSITORY_URL" >&2
            echo "[ERROR] Found: ${existing_remote:-no origin remote}" >&2
            return 1
        fi
        if [ ! -f "${INSTALL_DIRECTORY}/get_info.sh" ] ||
            [ ! -f "${INSTALL_DIRECTORY}/VERSION" ]; then
            echo "[ERROR] Existing checkout is missing required swarm-info files." >&2
            return 1
        fi
        echo "[INFO] Existing checkout found; preserving it."
        echo "[INFO] After installation, update it safely with: swarm-info -u"
        return 0
    fi
    if [ -e "$INSTALL_DIRECTORY" ]; then
        echo "[ERROR] Install target exists but is not a Git checkout: $INSTALL_DIRECTORY" >&2
        echo "[ERROR] Move it aside or set SWARM_INFO_INSTALL_DIRECTORY." >&2
        return 1
    fi

    install_parent="$(dirname "$INSTALL_DIRECTORY")"
    echo "[INFO] Cloning swarm-info into ${INSTALL_DIRECTORY}..."
    mkdir -p "$install_parent"
    "$GIT_COMMAND" clone "$REPOSITORY_URL" "$INSTALL_DIRECTORY"
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
#     Ensures the public entry point is executable, creates a symlink, edits
#     existing user profiles, and updates PATH for the installer process.
#
# Returns:
#     0 when all filesystem operations succeed; otherwise a command status.
# -----------------------------------------------------------------------------
configure_command() {
    chmod 0755 "${INSTALL_DIRECTORY}/get_info.sh"
    mkdir -p "$LOCAL_BIN_DIRECTORY"
    ln -sf "${INSTALL_DIRECTORY}/get_info.sh" "${LOCAL_BIN_DIRECTORY}/swarm-info"
    echo "[OK] Command created at ${LOCAL_BIN_DIRECTORY}/swarm-info"

    # POSIX login shells such as QNAP's /bin/sh read .profile, not .bashrc.
    touch "${HOME}/.profile"
    append_export_line "${HOME}/.profile"
    append_export_line "${HOME}/.bashrc"
    append_export_line "${HOME}/.bash_profile"
    append_export_line "${HOME}/.zshrc"

    export PATH="${LOCAL_BIN_DIRECTORY}:$PATH"
    if ! command -v docker >/dev/null 2>&1 && [ -n "$DOCKER_COMMAND" ]; then
        ln -sf "$DOCKER_COMMAND" "${LOCAL_BIN_DIRECTORY}/docker"
        echo "[OK] QNAP Docker command linked at ${LOCAL_BIN_DIRECTORY}/docker"
    fi
}

# -----------------------------------------------------------------------------
# Verify the command link before declaring installation successful.
# -----------------------------------------------------------------------------
verify_installed_command() {
    local installed_command="${LOCAL_BIN_DIRECTORY}/swarm-info"

    if [ ! -x "$installed_command" ]; then
        echo "[ERROR] Installed command is not executable: $installed_command" >&2
        return 1
    fi
    "$installed_command" --version >/dev/null
    echo "[OK] Installed command verified: $($installed_command --version)"
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

    docker_state="$(
        docker info \
            --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' \
            2>/dev/null || true
    )"
    if [ "$docker_state" != "active|true" ]; then
        check_mode="security"
        echo "[INFO] Swarm manager control was not detected."
        echo "[INFO] Validating portable local-container security mode."
    fi
    bash "$dependency_script" "--$check_mode" || dependency_status=$?
    case "$dependency_status" in
        0)
            return 0
            ;;
        2)
            echo
            echo "[WARN] swarm-info is installed, but some security workflows are not ready."
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
    local dependency_status=0
    local locale_file=""
    local installed_version=""

    parse_installer_arguments "$@"
    detect_host_platform
    echo
    echo "Installing swarm-info (Docker inspection and image security CLI)"
    echo "================================================================"
    echo "Install target: $INSTALL_DIRECTORY"
    echo

    check_installer_dependencies || dependency_status=$?
    if [ "$CHECK_ONLY" = "true" ]; then
        echo
        if [ "$dependency_status" -ne 0 ]; then
            echo "[ERROR] Installation preflight found required issues." >&2
            return 1
        fi
        if [ "$OPTIONAL_FAILURES" -gt 0 ]; then
            echo "[WARN] Core installation is ready." >&2
            echo "[WARN] Optional features have $OPTIONAL_FAILURES issue(s)." >&2
            return 2
        fi
        echo "[OK] This host is ready for swarm-info installation."
        return 0
    fi

    if should_install_packages; then
        install_missing_packages
        echo
        echo "[INFO] Rechecking requirements after package installation..."
        dependency_status=0
        check_installer_dependencies || dependency_status=$?
    elif [ "${#MISSING_PACKAGES[@]}" -gt 0 ]; then
        echo "[INFO] Package installation was not requested; continuing where safe."
    fi
    if [ "$dependency_status" -ne 0 ]; then
        echo "[ERROR] Resolve required preflight issues before installing swarm-info." >&2
        return 1
    fi

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
    verify_installed_command

    echo
    verify_runtime_dependencies

    echo
    echo "[OK] $OP_INSTALL_COMPLETE $installed_version"
    echo "     Launch the applicable Swarm or local-container workflow with: swarm-info"
    echo "     Recheck dependencies with: swarm-info --check-dependencies"
    if [ "$HOST_FAMILY" = "qnap" ]; then
        echo
        echo "Optional reboot-persistent QNAP running-container schedule:"
        printf '     sudo %s/swarm-info --install-security-cron \\\n' \
            "$LOCAL_BIN_DIRECTORY"
        echo "       --os qnap --cron-runtime-user $(id -un)"
    fi
    echo
    echo "If the command is not visible in the parent shell yet, run:"
    echo '     . "$HOME/.profile"; hash -r'
}

main "$@"
