#!/bin/bash

# =============================================================================
# Module: dependency_check.sh
#
# Description:
#     Verifies the host capabilities used by swarm-info. Core checks cover the
#     Docker manager environment and Git-backed update status. Portable security
#     mode requires only Bash 3+, local Docker access, Python 3.10+, and Docker
#     Scout. Remediation additionally requires Docker Compose v2. Guidance never
#     modifies the host.
#
# Dependencies:
#     - Bash 3+ for --security; Bash 4+ for Swarm modes
#     - Standard POSIX userland commands
# =============================================================================

REQUIRED_FAILURES=0
SCAN_FAILURES=0
CHECK_MODE="all"

dependency_script_directory="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=res/platforms/qnap.sh
source "$dependency_script_directory/platforms/qnap.sh"

# -----------------------------------------------------------------------------
# Print command usage for direct dependency-check execution.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_dependency_check_help() {
    echo "Usage: $0 [--core|--scan|--security|--remediation|--all]"
    echo
    echo "  --core  Require Docker, an active manager node, and Git."
    echo "  --scan  Require core dependencies, Python 3.10+, and Docker Scout."
    echo "  --security  Require portable local-container security dependencies only."
    echo "  --remediation  Add Docker Compose v2 for deployment mapping/remediation."
    echo "  --all   Report core, scanning, and remediation readiness (default)."
}

# -----------------------------------------------------------------------------
# Select the privilege prefix used in Debian/Ubuntu installation examples.
#
# Output:
#     Empty text for root and "sudo " for an unprivileged user.
#
# Returns:
#     Always 0.
# -----------------------------------------------------------------------------
dependency_privilege_prefix() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s' 'sudo '
    fi
}

# -----------------------------------------------------------------------------
# Print official Docker Engine installation guidance.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_docker_install_help() {
    echo "       Install Docker Engine: https://docs.docker.com/engine/install/"
    echo "       QNAP: install and start Container Station, then enable SSH access."
    echo "       QNAP guide: https://docs.qnap.com/application/container-station/"
    echo "       Verify access: docker info"
    echo "       Swarm inventory requires a manager; --security-check can use local containers."
}

# -----------------------------------------------------------------------------
# Print Git installation guidance for supported Linux package families.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_git_install_help() {
    local privilege_prefix=""

    privilege_prefix="$(dependency_privilege_prefix)"
    echo "       Debian/Ubuntu: ${privilege_prefix}apt-get install -y git"
    echo "       Fedora/RHEL:   ${privilege_prefix}dnf install -y git"
    echo "       Legacy RHEL:   ${privilege_prefix}yum install -y git"
    echo "       openSUSE:      ${privilege_prefix}zypper install git"
    echo "       Arch/Manjaro:  ${privilege_prefix}pacman -S --needed git"
    echo "       Alpine:        ${privilege_prefix}apk add git"
    echo "       QNAP: install/enable the QGit QPKG."
}

# -----------------------------------------------------------------------------
# Print calculator installation guidance for restart-rate calculations.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_bc_install_help() {
    local privilege_prefix=""

    privilege_prefix="$(dependency_privilege_prefix)"
    echo "       Debian/Ubuntu: ${privilege_prefix}apt-get install -y bc"
    echo "       Fedora/RHEL:   ${privilege_prefix}dnf install -y bc"
    echo "       Legacy RHEL:   ${privilege_prefix}yum install -y bc"
    echo "       openSUSE:      ${privilege_prefix}zypper install bc"
    echo "       Arch/Manjaro:  ${privilege_prefix}pacman -S --needed bc"
    echo "       Alpine:        ${privilege_prefix}apk add bc"
}

# -----------------------------------------------------------------------------
# Print Python installation guidance for the vulnerability scanner adapter.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_python_install_help() {
    local privilege_prefix=""

    privilege_prefix="$(dependency_privilege_prefix)"
    echo "       Debian/Ubuntu: ${privilege_prefix}apt-get install -y python3"
    echo "       Fedora/RHEL:   ${privilege_prefix}dnf install -y python3"
    echo "       Legacy RHEL:   ${privilege_prefix}yum install -y python3"
    echo "       openSUSE:      ${privilege_prefix}zypper install python3"
    echo "       Arch/Manjaro:  ${privilege_prefix}pacman -S --needed python"
    echo "       Alpine:        ${privilege_prefix}apk add python3"
    echo "       QNAP: install/enable the Python3 QPKG. swarm-info also checks its Install_Path."
    echo "       QNAP verified layout: <Install_Path>/opt/python3/bin/python3"
    echo "       Required version: Python 3.10 or newer."
}

# -----------------------------------------------------------------------------
# Print the official Docker Scout CLI-plugin installation and login guidance.
#
# The command intentionally installs Scout for the current operating-system
# user. The same user must later run swarm-info and own registry credentials.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_docker_scout_install_help() {
    local qnap_tmp_kb=""
    local scout_installer_url="https://raw.githubusercontent.com/docker/scout-cli/main/install.sh"

    echo "       Install Docker Scout for the current user:"
    echo "       Download and inspect the official installer before running it:"
    echo "       curl -fsSL ${scout_installer_url} -o install-scout.sh"
    echo "       sed -n '1,240p' install-scout.sh"
    echo "       sh install-scout.sh"
    if qnap_host_detected &&
        command -v df >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
        qnap_tmp_kb="$(df -Pk /tmp 2>/dev/null | awk 'END {print $4}')"
        case "$qnap_tmp_kb" in
            ''|*[!0-9]*) ;;
            *)
                if [ "$qnap_tmp_kb" -lt 262144 ]; then
                    echo "       QNAP /tmp has less than 256 MiB available."
                    echo "       Use HOME-backed TMPDIR for Scout extraction."
                fi
                ;;
        esac
    fi
    echo '       QNAP: mkdir -p "$HOME/.tmp-scout"'
    echo '       QNAP: TMPDIR="$HOME/.tmp-scout" sh install-scout.sh'
    echo "       docker scout version"
    echo '       Direct fallback: "$HOME/.docker/cli-plugins/docker-scout" version'
    echo "       Registry-backed Swarm scans may additionally require: docker login"
    echo "       About: https://docs.docker.com/scout/"
    echo "       Guide: https://github.com/docker/scout-cli#cli-plugin-installation"
}

# -----------------------------------------------------------------------------
# Verify the minimum host capabilities for local-container security scanning.
#
# This intentionally excludes Git, bc, Docker Compose, and Swarm manager access
# so NAS hosts can run the read-only image check without pretending that Swarm
# inventory and remediation are available.
# -----------------------------------------------------------------------------
check_security_core_dependencies() {
    echo "Portable container-security dependencies:"
    if [ "${BASH_VERSINFO[0]}" -ge 3 ]; then
        echo "[OK] Bash ${BASH_VERSION}"
    else
        record_required_failure "Bash 3 or newer is required; found ${BASH_VERSION}."
    fi

    if ! command -v docker >/dev/null 2>&1; then
        record_required_failure "The Docker CLI is required."
        show_docker_install_help
        return 0
    fi
    echo "[OK] Docker CLI found at $(command -v docker)"
    if docker info >/dev/null 2>&1; then
        echo "[OK] Docker daemon access is available for local inventory."
    else
        record_required_failure "Docker daemon access could not be verified."
        show_docker_install_help
    fi
}

# -----------------------------------------------------------------------------
# Explain the Docker Compose v2 plugin required by deployment mapping.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_docker_compose_install_help() {
    local privilege_prefix=""

    privilege_prefix="$(dependency_privilege_prefix)"
    echo "       Install the Docker Compose v2 CLI plugin:"
    echo "       Debian/Ubuntu: ${privilege_prefix}apt-get install -y docker-compose-plugin"
    echo "       Fedora/RHEL:   ${privilege_prefix}dnf install -y docker-compose-plugin"
    echo "       Verify: docker compose version"
    echo "       Guide: https://docs.docker.com/compose/install/linux/"
}

# -----------------------------------------------------------------------------
# Record one missing required core dependency.
#
# Parameters:
#     $1 - Human-readable failure message.
#
# Side effects:
#     Increments REQUIRED_FAILURES and writes an error to standard error.
#
# Returns:
#     Always 0 so all checks can run and report their state.
# -----------------------------------------------------------------------------
record_required_failure() {
    local message="$1"

    REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
    echo "[ERROR] $message" >&2
}

# -----------------------------------------------------------------------------
# Record one unavailable vulnerability-scanning dependency.
#
# Parameters:
#     $1 - Human-readable failure message.
#
# Side effects:
#     Increments SCAN_FAILURES and writes a warning to standard error.
#
# Returns:
#     Always 0 so all checks can run and report their state.
# -----------------------------------------------------------------------------
record_scan_failure() {
    local message="$1"

    SCAN_FAILURES=$((SCAN_FAILURES + 1))
    echo "[WARN] $message" >&2
}

# -----------------------------------------------------------------------------
# Verify the Bash, Git, Docker daemon, Swarm, and manager requirements.
#
# Side effects:
#     Updates REQUIRED_FAILURES and prints status or recovery guidance.
#
# Returns:
#     Always 0; the caller evaluates the accumulated failure count.
# -----------------------------------------------------------------------------
check_core_dependencies() {
    local docker_state=""
    local git_version=""
    local manager_state=""
    local swarm_state=""

    echo "Core dependencies:"
    if [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
        echo "[OK] Bash ${BASH_VERSION}"
    else
        record_required_failure "Bash 4 or newer is required; found ${BASH_VERSION}."
    fi

    if command -v git >/dev/null 2>&1 &&
        git_version="$(git --version 2>/dev/null)" && [ -n "$git_version" ]; then
        echo "[OK] $git_version"
    else
        record_required_failure "Git is required for installation and update checks."
        show_git_install_help
    fi

    if command -v bc >/dev/null 2>&1; then
        echo "[OK] bc is available for restart-rate calculations."
    else
        record_required_failure "bc is required for accurate restart-rate calculations."
        show_bc_install_help
    fi

    if ! command -v docker >/dev/null 2>&1; then
        record_required_failure "The Docker CLI is required."
        show_docker_install_help
        return 0
    fi
    echo "[OK] Docker CLI found at $(command -v docker)"

    docker_state="$(docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}' 2>/dev/null)"
    if [ -z "$docker_state" ]; then
        record_required_failure "Docker daemon access could not be verified."
        show_docker_install_help
        return 0
    fi

    IFS='|' read -r swarm_state manager_state <<< "$docker_state"
    if [ "$swarm_state" != "active" ]; then
        record_required_failure "Docker Swarm is not active on this node."
    elif [ "$manager_state" != "true" ]; then
        record_required_failure "This node is not a Docker Swarm manager."
    else
        echo "[OK] Docker Swarm is active and this node is a manager."
    fi
}

# -----------------------------------------------------------------------------
# Resolve a Python 3 executable supported by the scanner implementation.
#
# Output:
#     The command name of a Python 3.10+ runtime, when found.
#
# Returns:
#     0 when a compatible runtime exists; otherwise 1.
# -----------------------------------------------------------------------------
resolve_scanner_python() {
    local candidate=""
    local qnap_candidate=""
    local qnap_candidates=""
    local candidates=(python3 python)

    qnap_candidates="$(qnap_python_command_candidates)"
    while IFS= read -r qnap_candidate; do
        if [ -n "$qnap_candidate" ]; then
            candidates+=("$qnap_candidate")
        fi
    done <<< "$qnap_candidates"

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
# Resolve Docker Scout through Docker or its standalone per-user executable.
# -----------------------------------------------------------------------------
resolve_docker_scout() {
    local candidate=""
    local candidates=(
        "${SWARM_INFO_DOCKER_SCOUT_COMMAND:-}"
        "$(command -v docker-scout 2>/dev/null || true)"
        "$HOME/.docker/cli-plugins/docker-scout"
        "$HOME/.docker/scout/docker-scout"
    )

    if command -v docker >/dev/null 2>&1 &&
        docker scout version >/dev/null 2>&1; then
        printf '%s' 'docker scout'
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
# Verify Python and Docker Scout for all-service vulnerability scans.
#
# Side effects:
#     Updates SCAN_FAILURES and prints installation or login guidance.
#
# Returns:
#     Always 0; the caller evaluates the accumulated failure count.
# -----------------------------------------------------------------------------
check_scan_dependencies() {
    local python_command=""
    local scout_command=""

    echo
    echo "Vulnerability scanning dependencies:"
    if python_command="$(resolve_scanner_python)"; then
        echo "[OK] $($python_command --version 2>&1)"
    else
        record_scan_failure "Python 3.10 or newer is required for vulnerability scanning."
        show_python_install_help
    fi

    if scout_command="$(resolve_docker_scout)"; then
        echo "[OK] Docker Scout is available to user $(id -un) via $scout_command."
        if [ "$CHECK_MODE" = "security" ]; then
            echo "[INFO] Local-container mode scans exact local image IDs and needs no registry login."
        else
            echo "[INFO] Private registry fallback requires access for this same user (docker login)."
        fi
    else
        record_scan_failure "Docker Scout is unavailable to user $(id -un)."
        show_docker_scout_install_help
    fi
}

# -----------------------------------------------------------------------------
# Verify Docker Compose v2 for deployment mapping and declarative remediation.
#
# Side effects:
#     Updates SCAN_FAILURES and prints installation guidance.
#
# Returns:
#     Always 0; the caller evaluates the accumulated failure count.
# -----------------------------------------------------------------------------
check_remediation_dependencies() {
    echo
    echo "Deployment remediation dependencies:"
    if command -v docker >/dev/null 2>&1 &&
        docker compose version >/dev/null 2>&1; then
        echo "[OK] Docker Compose v2 is available for deployment mapping and remediation."
    else
        record_scan_failure "Docker Compose v2 is required for deployment mapping and declarative remediation."
        show_docker_compose_install_help
    fi
}

# -----------------------------------------------------------------------------
# Parse the requested check scope.
#
# Parameters:
#     All command-line arguments supplied to the script.
#
# Side effects:
#     Updates CHECK_MODE or exits after displaying help/invalid usage.
#
# Returns:
#     0 for a supported mode; exits 0 for help and 64 for invalid input.
# -----------------------------------------------------------------------------
parse_dependency_arguments() {
    if [ "$#" -gt 1 ]; then
        show_dependency_check_help >&2
        exit 64
    fi

    case "${1:---all}" in
        --core)
            CHECK_MODE="core"
            ;;
        --scan)
            CHECK_MODE="scan"
            ;;
        --security)
            CHECK_MODE="security"
            ;;
        --remediation)
            CHECK_MODE="remediation"
            ;;
        --all)
            CHECK_MODE="all"
            ;;
        -h|--help)
            show_dependency_check_help
            exit 0
            ;;
        *)
            echo "[ERROR] Unsupported dependency-check option: $1" >&2
            show_dependency_check_help >&2
            exit 64
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Run dependency checks and return a readiness-specific status.
#
# Parameters:
#     Optional mode argument accepted by parse_dependency_arguments.
#
# Returns:
#     0 when every selected dependency is ready.
#     1 when one or more required core dependencies are unavailable.
#     2 when core dependencies are ready but selected security tools are
#       unavailable.
#     64 when command-line arguments are invalid.
# -----------------------------------------------------------------------------
main() {
    parse_dependency_arguments "$@"

    echo "swarm-info dependency check"
    echo "==========================="
    if [ "$CHECK_MODE" = "security" ]; then
        check_security_core_dependencies
        check_scan_dependencies
    else
        check_core_dependencies
        if [ "$CHECK_MODE" != "core" ]; then
            check_scan_dependencies
        fi
        if [ "$CHECK_MODE" = "all" ] || [ "$CHECK_MODE" = "remediation" ]; then
            check_remediation_dependencies
        fi
    fi

    echo
    if [ "$REQUIRED_FAILURES" -gt 0 ]; then
        echo "[ERROR] Core readiness failed with $REQUIRED_FAILURES issue(s)." >&2
        return 1
    fi
    if [ "$SCAN_FAILURES" -gt 0 ]; then
        echo "[WARN] Core commands are ready, but selected security workflows have $SCAN_FAILURES issue(s)." >&2
        return 2
    fi

    echo "[OK] All selected swarm-info dependencies are ready."
    return 0
}

main "$@"
