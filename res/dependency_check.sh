#!/bin/bash

# =============================================================================
# Module: dependency_check.sh
#
# Description:
#     Verifies the host capabilities used by swarm-info. Core checks cover the
#     Docker manager environment and Git-backed update status. Security checks
#     add Python 3.10+ and Docker Scout; remediation checks additionally require
#     Docker Compose v2. Guidance never modifies the host.
#
# Dependencies:
#     - Bash 4+
#     - Standard POSIX userland commands
# =============================================================================

REQUIRED_FAILURES=0
SCAN_FAILURES=0
CHECK_MODE="all"

# -----------------------------------------------------------------------------
# Print command usage for direct dependency-check execution.
#
# Returns:
#     Nothing.
# -----------------------------------------------------------------------------
show_dependency_check_help() {
    echo "Usage: $0 [--core|--scan|--remediation|--all]"
    echo
    echo "  --core  Require Docker, an active manager node, and Git."
    echo "  --scan  Require core dependencies, Python 3.10+, and Docker Scout."
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
    echo "       Verify access: docker info"
    echo "       Run swarm-info from a Docker Swarm manager node."
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
    echo "       RHEL/Fedora:   ${privilege_prefix}dnf install -y git"
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
    echo "       RHEL/Fedora:   ${privilege_prefix}dnf install -y bc"
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
    echo "       RHEL/Fedora:   ${privilege_prefix}dnf install -y python3"
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
    local privilege_prefix=""
    local scout_installer_url="https://raw.githubusercontent.com/docker/scout-cli/main/install.sh"

    privilege_prefix="$(dependency_privilege_prefix)"
    echo "       Install Docker Scout for the current user:"
    echo "       ${privilege_prefix}apt-get update"
    echo "       ${privilege_prefix}apt-get install -y curl"
    echo "       curl -sSfL ${scout_installer_url} | sh -s --"
    echo "       docker scout version"
    echo "       docker login"
    echo "       About: https://docs.docker.com/scout/"
    echo "       Guide: https://github.com/docker/scout-cli#cli-plugin-installation"
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
    echo "       RHEL/Fedora:   ${privilege_prefix}dnf install -y docker-compose-plugin"
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

    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' \
                >/dev/null 2>&1; then
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

    echo
    echo "Vulnerability scanning dependencies:"
    if python_command="$(resolve_scanner_python)"; then
        echo "[OK] $($python_command --version 2>&1)"
    else
        record_scan_failure "Python 3.10 or newer is required for vulnerability scanning."
        show_python_install_help
    fi

    if command -v docker >/dev/null 2>&1 &&
        docker scout version >/dev/null 2>&1; then
        echo "[OK] Docker Scout is available to user $(id -un)."
        echo "[INFO] Private images require registry access for this same user (docker login)."
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
    check_core_dependencies
    if [ "$CHECK_MODE" != "core" ]; then
        check_scan_dependencies
    fi
    if [ "$CHECK_MODE" = "all" ] || [ "$CHECK_MODE" = "remediation" ]; then
        check_remediation_dependencies
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
