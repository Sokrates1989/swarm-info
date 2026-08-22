#!/bin/bash

# =============================================================================
# Module: platforms/qnap.sh
#
# Description:
#     Encapsulates read-only QNAP QPKG/getcfg command discovery needed before
#     Python can start. Scanner, cache, report, and job behavior stays outside
#     this adapter.
# =============================================================================

# Detect the QNAP vendor integration without reading arbitrary configuration.
qnap_host_detected() {
    [ -f /etc/config/uLinux.conf ] \
        || { command -v getcfg >/dev/null 2>&1 \
            && [ -f /etc/config/qpkg.conf ]; }
}

# Print the trusted installation root for one named QPKG when available.
qnap_qpkg_install_path() {
    local package_name="$1"

    command -v getcfg >/dev/null 2>&1 || return 1
    [ -f /etc/config/qpkg.conf ] || return 1
    getcfg "$package_name" Install_Path -f /etc/config/qpkg.conf 2>/dev/null
}

# Print the supported Python3 QPKG executable candidates, one per line.
qnap_python_command_candidates() {
    local python_root=""

    python_root="$(qnap_qpkg_install_path Python3 2>/dev/null || true)"
    [ -n "$python_root" ] || return 0
    printf '%s\n' \
        "$python_root/bin/python3" \
        "$python_root/bin/python" \
        "$python_root/opt/python3/bin/python3" \
        "$python_root/opt/python3/bin/python"
}
