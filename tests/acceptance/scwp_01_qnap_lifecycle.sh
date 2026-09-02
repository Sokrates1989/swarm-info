#!/bin/bash
# Close the QNAP persistent-cron lifecycle across one operator-controlled reboot.

set -Eeuo pipefail

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
helper="$script_directory/scwp_01_qnap_lifecycle.py"
report="${SWARM_INFO_ACCEPTANCE_REPORT_FILE:-/share/Public/swarm-info/security_scan-running.json}"
state_file="${SWARM_INFO_SCWP_01_STATE_FILE:-+/share/Public/swarm-info/scwp_01_qnap_reboot_state.json}"
crontab_path="/etc/config/crontab"
crond_restart="/etc/init.d/crond.sh"
block_begin="# BEGIN swarm-info managed container security scan"
block_end="# END swarm-info managed container security scan"
schedule_removed=false

fail() {
    printf '\n[FAIL] %s\n' "$1" >&2
    exit 1
}

resolve_python() {
    local candidate=""

    candidate=$(acceptance_python || true)
    if [ -n "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    # shellcheck source=res/platforms/qnap.sh
    source "$repository_root/res/platforms/qnap.sh"
    while IFS= read -r candidate; do
        if [ -x "$candidate" ] \
            && "$candidate" -c \
                'import sys; raise SystemExit(sys.version_info < (3, 10))' \
                >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done <<< "$(qnap_python_command_candidates)"
    return 1
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

require_complete_status() {
    local status=0

    "$swarm_info_command" --security-status --os qnap \
        --output-file "$report" || status=$?
    case "$status" in
        0|2) ;;
        *) fail "Scheduled QNAP evidence returned incomplete status $status." ;;
    esac
}

require_managed_block() {
    run_privileged grep -Fqx "$block_begin" "$crontab_path" \
        || fail "Managed QNAP cron opening marker is missing."
    run_privileged grep -Fqx "$block_end" "$crontab_path" \
        || fail "Managed QNAP cron closing marker is missing."
}

require_no_managed_block() {
    if run_privileged grep -Fq "$block_begin" "$crontab_path" \
        || run_privileged grep -Fq "$block_end" "$crontab_path"; then
        fail "Managed QNAP cron markers remain after removal."
    fi
}

unmanaged_hash() {
    run_privileged "$python_bin" "$helper" cron-hash "$crontab_path"
}

install_schedule() {
    run_privileged "$swarm_info_command" --install-security-cron \
        --os qnap \
        --cron-runtime-user "$runtime_user" \
        --container-scope running \
        --output-file "$report" \
        --cron-hour 3 \
        --cron-minute 17 \
        --cache-age-hours 72 \
        --max-age-hours 96 \
        --history-days 14 \
        --scout-timeout-minutes 45 \
        --scan-budget-minutes 240
}

restore_schedule_on_failure() {
    local status=$?

    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$schedule_removed" = true ]; then
        printf '\n[RECOVERY] Reinstalling the managed schedule after a failed check.\n' \
            >&2
        if ! install_schedule; then
            printf '[FAIL] Automatic schedule recovery also failed; reinstall it manually.\n' \
                >&2
        fi
    fi
    exit "$status"
}

prepare_phase() {
    local baseline_hash=""

    [ ! -e "$state_file" ] && [ ! -L "$state_file" ] \
        || fail "Lifecycle state already exists; run verify or inspect $state_file."
    printf '\n=== Run the established QNAP producer gate ===\n'
    /bin/bash "$script_directory/scwp_01_qnap.sh" \
        || fail "SCWP-01 QNAP producer gate failed."
    require_managed_block
    baseline_hash=$(unmanaged_hash) \
        || fail "Cannot hash unrelated persistent cron entries."

    printf '\n=== Restart QNAP cron and recheck persistent state ===\n'
    run_privileged "$crond_restart" restart \
        || fail "QNAP cron daemon restart failed."
    require_managed_block
    [ "$(unmanaged_hash)" = "$baseline_hash" ] \
        || fail "Unrelated persistent cron entries changed during restart."
    require_complete_status

    "$python_bin" "$helper" write-state "$state_file" \
        "$producer_commit" "$runtime_user" "$baseline_hash" \
        || fail "Cannot write private reboot-verification state."
    printf '[OK] Private reboot state written with mode 0600; no cron content recorded.\n'
    printf '\n[NEXT] Reboot the QNAP from its normal administration interface.\n'
    printf 'After the NAS and Container Station are available, run:\n'
    printf 'bash %q verify\n' "$script_directory/scwp_01_qnap_lifecycle.sh"
}

verify_phase() {
    local baseline_hash=""
    local current_hash=""

    [ -f "$state_file" ] && [ ! -L "$state_file" ] \
        || fail "Private prepare-phase state is missing: $state_file"
    baseline_hash=$(
        "$python_bin" "$helper" read-state "$state_file" \
            "$producer_commit" "$runtime_user"
    ) || fail "Reboot-verification state is invalid."

    printf '\n=== Verify the managed schedule after QNAP reboot ===\n'
    require_managed_block
    current_hash=$(unmanaged_hash) \
        || fail "Cannot hash unrelated persistent cron entries after reboot."
    [ "$current_hash" = "$baseline_hash" ] \
        || fail "Unrelated persistent cron entries changed across reboot."
    require_complete_status

    printf '\n=== Remove only the managed block and verify preservation ===\n'
    trap restore_schedule_on_failure EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    run_privileged "$swarm_info_command" --remove-security-cron --os qnap \
        || fail "Managed QNAP schedule removal failed."
    schedule_removed=true
    require_no_managed_block
    [ "$(unmanaged_hash)" = "$baseline_hash" ] \
        || fail "Managed removal changed unrelated persistent cron entries."

    printf '\n=== Reinstall the managed schedule and verify preservation ===\n'
    install_schedule || fail "Managed QNAP schedule reinstall failed."
    schedule_removed=false
    require_managed_block
    [ "$(unmanaged_hash)" = "$baseline_hash" ] \
        || fail "Managed reinstall changed unrelated persistent cron entries."
    require_complete_status
    trap - EXIT HUP INT TERM
    rm -f -- "$state_file"

    printf '\n============================================================\n'
    printf '[PASS] SCWP-01 QNAP reboot lifecycle passed\n'
    printf '============================================================\n'
    printf 'Producer: %s\n' "$producer_commit"
    printf 'Report:   %s\n' "$report"
    printf 'Result:   persistent, removed safely, and reinstalled\n'
}

phase="${1:-}"
case "$phase" in
    prepare|verify) ;;
    *)
        printf 'Usage: %s {prepare|verify}\n' "$0" >&2
        exit 64
        ;;
esac

acceptance_require_clean_checkout "$repository_root"
[ -f /etc/config/uLinux.conf ] \
    || fail "This entry point requires a real QNAP host."
[ -f "$helper" ] || fail "Lifecycle helper is missing: $helper"
[ -f "$crontab_path" ] || fail "QNAP persistent crontab is missing."
[ -x "$crond_restart" ] || fail "QNAP cron restart command is unavailable."
python_bin=$(resolve_python) || fail "Python 3.10 or newer was not found."
swarm_info_command=$(command -v swarm-info 2>/dev/null || true)
swarm_info_command="${swarm_info_command:-$repository_root/get_info.sh}"
[ -x "$swarm_info_command" ] || fail "swarm-info is not executable."
producer_commit=$(git -C "$repository_root" rev-parse HEAD) \
    || fail "Cannot resolve the producer commit."

if [ "$(id -u)" -eq 0 ]; then
    runtime_user="${SWARM_INFO_RUNTIME_USER:-${SUDO_USER:-}}"
    [ -n "$runtime_user" ] && [ "$runtime_user" != root ] \
        || fail "Set SWARM_INFO_RUNTIME_USER to the normal QNAP account."
else
    runtime_user=$(id -un)
    command -v sudo >/dev/null 2>&1 \
        || fail "sudo is required for QNAP persistent-cron lifecycle checks."
    sudo -v || fail "sudo authentication failed."
fi

mkdir -p -- "$(dirname -- "$state_file")" \
    || fail "Cannot create the private lifecycle-state directory."
[ -w "$(dirname -- "$state_file")" ] \
    || fail "Lifecycle-state directory is not writable by $runtime_user."

"${phase}_phase"
