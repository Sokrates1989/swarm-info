#!/bin/bash
#
# Validate the deployed QNAP running-container security schedule end to end.
#
# This operator-run workflow installs the owned persistent cron block, reuses
# fresh evidence when possible, and verifies report, cache, and lock contracts.
# It never removes images, changes containers, or edits unrelated cron entries.
#

set -u

script_directory="$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
checkout="$(CDPATH= cd "$script_directory/.." && pwd -P)"
acceptance_helper="$script_directory/qnap_security_schedule_acceptance.py"
. "$checkout/res/platforms/qnap.sh"
report="${SWARM_INFO_ACCEPTANCE_REPORT_FILE:-/share/Public/swarm-info/security_scan-running.json}"
cron_log="${report%.json}.log"
lock_holder=""
ready_file=""
release_file=""

# Print one fatal acceptance result and stop without concealing the cause.
fail() {
    printf '\n[FAIL] %s\n' "$1" >&2
    exit 1
}

# Locate QNAP's supported Python 3.10+ command, including its QPKG paths.
resolve_python() {
    local candidate=""

    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 \
            && "$candidate" -c \
                'import sys; raise SystemExit(sys.version_info < (3, 10))' \
                >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    while IFS= read -r candidate; do
        if [ -x "$candidate" ] \
            && "$candidate" -c \
                'import sys; raise SystemExit(sys.version_info < (3, 10))' \
                >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done < <(qnap_python_command_candidates)
    return 1
}
# Run the exact command as root only when QNAP persistence requires it.
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Accept only the documented complete scan states: clean or vulnerable.
require_complete_status() {
    local status="$1"
    local operation="$2"

    case "$status" in
        0|2) return 0 ;;
        *) fail "$operation returned incomplete exit code $status." ;;
    esac
}

# Execute the same bounded policy written to the managed cron entry.
run_scheduled_check() {
    "$swarm_info_command" --scheduled-security-check \
        --container-mode \
        --container-scope running \
        --os qnap \
        --platform auto \
        --output-file "$report" \
        --cache-age-hours 72 \
        --max-age-hours 96 \
        --history-days 14 \
        --scout-timeout-minutes 45 \
        --scan-budget-minutes 240
}

# Stop a background lock helper and remove only its per-process ready marker.
cleanup_lock_test() {
    if [ -n "$lock_holder" ]; then
        kill "$lock_holder" 2>/dev/null || true
        wait "$lock_holder" 2>/dev/null || true
    fi
    if [ -n "$ready_file" ]; then
        rm -f "$ready_file"
    fi
    if [ -n "$release_file" ]; then
        rm -f "$release_file"
    fi
}

trap cleanup_lock_test EXIT
trap 'exit 130' HUP INT TERM

[ -d "$checkout/.git" ] || fail "Checkout not found at $checkout."
[ -f "$acceptance_helper" ] || fail "Acceptance helper is missing."

python_bin="$(resolve_python)" \
    || fail "Python 3.10 or newer was not found."
swarm_info_command="$(command -v swarm-info 2>/dev/null || true)"
[ -n "$swarm_info_command" ] || swarm_info_command="$checkout/get_info.sh"
[ -x "$swarm_info_command" ] || fail "swarm-info is not executable."

cd "$checkout" || fail "Cannot enter $checkout."
checkout_status="$(git status --short)" \
    || fail "Cannot inspect the checkout state."
[ -z "$checkout_status" ] \
    || fail "The checkout has local changes; inspect git status first."

printf '\n=== 1. Verify installed release and dependencies ===\n'
version_text="$("$swarm_info_command" --version)" \
    || fail "Cannot read the installed swarm-info version."
version="${version_text##* }"
printf 'Installed: %s\n' "$version_text"
"$python_bin" "$acceptance_helper" validate-version "$version" \
    || fail "Install the current swarm-info release before acceptance."
"$swarm_info_command" --check-dependencies \
    || fail "Required container-security dependencies are unavailable."

mkdir -p "$(dirname "$report")" \
    || fail "Cannot create the report directory."
[ -w "$(dirname "$report")" ] \
    || fail "The report directory is not writable by $(id -un)."

if [ "$(id -u)" -eq 0 ]; then
    runtime_user="${SWARM_INFO_RUNTIME_USER:-${SUDO_USER:-}}"
    [ -n "$runtime_user" ] && [ "$runtime_user" != "root" ] \
        || fail "Set SWARM_INFO_RUNTIME_USER to the normal QNAP account."
else
    runtime_user="$(id -un)"
    command -v sudo >/dev/null 2>&1 \
        || fail "sudo is required once to update QNAP's persistent crontab."
    printf '\n=== 2. Obtain the one-time QNAP cron privilege ===\n'
    sudo -v || fail "sudo authentication failed."
fi

printf '\n=== 3. Install and verify the persistent QNAP schedule ===\n'
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
    --scan-budget-minutes 240 \
    || fail "Persistent cron installation failed."

cron_block="$(
    run_privileged sed -n \
        '/BEGIN swarm-info managed container security scan/,/END swarm-info managed container security scan/p' \
        /etc/config/crontab
)" || fail "Cannot read QNAP's persistent crontab."
printf '\n%s\n' "$cron_block"
for expected in \
    "BEGIN swarm-info managed container security scan" \
    "--scheduled-security-check" \
    "--container-scope running" \
    "--cache-age-hours 72" \
    "--max-age-hours 96" \
    "--scout-timeout-minutes 45" \
    "--scan-budget-minutes 240" \
    "/bin/su - $runtime_user"
do
    case "$cron_block" in
        *"$expected"*) ;;
        *) fail "Persistent cron block is missing: $expected" ;;
    esac
done

printf '\n=== 4. Run or reuse the exact scheduled evidence ===\n'
printf 'A missing, stale, or changed scope can require a full multi-hour scan.\n'
scan_started="$(date +%s)"
scan_status=0
run_scheduled_check || scan_status=$?
scan_elapsed=$(($(date +%s) - scan_started))
printf 'Scheduled-job exit code: %s\n' "$scan_status"
printf 'Scheduled-job duration:  %s seconds\n' "$scan_elapsed"
require_complete_status "$scan_status" "Scheduled security check"

printf '\n=== 5. Validate evidence and freshness ===\n'
"$python_bin" "$acceptance_helper" validate-report "$report" \
    || fail "Published evidence failed its contract checks."
first_completed_at="$(
    "$python_bin" "$acceptance_helper" completed-at "$report"
)" || fail "Cannot read the first completion timestamp."
security_status=0
"$swarm_info_command" --security-status \
    --output-file "$report" \
    --max-age-hours 96 \
    || security_status=$?
require_complete_status "$security_status" "Freshness check"

printf '\n=== 6. Verify immediate cache reuse ===\n'
reuse_started="$(date +%s)"
reuse_status=0
run_scheduled_check || reuse_status=$?
reuse_elapsed=$(($(date +%s) - reuse_started))
require_complete_status "$reuse_status" "Cache-reuse check"
second_completed_at="$(
    "$python_bin" "$acceptance_helper" completed-at "$report"
)" || fail "Cannot read the reused completion timestamp."
[ "$first_completed_at" = "$second_completed_at" ] \
    || fail "The second invocation rescanned instead of reusing evidence."
[ "$reuse_elapsed" -lt 180 ] \
    || fail "Cache reuse took unexpectedly long: $reuse_elapsed seconds."
printf '[OK] Matching evidence reused in %s seconds.\n' "$reuse_elapsed"

printf '\n=== 7. Verify non-overlap locking ===\n'
lock_file="${report}.lock"
ready_file="${lock_file}.acceptance-ready.$$"
release_file="${lock_file}.acceptance-release.$$"
"$python_bin" "$acceptance_helper" hold-lock \
    "$lock_file" "$ready_file" "$release_file" --timeout-seconds 120 &
lock_holder=$!
waited=0
while [ ! -f "$ready_file" ] && [ "$waited" -lt 20 ]; do
    if ! kill -0 "$lock_holder" 2>/dev/null; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done
[ -f "$ready_file" ] || fail "Could not establish the acceptance-test lock."
lock_status=0
run_scheduled_check || lock_status=$?
[ "$lock_status" -eq 0 ] \
    || fail "Overlapping invocation returned $lock_status instead of skipping."
locked_completed_at="$(
    "$python_bin" "$acceptance_helper" completed-at "$report"
)" || fail "Cannot read the locked completion timestamp."
[ "$locked_completed_at" = "$first_completed_at" ] \
    || fail "The locked invocation unexpectedly replaced the report."
printf 'release\n' > "$release_file" \
    || fail "Cannot release the acceptance-test lock."
wait "$lock_holder" || fail "The acceptance lock helper failed."
lock_holder=""
rm -f "$ready_file" "$release_file"
ready_file=""
release_file=""
printf '[OK] Overlapping invocation skipped without replacing evidence.\n'

printf '\n============================================================\n'
printf '[PASS] QNAP scheduled container security accepted\n'
printf '============================================================\n'
printf 'Version:       %s\n' "$version"
printf 'Report:        %s\n' "$report"
printf 'Cron log:      %s\n' "$cron_log"
printf 'Next schedule: daily at 03:17 QNAP local time\n'
printf 'Rescan policy: after 72h, or immediately when running scope changes\n'
printf 'Stale after:   96h\n'
printf 'Scan limits:   45m per image, 240m total\n'
printf '\nThe persistent cron entry remains installed.\n'
