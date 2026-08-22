#!/bin/bash
# Shared read-only checks for SCWP-01 real-host acceptance entry points.

set -u

acceptance_fail() {
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

acceptance_repository_root() {
    local script_directory=""

    script_directory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[1]}")" && pwd) \
        || acceptance_fail "Cannot resolve the acceptance script directory."
    CDPATH= cd -- "$script_directory/../.." && pwd
}

acceptance_require_clean_checkout() {
    local repository_root="$1"
    local status=""

    status=$(git -C "$repository_root" status --porcelain) \
        || acceptance_fail "Cannot inspect the repository checkout."
    [ -z "$status" ] \
        || acceptance_fail "Acceptance requires a clean checkout."
    printf 'Commit: %s\n' "$(git -C "$repository_root" rev-parse HEAD)"
}

acceptance_python() {
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

acceptance_validate_profile() {
    local expected_adapter="$1"
    local expected_runtime="$2"
    local profile_file="$3"
    local python_command="$4"

    "$python_command" - "$expected_adapter" "$expected_runtime" "$profile_file" <<'PY'
import json
from pathlib import Path
import sys

adapter, runtime, path = sys.argv[1:]
payload = json.loads(Path(path).read_text(encoding="utf-8"))
assert payload.get("schema_version") == 1, payload
assert payload.get("platform_adapter") == adapter, payload
assert payload.get("docker", {}).get("runtime_mode") == runtime, payload
assert payload.get("capabilities", {}).get("scheduler") in {
    "user-crontab",
    "qnap-persistent-crontab",
}, payload
assert "environment" not in payload, payload
print(
    "[OK] Platform profile: "
    f"adapter={adapter} runtime={runtime} "
    f"os={payload.get('os', {}).get('id')}"
)
PY
}
