#!/bin/bash
# Exercise SCWP-03C against one namespaced disposable QNAP Compose fixture.

set -Eeuo pipefail
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
current_tag="${SCWP_03C_CURRENT_IMAGE:-alpine:3.18}"
candidate_tag="${SCWP_03C_CANDIDATE_IMAGE:-alpine:3.22}"
project="swarm-info-scwp03c"
web_url="${SCWP_WEB_URL:-http://192.168.178.202:8091}"
fixture_root="${SCWP_03C_FIXTURE_ROOT:-/share/Public/swarm-info/scwp-03c-fixture.$$}"
compose_file="$fixture_root/compose.yml"
policy_file="$fixture_root/policy.json"
focused_report="$fixture_root/focused.json"
plan_file="$fixture_root/plan.json"
platform_file="$fixture_root/platform.json"
accepted="false"

[ "$(id -u)" -ne 0 ] \
    || acceptance_fail "Run this QNAP gate as the non-root Docker/Scout account."
acceptance_require_clean_checkout "$repository_root"
python_command=$(acceptance_python) \
    || acceptance_fail "Python 3.10+ is unavailable."
docker compose version >/dev/null 2>&1 \
    || acceptance_fail "Docker Compose v2 is unavailable."
if [ -n "$(docker container ls --all --quiet \
    --filter "label=com.docker.compose.project=$project")" ]; then
    acceptance_fail "Disposable fixture project already exists: $project"
fi
mkdir -p -- "$fixture_root" \
    || acceptance_fail "Cannot create private fixture directory: $fixture_root"
chmod 0700 "$fixture_root"

cleanup() {
    if [ -f "$compose_file" ]; then
        docker compose \
            --project-name "$project" \
            --project-directory "$fixture_root" \
            -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
    fi
    if [ "$accepted" = "true" ]; then
        rm -f -- \
            "$compose_file" \
            "$policy_file" \
            "$focused_report" \
            "$plan_file" \
            "$plan_file.source-backup" \
            "$plan_file.post-check.json" \
            "$platform_file"
        rmdir -- "$fixture_root" 2>/dev/null || true
    else
        printf '[INFO] Failed-run evidence retained at %s\n' "$fixture_root" >&2
    fi
}
trap cleanup EXIT HUP INT TERM

resolve_repository_digest() {
    local image="$1"

    docker image inspect \
        --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" |
        awk '/^alpine@sha256:[0-9a-f]+$/ { print; exit }'
}

validate_plan_status() {
    local expected="$1"

    "$python_command" - "$plan_file" "$expected" <<'PY'
import json
from pathlib import Path
import sys

path, expected = sys.argv[1:]
plan = json.loads(Path(path).read_text(encoding="utf-8"))
assert plan.get("schema_version") == 1, plan
assert plan.get("status") == expected, plan.get("status")
assert plan.get("compose_service") == "swarm-info-scwp03c/web", plan
print(f"[OK] Transaction plan status: {expected}")
PY
}

printf '\n=== Create digest-pinned disposable Compose fixture ===\n'
docker image pull "$current_tag" >/dev/null \
    || acceptance_fail "Could not pull current fixture image: $current_tag"
docker image pull "$candidate_tag" >/dev/null \
    || acceptance_fail "Could not pull candidate fixture image: $candidate_tag"
current_digest_reference=$(resolve_repository_digest "$current_tag")
candidate_digest_reference=$(resolve_repository_digest "$candidate_tag")
[ -n "$current_digest_reference" ] \
    || acceptance_fail "Current Alpine registry digest is unavailable."
[ -n "$candidate_digest_reference" ] \
    || acceptance_fail "Candidate Alpine registry digest is unavailable."
current_exact="${current_tag}@${current_digest_reference#*@}"
candidate_exact="${candidate_tag}@${candidate_digest_reference#*@}"

printf 'services:\n  web:\n    image: %s\n    command: ["sleep", "86400"]\n' \
    "$current_exact" >"$compose_file"
printf '%s\n' \
    '{' \
    '  "schema_version": 1,' \
    '  "targets": [' \
    '    {' \
    '      "id": "qnap-disposable-alpine-update",' \
    '      "enabled": true,' \
    '      "match": {' \
    '        "compose_service": "swarm-info-scwp03c/web",' \
    '        "repository": "alpine"' \
    '      },' \
    "      \"candidate_image\": \"$candidate_exact\"," \
    '      "backup": {' \
    '        "status": "not_required",' \
    '        "reason": "Repository-owned disposable stateless acceptance fixture."' \
    '      },' \
    '      "source": {' \
    '        "type": "yaml_image",' \
    '        "file": "compose.yml"' \
    '      },' \
    '      "verification": {"timeout_seconds": 120}' \
    '    }' \
    '  ]' \
    '}' >"$policy_file"

docker compose \
    --project-name "$project" \
    --project-directory "$fixture_root" \
    -f "$compose_file" up --detach \
    || acceptance_fail "Could not start the disposable current-image fixture."
current_image_id=$(docker container inspect \
    --format '{{.Image}}' "${project}-web-1") \
    || acceptance_fail "Could not inspect the disposable fixture."

"$repository_root/get_info.sh" --platform-info --json \
    --os qnap --runtime-mode containers --output-file "$platform_file" \
    || acceptance_fail "QNAP platform detection failed."
acceptance_validate_profile qnap containers "$platform_file" "$python_command" \
    || acceptance_fail "QNAP platform profile validation failed."

scan_status=0
"$repository_root/get_info.sh" --security-check \
    --compose-service "$project/web" \
    --os qnap \
    --output-file "$focused_report" || scan_status=$?
[ "$scan_status" -eq 2 ] \
    || acceptance_fail "The current fixture must have fixable findings; got status $scan_status. Override SCWP_03C_CURRENT_IMAGE if registry evidence changed."

printf '\n=== Validate dry-run without source or container mutation ===\n'
"$repository_root/get_info.sh" --compose-remediation \
    --compose-service "$project/web" \
    --vulnerability-report-file "$focused_report" \
    --remediation-policy "$policy_file" \
    --remediation-plan-file "$plan_file" \
    --os qnap \
    || acceptance_fail "Compose remediation dry-run failed."
validate_plan_status planned
grep -Fq "image: $current_exact" "$compose_file" \
    || acceptance_fail "Dry-run changed the Compose source."
[ "$(docker container inspect --format '{{.Image}}' "${project}-web-1")" = "$current_image_id" ] \
    || acceptance_fail "Dry-run changed the fixture container image."

printf '\n=== Confirm the default-No cancellation path ===\n'
printf 'Answer n at the first prompt.\n'
cancel_status=0
"$repository_root/get_info.sh" --compose-remediation --apply \
    --compose-service "$project/web" \
    --vulnerability-report-file "$focused_report" \
    --remediation-policy "$policy_file" \
    --remediation-plan-file "$plan_file" \
    --os qnap || cancel_status=$?
[ "$cancel_status" -eq 4 ] \
    || acceptance_fail "Expected the operator-cancelled status 4; got $cancel_status."
validate_plan_status cancelled
grep -Fq "image: $current_exact" "$compose_file" \
    || acceptance_fail "Cancelled apply changed the Compose source."

printf '\n=== Apply the reviewed fixture update ===\n'
printf 'Answer y to both default-No prompts.\n'
"$repository_root/get_info.sh" --compose-remediation --apply \
    --compose-service "$project/web" \
    --vulnerability-report-file "$focused_report" \
    --remediation-policy "$policy_file" \
    --remediation-plan-file "$plan_file" \
    --os qnap \
    || acceptance_fail "Confirmed Compose fixture update failed."
validate_plan_status deployed
grep -Fq "image: $candidate_exact" "$compose_file" \
    || acceptance_fail "Confirmed apply did not update the exact Compose source."

printf '\n=== Exercise explicit rollback ===\n'
printf 'Answer y to confirm rollback.\n'
"$repository_root/get_info.sh" --rollback-compose-remediation \
    --remediation-plan-file "$plan_file" \
    || acceptance_fail "Explicit Compose rollback failed."
validate_plan_status rolled-back
grep -Fq "image: $current_exact" "$compose_file" \
    || acceptance_fail "Rollback did not restore the exact Compose source."
[ "$(docker container inspect --format '{{.Image}}' "${project}-web-1")" = "$current_image_id" ] \
    || acceptance_fail "Rollback did not restore the exact prior image ID."

printf '\n============================================================\n'
printf 'Manual browser boundary\n'
printf '============================================================\n'
printf '1. Open %s and authenticate.\n' "$web_url"
printf '2. Confirm security evidence remains read-only and no Compose apply/rollback button exists.\n'
printf '3. Confirm the API/web containers still have no Docker socket mount.\n'
printf '\nDid all three browser/boundary checks pass? [y/N] '
IFS= read -r browser_acceptance </dev/tty
case "$browser_acceptance" in
    y|Y|yes|YES) ;;
    *) acceptance_fail "SCWP-03C QNAP browser boundary remains pending." ;;
esac

accepted="true"
printf '\n============================================================\n'
printf '[PASS] SCWP-03C QNAP acceptance passed\n'
printf '============================================================\n'
printf 'Producer: %s\n' "$(git -C "$repository_root" rev-parse HEAD)"
printf 'Fixture: %s -> %s -> rollback confirmed\n' "$current_exact" "$candidate_exact"
