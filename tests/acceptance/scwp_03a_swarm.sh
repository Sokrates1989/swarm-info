#!/usr/bin/env bash
# Run the non-mutating SCWP-03A regression on the deployed Ubuntu Swarm stack.

set -Eeuo pipefail
umask 077

script_directory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
swarm_repository="${SCWP_SWARM_REPOSITORY:-/swarm/administration/swarm-info-watchdog}"
stack_name="${SCWP_STACK_NAME:-swarm-info-watchdog}"
expected_version="${SCWP_WATCHDOG_VERSION:-0.5.0}"
web_url="${SCWP_WEB_URL:-https://swarm-info.fe-wi.com}"
vulnerability_report="${SCWP_VULNERABILITY_REPORT:-/info_json/vulnerability_scan.json}"
assessment_report="${SCWP_ASSESSMENT_REPORT:-/info_json/image_update_assessment.json}"

[ "$(id -u)" -eq 0 ] || acceptance_fail "Run this Ubuntu Swarm gate as root."
[ -r /etc/os-release ] || acceptance_fail "/etc/os-release is unavailable."
# shellcheck disable=SC1091
source /etc/os-release
[ "${ID:-}" = "ubuntu" ] || acceptance_fail "This gate requires Ubuntu."
[ -d "$swarm_repository/.git" ] \
    || acceptance_fail "Existing Swarm repository is missing: $swarm_repository"
[ -s "$swarm_repository/swarm-stack.yml" ] \
    || acceptance_fail "Generated Swarm stack is missing."
[ -s "$vulnerability_report" ] \
    || acceptance_fail "Vulnerability evidence is missing: $vulnerability_report"
[ -s "$assessment_report" ] \
    || acceptance_fail "Image assessment evidence is missing: $assessment_report"
command -v curl >/dev/null 2>&1 || acceptance_fail "curl is unavailable."

acceptance_require_clean_checkout "$repository_root"
acceptance_require_clean_checkout "$swarm_repository"
python_command=$(acceptance_python) \
    || acceptance_fail "Python 3.10+ is unavailable."

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/scwp-03a-swarm.XXXXXX") \
    || acceptance_fail "Cannot create the private acceptance directory."
service_file="$temporary_root/services"
container_file="$temporary_root/containers"
platform_file="$temporary_root/platform.json"
web_version_file="$temporary_root/version.json"

cleanup() {
    rm -f -- "$service_file" "$container_file" "$platform_file" "$web_version_file"
    rmdir -- "$temporary_root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}') \
    || acceptance_fail "Docker manager state is unavailable."
[ "$swarm_state" = "active|true" ] \
    || acceptance_fail "This host is not an active Swarm manager: $swarm_state"

if grep -q '/var/run/docker.sock' "$swarm_repository/swarm-stack.yml"; then
    acceptance_fail "The deployed stack source contains a forbidden Docker socket mount."
fi

docker service ls \
    --filter "label=com.docker.stack.namespace=$stack_name" \
    --format '{{.Name}}|{{.Image}}|{{.Replicas}}' >"$service_file" \
    || acceptance_fail "Could not inspect the deployed watchdog services."

"$python_command" - "$service_file" "$stack_name" "$expected_version" <<'PY'
from pathlib import Path
import sys

path, stack, version = sys.argv[1:]
rows = []
for line in Path(path).read_text(encoding="utf-8").splitlines():
    name, image, replicas = line.split("|", 2)
    rows.append((name, image, replicas))
assert rows, f"No services found for stack {stack}."
by_suffix = {}
for name, image, replicas in rows:
    for suffix in ("_admin-api", "_watchdog", "_web"):
        if name == f"{stack}{suffix}":
            by_suffix[suffix] = (image, replicas)
assert set(by_suffix) == {"_admin-api", "_watchdog", "_web"}, rows
expected = {
    "_admin-api": f"sokrates1989/swarm-info-watchdog:{version}",
    "_watchdog": f"sokrates1989/swarm-info-watchdog:{version}",
    "_web": f"sokrates1989/swarm-info-watchdog-web:{version}",
}
for suffix, (image, replicas) in by_suffix.items():
    assert image.split("@", 1)[0] == expected[suffix], (suffix, image, expected[suffix])
    if suffix in {"_admin-api", "_web"}:
        assert replicas == "1/1", (suffix, replicas)
    else:
        assert replicas in {"0/0", "0/1", "1/1"}, (suffix, replicas)
print(f"[OK] Deployed application and web images use explicit tag {version}.")
PY

watchdog_schedule=$(docker service inspect "${stack_name}_watchdog" \
    --format '{{index .Spec.Labels "swarm.cronjob.enable"}}|{{.Spec.Mode.Replicated.Replicas}}') \
    || acceptance_fail "Could not inspect the cron-triggered watchdog service."
[ "$watchdog_schedule" = "true|0" ] \
    || acceptance_fail \
        "Watchdog is not configured as an idle cron-triggered service: $watchdog_schedule"
printf '[OK] Watchdog 0/0 is the expected idle state between scheduled executions.\n'

printf '\n=== Producer and deployment regressions ===\n'
"$repository_root/get_info.sh" --platform-info --json \
    --output-file "$platform_file" \
    || acceptance_fail "Swarm platform detection failed."
acceptance_validate_profile standard-linux swarm "$platform_file" "$python_command" \
    || acceptance_fail "Swarm platform profile validation failed."

(
    CDPATH= cd -- "$swarm_repository"
    "$python_command" -B -m unittest discover -s tests -v
) || acceptance_fail "Swarm deployment repository tests failed."

"$repository_root/get_info.sh" --service-health \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Service-health regression failed."
"$repository_root/get_info.sh" --vulnerability-status \
    --output-file "$vulnerability_report" \
    || [ "$?" -eq 2 ] \
    || acceptance_fail "Vulnerability-status regression failed."

"$python_command" - "$assessment_report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report.get("schema_version") == 1, report
assert report.get("policy", {}).get("deployment_authorized") is False, report
resource_type = report.get("scope", {}).get(
    "resource_type", report.get("policy", {}).get("resource_type", "service")
)
assert resource_type == "service", resource_type
rows = report.get("resources", report.get("services"))
assert isinstance(rows, list) and rows, "Swarm assessment has no service rows."
assert all(row.get("deployment_authorized") is False for row in rows)
print(f"[OK] Swarm assessment retains {len(rows)} non-authorizing service row(s).")
PY

docker ps \
    --filter "label=com.docker.stack.namespace=$stack_name" \
    --format '{{.ID}}|{{.Label "com.docker.swarm.service.name"}}' >"$container_file" \
    || acceptance_fail "Could not locate the deployed admin API task."
admin_container=""
while IFS='|' read -r container_id service_name; do
    if [ "$service_name" = "${stack_name}_admin-api" ]; then
        admin_container="$container_id"
        break
    fi
done <"$container_file"
[ -n "$admin_container" ] || acceptance_fail "The deployed admin API container is unavailable."

docker exec -i "$admin_container" python - <<'PY'
import json
import os
import urllib.request

token_path = os.environ.get(
    "WATCHDOG_ADMIN_TOKEN_FILE",
    "/run/secrets/SWARMINFO_WATCHDOG_ADMIN_TOKEN",
)
with open(token_path, encoding="utf-8") as handle:
    token = handle.read().strip()
assert token, "Admin token is empty."
request = urllib.request.Request(
    "http://127.0.0.1:5000/image-update-assessment",
    headers={"X-Watchdog-Admin-Token": token},
)
with urllib.request.urlopen(request, timeout=15) as response:
    payload = json.load(response)
assert payload.get("success") is True, payload
data = payload.get("data", {})
assert data.get("resource_type") == "service", data
assert data.get("deployment_authorized") is False
assert isinstance(data.get("services"), list) and data["services"]
serialized = json.dumps(data)
for forbidden in ("/var/run/docker.sock", "docker_control_endpoint", "raw_findings"):
    assert forbidden not in serialized, forbidden
print(
    "[OK] Authenticated API returned "
    f"{len(data['services'])} sanitized Swarm service row(s)."
)
PY

curl -fsS "$web_url/health" >/dev/null \
    || acceptance_fail "Public web health endpoint failed: $web_url/health"
curl -fsS "$web_url/version.json" -o "$web_version_file" \
    || acceptance_fail "Public web version endpoint failed."
"$python_command" - "$web_version_file" "$expected_version" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload.get("version") == sys.argv[2], payload
print(f"[OK] Public web bundle reports version {sys.argv[2]}.")
PY

printf '\n============================================================\n'
printf 'Manual browser gate\n'
printf '============================================================\n'
printf '1. Open %s and authenticate.\n' "$web_url"
printf '2. Confirm cards are collapsed and the update card still uses Swarm service wording.\n'
printf '3. Expand the update card; confirm the existing service assessment, compatibility, and thresholds remain available.\n'
printf '4. Send one Telegram Info test and confirm exactly one new message arrives.\n'
printf '5. Confirm no browser action can run Docker, deploy, or recreate a service.\n'
printf '\nDid all five browser checks pass? [y/N] '
IFS= read -r browser_acceptance </dev/tty
case "$browser_acceptance" in
    y|Y|yes|YES) ;;
    *) acceptance_fail "SCWP-03A Ubuntu/Swarm operator acceptance remains pending." ;;
esac

printf '\n============================================================\n'
printf '[PASS] SCWP-03A Ubuntu/Swarm regression passed\n'
printf '============================================================\n'
printf 'Producer: %s\n' "$(git -C "$repository_root" rev-parse HEAD)"
printf 'Swarm deployment: %s\n' "$(git -C "$swarm_repository" rev-parse HEAD)"
printf 'Deployed image tag: %s\n' "$expected_version"
