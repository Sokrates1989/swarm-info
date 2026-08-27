#!/usr/bin/env bash
# Run the non-mutating SCWP-03B regression on one Ubuntu Swarm manager.

set -Eeuo pipefail
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/acceptance/scwp_01_common.sh
source "$script_directory/scwp_01_common.sh"

repository_root=$(acceptance_repository_root)
swarm_repository="${SCWP_SWARM_REPOSITORY:-/swarm/administration/swarm-info-watchdog}"
stack_name="${SCWP_STACK_NAME:-swarm-info-watchdog}"
expected_version="${SCWP_WATCHDOG_VERSION:-0.6.0}"
web_url="${SCWP_WEB_URL:-https://swarm-info.fe-wi.com}"

[ "$(id -u)" -eq 0 ] || acceptance_fail "Run this Ubuntu Swarm gate as root."
[ -r /etc/os-release ] || acceptance_fail "/etc/os-release is unavailable."
# shellcheck disable=SC1091
source /etc/os-release
[ "${ID:-}" = "ubuntu" ] || acceptance_fail "This gate requires Ubuntu."
[ -d "$swarm_repository/.git" ] \
    || acceptance_fail "Existing Swarm repository is missing: $swarm_repository"
[ -s "$swarm_repository/swarm-stack.yml" ] \
    || acceptance_fail "Generated Swarm stack is missing."
command -v curl >/dev/null 2>&1 || acceptance_fail "curl is unavailable."

acceptance_require_clean_checkout "$repository_root"
acceptance_require_clean_checkout "$swarm_repository"
python_command=$(acceptance_python) \
    || acceptance_fail "Python 3.10+ is unavailable."

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/scwp-03b-swarm.XXXXXX") \
    || acceptance_fail "Cannot create the private acceptance directory."
platform_file="$temporary_root/platform.json"
cleanup_report="$temporary_root/image_cleanup.json"
images_before="$temporary_root/images-before"
images_after="$temporary_root/images-after"
container_images="$temporary_root/container-images"
services_file="$temporary_root/services"
version_file="$temporary_root/version.json"

cleanup() {
    rm -f -- \
        "$platform_file" \
        "$cleanup_report" \
        "$images_before" \
        "$images_after" \
        "$container_images" \
        "$services_file" \
        "$version_file"
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
for standalone_setting in RUNTIME_HARDENING_FILE IMAGE_CLEANUP_FILE; do
    if grep -q "$standalone_setting" "$swarm_repository/swarm-stack.yml"; then
        acceptance_fail "Standalone evidence setting leaked into the Swarm stack: $standalone_setting"
    fi
done

printf '\n=== Swarm capability and deployment regression ===\n'
"$repository_root/get_info.sh" --platform-info --json \
    --output-file "$platform_file" \
    || acceptance_fail "Swarm platform detection failed."
acceptance_validate_profile standard-linux swarm "$platform_file" "$python_command" \
    || acceptance_fail "Swarm platform profile validation failed."

"$python_command" - "$platform_file" <<'PY'
import json
import sys

profile = json.load(open(sys.argv[1], encoding="utf-8"))
capabilities = profile.get("capabilities", {})
assert capabilities.get("runtime_hardening") is False, capabilities
assert capabilities.get("image_cleanup") is True, capabilities
print("[OK] Standalone hardening stays disabled while manager cleanup remains available.")
PY

docker service ls \
    --filter "label=com.docker.stack.namespace=$stack_name" \
    --format '{{.Name}}|{{.Image}}|{{.Replicas}}' >"$services_file" \
    || acceptance_fail "Could not inspect deployed watchdog services."
"$python_command" - "$services_file" "$stack_name" "$expected_version" <<'PY'
from pathlib import Path
import sys

path, stack, version = sys.argv[1:]
rows = [line.split("|", 2) for line in Path(path).read_text(encoding="utf-8").splitlines()]
expected = {
    f"{stack}_admin-api": f"sokrates1989/swarm-info-watchdog:{version}",
    f"{stack}_watchdog": f"sokrates1989/swarm-info-watchdog:{version}",
    f"{stack}_web": f"sokrates1989/swarm-info-watchdog-web:{version}",
}
actual = {name: image.split("@", 1)[0] for name, image, _replicas in rows}
assert expected.items() <= actual.items(), (expected, actual)
print(f"[OK] Deployed watchdog services use explicit tag {version}.")
PY

printf '\n=== Preview cleanup without changing the manager image inventory ===\n'
docker image ls --all --no-trunc --quiet | sort -u >"$images_before"
docker container ls --all --quiet --no-trunc | while IFS= read -r container_id; do
    [ -n "$container_id" ] || continue
    docker container inspect --format '{{.Image}}' "$container_id"
done | sort -u >"$container_images"

"$repository_root/get_info.sh" \
    --image-cleanup \
    --output-file "$cleanup_report" \
    || acceptance_fail "Swarm-manager cleanup preview failed."

docker image ls --all --no-trunc --quiet | sort -u >"$images_after"
cmp -s "$images_before" "$images_after" \
    || acceptance_fail "Image inventory changed during preview-only regression."

"$python_command" - "$cleanup_report" "$container_images" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report.get("schema_version") == 2, report
assert report.get("runtime") == "swarm-manager", report.get("runtime")
assert report.get("apply_allowed") is True, report.get("blockers")
assert report.get("last_result", {}).get("mode") == "preview"
assert report.get("last_result", {}).get("status") in {"preview", "no-candidates"}
candidate_ids = {
    candidate.get("image_id") for candidate in report.get("candidates", [])
}
container_ids = {
    line.strip()
    for line in open(sys.argv[2], encoding="utf-8")
    if line.strip()
}
assert candidate_ids.isdisjoint(container_ids), (
    "A manager container image appears in cleanup candidates."
)
assert report.get("summary", {}).get("protected_images", 0) >= len(container_ids)
print(
    "[OK] Swarm-manager preview protected "
    f"{report['summary']['protected_images']} image(s); no image was removed."
)
PY

printf '\n=== Existing Swarm repository regression suite ===\n'
(
    CDPATH='' cd -- "$swarm_repository"
    "$python_command" -B -m unittest discover -s tests -v
) || acceptance_fail "Swarm deployment repository tests failed."

curl -fsS "$web_url/health" >/dev/null \
    || acceptance_fail "Public web health endpoint failed: $web_url/health"
curl -fsS "$web_url/version.json" -o "$version_file" \
    || acceptance_fail "Public web version endpoint failed."
"$python_command" - "$version_file" "$expected_version" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload.get("version") == sys.argv[2], payload
print(f"[OK] Public web bundle reports version {sys.argv[2]}.")
PY

printf '\n============================================================\n'
printf 'Manual browser regression\n'
printf '============================================================\n'
printf '1. Open %s and authenticate.\n' "$web_url"
printf '2. Confirm the standalone Laufzeithärtung and Image-Bereinigung cards are not shown in Swarm mode.\n'
printf '3. Confirm existing Swarm image assessment, service health, settings, and thresholds still render.\n'
printf '4. Send one Telegram Info test and confirm exactly one new message arrives.\n'
printf '5. Confirm no browser action can run Docker, deploy, or remove an image.\n'
printf '\nDid all five browser checks pass? [y/N] '
IFS= read -r browser_acceptance </dev/tty
case "$browser_acceptance" in
    y|Y|yes|YES) ;;
    *) acceptance_fail "SCWP-03B Ubuntu/Swarm operator regression remains pending." ;;
esac

printf '\n============================================================\n'
printf '[PASS] SCWP-03B Ubuntu/Swarm regression passed\n'
printf '============================================================\n'
printf 'Producer: %s\n' "$(git -C "$repository_root" rev-parse HEAD)"
printf 'Swarm deployment: %s\n' "$(git -C "$swarm_repository" rev-parse HEAD)"
printf 'Deployed image tag: %s\n' "$expected_version"
