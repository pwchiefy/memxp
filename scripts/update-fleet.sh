#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="pwchiefy"
REPO_NAME="memxp"

INVENTORY_FILE=""
VERSION=""
CONCURRENCY=5
SSH_USER=""
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no"

usage() {
  cat <<'EOF'
Update memxp across a fleet via SSH.

Usage:
  ./update-fleet.sh --inventory <yaml|json> [--version <tag>] [--concurrency 5] [--ssh-user user]

The inventory file may be:
  - JSON: ["host1", "user@host2"]
  - YAML: ["host1", "user@host2"]
         (simple list format)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory)
      INVENTORY_FILE="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="${2:-5}"
      shift 2
      ;;
    --ssh-user)
      SSH_USER="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${INVENTORY_FILE}" || ! -f "${INVENTORY_FILE}" ]]; then
  echo "inventory file required and must exist"
  usage
  exit 1
fi

if [[ -z "${VERSION}" ]]; then
  VERSION="$(curl -fsSL -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" \
    | python3 - <<'PY'
import json, sys
data = json.load(sys.stdin)
print(data.get("tag_name", "").lstrip("v"))
PY
)"
  if [[ -z "${VERSION}" ]]; then
    echo "unable to determine latest release tag"
    exit 1
  fi
fi

VERSION="${VERSION#v}"
SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/v${VERSION}/scripts/install.sh"

readarray -t HOSTS < <(python3 - "$INVENTORY_FILE" <<'PY'
import json
import os
import sys

path = sys.argv[1]
if path.endswith(".json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
elif path.endswith(".yml") or path.endswith(".yaml"):
    try:
        import yaml  # type: ignore
    except Exception:
        text = open(path, "r", encoding="utf-8").read().splitlines()
        data = []
        for line in text:
            stripped = line.strip()
            if stripped.startswith("-"):
                data.append(stripped[1:].strip().strip("'\\\""))
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
else:
    raise SystemExit("unsupported inventory format. Use .json or .yml/.yaml")

if not isinstance(data, list):
    raise SystemExit("inventory must be a list")

for item in data:
    if isinstance(item, str) and item.strip():
        print(item.strip())
PY
)

if [[ "${#HOSTS[@]}" -eq 0 ]]; then
  echo "no hosts found in inventory"
  exit 1
fi

echo "Updating ${#HOSTS[@]} host(s) to ${VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
RESULTS="${TMP_DIR}/results.txt"
touch "${RESULTS}"

run_one() {
  local host="$1"
  local target="${host}"
  if [[ -n "${SSH_USER}" ]]; then
    target="${SSH_USER}@${host}"
  fi
  local remote_version="v${VERSION#v}"

  if ssh ${SSH_OPTS} "${target}" "curl -fsSL ${SCRIPT_URL} | sh -s -- --version ${remote_version}"; then
    echo "${host},ok" >> "${RESULTS}"
  else
    echo "${host},failed" >> "${RESULTS}"
  fi
}

export -f run_one
export SSH_OPTS SSH_USER VERSION SCRIPT_URL RESULTS

for host in "${HOSTS[@]}"; do
  run_one "${host}" &
  while (( $(jobs -r | wc -l) >= CONCURRENCY )); do
    wait -n
  done
done
wait

success=0
failed=0
failed_hosts=()
while IFS=',' read -r host status; do
  if [[ "${status}" == "ok" ]]; then
    ((success+=1))
  else
    ((failed+=1))
    failed_hosts+=("${host}")
  fi
done < "${RESULTS}"

echo "Summary: ${success} success, ${failed} failed"
if (( failed > 0 )); then
  echo "Failed hosts:"
  printf '  - %s\n' "${failed_hosts[@]}"
  echo
  echo "Rollback/retry command:"
  for h in "${failed_hosts[@]}"; do
    echo "  ssh ${h} \"curl -fsSL ${SCRIPT_URL} | sh -s -- --version v${VERSION#v}\""
  done
  exit 1
fi

echo "Fleet rollout complete."
