#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="pwchiefy"
REPO_NAME="memxp"

VERSION="${MEMXP_VERSION:-}"
INSTALL_DIR="${MEMXP_INSTALL_DIR:-$HOME/.local/bin}"
VERIFY_ONLY=0
BACKUP=1

usage() {
  cat <<'EOF'
memxp installer

Usage: sh install.sh [--version <tag>] [--install-dir <path>] [--verify-only] [--no-backup]

Options:
  --version <tag>      Target version/tag (e.g. v0.2.0). Defaults to latest release.
  --install-dir <path> Destination directory for memxp binary.
  --verify-only        Download release artifacts and verify checksum only.
  --no-backup          Skip backup/restore copy for existing binary replacement.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --verify-only|--check)
      VERIFY_ONLY=1
      shift
      ;;
    --no-backup)
      BACKUP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "fetching latest release..."
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

case "$(uname -s)" in
  Linux)
    BASE="memxp-linux-x86_64"
    ;;
  Darwin)
    case "$(uname -m)" in
      x86_64)
        BASE="memxp-macos-x86_64"
        ;;
      arm64)
        BASE="memxp-macos-arm64"
        ;;
      *)
        echo "unsupported macOS architecture: $(uname -m)"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "unsupported OS for install.sh: $(uname -s)"
    echo "use install.ps1 on Windows"
    exit 1
    ;;
esac

ASSET="${BASE}.tar.gz"
CHECKSUM_FILE="checksums.txt"
TAG="v${VERSION}"
BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}"
CHECKSUMS_URL="${BASE_URL}/${CHECKSUM_FILE}"
ARTIFACT_URL="${BASE_URL}/${ASSET}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading checksums..."
curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/${CHECKSUM_FILE}"

EXPECTED_SUM="$(awk -v asset="${ASSET}" '$2 == asset { print $1 }' "${TMP_DIR}/${CHECKSUM_FILE}")"
if [[ -z "${EXPECTED_SUM}" ]]; then
  echo "checksum not found for ${ASSET}"
  exit 1
fi

echo "Downloading memxp ${TAG} (${ASSET})..."
curl -fsSL "${ARTIFACT_URL}" -o "${TMP_DIR}/${ASSET}"
# Use platform-appropriate sha256 tool
if command -v sha256sum >/dev/null 2>&1; then
  echo "${EXPECTED_SUM}  ${TMP_DIR}/${ASSET}" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
  echo "${EXPECTED_SUM}  ${TMP_DIR}/${ASSET}" | shasum -a 256 -c -
else
  echo "ERROR: no sha256sum or shasum found. Cannot verify checksum."
  exit 1
fi

tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}"
if [[ ! -x "${TMP_DIR}/memxp" ]]; then
  echo "memxp binary not found in ${ASSET}"
  exit 1
fi

if [[ "${VERIFY_ONLY}" == "1" ]]; then
  echo "checksum-ok: ${TAG}/${ASSET}"
  exit 0
fi

mkdir -p "${INSTALL_DIR}"
TARGET="${INSTALL_DIR}/memxp"

if [[ -f "${TARGET}" && "${BACKUP}" == "1" ]]; then
  backup="${TARGET}.bak.$(date -u +%Y%m%d%H%M%S)"
  cp "${TARGET}" "${backup}"
  echo "backed up existing binary to ${backup}"
fi

cp "${TMP_DIR}/memxp" "${TARGET}"
chmod +x "${TARGET}"

# macOS: clear quarantine and ad-hoc sign (prevents SIGKILL from Gatekeeper)
if [[ "$(uname -s)" == "Darwin" ]]; then
  xattr -d com.apple.provenance "${TARGET}" 2>/dev/null || true
  xattr -d com.apple.quarantine "${TARGET}" 2>/dev/null || true
  codesign --force --sign - "${TARGET}" 2>/dev/null || true
fi

echo "installed to ${TARGET}"

# Install cr-sqlite extension to config directory
VAULT_DIR="${HOME}/.memxp"
mkdir -p "${VAULT_DIR}"

case "$(uname -s)" in
  Darwin) CRSQLITE_EXT="crsqlite.dylib" ;;
  *)      CRSQLITE_EXT="crsqlite.so" ;;
esac

if [[ -f "${TMP_DIR}/${CRSQLITE_EXT}" ]]; then
  cp "${TMP_DIR}/${CRSQLITE_EXT}" "${VAULT_DIR}/${CRSQLITE_EXT}"
  echo "installed cr-sqlite extension to ${VAULT_DIR}/${CRSQLITE_EXT}"
else
  echo "warning: cr-sqlite extension not found in archive (P2P sync requires it)"
fi

if command -v memxp >/dev/null 2>&1; then
  echo "memxp is now available via ${TARGET}"
else
  echo "Add ${INSTALL_DIR} to PATH to run memxp from your shell."
fi
