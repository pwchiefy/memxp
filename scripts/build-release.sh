#!/bin/bash
# Build, sign, and optionally notarize memxp release binaries.
#
# Usage:
#   ./scripts/build-release.sh                    # build + sign
#   ./scripts/build-release.sh --notarize         # build + sign + notarize
#   ./scripts/build-release.sh --version v0.2.0   # set version tag
#
# Prerequisites:
#   - Rust toolchain (cargo)
#   - Apple Developer ID Application certificate in keychain
#   - For notarization: app-specific password stored in keychain
#     xcrun notarytool store-credentials "memxp-notarize" \
#       --apple-id "$MEMXP_APPLE_ID" --team-id "$MEMXP_TEAM_ID"

set -euo pipefail

SIGN_IDENTITY="${MEMXP_SIGN_IDENTITY:-}"
TEAM_ID="${MEMXP_TEAM_ID:-}"
APPLE_ID="${MEMXP_APPLE_ID:-}"

if [[ -z "$SIGN_IDENTITY" ]]; then
  echo "Error: MEMXP_SIGN_IDENTITY not set."
  echo "Export your Apple Developer ID signing identity, e.g.:"
  echo "  export MEMXP_SIGN_IDENTITY=\"Developer ID Application: Your Name (TEAMID)\""
  echo "  export MEMXP_APPLE_ID=\"you@example.com\""
  echo "  export MEMXP_TEAM_ID=\"TEAMID\""
  exit 1
fi

NOTARIZE_PROFILE="memxp-notarize"
NOTARIZE=0
VERSION=""
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --notarize)  NOTARIZE=1; shift ;;
    --version)   VERSION="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/s/^# //p' "$0"
      exit 0
      ;;
    *) shift ;;
  esac
done

# Determine version from Cargo.toml if not specified
if [[ -z "$VERSION" ]]; then
  VERSION="v$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
fi

echo "Building memxp $VERSION"
echo ""

# ── Build ──────────────────────────────────────────────────────
echo "  > Building release binary..."
cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml"
BINARY="$PROJECT_ROOT/target/release/memxp"
echo "  + Built: $BINARY ($(du -h "$BINARY" | cut -f1 | tr -d ' '))"

# ── Sign ───────────────────────────────────────────────────────
echo "  > Signing with Developer ID..."
codesign --force \
  --sign "$SIGN_IDENTITY" \
  --options runtime \
  --timestamp \
  "$BINARY"

# Verify
codesign --verify --deep --strict "$BINARY" 2>&1
echo "  + Signed: $(codesign -dvv "$BINARY" 2>&1 | grep Authority= | head -1)"

# ── Notarize ───────────────────────────────────────────────────
if [[ "$NOTARIZE" == "1" ]]; then
  echo "  > Creating ZIP for notarization..."
  NOTARIZE_ZIP="$DIST_DIR/memxp-notarize.zip"
  mkdir -p "$DIST_DIR"
  ditto -c -k --keepParent "$BINARY" "$NOTARIZE_ZIP"

  echo "  > Submitting to Apple for notarization..."
  xcrun notarytool submit "$NOTARIZE_ZIP" \
    --keychain-profile "$NOTARIZE_PROFILE" \
    --wait

  echo "  + Notarized"
  rm -f "$NOTARIZE_ZIP"
fi

# ── Package ────────────────────────────────────────────────────
echo "  > Packaging release artifacts..."
mkdir -p "$DIST_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  arm64)  PLATFORM="macos-arm64" ;;
  x86_64) PLATFORM="macos-x86_64" ;;
esac

TARBALL="memxp-${PLATFORM}.tar.gz"

# Include cr-sqlite if available
CRSQLITE=""
if [[ -f "$HOME/.vaultp2p/crsqlite.dylib" ]]; then
  CRSQLITE="$HOME/.vaultp2p/crsqlite.dylib"
fi

# Create tarball
cd "$PROJECT_ROOT/target/release"
if [[ -n "$CRSQLITE" ]]; then
  cp "$CRSQLITE" ./crsqlite.dylib
  tar czf "$DIST_DIR/$TARBALL" memxp crsqlite.dylib
  rm -f ./crsqlite.dylib
else
  tar czf "$DIST_DIR/$TARBALL" memxp
fi

# Generate checksums
cd "$DIST_DIR"
shasum -a 256 "$TARBALL" > checksums.txt

echo "  + Package: $DIST_DIR/$TARBALL"
echo "  + Checksum: $DIST_DIR/checksums.txt"

echo ""
echo "  Release artifacts ready in: $DIST_DIR/"
echo ""
echo "  To upload to GitHub:"
echo "    gh release create $VERSION $DIST_DIR/$TARBALL $DIST_DIR/checksums.txt"
echo ""
