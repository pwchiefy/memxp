#!/bin/sh
# memxp uninstaller — removes memxp, Claude Code registration, and all data
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pwchiefy/memxp/main/scripts/uninstall.sh -o /tmp/uninstall-memxp.sh && sh /tmp/uninstall-memxp.sh

set -u

# Output helpers
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BOLD='\033[1m'
  DIM='\033[2m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BOLD='' DIM='' NC=''
fi

ok()   { printf "  ${GREEN}+${NC} %s\n" "$1"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$1"; }
info() { printf "  ${DIM}%s${NC}\n" "$1"; }

printf "\n"
printf "  ${BOLD}memxp uninstaller${NC}\n"
printf "\n"
printf "  This will remove:\n"
printf "    - memxp binary from ~/.local/bin\n"
printf "    - memxp data directory (~/.memxp or ~/.vaultp2p)\n"
printf "    - memxp MCP registration from Claude Code\n"
printf "    - Shell profile entries\n"
printf "\n"
printf "  ${RED}${BOLD}WARNING: This deletes your vault database and all saved${NC}\n"
printf "  ${RED}${BOLD}credentials, guides, and learnings. This cannot be undone.${NC}\n"
printf "\n"

# Prompt for confirmation
if [ -e /dev/tty ]; then
  printf "  Type ${BOLD}YES${NC} to confirm: "
  read -r CONFIRM < /dev/tty
else
  CONFIRM="NO"
fi

if [ "$CONFIRM" != "YES" ]; then
  printf "\n  Cancelled.\n\n"
  exit 0
fi

printf "\n"

# Remove Claude Code MCP registration
for p in /opt/homebrew/bin/claude /usr/local/bin/claude "$HOME/.local/bin/claude" "$HOME/.npm-global/bin/claude"; do
  if [ -x "$p" ]; then
    "$p" mcp remove memxp -s user 2>/dev/null && ok "Removed memxp from Claude Code" && break
  fi
done
# Also try PATH
if command -v claude >/dev/null 2>&1; then
  claude mcp remove memxp -s user 2>/dev/null || true
fi
# Also clean ~/.mcp.json directly (installer writes here)
if [ -f "$HOME/.mcp.json" ] && command -v python3 >/dev/null 2>&1; then
  python3 -c "
import json
path = '$HOME/.mcp.json'
with open(path, 'r') as f:
    config = json.load(f)
servers = config.get('mcpServers', {})
if 'memxp' in servers:
    del servers['memxp']
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
        f.write('\n')
" 2>/dev/null && ok "Cleaned ~/.mcp.json"
fi

# Clear passphrase from macOS Keychain
if [ "$(uname -s)" = "Darwin" ]; then
  security delete-generic-password -s "com.memxp.credentials" -a "db-passphrase" 2>/dev/null && ok "Cleared memxp passphrase from Keychain"
  security delete-generic-password -s "com.vaultp2p.credentials" -a "db-passphrase" 2>/dev/null || true
fi

# Remove binary and symlinks
for f in "$HOME/.local/bin/memxp" "$HOME/.local/bin/memxp.bak" "$HOME/.local/bin/vaultp2p" "$HOME/.local/bin/memxp-daemon-guard"; do
  if [ -f "$f" ] || [ -L "$f" ]; then
    rm -f "$f"
    ok "Removed $f"
  fi
done

# Remove data directories
for d in "$HOME/.memxp" "$HOME/.vaultp2p"; do
  if [ -d "$d" ] || [ -L "$d" ]; then
    rm -rf "$d"
    ok "Removed $d"
  fi
done

# Remove launchd plist if present
PLIST="$HOME/Library/LaunchAgents/com.memxp.sync-daemon.plist"
if [ -f "$PLIST" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  ok "Removed launchd daemon"
fi

# Clean shell profile entries
for profile in "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.profile" "$HOME/.bashrc"; do
  if [ -f "$profile" ]; then
    if grep -q 'memxp' "$profile" 2>/dev/null || grep -q 'vaultp2p' "$profile" 2>/dev/null; then
      sed -i '' '/memxp/d;/vaultp2p/d' "$profile" 2>/dev/null || \
      sed -i '/memxp/d;/vaultp2p/d' "$profile" 2>/dev/null || true
      ok "Cleaned $profile"
    fi
  fi
done

# Remove Meditation.md if in default location
if [ -f "$HOME/Developer/Meditation.md" ]; then
  rm -f "$HOME/Developer/Meditation.md"
  ok "Removed ~/Developer/Meditation.md"
fi

printf "\n"
printf "  ${GREEN}${BOLD}memxp has been completely removed.${NC}\n"
printf "\n"
