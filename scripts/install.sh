#!/bin/sh
# memxp — a second brain for your coding agent
#
# Today's coding agents are spiky geniuses with periodic amnesia.
# memxp levels them up with a second brain — YOUR second brain,
# the one you never had time to set up in a trendy task manager.
#
# Never attempt a task alone again. You and your agent share a record
# of what makes your work unique — what works, what fails, and how
# to give each session the best shot at success.
#
# Usage (download then run — so sudo and prompts work):
#   curl -fsSL https://raw.githubusercontent.com/pwchiefy/memxp/main/scripts/install.sh -o /tmp/install-memxp.sh && sh /tmp/install-memxp.sh
#
# Options:
#   --version v0.1.0    Install a specific version
#   --skip-claude       Don't install Claude Code
#   --auto-approve      Pre-approve memxp MCP tools (skip per-call prompts)
#
# What this sets up:
#   1. Claude Code (your AI partner, if not already installed)
#   2. memxp (encrypted second brain — guides, credentials, learnings)
#   3. Your project workspace
#   4. The learning loop — so your agent gets better every session
#
# After install, open Terminal and run: cd ~/Developer && claude
# Then say: "let's get started"
#
# Trust model:
#   memxp is a single-user, machine-local tool. The local agent process
#   (Claude Code MCP) is trusted. The passphrase in ~/.memxp/env (chmod 600)
#   proves machine-level authorization — equivalent to SSH keys in ~/.ssh/.
#   By default, Claude will prompt before each memxp tool call.
#   --auto-approve pre-approves all memxp tools (skip per-call prompts).

set -eu

# ── Interactive detection ─────────────────────────────────────
# When piped (curl | sh), stdin is consumed by the script content.
# We detect this and use /dev/tty for user prompts, which connects
# to the actual terminal even when stdin is a pipe.
# If /dev/tty isn't available (e.g., CI), fall back to defaults.
HAS_TTY=0
if [ -e /dev/tty ]; then
  HAS_TTY=1
fi

# prompt_user PROMPT DEFAULT — prints prompt, reads from /dev/tty, echoes result to stderr
# Caller captures the value via: result=$(prompt_user "prompt" "default")
# All display goes to stderr so it doesn't contaminate the captured value.
prompt_user() {
  if [ "$HAS_TTY" = "1" ]; then
    printf "%s" "$1" >&2
    read -r REPLY < /dev/tty || REPLY=""
    if [ -n "$REPLY" ]; then
      printf "%s" "$REPLY"
    else
      printf "%s" "$2"
    fi
  else
    printf "%s" "$2"
  fi
}

# ── Configuration ──────────────────────────────────────────────
REPO_OWNER="pwchiefy"
REPO_NAME="memxp"
VERSION="${MEMXP_VERSION:-}"
INSTALL_DIR="$HOME/.local/bin"
# Prefer ~/.memxp for new installs; use existing ~/.vaultp2p if present
if [ -d "$HOME/.memxp" ]; then
  VAULT_DIR="$HOME/.memxp"
elif [ -d "$HOME/.vaultp2p" ]; then
  VAULT_DIR="$HOME/.vaultp2p"
else
  VAULT_DIR="$HOME/.memxp"
fi
SKIP_CLAUDE=0
AUTO_APPROVE=0

# ── Parse arguments ───────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version)    VERSION="${2:-}"; shift 2 ;;
    --skip-claude) SKIP_CLAUDE=1; shift ;;
    --auto-approve) AUTO_APPROVE=1; shift ;;
    -h|--help)
      sed -n '2,/^$/s/^# //p' "$0"
      exit 0
      ;;
    *) shift ;;
  esac
done

# ── Output helpers ─────────────────────────────────────────────
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  BLUE='\033[0;34m'
  YELLOW='\033[1;33m'
  DIM='\033[2m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  GREEN='' BLUE='' YELLOW='' DIM='' BOLD='' NC=''
fi

step()  { printf "  ${BLUE}>${NC} %s\n" "$1"; }
ok()    { printf "  ${GREEN}+${NC} %s\n" "$1"; }
warn()  { printf "  ${YELLOW}!${NC} %s\n" "$1"; }
ask()   { printf "  ${BOLD}?${NC} %s" "$1"; }
info()  { printf "  ${DIM}%s${NC}\n" "$1"; }

# ── Welcome ────────────────────────────────────────────────────
printf "\n"
printf "  ${BOLD}memxp${NC} — a second brain for your coding agent\n"
printf "\n"
printf "  Your agent is brilliant but forgetful. memxp fixes that.\n"
printf "  It keeps an encrypted record of what you work on, what\n"
printf "  works, what breaks, and how to do things right — so every\n"
printf "  session picks up where the last one left off.\n"
printf "\n"
printf "  ${DIM}Data analysis, personal finance, coding projects, planning${NC}\n"
printf "  ${DIM}— whatever you work on, your agent remembers how to help.${NC}\n"
printf "\n"

# ── Platform detection ─────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  PLATFORM="macos-arm64" ;;
      x86_64) PLATFORM="macos-x86_64" ;;
      *) printf "  Unsupported Mac architecture: %s\n" "$ARCH"; exit 1 ;;
    esac
    CRSQLITE_EXT="crsqlite.dylib"
    SHELL_PROFILE="$HOME/.zprofile"
    ;;
  Linux)
    PLATFORM="linux-x86_64"
    CRSQLITE_EXT="crsqlite.so"
    SHELL_PROFILE="$HOME/.profile"
    ;;
  *)
    printf "  This installer supports macOS and Linux.\n"
    printf "  For Windows, see: https://github.com/%s/%s\n" "$REPO_OWNER" "$REPO_NAME"
    exit 1
    ;;
esac

ok "Detected $OS ($ARCH)"

# ── Check for Claude Code ─────────────────────────────────────
install_node_macos() {
  # Download and install Node.js via the official .pkg — no Homebrew needed
  step "Installing Node.js..."
  NODE_VER="22"
  if [ "$ARCH" = "arm64" ]; then
    NODE_PKG="node-v${NODE_VER}.14.0-darwin-arm64.tar.gz"
    NODE_URL="https://nodejs.org/dist/v${NODE_VER}.14.0/${NODE_PKG}"
  else
    NODE_PKG="node-v${NODE_VER}.14.0-darwin-x64.tar.gz"
    NODE_URL="https://nodejs.org/dist/v${NODE_VER}.14.0/${NODE_PKG}"
  fi

  NODE_TMP="$(mktemp -d)"
  if ! curl -fsSL "$NODE_URL" -o "$NODE_TMP/$NODE_PKG"; then
    warn "Could not download Node.js."
    rm -rf "$NODE_TMP"
    return 1
  fi

  tar -xzf "$NODE_TMP/$NODE_PKG" -C "$NODE_TMP"
  NODE_DIR="$(ls -d "$NODE_TMP"/node-v* 2>/dev/null | head -1)"

  # Install to ~/.local (no admin needed)
  mkdir -p "$HOME/.local/bin" "$HOME/.local/lib" "$HOME/.local/include"
  cp -f "$NODE_DIR/bin/node" "$HOME/.local/bin/"
  cp -rf "$NODE_DIR/lib/node_modules" "$HOME/.local/lib/"
  ln -sf "../lib/node_modules/npm/bin/npm-cli.js" "$HOME/.local/bin/npm"
  ln -sf "../lib/node_modules/npm/bin/npx-cli.js" "$HOME/.local/bin/npx"
  rm -rf "$NODE_TMP"

  # Verify
  if "$HOME/.local/bin/node" --version >/dev/null 2>&1; then
    ok "Node.js $("$HOME/.local/bin/node" --version) installed to ~/.local/bin"
  else
    warn "Node.js install failed."
    return 1
  fi
}

install_claude_code() {
  step "Installing Claude Code..."

  # Check for npm
  if ! command -v npm >/dev/null 2>&1; then
    # Check for Node.js without npm (unlikely but possible)
    if command -v node >/dev/null 2>&1; then
      warn "Node.js found but npm is missing"
      return 1
    fi

    # macOS: install Node.js directly (no Homebrew needed)
    if [ "$OS" = "Darwin" ]; then
      if ! install_node_macos; then
        warn "Skipping Claude Code install."
        return 1
      fi

    # Linux: use package manager
    elif [ "$OS" = "Linux" ]; then
      if command -v apt-get >/dev/null 2>&1; then
        step "Installing Node.js via apt..."
        if ! (sudo apt-get update -qq && sudo apt-get install -y -qq nodejs npm); then
          warn "Node.js install failed. Skipping Claude Code."
          return 1
        fi
      elif command -v dnf >/dev/null 2>&1; then
        step "Installing Node.js via dnf..."
        if ! sudo dnf install -y nodejs npm; then
          warn "Node.js install failed. Skipping Claude Code."
          return 1
        fi
      else
        warn "Could not install Node.js automatically. Skipping Claude Code."
        return 1
      fi
      ok "Node.js installed"
    fi
  fi

  # Verify Node.js version (need 18+)
  NODE_VERSION="$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1)"
  if [ -n "$NODE_VERSION" ] && [ "$NODE_VERSION" -lt 18 ] 2>/dev/null; then
    warn "Node.js 18+ required (found v$NODE_VERSION)"
    return 1
  fi

  step "Installing Claude Code (this may take a minute)..."
  if npm install -g @anthropic-ai/claude-code 2>/dev/null; then
    ok "Claude Code installed"
  else
    # npm global install may fail without sudo — try with user prefix
    info "Retrying with user-local install..."
    npm install -g --prefix "$HOME/.local" @anthropic-ai/claude-code 2>/dev/null
    ok "Claude Code installed"
  fi

  printf "\n"
  info "You'll need to sign in the first time you run Claude Code."
  info "Create a free account at: https://console.anthropic.com"
  printf "\n"
}

if [ "$SKIP_CLAUDE" = "0" ]; then
  # Find the real claude binary (not an alias/function)
  CLAUDE_BIN=""
  for p in /opt/homebrew/bin/claude /usr/local/bin/claude "$HOME/.local/bin/claude" "$HOME/.npm-global/bin/claude"; do
    if [ -x "$p" ]; then
      CLAUDE_BIN="$p"
      break
    fi
  done

  # Also check PATH (but skip shell functions)
  if [ -z "$CLAUDE_BIN" ] && command -v claude >/dev/null 2>&1; then
    REAL_PATH="$(command -v claude 2>/dev/null || true)"
    if [ -n "$REAL_PATH" ] && [ -x "$REAL_PATH" ]; then
      CLAUDE_BIN="$REAL_PATH"
    fi
  fi

  if [ -n "$CLAUDE_BIN" ]; then
    ok "Claude Code found at $CLAUDE_BIN"
  else
    printf "\n"
    printf "  Claude Code is not installed yet.\n"
    printf "  It's your AI coding partner — memxp gives it a brain\n"
    printf "  that persists between conversations.\n"
    printf "\n"
    answer="$(prompt_user "  ? Install Claude Code now? (Y/n): " "Y")"
    case "$answer" in
      n|N|no|No)
        warn "Skipping Claude Code install."
        info "Install later: npm install -g @anthropic-ai/claude-code"
        SKIP_CLAUDE=1
        ;;
      *)
        install_claude_code || true
        # Find claude — may be in ~/.local/bin or npm global bin
        CLAUDE_BIN=""
        for p in "$HOME/.local/bin/claude" "$HOME/.local/lib/node_modules/.bin/claude" \
                 /opt/homebrew/bin/claude /usr/local/bin/claude; do
          if [ -x "$p" ]; then
            CLAUDE_BIN="$p"
            break
          fi
        done
        [ -z "$CLAUDE_BIN" ] && CLAUDE_BIN="$(command -v claude 2>/dev/null || echo "")"
        ;;
    esac
  fi
fi

# ── Working directory ──────────────────────────────────────────
DEV_DEFAULT="$HOME/Developer"
printf "\n"
printf "  Where do you keep your projects? This is your home base\n"
printf "  — where you and Claude will work together.\n"
printf "\n"
dev_dir="$(prompt_user "  ? Directory (Enter for $DEV_DEFAULT): " "$DEV_DEFAULT")"

# Expand ~ if they typed it
case "$dev_dir" in
  "~"*)  dev_dir="$HOME${dev_dir#\~}" ;;
esac

mkdir -p "$dev_dir"
ok "Project directory: $dev_dir"

# ── Ensure PATH includes install dir ──────────────────────────
mkdir -p "$INSTALL_DIR"

ensure_path() {
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) return 0 ;;
  esac

  EXPORT_LINE="export PATH=\"\$HOME/.local/bin:\$PATH\""

  # Add to the appropriate shell profile
  if [ -f "$SHELL_PROFILE" ]; then
    if ! grep -q '.local/bin' "$SHELL_PROFILE" 2>/dev/null; then
      printf '\n# Added by memxp installer\n%s\n' "$EXPORT_LINE" >> "$SHELL_PROFILE"
    fi
  else
    printf '# Added by memxp installer\n%s\n' "$EXPORT_LINE" > "$SHELL_PROFILE"
  fi

  # Also add to .zshenv for non-interactive shells (macOS)
  if [ "$OS" = "Darwin" ] && [ -z "$(grep '.local/bin' "$HOME/.zshenv" 2>/dev/null || true)" ]; then
    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.zshenv"
  fi

  export PATH="$INSTALL_DIR:$PATH"
}

ensure_path

# ── Download memxp ─────────────────────────────────────────────
step "Downloading memxp..."

# Determine version
if [ -z "$VERSION" ]; then
  RELEASE_JSON="$(curl -fsSL -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null || echo "")"
  if [ -n "$RELEASE_JSON" ]; then
    # Try grep+sed (works on both BSD and GNU)
    VERSION="$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed 's/.*"tag_name"[^"]*"\([^"]*\)".*/\1/' | sed 's/^v//' | head -1)"
  fi
fi

if [ -z "$VERSION" ]; then
  warn "Could not determine latest version from GitHub."
  printf "  Try: sh install.sh --version v0.1.0\n"
  exit 1
fi

VERSION="${VERSION#v}"
TAG="v${VERSION}"
ASSET="memxp-${PLATFORM}.tar.gz"
BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Download and verify checksum
curl -fsSL "${BASE_URL}/checksums.txt" -o "$TMP_DIR/checksums.txt" 2>/dev/null
curl -fsSL "${BASE_URL}/${ASSET}" -o "$TMP_DIR/${ASSET}"

EXPECTED="$(awk -v a="$ASSET" '$2 == a { print $1 }' "$TMP_DIR/checksums.txt")"
if [ -n "$EXPECTED" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$EXPECTED  $TMP_DIR/$ASSET" | sha256sum -c - >/dev/null 2>&1
  elif command -v shasum >/dev/null 2>&1; then
    echo "$EXPECTED  $TMP_DIR/$ASSET" | shasum -a 256 -c - >/dev/null 2>&1
  fi
  ok "Download verified (SHA-256)"
else
  info "Checksum not available — skipping verification"
fi

tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"

# Install binary
TARGET="$INSTALL_DIR/memxp"
if [ -f "$TARGET" ]; then
  cp "$TARGET" "$TARGET.bak" 2>/dev/null || true
fi
cp "$TMP_DIR/memxp" "$TARGET"
chmod +x "$TARGET"

# macOS: remove quarantine and sign
if [ "$OS" = "Darwin" ]; then
  xattr -d com.apple.provenance "$TARGET" 2>/dev/null || true
  xattr -d com.apple.quarantine "$TARGET" 2>/dev/null || true
  codesign --force --sign - "$TARGET" 2>/dev/null || true
fi

ok "Installed memxp $TAG"

# Install cr-sqlite extension
mkdir -p "$VAULT_DIR"
if [ -f "$TMP_DIR/$CRSQLITE_EXT" ]; then
  cp "$TMP_DIR/$CRSQLITE_EXT" "$VAULT_DIR/$CRSQLITE_EXT"
  ok "Installed encryption extension"
fi

# ── Generate passphrase and initialize ─────────────────────────
step "Setting up encrypted storage..."

if [ -f "$VAULT_DIR/env" ]; then
  info "Existing passphrase found — keeping it"
else
  PASSPHRASE="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
  printf 'VAULT_PASSPHRASE="%s"\n' "$PASSPHRASE" > "$VAULT_DIR/env"
  chmod 600 "$VAULT_DIR/env"

  printf "\n"
  printf "  ${YELLOW}${BOLD}IMPORTANT: Save this passphrase somewhere safe${NC}\n"
  printf "  (e.g., a password manager). You'll need it to set up\n"
  printf "  memxp on other machines or recover from backups.\n\n"
  printf "  ${BOLD}Passphrase:${NC} %s\n\n" "$PASSPHRASE"
  ok "Passphrase stored in ~/.memxp/env (chmod 600)"
fi

# Source passphrase for this session and export so child processes see it
. "$VAULT_DIR/env" 2>/dev/null || true
export VAULT_PASSPHRASE

# Ensure shell profile sources the env file
if [ -f "$SHELL_PROFILE" ]; then
  if ! grep -q 'memxp/env' "$SHELL_PROFILE" 2>/dev/null; then
    printf '\n[ -f ~/.memxp/env ] && . ~/.memxp/env\n' >> "$SHELL_PROFILE"
  fi
else
  printf '[ -f ~/.memxp/env ] && . ~/.memxp/env\n' >> "$SHELL_PROFILE"
fi

# Create minimal config if it doesn't exist
if [ ! -f "$VAULT_DIR/config.yaml" ]; then
  cat > "$VAULT_DIR/config.yaml" <<CONF
database:
  cr_sqlite_extension: $VAULT_DIR/$CRSQLITE_EXT
  path: $VAULT_DIR/vault.db
security:
  clipboard_clear_seconds: 30
CONF
fi

# Initialize the database (create vault.db)
if "$TARGET" init 2>&1 | grep -qi "initialized\|already"; then
  ok "Encrypted database ready"
else
  # init may print warnings but still succeed — check if vault.db exists
  if [ -f "$VAULT_DIR/vault.db" ]; then
    ok "Encrypted database ready"
  else
    warn "Database initialization may have failed — run 'memxp init' manually"
  fi
fi

# ── Register with Claude Code ──────────────────────────────────
if [ "$SKIP_CLAUDE" = "0" ] && [ -n "${CLAUDE_BIN:-}" ]; then
  step "Connecting to Claude Code..."

  # Register MCP server with passphrase so it can decrypt the vault.
  # `claude mcp add -s user` writes to ~/.mcp.json. We write directly
  # to ensure the VAULT_PASSPHRASE env var is included.
  CLAUDE_JSON="$HOME/.mcp.json"
  VAULT_PASS="${VAULT_PASSPHRASE:-}"
  if [ -z "$VAULT_PASS" ]; then
    VAULT_PASS="$(. "$VAULT_DIR/env" 2>/dev/null && echo "$VAULT_PASSPHRASE")"
  fi

  # Build the MCP server entry with env var
  if command -v python3 >/dev/null 2>&1 && [ -n "$VAULT_PASS" ]; then
    python3 -c "
import json, os, sys
path = '$CLAUDE_JSON'
try:
    with open(path, 'r') as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    config = {}

servers = config.setdefault('mcpServers', {})
servers['memxp'] = {
    'type': 'stdio',
    'command': '$TARGET',
    'args': ['mcp'],
    'env': {
        'VAULT_PASSPHRASE': '$VAULT_PASS'
    }
}

with open(path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
" 2>/dev/null && ok "Registered memxp with Claude Code (with passphrase)" || {
      # Fallback to claude mcp add without env
      "$CLAUDE_BIN" mcp add memxp -s user -- "$TARGET" mcp 2>/dev/null || true
      ok "Registered memxp with Claude Code"
      warn "Passphrase not passed to MCP server — you may need to run:"
      info "  source ~/.memxp/env before starting claude"
    }
  else
    "$CLAUDE_BIN" mcp add memxp -s user -- "$TARGET" mcp 2>/dev/null || true
    ok "Registered memxp with Claude Code"
  fi

  # Pre-configure permissions only when explicitly requested
  if [ "$AUTO_APPROVE" = "1" ]; then
    SETTINGS_DIR="$HOME/.claude"
    SETTINGS_FILE="$SETTINGS_DIR/settings.json"
    mkdir -p "$SETTINGS_DIR"

    if [ -f "$SETTINGS_FILE" ]; then
      # Merge permissions into existing settings
      python3 -c "
import json, sys

with open('$SETTINGS_FILE', 'r') as f:
    settings = json.load(f)

perms = settings.setdefault('permissions', {})
allow = perms.setdefault('allow', [])

needed = ['mcp__memxp']
for rule in needed:
    if rule not in allow:
        allow.append(rule)

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
" 2>/dev/null || true
    else
      cat > "$SETTINGS_FILE" <<'SETTINGS'
{
  "permissions": {
    "allow": [
      "mcp__memxp"
    ]
  }
}
SETTINGS
    fi
    ok "Pre-approved memxp tools (no permission prompts)"
  else
    info "Claude will prompt before each memxp tool call (pass --auto-approve to skip)"
  fi

else
  if [ "$SKIP_CLAUDE" = "0" ]; then
    info "Claude Code not found — skipping MCP registration."
    info "After installing Claude Code, run:"
    info "  claude mcp add memxp -s user -- $TARGET mcp"
  fi
fi

# ── Bootstrap the second brain ────────────────────────────────
step "Building your second brain..."

# Write guide content to temp files to avoid shell escaping issues
GUIDE_DIR="$TMP_DIR/guides"
mkdir -p "$GUIDE_DIR"

cat > "$GUIDE_DIR/onboarding.md" <<'GUIDE_EOF'
# First-Session Onboarding

When you detect this guide exists AND there is no "user-profile" guide yet,
run this onboarding flow. Be warm, conversational, and brief.

## Step 1: Introduction
Say something like: "I have a second brain now. It means I can remember
things between our conversations: what you work on, what works, what to
avoid, credentials, procedures. Let me ask a few questions so I can be a
real collaborator, not just a tool that forgets you every session."

## Step 2: Learn about them (ask naturally, not as a survey)
Find out:
- Their name and what they do (role, industry, expertise level)
- 2-3 things they want help with (coding, data analysis, finances, planning)
- Tools/services they use regularly (languages, platforms, accounts)
- Any preferences for how you should work (verbose vs terse, ask first vs just do it)

## Step 3: Build the foundation
From their answers, create these:

### a) User profile guide
save_instructions("user-profile", content=their info as markdown, category="reference")

### b) MEMORY.md routing index
Create the auto-memory file at the path Claude Code uses for this project.
Include sections: About You, Projects, Feedback, Gotcha Quick-Reference.
Each starts empty except About You (link to profile guide).

### c) Meditation.md learning journal
If not already created by the installer, create it in their project directory.
Template: append-only log with Date/Task, What happened, Why, Next time format.

## Step 4: Confirm and invite
Tell them what you set up and suggest a first task. Frame it as: "Your second
brain is ready. Want to try something? Tell me about a project, or ask me to
help with anything — I will remember it for next time."

## Important
- Do NOT run this onboarding if a "user-profile" guide already exists
- Keep the profile guide updated as you learn more about the user
- The Meditation.md path should be in their project directory
GUIDE_EOF

cat > "$GUIDE_DIR/welcome.md" <<'GUIDE_EOF'
# memxp — Your Agent's Second Brain

Today's coding agents are spiky geniuses with periodic amnesia.
memxp fixes that. It gives your agent a persistent record of:

- What you work on — projects, goals, context that carries over
- What works — procedures, configurations, proven approaches
- What fails — mistakes and gotchas, so they never repeat
- What you need — credentials, API keys, account details (encrypted)

## How it works

Your agent has three systems that work together:

1. Vault — encrypted storage for guides, credentials, and notes.
   Uses remember() to save, recall() to retrieve, find() to search.

2. Memory routing — a concise index (MEMORY.md) that helps your agent
   navigate efficiently without searching blindly.

3. Learning journal — a log of errors and lessons (Meditation.md) that
   gets consolidated into actionable rules over time.

## What can you use it for?

Anything where continuity matters:
- Coding projects — architecture decisions, gotchas, deploy steps
- Data analysis — column mappings, data quality issues, query patterns
- Personal finance — account structures, recurring processes
- Planning — goals, timelines, dependencies, progress tracking
- Operations — server configs, deployment recipes, runbooks
- Learning — test results, what approaches worked, references

## The key idea

You are not using a tool. You are building a working relationship.
Every session makes the next one better.
GUIDE_EOF

cat > "$GUIDE_DIR/cleanup.md" <<'GUIDE_EOF'
# Vault Cleanup Process

Run this periodically (weekly, or when the user says /cleanup) to keep
the second brain healthy.

## 1. MEMORY.md Audit
- Read the auto-memory MEMORY.md routing index
- Verify it is under 200 lines (truncation happens beyond that)
- Check that project references match actual vault guides
- Remove entries for deleted/deprecated guides
- Keep the index concise — one line per entry, no prose

## 2. Learning Journal Sync
- Read Meditation.md for entries not yet captured in vault guides
- Categorize: code gotcha, config issue, workflow lesson, tool quirk
- If 3+ entries share a theme, create or update a consolidated guide
- Update the Gotcha Quick-Reference table in MEMORY.md
- Do NOT modify Meditation.md — it is append-only raw history

## 3. Guide Health Check
- Run stale_instructions(threshold_days=90) for unverified guides
- Verify, update, or deprecate each stale guide
- Run vault_lint() for naming issues and near-duplicates
- Suggest merging overlapping guides

## 4. Credential Hygiene
- Run vault_rotation_alerts(window_days=30)
- Flag credentials with no notes or service tags

## 5. Report
Summarize what was found and fixed. Save as a dated cleanup report guide.
GUIDE_EOF

# Seed guides using --file flag (avoids shell escaping)
"$TARGET" guide add memxp-onboarding --file "$GUIDE_DIR/onboarding.md" \
  --category setup --tags '["onboarding","first-run"]' 2>/dev/null || true
"$TARGET" guide add memxp-welcome --file "$GUIDE_DIR/welcome.md" \
  --category reference --tags '["welcome","overview"]' 2>/dev/null || true
"$TARGET" guide add memxp-cleanup-process --file "$GUIDE_DIR/cleanup.md" \
  --category runbook --tags '["maintenance","cleanup"]' 2>/dev/null || true

ok "Second brain initialized"
info "Three guides seeded: onboarding, welcome, cleanup process"

# ── Set up Meditation.md learning journal ─────────────────────
MEDITATION_FILE="$dev_dir/Meditation.md"
if [ ! -f "$MEDITATION_FILE" ]; then
  cat > "$MEDITATION_FILE" <<'MEDITATION'
# Meditation — Learning Journal

When something goes wrong or could have gone better, record it here.
This journal is the raw feed — the cleanup process consolidates it
into actionable guides so your agent improves over time.

Format:

## [Date] — [Task]
**What happened:** Brief description of the error or suboptimal result.
**Why:** Root cause — what led to this.
**Next time:** Concrete rule to follow going forward.
MEDITATION
  ok "Learning journal created at $dev_dir/Meditation.md"
fi

# ── Ensure CLAUDE.md includes memxp instructions ──────────────
CLAUDE_MD="$dev_dir/CLAUDE.md"
MEMXP_BLOCK='## memxp — Second Brain

You have a second brain called memxp. It remembers things between conversations.
Always check it before asking the user for information you might already have.

### How to use it
- `whats_saved()` — see everything in memory
- `find(query)` / `recall(path)` — look things up
- `remember(path, value)` — save credentials, notes, or any info
- `save_instructions(name, content)` — save a guide, procedure, or reference
- `read_instructions(name)` — read a saved guide
- `find_instructions(query)` — search guides

### What to save
- When the user tells you about themselves, save it as a guide (e.g. "user-profile")
- When you figure out a procedure, save it as a guide so you remember next time
- When the user gives you a credential, save it with remember()
- At the end of each session, persist anything new you learned'

if [ -f "$CLAUDE_MD" ]; then
  # Existing CLAUDE.md — append memxp section if not already present
  if ! grep -q 'memxp' "$CLAUDE_MD" 2>/dev/null; then
    printf '\n\n%s\n' "$MEMXP_BLOCK" >> "$CLAUDE_MD"
    ok "Added memxp instructions to existing CLAUDE.md"
  else
    info "CLAUDE.md already mentions memxp — skipping"
  fi
else
  # No CLAUDE.md — create one
  cat > "$CLAUDE_MD" <<CLAUDEMD
# Instructions for Claude

$MEMXP_BLOCK
CLAUDEMD
  ok "Created CLAUDE.md (Claude reads this at session start)"
fi

# ── Done ───────────────────────────────────────────────────────
printf "\n"
printf "  ${GREEN}${BOLD}Your second brain is ready.${NC}\n"
printf "\n"

if [ -n "${CLAUDE_BIN:-}" ]; then
  # Claude Code is installed and memxp is registered — ready to go
  printf "  ${BOLD}What to do now:${NC}\n"
  printf "\n"
  printf "  1. Close this Terminal window\n"
  printf "  2. Open a ${BOLD}new Terminal window${NC}\n"
  printf "  3. Copy and paste this:\n"
  printf "\n"
  printf "     ${BOLD}cd %s && claude${NC}\n" "$dev_dir"
  printf "\n"
  printf "  memxp is now connected to Claude. Things you can try:\n"
  printf "\n"
  printf "  ${DIM}  \"Tell me about yourself so I can save it for next time\"${NC}\n"
  printf "  ${DIM}  \"Save a guide on how I deploy my app to production\"${NC}\n"
  printf "  ${DIM}  \"Remember my OpenAI API key: sk-...\"${NC}\n"
  printf "  ${DIM}  \"What do you know about me?\"${NC}\n"
  printf "\n"
  printf "  Just work on whatever you need — Claude will remember\n"
  printf "  what matters for next time.\n"
else
  # memxp is installed but Claude Code is not
  printf "  memxp is installed and working.\n"
  printf "\n"
  printf "  ${YELLOW}Claude Code could not be installed automatically.${NC}\n"
  printf "  This is usually a permissions issue. Try this:\n"
  printf "\n"
  printf "  1. Close this Terminal window\n"
  printf "  2. Open a ${BOLD}new Terminal window${NC}\n"
  printf "  3. Copy and paste these lines ${BOLD}one at a time${NC}:\n"
  printf "\n"
  printf "     ${BOLD}npm install -g @anthropic-ai/claude-code${NC}\n"
  printf "     ${BOLD}claude mcp add memxp -s user -- %s mcp${NC}\n" "$TARGET"
  printf "     ${BOLD}cd %s && claude${NC}\n" "$dev_dir"
  printf "\n"
  printf "  Then just tell Claude what you need — it will remember for next time.\n"
  printf "\n"
  printf "  If 'npm' is not found, run the installer again from\n"
  printf "  an admin account, or visit: https://nodejs.org\n"
fi

printf "\n"
printf "  ${DIM}Passphrase stored in ~/.memxp/env (chmod 600)${NC}\n"
printf "\n"
