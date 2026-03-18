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
# Usage:
#   curl -fsSL https://memxp.dev/install | sh
#   sh install.sh [--version v0.1.0] [--skip-claude]
#
# What this sets up:
#   1. Claude Code (your AI partner, if not already installed)
#   2. memxp (encrypted second brain — guides, credentials, learnings)
#   3. Your project workspace
#   4. The learning loop — so your agent gets better every session
#
# After install, open Terminal and run: cd ~/Developer && claude
# Then say: "let's get started"

set -eu

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

# ── Parse arguments ───────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version)    VERSION="${2:-}"; shift 2 ;;
    --skip-claude) SKIP_CLAUDE=1; shift ;;
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
install_claude_code() {
  step "Installing Claude Code..."

  # Check for npm
  if ! command -v npm >/dev/null 2>&1; then
    # Check for Node.js without npm (unlikely but possible)
    if command -v node >/dev/null 2>&1; then
      warn "Node.js found but npm is missing"
      printf "  Please install npm and try again.\n"
      exit 1
    fi

    # macOS: use Homebrew
    if [ "$OS" = "Darwin" ]; then
      if ! command -v brew >/dev/null 2>&1; then
        step "Installing Homebrew (macOS package manager)..."
        info "This is a standard tool used by most Mac developers."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Add Homebrew to PATH for this session
        if [ -f /opt/homebrew/bin/brew ]; then
          eval "$(/opt/homebrew/bin/brew shellenv)"
        elif [ -f /usr/local/bin/brew ]; then
          eval "$(/usr/local/bin/brew shellenv)"
        fi
        ok "Homebrew installed"
      fi

      step "Installing Node.js..."
      brew install node 2>/dev/null
      ok "Node.js installed"

    # Linux: use package manager
    elif [ "$OS" = "Linux" ]; then
      if command -v apt-get >/dev/null 2>&1; then
        step "Installing Node.js via apt..."
        sudo apt-get update -qq && sudo apt-get install -y -qq nodejs npm
      elif command -v dnf >/dev/null 2>&1; then
        step "Installing Node.js via dnf..."
        sudo dnf install -y nodejs npm
      else
        warn "Could not install Node.js automatically."
        printf "  Please install Node.js 18+ and try again.\n"
        printf "  https://nodejs.org/en/download\n"
        exit 1
      fi
      ok "Node.js installed"
    fi
  fi

  # Verify Node.js version (need 18+)
  NODE_VERSION="$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1)"
  if [ -n "$NODE_VERSION" ] && [ "$NODE_VERSION" -lt 18 ] 2>/dev/null; then
    warn "Node.js 18+ required (found v$NODE_VERSION)"
    printf "  Update Node.js: brew upgrade node (macOS) or see nodejs.org\n"
    exit 1
  fi

  npm install -g @anthropic-ai/claude-code 2>/dev/null
  ok "Claude Code installed"

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
    ask "Install Claude Code now? (Y/n): "
    read -r answer
    case "$answer" in
      n|N|no|No)
        warn "Skipping Claude Code install."
        info "Install later: npm install -g @anthropic-ai/claude-code"
        SKIP_CLAUDE=1
        ;;
      *)
        install_claude_code
        CLAUDE_BIN="$(command -v claude 2>/dev/null || echo "")"
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
ask "Directory (Enter for $DEV_DEFAULT): "
read -r dev_dir
dev_dir="${dev_dir:-$DEV_DEFAULT}"

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
  VERSION="$(curl -fsSL -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null || echo "")"
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

  # Save passphrase backup in a findable location
  BACKUP_FILE="$HOME/Desktop/memxp-passphrase.txt"
  cat > "$BACKUP_FILE" <<PASSFILE
memxp Passphrase — KEEP THIS SAFE
==================================

Your memxp encryption passphrase is:

  $PASSPHRASE

This passphrase protects everything Claude remembers for you.
You'll need it if you set up memxp on another computer.

Store this somewhere safe (like a password manager), then
delete this file from your Desktop.

Setup date: $(date '+%B %d, %Y')
PASSFILE
  chmod 600 "$BACKUP_FILE"
  ok "Passphrase saved to Desktop/memxp-passphrase.txt"
  info "Move it somewhere safe, then delete the file."
fi

# Source passphrase for this session
. "$VAULT_DIR/env" 2>/dev/null || true

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
"$TARGET" status >/dev/null 2>&1 || true
ok "Encrypted database ready"

# ── Register with Claude Code ──────────────────────────────────
if [ "$SKIP_CLAUDE" = "0" ] && [ -n "${CLAUDE_BIN:-}" ]; then
  step "Connecting to Claude Code..."

  # Register MCP server (user scope — available in all projects)
  "$CLAUDE_BIN" mcp add memxp -s user -- "$TARGET" mcp 2>/dev/null || true
  ok "Registered memxp with Claude Code"

  # Pre-configure permissions so Claude can use memxp without prompting
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

# ── Done ───────────────────────────────────────────────────────
printf "\n"
printf "  ${GREEN}${BOLD}Your second brain is ready.${NC}\n"
printf "\n"
printf "  ${BOLD}To start:${NC}\n"
printf "\n"
printf "    cd %s\n" "$dev_dir"
printf "    claude\n"
printf "\n"
printf "  Claude will introduce itself and ask a few questions\n"
printf "  to learn about you and what you work on. From there,\n"
printf "  every session builds on the last.\n"
printf "\n"

if [ "$SKIP_CLAUDE" = "0" ] && [ -z "${CLAUDE_BIN:-}" ]; then
  printf "  ${YELLOW}First:${NC} Install Claude Code:\n"
  printf "    npm install -g @anthropic-ai/claude-code\n"
  printf "    claude mcp add memxp -s user -- %s mcp\n" "$TARGET"
  printf "\n"
fi

printf "  ${DIM}Passphrase backup: ~/Desktop/memxp-passphrase.txt${NC}\n"
printf "  ${DIM}Store it somewhere safe, then delete the file.${NC}\n"
printf "\n"
