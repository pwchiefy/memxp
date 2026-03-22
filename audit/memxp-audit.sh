#!/bin/bash
# memxp-audit — Self-auditing knowledge system for memxp
#
# Discovers what to check from your memxp database, verifies claims against
# reality through parallel Claude agents, and reports discrepancies.
#
# Usage:
#   memxp-audit              # Run audit (skip if today's report exists)
#   memxp-audit --force      # Force re-run even if report exists
#
# Requires:
#   - Claude Code CLI (claude)
#   - memxp MCP server configured in ~/.mcp.json
#   - Config at ~/.config/memxp-audit/config.env
#
# Architecture:
#   Phase 1: Pre-collect raw data (bash — deterministic, fast)
#   Phase 2: Parallel audit agents (claude -p — Read + MCP only, no Bash)
#   Phase 3: Wait and collect results
#   Phase 4: Synthesis agent produces final report
#   Phase 5: Optional notification

set -euo pipefail

DATE=$(date +%Y-%m-%d)
DAY_OF_WEEK=$(date +%A)
FORCE=false
[ "${1:-}" = "--force" ] && FORCE=true

# ─── Load config ────────────────────────────────────────────

CONFIG_FILE="${HOME}/.config/memxp-audit/config.env"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: No config found at $CONFIG_FILE"
    echo "Copy config.example.env to $CONFIG_FILE and edit it."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# ─── Derived paths ──────────────────────────────────────────

CHECKS_DIR="${WORK_DIR}/checks/${DATE}"
RAW_DIR="${CHECKS_DIR}/raw"
AGENTS_DIR="${CHECKS_DIR}/agents"
PROMPTS_DIR="${WORK_DIR}/prompts"
OUTPUT_FILE="${OUTPUT_DIR}/${DATE}.md"
LOG_FILE="${WORK_DIR}/audit.log"
# ─── Discover tools ─────────────────────────────────────────

# Claude CLI: use config, then PATH discovery, then fail clearly
if [ -n "${CLAUDE_PATH:-}" ]; then
    CLAUDE="$CLAUDE_PATH"
elif command -v claude &>/dev/null; then
    CLAUDE="$(command -v claude)"
else
    echo "ERROR: Claude CLI not found. Install it or set CLAUDE_PATH in config."
    exit 1
fi

# timeout: available natively on Linux, needs coreutils on macOS
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        # macOS with coreutils installed via Homebrew
        timeout() { gtimeout "$@"; }
    else
        echo "ERROR: 'timeout' command not found. Install coreutils (brew install coreutils on macOS)."
        exit 1
    fi
fi

# ─── Environment ────────────────────────────────────────────

export HOME="${HOME}"
unset CLAUDECODE 2>/dev/null || true

# Source vault passphrase (required for MCP access from schedulers where Keychain is unavailable)
# Check both paths: post-rebrand (~/.memxp/env) and legacy (~/.vaultp2p/env)
for VAULT_ENV in "${HOME}/.memxp/env" "${HOME}/.vaultp2p/env"; do
    if [ -f "$VAULT_ENV" ]; then
        # shellcheck source=/dev/null
        source "$VAULT_ENV"
        export VAULT_PASSPHRASE
        break
    fi
done

# SSH agent socket discovery (platform-adaptive)
if [ -z "${SSH_AUTH_SOCK:-}" ]; then
    case "$(uname -s)" in
        Darwin)
            # macOS launchd context doesn't inherit SSH_AUTH_SOCK
            SOCK=$(find /private/tmp/com.apple.launchd.* -name Listeners -type s 2>/dev/null | head -1)
            ;;
        Linux)
            # systemd user session or gnome-keyring
            SOCK=$(find /run/user/"$(id -u)" -name 'agent.*' -o -name 'ssh' -type s 2>/dev/null | head -1)
            ;;
    esac
    if [ -n "${SOCK:-}" ]; then
        export SSH_AUTH_SOCK="$SOCK"
    fi
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes"

# ─── Setup ──────────────────────────────────────────────────

mkdir -p "$WORK_DIR" "$CHECKS_DIR" "$RAW_DIR" "$AGENTS_DIR" "$PROMPTS_DIR" "$OUTPUT_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
log "Starting memxp-audit for $DATE ($DAY_OF_WEEK)"

# ─── Skip guard ─────────────────────────────────────────────

if [ "$FORCE" = false ] && [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    log "Audit report already exists for $DATE, skipping (use --force to override)"
    # Copy to secondary location if configured
    if [ -n "${COPY_TO:-}" ] && [ -d "$COPY_TO" ]; then
        cp "$OUTPUT_FILE" "$COPY_TO/$DATE.md" 2>/dev/null || true
    fi
    exit 0
fi

# Clean up old check dirs (keep 7 days)
find "$WORK_DIR/checks" -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true

# ─── Verify prerequisites ──────────────────────────────────

if [ ! -x "$CLAUDE" ] && ! command -v claude &>/dev/null; then
    log "ERROR: Claude CLI not found at $CLAUDE"
    exit 1
fi

if [ ! -d "$PROMPTS_DIR" ] || [ -z "$(ls -A "$PROMPTS_DIR" 2>/dev/null)" ]; then
    log "ERROR: No prompt files found in $PROMPTS_DIR"
    exit 1
fi

# ─── Phase 1: Pre-collection ───────────────────────────────

log "Phase 1: Collecting raw data..."

# --- Git activity (discovered from MEMORY.md) ---
if [ -f "${MEMORY_FILE:-}" ]; then
    log "Scanning MEMORY.md for local repos..."
    {
        # Extract paths from MEMORY.md (often backtick-wrapped like `~/Developer/foo/`)
        # First extract backtick content, then pull out ~/... paths
        grep -o '`[^`]*`' "$MEMORY_FILE" 2>/dev/null \
            | grep -oE '~/[A-Za-z0-9_./-]+' \
            | sed 's|/$||' \
            | sort -u \
            | while IFS= read -r repo; do
            expanded="${repo/#\~/$HOME}"
            if [ -d "$expanded/.git" ]; then
                name=$(basename "$expanded")
                last=$(git -C "$expanded" log -1 --format='%ci | %s' 2>/dev/null || echo "no commits")
                branch=$(git -C "$expanded" branch --show-current 2>/dev/null || echo "unknown")
                ahead=$(git -C "$expanded" rev-list --count '@{upstream}..HEAD' 2>/dev/null || echo "?")
                echo "$name ($expanded): branch=$branch ahead=$ahead | $last"
            fi
        done
    } > "$RAW_DIR/git-activity.txt" 2>&1
    log "Git activity collected: $(wc -l < "$RAW_DIR/git-activity.txt" 2>/dev/null || echo 0) repos"
else
    echo "No MEMORY_FILE configured" > "$RAW_DIR/git-activity.txt"
    log "WARNING: MEMORY_FILE not found, skipping git activity collection"
fi

# --- Pre-collect Meditation.md (last 500 lines to save agent budget) ---
if [ -f "${MEDITATION_FILE:-}" ]; then
    {
        echo "=== MEDITATION JOURNAL (last 500 lines of $(wc -l < "$MEDITATION_FILE") total) ==="
        tail -500 "$MEDITATION_FILE"
    } > "$RAW_DIR/meditation-recent.txt" 2>&1
    log "Meditation pre-collected: $(wc -l < "$RAW_DIR/meditation-recent.txt") lines"
else
    echo "No MEDITATION_FILE configured" > "$RAW_DIR/meditation-recent.txt"
fi

# --- Pre-collect guide list via memxp CLI (saves agents from 30+ individual MCP calls) ---
if command -v memxp &>/dev/null; then
    memxp guide list 2>/dev/null > "$RAW_DIR/guide-list.txt" || echo "memxp guide list failed" > "$RAW_DIR/guide-list.txt"
    log "Guide list pre-collected: $(wc -l < "$RAW_DIR/guide-list.txt") entries"
elif command -v vaultp2p &>/dev/null; then
    vaultp2p guide list 2>/dev/null > "$RAW_DIR/guide-list.txt" || echo "vaultp2p guide list failed" > "$RAW_DIR/guide-list.txt"
    log "Guide list pre-collected: $(wc -l < "$RAW_DIR/guide-list.txt") entries"
else
    echo "memxp CLI not found" > "$RAW_DIR/guide-list.txt"
    log "WARNING: memxp CLI not found, guide list not pre-collected"
fi

# --- SSH infrastructure collection (from config, not hardcoded) ---
if [ -n "${SSH_TARGETS:-}" ]; then
    log "Collecting infrastructure data from SSH targets..."
    for target_spec in $SSH_TARGETS; do
        host="${target_spec%%:*}"
        label="${target_spec##*:}"
        log "  Collecting from $label ($host)..."

        if timeout 60 ssh $SSH_OPTS "$host" bash <<'REMOTE_SCRIPT' > "$RAW_DIR/infra-${label}.txt" 2>&1; then
echo "===HOSTNAME==="
hostname 2>/dev/null || echo "unknown"
echo "===UPTIME==="
uptime
echo "===DISK==="
df -h / 2>/dev/null
df -h 2>/dev/null | grep -E '/mnt|/var|/opt' || true
echo "===MEMORY==="
free -h 2>/dev/null || vm_stat 2>/dev/null || echo "memory info unavailable"
echo "===PROCESSES==="
ps aux --sort=-rss 2>/dev/null | head -15 || ps aux 2>/dev/null | head -15
echo "===DOCKER==="
if command -v docker &>/dev/null; then
    echo "docker_available=true"
    echo "running=$(docker ps -q 2>/dev/null | wc -l)"
    echo "total=$(docker ps -aq 2>/dev/null | wc -l)"
    docker ps --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null | sort
    echo "===UNHEALTHY==="
    docker ps --filter "health=unhealthy" --format '{{.Names}} {{.Status}}' 2>/dev/null || true
    docker ps --filter "status=restarting" --format '{{.Names}} {{.Status}}' 2>/dev/null || true
else
    echo "docker_available=false"
fi
echo "===SYSTEMD==="
if command -v systemctl &>/dev/null; then
    echo "systemd_available=true"
    echo "===SYSTEMD_FAILED==="
    systemctl --failed --no-legend 2>/dev/null || true
    echo "===SYSTEMD_SERVICES==="
    systemctl list-units --type=service --state=running --no-legend 2>/dev/null | head -30 || true
else
    echo "systemd_available=false"
fi
echo "===CRONTAB==="
crontab -l 2>/dev/null || echo "no crontab"
echo "===BACKUPS==="
# Look for backup files in common locations (recurse into subdirs)
for dir in /var/backups /root/backups /opt/backups /backup; do
    if [ -d "$dir" ]; then
        echo "--- $dir ---"
        # Show directory structure
        find "$dir" -maxdepth 3 -type d 2>/dev/null | head -20
        # Show most recent backup files (sql, gz, gpg, tar)
        echo "--- recent files ---"
        find "$dir" -maxdepth 4 -type f \( -name "*.sql*" -o -name "*.gz" -o -name "*.gpg" -o -name "*.tar*" -o -name "manifest*" -o -name "*.log" \) -printf '%T+ %s %p\n' 2>/dev/null | sort -r | head -20 || \
        find "$dir" -maxdepth 4 -type f \( -name "*.sql*" -o -name "*.gz" -o -name "*.gpg" -o -name "*.tar*" -o -name "manifest*" \) 2>/dev/null | xargs ls -lt 2>/dev/null | head -20
    fi
done
echo "===END==="
REMOTE_SCRIPT
            log "  Collected from $label"
        else
            echo "SSH_FAILED: Could not connect to $host (timeout or auth failure)" > "$RAW_DIR/infra-${label}.txt"
            log "  WARNING: SSH failed for $label ($host)"
        fi
    done
fi

# --- External URL health checks (from config) ---
if [ -n "${PRODUCT_URLS:-}" ]; then
    log "Checking product URLs..."
    {
        for url in $PRODUCT_URLS; do
            status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 "$url" 2>/dev/null || echo "FAIL")
            echo "$url: $status"
        done
    } > "$RAW_DIR/url-health.txt" 2>&1
    log "URL health collected"
fi

# --- GitHub repo check (from config) ---
if [ -n "${GH_OWNER:-}" ]; then
    log "Collecting GitHub repo data..."
    if gh repo list "$GH_OWNER" --limit 30 \
        --json name,visibility,pushedAt,description \
        --jq '.[] | "\(.name) | \(.visibility) | \(.pushedAt) | \(.description // "")"' \
        > "$RAW_DIR/github-repos.txt" 2>&1; then
        log "GitHub data collected: $(wc -l < "$RAW_DIR/github-repos.txt") repos"
    else
        echo "gh CLI failed or not authenticated" > "$RAW_DIR/github-repos.txt"
        log "WARNING: GitHub collection failed"
    fi
fi

log "Phase 1 complete. Raw data in $RAW_DIR"

# ─── Phase 2: Parallel audit agents ────────────────────────

log "Phase 2: Launching audit agents..."

PIDS=()
AGENT_NAMES=()

launch_agent() {
    local name="$1"
    local prompt_file="$2"
    local context="$3"

    if [ ! -f "$prompt_file" ]; then
        log "WARNING: Prompt file not found: $prompt_file — skipping agent $name"
        echo "AGENT_SKIPPED: Prompt file not found" > "$AGENTS_DIR/${name}.md"
        return
    fi

    timeout 300 "$CLAUDE" -p \
        --model "${AUDIT_MODEL:-sonnet}" \
        --output-format text \
        --disallowed-tools "Bash,Edit,Write,NotebookEdit,Agent" \
        --permission-mode bypassPermissions \
        --no-session-persistence \
        --max-budget-usd "${AGENT_BUDGET:-0.50}" \
        --append-system-prompt "Today is $DATE ($DAY_OF_WEEK). $context" \
        "$(cat "$prompt_file")" \
        > "$AGENTS_DIR/${name}.md" 2>>"$LOG_FILE" &

    local pid=$!
    PIDS+=("$pid")
    AGENT_NAMES+=("$name")
    log "  Launched agent: $name (PID $pid)"
}

# Core agents (always run — they only need memxp + local files)
launch_agent "knowledge-health" \
    "$PROMPTS_DIR/knowledge-health.md" \
    "MEMORY_FILE=${MEMORY_FILE:-not_configured} GUIDE_LIST=$RAW_DIR/guide-list.txt"

launch_agent "meditation-patterns" \
    "$PROMPTS_DIR/meditation-patterns.md" \
    "MEDITATION_FILE=$RAW_DIR/meditation-recent.txt"

launch_agent "project-activity" \
    "$PROMPTS_DIR/project-activity.md" \
    "MEMORY_FILE=${MEMORY_FILE:-not_configured} RAW_DATA=$RAW_DIR/git-activity.txt GUIDE_LIST=$RAW_DIR/guide-list.txt"

# Infrastructure agent (only if SSH data was collected)
if ls "$RAW_DIR"/infra-*.txt >/dev/null 2>&1; then
    launch_agent "infrastructure-verify" \
        "$PROMPTS_DIR/infrastructure-verify.md" \
        "RAW_DIR=$RAW_DIR"
else
    log "  No SSH targets configured — skipping infrastructure-verify agent"
fi

log "All agents launched: ${#PIDS[@]} total"

# ─── Phase 3: Wait and collect ──────────────────────────────

log "Phase 3: Waiting for agents..."

FAILED_COUNT=0
for i in "${!PIDS[@]}"; do
    pid="${PIDS[$i]}"
    name="${AGENT_NAMES[$i]}"
    if wait "$pid" 2>/dev/null; then
        lines=$(wc -l < "$AGENTS_DIR/${name}.md" 2>/dev/null || echo 0)
        log "  Agent $name (PID $pid) completed: $lines lines"
        # Flag suspiciously short output
        if [ "$lines" -lt 5 ]; then
            log "  WARNING: Agent $name produced only $lines lines — may have failed silently"
        fi
    else
        exit_code=$?
        log "  WARNING: Agent $name (PID $pid) failed with exit code $exit_code"
        echo "" >> "$AGENTS_DIR/${name}.md"
        echo "AGENT_FAILED: exit code $exit_code (timeout or error)" >> "$AGENTS_DIR/${name}.md"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

log "Phase 3 complete. $FAILED_COUNT agent(s) failed."

# ─── Phase 4: Synthesis ────────────────────────────────────

log "Phase 4: Running synthesis agent..."

SYNTHESIS_PROMPT_FILE="$PROMPTS_DIR/synthesis.md"
if [ ! -f "$SYNTHESIS_PROMPT_FILE" ]; then
    log "ERROR: Synthesis prompt not found at $SYNTHESIS_PROMPT_FILE"
    # Fallback: concatenate agent outputs
    {
        echo "# memxp Audit — $DATE ($DAY_OF_WEEK) [PARTIAL — No Synthesis Prompt]"
        echo ""
        for f in "$AGENTS_DIR"/*.md; do
            [ -f "$f" ] || continue
            echo "---"
            echo "## $(basename "$f" .md)"
            echo ""
            cat "$f"
            echo ""
        done
    } > "$OUTPUT_FILE"
else
    if timeout 420 "$CLAUDE" -p \
        --model "${AUDIT_MODEL:-sonnet}" \
        --output-format text \
        --disallowed-tools "Bash,Edit,Write,NotebookEdit,Agent" \
        --permission-mode bypassPermissions \
        --no-session-persistence \
        --max-budget-usd "${SYNTHESIS_BUDGET:-1.00}" \
        --append-system-prompt "Today is $DATE ($DAY_OF_WEEK). AGENTS_DIR=$AGENTS_DIR RAW_DIR=$RAW_DIR GUIDE_LIST=$RAW_DIR/guide-list.txt" \
        "$(cat "$SYNTHESIS_PROMPT_FILE")" \
        > "$OUTPUT_FILE" 2>>"$LOG_FILE"; then
        log "Synthesis completed: $(wc -l < "$OUTPUT_FILE") lines"
    else
        log "ERROR: Synthesis agent failed (exit $?) — producing fallback report"
        {
            echo "# memxp Audit — $DATE ($DAY_OF_WEEK) [PARTIAL — Synthesis Failed]"
            echo ""
            echo "The synthesis agent failed. Raw agent outputs below."
            echo ""
            for f in "$AGENTS_DIR"/*.md; do
                [ -f "$f" ] || continue
                echo "---"
                echo "## $(basename "$f" .md)"
                echo ""
                cat "$f"
                echo ""
            done
        } > "$OUTPUT_FILE"
    fi
fi

# ─── Copy to secondary location ────────────────────────────

if [ -n "${COPY_TO:-}" ] && [ -d "$COPY_TO" ]; then
    if cp "$OUTPUT_FILE" "$COPY_TO/$DATE.md" 2>/dev/null; then
        log "Copied report to $COPY_TO/$DATE.md"
    else
        log "WARNING: Could not copy to $COPY_TO"
    fi
fi

# ─── Phase 5: Optional notification ────────────────────────

if [ -n "${SIGNAL_PHONE:-}" ]; then
    log "Phase 5: Sending Signal notification..."

    # Discover signal-cli: config, then PATH
    if [ -n "${SIGNAL_CLI:-}" ]; then
        SIGNAL_CLI_BIN="$SIGNAL_CLI"
    elif command -v signal-cli &>/dev/null; then
        SIGNAL_CLI_BIN="$(command -v signal-cli)"
    else
        log "WARNING: signal-cli not found, skipping notification"
        SIGNAL_PHONE=""  # disable notification for this run
    fi

    if [ -n "${SIGNAL_PHONE:-}" ]; then
        SIGNAL_DATA_DIR="${SIGNAL_DATA:-$HOME/.local/share/signal-cli}"
        UID_NUM=$(id -u)

        # Build summary
        AUDIT_STATUS="VERIFIED"
        if [ "$FAILED_COUNT" -gt 0 ]; then
            AUDIT_STATUS="PARTIAL ($FAILED_COUNT agents failed)"
        fi

        SIGNAL_MSG=$(cat <<MSG_EOF
memxp Audit [$AUDIT_STATUS] — $DATE ($DAY_OF_WEEK)

$(head -40 "$OUTPUT_FILE" | grep -E "^##|^-|^\|" | head -12)

Full report: $OUTPUT_FILE
MSG_EOF
        )

        # Stop Signal daemon if configured (platform-adaptive)
        if [ -n "${SIGNAL_DAEMON_PLIST:-}" ] && [ -f "$SIGNAL_DAEMON_PLIST" ]; then
            # macOS: launchctl
            launchctl bootout "gui/$UID_NUM" "$SIGNAL_DAEMON_PLIST" 2>/dev/null || true
            sleep 3
        elif [ -n "${SIGNAL_DAEMON_SERVICE:-}" ]; then
            # Linux: systemctl
            systemctl --user stop "$SIGNAL_DAEMON_SERVICE" 2>/dev/null || true
            sleep 3
        fi

        if "$SIGNAL_CLI_BIN" --config "$SIGNAL_DATA_DIR" \
            -a "$SIGNAL_PHONE" send \
            -m "$SIGNAL_MSG" \
            "$SIGNAL_PHONE" 2>>"$LOG_FILE"; then
            log "Signal notification sent"
        else
            log "WARNING: Signal send failed"
        fi

        # Restart Signal daemon
        if [ -n "${SIGNAL_DAEMON_PLIST:-}" ] && [ -f "$SIGNAL_DAEMON_PLIST" ]; then
            launchctl bootstrap "gui/$UID_NUM" "$SIGNAL_DAEMON_PLIST" 2>>"$LOG_FILE" || true
        elif [ -n "${SIGNAL_DAEMON_SERVICE:-}" ]; then
            systemctl --user start "$SIGNAL_DAEMON_SERVICE" 2>>"$LOG_FILE" || true
        fi
    fi
fi

# ─── Done ───────────────────────────────────────────────────

log "memxp-audit complete for $DATE. Report: $OUTPUT_FILE"
echo "Audit complete. Report: $OUTPUT_FILE"
