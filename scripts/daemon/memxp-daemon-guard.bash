#!/usr/bin/env bash
# memxp Daemon Guard (Linux / systemd)
# Ensures exactly one daemon instance runs.
# - Cleans stale PID files and legacy vaultp2p artifacts
# - Exits cleanly if daemon already running
# - Monitors daemon and keeps wrapper alive for systemd lifecycle management
# - Clean shutdown on SIGTERM

set -uo pipefail

export HOME="${HOME:-/root}"
export PATH="/usr/local/bin:$HOME/.local/bin:$PATH"

MEMXP="$(command -v memxp || echo /usr/local/bin/memxp)"
PIDFILE="/tmp/memxp-daemon.pid"
LEGACY_PIDFILE="/tmp/vaultp2p-daemon.pid"

# Source passphrase (Keychain unavailable)
[[ -f "$HOME/.vaultp2p/env" ]] && source "$HOME/.vaultp2p/env"
[[ -f "$HOME/.memxp/env" ]] && source "$HOME/.memxp/env"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] memxp-guard: $*"; }

# --- Stale PID cleanup ---
if [[ -f "$PIDFILE" ]]; then
    pid=$(cat "$PIDFILE")
    if kill -0 "$pid" 2>/dev/null; then
        log "Daemon already running (PID $pid). Nothing to do."
        exit 0
    else
        log "Stale PID file (PID $pid not running). Cleaning up."
        rm -f "$PIDFILE"
    fi
fi

# Clean legacy PID file
rm -f "$LEGACY_PIDFILE"

# --- Port check ---
if lsof -i :5480 -sTCP:LISTEN >/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -q ':5480 '; then
    log "Port 5480 already in use. Aborting."
    exit 0
fi

# --- Log rotation ---
for logdir in "$HOME/.vaultp2p/logs" "$HOME/.memxp/logs"; do
    [[ -d "$logdir" ]] || continue
    for logfile in "$logdir"/*.log; do
        [[ -f "$logfile" ]] || continue
        size=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
        if (( size > 52428800 )); then
            tail -c 10485760 "$logfile" > "${logfile}.tmp" && mv "${logfile}.tmp" "$logfile"
            log "Rotated $logfile (was $(( size / 1048576 )) MB)."
        fi
    done
done

# --- Start daemon ---
log "Starting memxp daemon..."
"$MEMXP" daemon start --insecure-skip-tls-verify 2>&1

sleep 2

if [[ ! -f "$PIDFILE" ]]; then
    log "ERROR: Daemon failed to start (no PID file created)."
    exit 1
fi

DAEMON_PID=$(cat "$PIDFILE")
log "Daemon started (PID $DAEMON_PID)."

# --- Clean shutdown handler ---
cleanup() {
    log "Received shutdown signal. Stopping daemon..."
    "$MEMXP" daemon stop 2>/dev/null || kill "$DAEMON_PID" 2>/dev/null || true
    rm -f "$PIDFILE" 2>/dev/null
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

# --- Monitor loop ---
while true; do
    if [[ -f "$PIDFILE" ]]; then
        current_pid=$(cat "$PIDFILE")
        if ! kill -0 "$current_pid" 2>/dev/null; then
            log "Daemon (PID $current_pid) is no longer running."
            rm -f "$PIDFILE"
            exit 1
        fi
    else
        log "PID file disappeared. Daemon likely stopped externally."
        exit 1
    fi
    sleep 30
done
