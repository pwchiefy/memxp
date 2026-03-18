#!/bin/zsh
# memxp Daemon Guard (macOS / launchd)
# Ensures exactly one daemon instance runs.
# - Cleans stale PID files and legacy vaultp2p artifacts
# - Exits cleanly if daemon already running (prevents launchd restart loops)
# - Monitors daemon and keeps wrapper alive for launchd lifecycle management
# - Clean shutdown on SIGTERM

set -uo pipefail

MEMXP="$HOME/.local/bin/memxp"
PIDFILE="/private/tmp/memxp-daemon.pid"
LEGACY_PIDFILE="/private/tmp/vaultp2p-daemon.pid"

# Source passphrase (Keychain inaccessible from launchd)
[[ -f "$HOME/.vaultp2p/env" ]] && source "$HOME/.vaultp2p/env"
[[ -f "$HOME/.memxp/env" ]] && source "$HOME/.memxp/env"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] memxp-guard: $*"; }

# --- Stale PID cleanup ---
if [[ -f "$PIDFILE" ]]; then
    pid=$(<"$PIDFILE")
    if kill -0 "$pid" 2>/dev/null; then
        log "Daemon already running (PID $pid). Nothing to do."
        exit 0  # Clean exit -> launchd won't restart (SuccessfulExit=false)
    else
        log "Stale PID file (PID $pid not running). Cleaning up."
        rm -f "$PIDFILE"
    fi
fi

# Clean legacy PID file
rm -f "$LEGACY_PIDFILE"

# --- Port check: make sure 5480 isn't already bound ---
if lsof -i :5480 -sTCP:LISTEN >/dev/null 2>&1; then
    log "Port 5480 already in use by another process. Aborting."
    exit 0
fi

# --- Log rotation: keep last 10 MB if log exceeds 50 MB ---
for logdir in "$HOME/.vaultp2p/logs" "$HOME/.memxp/logs"; do
    [[ -d "$logdir" ]] || continue
    for logfile in "$logdir"/*.log; do
        [[ -f "$logfile" ]] || continue
        size=$(stat -f%z "$logfile" 2>/dev/null || echo 0)
        if (( size > 52428800 )); then
            tail -c 10485760 "$logfile" > "${logfile}.tmp" && mv "${logfile}.tmp" "$logfile"
            log "Rotated $logfile (was $(( size / 1048576 )) MB)."
        fi
    done
done

# --- Start daemon ---
INSECURE_TLS="true"  # default for backward compat
CONFIG_FILE="$HOME/.memxp/config.yaml"
[[ ! -f "$CONFIG_FILE" ]] && CONFIG_FILE="$HOME/.vaultp2p/config.yaml"
if [[ -f "$CONFIG_FILE" ]]; then
    grep -q 'insecure_skip_tls_verify:\s*false' "$CONFIG_FILE" 2>/dev/null && INSECURE_TLS="false"
fi

log "Starting memxp daemon..."
if [[ "$INSECURE_TLS" == "true" ]]; then
    "$MEMXP" daemon start --insecure-skip-tls-verify 2>&1
else
    "$MEMXP" daemon start 2>&1
fi

sleep 2

if [[ ! -f "$PIDFILE" ]]; then
    log "ERROR: Daemon failed to start (no PID file created)."
    exit 1  # Non-zero -> launchd will retry after ThrottleInterval
fi

DAEMON_PID=$(<"$PIDFILE")
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

# --- Monitor loop: keep alive for launchd, exit if daemon dies ---
while true; do
    if [[ -f "$PIDFILE" ]]; then
        current_pid=$(<"$PIDFILE")
        if ! kill -0 "$current_pid" 2>/dev/null; then
            log "Daemon (PID $current_pid) is no longer running."
            rm -f "$PIDFILE"
            exit 1  # Non-zero -> launchd restarts us
        fi
    else
        log "PID file disappeared. Daemon likely stopped externally."
        exit 1
    fi
    sleep 30
done
