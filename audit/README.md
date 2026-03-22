# memxp-audit

A self-auditing knowledge system for memxp. Discovers what to check by searching your memxp database, verifies claims against reality through parallel Claude agents, and reports discrepancies.

## Why

memxp stores guides, credentials, error journals, and project indexes. This knowledge goes stale silently — guides claim things that are no longer true, trackers fall behind reality, pipelines die without anyone noticing. A daily summary of cached metadata won't catch this. You need **verification**.

memxp-audit compares what your knowledge base *claims* against what's *actually true*.

## How it works

```
memxp-audit.sh
├── Phase 1: Pre-collect raw data (bash — SSH, git, curl — fast, deterministic)
├── Phase 2: Parallel audit agents (4x claude -p with MCP access)
│   ├── knowledge-health    — guide freshness, contradictions, dead references
│   ├── meditation-patterns  — recurring errors, unresolved issues
│   ├── project-activity     — project index vs actual git/vault activity
│   └── infrastructure-verify — guide claims vs live system data (optional)
├── Phase 3: Wait + collect results
└── Phase 4: Synthesis agent → unified report with Discrepancies section
```

**Key design choices:**
- **Discovery-based**: Agents search memxp to find what to check — no hardcoded guide names
- **Pre-collection**: Raw data collected by bash (seconds), agents only read files + MCP (no Bash tool = no runaway SSH loops)
- **Parallel**: 4 agents run concurrently, each specialized on one domain
- **Graceful degradation**: SSH fails → UNVERIFIED. Agent fails → AGENT_FAILED. Synthesis fails → concatenated raw outputs. Always produces a report.
- **No PII in code**: All user-specific data (IPs, SSH targets, paths) lives in your config file only

## Install

```bash
cd audit
bash install.sh
```

This copies prompts to `~/.local/share/memxp-audit/prompts/`, installs the CLI to `~/.local/bin/memxp-audit`, and creates a config template at `~/.config/memxp-audit/config.env`.

Edit the config with your paths:

```bash
$EDITOR ~/.config/memxp-audit/config.env
```

At minimum, set `MEMORY_FILE` and `MEDITATION_FILE`. Everything else is optional.

## Usage

```bash
memxp-audit              # Run (skips if today's report exists)
memxp-audit --force      # Force re-run
```

Reports are saved to `~/.local/share/memxp-audit/reports/YYYY-MM-DD.md`.

## Run daily (optional)

### macOS (launchd)

Create `~/Library/LaunchAgents/com.memxp.audit.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.memxp.audit</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${HOME}/.local/bin/memxp-audit</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>6</integer>
    <key>Minute</key><integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>${HOME}/.local/share/memxp-audit/launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${HOME}/.local/share/memxp-audit/launchd.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>${HOME}</string>
  </dict>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.memxp.audit.plist
```

### Linux (systemd)

```bash
# ~/.config/systemd/user/memxp-audit.service
[Unit]
Description=memxp daily audit

[Service]
Type=oneshot
ExecStart=%h/.local/bin/memxp-audit

# ~/.config/systemd/user/memxp-audit.timer
[Unit]
Description=Run memxp-audit daily at 6am

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable --now memxp-audit.timer
```

## Configuration

All configuration lives in `~/.config/memxp-audit/config.env`. See `config.example.env` for all options.

| Setting | Required | Description |
|---------|----------|-------------|
| `MEMORY_FILE` | Yes | Path to your MEMORY.md routing index |
| `MEDITATION_FILE` | Yes | Path to your Meditation.md error journal |
| `AUDIT_MODEL` | No | Claude model (default: sonnet) |
| `AGENT_BUDGET` | No | USD budget per agent (default: 0.75) |
| `SYNTHESIS_BUDGET` | No | USD budget for synthesis (default: 1.00) |
| `SSH_TARGETS` | No | Space-separated `user@host:label` for infrastructure checks |
| `GH_OWNER` | No | GitHub org/user for repo visibility checks |
| `PRODUCT_URLS` | No | Space-separated URLs to health-check |
| `SIGNAL_PHONE` | No | Phone number for Signal notification |
| `COPY_TO` | No | Secondary output directory (e.g., cloud sync folder) |

## The Discrepancies section

The core value of memxp-audit. Every mismatch between what your knowledge base claims and what was observed:

```
## Discrepancies Found
| # | Agent | Source Says | Reality Shows | Action Needed |
|---|-------|-------------|---------------|---------------|
| 1 | infrastructure-verify | guide: "backup runs daily at 2am" | No backup files found | Check backup cron |
| 2 | project-activity | MEMORY.md: project not indexed | 10 active guides exist | Add to index |
| 3 | meditation-patterns | avoidance rule written | Same error recurred 3x | Rule isn't working |
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- memxp with MCP server configured in `~/.mcp.json`
- `timeout` command (Linux: built-in, macOS: `brew install coreutils`)
- Optional: `ssh`, `gh`, `curl`, `signal-cli` for extended checks

## Cost

~$0.80–1.50/day with Sonnet. Configurable via `AGENT_BUDGET` and `SYNTHESIS_BUDGET`.
