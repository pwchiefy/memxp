# memxp

**A second brain for your coding agent.**

Today's coding agents are spiky geniuses with periodic amnesia. memxp fixes that.
It gives your agent an encrypted, persistent record of what you work on, what works,
what fails, and how to help -- so every session picks up where the last one left off.

---

## Get Started (2 minutes)

One command installs everything -- memxp, Claude Code (if you don't have it),
encrypted storage, and the onboarding system. Nothing else to configure.

```bash
curl -fsSL https://raw.githubusercontent.com/pwchiefy/memxp/main/scripts/install.sh | sh
```

The installer will:
1. Install **Claude Code** if you don't have it (includes Node.js and Homebrew if needed)
2. Download and set up **memxp** with encrypted storage
3. Connect memxp to Claude Code with permissions pre-approved
4. Create your **project directory** (defaults to ~/Developer)
5. Set up your **learning journal** so your agent improves over time

After install, open Terminal and run:

```bash
cd ~/Developer
claude
```

Claude will introduce itself, ask a few questions about you and what you work on,
and from there every session builds on the last. That's it.

> **What can you use it for?** Coding projects, data analysis, personal finance,
> planning, operations, learning -- anything where you'd benefit from an AI partner
> that actually remembers your work. Your agent keeps track of what works, what
> breaks, and how to do things right.

---

## Why memxp?

### The Problem

Every AI coding tool tells you to create markdown files: `CLAUDE.md`, `.cursorrules`, `AGENTS.md`.
You maintain them by hand. They drift across machines. They go stale.
Switch tools and you start over. Your agent asks the same questions every session.

### The Solution

memxp is an encrypted knowledge base that replaces scattered config files with a
shared second brain. Your agent reads from it, writes to it, and gets better over
time. It keeps a record of what you work on, what works, what fails, and how to
give each session the best shot at success. Never attempt a task alone again.

- **Second brain** -- Guides, procedures, learnings, and credentials in one place
- **Gets smarter** -- A learning journal tracks mistakes so they never repeat
- **Encrypted** -- API keys, tokens, passwords -- AES-256 at rest, zero plaintext
- **Syncs everywhere** -- Automatic P2P replication across your machines
- **Works with any agent** -- Claude Code, Cursor, Codex, Pi, OpenCode -- anything that speaks MCP
- **Single binary** -- CLI, MCP server, sync daemon, and web GUI in one `memxp` binary

---

## How It Works

```
  Machine A (macOS)                               Machine B (Linux VPS)
 +----------------------+                        +----------------------+
 |  memxp CLI / MCP  |                        |  memxp CLI / MCP  |
 |         |            |                        |         |            |
 |    +----v----+       |   Tailscale Mesh       |    +----v----+       |
 |    | SQLite  |       |   (WireGuard)          |    | SQLite  |       |
 |    | Cipher  |<------+------------------------+---->| Cipher  |       |
 |    |  + CRDT |       |  HMAC-authenticated    |    |  + CRDT |       |
 |    +---------+       |  binary protocol       |    +---------+       |
 +----------------------+  over mutual TLS       +----------------------+
           |                                                |
           |            Machine C (Windows)                 |
           |           +----------------------+             |
           |           |  memxp CLI / MCP  |             |
           |           |         |            |             |
           +---------->|    +----v----+       |<------------+
                       |    | SQLite  |       |
                       |    | Cipher  |       |
                       |    |  + CRDT |       |
                       |    +---------+       |
                       +----------------------+
```

Each machine maintains its own encrypted SQLite database. The sync daemon runs in the
background and replicates changes using [cr-sqlite](https://github.com/vlcn-io/cr-sqlite)
CRDTs over a custom binary protocol (MessagePack payloads, HMAC-SHA256 authenticated,
TLS-encrypted). Tailscale provides the network mesh -- no ports exposed to the public
internet.

Changes merge automatically. When two machines modify the same entry simultaneously,
memxp resolves it via last-write-wins (LWW) or queues the conflict for manual review,
depending on your per-path conflict policy.

---

## Developer Setup

If you already have Claude Code and want manual control, or if you're
building from source:

### Install from source

```bash
cargo install --git https://github.com/pwchiefy/memxp.git memxp
memxp init
memxp doctor   # verify everything works

# Register with Claude Code
claude mcp add memxp -s user -- memxp mcp
```

### Manual setup (without the installer)

```bash
# Add a guide
memxp guide add deploy-vps \
  --content "# Deploy to VPS\n1. SSH into server..." \
  --category procedure

# Store a credential
memxp set openai/api/key "sk-..." --service openai --category api_key

# Your agent can now access your knowledge via MCP:
#   read_instructions("deploy-vps")
#   recall("openai/api/key")
```

### Start the sync daemon

```bash
memxp daemon start --interval 60
```

The daemon listens on port 5480 and syncs with discovered peers every 60 seconds.
Peers are discovered automatically via Tailscale, or you can trigger a manual sync:

```bash
memxp sync 100.64.0.2
```

### Launch the web dashboard

```bash
memxp web --port 8777
# Open http://127.0.0.1:8777
```

---

## Agent Knowledge System

memxp is persistent memory for AI coding agents. Guides are Markdown documents
stored inside the encrypted database, synced across all machines, and accessible
via both CLI and MCP. Agents read them, follow them, and write improved versions
back -- building institutional knowledge that compounds over time.

### Guides

Guides store operational knowledge: deployment procedures, troubleshooting steps,
architecture decisions, configuration recipes. They sync across machines just like
credentials, so an agent on your laptop can read a guide written by an agent on your
server.

```bash
# Store a deployment runbook
memxp guide add deploy-production \
  --file deploy.md \
  --category runbook \
  --tags "production,deploy,caddy"

# Retrieve it
memxp guide deploy-production

# Track freshness
memxp guide verify deploy-production

# Find stale guides (not verified in 90+ days)
memxp guide stale --days 90
```

### Session Context

The `session-start` command gives agents a morning briefing -- unresolved conflicts,
rotation alerts, and recent changes:

```bash
memxp session-start --rotation-window-days 7
```

Via MCP, agents call `vault_session_start()` to get this context at the beginning
of a conversation.

### Impact Analysis

Before rotating a credential, agents can check which applications depend on it:

```bash
memxp impact myapp
```

This returns all credentials tagged with that application, so the agent knows what
will break if a secret changes.

---

## CLI Reference

### Guides (Knowledge Base)

| Command | Description |
|---------|-------------|
| `memxp guide <name>` | Retrieve a guide by name |
| `memxp guide add <name> --file doc.md` | Add or update a guide from a file |
| `memxp guide list` | List all guides (supports `--category`, `--status`) |
| `memxp guide search <query>` | Search guides by content, name, or tags |
| `memxp guide verify <name>` | Mark a guide as verified (freshness tracking) |
| `memxp guide stale --days 90` | Find guides that haven't been verified recently |

### Credentials

| Command | Description |
|---------|-------------|
| `memxp get <path>` | Retrieve a credential (supports `--value-only`, `--clipboard`, `--redact`, `--json`) |
| `memxp set <path> <value>` | Store a credential (supports `--service`, `--category`, `--tags`, `--rotation-days`) |
| `memxp delete <path>` | Delete a credential |
| `memxp list` | List all credentials with masked values (supports `--service`, `--category`, `--prefix`) |
| `memxp search <query>` | Full-text search across paths, notes, and tags |
| `memxp smart-get <query>` | Fuzzy lookup -- returns best match with confidence score |
| `memxp bundle <prefix>` | Get all credentials under a path prefix |
| `memxp set-batch --file creds.json` | Bulk import credentials from JSON |
| `memxp has <path>` | Check if a credential exists (exit code 0/1) |

### Sync and Daemon

| Command | Description |
|---------|-------------|
| `memxp daemon start` | Start the background sync daemon (port 5480) |
| `memxp daemon stop` | Stop the sync daemon |
| `memxp daemon status` | Check if the daemon is running |
| `memxp sync [peer]` | One-shot sync with a specific peer or all known peers |
| `memxp conflicts` | List unresolved sync conflicts |
| `memxp resolve <id> <resolution>` | Resolve a conflict (`keep_local`, `keep_remote`, `merge`) |

### Security and Operations

| Command | Description |
|---------|-------------|
| `memxp inject <path> <ENV_VAR>` | Inject a credential into an environment variable |
| `memxp use <path> <ENV_VAR> -- cmd` | Run a command with a secret injected as an env var |
| `memxp expand <file>` | Replace `<vault:path>` placeholders with secret values |
| `memxp audit` | View the access audit log |
| `memxp rotation-alerts --days 30` | Check for credentials nearing rotation |
| `memxp lint` | Analyze paths for naming issues and duplicates |
| `memxp lock` / `unlock` | Lock/unlock the vault |
| `memxp operator enable` | Enable operator mode for high-risk mutations |

### Utilities

| Command | Description |
|---------|-------------|
| `memxp status` | Vault health overview |
| `memxp doctor` | Health check — diagnoses issues with plain-language output and fix suggestions |
| `memxp discover` | Summary of services, categories, and totals |
| `memxp export -o backup.json` | Export vault to JSON |
| `memxp import backup.json` | Import vault from JSON |
| `memxp self-update` | Update to the latest release |
| `memxp web --port 8777` | Launch the web GUI |
| `memxp mcp` | Start the MCP server (stdio transport) |

---

## MCP Integration

memxp includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/)
server with 37 tools. This lets AI agents like Claude Code interact with your
knowledge base and credentials directly -- no shell wrappers or fragile parsing needed.

### Setup with Claude Code

Add to your `~/.mcp.json`:

```json
{
  "mcpServers": {
    "memxp": {
      "command": "memxp",
      "args": ["mcp"]
    }
  }
}
```

Claude Code will automatically discover all 37 tools on startup.

### Example tool calls

```
# Agent reads an operational guide
read_instructions(name="deploy-production")

# Agent saves a new runbook it figured out
save_instructions(name="redis-failover", content="# Redis Failover\n\n1. Check sentinel...", category="runbook")

# Agent discovers what's in the vault
whats_saved()

# Agent searches for a credential
find(query="openai")

# Agent retrieves the value
recall(path="api/openai/key")

# Agent stores a new credential it generated
remember(path="aws/deploy/token", value="AKIA...", service="aws", category="api_key")

# Agent checks for rotation alerts
vault_rotation_alerts(window_days=7)

# Agent injects a secret for a build (never appears in chat)
vault_inject(path="npm/token", env_var="NPM_TOKEN")
```

### MCP Tool Groups

| Group | Tools | Examples |
|-------|-------|---------|
| How-tos | 8 | `read_instructions`, `save_instructions`, `find_instructions`, `verify_instructions` |
| Memory | 12 | `recall`, `remember`, `find`, `smart_recall`, `remember_batch` |
| Security | 5 | `vault_inject`, `vault_use`, `vault_expand`, `vault_audit`, `vault_show_gui` |
| Auth | 5 | `vault_lock`, `vault_unlock`, `vault_operator_mode`, `vault_auth_status`, `vault_authenticate` |
| Monitoring | 4 | `vault_changes`, `vault_impact`, `vault_lint`, `vault_rotation_alerts` |
| Conflicts | 3 | `vault_conflicts`, `vault_resolve_conflict`, `vault_conflict_mode` |

---

## Security Model

### Encryption at Rest

- Database encrypted with **SQLCipher** (AES-256-CBC, HMAC-SHA1 page-level authentication)
- Encryption key derived from passphrase via SQLCipher's internal **PBKDF2-HMAC-SHA512** (256K iterations)
- Passphrase stored in **OS keychain** (macOS Keychain, Windows Credential Manager, Linux Secret Service) or an env var
- On headless machines, passphrase loaded from `VAULT_PASSPHRASE` environment variable

### Encryption in Transit

- All peer-to-peer sync uses **mutual TLS** (self-signed certificates, auto-generated)
- Custom binary wire protocol with **HMAC-SHA256** message authentication
- HMAC key derived from the shared vault passphrase -- only machines with the same passphrase can sync
- Transport runs over **Tailscale** (WireGuard) -- double-encrypted, no public internet exposure

### Access Control

- **Vault lock/unlock** -- Lock the vault to block all access; unlock requires the passphrase
- **Operator mode** -- Time-limited elevation (default 15 minutes) required for destructive operations (delete, expand, use)
- **Challenge-response** -- Operator mode activation requires passphrase verification
- **MCP session tokens** -- Optional `VAULT_MCP_SESSION_TOKEN` to authenticate MCP processes
- **Audit logging** -- Every read, write, and administrative action is logged with timestamps and machine IDs

### Path Naming

Credentials follow a hierarchical `service/resource/detail` convention:

```
aws/s3/access_key
postgres/prod/url
openai/api/key
```

The `vault lint` command detects naming issues, near-duplicates, and drift.

---

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS | ARM64 (Apple Silicon) | Supported |
| macOS | x86_64 (Intel) | Supported |
| Linux | x86_64 (GNU) | Supported |
| Windows | x86_64 | Supported |

Pre-built binaries are published with each [GitHub release](https://github.com/pwchiefy/memxp/releases).

---

## Project Structure

memxp is a Cargo workspace with five crates:

```
crates/
  vault-core/    Core database, crypto, config, audit logging
  vault-sync/    P2P sync protocol, daemon, CRDT replication
  vault-mcp/     MCP server (37 tools via rmcp)
  vault-web/     Web dashboard (Axum + embedded static files)
  vault-cli/     CLI binary (40+ commands via clap)
tests/           Integration and end-to-end tests
```

---

## Self-Update

Check for updates:

```bash
memxp self-update --check
```

Update to latest:

```bash
memxp self-update
```

Verify installed binary against release checksums:

```bash
memxp self-update --verify-only --version v0.1.0
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branch conventions, and
review expectations. Keep commits focused and small. Security-sensitive changes require
a risk review in the PR.

## Security

Report security issues privately. Do not file public issues for vulnerabilities.
See [SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

MIT. See [LICENSE](LICENSE).
