# memxp Usage Examples

Complete workflow examples for the memxp CLI and MCP tools.
MCP examples show the tool name as called from Claude Code
(prefixed `mcp__memxp__` in practice).

---

## 1. Solo Developer Workflow

### 1.1 Initialize the vault

```bash
# First-time setup (creates ~/.memxp/ directory, DB, config, and TLS certs)
memxp init

# On headless machines, set VAULT_PASSPHRASE first so init can encrypt non-interactively
export VAULT_PASSPHRASE="my-strong-passphrase"
memxp init
```

### 1.2 Store API keys

```bash
# Preferred — pipe value via stdin to avoid shell history exposure
echo "sk-proj-abc123def456" | memxp set api/openai/key -

# Inline form (value visible in shell history — use for non-sensitive data)
memxp set api/openai/key "sk-proj-abc123def456"

# With full metadata for search, rotation alerts, and impact tracking
echo "sk-proj-abc123def456" | memxp set api/openai/key - \
  --category api_key \
  --service openai \
  --notes "Production key, billing account eng@company.com" \
  --tags "ai,production" \
  --env production \
  --rotation-days 90

# Store a database connection string
memxp set postgres/prod/url "postgresql://app:s3cret@db.internal:5432/myapp" \
  --category password \
  --service postgres \
  --env production \
  --notes "Primary production database"

# Store an SSH private key from a file (value is the file contents)
memxp set deploy/ssh/private_key "$(cat ~/.ssh/deploy_ed25519)" \
  --category ssh_key \
  --service deploy \
  --notes "CI/CD deploy key for production servers"
```

### 1.3 Retrieve credentials

```bash
# Full output with metadata
memxp get api/openai/key

# Value only — useful for piping into other commands
memxp get api/openai/key --value-only

# Copy to clipboard instead of printing (auto-clears after 30s)
memxp get api/openai/key --clipboard

# JSON output for scripting
memxp get api/openai/key --json

# Redact output and copy to clipboard (safe for screen-sharing)
memxp get api/openai/key --redact
```

### 1.4 Smart lookup (fuzzy search + retrieve in one step)

```bash
# Natural language query — returns best matches with confidence scores
memxp smart-get "openai production key"

# Include the actual value in output
memxp smart-get "postgres password" --include-value

# Copy best match to clipboard without printing value
memxp smart-get "deploy ssh key" --clipboard --redact
```

### 1.5 Search and list credentials

```bash
# Keyword search across paths, notes, and tags (values are never shown)
memxp search "openai"
memxp search "production database"

# List all credentials for a service
memxp list --service openai

# List all API keys
memxp list --category api_key

# List everything under a path prefix
memxp list --prefix "postgres/"

# Get a bundle of all credentials under a prefix
memxp bundle "postgres/" --include-values

# High-level overview of the entire vault
memxp discover
```

### 1.6 Add operational guides (runbooks)

```bash
# Inline content
memxp guide add postgres-backup \
  --content "# PostgreSQL Backup

## Daily backup
\`\`\`bash
pg_dump -Fc myapp > /backups/myapp-\$(date +%Y%m%d).dump
\`\`\`

## Restore
\`\`\`bash
pg_restore -d myapp /backups/myapp-20260305.dump
\`\`\`" \
  --category runbook \
  --tags "postgres,backup,restore"

# From a markdown file
memxp guide add deploy-procedure \
  --file ./docs/deploy-runbook.md \
  --category procedure \
  --tags "deploy,production" \
  --related-paths "api/openai/key,postgres/prod/url"

# Retrieve a guide
memxp guide postgres-backup

# Search guides
memxp guide search "deploy"

# List all guides
memxp guide list

# List only runbooks
memxp guide list --category runbook

# Mark a guide as verified (confirms content is still accurate)
memxp guide verify postgres-backup

# Find stale guides (not verified in 90+ days)
memxp guide stale
```

### 1.7 Organize guides at scale (cross-references and routing)

As your guide count grows (50+), flat keyword search becomes inefficient.
Agents waste tokens guessing search terms instead of navigating directly.
The solution is a **convention layer** on top of memxp guides: cross-reference
headers, hub guides, and inline routing hints.

#### Header convention

Every guide should start with a blockquote header that links to related
guides. This gives agents immediate context without reading the full guide:

```markdown
> **Part of:** Data Warehouse Lakehouse · Hub: `data-warehouse-agent-reference`
> **Related:** `sms-vault-setup`, `scheduling-vault-setup` · **People:** `staff-directory`

# My Guide Title

Content here...
```

**Rules:**
- 1-2 lines max (~30 tokens)
- Never self-reference (don't link to yourself)
- Always point to the hub guide for the domain
- Use backtick-quoted guide names so agents can call `read_instructions("name")`

#### Hub guides (routing tables)

Hub guides act as domain indexes. They list child guides by category so
agents can navigate top-down instead of keyword-fishing:

```bash
memxp guide add vps-operations \
  --content "# VPS Operations Hub

## Deploy Guides
- \`vps-nginx-deploy\` — Nginx reverse proxy setup
- \`vps-docker-deploy\` — Docker Compose deployments

## Security
- \`vps-firewall\` — UFW rules and fail2ban
- \`vps-ssh-hardening\` — Key-only auth, port changes

## Monitoring
- \`vps-alerts\` — Uptime and disk monitoring" \
  --category runbook \
  --tags "hub,vps,index"
```

Agents start broad (`read_instructions("vps-operations")`) and drill into the
specific child guide they need — 2 tool calls instead of 5+ keyword searches.

#### Inline routing hints

When a guide references data stored elsewhere, include the exact query
an agent should run. This prevents agents from guessing:

```markdown
## Staff Contacts

See the full directory in `team-contacts`.

Individual records with phone, email, and title:
- `vault_list(prefix="company/staff/")` — all staff
- `vault_list(prefix="company/management/")` — management team

Each record is JSON: `recall("company/staff/jane-doe", include_value=true)`
```

**Why this matters:** Without inline hints, an agent that reads a guide and
needs phone numbers will try `find("phone")`,
`find("mobile")`, `find("cell number")` — burning 5-10 calls.
With the hint, it calls `vault_list(prefix="company/staff/")` once.

#### Naming convention

Use `<service>-<action>` or `<domain>-<topic>`:
- `vps-deploy`, `postgres-backup`, `caddy-ssl-renewal`
- `team-contacts`, `data-warehouse-lakehouse-v2`, `messaging-app-setup`

Consistent naming makes `find_instructions()` more predictable.

#### Example: full guide with routing

```bash
memxp guide add caddy-ssl-renewal \
  --content "> **Part of:** VPS Infrastructure · Hub: \`vps-operations\`
> **Related:** \`vps-deploy\`, \`vps-firewall\`

# Caddy SSL Renewal

## Prerequisites
- Caddy credentials: \`recall(\"caddy/api/key\")\`
- VPS SSH access: see \`vps-operations\`

## Steps
1. SSH into VPS: \`ssh root@192.0.2.10\`
2. Check cert: \`caddy list-certs\`
3. Force renewal: \`caddy renew --force\`

## Troubleshooting
If ACME fails, check firewall: see \`vps-firewall\`" \
  --category runbook \
  --tags "caddy,ssl,tls" \
  --related-paths "caddy/api/key"
```

### 1.8 Inject secrets as environment variables (never in chat history)

`vault_use` runs a command with a secret injected as an env var. The secret
never appears in shell history, process listings, or agent chat logs.

```bash
# Enable operator mode first (required for vault_use and expand)
memxp operator enable

# Run a curl command with the API key injected
memxp use api/openai/key OPENAI_API_KEY \
  --experimental \
  -- curl -s -H "Authorization: Bearer \$OPENAI_API_KEY" \
     https://api.openai.com/v1/models

# Run a database migration with the connection string injected
memxp use postgres/prod/url DATABASE_URL \
  --experimental \
  -- python manage.py migrate

# Disable operator mode when done
memxp operator disable
```

### 1.8 Template expansion with `<vault:path>` placeholders

Create config files with placeholders that get replaced with vault secrets.

Given a template file `docker-compose.template.yml`:
```yaml
services:
  app:
    environment:
      DATABASE_URL: <vault:postgres/prod/url>
      OPENAI_API_KEY: <vault:api/openai/key>
      REDIS_URL: <vault:redis/prod/url>
```

Expand it:
```bash
# Operator mode required
memxp operator enable

# Expand from file — writes to stdout
memxp expand docker-compose.template.yml > docker-compose.yml

# Expand from stdin
cat docker-compose.template.yml | memxp expand --stdin > docker-compose.yml

# JSON output shows replacement count and any missing paths
memxp expand docker-compose.template.yml --json
```

### 1.9 Batch import credentials

Create a JSON file `secrets.json`:
```json
[
  {
    "path": "aws/s3/access_key",
    "value": "AKIAIOSFODNN7EXAMPLE",
    "category": "api_key",
    "service": "aws",
    "notes": "S3 read-only access"
  },
  {
    "path": "aws/s3/secret_key",
    "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "category": "api_key",
    "service": "aws",
    "notes": "S3 read-only secret"
  }
]
```

```bash
# Operator mode required for batch operations
memxp operator enable
memxp set-batch --file secrets.json
# Output: saved=2 errors=0
```

### 1.10 Monitoring and hygiene

```bash
# Check for credentials nearing rotation (30-day window by default)
memxp rotation-alerts
memxp rotation-alerts --days 7 --include-overdue

# View audit log (who accessed what and when)
memxp audit --limit 20
memxp audit --path "api/openai/key"
memxp audit --action "get" --brief

# View change history
memxp changes --limit 10
memxp changes --prefix "postgres/"

# Impact analysis — which credentials affect a given app
memxp impact myapp

# Lint paths for duplicates, typos, and naming drift
memxp lint
memxp lint --prefix "api/" --include-suggestions

# Check if a credential exists (useful in scripts — exit code 0 if found)
memxp has api/openai/key

# Morning briefing — summary of conflicts and rotation alerts
memxp session-start

# Show the 5 most recently updated entries
memxp recent --limit 5
```

---

## 2. Multi-Machine Fleet

memxp uses cr-sqlite CRDTs over Tailscale for peer-to-peer sync.
Every machine maintains a full local copy of the vault database.

### 2.1 Initialize each machine with the same passphrase

The passphrase must be identical across all machines — it derives both the
database encryption key and the HMAC key used for sync authentication.

```bash
# On each machine:
export VAULT_PASSPHRASE="shared-fleet-passphrase-change-me"
memxp init

# Persist the passphrase for daemon use (macOS Keychain is inaccessible from
# launchd/systemd, so use an env file with restricted permissions)
mkdir -p ~/.memxp
echo 'export VAULT_PASSPHRASE="shared-fleet-passphrase-change-me"' > ~/.memxp/env
chmod 600 ~/.memxp/env

# Source it from your shell profile
echo 'source ~/.memxp/env' >> ~/.zprofile   # macOS
echo 'source ~/.memxp/env' >> ~/.bashrc     # Linux
```

### 2.2 Start the sync daemon

The daemon listens on port 5480 by default and syncs with discovered peers
at a configurable interval.

```bash
# Start with self-signed TLS (Tailscale provides the encryption layer)
memxp daemon start --insecure-skip-tls-verify

# Custom port and sync interval (seconds)
memxp daemon start --insecure-skip-tls-verify --port 5480 --interval 120

# Check daemon status
memxp daemon status

# Stop the daemon
memxp daemon stop
```

### 2.3 Manual one-shot sync

```bash
# Sync with a specific peer by Tailscale IP
memxp sync 100.64.1.2 --insecure-skip-tls-verify

# Check vault status (includes sync info)
memxp status
```

### 2.4 Production daemon setup (launchd / systemd)

**macOS (launchd):**

Create `~/Library/LaunchAgents/com.memxp.sync-daemon.plist` or use a
guard script at `~/.local/bin/memxp-daemon-guard`:

```bash
#!/bin/zsh
source "$HOME/.memxp/env"
exec "$HOME/.local/bin/memxp" daemon start --insecure-skip-tls-verify
```

```bash
chmod +x ~/.local/bin/memxp-daemon-guard
# Load via launchd plist pointing to the guard script
```

**Linux (systemd):**

Create `/etc/systemd/system/memxp-daemon.service`:
```ini
[Unit]
Description=memxp Sync Daemon
After=network-online.target

[Service]
Type=simple
EnvironmentFile=/root/.memxp/env.systemd
ExecStart=/root/.local/bin/memxp daemon start --insecure-skip-tls-verify
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Note: the systemd `EnvironmentFile` format requires lines like
`VAULT_PASSPHRASE=value` (no `export` keyword).

```bash
systemctl daemon-reload
systemctl enable --now memxp-daemon
```

### 2.5 Handle sync conflicts

By default, conflicts are resolved using Last-Write-Wins (LWW). For
sensitive paths, you can switch to `review` mode so conflicts queue for
manual resolution.

```bash
# Set review mode for production database credentials
memxp conflict-mode "postgres/prod/*" review

# Set auto (LWW) mode for less sensitive paths
memxp conflict-mode "api/*" auto

# List pending conflicts
memxp conflicts

# Get conflict statistics
memxp conflicts --stats

# Resolve a conflict
memxp resolve <conflict-id> keep_local
memxp resolve <conflict-id> keep_remote
memxp resolve <conflict-id> merge --value "merged-value" --notes "Combined both versions"
```

### 2.6 Export and import (migration / backup)

```bash
# Export entire vault to JSON (includes credentials and guides)
memxp export -o vault-backup-20260305.json

# Import into a new vault
memxp import vault-backup-20260305.json
```

> **Security note:** `memxp export` writes plaintext JSON including credential
> values. Encrypt the output if storing it:
> ```bash
> memxp export | gpg --symmetric --cipher-algo AES256 > vault-backup.gpg
> ```

---

## 3. Claude Code / MCP Integration

### 3.1 Configure MCP server

Add to `~/.mcp.json`:
```json
{
  "mcpServers": {
    "memxp": {
      "command": "/Users/you/.local/bin/memxp",
      "args": ["mcp"]
    }
  }
}
```

All MCP tools are then available in Claude Code as `mcp__memxp__<tool_name>`.

### 3.2 Typical agent session: discover, search, get

An agent starting a new session should follow this pattern:

```
Agent: I need the OpenAI API key for this project.

Step 1 — Discover what's in the vault:
  whats_saved()
  -> { total_credentials: 47, total_guides: 12,
       services: { openai: 3, postgres: 5, aws: 4, ... } }

Step 2 — Search for the credential:
  find(query="openai")
  -> { results: [
         { path: "api/openai/key", category: "api_key", service: "openai" },
         { path: "api/openai/org_id", category: "api_key", service: "openai" }
       ]}

Step 3 — Get the value (include_value=true to receive plaintext):
  recall(path="api/openai/key", include_value=true)
  -> { path: "api/openai/key", value: "sk-proj-abc123..." }
```

Or use `smart_recall` to combine search + get in one call:

```
  smart_recall(query="openai production key", include_value=true)
  -> { matches: [
         { path: "api/openai/key", confidence: 92, value: "sk-proj-abc123..." }
       ]}
```

### 3.3 Safe secret handling (redact / clipboard / inject)

Agents should avoid exposing secrets in chat history. Three patterns:

```
# Pattern 1: Redact — value goes to clipboard, response shows [REDACTED]
recall(path="api/openai/key", include_value=true, redact=true)
-> { path: "api/openai/key", value: "[REDACTED - copied to clipboard]",
     _clipboard: "Value copied to clipboard (auto-clears in 30s)" }

# Pattern 2: Inject — set as env var in the MCP server process
vault_inject(path="api/openai/key", env_var="OPENAI_API_KEY")
-> { status: "injected", path: "api/openai/key", env_var: "OPENAI_API_KEY" }

# Pattern 3: Use — run a command with the secret, see only stdout/stderr
vault_use(
  path="api/openai/key",
  env_var="OPENAI_API_KEY",
  command=["curl", "-s", "-H", "Authorization: Bearer $OPENAI_API_KEY",
           "https://api.openai.com/v1/models"]
)
-> { exit_code: 0, stdout: "{ \"data\": [...] }", stderr: "" }
```

### 3.4 Guide workflow

```
# Search for relevant guides
find_instructions(query="deploy")
-> { guides: [
       { name: "vps-deploy", category: "procedure" },
       { name: "deploy-procedure", category: "procedure" }
     ]}

# Read the guide
read_instructions(name="vps-deploy")
-> { name: "vps-deploy", content: "# VPS Deploy\n\n## Steps\n1. SSH in...",
     category: "procedure", tags: ["deploy", "production"] }

# After following the guide successfully, verify it
verify_instructions(name="vps-deploy")

# Add a new guide after figuring out a procedure
save_instructions(
  name="caddy-ssl-renewal",
  content="# Caddy SSL Renewal\n\n## Steps\n1. Check cert expiry...",
  category="runbook",
  tags=["caddy", "ssl", "tls"],
  related_paths=["caddy/api/key"]
)
```

### 3.5 Operator mode for mutations

Mutations (set existing, delete, batch operations, expand, use) require
operator mode. The agent must provide the vault passphrase to elevate.

```
# Enable operator mode (15 minutes by default, max 4 hours)
vault_operator_mode(enable=true, password="vault-passphrase")
-> { operator_active: true, operator_expires_at: "2026-03-05T15:30:00Z" }

# Now mutations work
remember(path="api/stripe/key", value="sk_live_...", category="api_key",
          service="stripe", notes="Live payment key")
forget(path="api/old-service/key")

# Disable when done
vault_operator_mode(enable=false)

# Check current auth status at any time
vault_auth_status()
-> { authenticated: true, locked: false, operator_active: false, ... }
```

### 3.6 Session token authentication (optional hardening)

For additional security, require a session token before the MCP server
responds to any tool calls:

```bash
# Set the token as an environment variable before launching Claude Code
export VAULT_MCP_SESSION_TOKEN="random-session-token-here"
```

Update `~/.mcp.json`:
```json
{
  "mcpServers": {
    "memxp": {
      "command": "/Users/you/.local/bin/memxp",
      "args": ["mcp"],
      "env": {
        "VAULT_MCP_SESSION_TOKEN": "random-session-token-here"
      }
    }
  }
}
```

The agent must then authenticate before any other tool works:
```
vault_authenticate(token="random-session-token-here")
-> { authenticated: true, message: "MCP session authenticated." }
```

### 3.7 Lock and unlock

```
# Lock the vault (blocks all tool access)
vault_lock()
-> { status: "locked" }

# Unlock with passphrase
vault_unlock(password="vault-passphrase")
-> { status: "unlocked" }
```

---

## 4. CI/CD Secret Injection

### 4.1 Inject secrets into a build script with `vault_use`

```bash
# In your CI pipeline (after sourcing ~/.memxp/env):
memxp operator enable

# Run tests with the database URL injected
memxp use postgres/staging/url DATABASE_URL \
  --experimental \
  -- pytest tests/ -v

# Build a Docker image with a build arg
memxp use api/sentry/dsn SENTRY_DSN \
  --experimental \
  -- docker build --build-arg "SENTRY_DSN=$SENTRY_DSN" -t myapp:latest .

memxp operator disable
```

### 4.2 Generate config files with `vault_expand`

Template file `deploy/.env.template`:
```
DATABASE_URL=<vault:postgres/prod/url>
REDIS_URL=<vault:redis/prod/url>
OPENAI_API_KEY=<vault:api/openai/key>
SENTRY_DSN=<vault:api/sentry/dsn>
SECRET_KEY=<vault:myapp/django/secret_key>
```

CI script:
```bash
#!/bin/bash
set -euo pipefail

source ~/.memxp/env
memxp operator enable

# Expand template into actual .env file
memxp expand deploy/.env.template > .env

# Deploy
docker compose --env-file .env up -d

# Clean up — never leave plaintext .env on disk longer than needed
rm -f .env
memxp operator disable
```

### 4.3 Generate a docker-compose.yml from a template

Template `docker-compose.template.yml`:
```yaml
version: "3.8"
services:
  app:
    image: myapp:latest
    environment:
      DATABASE_URL: <vault:postgres/prod/url>
      REDIS_URL: <vault:redis/prod/url>
      SECRET_KEY: <vault:myapp/django/secret_key>
  worker:
    image: myapp:latest
    command: celery -A myapp worker
    environment:
      DATABASE_URL: <vault:postgres/prod/url>
      BROKER_URL: <vault:redis/prod/url>
```

```bash
memxp operator enable
memxp expand docker-compose.template.yml > docker-compose.yml
docker compose up -d
rm docker-compose.yml   # remove plaintext secrets
memxp operator disable
```

### 4.4 Check credential existence in scripts

```bash
#!/bin/bash
# Pre-flight check: ensure all required credentials exist before deploying

required_paths=(
  "postgres/prod/url"
  "api/openai/key"
  "api/sentry/dsn"
  "myapp/django/secret_key"
)

missing=0
for path in "${required_paths[@]}"; do
  if ! memxp has "$path" --quiet; then
    echo "MISSING: $path"
    missing=$((missing + 1))
  fi
done

if [ $missing -gt 0 ]; then
  echo "ERROR: $missing required credentials missing. Aborting deploy."
  exit 1
fi

echo "All credentials present. Proceeding with deploy."
```

### 4.5 Bundle retrieval for environment setup

```bash
# Get all postgres credentials at once (values included)
memxp bundle "postgres/prod" --include-values --json

# Example output:
# {
#   "prefix": "postgres/prod",
#   "count": 3,
#   "entries": [
#     { "path": "postgres/prod/url", "value": "postgresql://..." },
#     { "path": "postgres/prod/user", "value": "app" },
#     { "path": "postgres/prod/password", "value": "s3cret" }
#   ]
# }
```

---

## 5. Agent Messaging (Planned)

Multi-machine agent coordination via P2P task queues is planned for a future release.
The sync protocol already supports the underlying data replication — the agent-facing
API is being redesigned around the friendly tool naming convention.

---

## 6. Quick Reference

### CLI command summary

| Command | Purpose |
|---------|---------|
| `memxp init` | Initialize vault (dirs, DB, config, TLS certs) |
| `memxp set <path> <value>` | Store a credential |
| `memxp get <path>` | Retrieve a credential |
| `memxp delete <path>` | Delete a credential |
| `memxp search <query>` | Search by keyword |
| `memxp list` | List credentials with filters |
| `memxp smart-get <query>` | Fuzzy search + retrieve |
| `memxp has <path>` | Check existence (exit code) |
| `memxp bundle <prefix>` | Get all creds under a prefix |
| `memxp set-batch --file <f>` | Batch import from JSON |
| `memxp discover` | Vault overview |
| `memxp recent` | Recently updated entries |
| `memxp guide <name>` | Read a guide |
| `memxp guide add <name>` | Add/update a guide |
| `memxp guide search <q>` | Search guides |
| `memxp guide list` | List all guides |
| `memxp guide verify <name>` | Mark guide as verified |
| `memxp guide deprecate <n>` | Deprecate a guide |
| `memxp guide stale` | Find unverified guides |
| `memxp inject <path> <var>` | Set env var in process |
| `memxp use <path> <var> -- cmd` | Run command with injected secret |
| `memxp expand [file]` | Expand `<vault:path>` placeholders |
| `memxp operator enable` | Elevate to operator mode |
| `memxp operator disable` | Drop operator mode |
| `memxp daemon start` | Start sync daemon |
| `memxp daemon stop` | Stop sync daemon |
| `memxp daemon status` | Check daemon status |
| `memxp sync <peer>` | One-shot sync with peer |
| `memxp conflicts` | List sync conflicts |
| `memxp resolve <id> <res>` | Resolve a conflict |
| `memxp conflict-mode <p> <m>` | Set conflict handling mode |
| `memxp audit` | View audit log |
| `memxp changes` | View change history |
| `memxp impact <app>` | Credential impact analysis |
| `memxp lint` | Path hygiene analysis |
| `memxp rotation-alerts` | Rotation/expiry alerts |
| `memxp session-start` | Morning briefing |
| `memxp status` | Vault status |
| `memxp export` | Export vault to JSON |
| `memxp import <file>` | Import vault from JSON |
| `memxp config show` | Show current configuration |
| `memxp web` | Launch web GUI (port 8777) |
| `memxp mcp` | Launch MCP server on stdio |
| `memxp lock` | Lock CLI access |
| `memxp unlock` | Unlock CLI access |

### MCP tool summary

| Tool | Operator? | Description |
|------|-----------|-------------|
| `vault_help` | No | Usage guide |
| `whats_saved` | No | Vault overview |
| `recent` | No | Recently updated entries |
| `vault_session_start` | No | Morning briefing |
| `vault_list` | No | List credentials (masked) |
| `find` | No | Keyword search (no values) |
| `smart_recall` | No | Fuzzy search + retrieve |
| `recall` | No | Get credential by path |
| `remember` | Yes* | Store credential (*new paths don't require operator) |
| `forget` | Yes | Delete credential |
| `remember_batch` | Yes | Batch store credentials |
| `recall_bundle` | No | Get all creds under prefix |
| `vault_inject` | No | Set env var in MCP process |
| `vault_show_gui` | No | Display in GUI (no value in response) |
| `vault_audit` | No | View audit log |
| `vault_use` | Yes | Run command with injected secret |
| `vault_expand` | Yes | Expand `<vault:path>` placeholders |
| `vault_changes` | No | View change history |
| `vault_impact` | No | App impact analysis |
| `vault_lint` | No | Path hygiene analysis |
| `vault_rotation_alerts` | No | Rotation/expiry alerts |
| `vault_conflicts` | No | List sync conflicts |
| `vault_resolve_conflict` | Yes | Resolve a conflict |
| `vault_conflict_mode` | Yes | Set conflict mode for path |
| `save_instructions` | Yes* | Add guide (*new guides don't require operator) |
| `read_instructions` | No | Read a guide |
| `list_instructions` | No | List guides |
| `find_instructions` | No | Search guides |
| `forget_instructions` | Yes | Delete a guide |
| `verify_instructions` | No | Mark guide verified |
| `deprecate_instructions` | Yes | Mark guide deprecated |
| `stale_instructions` | No | Find stale guides |
| `vault_authenticate` | No | Authenticate MCP session |
| `vault_auth_status` | No | Check auth state |
| `vault_operator_mode` | No | Enable/disable operator mode |
| `vault_lock` | No | Lock vault |
| `vault_unlock` | No | Unlock vault |
