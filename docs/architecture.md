# memxp Architecture

**Version:** 0.1.0
**Last updated:** 2026-03-05

---

## System Overview

memxp is a 5-crate Rust workspace (plus an integration test crate) that provides persistent memory for AI coding agents with P2P synchronization.

```
+-----------------------------------------------------------------------------------+
|                               memxp workspace                                      |
|                                                                                    |
|  +-------------+     +-------------+     +-------------+     +-------------+       |
|  | vault-cli   |     | vault-mcp   |     | vault-web   |     | vault-sync  |       |
|  | (binary)    |     | (MCP server)|     | (web GUI)   |     | (P2P daemon)|       |
|  |             |     |             |     |             |     |             |       |
|  | clap CLI    |     | rmcp stdio  |     | axum HTTP   |     | TLS+HMAC   |        | 
|  | 40+ cmds    |     | 37+ tools   |     | REST API    |     | TCP server  |       |
|  +------+------+     +------+------+     +------+------+     +------+------+       |
|         |                   |                   |                   |              |
|         +-------------------+-------------------+-------------------+              |
|                             |                                                      |
|                    +--------+--------+                                             |
|                    |   vault-core    |                                             |
|                    |   (library)     |                                             |
|                    |                 |                                             |
|                    | CrSqliteDatabase|                                             |
|                    | Crypto (SHA-256)|                                             |
|                    | Auth / Keyring  |                                             |
|                    | Conflicts       |                                             |
|                    | AuditLogger     |                                             |
|                    | Config          |                                             |
|                    | Models          |                                             |
|                    +-----------------+                                             |
|                             |                                                      |
|              +--------------+--------------+                                       |
|              |                             |                                       |
|     +--------+--------+          +--------+--------+                               |
|     | SQLCipher DB     |          | OS Keychain     |                              |
|     | (AES-256-CBC)    |          | (macOS/Win/Lin) |                              |
|     | + cr-sqlite CRDT |          +-----------------+                              |
|     +-----------------+                                                            |
|                                                                                    |
+-----------------------------------------------------------------------------------+
                    |                                      |
                    v                                      v
           +----------------+                     +----------------+
           | Peer Machine A |  <-- Tailscale -->  | Peer Machine B |
           | (100.x.x.x)   |   TLS + HMAC-SHA256 | (100.y.y.y)   |
           +----------------+                     +----------------+
```

---

## Crate Responsibilities

| Crate | Type | Purpose | Key Types / Traits |
|-------|------|---------|-------------------|
| `vault-core` | Library | Database, cryptography, models, authentication, conflict resolution, audit logging, configuration | `CrSqliteDatabase`, `CredentialStore`, `VaultEntry`, `VaultGuide`, `SyncChange`, `ConflictQueue`, `AuditLogger`, `ChallengeStore`, `VaultConfig` |
| `vault-sync` | Library | P2P sync protocol, daemon, session management, wire serialization, capability negotiation | `SyncDaemon`, `DaemonConfig`, `WireFrame`, `MessageType`, `SyncSession`, `PeerCapabilities`, `HelloMessage`, `SyncRequest`, `SyncResponse` |
| `vault-mcp` | Library | MCP server bridging vault-core to Claude Code and other MCP clients via stdio transport | `VaultMcpServer`, `VaultState`, `SharedState`, tool param structs (`VaultGetParams`, `VaultSetParams`, etc.) |
| `vault-web` | Library | Localhost web dashboard with REST API, password + TOTP authentication, session management | `AppState`, `AuthState`, `WebConfig`, `build_router()`, `start()` |
| `vault-cli` | Binary | Command-line interface with 40+ subcommands, daemon management, MCP bridge launcher | `Cli` (clap derive), command modules: `credentials`, `guides`, `daemon`, `sync`, `conflicts`, `encrypt`, `auth`, `config`, `monitoring`, `export_import`, `advanced` |
| `tests` | Integration | End-to-end workspace tests | N/A |

### Dependency Graph

```
vault-cli -----> vault-core
      |--------> vault-sync
      |--------> vault-mcp
      |--------> vault-web

vault-mcp -----> vault-core

vault-web -----> vault-core

vault-sync ----> vault-core
```

All four interface crates depend on `vault-core`. No circular dependencies exist. The `vault-cli` binary is the only crate that links all others, serving as the single entry point for both interactive CLI use and daemon/server modes.

---

## Storage Layer

### SQLCipher Database

The primary data store is a SQLCipher-encrypted SQLite database at `~/.memxp/vault.db`. SQLCipher provides AES-256-CBC full-database encryption -- every page (including metadata, indexes, and WAL) is encrypted with a key derived from the vault passphrase.

**Database open sequence:**

```
1. Connection::open(path)
2. PRAGMA key = '<passphrase>'      -- SQLCipher sets encryption key
3. PRAGMA cipher_version             -- Verify SQLCipher is active
4. Load cr-sqlite extension          -- Enable CRDT replication (if available)
5. init_schema()                     -- Create tables, enable CRR, run migrations
6. PRAGMA journal_mode=WAL           -- Write-Ahead Logging for concurrency
```

### Schema Overview

**Replicated tables** (synced via cr-sqlite CRDTs):

| Table | Primary Key | Purpose |
|-------|-------------|---------|
| `vault_entries` | `path TEXT` | Credentials (path, value, category, service, tags, storage_mode, expiry, rotation) |
| `read_instructionss` | `name TEXT` | Operational guides (content, category, tags, version, status, verification) |
| `vault_meta` | `key TEXT` | Key-value metadata (schema_version, migration flags) |
| `file_transfers` | `id TEXT` | File transfer headers (filename, size, checksum, chunk_count) |
| `file_chunks` | `id TEXT` | File transfer data chunks (base64 data, per-chunk checksum) |
| `sync_conflicts` | `id TEXT` | Conflict queue entries (local/remote values, resolution, audit context) |
| `conflict_settings` | `path TEXT` | Per-path conflict mode settings (auto, review, reject) |

**Local-only tables** (NOT replicated):

| Table | Purpose |
|-------|---------|
| `sync_audit` | Sync operation log (peer, direction, change count, duration, result) |
| `sync_peers` | Peer version tracking (last_seen_version, last_known_addr) |
| `sync_backlog` | Changes that could not be sent to a peer (table not supported) |
| `agent_tasks_archive` | Archived legacy agent tasks (only exists on DBs upgraded from pre-0.2.0; not created on fresh installs) |

### cr-sqlite CRDT Integration

When the cr-sqlite extension is loaded, tables are registered as **Conflict-Free Replicated Relations (CRR)** via `SELECT crsql_as_crr('<table>')`. This adds hidden CRDT metadata columns to each table, enabling:

- **Per-column Last-Write-Wins (LWW):** Each cell has an independent logical clock. When two peers modify the same row but different columns, both changes are preserved. When they modify the same cell, the one with the higher causal version wins.

- **Site identity:** Each database has a unique `crsql_site_id()` (random bytes). Changes carry their originating site ID, preventing echo loops.

- **Incremental delta sync:** `crsql_changes` virtual table exposes only the changes since a given `db_version`, enabling efficient incremental synchronization without full-table scans.

- **Tombstone-based deletes:** Deleted rows are represented as CRDT tombstones that replicate to all peers.

### OS Keychain Integration

The `credential_store` module wraps `CrSqliteDatabase` with keychain awareness via the `keyring` crate and enforces value stripping on bulk reads. All credential access from MCP, CLI, and Web goes through `CredentialStore`. Three storage modes are supported:

| Mode | DB stores | Keychain stores | Sync behavior |
|------|-----------|-----------------|---------------|
| `vault` (default) | Actual value | Nothing | Value replicates to all peers |
| `keychain` | Empty placeholder (`""`) | Actual value | Only metadata replicates; value is machine-local |
| `both` | Actual value | Actual value (preferred on read) | Value replicates; local keychain is authoritative |

The `keychain` mode is useful for credentials that should not leave the machine (e.g., local SSH keys). The `both` mode provides redundancy -- keychain is preferred on read, DB is the sync fallback.

---

## Sync Protocol

### Overview

The sync daemon (`vault-sync`) implements a binary framed protocol over TLS, using HMAC-SHA256 for per-frame authentication. Synchronization is bidirectional and incremental, exchanging only the cr-sqlite delta changesets since the last known peer version.

### Wire Frame Format (v3)

```
+----------+----------+----------+----------+----------+----------+
| MAGIC    | VERSION  | LENGTH   | TYPE     | PAYLOAD  | HMAC     |
| 9 bytes  | 1 byte   | 4 bytes  | 16 bytes | variable | 32 bytes |
| "VAULT_  | 0x03     | BE u32   | null-    | JSON or  | SHA-256  |
|  P2P"    |          |          | padded   | msgpack  |          |
+----------+----------+----------+----------+----------+----------+
         |<---------- HMAC covers this region --------->|
```

- **MAGIC:** `VAULT_P2P` (9 ASCII bytes) -- identifies the protocol
- **VERSION:** `0x03` -- current protocol version (v1 and v2 are rejected)
- **LENGTH:** Big-endian u32 -- payload size in bytes (max 10 MB)
- **TYPE:** 16-byte null-padded ASCII string -- message type identifier
- **PAYLOAD:** JSON-encoded message body
- **HMAC:** HMAC-SHA256 tag computed over everything before it (MAGIC through PAYLOAD)

### Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `HELLO` | Client -> Server | Capability exchange (site_id, supported tables/features, schema version, 16-byte random nonce) |
| `HELLO_ACK` | Server -> Client | Echo nonce, send server capabilities and current db_version |
| `SYNC_REQUEST` | Client -> Server | Send local changes, request remote changes since `last_seen_version` |
| `SYNC_RESPONSE` | Server -> Client | Return remote changes, current db_version |
| `SYNC_TRIGGER` | Either | Request immediate sync (e.g., after a local write) |
| `TRIGGER_ACK` | Either | Acknowledge trigger |
| `ERROR` | Either | Error response with code and message |

### Sync Flow

```
  Client (Peer A)                           Server (Peer B)
       |                                         |
       |  1. TCP connect + TLS handshake          |
       |----------------------------------------->|
       |                                         |
       |  2. HELLO {site_id, nonce, caps}        |
       |----------------------------------------->|
       |                                         |  Store peer capabilities
       |  3. HELLO_ACK {site_id, peer_nonce,     |
       |               db_version, caps}          |
       |<-----------------------------------------|
       |  Verify nonce echo                       |
       |                                         |
       |  4. SYNC_REQUEST {                      |
       |       site_id,                          |
       |       db_version,                       |
       |       changes: [...local deltas...],    |
       |       last_seen_version                 |
       |     }                                   |
       |----------------------------------------->|
       |                                         |  Apply incoming changes
       |                                         |  Get changes since
       |                                         |    last_seen_version
       |  5. SYNC_RESPONSE {                     |
       |       site_id,                          |
       |       db_version,                       |
       |       changes: [...remote deltas...],   |
       |       current_version                   |
       |     }                                   |
       |<-----------------------------------------|
       |  Apply incoming changes                  |
       |  Update peer version tracking            |
       |                                         |
```

### Peer Discovery and Authentication

1. **Discovery:** Peers are explicitly configured in `~/.memxp/config.yaml` or via CLI flags (`--peers 100.x.x.x`). There is no automatic peer discovery.

2. **IP Allowlist:** The daemon enforces a two-layer check:
   - Layer 1: Connection must originate from a Tailscale CGNAT IP (100.x.x.x) or localhost
   - Layer 2: The IP must be in the explicit allowlist, or (if no allowlist is configured) in the peers list
   - Empty allowlist + empty peers = reject all (fail-closed)

3. **HMAC Authentication:** Both peers derive the same HMAC key from the shared passphrase via `derive_sync_hmac_key()`. Every frame is HMAC-authenticated. A mismatched passphrase causes `HmacVerificationFailed` and connection termination.

4. **Nonce Exchange:** The HELLO message includes a random 16-byte nonce. The HELLO_ACK must echo it back, preventing replay attacks where a recorded HELLO_ACK is replayed to a different client.

5. **TLS:** Self-signed certificates are generated at daemon startup. Two verification modes:
   - `--peer-cert-fingerprint <sha256-hex>`: Pin to a specific certificate fingerprint
   - `--insecure-skip-tls-verify`: Accept any certificate (development only)

### Deadlock Prevention

The sync daemon holds the database mutex (`tokio::sync::Mutex`) only for brief operations:
- **Lock:** Read site_id, prepare changes, apply received changes
- **Unlock:** All network I/O (TLS handshake, frame read/write)

This prevents the classic deadlock scenario where Peer A holds its DB lock while waiting for Peer B's response, while Peer B is simultaneously trying to sync with Peer A.

---

## MCP Server

### Architecture

The `vault-mcp` crate implements an MCP (Model Context Protocol) server using the `rmcp` framework over stdio transport. It bridges `vault-core` operations to AI agents (Claude Code, etc.) as callable tools.

```
  Claude Code / MCP Client
         |
         | stdio (JSON-RPC)
         v
  +-------------------+
  | VaultMcpServer    |
  |                   |
  | tool_router       |----> 37+ tool methods
  | state: SharedState|       (recall, remember,
  |   (Arc<Mutex<     |        find, read_instructions,
  |    VaultState>>)  |        vault_conflicts, etc.)
  +-------------------+
         |
         v
  +-------------------+
  | VaultState        |
  |  .db              |----> CrSqliteDatabase
  |  .audit           |----> AuditLogger
  |  .locked          |----> AtomicBool
  |  .operator_until  |----> AtomicI64
  |  .session_*       |----> Session auth state
  +-------------------+
```

### Tool Categories

| Category | Count | Examples |
|----------|-------|---------|
| Credentials | 12 | `recall`, `remember`, `forget`, `find`, `vault_list`, `whats_saved`, `recent`, `smart_recall`, `remember_batch`, `recall_bundle`, `vault_help`, `vault_session_start` |
| Security | 5 | `vault_inject`, `vault_show_gui`, `vault_audit`, `vault_use`, `vault_expand` |
| Monitoring | 4 | `vault_changes`, `vault_impact`, `vault_lint`, `vault_rotation_alerts` |
| Conflicts | 3 | `vault_conflicts`, `vault_resolve_conflict`, `vault_conflict_mode` |
| Guides | 8 | `save_instructions`, `read_instructions`, `list_instructions`, `find_instructions`, `forget_instructions`, `verify_instructions`, `deprecate_instructions`, `stale_instructions` |
| Auth | 5 | `vault_authenticate`, `vault_auth_status`, `vault_operator_mode`, `vault_lock`, `vault_unlock` |

### Security Boundaries

1. **Session authentication:** If `VAULT_MCP_SESSION_TOKEN` is set, all tools (except `vault_authenticate` and `vault_auth_status`) require a prior `vault_authenticate(token)` call.

2. **Vault lock:** When locked, only `vault_lock`, `vault_unlock`, and `vault_auth_status` are accessible.

3. **Operator mode:** Destructive operations (`forget`, `vault_use`, `vault_expand`) require active operator mode (passphrase-gated, time-limited).

4. **Value masking:** `vault_list` and `find` never return actual values. `recall` returns values only when `include_value=true` is explicitly set. The `redact=true` flag copies to clipboard without exposing the value in the response.

5. **Reserved paths:** Paths starting with `_agents/` are blocked from modification via generic credential tools.

---

## Web Interface

### Architecture

The `vault-web` crate provides a localhost-only web dashboard built with Axum, serving embedded HTML/CSS/JS (compiled into the binary) or optional disk-based static files.

```
  Browser (localhost:8777)
         |
         | HTTP (127.0.0.1 only)
         v
  +----------------------------+
  | Axum Router                |
  |                            |
  | /api/auth/*    (no session)|----> AuthState (in-memory)
  | /api/credentials/* (auth)  |      - Argon2id password hash
  | /api/guides/*      (auth)  |      - TOTP secret
  | /api/challenges/*  (auth)  |      - Session map (UUID -> Session)
  | /api/clipboard/*   (auth)  |      - Rate limit counter
  | /api/events/poll   (auth)  |
  | /api/sync/status   (auth)  |
  | /api/audit         (auth)  |
  +----------------------------+
         |
         v
  +----------------------------+
  | AppState                   |
  |  .db: Mutex<CrSqliteDb>   |
  |  .audit: Mutex<AuditLogger>|
  |  .auth: AuthState          |
  +----------------------------+
```

### Authentication Flow

1. **Initial state:** No auth configured. All protected endpoints return `403 Forbidden` with a message to register first.

2. **Registration:** `POST /api/auth/register` with `{"password": "..."}`. The password is hashed with Argon2id and stored in memory. A session is created immediately.

3. **Login:** `POST /api/auth/login` with `{"password": "..."}`. Verified against the stored Argon2id hash. Rate-limited to 10 attempts per 5-minute window.

4. **TOTP (optional):** `POST /api/auth/totp/setup` generates a TOTP secret and otpauth URI. `POST /api/auth/totp/verify` validates a 6-digit code and creates a session.

5. **Session management:**
   - Session ID delivered exclusively via `Set-Cookie: vault_session=<uuid>; HttpOnly; SameSite=Strict; Path=/api; Max-Age=86400`
   - No query-parameter fallback — cookie-only to prevent token leakage in URLs, Referer headers, and server logs
   - Idle timeout: 30 minutes
   - Max lifetime: 24 hours
   - `POST /api/auth/lock` invalidates all sessions

6. **Credential masking:** The web API returns masked values (`sk-a****z789`) via the `mask_value()` function. Actual values are never sent over HTTP -- the clipboard copy endpoint (`POST /api/clipboard/{path}`) copies directly to the OS clipboard without returning the value in the response.

**Important:** Auth state is entirely in-memory. Restarting the web server clears all passwords, TOTP secrets, and sessions. Users must re-register after restart.

---

## CLI

### Command Structure

The CLI is built with `clap` (derive mode) and organized into subcommand modules:

```
memxp
  |-- init                      # Initialize vault directory and database
  |-- get <path>                # Get credential value
  |-- set <path> <value>        # Set credential
  |-- delete <path>             # Delete credential
  |-- list [--service] [--prefix]  # List credentials (masked values)
  |-- search <query>            # Search by keyword
  |-- discover                  # Overview of vault contents
  |-- recent                    # Recently added entries
  |-- guide <name>              # Get guide content
  |-- add-guide <name>          # Add/update guide
  |-- list-guides               # List all guides
  |-- search-guides <query>     # Search guides
  |-- delete-guide <name>       # Delete guide
  |-- encrypt                   # Set up database encryption
  |-- daemon start              # Start sync daemon
  |-- daemon stop               # Stop sync daemon
  |-- daemon status             # Check daemon status
  |-- sync trigger              # Trigger immediate sync
  |-- conflicts list            # List sync conflicts
  |-- conflicts resolve <id>    # Resolve a conflict
  |-- config show               # Show current config
  |-- config set <key> <value>  # Update config
  |-- audit [--path] [--action] # View audit log
  |-- export                    # Export vault (plaintext JSON — encrypt externally)
  |-- import                    # Import from export
  |-- lock                      # Lock the vault
  |-- unlock                    # Unlock with passphrase
  |-- confirm <challenge_id>    # Confirm operator challenge
  |-- mcp-bridge                # Launch MCP server (stdio)
  |-- web                       # Start web GUI
  |-- self-update               # Check for updates
  |-- status                    # Vault health check
  |-- lint                      # Analyze path naming
  |-- changes                   # View credential change history
  |-- impact <app>              # Assess credential impact
  |-- rotation-alerts           # Check rotation/expiry
  |-- operator-mode             # Enable/disable operator mode
  `-- ... (40+ commands total)
```

### How CLI Calls vault-core

Each CLI command follows a consistent pattern:

```rust
// 1. Resolve passphrase (keychain-first or env-first)
let passphrase = vault_core::auth::configured_passphrase()?;

// 2. Open encrypted database
let db = CrSqliteDatabase::open(&db_path, &passphrase, extension_path.as_deref())?;

// 3. Perform operation via CredentialStore (handles keychain routing + value policy)
let store = CredentialStore::new(&db);
let entry = store.recall("api/openai/key")?;

// 4. (Optional) Log audit event
let audit = AuditLogger::open_default()?;
audit.log("get", Some("api/openai/key"), ...)?;
```

The `mcp-bridge` command is special -- it creates a `VaultMcpServer` and runs it with `rmcp::ServiceExt::serve` over stdio, bridging all tool calls to `vault-core` operations.

---

## Conflict Resolution

### Default: Last-Write-Wins (LWW)

By default, cr-sqlite handles conflicts automatically using per-column LWW semantics. When two peers modify the same cell concurrently:

1. Each peer assigns a causal version (monotonically increasing per-site)
2. During sync, the cell with the higher `(col_version, site_id)` tuple wins
3. The losing value is silently overwritten
4. Both peers converge to the same state after sync

This is the `auto` conflict mode and requires no manual intervention.

### Conflict Queue (Review Mode)

For sensitive paths, operators can enable `review` mode:

```
vault_conflict_mode(path="production/*", mode="review")
```

When a conflict is detected on a `review`-mode path:

1. A `SyncConflict` record is created in the `sync_conflicts` table with `resolution=pending`
2. The conflict includes both local and remote values, timestamps, and site IDs
3. The cr-sqlite LWW still applies (the DB converges), but the conflict record flags it for review
4. An agent or operator reviews via `vault_conflicts()` and resolves with:
   - `keep_local` -- revert to the local value
   - `keep_remote` -- accept the remote value (no-op if LWW already chose it)
   - `merge` -- provide a manually merged value
5. `apply_resolution()` writes the resolved value back to `vault_entries`

### Reject Mode

The `reject` mode automatically resolves all conflicts to `keep_local`, preventing any remote changes from overwriting the local value on that path:

```
vault_conflict_mode(path="machine-specific/*", mode="reject")
```

### Conflict Mode Resolution Order

1. **Exact match:** `conflict_settings` WHERE `path = '<exact path>'`
2. **Wildcard match:** Patterns like `api/*` or `production/*`, ordered by longest prefix
3. **Default:** `auto` (LWW)

---

## Guide System

Guides are markdown documents stored in the `read_instructionss` table and replicated across all peers via cr-sqlite.

### Storage

Each guide has:

| Field | Type | Description |
|-------|------|-------------|
| `name` | TEXT (PK) | Unique identifier (e.g., `vps-deploy`, `caddy-config`) |
| `content` | TEXT | Full markdown content |
| `category` | TEXT | `procedure`, `troubleshooting`, `runbook`, `setup` |
| `tags` | TEXT (JSON) | Searchable tags (e.g., `["deploy", "docker"]`) |
| `version` | INTEGER | Monotonically increasing version number |
| `status` | TEXT | `active`, `deprecated` |
| `verified_at` | TEXT | RFC3339 timestamp of last verification |
| `related_paths` | TEXT (JSON) | Credential paths referenced by this guide |
| `created_at` | TEXT | RFC3339 creation timestamp |
| `updated_at` | TEXT | RFC3339 last-update timestamp |

### Versioning

The `version` field increments on each update. This is tracked locally -- cr-sqlite does not enforce version ordering across peers. The `updated_at` timestamp provides a wall-clock ordering for human review.

### Search

Guide search is implemented as SQLite `LIKE` queries across `name`, `content`, and `tags` fields:

```sql
SELECT * FROM read_instructionss
WHERE name LIKE '%query%'
   OR content LIKE '%query%'
   OR tags LIKE '%query%'
ORDER BY updated_at DESC
```

There is no full-text index (e.g., Tantivy). For the current scale (hundreds of guides), `LIKE` queries with WAL mode are fast enough. A full-text search engine could be added as an optimization if the guide count grows significantly.

### Freshness Tracking

- `verify_instructions(name)` sets `verified_at` to now, confirming the guide's content is current
- `stale_instructions(threshold_days=90)` lists guides that haven't been verified within the threshold
- `deprecate_instructions(name)` sets `status=deprecated`, signaling the guide should not be used

### Sync Behavior

Guides are replicated to all peers via the same cr-sqlite CRR mechanism as credentials. LWW applies per-column -- if two peers edit the same guide's content simultaneously, the later writer wins. Guide metadata (tags, status, verified_at) can be updated independently without conflicting with content changes.

### Guide Organization at Scale

As guide count grows beyond ~50, flat keyword search (`find_instructions`) becomes insufficient for agents. Agents waste tokens guessing search terms and following dead ends. memxp's guide system supports a **convention-based routing layer** to address this:

#### Cross-reference headers

Guides should begin with a blockquote header linking to related guides and the domain hub:

```markdown
> **Part of:** VPS Infrastructure · Hub: `vps-operations`
> **Related:** `vps-deploy`, `vps-firewall` · **People:** `staff-directory`
```

These headers cost ~30 tokens but give agents immediate navigation context. When an agent reads any guide, it can follow the header links to discover related information without additional search calls.

#### Hub guides

Hub guides serve as domain-level routing tables. They list child guides by category, enabling top-down navigation:

- `vps-operations` — VPS infrastructure (~22 child guides)
- `data-pipeline-reference` — data lakehouse (~25 child guides)
- `unifi-protect-api-reference` — camera/network (~10 child guides)

Agents start with `read_instructions("hub-name")` and drill into specific children -- typically 2 tool calls vs 5+ keyword searches.

#### Inline routing hints

When a guide references data stored in credential entries, it should include the exact vault query to retrieve that data:

```markdown
Individual staff records: `vault_list(prefix="company/staff/")` — JSON with phone, email, title
```

This prevents agents from guessing keywords like "phone", "mobile", "cell" -- they call `vault_list` with the correct prefix directly.

#### Design rationale

This routing system is a convention layer, not enforced by code. The `related_paths` field on `VaultGuide` links guides to credential paths, but guide-to-guide relationships are expressed in markdown content. This keeps the data model simple while providing rich navigability for agents that read guide content.

See `docs/examples.md` Section 1.7 for practical examples of the header convention, hub guides, and inline routing hints.
