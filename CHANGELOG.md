# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-18

Security hardening release. All defaults flipped to secure-by-default.
No breaking API changes; behavioral changes require explicit opt-in via
environment variables or flags.

### Changed

#### Security: Secure-by-Default
- **Installer no longer pre-approves MCP tools.** Claude will prompt before each memxp tool call. Pass `--auto-approve` to opt in to the previous behavior. The old `--no-auto-approve` flag has been removed.
- **Operator auto-promotion disabled by default.** `vault_operator_mode` now requires an explicit password unless `VAULT_OPERATOR_AUTO_PROMOTE=1` is set in the environment. Previously, operator mode silently auto-promoted when the passphrase was available at startup.
- **Daemon-guard TLS default flipped to secure.** Guard scripts now default to TLS verification enabled (`INSECURE_TLS="false"`). Existing deployments with `insecure_skip_tls_verify: true` in config.yaml are unaffected — the guard reads the config.

#### Web Dashboard: Cookie-Only Auth
- Removed `session_id` from all JSON response bodies (register, login, TOTP verify)
- Removed `AuthQuery` struct and query-parameter session fallback from all 14 protected endpoints
- Frontend (`app.js`) switched to `credentials: 'same-origin'` with status-based auth checks
- Session delivery is now exclusively via `Set-Cookie: vault_session=...; HttpOnly; SameSite=Strict`

#### CLI
- `memxp set` now accepts `-` as value to read from stdin, avoiding shell history exposure. Example: `echo "secret" | memxp set path/to/key -`

#### Installer
- Removed plaintext passphrase backup file from `~/Desktop/memxp-passphrase.txt`. Passphrase is now shown in terminal only during install, with guidance to save it in a password manager.
- Added trust model documentation in installer header comments

#### MCP Server
- Operator mode audit log now tracks promotion method (`password` vs `startup_passphrase_auto`)
- Added trust model documentation in `server.rs`

### Fixed

#### Documentation Accuracy
- Fixed "mutual TLS" claim in README — now accurately says "TLS" with note about no client certificate authentication
- Fixed "zero plaintext" claim in README — removed overstated guarantee
- Fixed "encrypted JSON" export description in architecture docs — now says "plaintext JSON — encrypt externally"
- Added security note in examples docs recommending `gpg` encryption for vault exports
- Added Tailscale as primary transport security layer in README security section
- Fixed stale query-param session fallback documentation in architecture.md
- Fixed stale comment in `server.rs` route registration

#### Credential Store
- `CredentialStore` now surfaces keychain resolution warnings in bulk paths
- Restricted raw DB access to prevent bypassing keychain safety checks

### Security

- Web auth tokens no longer leak via URL query parameters, Referer headers, browser history, or server access logs
- Operator mode promotion method is now auditable (password vs auto-promote)
- CI workflow includes `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test` across macOS, Linux, and Windows
- Added `cargo audit` to dependency checking workflow

## [0.1.0] - 2026-03-03

Initial public release of memxp, a local-first encrypted knowledge base and
credential store for AI coding agents.

### Added

#### Core (`vault-core`)
- SQLite-backed encrypted credential store using SQLCipher (AES-256-CBC, PBKDF2-HMAC-SHA512 256K iterations)
- Credential CRUD with rich metadata: path, service, category, tags, environment, notes, rotation interval
- Guide/knowledge-base system with category, tags, freshness tracking, verification, and deprecation
- Query engine with keyword search, prefix filtering, service/category facets, and fuzzy smart-get
- Credential linting: detects duplicate paths, naming inconsistencies, and similar-path collisions
- Rotation alerting: identifies overdue and upcoming credential expirations
- Change history and audit logging for all vault operations
- Impact analysis: maps which credentials an application depends on
- Conflict detection and resolution (keep-local, keep-remote, merge) for P2P sync
- Operator session model with TTL-based elevation for high-risk mutations
- Out-of-band challenge/response authentication (eliminates passphrase-in-chat exposure)
- Platform keyring integration (macOS Keychain native backend via `keyring` crate)
- cr-sqlite CRDT extension support for conflict-free replication

#### Sync (`vault-sync`)
- Peer-to-peer sync daemon over TLS (rustls with self-signed or CA certificates)
- HMAC-authenticated wire protocol using MessagePack serialization
- Automatic peer discovery and version tracking
- Configurable sync intervals and peer lists
- Daemon management: start, stop, status with PID file tracking
- `--insecure-skip-tls-verify` flag for Tailscale-encrypted development environments
- Optional peer certificate fingerprint pinning for explicit trust

#### CLI (`vault-cli`)
- 40+ commands with full CLI-MCP parity
- Credential commands: `get`, `set`, `delete`, `list`, `search`, `has`, `discover`, `recent`, `smart-get`, `bundle`, `set-batch`, `inject`, `use`, `expand`
- Guide commands: `guide add`, `guide list`, `guide search`, `guide delete`, `guide verify`, `guide deprecate`, `guide stale`
- Monitoring commands: `audit`, `changes`, `impact`, `lint`, `rotation-alerts`, `session-start`
- Conflict commands: `conflicts`, `resolve`, `conflict-mode`
- Auth commands: `operator enable/disable`, `confirm-operator`, `auth-status`, `lock`, `unlock`
- Sync commands: `sync` (one-shot), `daemon start/stop/status`
- Admin commands: `init`, `status`, `config show/edit`, `export`, `import`, `migrate`, `encrypt`, `self-update`, `mcp`, `web`
- `--json` output on all data commands for agent/script consumption
- `--clipboard` and `--redact` flags for zero-plaintext secret retrieval
- `--value-only` for piping raw values to other tools
- `--quiet` and `--no-color` global flags
- `<vault:path>` placeholder expansion from files or stdin (`expand` command)
- `vault_use`: run a subprocess with a secret injected as an environment variable (experimental)
- Self-update with GitHub Release integration, checksum verification, and `--check` mode

#### MCP Server (`vault-mcp`)
- 37 MCP tools exposed via stdio transport (rmcp framework)
- Full credential lifecycle: `vault_get`, `vault_set`, `vault_delete`, `vault_list`, `vault_search`, `vault_discover`, `vault_recent`, `vault_smart_get`, `vault_get_bundle`, `vault_set_batch`, `vault_inject`, `vault_use`, `vault_expand`
- Guide tools: `vault_add_guide`, `vault_guide`, `vault_list_guides`, `vault_search_guides`, `vault_delete_guide`, `vault_verify_guide`, `vault_deprecate_guide`, `vault_stale_guides`
- Security tools: `vault_auth_status`, `vault_authenticate`, `vault_operator_mode`, `vault_session_start`, `vault_lock`, `vault_unlock`, `vault_changes`, `vault_audit`, `vault_impact`, `vault_lint`, `vault_rotation_alerts`
- Conflict tools: `vault_conflicts`, `vault_resolve_conflict`, `vault_conflict_mode`
- Contextual help system (`vault_help`) with topic-based assistance
- Clipboard integration with configurable auto-clear

#### Web GUI (`vault-web`)
- Axum-based web dashboard on port 8777
- Password + optional TOTP two-factor authentication (in-memory session)
- REST API for credentials, guides, and vault metadata
- Dashboard with credential browsing, search, and guide management
- Delete endpoints for credentials and guides
- CORS support for local development
- Static asset serving (HTML/CSS/JS SPA)

#### Distribution & CI
- GitHub Actions CI: build and test on macOS (arm64 cross-compiled), Ubuntu, and Windows
- GitHub Actions release workflow: builds 4-platform archives (macOS arm64, macOS x86_64, Linux x86_64, Windows x86_64) with SHA-256 checksums
- Install scripts: `install.sh` (Linux/macOS) and `install.ps1` (Windows/PowerShell)
- Fleet update script: `update-fleet.sh` with inventory-based rolling deployment
- Self-update mechanism built into the CLI binary

#### Project Governance
- MIT license
- Security policy with private disclosure process
- Contributing guidelines and PR template
- Code of Conduct
- Issue templates for bug reports and feature requests
- Public roadmap (`ROADMAP.md`)
- Release checklist (`RELEASE_CHECKLIST.md`)

### Removed

- MCP messaging and task tools (`local_agent.rs`, `p2p.rs`) removed from public API surface
- Legacy `agent_tasks` table migrated to `agent_tasks_archive` on schema upgrade; no longer used at runtime

### Security

- All vault data encrypted at rest via SQLCipher (AES-256-CBC with HMAC-SHA1 page authentication)
- PBKDF2-HMAC-SHA512 key derivation from user passphrase (256K iterations, SQLCipher internal)
- HMAC-SHA256 authentication on sync wire protocol
- TLS transport for peer-to-peer sync (rustls)
- Out-of-band challenge/response for operator elevation (no passphrase in chat/LLM context)
- Constant-time session token comparison
- Secrets redacted by default in list/search operations (opt-in plaintext via `include_value` or `--value-only`)
- Clipboard auto-clear after configurable timeout
- Audit logging of all credential access
- Operator mode with TTL-based session expiry for destructive operations
- Platform keyring storage option (macOS Keychain)
- Generated passphrases only shown with explicit `--print-passphrase` flag

[0.2.0]: https://github.com/pwchiefy/memxp/releases/tag/v0.2.0
[0.1.0]: https://github.com/pwchiefy/memxp/releases/tag/v0.1.0
