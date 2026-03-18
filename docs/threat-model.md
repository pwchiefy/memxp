# memxp Threat Model

**Version:** 0.2.0
**Last updated:** 2026-03-17
**Scope:** memxp Rust workspace (`memxp`), covering credential storage, P2P sync, web dashboard, and MCP server interfaces.

---

## What memxp Protects

memxp is a distributed credential and knowledge management system designed to protect:

1. **Credentials at rest** -- All credential data is stored in a SQLCipher-encrypted database (AES-256-CBC, page-level encryption). The codebase includes XChaCha20-Poly1305 primitives for future per-value encryption, but the current storage path relies on SQLCipher as the single encryption layer.

2. **Credentials in transit** -- All P2P sync traffic is wrapped in TLS 1.3 (via `rustls`) and every frame is authenticated with HMAC-SHA256 derived from the shared vault passphrase. Peers must be in the Tailscale CGNAT range (100.x.x.x) and on the configured allowlist.

3. **Operator-mode mutations** -- Destructive operations (credential deletion, `vault_use`, `vault_expand`) require elevated "operator mode," which demands the vault passphrase and is time-limited (default 15 minutes, max 4 hours).

4. **Knowledge integrity** -- Guides (operational procedures, runbooks) are stored in the same encrypted database and replicated via cr-sqlite CRDTs, ensuring convergence across the fleet.

---

## Trust Boundaries

```
                          TRUST BOUNDARY 1: Local Machine
  +---------------------------------------------------------------------------+
  |                                                                           |
  |  User / Agent                                                             |
  |       |                                                                   |
  |       v                                                                   |
  |  +----------+     +----------+     +-------------------+                  |
  |  | CLI      | --> | vault-   | --> | CrSqliteDatabase  |                  |
  |  | (clap)   |     | core     |     | (SQLCipher AES-   |                  |
  |  +----------+     |          |     |  256-CBC + CRDTs) |                  |
  |                    |          |     +-------------------+                  |
  |  +----------+     |          |            |                               |
  |  | MCP      | --> | auth,    |     +------+------+                        |
  |  | (rmcp    |     | crypto,  |     | OS Keychain |                        |
  |  |  stdio)  |     | db,      |     | (optional)  |                        |
  |  +----------+     | security |     +-------------+                        |
  |                    +----------+                                           |
  |  +----------+                                                             |
  |  | Web GUI  |  (localhost:8777 only, password+TOTP auth)                  |
  |  | (axum)   |                                                             |
  |  +----------+                                                             |
  |                                                                           |
  +---------------------------------------------------------------------------+
         |                                            ^
         | TLS 1.3 + HMAC-SHA256 (port 5480)          | TLS 1.3 + HMAC-SHA256
         v                                            |
  +---------------------------------------------------------------------------+
  |                     TRUST BOUNDARY 2: Tailscale Network                   |
  |                                                                           |
  |  Peer A (100.x.x.x:5480) <------> Peer B (100.y.y.y:5480)               |
  |                                                                           |
  |  - IP allowlist enforcement (fail-closed)                                 |
  |  - Tailscale WireGuard encryption (outer layer)                           |
  |  - TLS + HMAC-SHA256 (inner layer)                                        |
  |  - cr-sqlite changeset exchange (delta sync)                              |
  |                                                                           |
  +---------------------------------------------------------------------------+
```

**Boundary 1 (Local Machine):** The passphrase is the root of trust. It is passed directly to SQLCipher via `PRAGMA key`, where SQLCipher's internal KDF (PBKDF2-HMAC-SHA512, 256K iterations) derives the database encryption key. The same passphrase is used to derive the HMAC sync key (via SHA-256) and to gate operator mode. The passphrase is sourced from the OS keychain or `VAULT_PASSPHRASE` environment variable. The codebase includes an Argon2id `derive_key` function (with `Zeroizing<[u8; 32]>` output) and XChaCha20-Poly1305 encrypt/decrypt primitives, but neither is currently wired into the storage path — they are available for future per-value encryption.

**Boundary 2 (Tailscale Network):** Peers authenticate via shared HMAC key (derived from the same passphrase). Tailscale provides WireGuard encryption at the network layer; memxp adds TLS + HMAC at the application layer for defense in depth.

---

## Threat Matrix

| # | Threat | Mitigation | Residual Risk |
|---|--------|-----------|---------------|
| T1 | **Stolen database file** | SQLCipher AES-256-CBC full-database encryption. Passphrase required to read any data. SQLCipher's internal KDF (PBKDF2-HMAC-SHA512, 256K iterations) makes brute force expensive. | If attacker also obtains the passphrase (keychain dump, env var leak), the database is fully readable. Offline brute force against weak passphrases is feasible over time. PBKDF2 is less memory-hard than Argon2id, so GPU-accelerated attacks are more practical against short passphrases. |
| T2 | **Man-in-the-middle on sync** | TLS 1.3 encryption (rustls). HMAC-SHA256 authentication on every frame -- shared secret derived from vault passphrase. Optional peer certificate fingerprint pinning. Nonce exchange in HELLO/HELLO_ACK prevents replay. | When using `--insecure-skip-tls-verify` (development mode), TLS certificate verification is disabled. HMAC still protects integrity, but a network-level attacker on the Tailscale overlay could observe traffic patterns if the WireGuard tunnel is somehow compromised. |
| T3 | **Compromised peer machine** | IP allowlist enforcement (fail-closed -- empty allowlist rejects all). Only Tailscale CGNAT IPs (100.x.x.x) or localhost accepted. Conflict modes (`review`, `reject`) let operators gate which paths accept remote changes. Audit logging of all sync operations. | A compromised peer with the correct passphrase can inject arbitrary credential values. cr-sqlite LWW (Last-Write-Wins) will propagate those values to all peers. No per-credential signing or peer-specific authorization exists. |
| T4 | **Passphrase brute force** | SQLCipher's PBKDF2-HMAC-SHA512 with 256K iterations and per-database random salt. Web UI rate-limits to 10 failed attempts per 5-minute window. | PBKDF2 is not memory-hard, so GPU/ASIC-accelerated offline brute force is more practical than with Argon2id. A dedicated attacker with the database file could attempt offline attacks. Passphrases shorter than 20 characters with low entropy are at elevated risk. |
| T5 | **MCP tool injection (malicious prompt)** | Vault is locked by default if `VAULT_MCP_SESSION_TOKEN` is set -- requires explicit authentication. Operator mode required for destructive operations (`vault_delete`, `vault_use`, `vault_expand`). Reserved path prefixes (`_agents/`) prevent metadata tampering. Values are masked in search/list responses. `recall` supports `redact=true` to keep secrets out of chat history. | An agent with an active MCP session can read any credential via `recall(path, include_value=true)`. A compromised or manipulated agent could exfiltrate all credentials within a session. The `redact` and `copy_to_clipboard` modes mitigate but do not eliminate this if the agent bypasses them. |
| T6 | **Web UI session hijack** | Bound to `127.0.0.1` only (never `0.0.0.0`). HttpOnly + SameSite=Strict cookies. Session IDs are UUIDv4 (128-bit random). Idle timeout: 30 minutes. Max session lifetime: 24 hours. Strict CORS origin matching to `localhost:port`. Rate limiting on auth endpoints. | No HTTPS on localhost (plaintext HTTP). A local attacker or malware with access to loopback traffic could intercept session cookies. In-memory auth state (password hash, TOTP secret, sessions) is lost on restart -- there is no persistent web credential store. |
| T7 | **Memory dump / core dump exposure** | File permissions set to 0o600/0o700 on Unix (challenge files, database, config). Audit log machine IDs are SHA-256 hashed by default to reduce correlation. The `zeroize` crate is available and used in the `derive_key` function, but this function is not called in the current storage path (SQLCipher handles key derivation internally). | The vault passphrase is held in process memory as a plain `String` during active use (passed to SQLCipher via `PRAGMA key`). Decrypted credential values also exist in memory. A memory dump (`/proc/pid/mem`, core file, swap) could expose them. No memory locking (`mlock`) is used. No active zeroization occurs on the passphrase or credential values in the current implementation. |
| T8 | **Supply chain attack (dependencies)** | Pinned dependency versions in `Cargo.lock`. Minimal dependency surface: `chacha20poly1305`, `argon2`, `sha2`, `hmac` from RustCrypto (widely audited). `rusqlite` with `bundled-sqlcipher-vendored-openssl` (statically linked, no system OpenSSL). `rustls` (no OpenSSL for TLS). | The `rmcp` MCP framework, `keyring`, `axum`, and `tower-http` crates are less audited than the core cryptographic dependencies. A compromised upstream crate update could introduce backdoors. No `cargo-audit` or `cargo-vet` is currently integrated into CI. |
| T9 | **Credential leakage via audit logs** | Audit log stores action, path, and timestamp -- never credential values. Machine IDs are SHA-256 hashed (`machine:hex`) unless `VAULT_AUDIT_LOG_RAW_MACHINE_ID=1` is set. Value changes are tracked via truncated SHA-256 hash (first 4 bytes) rather than the actual value. | Audit database (`audit.db`) is not encrypted with SQLCipher. An attacker with filesystem access can read the audit log to discover which credentials exist and when they were accessed, even without the vault passphrase. |
| T10 | **Challenge/confirmation bypass** | Challenge files use `O_CREAT | O_EXCL` (atomic create). File ownership verified via UID. Permissions enforced at 0o600. Challenges expire after 60 seconds. Single-use consumption with rename-to-consumed pattern. Session nonce binding prevents cross-session replay. | On Windows, ACL enforcement via `icacls` is best-effort. A local attacker running as the same user can create confirmation files to approve their own challenges. |

---

## What memxp Does NOT Protect Against

The following threats are **out of scope** by design:

- **Compromised local machine with active session** -- If an attacker has shell access while the vault is unlocked, they can read all credentials via the CLI or MCP tools. memxp assumes the local operating environment is trusted during active use.

- **Keylogger / screen capture capturing the passphrase** -- The passphrase is the root of all security. If it is captured at input time, all protections collapse.

- **Nation-state adversaries with physical access** -- Cold boot attacks, hardware implants, or firmware-level compromise are beyond the threat model.

- **Quantum computing** -- The symmetric primitives (AES-256, ChaCha20, SHA-256, HMAC-SHA256) are considered quantum-resistant to Grover's algorithm (effective 128-bit security). However, memxp does not use post-quantum key exchange for TLS.

- **Insider threat with passphrase knowledge** -- All machines sharing the same passphrase have full read/write access. There is no per-user or per-machine authorization model. A rogue machine with the passphrase can read, modify, or delete any credential.

- **Denial-of-service on the sync daemon** -- The TLS listener accepts connections from allowlisted IPs, but does not implement connection rate limiting or resource quotas beyond the 10 MB max payload size.

- **Unencrypted audit database** -- The `audit.db` file reveals access patterns (paths, timestamps, actions) to anyone with filesystem read access, without requiring the vault passphrase.

---

## Cryptographic Primitives

| Primitive | Algorithm | Key Size | Purpose | Implementation |
|-----------|-----------|----------|---------|----------------|
| Database encryption | AES-256-CBC (SQLCipher) | 256-bit | Full-database encryption at rest | `rusqlite` with `bundled-sqlcipher-vendored-openssl` feature |
| Value-level encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce | Per-value AEAD encryption (available in `crypto.rs`, not yet wired into default storage path) | `chacha20poly1305` crate (RustCrypto) |
| Key derivation (DB) | PBKDF2-HMAC-SHA512 (SQLCipher internal) | 256-bit output | Passphrase to DB encryption key (256K iterations, per-DB salt) | Built into SQLCipher (`bundled-sqlcipher-vendored-openssl`) |
| Key derivation (future) | Argon2id v0x13 | 256-bit output | Available for per-value encryption (64 MiB memory, 3 iterations, 1 lane). Not currently used in storage path. | `argon2` crate (RustCrypto) |
| Key derivation (sync) | SHA-256 with domain separator | 256-bit output | Passphrase to HMAC key (`vaultp2p-sync-hmac-v1:` prefix) | `sha2` crate (RustCrypto) |
| Frame authentication | HMAC-SHA256 | 256-bit key | Per-frame integrity and authentication on sync protocol | `hmac` + `sha2` crates (RustCrypto) |
| TLS transport | TLS 1.3 (rustls) | Varies (ECDHE + AES-256-GCM or ChaCha20-Poly1305) | Sync daemon encryption and server authentication | `rustls` + `tokio-rustls` |
| Certificate generation | Self-signed X.509 (rcgen) | Ed25519 or ECDSA P-256 | TLS server identity for sync daemon | `rcgen` crate |
| Web password hashing | Argon2id (PHC string format) | Default params | Web UI password authentication | `argon2` crate (password-hash feature) |
| TOTP | HMAC-SHA1 (RFC 6238) | 160-bit shared secret | Web UI two-factor authentication | `totp-rs` crate |
| Value hashing | SHA-256 (truncated to 4 bytes) | N/A | Conflict detection without exposing values | `sha2` crate |
| Nonce generation | OS CSPRNG | 128-bit (16 bytes) | HELLO handshake replay prevention | `rand::OsRng` |
| Session IDs | UUIDv4 | 128-bit | Web UI session tokens and challenge IDs | `uuid` crate |
| Key zeroization | Zeroize on drop | N/A | Available in `derive_key` output (`Zeroizing<[u8; 32]>`), but not active in current storage path — SQLCipher manages its own key lifecycle. Passphrase and credential values are not zeroized. | `zeroize` crate |

---

## Key Derivation Flow

### Passphrase to Database Encryption Key

```
                    passphrase (user input)
                           |
                           v
                  PRAGMA key = passphrase
                           |
                           v
              +----------------------------+
              |  SQLCipher internal KDF    |
              |  PBKDF2-HMAC-SHA512       |
              |  256,000 iterations       |
              |  per-database salt        |
              +----------------------------+
                           |
                           v
                  256-bit AES-CBC key
                  (page-level encryption)
```

The raw passphrase is passed directly to SQLCipher via `PRAGMA key`. SQLCipher applies its own internal KDF (PBKDF2-HMAC-SHA512 with 256K iterations and a per-database random salt) to derive the AES-256-CBC page encryption key. memxp does **not** run Argon2id in the database encryption path.

The `crypto.rs` module contains an Argon2id `derive_key` function and XChaCha20-Poly1305 `encrypt_value`/`decrypt_value` primitives. These are tested and available for future per-value encryption but are not currently called in the storage path — SQLCipher page-level encryption is the single encryption layer for data at rest.

### Passphrase to HMAC Sync Key

```
                    passphrase (same as above)
                           |
                           v
              +----------------------------+
              |         SHA-256            |
              |  input: "vaultp2p-sync-    |
              |          hmac-v1:" +       |
              |          passphrase        |
              +----------------------------+
                           |
                           v
                  256-bit HMAC key
                  ([u8; 32])
                           |
                           v
              +----------------------------+
              |       HMAC-SHA256          |
              |  Signs every wire frame:   |
              |  MAGIC | VERSION | LENGTH  |
              |  | TYPE | PAYLOAD          |
              +----------------------------+
                           |
                           v
                  32-byte tag appended
                  to each frame
```

The `derive_sync_hmac_key` function derives a separate SHA-256-based key for P2P sync frame authentication. This key is distinct from the Argon2id-derived SQLCipher key and serves only to authenticate wire-protocol frames.

This derivation is intentionally fast (SHA-256, not Argon2) because:
1. It runs on every sync frame (latency-sensitive)
2. The passphrase has already been validated by Argon2 during database open
3. The domain separator (`vaultp2p-sync-hmac-v1:`) prevents the sync key from being used as a database key

**Critical coupling:** All peers MUST share the same passphrase. The `derive_sync_hmac_key()` function produces the same key for the same passphrase on every platform. A passphrase mismatch causes HMAC verification failure and sync rejection.

---

## Recommendations

### For Operators

1. **Use a strong passphrase** -- Minimum 20 characters, high entropy. The passphrase is the single root of trust for both encryption and sync authentication. Consider using a passphrase generator.

2. **Enable Tailscale ACLs** -- Restrict which machines can reach port 5480 at the Tailscale layer, in addition to memxp's own IP allowlist. This provides network-level defense-in-depth.

3. **Rotate credentials regularly** -- Use `vault_rotation_alerts` to monitor upcoming rotations. Set `rotation_interval_days` on sensitive credentials to receive proactive warnings.

4. **Use operator mode for mutations** -- Enable operator mode only when performing destructive operations. The default 15-minute TTL limits the blast radius of a compromised session.

5. **Avoid `--insecure-skip-tls-verify` in production** -- Use `--peer-cert-fingerprint` for TLS certificate pinning between peers. Self-signed certificates are acceptable when pinned by SHA-256 fingerprint.

6. **Protect the passphrase environment** -- On macOS, prefer OS Keychain storage over `VAULT_PASSPHRASE` env var. On Linux headless machines, use `~/.memxp/env` with 0600 permissions and source it explicitly.

7. **Monitor audit logs** -- Regularly review `vault_audit` output for unexpected access patterns. Consider forwarding audit events to a central SIEM.

8. **Use `redact=true` for sensitive retrievals** -- When using MCP tools, prefer `recall(path, redact=true, copy_to_clipboard=true)` to avoid exposing credential values in agent chat history.

9. **Set conflict modes for critical paths** -- Use `vault_conflict_mode(path="production/*", mode="review")` to prevent automatic LWW overwrites of production credentials.

### For Developers

1. **Integrate `cargo-audit` into CI** -- Run `cargo audit` on every build to catch known vulnerabilities in dependencies.

2. **Consider encrypting the audit database** -- The current `audit.db` is unencrypted SQLite. Adding SQLCipher encryption would prevent access-pattern leakage.

3. **Add memory locking** -- Use `mlock` / `VirtualLock` on pages containing key material to prevent swapping to disk.

4. **Implement per-credential ACLs** -- The current model grants all-or-nothing access. Path-based ACLs with per-machine permissions would limit the blast radius of a compromised peer.

5. **Add TLS mutual authentication** -- Client certificates would provide stronger peer identity verification than the current shared-secret HMAC model.

6. **Harden TOTP implementation** -- The current TOTP uses SHA1 (standard for RFC 6238 compatibility). Consider adding SHA-256 TOTP support as an option.

7. **Rate-limit the sync daemon** -- Add per-IP connection rate limiting to the TLS listener to mitigate denial-of-service from a rogue peer.
