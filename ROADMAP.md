# memxp Roadmap

## 0.1.0 (Released — 2026-03-03)

- [x] Friendly MCP tool names (remember, recall, find, save_instructions)
- [x] One-command installer with Claude Code setup
- [x] Developer ID signed macOS binary
- [x] First-run onboarding (conversational profile setup)
- [x] Learning journal system (Meditation.md + cleanup skill)
- [x] `memxp doctor` health check command
- [x] Public API cleanup (P2P messaging removed from public surface)
- [x] Release packaging with checksum verification
- [x] Install + self-update path hardened

## 0.2.0 (Released — 2026-03-18)

- [x] Security audit: secure-by-default installer, operator mode, daemon TLS
- [x] Web dashboard cookie-only auth (no session tokens in URLs)
- [x] CLI stdin mode for secret input (`memxp set path -`)
- [x] Documentation accuracy pass (TLS, encryption, export claims)
- [x] Threat model updated with new trust boundary controls
- [x] CI: `cargo fmt`, `cargo clippy -D warnings`, `cargo test` on 3 platforms
- [x] `cargo audit` integrated into CI
- [x] Branch protection on main

## 0.3.x (Next)

- [ ] Homebrew tap (`brew install memxp`)
- [ ] Apple notarization for zero-dialog installs
- [ ] Intel Mac and Linux release binaries
- [ ] Auto-backup to iCloud/cloud storage for single-device users
- [ ] Deterministic build workflow
- [ ] SBOM publishing
- [ ] Backup and recovery documentation
- [ ] Sync protocol version compatibility matrix

## 1.0 Candidate

- [ ] API and CLI stability contract
- [ ] Final legal/docs audit
- [ ] Public governance for maintainers and release owners
- [ ] Cross-platform install matrix verified (Linux, macOS, Windows)
- [ ] CI/CD integration extension points

## Non-goals (initially)

- Replacing commercial secret managers at enterprise scale
- Becoming a general-purpose deployment orchestrator
- Building monolithic platform integrations without demand signals
