# Public Release Checklist

## Repo and Governance

- [x] License file present (MIT)
- [x] README with install instructions and feature overview
- [x] CONTRIBUTING.md with development setup
- [x] CODE_OF_CONDUCT.md and SECURITY.md present
- [x] Issue templates and PR template added
- [x] Branch protection + required status checks (4 checks: macOS, Linux, Windows, Security Audit)

## Product Surface

- [x] Security model and threat boundaries documented (docs/threat-model.md)
- [x] CLI quick-start verified on macOS (Apple Silicon)
- [x] Friendly MCP tool names for non-technical users
- [x] First-run onboarding guide seeded during install
- [x] `memxp doctor` health check with fix suggestions
- [x] CLI quick-start verified on Linux (Debian 13 x86_64) and Windows (Windows 11 Pro x86_64)
- [ ] Secret rotation and revocation paths clarified in docs

## Security Hardening (0.2.0)

- [x] Installer defaults to secure (no auto-approve, no Desktop passphrase file)
- [x] Operator auto-promotion gated behind `VAULT_OPERATOR_AUTO_PROMOTE=1`
- [x] Web auth cookie-only (no session tokens in URLs or JSON responses)
- [x] Daemon TLS default flipped to secure
- [x] CLI stdin mode for secret input (avoids shell history)
- [x] Documentation accuracy: TLS, encryption, and export claims corrected
- [x] Threat model updated (T5 operator controls, T6 cookie-only auth)

## Release Pipeline

- [x] Developer ID signed macOS binary
- [x] Artifact publishing flow (GitHub Releases)
- [x] Checksum verification in install script
- [x] Build-release script with env-var signing identity
- [x] CI covers formatting, linting, tests (3 platforms: macOS, Linux, Windows)
- [x] Pinned dependency audit (`cargo audit` via `rustsec/audit-check` in CI)
- [ ] Apple notarization

## Community

- [x] Public roadmap shared (ROADMAP.md)
- [ ] First-pass contributor onboarding guide
- [ ] Communication channel / issue labeling
