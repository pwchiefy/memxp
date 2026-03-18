# Public Release Checklist

## Repo and Governance

- [x] License file present (MIT)
- [x] README with install instructions and feature overview
- [x] CONTRIBUTING.md with development setup
- [x] CODE_OF_CONDUCT.md and SECURITY.md present
- [x] Issue templates and PR template added
- [ ] Branch protection + maintainer review policy

## Product Surface

- [x] Security model and threat boundaries documented (docs/threat-model.md)
- [x] CLI quick-start verified on macOS (Apple Silicon)
- [x] Friendly MCP tool names for non-technical users
- [x] First-run onboarding guide seeded during install
- [x] `memxp doctor` health check with fix suggestions
- [ ] CLI quick-start verified on Linux and Windows
- [ ] Secret rotation and revocation paths clarified in docs

## Release Pipeline

- [x] Developer ID signed macOS binary
- [x] Artifact publishing flow (GitHub Releases)
- [x] Checksum verification in install script
- [x] Build-release script with env-var signing identity
- [ ] CI covers formatting, linting, tests
- [ ] Pinned dependency audit (cargo-audit)
- [ ] Apple notarization

## Community

- [x] Public roadmap shared (ROADMAP.md)
- [ ] First-pass contributor onboarding guide
- [ ] Communication channel / issue labeling
