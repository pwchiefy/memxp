# Contributing to memxp

Welcome. This project is in release-prep and is optimized for contributors who want to
help ship a practical secrets platform.

## Before you start

- Read and follow [SECURITY.md](SECURITY.md).
- Use the issue templates in `.github/ISSUE_TEMPLATE`.
- Keep commits focused and small. One meaningful change per commit.

## Local workflow

```bash
cargo build
cargo test --workspace
cargo fmt
```

If you touch CLI/sync behavior, include tests or provide a clear test plan in the PR description.

### macOS Keychain prompts during tests

On macOS, running `cargo test` will trigger **Keychain access prompts** (typically 3–4 dialogs).
This is expected — several tests exercise the `keyring` crate which reads from / writes to
the macOS Keychain under the service name `com.memxp.credentials`. Each test binary is a
separate process, so macOS asks for authorization individually.

Click **Always Allow** to avoid repeat prompts on future test runs. The tests only access
a dedicated test entry (`vault-core-test/keyring-roundtrip`) and will not touch your real
credentials. On CI (Linux/Windows), keyring tests are automatically skipped when no
credential store is available.

## Branches and PRs

- Branch names: `feat/*`, `fix/*`, `chore/*`, `doc/*`
- PRs should include:
  - summary of change
  - what was tested
  - security impact (if any)
  - links to related issues

## Review expectations

- Prefer explicit error handling over silent fallbacks.
- Keep API boundaries backward-compatible when possible.
- Add docs for user-facing behavior changes.
- For security-sensitive areas (`crypto`, `key storage`, `sync`, `passphrase handling`),
  include a short risk review in the PR.

