# Governance

## Project Leadership

memxp uses a **single maintainer** model, appropriate for its current stage. The project creator serves as the maintainer and has final authority on all decisions.

As the project grows, additional maintainers may be appointed (see "Becoming a Maintainer" below).

## Decision Making

- The maintainer has final say on all technical and project decisions.
- Community input is welcomed via GitHub Issues and Discussions.
- Significant changes should be proposed as Issues before submitting a pull request.
- RFCs or design documents may be requested for large architectural changes.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

**Issue Triage Labels:**
- `bug` — Confirmed defect
- `enhancement` — Feature request or improvement
- `good first issue` — Suitable for new contributors
- `help wanted` — Maintainer is open to external contributions
- `wontfix` — Out of scope or by design
- `security` — Security-related (may be handled privately)

## Becoming a Maintainer

Maintainer status may be offered to contributors who demonstrate:

1. **Sustained contributions** — Multiple accepted PRs over an extended period
2. **Code review quality** — Thoughtful, constructive reviews on others' PRs
3. **Project understanding** — Deep familiarity with the codebase and architecture
4. **Alignment with project values** — Security-first mindset, backward compatibility, clear documentation
5. **Reliability** — Responsive communication and follow-through on commitments

Maintainer invitations are at the discretion of the current maintainer(s).

## Release Process

1. All releases are tagged from the `main` branch.
2. The project follows [Semantic Versioning](https://semver.org/).
3. Every release must include a changelog entry.
4. Release artifacts are built via CI for macOS (arm64/x86_64), Linux (x86_64), and Windows (x86_64).
5. Binaries and checksums are published as GitHub Release assets.

## Communication Channels

| Channel | Purpose |
|---------|---------|
| [GitHub Issues](../../issues) | Bug reports, feature requests |
| [GitHub Discussions](../../discussions) | Questions, ideas, general conversation |

There are no external chat platforms at this time. All project communication happens on GitHub.

## Code of Conduct

All participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md). In short: be respectful, constructive, and professional.

Reports of unacceptable behavior can be sent to the maintainer via the contact information in the Code of Conduct.
