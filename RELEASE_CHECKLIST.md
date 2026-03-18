# Public Release Checklist

## Repo and governance

- [ ] License file present and legal review complete
- [ ] README and contributing docs present
- [ ] CODE_OF_CONDUCT and SECURITY present
- [ ] Branch protection + maintainer review policy in place
- [ ] Issue templates and PR template added

## Product surface

- [ ] Security model and threat boundaries documented
- [ ] Threat model and recovery story documented
- [ ] CLI quick-start verified on Linux, macOS, Windows
- [ ] Secret rotation and revocation paths clarified
- [x] Deterministic install instructions

## Release pipeline

- [ ] Build pipeline uses pinned dependencies
- [ ] CI covers formatting, linting, tests (where feasible)
- [x] Artifact publishing flow validated (GitHub Release workflow)
- [x] Multi-platform install and checksum verification flow added
- [ ] Release signing process defined

## Community

- [ ] First-pass contributor onboarding done
- [ ] Public roadmap shared
- [ ] Community communication channel/issue labeling set
