---
description: Bootstrap your memxp knowledge base — interview, scan sources, create guides and secure credentials
allowed-tools: Read, Glob, Grep, Bash(cat:*), Bash(grep:*), Bash(find:*), Bash(ls:*), Bash(head:*), mcp__memxp__vault_add_guide, mcp__memxp__vault_set, mcp__memxp__vault_search, mcp__memxp__vault_search_guides, mcp__memxp__vault_discover, mcp__memxp__vault_list_guides, mcp__memxp__vault_guide, AskUserQuestion, Agent
argument-hint: Optional focus area (e.g., "projects", "credentials", "style", "full")
---

# memup — Bootstrap Your Agent Memory

You are setting up (or enriching) the user's persistent knowledge base so that ANY AI coding agent on ANY machine can work effectively without asking the same questions twice.

The knowledge base is stored in memxp — an encrypted, P2P-synced store accessible via MCP tools (`vault_add_guide`, `vault_set`, etc.) and CLI.

**User's request:** $ARGUMENTS

---

## Before You Start

1. Run `vault_discover()` to see what already exists in the vault
2. Run `vault_list_guides()` to see existing guides
3. Briefly tell the user what you found and what's missing

If the vault already has rich guides, skip to whichever phase is relevant. Don't duplicate existing knowledge — update or enrich it.

---

## Phase 1: Interview (2-3 minutes)

**Goal:** Understand who this person is so agents can work in their voice and context.

Ask the user these questions using AskUserQuestion (batch related questions together, don't ask one at a time):

**Identity & Role:**
- What do you do? (job title, domains, key responsibilities)
- What projects are you actively working on?
- What machines do you work across? (laptop, desktop, VPS, Mac Minis, etc.)

**Working Style:**
- How do you prefer agents to communicate? (concise vs detailed, formal vs casual)
- Any pet peeves with AI output? (too verbose, too many emojis, over-explains, etc.)
- Preferred languages/frameworks/tools?

**Workflows:**
- What recurring tasks do you do daily or weekly?
- What tasks do you wish you could delegate to an agent?
- Any deployment processes, maintenance routines, or review cycles?

Adapt based on $ARGUMENTS — if the user said "credentials" skip to Phase 3, if "projects" focus on workflow discovery, if "style" focus on voice/preferences, if "full" do everything.

---

## Phase 2: Source Scan (automatic)

**Goal:** Find existing configuration and context files to import.

Scan for these files silently (don't ask permission for each — just report what you found):

**Agent configs:**
- `~/.claude/CLAUDE.md`
- `~/.claude/projects/*/CLAUDE.md`
- `~/.cursor/rules/*.mdc`
- `~/.codex/instructions.md`
- `CLAUDE.md` in common project directories
- `AGENTS.md` in common project directories
- `.claude/commands/*.md` (existing skills)

**Personal context:**
- `~/about-me.md`, `~/brand-voice.md`, `~/working-style.md`
- Any `context/` or `Claude-Workspace/context/` directories

**Credentials in plaintext (security scan):**
- `~/.zshrc`, `~/.bashrc`, `~/.bash_profile` — look for `export *_KEY=`, `export *_TOKEN=`, `export *_SECRET=`
- `~/.env`, `.env` files in home directory
- `~/.aws/credentials`
- `~/.netrc`

Report findings as a checklist:
```
Source scan complete:
  Agent configs:
    ~/.claude/CLAUDE.md (187 lines) — import as guide?
    ~/.cursor/rules/memxp.mdc (42 lines) — import as guide?

  Plaintext credentials found:
    ~/.zshrc: OPENAI_API_KEY, ANTHROPIC_API_KEY
    ~/.aws/credentials: access key for profile "default"

  No personal context files found (will create from interview)
```

Ask the user: "Which of these should I import into memxp?"

---

## Phase 3: Knowledge Creation

**Goal:** Create guides from interview answers and imported sources.

Create guides using `vault_add_guide()`. Use these categories:

| Guide | Category | Content |
|-------|----------|---------|
| `about-me` | context | Role, projects, domains, communication preferences |
| `working-style` | context | Tone, pet peeves, conventions, preferred tools |
| `active-projects` | context | Current projects with brief descriptions and locations |
| `machine-fleet` | context | Machines, their roles, SSH access, what runs where |
| `weekly-workflows` | procedure | Recurring tasks, routines, review cycles |
| `deploy-{project}` | procedure | Deployment steps for each project (if discussed) |

For imported agent configs (CLAUDE.md, .cursorrules), create guides named after their source:
- `claude-md-global` — imported from ~/.claude/CLAUDE.md
- `cursor-rules-{name}` — imported from cursor rules

**Important:** Don't just dump file contents. Restructure into clean, actionable guides. Extract the useful instructions and discard boilerplate.

---

## Phase 4: Credential Securing

**Goal:** Move plaintext credentials into encrypted storage.

For each credential found in Phase 2:

1. Confirm with the user before touching anything
2. Use `vault_set(path, value, category, service, notes)` to store securely
3. Follow the path convention: `service/resource/detail` (e.g., `openai/api/key`)
4. Do NOT remove credentials from the source files — just inform the user they can do so manually ("You can now remove the OPENAI_API_KEY line from ~/.zshrc since it's secured in memxp")

---

## Phase 5: Summary & Next Steps

**Goal:** Show the user what was created and how to use it.

Print a summary:
```
memxp is ready!

Guides created:
  about-me — your role and communication preferences
  working-style — how you like agents to work
  active-projects — 4 projects with descriptions
  weekly-workflows — 3 recurring routines

Credentials secured:
  openai/api/key — OpenAI API key
  anthropic/api/key — Anthropic API key

Your agents can now:
  "Check memxp for how to deploy the VPS app"
  "Show me my weekly workflows from the vault"
  "Get the OpenAI API key from the vault"

To level up further:
  - Run /memup again anytime to add more knowledge
  - Agents will write improved guides back automatically
  - Everything syncs across your machines via P2P
```

---

## Rules

- NEVER store credential values in guides — guides are for procedures, credentials go in `vault_set`
- NEVER delete or modify the user's source files (CLAUDE.md, .zshrc, etc.) — only read and import
- If the vault already has a guide with the same name, READ it first and MERGE new information rather than overwriting
- Keep guides concise and actionable — agents will read these, not humans
- Use `vault_search_guides()` before creating to avoid duplicates
- If the user seems overwhelmed, do fewer phases. The minimum viable memup is: interview + about-me guide + working-style guide
