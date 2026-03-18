# memxp Agent Skill

## Safe Defaults
- Prefer `memxp has <path>` before any retrieval.
- Prefer `memxp get <path> --clipboard` or default masked `memxp get <path>`.
- Avoid plaintext retrieval unless explicitly required (`--value-only` or MCP `include_value=true`).

## Recommended Workflow
1. `memxp has <path>`
2. If missing, request `memxp set <path> <value>`
3. Use `memxp inject <path> <ENV_VAR>` or `memxp get <path> --clipboard`
4. Execute dependent operation
5. Avoid logging raw secret values

## Operator Actions
- High-risk mutations require operator mode:
  - `memxp operator enable --ttl 900`
  - perform mutation
  - `memxp operator disable`

## Out-of-Band Confirmation
- For MCP pending challenge responses:
  - `memxp confirm-operator <challenge-id> --action operator_mode`
  - `memxp confirm-operator <challenge-id> --action unlock`

## Placeholder Convention
- Use placeholder tokens in generated artifacts:
  - `<vault:api/openai/key>`
- Expand placeholders intentionally:
  - `memxp expand config.template > config`

## Guide Navigation (Routing)

When the vault has many guides (50+), efficient navigation prevents wasted tool calls:

1. **Start with hub guides for broad queries.** If you need something in a domain (VPS, Data Warehouse, UniFi), read the hub guide first — it's a routing table.
   - `read_instructions("vps-operations")` → lists all VPS child guides
   - `read_instructions("data-warehouse-agent-reference")` → lists all data pipeline guides

2. **Follow cross-reference headers.** Guide headers (blockquote at top) link to related guides and the domain hub. Read and follow these before searching.

3. **Follow inline routing hints.** When a guide says `vault_list(prefix="company/staff/")`, call it directly — don't search for keywords like "phone" or "mobile".

4. **Use `vault_list(prefix=...)` for structured data.** When you know the path hierarchy (e.g., `company/staff/`, `company-hq/google-workspace/`), browse by prefix instead of keyword searching.

5. **Search is the fallback, not the first step.** Only use `find_instructions(query)` or `find(query)` when you don't know which guide or path prefix to look at.

### Navigation anti-pattern (wasteful)

```
find("phone numbers")        # no results
find("mobile")               # no results
find("cell")                  # no results
find_instructions("staff phone")   # no results
# ...10 wasted calls
```

### Navigation best practice (efficient)

```
read_instructions("team-contacts")                    # read the contacts guide
# Guide says: vault_list(prefix="company/staff/")
vault_list(prefix="company/staff/")                # browse staff records
recall("company/staff/jane-doe", include_value=true)  # get the data
# 3 calls total
```

## Anti-Patterns
- Do not pass passphrases directly in chat/tool payloads if avoidable.
- Do not print plaintext secrets in summaries, logs, or markdown outputs.
- Do not keyword-fish with `find` when a guide gives you an explicit `vault_list(prefix=...)` hint.
- Do not skip guide headers — they are navigation aids, not decoration.
