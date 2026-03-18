//! Credential management commands: get, set, delete, list, search.

use vault_core::credential_store::CredentialStore;
use vault_core::security::mask_value;

use super::init::open_db;

/// `memxp get <path>`
pub fn get(
    path: &str,
    json: bool,
    value_only: bool,
    redact: bool,
    clipboard: bool,
) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let entry = store
        .recall(path)?
        .ok_or_else(|| anyhow::anyhow!("Entry not found: {path}"))?;
    let security =
        vault_core::config::VaultConfig::load(&vault_core::config::config_path()).security;
    let effective_redact = redact || !value_only || security.redact_secrets_in_responses;
    let clipboard_clear_seconds = security.clipboard_clear_seconds as u64;

    if clipboard || effective_redact {
        let _ = vault_mcp::clipboard::copy_and_clear(&entry.value, clipboard_clear_seconds);
    }

    if value_only && !effective_redact {
        println!("{}", entry.value);
        return Ok(());
    }

    if json {
        let j = serde_json::json!({
            "path": entry.path,
            "value": if effective_redact { mask_value(&entry.value) } else { entry.value.clone() },
            "category": entry.category,
            "service": entry.service,
            "app": entry.app,
            "env": entry.env,
            "notes": entry.notes,
            "tags": entry.tags,
            "storage_mode": entry.storage_mode,
            "expires_at": entry.expires_at,
            "rotation_interval_days": entry.rotation_interval_days,
            "related_apps": entry.related_apps,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "_redacted": effective_redact,
            "_clipboard": if clipboard || effective_redact {
                format!("Value copied to clipboard (auto-clears in {clipboard_clear_seconds}s)")
            } else {
                String::new()
            },
        });
        println!("{}", serde_json::to_string_pretty(&j)?);
        return Ok(());
    }

    println!("Path: {}", entry.path);
    println!(
        "Value: {}",
        if effective_redact {
            mask_value(&entry.value)
        } else {
            entry.value.clone()
        }
    );
    if clipboard || effective_redact {
        println!("(copied to clipboard, clears in {clipboard_clear_seconds}s)");
    }
    if entry.category != "env_var" {
        println!("Category: {}", entry.category);
    }
    if let Some(ref s) = entry.service {
        println!("Service: {s}");
    }
    if let Some(ref a) = entry.app {
        println!("App: {a}");
    }
    if let Some(ref e) = entry.env {
        println!("Env: {e}");
    }
    if let Some(ref n) = entry.notes {
        println!("Notes: {n}");
    }
    if !entry.tags.is_empty() {
        println!("Tags: {}", entry.tags.join(", "));
    }
    if entry.storage_mode != "vault" {
        println!("Storage: {}", entry.storage_mode);
    }
    if let Some(ref e) = entry.expires_at {
        println!("Expires: {e}");
    }
    if let Some(d) = entry.rotation_interval_days {
        println!("Rotation: every {d} days");
    }
    if !entry.related_apps.is_empty() {
        println!("Related apps: {}", entry.related_apps.join(", "));
    }
    if let Some(ref c) = entry.created_at {
        println!("Created: {c}");
    }
    if let Some(ref u) = entry.updated_at {
        println!("Updated: {u}");
    }
    Ok(())
}

/// Options for the set command.
pub struct SetOpts<'a> {
    pub path: &'a str,
    pub value: &'a str,
    pub category: Option<&'a str>,
    pub service: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub tags: &'a [String],
    pub env: Option<&'a str>,
    pub storage_mode: Option<&'a str>,
    pub rotation_days: Option<i32>,
}

/// `memxp set <path> <value>`
pub fn set(opts: &SetOpts<'_>) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);

    let existing = store.exists(opts.path)?;
    if existing && !vault_core::operator_session::is_operator_session_active() {
        anyhow::bail!(
            "Overwriting existing credential '{}' requires operator mode. Run `memxp operator enable` first.",
            opts.path
        );
    }

    let tags_opt = if opts.tags.is_empty() {
        None
    } else {
        Some(opts.tags)
    };

    let entry = store.remember(
        opts.path,
        opts.value,
        opts.category,
        opts.service,
        None, // app
        opts.env,
        opts.notes,
        tags_opt,
        opts.storage_mode,
        None, // expires_at
        opts.rotation_days,
        None, // related_apps
    )?;

    println!("Set: {}", entry.path);
    println!("  Value: {}", mask_value(&entry.value));
    if entry.category != "env_var" {
        println!("  Category: {}", entry.category);
    }
    if let Some(ref s) = entry.service {
        println!("  Service: {s}");
    }
    Ok(())
}

/// `memxp delete <path>`
pub fn delete(path: &str) -> anyhow::Result<()> {
    if !vault_core::operator_session::is_operator_session_active() {
        anyhow::bail!(
            "Deleting credentials requires operator mode. Run `memxp operator enable` first."
        );
    }
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let deleted = store.forget(path)?;
    if deleted {
        println!("Deleted: {path}");
    } else {
        println!("Not found: {path}");
    }
    Ok(())
}

/// `memxp list`
pub fn list(
    service: Option<&str>,
    category: Option<&str>,
    prefix: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let entries = store.list(service, category, prefix)?;

    if json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "value": mask_value(&e.value),
                    "category": e.category,
                    "service": e.service,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("{} entries:", entries.len());
    for e in &entries {
        let svc = e.service.as_deref().unwrap_or("-");
        println!(
            "  {} [{}] ({}) = {}",
            e.path,
            e.category,
            svc,
            mask_value(&e.value)
        );
    }
    Ok(())
}

/// `memxp search <query>`
pub fn search(query: &str, json: bool) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let entries = store.find(query, 20)?;

    if json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "value": mask_value(&e.value),
                    "category": e.category,
                    "service": e.service,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No matches for '{query}'.");
        return Ok(());
    }

    println!("{} matches:", entries.len());
    for e in &entries {
        let svc = e.service.as_deref().unwrap_or("-");
        println!(
            "  {} [{}] ({}) = {}",
            e.path,
            e.category,
            svc,
            mask_value(&e.value)
        );
    }
    Ok(())
}

/// `memxp status`
pub fn status() -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);

    let db_path = vault_core::config::db_path();
    let version = db.db_version()?;
    let schema = db.schema_version();
    let cr = db.cr_enabled();
    let machine_id = vault_core::config::get_local_machine_id();

    let entries = store.list(None, None, None)?;

    // Count by category
    let mut by_category = std::collections::HashMap::new();
    let mut by_service = std::collections::HashMap::new();
    for e in &entries {
        *by_category.entry(e.category.clone()).or_insert(0u32) += 1;
        if let Some(ref s) = e.service {
            *by_service.entry(s.clone()).or_insert(0u32) += 1;
        }
    }

    println!("memxp Status:");
    println!("  Database: {}", db_path.display());
    println!("  Machine ID: {machine_id}");
    println!("  Schema: v{schema}");
    println!("  DB version: {version}");
    println!("  cr-sqlite: {}", if cr { "enabled" } else { "disabled" });
    println!("  Entries: {}", entries.len());
    let archived_task_rows = db.agent_task_archive_row_count();
    if archived_task_rows > 0 {
        println!(
            "  Legacy messaging migration: {} rows moved to agent_tasks_archive (archived, not synced).",
            archived_task_rows
        );
    }

    if !by_category.is_empty() {
        println!("  By category:");
        let mut cats: Vec<_> = by_category.into_iter().collect();
        cats.sort_by(|a, b| b.1.cmp(&a.1));
        for (cat, count) in cats {
            println!("    {cat}: {count}");
        }
    }

    if !by_service.is_empty() {
        println!("  By service:");
        let mut svcs: Vec<_> = by_service.into_iter().collect();
        svcs.sort_by(|a, b| b.1.cmp(&a.1));
        for (svc, count) in svcs {
            println!("    {svc}: {count}");
        }
    }

    Ok(())
}
