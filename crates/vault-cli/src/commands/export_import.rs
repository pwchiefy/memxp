//! Export/import commands.

use vault_core::credential_store::CredentialStore;

use super::init::open_db;

/// `memxp export [-o <file>]`
pub fn export(output: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let (entries, unresolved) = store.export_all()?;
    let guides = db.list_guides(None, None)?;

    let version = db.db_version()?;
    let site_id = db
        .conn()
        .query_row("SELECT hex(crsql_site_id())", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap_or_else(|_| "unknown".to_string());

    let export_data = serde_json::json!({
        "version": 1,
        "site_id": site_id,
        "db_version": version,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "entries": entries.iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "value": e.value,
                "category": e.category,
                "service": e.service,
                "app": e.app,
                "env": e.env,
                "notes": e.notes,
                "tags": e.tags,
                "storage_mode": e.storage_mode,
                "expires_at": e.expires_at,
                "rotation_interval_days": e.rotation_interval_days,
                "related_apps": e.related_apps,
            })
        }).collect::<Vec<_>>(),
        "guides": guides.iter().map(|g| {
            serde_json::json!({
                "name": g.name,
                "content": g.content,
                "category": g.category,
                "tags": g.tags,
                "status": g.status,
                "related_paths": g.related_paths,
            })
        }).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&export_data)?;

    if let Some(path) = output {
        std::fs::write(path, &json)?;
        println!(
            "Exported {} entries, {} guides to {}",
            entries.len(),
            guides.len(),
            path
        );
    } else {
        println!("{json}");
    }

    if !unresolved.is_empty() {
        eprintln!(
            "WARNING: {} keychain entries could not be exported:",
            unresolved.len()
        );
        for p in &unresolved {
            eprintln!("  - {p}");
        }
    }

    Ok(())
}

/// `memxp import <file>`
pub fn import(file: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let store = CredentialStore::new(&db);
    let content = std::fs::read_to_string(file)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    let mut entry_count = 0;
    let mut guide_count = 0;

    if let Some(entries) = data.get("entries").and_then(|v| v.as_array()) {
        for e in entries {
            let path = e.get("path").and_then(|v| v.as_str()).unwrap_or_default();
            let value = e.get("value").and_then(|v| v.as_str()).unwrap_or_default();

            if path.is_empty() {
                continue;
            }

            let storage_mode = e
                .get("storage_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("vault");
            if storage_mode == "keychain" && value.is_empty() {
                eprintln!(
                    "SKIP: {path} (keychain entry with empty value — would overwrite real secret)"
                );
                continue;
            }

            let tags: Vec<String> = e
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let related_apps: Vec<String> = e
                .get("related_apps")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let rotation_days = e
                .get("rotation_interval_days")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32);

            let tags_opt = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };
            let apps_opt = if related_apps.is_empty() {
                None
            } else {
                Some(related_apps.as_slice())
            };

            store.remember(
                path,
                value,
                e.get("category").and_then(|v| v.as_str()),
                e.get("service").and_then(|v| v.as_str()),
                e.get("app").and_then(|v| v.as_str()),
                e.get("env").and_then(|v| v.as_str()),
                e.get("notes").and_then(|v| v.as_str()),
                tags_opt,
                e.get("storage_mode").and_then(|v| v.as_str()),
                e.get("expires_at").and_then(|v| v.as_str()),
                rotation_days,
                apps_opt,
            )?;
            entry_count += 1;
        }
    }

    if let Some(guides) = data.get("guides").and_then(|v| v.as_array()) {
        for g in guides {
            let name = g.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            let content = g
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            if name.is_empty() {
                continue;
            }

            let tags: Vec<String> = g
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let related_paths: Vec<String> = g
                .get("related_paths")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let tags_opt = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };
            let paths_opt = if related_paths.is_empty() {
                None
            } else {
                Some(related_paths.as_slice())
            };

            db.set_guide(
                name,
                content,
                g.get("category").and_then(|v| v.as_str()),
                tags_opt,
                g.get("status").and_then(|v| v.as_str()),
                None, // verified_at
                paths_opt,
            )?;
            guide_count += 1;
        }
    }

    println!("Imported {entry_count} entries, {guide_count} guides from {file}");
    Ok(())
}
