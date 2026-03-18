//! Credential management tools (12 tools).
//!
//! help, discover, recent, session_start, list, search, smart_get, get, set, delete, set_batch, get_bundle

use rmcp::model::{CallToolResult, Content};

use vault_core::config::{config_path, VaultConfig};
use vault_core::crypto;
use vault_core::query::rank_matches;
use vault_core::rotation::get_rotation_alerts;
use vault_core::security::mask_value;

use crate::clipboard;
use crate::response::{build_response, entry_to_json, format_response};
use crate::server::VaultState;

fn security_config() -> vault_core::config::SecurityConfig {
    VaultConfig::load(&config_path()).security
}

pub fn vault_help(topic: Option<&str>) -> CallToolResult {
    let topic = topic.unwrap_or("all");
    let text = match topic {
        "workflow" => include_str!("../../help/workflow.txt"),
        "security" => include_str!("../../help/security.txt"),
        "tools" => include_str!("../../help/tools.txt"),
        _ => include_str!("../../help/all.txt"),
    };
    ok_text(text.to_string())
}

pub fn vault_discover(state: &VaultState, query: Option<&str>) -> CallToolResult {
    let entries = match query {
        Some(prefix) => state.db.list_entries(None, None, Some(prefix)),
        None => state.db.list_entries(None, None, None),
    };
    let entries = entries.unwrap_or_default();

    let mut categories: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut services: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in &entries {
        *categories.entry(e.category.clone()).or_insert(0) += 1;
        if let Some(ref s) = e.service {
            *services.entry(s.clone()).or_insert(0) += 1;
        }
    }

    let guides = state.db.list_guides(None, None).unwrap_or_default();

    let result = serde_json::json!({
        "total_credentials": entries.len(),
        "total_guides": guides.len(),
        "categories": categories,
        "services": services,
    });

    state.log_audit("discover", None, None);
    ok_json(build_response(result))
}

pub fn vault_recent(state: &VaultState, limit: i32) -> CallToolResult {
    let mut entries = state.db.list_entries(None, None, None).unwrap_or_default();

    // Sort by updated_at descending
    entries.sort_by(|a, b| {
        let a_ts = a.updated_at.as_deref().unwrap_or("");
        let b_ts = b.updated_at.as_deref().unwrap_or("");
        b_ts.cmp(a_ts)
    });
    entries.truncate(limit as usize);

    let result = serde_json::json!({
        "count": entries.len(),
        "entries": entries.iter().map(|e| entry_to_json(e, false)).collect::<Vec<_>>(),
    });

    state.log_audit("recent", None, None);
    ok_json(build_response(result))
}

pub fn vault_session_start(
    state: &VaultState,
    _since: Option<&str>,
    rotation_window_days: i32,
) -> CallToolResult {
    let conflict_queue = vault_core::conflicts::ConflictQueue::new(&state.db);
    let conflicts = conflict_queue.get_pending_conflicts().unwrap_or_default();

    // Rotation alerts via free function
    let rotation_entries = state.db.list_rotation_candidates().unwrap_or_default();
    let rotation_alerts = get_rotation_alerts(&rotation_entries, rotation_window_days, true);

    let result = serde_json::json!({
        "unresolved_conflicts": conflicts.len(),
        "rotation_alerts": rotation_alerts.len(),
    });

    state.log_audit("session_start", None, None);
    ok_json(build_response(result))
}

pub fn vault_list(
    state: &VaultState,
    category: Option<&str>,
    service: Option<&str>,
    prefix: Option<&str>,
    limit: i32,
    _offset: i32,
) -> CallToolResult {
    let mut entries = state
        .db
        .list_entries(service, category, prefix)
        .unwrap_or_default();

    entries.truncate(limit as usize);

    let result = serde_json::json!({
        "total": entries.len(),
        "entries": entries.iter().map(|e| entry_to_json(e, false)).collect::<Vec<_>>(),
        "limit": limit,
    });

    state.log_audit("list", None, None);
    ok_json(build_response(result))
}

pub fn vault_search(state: &VaultState, query: &str) -> CallToolResult {
    let entries = state.db.search_entries(query, 100).unwrap_or_default();

    let results: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "path": e.path,
                "category": e.category,
                "service": e.service,
                "app": e.app,
                "env": e.env,
            })
        })
        .collect();

    let result = serde_json::json!({
        "query": query,
        "count": results.len(),
        "results": results,
    });

    state.log_audit("search", None, None);
    ok_json(build_response(result))
}

/// Maximum results when include_value=true on smart_get (prevents bulk dump via wildcard query).
const MAX_SMART_GET_WITH_VALUES: usize = 5;

pub fn vault_smart_get(
    state: &VaultState,
    query: &str,
    include_value: bool,
    max_candidates: i32,
    _min_confidence: f64,
    copy_to_clipboard: bool,
    redact: bool,
) -> CallToolResult {
    let entries = state.db.list_entries(None, None, None).unwrap_or_default();
    let security = security_config();
    let clipboard_clear_seconds = security.clipboard_clear_seconds as u64;
    let force_redact = security.redact_secrets_in_responses;

    // Cap max_candidates when include_value to prevent bulk dumps
    let effective_max = if include_value {
        (max_candidates as usize).min(MAX_SMART_GET_WITH_VALUES)
    } else {
        max_candidates as usize
    };

    let ranked = rank_matches(query, &entries, effective_max);

    let mut matches: Vec<serde_json::Value> = Vec::new();
    for search_match in &ranked {
        let entry = &search_match.entry;
        let mut m = serde_json::json!({
            "path": entry.path,
            "confidence": search_match.confidence,
            "category": entry.category,
            "service": entry.service,
        });

        let effective_redact = redact || (include_value && force_redact);
        if include_value && !effective_redact {
            m["value"] = serde_json::Value::String(entry.value.clone());
        } else if include_value {
            m["value"] = serde_json::Value::String("[REDACTED - copied to clipboard]".into());
        }

        if !include_value {
            m["value_preview"] = serde_json::Value::String(mask_value(&entry.value));
        }

        if copy_to_clipboard || effective_redact {
            let _ = clipboard::copy_and_clear(&entry.value, clipboard_clear_seconds);
            m["_clipboard"] = serde_json::Value::String(format!(
                "Value copied to clipboard (auto-clears in {}s)",
                clipboard_clear_seconds
            ));
        }

        matches.push(m);
    }

    let result = serde_json::json!({
        "query": query,
        "count": matches.len(),
        "matches": matches,
    });

    state.log_audit("smart_get", None, None);
    ok_json(build_response(result))
}

pub fn vault_get(
    state: &VaultState,
    path: &str,
    include_value: bool,
    show_metadata: bool,
    copy_to_clipboard: bool,
    redact: bool,
) -> CallToolResult {
    let entry = state.db.get_entry(path).unwrap_or(None);
    let entry = match entry {
        Some(e) => e,
        None => return ok_json(serde_json::json!({"error": format!("Not found: {path}")})),
    };
    let security = security_config();
    let clipboard_clear_seconds = security.clipboard_clear_seconds as u64;
    let effective_redact = redact || !include_value || security.redact_secrets_in_responses;

    state.log_audit("get", Some(path), None);

    let mut result = if show_metadata {
        entry_to_json(&entry, !effective_redact)
    } else {
        let mut m = serde_json::json!({"path": entry.path});
        if effective_redact {
            m["value"] = serde_json::Value::String(mask_value(&entry.value));
            m["_redacted"] = serde_json::Value::Bool(true);
        } else {
            m["value"] = serde_json::Value::String(entry.value.clone());
        }
        m
    };

    if copy_to_clipboard || effective_redact {
        let _ = clipboard::copy_and_clear(&entry.value, clipboard_clear_seconds);
        result["_clipboard"] = serde_json::Value::String(format!(
            "Value copied to clipboard (auto-clears in {}s)",
            clipboard_clear_seconds
        ));
    }

    ok_json(build_response(result))
}

pub fn vault_has(state: &VaultState, path: &str) -> CallToolResult {
    match state.db.get_entry(path) {
        Ok(Some(entry)) => ok_json(build_response(serde_json::json!({
            "exists": true,
            "path": path,
            "service": entry.service,
            "category": entry.category,
        }))),
        Ok(None) => ok_json(build_response(serde_json::json!({
            "exists": false,
            "path": path,
        }))),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn vault_set(
    state: &VaultState,
    path: &str,
    value: &str,
    category: Option<&str>,
    service: Option<&str>,
    app: Option<&str>,
    env: Option<&str>,
    notes: Option<&str>,
    tags: Option<&[String]>,
    storage_mode: Option<&str>,
    expires_at: Option<&str>,
    rotation_interval_days: Option<i32>,
    related_apps: Option<&[String]>,
) -> CallToolResult {
    if let Err(msg) = VaultState::ensure_non_reserved_path(path) {
        return ok_json(serde_json::json!({"error": msg}));
    }

    let existing = state.db.get_entry(path).unwrap_or(None);
    if existing.is_some() && !state.is_operator_active() {
        return ok_json(serde_json::json!({
            "error": format!(
                "Overwriting existing credential '{path}' requires operator mode. \
                 Call vault_operator_mode(enable=true) first."
            )
        }));
    }

    match state.db.set_entry(
        path,
        value,
        category,
        service,
        app,
        env,
        notes,
        tags,
        storage_mode,
        expires_at,
        rotation_interval_days,
        related_apps,
    ) {
        Ok(entry) => {
            let value_hash = crypto::value_hash(value);
            state.log_audit("set", Some(path), Some(&format!("hash={value_hash}")));

            let mut result = entry_to_json(&entry, false);
            result["value_hash"] = serde_json::Value::String(value_hash);
            result["message"] = serde_json::Value::String(format!("Credential '{path}' saved"));
            ok_json(build_response(result))
        }
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_delete(state: &VaultState, path: &str) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_delete") {
        return ok_json(serde_json::json!({"error": msg}));
    }
    if let Err(msg) = VaultState::ensure_non_reserved_path(path) {
        return ok_json(serde_json::json!({"error": msg}));
    }

    match state.db.delete_entry(path) {
        Ok(true) => {
            state.log_audit("delete", Some(path), None);
            ok_json(serde_json::json!({
                "path": path,
                "deleted": true,
                "message": format!("Credential '{path}' deleted"),
            }))
        }
        Ok(false) => ok_json(serde_json::json!({"error": format!("Not found: {path}")})),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_set_batch(state: &VaultState, entries: &[serde_json::Value]) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_set_batch") {
        return ok_json(serde_json::json!({"error": msg}));
    }

    let mut saved = Vec::new();
    let mut errors = Vec::new();

    for entry_json in entries {
        let path = entry_json.get("path").and_then(|v| v.as_str());
        let value = entry_json.get("value").and_then(|v| v.as_str());

        let (path, value) = match (path, value) {
            (Some(p), Some(v)) => (p, v),
            _ => {
                errors.push("Missing path or value in batch entry".to_string());
                continue;
            }
        };

        if let Err(msg) = VaultState::ensure_non_reserved_path(path) {
            errors.push(msg);
            continue;
        }

        let category = entry_json.get("category").and_then(|v| v.as_str());
        let service = entry_json.get("service").and_then(|v| v.as_str());
        let app = entry_json.get("app").and_then(|v| v.as_str());
        let env = entry_json.get("env").and_then(|v| v.as_str());
        let notes = entry_json.get("notes").and_then(|v| v.as_str());
        let storage_mode = entry_json.get("storage_mode").and_then(|v| v.as_str());
        let expires_at = entry_json.get("expires_at").and_then(|v| v.as_str());
        let rotation_interval_days = entry_json
            .get("rotation_interval_days")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let tags_vec: Option<Vec<String>> =
            entry_json
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });

        let related_vec: Option<Vec<String>> = entry_json
            .get("related_apps")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        match state.db.set_entry(
            path,
            value,
            category,
            service,
            app,
            env,
            notes,
            tags_vec.as_deref(),
            storage_mode,
            expires_at,
            rotation_interval_days,
            related_vec.as_deref(),
        ) {
            Ok(_) => {
                state.log_audit(
                    "set",
                    Some(path),
                    Some(&format!("batch, hash={}", crypto::value_hash(value))),
                );
                saved.push(path.to_string());
            }
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }

    let result = serde_json::json!({
        "saved": saved.len(),
        "errors": errors.len(),
        "saved_paths": saved,
        "error_details": errors,
    });

    ok_json(build_response(result))
}

/// Maximum number of entries to return with plaintext values in a single bundle.
const MAX_BUNDLE_WITH_VALUES: usize = 25;

pub fn vault_get_bundle(
    state: &VaultState,
    prefix: &str,
    include_values: bool,
    _show_metadata: bool,
) -> CallToolResult {
    let security = security_config();
    let include_plaintext_values = include_values && !security.redact_secrets_in_responses;

    // Reject empty-prefix dumps with include_values=true
    if include_values && prefix.trim().is_empty() {
        return ok_json(serde_json::json!({
            "error": "Refused: vault_get_bundle with empty prefix and include_values=true would dump the entire vault. \
                      Provide a specific prefix (e.g., 'aws/', 'postgres/')."
        }));
    }

    let entries = state
        .db
        .list_entries(None, None, Some(prefix))
        .unwrap_or_default();

    // Cap the number of entries returned with plaintext values
    let capped = if include_plaintext_values && entries.len() > MAX_BUNDLE_WITH_VALUES {
        state.log_audit(
            "get_bundle",
            Some(prefix),
            Some(&format!(
                "capped: {} entries total, returning {}",
                entries.len(),
                MAX_BUNDLE_WITH_VALUES
            )),
        );
        &entries[..MAX_BUNDLE_WITH_VALUES]
    } else {
        state.log_audit("get_bundle", Some(prefix), None);
        &entries[..]
    };

    let result = serde_json::json!({
        "prefix": prefix,
        "count": capped.len(),
        "total_matching": entries.len(),
        "capped": entries.len() > capped.len(),
        "requested_include_values": include_values,
        "include_values": include_plaintext_values,
        "redacted_by_policy": include_values && !include_plaintext_values,
        "entries": capped.iter().map(|e| entry_to_json(e, include_plaintext_values)).collect::<Vec<_>>(),
    });

    ok_json(build_response(result))
}

fn ok_text(text: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

fn ok_json(value: serde_json::Value) -> CallToolResult {
    ok_text(format_response(&value))
}
