//! Conflict resolution tools (3 tools).
//!
//! conflicts, resolve_conflict, conflict_mode

use rmcp::model::{CallToolResult, Content};

use vault_core::conflicts::ConflictQueue;
use vault_core::models::ConflictMode;
use vault_core::security::mask_value;

use crate::response::{build_response, format_response};
use crate::server::VaultState;

pub fn vault_conflicts(
    state: &VaultState,
    include_resolved: bool,
    path: Option<&str>,
    stats_only: bool,
) -> CallToolResult {
    let queue = ConflictQueue::new(&state.db);

    if stats_only {
        let stats = queue
            .get_stats()
            .unwrap_or(vault_core::conflicts::ConflictStats {
                total: 0,
                pending: 0,
                kept_local: 0,
                kept_remote: 0,
                merged: 0,
            });
        return ok_json(serde_json::json!({
            "pending": stats.pending,
            "kept_local": stats.kept_local,
            "kept_remote": stats.kept_remote,
            "merged": stats.merged,
            "total": stats.total,
        }));
    }

    let conflicts = if include_resolved {
        queue
            .list_conflicts(include_resolved, 1000)
            .unwrap_or_default()
    } else {
        queue.get_pending_conflicts().unwrap_or_default()
    };

    // Filter by path if specified
    let conflicts: Vec<_> = if let Some(p) = path {
        conflicts.into_iter().filter(|c| c.path == p).collect()
    } else {
        conflicts
    };

    let result = serde_json::json!({
        "count": conflicts.len(),
        "conflicts": conflicts.iter().map(|c| {
            let mut conflict = serde_json::json!({
                "id": c.id,
                "path": c.path,
                "local_value_masked": c.local_value.as_deref().map(mask_value),
                "remote_value_masked": c.remote_value.as_deref().map(mask_value),
                "local_updated_at": c.local_updated_at,
                "remote_updated_at": c.remote_updated_at,
                "remote_site_id": c.remote_site_id,
                "created_at": c.created_at,
            });
            if let Some(ref r) = c.resolution {
                conflict["resolution"] = serde_json::Value::String(r.clone());
                conflict["resolved_at"] = c.resolved_at.as_ref()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .unwrap_or(serde_json::Value::Null);
            }
            conflict
        }).collect::<Vec<_>>(),
    });

    state.log_audit("conflicts", None, None);
    ok_json(build_response(result))
}

pub fn vault_resolve_conflict(
    state: &VaultState,
    conflict_id: &str,
    resolution: &str,
    value: Option<&str>,
    notes: Option<&str>,
) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_resolve_conflict") {
        return ok_json(serde_json::json!({"error": msg}));
    }

    let queue = ConflictQueue::new(&state.db);

    // Validate resolution
    if !["keep_local", "keep_remote", "merge"].contains(&resolution) {
        return ok_json(serde_json::json!({
            "error": format!("Invalid resolution: {resolution}. Must be keep_local, keep_remote, or merge")
        }));
    }

    // Merge requires a value
    if resolution == "merge" && value.is_none() {
        return ok_json(serde_json::json!({
            "error": "Merge resolution requires a 'value' parameter"
        }));
    }

    match queue.resolve_conflict(conflict_id, resolution, value, notes.unwrap_or("")) {
        Ok(Some(conflict)) => {
            state.log_audit(
                "resolve_conflict",
                Some(&conflict.path),
                Some(&format!("resolution={resolution}")),
            );
            ok_json(serde_json::json!({
                "id": conflict.id,
                "path": conflict.path,
                "resolution": conflict.resolution,
                "resolved_at": conflict.resolved_at,
                "message": format!("Conflict resolved with '{resolution}'"),
            }))
        }
        Ok(None) => ok_json(serde_json::json!({
            "error": format!("Conflict not found: {conflict_id}")
        })),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_conflict_mode(state: &VaultState, path: &str, mode: &str) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_conflict_mode") {
        return ok_json(serde_json::json!({"error": msg}));
    }

    let queue = ConflictQueue::new(&state.db);

    let conflict_mode = ConflictMode::parse(mode);

    match queue.set_conflict_mode(path, &conflict_mode) {
        Ok(_) => {
            state.log_audit("conflict_mode", Some(path), Some(&format!("mode={mode}")));
            ok_json(serde_json::json!({
                "path": path,
                "mode": mode,
                "message": format!("Conflict mode for '{path}' set to '{mode}'"),
            }))
        }
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

fn ok_json(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(format_response(&value))])
}
