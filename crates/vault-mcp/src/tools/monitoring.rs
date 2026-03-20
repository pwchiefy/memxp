//! Monitoring tools (4 tools).
//!
//! changes, impact, lint, rotation_alerts

use rmcp::model::{CallToolResult, Content};

use vault_core::lint;
use vault_core::rotation::get_rotation_alerts;
use vault_core::security::mask_value;

use crate::response::{build_response, format_response};
use crate::server::VaultState;

pub fn vault_changes(
    state: &VaultState,
    _since: Option<&str>,
    path: Option<&str>,
    prefix: Option<&str>,
    _action: Option<&str>,
    limit: i32,
) -> CallToolResult {
    let (hashed_entries, unresolved) = state
        .credentials()
        .list_with_hashes(None, None, prefix)
        .unwrap_or_else(|_| (Vec::new(), Vec::new()));

    let mut changes: Vec<serde_json::Value> = Vec::new();
    for he in &hashed_entries {
        if let Some(p) = path {
            if he.entry.path != p {
                continue;
            }
        }

        changes.push(serde_json::json!({
            "path": he.entry.path,
            "action": "set",
            "value_hash": he.value_hash,
            "value_length": he.value_length,
            "updated_at": he.entry.updated_at,
        }));
    }

    changes.truncate(limit as usize);

    let mut result = serde_json::json!({
        "count": changes.len(),
        "changes": changes,
    });

    if !unresolved.is_empty() {
        result["unresolved_keychain_paths"] = serde_json::json!(unresolved);
    }

    state.log_audit("changes", None, None);
    ok_json(build_response(result))
}

pub fn vault_impact(state: &VaultState, app: &str) -> CallToolResult {
    let entries = state
        .credentials()
        .list(None, None, None)
        .unwrap_or_default();

    let affected: Vec<serde_json::Value> = entries
        .iter()
        .filter(|e| e.related_apps.iter().any(|a| a == app) || e.app.as_deref() == Some(app))
        .map(|e| {
            serde_json::json!({
                "path": e.path,
                "category": e.category,
                "service": e.service,
                "value_preview": mask_value(&e.value),
            })
        })
        .collect();

    let result = serde_json::json!({
        "app": app,
        "count": affected.len(),
        "credentials": affected,
    });

    state.log_audit("impact", None, Some(&format!("app={app}")));
    ok_json(build_response(result))
}

pub fn vault_lint(
    state: &VaultState,
    prefix: Option<&str>,
    similarity_threshold: f64,
    max_similar_pairs: usize,
    include_suggestions: bool,
) -> CallToolResult {
    let entries = state
        .credentials()
        .list(None, None, prefix)
        .unwrap_or_default();
    let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();

    let report = lint::lint_paths(&paths, similarity_threshold, max_similar_pairs);

    let mut result = serde_json::json!({
        "total_paths": report.total_paths,
        "duplicate_groups": report.duplicates.len(),
        "similar_pairs": report.similar_pairs.len(),
    });

    if !report.duplicates.is_empty() {
        result["duplicates"] = serde_json::json!(report
            .duplicates
            .iter()
            .map(|g| {
                serde_json::json!({
                    "canonical": g.canonical,
                    "paths": g.paths,
                })
            })
            .collect::<Vec<_>>());
    }

    if !report.similar_pairs.is_empty() {
        result["similar"] = serde_json::json!(report
            .similar_pairs
            .iter()
            .map(|p| {
                serde_json::json!({
                    "path_a": p.path_a,
                    "path_b": p.path_b,
                    "similarity": format!("{:.2}", p.similarity),
                })
            })
            .collect::<Vec<_>>());
    }

    if include_suggestions && !report.suggestions.is_empty() {
        result["suggestions"] = serde_json::json!(report
            .suggestions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "path": s.path,
                    "suggested": s.suggested,
                    "issues": s.issues,
                })
            })
            .collect::<Vec<_>>());
    }

    state.log_audit("lint", None, None);
    ok_json(build_response(result))
}

pub fn vault_rotation_alerts(
    state: &VaultState,
    window_days: i32,
    include_overdue: bool,
) -> CallToolResult {
    let entries = state
        .credentials()
        .list_rotation_candidates()
        .unwrap_or_default();
    let alerts = get_rotation_alerts(&entries, window_days, include_overdue);

    let result = serde_json::json!({
        "window_days": window_days,
        "include_overdue": include_overdue,
        "count": alerts.len(),
        "alerts": alerts.iter().map(|a| {
            serde_json::json!({
                "path": a.entry.path,
                "due_at": a.due_at.to_rfc3339(),
                "days_until_due": a.days_until_due,
            })
        }).collect::<Vec<_>>(),
    });

    state.log_audit("rotation_alerts", None, None);
    ok_json(build_response(result))
}

fn ok_json(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(format_response(&value))])
}
