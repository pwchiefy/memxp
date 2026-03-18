//! Guide management tools (8 tools).
//!
//! add_guide, guide, list_guides, search_guides, delete_guide,
//! verify_guide, deprecate_guide, stale_guides

use rmcp::model::{CallToolResult, Content};

use crate::response::{build_response, format_response, guide_to_json};
use crate::server::VaultState;

pub fn vault_add_guide(
    state: &VaultState,
    name: &str,
    content: &str,
    category: Option<&str>,
    tags: Option<&[String]>,
    status: Option<&str>,
    related_paths: Option<&[String]>,
) -> CallToolResult {
    let existing = state.db.get_guide(name).unwrap_or(None);
    if existing.is_some() && !state.is_operator_active() {
        return ok_json(serde_json::json!({
            "error": format!(
                "Updating existing guide '{name}' requires operator mode. \
                 Call vault_operator_mode(enable=true) first."
            )
        }));
    }

    match state.db.set_guide(
        name,
        content,
        category,
        tags,
        status,
        None, // verified_at
        related_paths,
    ) {
        Ok(guide) => {
            state.log_audit("set_guide", Some(&format!("guide:{name}")), None);
            let mut result = guide_to_json(&guide, false);
            result["message"] = serde_json::Value::String(format!(
                "Guide '{name}' saved (version {})",
                guide.version
            ));
            ok_json(build_response(result))
        }
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_guide(state: &VaultState, name: &str) -> CallToolResult {
    match state.db.get_guide(name) {
        Ok(Some(guide)) => {
            state.log_audit("get_guide", Some(&format!("guide:{name}")), None);
            ok_json(build_response(guide_to_json(&guide, true)))
        }
        Ok(None) => ok_json(serde_json::json!({"error": format!("Guide not found: {name}")})),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_list_guides(
    state: &VaultState,
    category: Option<&str>,
    status: Option<&str>,
) -> CallToolResult {
    let guides = state.db.list_guides(category, status).unwrap_or_default();

    let result = serde_json::json!({
        "count": guides.len(),
        "guides": guides.iter().map(|g| guide_to_json(g, false)).collect::<Vec<_>>(),
    });

    state.log_audit("list_guides", None, None);
    ok_json(build_response(result))
}

pub fn vault_search_guides(state: &VaultState, query: &str) -> CallToolResult {
    let guides = state.db.search_guides(query).unwrap_or_default();

    let result = serde_json::json!({
        "query": query,
        "count": guides.len(),
        "guides": guides.iter().map(|g| guide_to_json(g, false)).collect::<Vec<_>>(),
    });

    state.log_audit("search_guides", None, None);
    ok_json(build_response(result))
}

pub fn vault_delete_guide(state: &VaultState, name: &str) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_delete_guide") {
        return ok_json(serde_json::json!({"error": msg}));
    }

    match state.db.delete_guide(name) {
        Ok(true) => {
            state.log_audit("delete_guide", Some(&format!("guide:{name}")), None);
            ok_json(serde_json::json!({
                "name": name,
                "deleted": true,
                "message": format!("Guide '{name}' deleted"),
            }))
        }
        Ok(false) => ok_json(serde_json::json!({"error": format!("Guide not found: {name}")})),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_verify_guide(state: &VaultState, name: &str) -> CallToolResult {
    match state.db.verify_guide(name) {
        Ok(Some(guide)) => {
            state.log_audit("verify_guide", Some(&format!("guide:{name}")), None);
            ok_json(serde_json::json!({
                "name": guide.name,
                "status": guide.status,
                "verified_at": guide.verified_at,
                "message": format!("Guide '{name}' verified at {}", guide.verified_at.unwrap_or_default()),
            }))
        }
        Ok(None) => ok_json(serde_json::json!({"error": format!("Guide not found: {name}")})),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_deprecate_guide(state: &VaultState, name: &str) -> CallToolResult {
    if let Err(msg) = state.require_operator("vault_deprecate_guide") {
        return ok_json(serde_json::json!({"error": msg}));
    }

    match state.db.deprecate_guide(name) {
        Ok(Some(guide)) => {
            state.log_audit("deprecate_guide", Some(&format!("guide:{name}")), None);
            ok_json(serde_json::json!({
                "name": guide.name,
                "status": guide.status,
                "updated_at": guide.updated_at,
                "message": format!("Guide '{name}' marked as deprecated"),
            }))
        }
        Ok(None) => ok_json(serde_json::json!({"error": format!("Guide not found: {name}")})),
        Err(e) => ok_json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn vault_stale_guides(state: &VaultState, threshold_days: i32) -> CallToolResult {
    let guides = state
        .db
        .list_stale_guides(threshold_days)
        .unwrap_or_default();

    let result = serde_json::json!({
        "threshold_days": threshold_days,
        "stale_count": guides.len(),
        "guides": guides.iter().map(|g| {
            serde_json::json!({
                "name": g.name,
                "category": g.category,
                "verified_at": g.verified_at,
                "updated_at": g.updated_at,
            })
        }).collect::<Vec<_>>(),
    });

    state.log_audit("stale_guides", None, None);
    ok_json(build_response(result))
}

fn ok_json(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(format_response(&value))])
}
