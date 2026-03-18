//! CLI conflict command family.

use super::mcp_bridge::{build_state, ensure_no_error, print_json, result_json};

pub fn conflicts(
    include_resolved: bool,
    path: Option<&str>,
    stats_only: bool,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::conflicts::vault_conflicts(
        &state,
        include_resolved,
        path,
        stats_only,
    ))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    if stats_only {
        println!(
            "pending={} total={} kept_local={} kept_remote={} merged={}",
            value["pending"].as_i64().unwrap_or(0),
            value["total"].as_i64().unwrap_or(0),
            value["kept_local"].as_i64().unwrap_or(0),
            value["kept_remote"].as_i64().unwrap_or(0),
            value["merged"].as_i64().unwrap_or(0)
        );
        return Ok(());
    }
    let list = value["conflicts"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("No conflicts.");
        return Ok(());
    }
    for c in list {
        println!(
            "{} {}",
            c["id"].as_str().unwrap_or("-"),
            c["path"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}

pub fn resolve(
    conflict_id: &str,
    resolution: &str,
    value: Option<&str>,
    notes: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::conflicts::vault_resolve_conflict(
        &state,
        conflict_id,
        resolution,
        value,
        notes,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "{}",
        out["message"]
            .as_str()
            .unwrap_or("Conflict resolution applied.")
    );
    Ok(())
}

pub fn conflict_mode(path: &str, mode: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::conflicts::vault_conflict_mode(
        &state, path, mode,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "{}",
        out["message"].as_str().unwrap_or("Conflict mode updated.")
    );
    Ok(())
}
