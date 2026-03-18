//! CLI monitoring and discovery commands.

use super::mcp_bridge::{build_state, ensure_no_error, print_json, result_json};

pub fn discover(prefix: Option<&str>, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_discover(
        &state, prefix,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "credentials={} guides={}",
        out["total_credentials"].as_i64().unwrap_or(0),
        out["total_guides"].as_i64().unwrap_or(0)
    );
    Ok(())
}

pub fn recent(limit: i32, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_recent(&state, limit))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for entry in out["entries"].as_array().cloned().unwrap_or_default() {
        println!("{}", entry["path"].as_str().unwrap_or("-"));
    }
    Ok(())
}

pub fn session_start(since: Option<&str>, rotation_days: i32, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_session_start(
        &state,
        since,
        rotation_days,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "conflicts={} rotation_alerts={}",
        out["unresolved_conflicts"].as_i64().unwrap_or(0),
        out["rotation_alerts"].as_i64().unwrap_or(0)
    );
    Ok(())
}

pub fn audit(
    path: Option<&str>,
    action: Option<&str>,
    limit: i32,
    brief: bool,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::security::vault_audit(
        &state, path, action, limit, brief,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for entry in out["entries"].as_array().cloned().unwrap_or_default() {
        let ts = entry["timestamp"].as_str().unwrap_or("-");
        let act = entry["action"].as_str().unwrap_or("-");
        let p = entry["path"].as_str().unwrap_or("-");
        println!("{ts} {act} {p}");
    }
    Ok(())
}

pub fn changes(
    since: Option<&str>,
    path: Option<&str>,
    prefix: Option<&str>,
    action: Option<&str>,
    limit: i32,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::monitoring::vault_changes(
        &state, since, path, prefix, action, limit,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for change in out["changes"].as_array().cloned().unwrap_or_default() {
        println!(
            "{} {} {}",
            change["path"].as_str().unwrap_or("-"),
            change["action"].as_str().unwrap_or("-"),
            change["updated_at"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}

pub fn impact(app: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::monitoring::vault_impact(&state, app))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for cred in out["credentials"].as_array().cloned().unwrap_or_default() {
        println!("{}", cred["path"].as_str().unwrap_or("-"));
    }
    Ok(())
}

pub fn lint(
    prefix: Option<&str>,
    similarity_threshold: f64,
    max_similar_pairs: usize,
    include_suggestions: bool,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::monitoring::vault_lint(
        &state,
        prefix,
        similarity_threshold,
        max_similar_pairs,
        include_suggestions,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "total_paths={} duplicate_groups={} similar_pairs={}",
        out["total_paths"].as_i64().unwrap_or(0),
        out["duplicate_groups"].as_i64().unwrap_or(0),
        out["similar_pairs"].as_i64().unwrap_or(0),
    );
    Ok(())
}

pub fn rotation_alerts(window_days: i32, include_overdue: bool, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::monitoring::vault_rotation_alerts(
        &state,
        window_days,
        include_overdue,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for alert in out["alerts"].as_array().cloned().unwrap_or_default() {
        println!(
            "{} due={} days={}",
            alert["path"].as_str().unwrap_or("-"),
            alert["due_at"].as_str().unwrap_or("-"),
            alert["days_until_due"].as_i64().unwrap_or(0),
        );
    }
    Ok(())
}
