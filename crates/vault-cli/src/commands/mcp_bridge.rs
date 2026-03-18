//! Helpers for invoking MCP tool implementations from CLI commands.

use std::sync::atomic::{AtomicBool, AtomicI64};

use anyhow::Context;
use rmcp::model::CallToolResult;
use vault_core::security::AuditLogger;
use vault_mcp::server::VaultState;

use super::init::open_db;

pub fn build_state() -> anyhow::Result<VaultState> {
    let db = open_db()?;
    let audit = AuditLogger::open(vault_core::config::audit_db_path())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(VaultState {
        db,
        audit,
        locked: AtomicBool::new(false),
        session_required: false,
        session_token: None,
        session_authenticated: AtomicBool::new(true),
        operator_until_epoch: AtomicI64::new(0),
    })
}

pub fn result_json(result: CallToolResult) -> anyhow::Result<serde_json::Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.clone())
        .context("tool response missing text content")?;
    serde_json::from_str::<serde_json::Value>(&text)
        .or_else(|_| Ok(serde_json::json!({ "text": text })))
}

pub fn ensure_no_error(value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
        anyhow::bail!("{err}");
    }
    Ok(value)
}

pub fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
