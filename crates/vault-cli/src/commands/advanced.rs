//! Advanced credential command family.

use std::io::Read;

use super::init::open_db;
use super::mcp_bridge::{build_state, ensure_no_error, print_json, result_json};

pub fn has(path: &str, json: bool) -> anyhow::Result<bool> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_has(&state, path))?;
    let out = ensure_no_error(out)?;
    let exists = out["exists"].as_bool().unwrap_or(false);
    if json {
        print_json(&out)?;
    } else {
        println!(
            "{}",
            if exists {
                format!("Found: {path}")
            } else {
                format!("Missing: {path}")
            }
        );
    }
    Ok(exists)
}

pub fn smart_get(
    query: &str,
    include_value: bool,
    max_candidates: i32,
    min_confidence: f64,
    copy_to_clipboard: bool,
    redact: bool,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_smart_get(
        &state,
        query,
        include_value,
        max_candidates,
        min_confidence,
        copy_to_clipboard,
        redact,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for m in out["matches"].as_array().cloned().unwrap_or_default() {
        let path = m["path"].as_str().unwrap_or("-");
        if let Some(v) = m.get("value").and_then(|v| v.as_str()) {
            println!("{path}={v}");
        } else if let Some(v) = m.get("value_preview").and_then(|v| v.as_str()) {
            println!("{path}={v}");
        } else {
            println!("{path}");
        }
    }
    Ok(())
}

pub fn bundle(
    prefix: &str,
    include_values: bool,
    show_metadata: bool,
    json: bool,
) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::credentials::vault_get_bundle(
        &state,
        prefix,
        include_values,
        show_metadata,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    for e in out["entries"].as_array().cloned().unwrap_or_default() {
        println!("{}", e["path"].as_str().unwrap_or("-"));
    }
    Ok(())
}

pub fn set_batch(file: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let raw = std::fs::read_to_string(file)?;
    let json_value: serde_json::Value = serde_json::from_str(&raw)?;
    let entries = json_value
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .or_else(|| json_value.as_array().cloned())
        .ok_or_else(|| anyhow::anyhow!("Expected JSON array or object with `entries` array"))?;
    let out = result_json(vault_mcp::tools::credentials::vault_set_batch(
        &state, &entries,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "saved={} errors={}",
        out["saved"].as_i64().unwrap_or(0),
        out["errors"].as_i64().unwrap_or(0)
    );
    Ok(())
}

pub fn inject(path: &str, env_var: &str, overwrite: bool, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let out = result_json(vault_mcp::tools::security::vault_inject(
        &state, path, env_var, overwrite,
    ))?;
    let out = ensure_no_error(out)?;
    if json {
        return print_json(&out);
    }
    println!(
        "{}",
        out["status"]
            .as_str()
            .unwrap_or("Credential injected into environment.")
    );
    Ok(())
}

pub fn use_secret(
    path: &str,
    env_var: &str,
    command: &[String],
    experimental: bool,
    json: bool,
) -> anyhow::Result<()> {
    if !experimental {
        anyhow::bail!("`memxp use` is experimental. Re-run with --experimental.");
    }
    if command.is_empty() {
        anyhow::bail!("Missing command to execute after `--`.");
    }
    if !vault_core::operator_session::is_operator_session_active() {
        anyhow::bail!("`memxp use` requires operator mode. Run `memxp operator enable` first.");
    }

    let db = open_db()?;
    let store = vault_core::credential_store::CredentialStore::new(&db);
    let entry = store
        .recall(path)?
        .ok_or_else(|| anyhow::anyhow!("Not found: {path}"))?;

    let output = std::process::Command::new(&command[0])
        .args(&command[1..])
        .env(env_var, &entry.value)
        .output()?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": path,
                "env_var": env_var,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            }))?
        );
    } else {
        if !stdout.is_empty() {
            print!("{stdout}");
        }
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
        println!("\n[exit_code={exit_code}]");
    }
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!("Command failed with exit code {exit_code}");
    }
}

fn expand_placeholders(
    input: &str,
    store: &vault_core::credential_store::CredentialStore<'_>,
) -> anyhow::Result<(String, usize)> {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut replaced = 0usize;

    while let Some(rel_start) = input[cursor..].find("<vault:") {
        let start = cursor + rel_start;
        output.push_str(&input[cursor..start]);
        let after_prefix = start + "<vault:".len();
        let Some(rel_end) = input[after_prefix..].find('>') else {
            output.push_str(&input[start..]);
            cursor = input.len();
            break;
        };
        let end = after_prefix + rel_end;
        let path = &input[after_prefix..end];
        let entry = store
            .recall(path)?
            .ok_or_else(|| anyhow::anyhow!("Missing placeholder secret: {path}"))?;
        output.push_str(&entry.value);
        replaced += 1;
        cursor = end + 1;
    }
    if cursor < input.len() {
        output.push_str(&input[cursor..]);
    }
    Ok((output, replaced))
}

pub fn expand(file: Option<&str>, stdin_mode: bool, json: bool) -> anyhow::Result<()> {
    if !vault_core::operator_session::is_operator_session_active() {
        anyhow::bail!("`memxp expand` requires operator mode. Run `memxp operator enable` first.");
    }
    let db = open_db()?;
    let store = vault_core::credential_store::CredentialStore::new(&db);
    let input = if stdin_mode || file.is_none() {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(file.unwrap_or_default())?
    };

    let (expanded, replaced) = expand_placeholders(&input, &store)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "replaced": replaced,
                "output": expanded,
            }))?
        );
    } else {
        print!("{expanded}");
    }
    Ok(())
}
