//! Security tools (5 tools).
//!
//! inject, show_gui, audit, use, expand

use std::process::Command;
use std::time::Duration;

use rmcp::model::{CallToolResult, Content};

use crate::clipboard;
use crate::response::{build_response, format_response};
use crate::server::VaultState;

/// Environment variable names that must never be injected.
/// These can be used for shared library injection, command hijacking,
/// or process-level code execution.
const DANGEROUS_ENV_VARS: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "PERL5LIB",
    "RUBYLIB",
    "CLASSPATH",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "PROMPT_COMMAND",
    "SHELL",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TEMP",
    "TMP",
];

/// Check if an env var name is dangerous to inject.
fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    // Exact match against blocklist
    if DANGEROUS_ENV_VARS.iter().any(|&d| d == upper) {
        return true;
    }
    // Block any LD_* or DYLD_* prefix (covers future variants)
    if upper.starts_with("LD_") || upper.starts_with("DYLD_") {
        return true;
    }
    false
}

pub fn vault_inject(
    state: &VaultState,
    path: &str,
    env_var: &str,
    overwrite: bool,
) -> CallToolResult {
    // Validate env var name against blocklist
    if is_dangerous_env_var(env_var) {
        return ok_json(serde_json::json!({
            "error": format!(
                "Refused to inject '{env_var}': this environment variable can be used for code injection. \
                 Only application-specific env vars (e.g., OPENAI_API_KEY, DATABASE_URL) are allowed."
            )
        }));
    }

    // Validate env var name format (alphanumeric + underscore only)
    if !env_var
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || env_var.is_empty()
    {
        return ok_json(serde_json::json!({
            "error": format!("Invalid env var name '{env_var}': must be non-empty and contain only A-Z, a-z, 0-9, _")
        }));
    }

    // Check if env var already exists
    if !overwrite && std::env::var(env_var).is_ok() {
        return ok_json(serde_json::json!({
            "error": format!("Environment variable '{env_var}' already set. Use overwrite=true to replace.")
        }));
    }

    let entry = state.credentials().recall(path).unwrap_or(None);
    let entry = match entry {
        Some(e) => e,
        None => return ok_json(serde_json::json!({"error": format!("Not found: {path}")})),
    };

    // Set the environment variable
    unsafe {
        std::env::set_var(env_var, &entry.value);
    }

    state.log_audit("inject", Some(path), Some(&format!("env_var={env_var}")));

    // NO value in response
    ok_json(serde_json::json!({
        "status": "injected",
        "path": path,
        "env_var": env_var,
    }))
}

pub fn vault_show_gui(
    state: &VaultState,
    path: &str,
    copy_to_clipboard: bool,
    auto_clear_seconds: u64,
) -> CallToolResult {
    let entry = state.credentials().recall(path).unwrap_or(None);
    let entry = match entry {
        Some(e) => e,
        None => return ok_json(serde_json::json!({"error": format!("Not found: {path}")})),
    };

    if copy_to_clipboard {
        let _ = clipboard::copy_and_clear(&entry.value, auto_clear_seconds);
    }

    state.log_audit("show_gui", Some(path), None);

    // NO value in response
    ok_json(serde_json::json!({
        "status": "displayed",
        "path": path,
        "_clipboard": if copy_to_clipboard {
            format!("Value copied to clipboard (auto-clears in {auto_clear_seconds}s)")
        } else {
            "Not copied".into()
        },
    }))
}

pub fn vault_audit(
    state: &VaultState,
    path: Option<&str>,
    action: Option<&str>,
    limit: i32,
    brief: bool,
) -> CallToolResult {
    let logs = state.audit.list(path, action, limit).unwrap_or_default();

    let entries: Vec<serde_json::Value> = if brief {
        logs.iter()
            .map(|log| {
                serde_json::json!({
                    "path": log.path,
                    "action": log.action,
                    "timestamp": log.timestamp,
                })
            })
            .collect()
    } else {
        logs.iter()
            .map(|log| {
                serde_json::json!({
                    "id": log.id,
                    "path": log.path,
                    "action": log.action,
                    "timestamp": log.timestamp,
                    "details": log.details,
                    "tool_name": log.tool_name,
                    "success": log.success,
                })
            })
            .collect()
    };

    let result = serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    });

    ok_json(build_response(result))
}

pub fn vault_use(
    state: &VaultState,
    path: &str,
    env_var: &str,
    command: &[&str],
    timeout_seconds: Option<u64>,
) -> CallToolResult {
    // Require operator mode
    if let Err(e) = state.require_operator("vault_use") {
        return ok_json(serde_json::json!({"error": e}));
    }

    // Validate env var against dangerous list
    if is_dangerous_env_var(env_var) {
        return ok_json(serde_json::json!({
            "error": format!(
                "Refused to inject '{env_var}': this environment variable can be used for code injection. \
                 Only application-specific env vars (e.g., OPENAI_API_KEY, DATABASE_URL) are allowed."
            )
        }));
    }

    // Validate env var format
    if !env_var
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || env_var.is_empty()
    {
        return ok_json(serde_json::json!({
            "error": format!("Invalid env var name '{env_var}': must be non-empty and contain only A-Z, a-z, 0-9, _")
        }));
    }

    // Validate command is not empty
    if command.is_empty() {
        return ok_json(serde_json::json!({
            "error": "Command must not be empty."
        }));
    }

    // Get the credential
    let entry = state.credentials().recall(path).unwrap_or(None);
    let entry = match entry {
        Some(e) => e,
        None => return ok_json(serde_json::json!({"error": format!("Not found: {path}")})),
    };

    // Clamp timeout: default 30s, max 300s
    let timeout = Duration::from_secs(timeout_seconds.unwrap_or(30).min(300));

    // Execute the command with the secret injected as an env var
    let child = Command::new(command[0])
        .args(&command[1..])
        .env(env_var, &entry.value)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let child = match child {
        Ok(c) => c,
        Err(e) => {
            state.log_audit("vault_use", Some(path), Some(&format!("spawn_error: {e}")));
            return ok_json(serde_json::json!({
                "error": format!("Failed to spawn command '{}': {e}", command[0])
            }));
        }
    };

    // Drain stdout/stderr in background threads to prevent pipe buffer deadlock.
    // OS pipe buffers are small (16–64 KB). If the child fills them without a reader,
    // it blocks on write and never exits — causing a spurious timeout kill.
    // We take the pipe handles before polling so readers run concurrently.
    // Reads are capped at 1 MB to prevent OOM from a malicious/runaway child.
    const MAX_OUTPUT_BYTES: usize = 1_024 * 1_024;
    let timeout_secs = timeout.as_secs();
    let mut child = child;

    let stdout_handle = child.stdout.take().map(|out| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = vec![0u8; MAX_OUTPUT_BYTES];
            let mut out = out;
            let mut total = 0;
            loop {
                match out.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if total >= MAX_OUTPUT_BYTES {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            buf.truncate(total);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    let stderr_handle = child.stderr.take().map(|err| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = vec![0u8; MAX_OUTPUT_BYTES];
            let mut err = err;
            let mut total = 0;
            loop {
                match err.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if total >= MAX_OUTPUT_BYTES {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            buf.truncate(total);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited — join reader threads
                let stdout_buf = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                let stderr_buf = stderr_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                let exit_code = status.code().unwrap_or(-1);

                state.log_audit(
                    "vault_use",
                    Some(path),
                    Some(&format!("env_var={env_var}, exit_code={exit_code}")),
                );

                return ok_json(serde_json::json!({
                    "exit_code": exit_code,
                    "stdout": stdout_buf,
                    "stderr": stderr_buf,
                }));
            }
            Ok(None) => {
                // Still running — check timeout
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait(); // Reap zombie
                    state.log_audit(
                        "vault_use",
                        Some(path),
                        Some(&format!("timeout after {timeout_secs}s — process killed")),
                    );
                    return ok_json(serde_json::json!({
                        "error": format!("Command timed out after {timeout_secs}s — process was killed")
                    }));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                state.log_audit("vault_use", Some(path), Some(&format!("wait_error: {e}")));
                return ok_json(serde_json::json!({
                    "error": format!("Failed to wait for command: {e}")
                }));
            }
        }
    }
}

pub fn vault_expand(state: &VaultState, template: &str) -> CallToolResult {
    // Require operator mode
    if let Err(e) = state.require_operator("vault_expand") {
        return ok_json(serde_json::json!({"error": e}));
    }

    // Guard: reject templates larger than 1 MB
    if template.len() > 1_048_576 {
        return ok_json(serde_json::json!({"error": "Template exceeds 1 MB size limit."}));
    }

    // Guard: reject templates with more than 100 placeholders
    let placeholder_count = template.matches("<vault:").count();
    if placeholder_count > 100 {
        return ok_json(serde_json::json!({
            "error": format!("Template contains {} placeholders (limit: 100).", placeholder_count)
        }));
    }

    let mut expanded = template.to_string();
    let mut replacements: usize = 0;
    let mut missing: Vec<String> = Vec::new();

    // Find all <vault:path> patterns
    // We process from the end so that replacements don't shift indices
    let mut matches: Vec<(usize, usize, String)> = Vec::new();
    let mut search_from = 0;
    while let Some(start) = expanded[search_from..].find("<vault:") {
        let abs_start = search_from + start;
        if let Some(end_offset) = expanded[abs_start..].find('>') {
            let abs_end = abs_start + end_offset + 1; // include the '>'
            let path = &expanded[abs_start + 7..abs_end - 1]; // skip "<vault:" and ">"
            matches.push((abs_start, abs_end, path.to_string()));
            search_from = abs_end;
        } else {
            // No closing '>', stop searching
            break;
        }
    }

    // Process matches in reverse order to preserve indices
    for (start, end, path) in matches.iter().rev() {
        let entry = state.credentials().recall(path).unwrap_or(None);
        match entry {
            Some(e) => {
                expanded.replace_range(start..end, &e.value);
                replacements += 1;
                state.log_audit("vault_expand", Some(path), None);
            }
            None => {
                missing.push(path.clone());
                // Leave placeholder as-is for missing paths
            }
        }
    }

    ok_json(serde_json::json!({
        "expanded": expanded,
        "replacements": replacements,
        "missing": missing,
    }))
}

fn ok_json(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(format_response(&value))])
}
