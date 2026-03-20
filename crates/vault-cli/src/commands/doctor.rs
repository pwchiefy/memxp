//! `memxp doctor` — plain-language health check for non-technical users.

use std::path::Path;
use std::process::Command;

use std::path::PathBuf;

use vault_core::config;

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Run all health checks and print a human-friendly report.
pub fn doctor() -> anyhow::Result<()> {
    let mut issues: Vec<String> = Vec::new();
    let mut ok_items: Vec<String> = Vec::new();

    // ── 1. Database ──────────────────────────────────────────
    let db_path = config::db_path();
    if db_path.exists() {
        let size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
        let size_str = if size > 1_048_576 {
            format!("{:.1} MB", size as f64 / 1_048_576.0)
        } else {
            format!("{:.0} KB", size as f64 / 1024.0)
        };

        // Try to open the database
        match try_open_db() {
            Ok((creds, guides)) => {
                ok_items.push(format!(
                    "Vault: {} items, {} guides ({})",
                    creds, guides, size_str
                ));
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not a database") || msg.contains("decrypt") {
                    issues.push(
                        "Vault exists but can't be opened (wrong passphrase?)\n\
                         Fix: check that ~/.memxp/env contains the correct VAULT_PASSPHRASE"
                            .to_string(),
                    );
                } else {
                    issues.push(format!("Vault error: {msg}"));
                }
            }
        }
    } else {
        issues.push(
            "Vault database not found\n\
             Fix: run \"memxp init\" to create it"
                .to_string(),
        );
    }

    // ── 2. Passphrase ────────────────────────────────────────
    let env_file = config::vault_base_dir().join("env");
    if env_file.exists() {
        let env_content = std::fs::read_to_string(&env_file).unwrap_or_default();
        if env_content.contains("VAULT_PASSPHRASE") {
            ok_items.push("Passphrase: configured".to_string());
        } else {
            issues.push(
                "Passphrase file exists but VAULT_PASSPHRASE not set\n\
                 Fix: add VAULT_PASSPHRASE=\"your-passphrase\" to ~/.memxp/env"
                    .to_string(),
            );
        }
    } else {
        // Check environment variable
        if std::env::var("VAULT_PASSPHRASE").is_ok() {
            ok_items.push("Passphrase: set via environment variable".to_string());
        } else {
            // Check keychain
            match vault_core::auth::resolve_passphrase_keychain_first() {
                Ok(Some(_)) => {
                    ok_items.push("Passphrase: stored in OS keychain".to_string());
                }
                _ => {
                    issues.push(
                        "No passphrase found (env file, environment variable, or keychain)\n\
                         Fix: create ~/.memxp/env with VAULT_PASSPHRASE=\"your-passphrase\""
                            .to_string(),
                    );
                }
            }
        }
    }

    // ── 3. cr-sqlite extension ───────────────────────────────
    let ext_path = config::cr_sqlite_extension_path();
    if ext_path.exists() {
        ok_items.push("Encryption extension: installed".to_string());
    } else {
        issues.push(format!(
            "cr-sqlite extension missing at {}\n\
             Fix: reinstall memxp or copy crsqlite.dylib to ~/.memxp/",
            ext_path.display()
        ));
    }

    // ── 4. Claude Code ───────────────────────────────────────
    let claude_bin = find_claude_binary();
    match claude_bin {
        Some(path) => {
            ok_items.push(format!("Claude Code: installed ({})", path));

            // Check MCP registration
            let mcp_registered = check_mcp_registration();
            if mcp_registered {
                ok_items.push("MCP server: registered with Claude Code".to_string());
            } else {
                issues.push(
                    "memxp not registered as Claude Code MCP server\n\
                     Fix: run \"claude mcp add memxp -s user -- memxp mcp\""
                        .to_string(),
                );
            }

            // Check permissions
            let permissions_ok = check_permissions_configured();
            if permissions_ok {
                ok_items.push("Permissions: memxp tools pre-approved".to_string());
            } else {
                issues.push(
                    "memxp tools not pre-approved (Claude will ask permission for each action)\n\
                     Fix: add \"mcp__memxp\" to permissions.allow in ~/.claude/settings.json"
                        .to_string(),
                );
            }
        }
        None => {
            issues.push(
                "Claude Code not found\n\
                 Fix: npm install -g @anthropic-ai/claude-code"
                    .to_string(),
            );
        }
    }

    // ── 5. Daemon (optional — only check if config has sync enabled) ──
    let cfg = config::VaultConfig::load(&config::config_path());
    if cfg.sync.enabled {
        let daemon_running = check_daemon_running();
        if daemon_running {
            ok_items.push("Sync daemon: running".to_string());
        } else {
            issues.push(
                "Sync is enabled but daemon is not running\n\
                 Fix: run \"memxp daemon start\" or restart your computer"
                    .to_string(),
            );
        }
    }

    // ── 6. PATH ──────────────────────────────────────────────
    if let Ok(path) = std::env::var("PATH") {
        let install_dir = std::env::var("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".local/bin"))
            .unwrap_or_default();
        if path
            .split(':')
            .any(|p| Path::new(p) == install_dir.as_path())
        {
            ok_items.push("PATH: ~/.local/bin is in your PATH".to_string());
        } else {
            issues.push(
                "~/.local/bin is not in your PATH\n\
                 Fix: add 'export PATH=\"$HOME/.local/bin:$PATH\"' to ~/.zprofile"
                    .to_string(),
            );
        }
    }

    // ── Report ───────────────────────────────────────────────
    println!();
    if issues.is_empty() {
        println!("  memxp is healthy!\n");
        for item in &ok_items {
            println!("    + {item}");
        }
        println!("\n  Everything is working.");
    } else {
        println!(
            "  memxp found {} issue{}:\n",
            issues.len(),
            if issues.len() == 1 { "" } else { "s" }
        );
        for issue in &issues {
            let lines: Vec<&str> = issue.lines().collect();
            if let Some(first) = lines.first() {
                println!("    x {first}");
            }
            for line in lines.iter().skip(1) {
                println!("      {line}");
            }
            println!();
        }

        if !ok_items.is_empty() {
            println!("  What's working:");
            for item in &ok_items {
                println!("    + {item}");
            }
        }
    }
    println!();

    Ok(())
}

/// Try to open the database and count entries/guides.
fn try_open_db() -> anyhow::Result<(usize, usize)> {
    use super::init::open_db;
    use vault_core::credential_store::CredentialStore;

    let db = open_db()?;
    let store = CredentialStore::new(&db);

    let entries = store.list(None, None, None).unwrap_or_default();
    let guides = db.list_guides(None, None).unwrap_or_default();
    Ok((entries.len(), guides.len()))
}

/// Find the Claude Code binary.
fn find_claude_binary() -> Option<String> {
    let candidates = ["/opt/homebrew/bin/claude", "/usr/local/bin/claude"];

    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    // Check PATH
    Command::new("which")
        .arg("claude")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Check if memxp is registered as an MCP server in Claude Code.
fn check_mcp_registration() -> bool {
    // Check ~/.claude/settings.json and ~/.claude/settings.local.json for mcpServers.memxp
    let settings_paths = [
        home_dir().map(|h| h.join(".claude/settings.json")),
        home_dir().map(|h| h.join(".claude/settings.local.json")),
    ];

    for path in settings_paths.iter().flatten() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("\"memxp\"") && content.contains("mcp") {
                return true;
            }
        }
    }

    // Also check via `claude mcp list` output
    Command::new("claude")
        .args(["mcp", "list"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("memxp"))
        .unwrap_or(false)
}

/// Check if memxp tools are pre-approved in Claude Code settings.
fn check_permissions_configured() -> bool {
    let settings_path = home_dir().map(|h| h.join(".claude/settings.json"));
    if let Some(path) = settings_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            return content.contains("mcp__memxp");
        }
    }
    false
}

/// Check if the sync daemon process is running.
fn check_daemon_running() -> bool {
    Command::new("pgrep")
        .args(["-f", "memxp daemon"])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
