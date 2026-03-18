//! memxp CLI — main binary.
//!
//! Provides credential management, sync, MCP server, and web GUI
//! all from a single `memxp` binary.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "memxp", about = "memxp — a second brain for your coding agent")]
#[command(version, propagate_version = true)]
struct Cli {
    /// Suppress non-essential output where supported.
    #[arg(long, global = true)]
    quiet: bool,
    /// Disable ANSI color output.
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the vault (create dirs, DB, config)
    Init {
        /// Force reinitialize (preserves existing data)
        #[arg(long)]
        force: bool,
        /// Print generated passphrase (non-repeatable bootstrap use only)
        #[arg(long)]
        print_passphrase: bool,
    },

    /// Get a credential by path
    Get {
        /// Credential path (e.g. api/openai/key)
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Print only the value (no metadata)
        #[arg(long)]
        value_only: bool,
        /// Explicitly redact response and copy to clipboard
        #[arg(long)]
        redact: bool,
        /// Copy value to clipboard (no plaintext needed in terminal)
        #[arg(long)]
        clipboard: bool,
    },

    /// Set a credential
    Set {
        /// Credential path (e.g. api/openai/key)
        path: String,
        /// Secret value
        value: String,
        /// Category (api_key, password, token, certificate, ssh_key, env_var)
        #[arg(long)]
        category: Option<String>,
        /// Service name (e.g. openai, aws, postgres)
        #[arg(long)]
        service: Option<String>,
        /// Description or usage notes
        #[arg(long)]
        notes: Option<String>,
        /// Tags (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Environment (dev, staging, production)
        #[arg(long)]
        env: Option<String>,
        /// Storage mode (vault, keychain, both)
        #[arg(long)]
        storage_mode: Option<String>,
        /// Rotation interval in days
        #[arg(long)]
        rotation_days: Option<i32>,
    },

    /// Delete a credential
    Delete {
        /// Credential path
        path: String,
    },

    /// List credentials
    List {
        /// Filter by service
        #[arg(long)]
        service: Option<String>,
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
        /// Filter by path prefix
        #[arg(long)]
        prefix: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search credentials by keyword
    Search {
        /// Search query
        query: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Check whether a credential exists by path
    Has {
        /// Credential path
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage guides
    Guide {
        #[command(subcommand)]
        action: Option<GuideAction>,
        /// Shorthand for `guide get <name>`
        name: Option<String>,
        /// Output as JSON (applies to shorthand form)
        #[arg(long)]
        json: bool,
    },

    /// Discover vault categories/services overview
    Discover {
        /// Optional path prefix filter
        #[arg(long)]
        prefix: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show recently updated entries
    Recent {
        /// Maximum entries to return
        #[arg(long, default_value = "10")]
        limit: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Morning briefing for agent context
    SessionStart {
        /// Optional since timestamp
        #[arg(long)]
        since: Option<String>,
        /// Rotation alert window in days
        #[arg(long, default_value = "7")]
        rotation_window_days: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Audit log query
    Audit {
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long, default_value = "50")]
        limit: i32,
        #[arg(long)]
        brief: bool,
        #[arg(long)]
        json: bool,
    },

    /// Change history query
    Changes {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long, default_value = "50")]
        limit: i32,
        #[arg(long)]
        json: bool,
    },

    /// Impact analysis for an app
    Impact {
        app: String,
        #[arg(long)]
        json: bool,
    },

    /// Path lint analysis
    Lint {
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, default_value = "0.7")]
        similarity_threshold: f64,
        #[arg(long, default_value = "20")]
        max_similar_pairs: usize,
        #[arg(long, default_value_t = true)]
        include_suggestions: bool,
        #[arg(long)]
        json: bool,
    },

    /// Rotation and expiry alerts
    RotationAlerts {
        #[arg(long, default_value = "30")]
        days: i32,
        #[arg(long, default_value_t = true)]
        include_overdue: bool,
        #[arg(long)]
        json: bool,
    },

    /// List conflicts or stats
    Conflicts {
        #[arg(long)]
        include_resolved: bool,
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        stats: bool,
        #[arg(long)]
        json: bool,
    },

    /// Resolve a conflict
    Resolve {
        conflict_id: String,
        resolution: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Set conflict mode for a path
    ConflictMode {
        path: String,
        mode: String,
        #[arg(long)]
        json: bool,
    },

    /// Smart lookup for credentials
    SmartGet {
        query: String,
        #[arg(long)]
        include_value: bool,
        #[arg(long, default_value = "3")]
        max_candidates: i32,
        #[arg(long, default_value = "10")]
        min_confidence: f64,
        #[arg(long)]
        clipboard: bool,
        #[arg(long)]
        redact: bool,
        #[arg(long)]
        json: bool,
    },

    /// Get a prefix bundle of credentials
    Bundle {
        prefix: String,
        #[arg(long)]
        include_values: bool,
        #[arg(long)]
        show_metadata: bool,
        #[arg(long)]
        json: bool,
    },

    /// Batch set credentials from JSON file
    SetBatch {
        #[arg(long)]
        file: String,
        #[arg(long)]
        json: bool,
    },

    /// Inject credential into environment variable
    Inject {
        path: String,
        env_var: String,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        json: bool,
    },

    /// Experimental: run a command with a secret injected as env var
    Use {
        path: String,
        env_var: String,
        /// Required for this experimental command
        #[arg(long)]
        experimental: bool,
        /// Command to execute (everything after `--`)
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
        #[arg(long)]
        json: bool,
    },

    /// Expand <vault:path> placeholders from file/stdin
    Expand {
        /// Input file (defaults to stdin if omitted)
        file: Option<String>,
        /// Force stdin input mode
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },

    /// Show vault status
    Status,

    /// Health check — diagnose issues with plain-language output
    Doctor,

    /// Export vault to JSON
    Export {
        /// Output file (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Import vault from JSON
    Import {
        /// JSON file to import
        file: String,
    },

    /// Manage sync daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Operator mode control
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },

    /// Confirm out-of-band operator/unlock challenge
    ConfirmOperator {
        challenge: String,
        /// Challenge action type (operator_mode or unlock)
        #[arg(long, default_value = "operator_mode")]
        action: String,
        /// Allow non-interactive confirmation (automation only)
        #[arg(long)]
        allow_non_interactive: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show local auth status
    AuthStatus {
        #[arg(long)]
        json: bool,
    },

    /// Lock local CLI access
    Lock {
        #[arg(long)]
        json: bool,
    },

    /// Unlock local CLI access
    Unlock {
        #[arg(long, env = "VAULT_PASSPHRASE")]
        password: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Manual one-shot sync
    Sync {
        /// Peer address (Tailscale IP)
        peer: Option<String>,
        /// Development-only: allow insecure TLS certificates (self-signed/dev mode)
        #[arg(long)]
        insecure_skip_tls_verify: bool,
        /// Optional peer certificate fingerprint (SHA-256 hex) for explicit trust
        #[arg(long, alias = "trusted-peer-cert-fingerprint")]
        peer_cert_fingerprint: Option<String>,
    },

    /// Launch MCP server on stdio
    Mcp,

    /// Launch web GUI
    Web {
        /// Port to listen on
        #[arg(long, default_value = "8777")]
        port: u16,
    },

    /// Migrate Python vault.db to encrypted Rust DB (entry-by-entry copy)
    Migrate {
        /// Path to old Python vault.db
        old_db: String,
    },

    /// Encrypt an existing unencrypted vault.db in-place (preserves cr-sqlite site_id)
    Encrypt {
        /// Path to unencrypted vault.db (defaults to ~/.memxp/vault.db)
        #[arg(long)]
        source: Option<String>,
        /// Encryption passphrase (or set VAULT_PASSPHRASE env var)
        #[arg(long, env = "VAULT_PASSPHRASE")]
        passphrase: Option<String>,
        /// Print the generated passphrase (non-repeatable bootstrap use only)
        #[arg(long)]
        print_passphrase: bool,
        /// Securely delete the unencrypted backup after successful encryption
        #[arg(long)]
        delete_backup: bool,
    },

    /// Check or apply local memxp updates
    SelfUpdate {
        /// Install a specific version (default: latest tag)
        #[arg(long)]
        version: Option<String>,
        /// Force reinstall even if already current
        #[arg(long)]
        force: bool,
        /// Verify downloaded artifact checksum for the requested version.
        #[arg(long)]
        verify_only: bool,
        /// Check latest release and print update status.
        #[arg(long)]
        check: bool,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the sync daemon
    Start {
        /// Port to listen on
        #[arg(long)]
        port: Option<u16>,
        /// Sync interval in seconds
        #[arg(long)]
        interval: Option<u32>,
        /// Development-only: allow insecure TLS certificates (self-signed/dev mode)
        #[arg(long)]
        insecure_skip_tls_verify: bool,
        /// Optional peer certificate fingerprint (SHA-256 hex) for explicit trust
        #[arg(long)]
        peer_cert_fingerprint: Option<String>,
    },
    /// Stop the sync daemon
    Stop,
    /// Check daemon status
    Status,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Open config in editor
    Edit,
}

#[derive(Subcommand)]
enum GuideAction {
    /// Add or update a guide
    Add {
        name: String,
        /// Content inline (if omitted, reads --file or stdin)
        #[arg(long)]
        content: Option<String>,
        /// File path for markdown content
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, value_delimiter = ',')]
        related_paths: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List guides
    List {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Search guides
    Search {
        query: String,
        #[arg(long)]
        json: bool,
    },
    /// Delete a guide
    Delete {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a guide freshness
    Verify {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Mark guide deprecated
    Deprecate {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// List stale guides
    Stale {
        #[arg(long, default_value = "90")]
        days: i32,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum OperatorAction {
    /// Enable operator mode
    Enable {
        #[arg(long, default_value = "900")]
        ttl: i64,
        #[arg(long)]
        json: bool,
    },
    /// Disable operator mode
    Disable {
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    if cli.no_color {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }
    if cli.quiet {
        unsafe {
            std::env::set_var("VAULT_CLI_QUIET", "1");
        }
    }

    let result = match cli.command {
        Commands::Init {
            force,
            print_passphrase,
        } => commands::init::run(force, print_passphrase),

        Commands::Get {
            path,
            json,
            value_only,
            redact,
            clipboard,
        } => commands::credentials::get(&path, json, value_only, redact, clipboard),

        Commands::Set {
            path,
            value,
            category,
            service,
            notes,
            tags,
            env,
            storage_mode,
            rotation_days,
        } => commands::credentials::set(&commands::credentials::SetOpts {
            path: &path,
            value: &value,
            category: category.as_deref(),
            service: service.as_deref(),
            notes: notes.as_deref(),
            tags: &tags,
            env: env.as_deref(),
            storage_mode: storage_mode.as_deref(),
            rotation_days,
        }),

        Commands::Delete { path } => commands::credentials::delete(&path),

        Commands::List {
            service,
            category,
            prefix,
            json,
        } => commands::credentials::list(
            service.as_deref(),
            category.as_deref(),
            prefix.as_deref(),
            json,
        ),

        Commands::Search { query, json } => commands::credentials::search(&query, json),

        Commands::Has { path, json } => match commands::advanced::has(&path, json) {
            Ok(true) => Ok(()),
            Ok(false) => {
                std::process::exit(1);
            }
            Err(e) => Err(e),
        },

        Commands::Guide { action, name, json } => match action {
            None => {
                if let Some(guide_name) = name {
                    commands::guides::guide_get(&guide_name, json)
                } else {
                    Err(anyhow::anyhow!(
                        "Guide name required. Use `memxp guide <name>` or a guide subcommand."
                    ))
                }
            }
            Some(GuideAction::Add {
                name,
                content,
                file,
                category,
                tags,
                status,
                related_paths,
                json,
            }) => commands::guides::guide_add(commands::guides::GuideAddOpts {
                name: &name,
                content: content.as_deref(),
                file: file.as_deref(),
                category: category.as_deref(),
                tags: &tags,
                status: status.as_deref(),
                related_paths: &related_paths,
                json,
            }),
            Some(GuideAction::List {
                category,
                status,
                json,
            }) => commands::guides::guide_list(category.as_deref(), status.as_deref(), json),
            Some(GuideAction::Search { query, json }) => {
                commands::guides::guide_search(&query, json)
            }
            Some(GuideAction::Delete { name, json }) => commands::guides::guide_delete(&name, json),
            Some(GuideAction::Verify { name, json }) => commands::guides::guide_verify(&name, json),
            Some(GuideAction::Deprecate { name, json }) => {
                commands::guides::guide_deprecate(&name, json)
            }
            Some(GuideAction::Stale { days, json }) => commands::guides::guide_stale(days, json),
        },

        Commands::Discover { prefix, json } => {
            commands::monitoring::discover(prefix.as_deref(), json)
        }

        Commands::Recent { limit, json } => commands::monitoring::recent(limit, json),

        Commands::SessionStart {
            since,
            rotation_window_days,
            json,
        } => commands::monitoring::session_start(since.as_deref(), rotation_window_days, json),

        Commands::Audit {
            path,
            action,
            limit,
            brief,
            json,
        } => commands::monitoring::audit(path.as_deref(), action.as_deref(), limit, brief, json),

        Commands::Changes {
            since,
            path,
            prefix,
            action,
            limit,
            json,
        } => commands::monitoring::changes(
            since.as_deref(),
            path.as_deref(),
            prefix.as_deref(),
            action.as_deref(),
            limit,
            json,
        ),

        Commands::Impact { app, json } => commands::monitoring::impact(&app, json),

        Commands::Lint {
            prefix,
            similarity_threshold,
            max_similar_pairs,
            include_suggestions,
            json,
        } => commands::monitoring::lint(
            prefix.as_deref(),
            similarity_threshold,
            max_similar_pairs,
            include_suggestions,
            json,
        ),

        Commands::RotationAlerts {
            days,
            include_overdue,
            json,
        } => commands::monitoring::rotation_alerts(days, include_overdue, json),

        Commands::Conflicts {
            include_resolved,
            path,
            stats,
            json,
        } => commands::conflicts::conflicts(include_resolved, path.as_deref(), stats, json),

        Commands::Resolve {
            conflict_id,
            resolution,
            value,
            notes,
            json,
        } => commands::conflicts::resolve(
            &conflict_id,
            &resolution,
            value.as_deref(),
            notes.as_deref(),
            json,
        ),

        Commands::ConflictMode { path, mode, json } => {
            commands::conflicts::conflict_mode(&path, &mode, json)
        }

        Commands::SmartGet {
            query,
            include_value,
            max_candidates,
            min_confidence,
            clipboard,
            redact,
            json,
        } => commands::advanced::smart_get(
            &query,
            include_value,
            max_candidates,
            min_confidence,
            clipboard,
            redact,
            json,
        ),

        Commands::Bundle {
            prefix,
            include_values,
            show_metadata,
            json,
        } => commands::advanced::bundle(&prefix, include_values, show_metadata, json),

        Commands::SetBatch { file, json } => commands::advanced::set_batch(&file, json),

        Commands::Inject {
            path,
            env_var,
            overwrite,
            json,
        } => commands::advanced::inject(&path, &env_var, overwrite, json),

        Commands::Use {
            path,
            env_var,
            experimental,
            command,
            json,
        } => commands::advanced::use_secret(&path, &env_var, &command, experimental, json),

        Commands::Expand { file, stdin, json } => {
            commands::advanced::expand(file.as_deref(), stdin, json)
        }

        Commands::Status => commands::credentials::status(),
        Commands::Doctor => commands::doctor::doctor(),

        Commands::Export { output } => commands::export_import::export(output.as_deref()),

        Commands::Import { file } => commands::export_import::import(&file),

        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                port,
                interval,
                insecure_skip_tls_verify,
                peer_cert_fingerprint,
            } => {
                commands::daemon::start(
                    port,
                    interval,
                    insecure_skip_tls_verify,
                    peer_cert_fingerprint,
                )
                .await
            }
            DaemonAction::Stop => commands::daemon::stop(),
            DaemonAction::Status => commands::daemon::daemon_status(),
        },

        Commands::Operator { action } => match action {
            OperatorAction::Enable { ttl, json } => commands::auth::operator_enable(ttl, json),
            OperatorAction::Disable { json } => commands::auth::operator_disable(json),
        },

        Commands::ConfirmOperator {
            challenge,
            action,
            allow_non_interactive,
            json,
        } => commands::confirm::confirm_operator(&challenge, &action, allow_non_interactive, json),

        Commands::AuthStatus { json } => commands::auth::auth_status(json),

        Commands::Lock { json } => commands::auth::lock(json),

        Commands::Unlock { password, json } => commands::auth::unlock(password.as_deref(), json),

        Commands::Sync {
            peer,
            insecure_skip_tls_verify,
            peer_cert_fingerprint,
        } => {
            commands::sync::run(
                peer.as_deref(),
                insecure_skip_tls_verify,
                peer_cert_fingerprint.as_deref(),
            )
            .await
        }

        Commands::Mcp => run_mcp().await,

        Commands::Web { port } => run_web(port).await,

        Commands::Migrate { old_db } => run_migrate(&old_db),

        Commands::Encrypt {
            source,
            passphrase,
            print_passphrase,
            delete_backup,
        } => {
            let generated = passphrase.is_none();
            let pass = passphrase.unwrap_or_else(generate_passphrase);
            commands::encrypt::run(
                source.as_deref(),
                &pass,
                generated,
                print_passphrase,
                delete_backup,
            )
        }

        Commands::SelfUpdate {
            version,
            force,
            verify_only,
            check,
        } => commands::self_update::run(version.as_deref(), force, verify_only, check).await,

        Commands::Config { action } => match action {
            ConfigAction::Show => commands::config::show(),
            ConfigAction::Edit => commands::config::edit(),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(exit_code_for_error(&e.to_string()));
    }
}

fn exit_code_for_error(msg: &str) -> i32 {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("missing:") {
        return 1;
    }
    if lower.contains("vault is locked")
        || (lower.contains("unlock") && lower.contains("required"))
        || lower.contains("passphrase")
    {
        return 2;
    }
    if lower.contains("operator mode required") || lower.contains("requires operator mode") {
        return 3;
    }
    if lower.contains("invalid")
        || lower.contains("required")
        || lower.contains("must be")
        || lower.contains("expected")
    {
        return 4;
    }
    if lower.contains("conflict") {
        return 5;
    }
    10
}

/// Launch web GUI on localhost.
async fn run_web(port: u16) -> anyhow::Result<()> {
    use vault_core::security::AuditLogger;
    use vault_web::server::WebConfig;

    let db = commands::init::open_db()?;
    let audit = AuditLogger::open(vault_core::config::audit_db_path())?;

    // Static files are embedded in the binary. External dir is optional override.
    let static_dir = [
        Some(vault_core::config::vault_base_dir().join("static")),
        Some(std::path::PathBuf::from("static")),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.join("index.html").exists());

    let config = WebConfig { port, static_dir };

    println!("memxp web dashboard: http://127.0.0.1:{port}");
    vault_web::server::start(db, audit, config)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Launch MCP server on stdio.
async fn run_mcp() -> anyhow::Result<()> {
    use vault_core::security::AuditLogger;
    use vault_mcp::server::VaultMcpServer;

    let db = commands::init::open_db()?;
    let audit = AuditLogger::open(vault_core::config::audit_db_path())?;
    let server = VaultMcpServer::new(db, audit);

    use rmcp::ServiceExt;
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Migrate Python vault.db to encrypted Rust DB.
fn run_migrate(old_db_path: &str) -> anyhow::Result<()> {
    use vault_core::db::CrSqliteDatabase;

    let old_path = std::path::Path::new(old_db_path);
    if !old_path.exists() {
        anyhow::bail!("Old database not found: {old_db_path}");
    }

    println!("Migrating {old_db_path}...");

    // Open old unencrypted DB
    let old_db = CrSqliteDatabase::open_unencrypted(old_path, None)?;
    let old_entries = old_db.list_entries(None, None, None)?;
    let old_guides = old_db.list_guides(None, None)?;

    println!(
        "  Found {} entries, {} guides",
        old_entries.len(),
        old_guides.len()
    );

    // Open new encrypted DB
    let new_path = vault_core::config::db_path();
    let passphrase = commands::init::db_passphrase()?;
    let ext = commands::init::extension_path();
    let new_db = CrSqliteDatabase::open(&new_path, &passphrase, ext.as_deref())?;

    // Copy entries
    for e in &old_entries {
        let tags = if e.tags.is_empty() {
            None
        } else {
            Some(e.tags.as_slice())
        };
        let apps = if e.related_apps.is_empty() {
            None
        } else {
            Some(e.related_apps.as_slice())
        };
        new_db.set_entry(
            &e.path,
            &e.value,
            Some(&e.category),
            e.service.as_deref(),
            e.app.as_deref(),
            e.env.as_deref(),
            e.notes.as_deref(),
            tags,
            Some(&e.storage_mode),
            e.expires_at.as_deref(),
            e.rotation_interval_days,
            apps,
        )?;
    }

    // Copy guides
    for g in &old_guides {
        let tags = if g.tags.is_empty() {
            None
        } else {
            Some(g.tags.as_slice())
        };
        let paths = if g.related_paths.is_empty() {
            None
        } else {
            Some(g.related_paths.as_slice())
        };
        new_db.set_guide(
            &g.name,
            &g.content,
            Some(&g.category),
            tags,
            Some(&g.status),
            g.verified_at.as_deref(),
            paths,
        )?;
    }

    // Backup original
    let backup_path = format!("{old_db_path}.bak");
    std::fs::copy(old_path, &backup_path)?;

    println!("  Migrated to: {}", new_path.display());
    println!("  Backup: {backup_path}");

    // Verify counts
    let new_entries = new_db.list_entries(None, None, None)?;
    let new_guides = new_db.list_guides(None, None)?;
    println!(
        "  Verified: {} entries, {} guides",
        new_entries.len(),
        new_guides.len()
    );

    old_db.close()?;
    new_db.close()?;

    println!("Migration complete.");
    Ok(())
}

/// Generate a random passphrase (hex-encoded 32 bytes = 64 hex chars).
fn generate_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    vault_core::crypto::hex::encode(&bytes)
}
