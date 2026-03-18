//! `memxp init` — first-time setup.

use vault_core::config;
use vault_core::db::CrSqliteDatabase;

/// Initialize the vault: create directories, generate default config, open encrypted DB.
pub fn run(force: bool, print_passphrase: bool) -> anyhow::Result<()> {
    let db_path = config::db_path();
    let config_path = config::config_path();

    if db_path.exists() && !force {
        println!("Vault already initialized at {}", db_path.display());
        println!("Use --force to reinitialize (existing data preserved).");
        return Ok(());
    }

    // Ensure all directories exist
    config::ensure_directories()?;

    // Write default config if missing
    if !config_path.exists() {
        let cfg = config::VaultConfig::default();
        cfg.save(&config_path)?;
        println!("Created config: {}", config_path.display());
    }

    // Clean up WAL/SHM if force reinit
    if force {
        let wal = db_path.with_extension("db-wal");
        let shm = db_path.with_extension("db-shm");
        for p in [&wal, &shm] {
            if p.exists() {
                std::fs::remove_file(p)?;
            }
        }
    }

    // Open encrypted DB (creates it if missing, runs schema init)
    // Use init-specific passphrase handling that auto-generates on first run
    let passphrase = db_passphrase_for_init(print_passphrase)?;
    let ext = extension_path();
    let db = CrSqliteDatabase::open(&db_path, &passphrase, ext.as_deref())?;

    let version = db.db_version()?;
    let schema = db.schema_version();
    let cr = db.cr_enabled();

    println!("Vault initialized:");
    println!("  Database: {}", db_path.display());
    println!("  Schema version: {schema}");
    println!("  DB version: {version}");
    println!("  cr-sqlite: {}", if cr { "enabled" } else { "disabled" });

    // Write sentinel
    let sentinel = config::sentinel_path();
    std::fs::write(&sentinel, "initialized")?;

    db.close()?;
    Ok(())
}

/// Get DB passphrase from env or keychain. Errors if none found.
pub fn db_passphrase() -> anyhow::Result<String> {
    // 1. Environment variable (highest priority)
    if let Ok(p) = std::env::var("VAULT_PASSPHRASE") {
        // Trim whitespace — cmd.exe `set VAR=value &` includes trailing spaces
        return Ok(p.trim().to_string());
    }
    // 2. System keychain (stored by `memxp encrypt` or `memxp init`)
    if let Some(p) = super::encrypt::get_passphrase_from_keychain() {
        return Ok(p.trim().to_string());
    }
    anyhow::bail!(
        "No passphrase found. Either:\n  \
         1. Set VAULT_PASSPHRASE environment variable, or\n  \
         2. Run `memxp encrypt` to store passphrase in keychain\n\n  \
         If migrating from default, use: export VAULT_PASSPHRASE='vault-default-passphrase'"
    )
}

/// Get or generate DB passphrase for first-time init.
///
/// Unlike `db_passphrase()`, this auto-generates a random passphrase and stores
/// it in the system keychain when no passphrase source exists.
fn db_passphrase_for_init(print_passphrase: bool) -> anyhow::Result<String> {
    // 1. Environment variable (highest priority)
    if let Ok(p) = std::env::var("VAULT_PASSPHRASE") {
        return Ok(p.trim().to_string());
    }
    // 2. System keychain
    if let Some(p) = super::encrypt::get_passphrase_from_keychain() {
        return Ok(p.trim().to_string());
    }
    // 3. Generate new passphrase and store in keychain
    let passphrase = generate_random_passphrase();
    match super::encrypt::store_passphrase_in_keychain(&passphrase) {
        Ok(()) => {
            println!("Generated and stored passphrase in system keychain.");
        }
        Err(e) => {
            // If keychain storage fails, avoid printing passphrase by default.
            if print_passphrase {
                println!("Generated passphrase (save this!): {passphrase}");
            } else {
                println!(
                    "Generated passphrase could not be stored in keyring. Re-run with --print-passphrase if needed."
                );
            }
            println!("Warning: Could not store in keychain: {e}");
        }
    }
    Ok(passphrase)
}

/// Generate a random passphrase (hex-encoded 32 bytes = 64 hex chars).
fn generate_random_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    vault_core::crypto::hex::encode(&bytes)
}

/// Get cr-sqlite extension path if set.
pub fn extension_path() -> Option<std::path::PathBuf> {
    std::env::var("VAULT_CR_SQLITE_PATH")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            let p = config::cr_sqlite_extension_path();
            if p.exists() {
                Some(p)
            } else {
                None
            }
        })
}

/// Open the vault database (shared helper for all commands).
pub fn open_db() -> anyhow::Result<CrSqliteDatabase> {
    let db_path = config::db_path();
    if !db_path.exists() {
        anyhow::bail!("Vault not initialized. Run `memxp init` first.");
    }
    if config::lock_file_path().exists() {
        anyhow::bail!("Vault is locked. Run `memxp unlock` first.");
    }
    let passphrase = db_passphrase()?;
    let ext = extension_path();
    let db = CrSqliteDatabase::open(&db_path, &passphrase, ext.as_deref())?;

    if let Ok(Some(count)) = db.consume_agent_task_archive_migration_notice() {
        println!(
            "NOTICE: Legacy task/message rows were migrated to `agent_tasks_archive` for compatibility ({count} rows)."
        );
        println!(
            "These rows are archived and no longer active in sync/runtime for the public API surface."
        );
        println!(
            "To restore manually, inspect `{}` and copy rows back to `agent_tasks` only if you accept legacy behavior.",
            config::db_path().display()
        );
    }

    Ok(db)
}
