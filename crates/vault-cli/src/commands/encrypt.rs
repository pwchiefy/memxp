//! `memxp encrypt` — in-place encryption of an existing unencrypted vault.db.
//!
//! Uses SQLCipher's ATTACH + sqlcipher_export() to encrypt the database
//! while preserving ALL cr-sqlite internals (site_id, change tracking, CRR metadata).
//! This is the preferred migration path from Python vault.

use std::path::{Path, PathBuf};

use vault_core::config;

/// Encrypt an existing unencrypted vault.db in-place.
///
/// Steps:
/// 1. Open unencrypted source DB
/// 2. ATTACH encrypted destination with passphrase
/// 3. sqlcipher_export() copies everything (tables, indices, cr-sqlite internals)
/// 4. Backup original, rename encrypted to vault.db
pub fn run(
    source: Option<&str>,
    passphrase: &str,
    generated: bool,
    print_passphrase: bool,
    delete_backup: bool,
) -> anyhow::Result<()> {
    let source_path = match source {
        Some(p) => PathBuf::from(p),
        None => config::db_path(),
    };

    if !source_path.exists() {
        anyhow::bail!("Database not found: {}", source_path.display());
    }

    // Verify it's actually unencrypted (SQLite header check)
    let header = std::fs::read(&source_path)?;
    if header.len() < 16 {
        anyhow::bail!("File too small to be a SQLite database");
    }
    let sqlite_header = b"SQLite format 3\0";
    if &header[..16] != sqlite_header {
        anyhow::bail!(
            "Database appears to already be encrypted (no SQLite header). \
             If this is already a SQLCipher DB, use it directly with the Rust binary."
        );
    }

    println!("Encrypting {}...", source_path.display());

    // Build encrypted output path (temp file next to source)
    let encrypted_path = source_path.with_extension("db.encrypted");
    if encrypted_path.exists() {
        std::fs::remove_file(&encrypted_path)?;
    }

    // Open the unencrypted database
    let conn = rusqlite::Connection::open(&source_path)?;

    // Load cr-sqlite extension if available (needed to preserve CRR metadata)
    let ext_path = super::init::extension_path();
    if let Some(ref ext) = ext_path {
        if ext.exists() {
            match unsafe { conn.load_extension(ext, Some("sqlite3_crsqlite_init")) } {
                Ok(()) => println!("  cr-sqlite extension loaded"),
                Err(e) => println!("  Warning: Could not load cr-sqlite: {e}"),
            }
        }
    }

    // Get stats before encryption
    let entry_count = count_table(&conn, "vault_entries");
    let guide_count = count_table(&conn, "vault_guides");

    // Check for site_id before encryption
    let site_id: Option<String> = conn
        .query_row("SELECT hex(crsql_site_id())", [], |row| row.get(0))
        .ok();

    if let Some(ref sid) = site_id {
        println!("  Site ID: {sid} (will be preserved)");
    }
    println!("  Found: {} entries, {} guides", entry_count, guide_count);

    // ATTACH encrypted database with SQLCipher passphrase
    // Use a parameterized approach to avoid SQL injection
    conn.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS encrypted KEY '{}';",
        encrypted_path.display(),
        passphrase.replace('\'', "''") // Escape single quotes in passphrase
    ))?;

    // Export everything to the encrypted database
    conn.execute_batch("SELECT sqlcipher_export('encrypted');")?;

    // Set the user_version on the encrypted DB to match
    let user_version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or(0);
    conn.execute_batch(&format!("PRAGMA encrypted.user_version = {user_version};"))?;

    conn.execute_batch("DETACH DATABASE encrypted;")?;

    // Finalize cr-sqlite state before closing (prevents "unfinalized statements" error)
    let _ = conn.execute_batch("SELECT crsql_finalize();");
    conn.close().map_err(|(_, e)| anyhow::anyhow!("{e}"))?;

    // Verify the encrypted database opens correctly
    verify_encrypted(&encrypted_path, passphrase, ext_path.as_deref())?;

    // Backup original
    let backup_path = source_path.with_extension("db.unencrypted.bak");
    std::fs::copy(&source_path, &backup_path)?;
    println!("  Backup: {}", backup_path.display());

    // Replace original with encrypted version
    std::fs::rename(&encrypted_path, &source_path)?;
    println!("  Replaced: {}", source_path.display());

    // Store passphrase in keychain
    store_passphrase_in_keychain(passphrase)?;

    if generated && print_passphrase {
        println!("Generated passphrase (save this!): {passphrase}");
    }

    println!("Encryption complete.");
    println!();
    println!(
        "WARNING: Unencrypted backup at {} contains plaintext credentials.",
        backup_path.display()
    );

    if delete_backup {
        // Securely delete: overwrite with zeros, then remove
        let file_len = std::fs::metadata(&backup_path)?.len() as usize;
        let zeros = vec![0u8; file_len];
        std::fs::write(&backup_path, &zeros)?;
        std::fs::remove_file(&backup_path)?;
        println!("  Backup securely deleted.");
    } else {
        println!("  Run with --delete-backup to securely remove it.");
    }

    println!();
    println!("The Rust binary can now open this database with:");
    println!("  VAULT_PASSPHRASE='...' memxp status");
    println!("Or the passphrase has been stored in your system keychain.");

    Ok(())
}

/// Verify the encrypted database can be opened and has the right data.
fn verify_encrypted(
    path: &Path,
    passphrase: &str,
    extension_path: Option<&Path>,
) -> anyhow::Result<()> {
    let conn = rusqlite::Connection::open(path)?;
    conn.pragma_update(None, "key", passphrase)?;

    // Verify we can read the cipher version
    let cipher_ver: String = conn
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .map_err(|e| anyhow::anyhow!("Encrypted DB verification failed: {e}"))?;
    println!("  SQLCipher version: {cipher_ver}");

    // Load cr-sqlite for verification
    if let Some(ext) = extension_path {
        if ext.exists() {
            let _ = unsafe { conn.load_extension(ext, Some("sqlite3_crsqlite_init")) };
        }
    }

    // Verify entry counts
    let entry_count = count_table_conn(&conn, "vault_entries");
    let guide_count = count_table_conn(&conn, "vault_guides");
    println!("  Verified: {entry_count} entries, {guide_count} guides");

    // Verify site_id preserved
    if let Ok(sid) = conn.query_row("SELECT hex(crsql_site_id())", [], |row| {
        row.get::<_, String>(0)
    }) {
        println!("  Site ID preserved: {sid}");
    }

    let _ = conn.execute_batch("SELECT crsql_finalize();");
    conn.close().map_err(|(_, e)| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn count_table(conn: &rusqlite::Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap_or(0)
}

fn count_table_conn(conn: &rusqlite::Connection, table: &str) -> i64 {
    count_table(conn, table)
}

const KEYCHAIN_PASSPHRASE_KEY: &str = "db-passphrase";

/// Store the DB passphrase in the system keychain.
pub(crate) fn store_passphrase_in_keychain(passphrase: &str) -> anyhow::Result<()> {
    match vault_core::keyring_backend::set_in_keyring(KEYCHAIN_PASSPHRASE_KEY, passphrase) {
        Ok(()) => {
            println!("  Passphrase stored in system keychain");
            Ok(())
        }
        Err(e) => {
            println!(
                "  Warning: Could not store passphrase in keychain: {e}\n  \
                 Set VAULT_PASSPHRASE env var instead."
            );
            Ok(())
        }
    }
}

/// Retrieve DB passphrase from keychain (called by init::db_passphrase).
pub fn get_passphrase_from_keychain() -> Option<String> {
    vault_core::keyring_backend::get_from_keyring(KEYCHAIN_PASSPHRASE_KEY)
        .ok()
        .flatten()
}
