use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::models::{DEFAULT_CLIPBOARD_CLEAR_SECONDS, DEFAULT_SYNC_INTERVAL, DEFAULT_SYNC_PORT};

/// Base directory name for memxp data.
const VAULT_DIR_NAME: &str = ".memxp";

/// Cache TTL for machine ID lookups.
const MACHINE_ID_TTL: Duration = Duration::from_secs(300);

/// Cached machine ID with TTL.
static MACHINE_ID_CACHE: Mutex<Option<(String, Instant)>> = Mutex::new(None);

/// Get the base directory for memxp data (`~/.memxp/`).
pub fn vault_base_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(VAULT_DIR_NAME)
}

/// Get the default database path.
pub fn db_path() -> PathBuf {
    if let Ok(p) = std::env::var("VAULT_DB_PATH") {
        return PathBuf::from(p);
    }
    vault_base_dir().join("vault.db")
}

/// Get the default config file path.
pub fn config_path() -> PathBuf {
    vault_base_dir().join("config.yaml")
}

/// Get the audit log database path.
pub fn audit_db_path() -> PathBuf {
    vault_base_dir().join("logs").join("audit.db")
}

/// Get the log directory.
pub fn log_dir() -> PathBuf {
    vault_base_dir().join("logs")
}

/// Get the sentinel file path.
pub fn sentinel_path() -> PathBuf {
    vault_base_dir().join("vault.sentinel.json")
}

/// Get the lock-file path used by CLI auth-status/lock/unlock.
pub fn lock_file_path() -> PathBuf {
    vault_base_dir().join("vault.lock")
}

/// Get the cr-sqlite extension path for this platform.
pub fn cr_sqlite_extension_path() -> PathBuf {
    let ext = if cfg!(target_os = "macos") {
        "crsqlite.dylib"
    } else if cfg!(target_os = "windows") {
        "crsqlite.dll"
    } else {
        "crsqlite.so"
    };
    vault_base_dir().join(ext)
}

/// Ensure all required directories exist with secure permissions.
pub fn ensure_directories() -> std::io::Result<()> {
    let base = vault_base_dir();
    std::fs::create_dir_all(&base)?;
    std::fs::create_dir_all(log_dir())?;

    // Set secure permissions (owner only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(base, perms.clone());
        let _ = std::fs::set_permissions(log_dir(), perms);
    }

    Ok(())
}

/// Get the local Tailscale IP address with caching.
pub fn get_local_machine_id() -> String {
    // Check cache
    if let Ok(guard) = MACHINE_ID_CACHE.lock() {
        if let Some((ref id, ref when)) = *guard {
            if when.elapsed() < MACHINE_ID_TTL {
                return id.clone();
            }
        }
    }

    let id = detect_machine_id();

    if let Ok(mut guard) = MACHINE_ID_CACHE.lock() {
        *guard = Some((id.clone(), Instant::now()));
    }

    id
}

fn detect_machine_id() -> String {
    // Method 1: tailscale ip -4
    let tailscale_paths = if cfg!(target_os = "macos") {
        vec![
            "tailscale",
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            "/usr/local/bin/tailscale",
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            "tailscale",
            r"C:\Program Files\Tailscale\tailscale.exe",
            r"C:\Program Files (x86)\Tailscale\tailscale.exe",
        ]
    } else {
        vec![
            "tailscale",
            "/usr/bin/tailscale",
            "/usr/local/bin/tailscale",
        ]
    };

    for cmd in &tailscale_paths {
        if let Ok(output) = Command::new(cmd).args(["ip", "-4"]).output() {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if ip.starts_with("100.") {
                    return ip;
                }
            }
        }
    }

    // Method 2: Scan network interfaces for Tailscale CGNAT range
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("ifconfig").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(cap) = regex_lite_find_100_ips(&text).into_iter().next() {
                    return cap;
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("ipconfig").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(cap) = regex_lite_find_100_ips_windows(&text).into_iter().next() {
                    return cap;
                }
            }
        }
    }

    // Fallback: hostname (works on all platforms)
    if let Ok(output) = Command::new("hostname").output() {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }

    "unknown".to_string()
}

/// Simple regex-free scan for 100.x.x.x IPs in ifconfig output.
#[cfg(unix)]
fn regex_lite_find_100_ips(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(idx) = line.find("inet ") {
            let rest = &line[idx + 5..];
            let ip: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if ip.starts_with("100.") && ip.split('.').count() == 4 {
                results.push(ip);
            }
        }
    }
    results
}

/// Parse 100.x.x.x IPs from Windows `ipconfig` output.
///
/// Windows `ipconfig` uses "IPv4 Address. . . . . . . . . : 100.x.x.x" format.
#[cfg(windows)]
fn regex_lite_find_100_ips_windows(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Windows ipconfig: "IPv4 Address. . . . . . . . . . : 100.64.1.1"
        if let Some(idx) = line.find(": ") {
            let ip_part = line[idx + 2..].trim();
            let ip: String = ip_part
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if ip.starts_with("100.") && ip.split('.').count() == 4 {
                results.push(ip);
            }
        }
    }
    results
}

/// Validate that an IP is a valid Tailscale IP (100.x.x.x CGNAT range).
pub fn validate_tailscale_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Vec<u8> = match parts.iter().map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    octets[0] == 100
}

/// VaultP2P configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    #[serde(default = "default_database_config")]
    pub database: DatabaseConfig,
    #[serde(default = "default_sync_config")]
    pub sync: SyncConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path_string")]
    pub path: String,
    pub cr_sqlite_extension: Option<String>,
    pub passphrase_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_sync_port")]
    pub port: u16,
    #[serde(default = "default_sync_interval")]
    pub interval_seconds: u32,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub allow_localhost: bool,
    pub bind_address: Option<String>,
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_seconds: u32,
    #[serde(default)]
    pub redact_secrets_in_responses: bool,
}

// Default constructors
fn default_database_config() -> DatabaseConfig {
    DatabaseConfig {
        path: db_path().to_string_lossy().into_owned(),
        cr_sqlite_extension: None,
        passphrase_env: None,
    }
}

fn default_sync_config() -> SyncConfig {
    SyncConfig {
        enabled: true,
        port: DEFAULT_SYNC_PORT,
        interval_seconds: DEFAULT_SYNC_INTERVAL,
        peers: Vec::new(),
        allowed_ips: Vec::new(),
        allow_localhost: false,
        bind_address: None,
        max_payload_bytes: 10 * 1024 * 1024,
    }
}

fn default_true() -> bool {
    true
}
fn default_sync_port() -> u16 {
    DEFAULT_SYNC_PORT
}
fn default_sync_interval() -> u32 {
    DEFAULT_SYNC_INTERVAL
}
fn default_max_payload() -> usize {
    10 * 1024 * 1024
}
fn default_clipboard_clear() -> u32 {
    DEFAULT_CLIPBOARD_CLEAR_SECONDS
}
fn default_db_path_string() -> String {
    db_path().to_string_lossy().into_owned()
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            database: default_database_config(),
            sync: default_sync_config(),
            security: SecurityConfig::default(),
        }
    }
}

impl VaultConfig {
    /// Load config from a YAML file, falling back to defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_yaml::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save config to a YAML file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let content = serde_yaml::to_string(self).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_platform_paths() {
        let base = vault_base_dir();
        let base_str = base.to_string_lossy();
        assert!(
            base_str.contains(VAULT_DIR_NAME),
            "vault_base_dir should contain .memxp, got: {base_str}"
        );

        let db = db_path();
        assert!(db.to_string_lossy().ends_with("vault.db"));

        // Test YAML round-trip
        let config = VaultConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: VaultConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.sync.port, DEFAULT_SYNC_PORT);
        assert_eq!(parsed.sync.interval_seconds, DEFAULT_SYNC_INTERVAL);
        assert!(parsed.sync.enabled);

        // Defaults generated
        assert!(!config.database.path.is_empty());
    }

    #[test]
    fn test_validate_tailscale_ip() {
        assert!(validate_tailscale_ip("100.64.1.1"));
        assert!(validate_tailscale_ip("100.127.0.1"));
        assert!(!validate_tailscale_ip("192.168.1.1"));
        assert!(!validate_tailscale_ip("not-an-ip"));
        assert!(!validate_tailscale_ip("100.1.2"));
    }
}
