//! Self-update helpers for `memxp`.
//!
//! Performs version check against GitHub releases and invokes the repository
//! install script for the current platform. Verification can be run in
//! checksum-only mode with `--verify-only`.

use std::process::Command;

const REPO_OWNER: &str = "pwchiefy";
const REPO_NAME: &str = "memxp";

/// Run self-update flow.
pub async fn run(
    version: Option<&str>,
    force: bool,
    verify_only: bool,
    check: bool,
) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION").trim_start_matches('v');
    let target = version
        .map(|v| v.trim_start_matches('v').to_string())
        .unwrap_or_else(|| fetch_latest_version().unwrap_or_else(|_| current.to_string()));

    if check {
        if compare_versions(&target, current)? == std::cmp::Ordering::Greater {
            println!("Update available: {current} -> {target}");
        } else {
            println!("memxp is up to date: {current}");
        }
        return Ok(());
    }

    if compare_versions(&target, current)? != std::cmp::Ordering::Greater && !force {
        println!("memxp is already at {current}.");
        return Ok(());
    }

    println!("memxp latest available: {target}");
    if verify_only {
        verify_checksum(&target)?;
        return Ok(());
    }

    run_install_bootstrap(&target)
}

fn fetch_latest_version() -> anyhow::Result<String> {
    let url = format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest");
    let body = http_get(&url)?;
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let tag = parsed
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("v0.0.0")
        .trim_start_matches('v')
        .to_string();
    Ok(tag)
}

fn verify_checksum(version: &str) -> anyhow::Result<()> {
    let tag = release_tag(version);
    let checksums = fetch_checksums(&tag)?;
    let expected = platform_checksum_key()?;
    let current_binary = std::env::current_exe()?;

    let local = sha256_hex_file(&current_binary)?;
    match checksums.get(&expected) {
        Some(remote) => {
            if remote.eq_ignore_ascii_case(&local) {
                println!(
                    "OK: {} checksum match for {}",
                    version,
                    current_binary.display()
                );
                Ok(())
            } else {
                anyhow::bail!("checksum mismatch: local {local}, remote {remote}")
            }
        }
        None => anyhow::bail!("checksum for expected artifact '{expected}' not found"),
    }
}

fn run_install_bootstrap(version: &str) -> anyhow::Result<()> {
    let tag = release_tag(version);
    let script = if cfg!(target_os = "windows") {
        let exe = script_url(&tag, "install.ps1");
        if exe.is_empty() {
            anyhow::bail!("install.ps1 script unavailable");
        }
        let status = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(format!(
                "iwr -UseBasicParsing -Uri {exe} | Invoke-Expression"
            ))
            .status()?;
        if !status.success() {
            anyhow::bail!("installer script failed (exit {})", status);
        }
        return Ok(());
    } else {
        script_url(&tag, "install.sh")
    };

    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -fsSL {script} | sh -s -- --version {version}"
        ))
        .status()?;
    if !status.success() {
        anyhow::bail!("installer script failed (exit {})", status);
    }
    Ok(())
}

fn release_tag(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn script_url(version: &str, name: &str) -> String {
    format!("https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{version}/scripts/{name}")
}

fn fetch_checksums(version: &str) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let url = format!(
        "https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/{version}/checksums.txt"
    );
    let body = http_get(&url)?;
    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(sum), Some(file)) = (parts.next(), parts.next()) {
            map.insert(file.to_string(), sum.to_string());
        }
    }
    Ok(map)
}

fn platform_checksum_key() -> anyhow::Result<String> {
    let file = match std::env::consts::OS {
        "macos" => match std::env::consts::ARCH {
            "aarch64" => "memxp-macos-arm64",
            _ => "memxp-macos-x86_64",
        },
        "linux" => "memxp-linux-x86_64",
        "windows" => "memxp-windows-x86_64",
        other => anyhow::bail!("unsupported OS: {other}"),
    };
    let ext = if std::env::consts::OS == "windows" {
        "zip"
    } else {
        "tar.gz"
    };
    Ok(format!("{file}.{ext}"))
}

fn http_get(url: &str) -> anyhow::Result<String> {
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("-H")
        .arg("Accept: application/vnd.github+json")
        .arg(url)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "request failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn compare_versions(a: &str, b: &str) -> anyhow::Result<std::cmp::Ordering> {
    let pa = a.trim().trim_start_matches('v');
    let pb = b.trim().trim_start_matches('v');
    let va = parse_version(pa)?;
    let vb = parse_version(pb)?;
    Ok(va.cmp(&vb))
}

fn parse_version(v: &str) -> anyhow::Result<Vec<u32>> {
    v.split('.')
        .map(|p| {
            p.trim()
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("invalid version segment: {p}"))
        })
        .collect()
}

fn sha256_hex_file(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    let sum = Sha256::digest(&data);
    Ok(sum.iter().map(|b| format!("{b:02x}")).collect())
}
