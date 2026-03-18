//! Config commands: show, edit.

use vault_core::config;

/// `memxp config show`
pub fn show() -> anyhow::Result<()> {
    let config_path = config::config_path();
    if !config_path.exists() {
        println!("No config file. Run `memxp init` to create one.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&config_path)?;
    println!("Config: {}\n", config_path.display());
    println!("{content}");
    Ok(())
}

/// `memxp config edit`
pub fn edit() -> anyhow::Result<()> {
    let config_path = config::config_path();
    if !config_path.exists() {
        anyhow::bail!("No config file. Run `memxp init` first.");
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()?;

    if status.success() {
        // Validate the config loads correctly
        let _cfg = config::VaultConfig::load(&config_path);
        println!("Config saved.");
    } else {
        println!("Editor exited with error.");
    }
    Ok(())
}
