//! Out-of-band challenge confirmation command.

use std::io::IsTerminal;

use vault_core::challenge::ChallengeStore;

pub fn confirm_operator(
    challenge_id: &str,
    action: &str,
    allow_non_interactive: bool,
    json: bool,
) -> anyhow::Result<()> {
    if !allow_non_interactive
        && (!std::io::stdin().is_terminal() || !std::io::stdout().is_terminal())
    {
        anyhow::bail!(
            "confirm-operator requires an interactive TTY. Use --allow-non-interactive to override."
        );
    }

    let candidate = vault_core::auth::resolve_passphrase_keychain_first()?;
    let passphrase = candidate.ok_or_else(|| {
        anyhow::anyhow!("No passphrase source available (set VAULT_PASSPHRASE or keychain entry)")
    })?;
    if !vault_core::auth::validate_passphrase(&passphrase)? {
        anyhow::bail!("Invalid passphrase");
    }

    let store = ChallengeStore::new();
    let challenge = store.confirm(challenge_id, action, None)?;
    let out = serde_json::json!({
        "status": "confirmed",
        "challenge": challenge.challenge_id,
        "action": challenge.action,
        "expires_at": challenge.expires_at,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "Confirmed challenge {} for action {}.",
            out["challenge"].as_str().unwrap_or(challenge_id),
            out["action"].as_str().unwrap_or(action)
        );
    }
    Ok(())
}
