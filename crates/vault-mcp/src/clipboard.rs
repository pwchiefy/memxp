//! Cross-platform clipboard with auto-clear timer.

use std::sync::atomic::{AtomicU64, Ordering};

static CLIPBOARD_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Copy text to clipboard and schedule auto-clear after `clear_after_secs`.
pub fn copy_and_clear(text: &str, clear_after_secs: u64) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("clipboard init failed: {e}"))?;
    clipboard
        .set_text(text)
        .map_err(|e| format!("clipboard set failed: {e}"))?;

    let gen = CLIPBOARD_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    // Spawn a background task to clear clipboard after delay
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(clear_after_secs));
        // Only clear if no newer copy has happened
        if CLIPBOARD_GENERATION.load(Ordering::SeqCst) == gen {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text("");
            }
        }
    });

    Ok(())
}

/// Copy text to clipboard without auto-clear.
pub fn copy(text: &str) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("clipboard init failed: {e}"))?;
    clipboard
        .set_text(text)
        .map_err(|e| format!("clipboard set failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Clipboard tests require a display server, skip in CI
}
