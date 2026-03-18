//! Credential rotation alert helpers.
//!
//! Computes when credentials are due for rotation based on
//! `expires_at` and `rotation_interval_days` fields.

use chrono::{DateTime, Duration, Utc};

use crate::models::VaultEntry;

/// A rotation notice for a credential nearing expiry or rotation.
#[derive(Debug, Clone)]
pub struct RotationNotice {
    pub entry: VaultEntry,
    pub due_at: DateTime<Utc>,
    pub days_until_due: i64,
}

/// Parse an ISO timestamp string, handling common formats.
fn parse_iso(value: &str) -> Option<DateTime<Utc>> {
    if value.is_empty() {
        return None;
    }
    // Try standard RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try with Z suffix replacement
    let normalized = value.replace('Z', "+00:00");
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try naive datetime
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return Some(dt.and_utc());
    }
    None
}

/// Compute when a credential is due for rotation/expiry.
///
/// Takes the earliest of:
/// - `expires_at` date (if set)
/// - `updated_at + rotation_interval_days` (if interval set)
pub fn compute_due_at(entry: &VaultEntry) -> Option<DateTime<Utc>> {
    let mut candidates: Vec<DateTime<Utc>> = Vec::new();

    // Check expires_at
    if let Some(ref expires) = entry.expires_at {
        if let Some(dt) = parse_iso(expires) {
            candidates.push(dt);
        }
    }

    // Check rotation_interval_days
    if let Some(days) = entry.rotation_interval_days {
        let base = entry
            .updated_at
            .as_deref()
            .and_then(parse_iso)
            .or_else(|| entry.created_at.as_deref().and_then(parse_iso));

        if let Some(base_dt) = base {
            candidates.push(base_dt + Duration::days(days as i64));
        }
    }

    candidates.into_iter().min()
}

/// Get rotation notices for entries within a time window.
pub fn get_rotation_alerts(
    entries: &[VaultEntry],
    window_days: i32,
    include_overdue: bool,
) -> Vec<RotationNotice> {
    let now = Utc::now();

    let mut notices = Vec::new();

    for entry in entries {
        if let Some(due_at) = compute_due_at(entry) {
            let days_until = (due_at - now).num_days();

            if days_until <= window_days as i64 {
                if days_until < 0 && !include_overdue {
                    continue;
                }
                notices.push(RotationNotice {
                    entry: entry.clone(),
                    due_at,
                    days_until_due: days_until,
                });
            }
        }
    }

    // Sort by urgency (most urgent first)
    notices.sort_by_key(|n| n.days_until_due);
    notices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_due_at_expires() {
        let entry = VaultEntry {
            path: "test/key".into(),
            value: "val".into(),
            expires_at: Some("2025-06-01T00:00:00+00:00".into()),
            ..VaultEntry::new("", "")
        };

        let due = compute_due_at(&entry).unwrap();
        assert_eq!(due.date_naive().to_string(), "2025-06-01");
    }

    #[test]
    fn test_rotation_due_at_interval() {
        let entry = VaultEntry {
            path: "test/key".into(),
            value: "val".into(),
            rotation_interval_days: Some(90),
            updated_at: Some("2025-01-01T00:00:00+00:00".into()),
            ..VaultEntry::new("", "")
        };

        let due = compute_due_at(&entry).unwrap();
        assert_eq!(due.date_naive().to_string(), "2025-04-01");
    }

    #[test]
    fn test_rotation_due_at_both() {
        // When both are set, should return the earlier one
        let entry = VaultEntry {
            path: "test/key".into(),
            value: "val".into(),
            expires_at: Some("2025-03-01T00:00:00+00:00".into()),
            rotation_interval_days: Some(365),
            updated_at: Some("2025-01-01T00:00:00+00:00".into()),
            ..VaultEntry::new("", "")
        };

        let due = compute_due_at(&entry).unwrap();
        // expires_at is March 1, rotation is Jan 1 + 365 = Dec 31
        // March 1 is earlier
        assert_eq!(due.date_naive().to_string(), "2025-03-01");
    }

    #[test]
    fn test_rotation_due_at_none() {
        let entry = VaultEntry::new("test/key", "val");
        assert!(compute_due_at(&entry).is_none());
    }
}
