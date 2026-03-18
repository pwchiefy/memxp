//! Peer capabilities and table gating for backward-compatible sync.
//!
//! Tracks which tables and features each peer supports, and filters
//! changes accordingly during sync.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// All CRR table names (must match Python's SYNC_TABLES).
pub const ALL_CRR_TABLES: &[&str] = &[
    "vault_entries",
    "vault_guides",
    "vault_meta",
    "file_transfers",
    "file_chunks",
    "sync_conflicts",
    "conflict_settings",
];

/// All known sync protocol features.
pub const ALL_FEATURES: &[&str] = &[
    "incremental_sync",
    "hello_negotiation",
    "sync_triggers",
    "conflict_detection",
    "sync_gating",
];

/// Capabilities of a sync peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Tables this peer supports.
    pub supported_tables: HashSet<String>,
    /// Features this peer supports.
    pub supported_features: HashSet<String>,
    /// Schema version of the peer.
    pub schema_version: i32,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            supported_tables: ALL_CRR_TABLES.iter().map(|s| s.to_string()).collect(),
            supported_features: ALL_FEATURES.iter().map(|s| s.to_string()).collect(),
            schema_version: vault_core::models::SCHEMA_VERSION,
        }
    }
}

impl PeerCapabilities {
    /// Create capabilities with only the specified tables.
    pub fn with_tables(tables: &[&str]) -> Self {
        Self {
            supported_tables: tables.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// Check if a table is supported by this peer.
    pub fn supports_table(&self, table: &str) -> bool {
        self.supported_tables.contains(table)
    }

    /// Check if a feature is supported.
    pub fn supports_feature(&self, feature: &str) -> bool {
        self.supported_features.contains(feature)
    }
}

/// Filter changes to only include those for tables the peer supports.
///
/// Changes for unsupported tables are returned separately for backlog storage.
pub fn filter_changes_for_peer<T: HasTable + Clone>(
    changes: &[T],
    peer: &PeerCapabilities,
) -> (Vec<T>, Vec<T>) {
    let mut accepted = Vec::new();
    let mut backlogged = Vec::new();

    for change in changes {
        if peer.supports_table(change.table_name()) {
            accepted.push(change.clone());
        } else {
            backlogged.push(change.clone());
        }
    }

    (accepted, backlogged)
}

/// Trait for items that have a table name.
pub trait HasTable {
    fn table_name(&self) -> &str;
}

impl HasTable for vault_core::models::SyncChange {
    fn table_name(&self) -> &str {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::models::SyncChange;

    #[test]
    fn test_default_capabilities() {
        let caps = PeerCapabilities::default();
        assert!(caps.supports_table("vault_entries"));
        assert!(caps.supports_table("vault_guides"));
        assert!(caps.supports_feature("incremental_sync"));
    }

    #[test]
    fn test_filter_changes_for_peer() {
        let changes = vec![
            SyncChange {
                table: "vault_entries".to_string(),
                pk: b"key1".to_vec(),
                cid: "value".to_string(),
                val: None,
                col_version: 1,
                db_version: 1,
                site_id: None,
                cl: 1,
                seq: 0,
            },
            SyncChange {
                table: "vault_guides".to_string(),
                pk: b"guide1".to_vec(),
                cid: "content".to_string(),
                val: None,
                col_version: 1,
                db_version: 2,
                site_id: None,
                cl: 1,
                seq: 0,
            },
            SyncChange {
                table: "sync_conflicts".to_string(),
                pk: b"task1".to_vec(),
                cid: "title".to_string(),
                val: None,
                col_version: 1,
                db_version: 3,
                site_id: None,
                cl: 1,
                seq: 0,
            },
        ];

        // Peer only supports vault_entries
        let peer = PeerCapabilities::with_tables(&["vault_entries"]);
        let (accepted, backlog) = filter_changes_for_peer(&changes, &peer);

        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].table, "vault_entries");
        assert_eq!(backlog.len(), 2);
        assert!(backlog.iter().any(|c| c.table == "vault_guides"));
        assert!(backlog.iter().any(|c| c.table == "sync_conflicts"));
    }
}
