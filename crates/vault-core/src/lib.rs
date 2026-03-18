pub mod auth;
pub mod challenge;
pub mod config;
pub mod conflicts;
pub mod credential_store;
pub mod crypto;
pub mod db;
pub mod keyring_backend;
pub mod lint;
pub mod models;
pub mod operator_session;
pub mod query;
pub mod rotation;
pub mod security;
mod tasks;

// Re-exports for convenience
pub use config::VaultConfig;
pub use conflicts::ConflictQueue;
pub use credential_store::CredentialStore;
pub use db::CrSqliteDatabase;
pub use models::*;
