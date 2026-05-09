//! Сервисы Oracle

pub mod app_state;
pub mod replication;

pub use app_state::AppState;
pub use replication::{ReplicationService, ReplicationSettings, FileReplicationStatus, UploadTarget};