//! Сервисы Oracle

pub mod app_state;
pub mod replication;

pub use app_state::AppState;
pub use replication::{
    FileReplicationStatus, ReplicationService, ReplicationSettings, UploadTarget,
};
