//! XRPL Vault Oracle Server
//!
//! Central server for managing encrypted files
//! with NFT-based access control.
//!
//! ## Oracle Responsibilities
//!
//! 1. **Metadata storage** - links NFTs to encrypted files
//! 2. **PRE re-encryption** - transforms encrypted_aes_key during NFT transfer
//! 3. **Storage coordination** - distributes fragments across storage nodes
//! 4. **Access verification** - checks NFT ownership before returning data
//!
//! ## What Oracle Does NOT See
//!
//! - User private keys
//! - Plaintext AES keys
//! - Decrypted file content

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod migrations;
pub mod models;
pub mod nft_image;
pub mod services;
pub mod storage;
pub mod storage_token;
pub mod sync;
pub mod xrpl;
pub mod xrpl_verify;

pub use auth::{create_token, verify_token, AuthenticatedUser, Claims, OptionalAuth};
pub use config::Config;
pub use error::{ApiError, Result};
pub use migrations::{run_embedded_migrations, run_migrations};
pub use storage_token::{
    sign_storage_token, verify_storage_token, StorageToken, StorageUrlGenerator,
};
pub use sync::{SyncAction, SyncConfig, SyncStats, XrplSyncService};
pub use xrpl_verify::verify_xrpl_signature;
