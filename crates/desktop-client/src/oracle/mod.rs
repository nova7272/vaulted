//! Oracle server communication module
//!
//! HTTP API for:
//! - Registering encrypted files
//! - Getting file access by NFT
//! - Initiating PRE re-encryption during transfer

pub mod api;

pub use api::{
    CreateVaultRequest, CreateVaultResponse, InitiateTransferResponse, OracleClient, OracleConfig,
    VaultFragment, VaultManifest,
};
