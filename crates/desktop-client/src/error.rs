//! Client application error types

use thiserror::Error;

/// Client operation result
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client application errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// Authorization error
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// External wallet/signing layer error
    #[error("External wallet error: {0}")]
    ExternalWallet(String),

    /// Session not found
    #[error("No active session. Please login first.")]
    NoSession,

    /// Session expired
    #[error("Session expired. Please login again.")]
    SessionExpired,

    /// Cryptography error
    #[error("Crypto error: {0}")]
    Crypto(#[from] xrpl_vault_crypto_core::CryptoError),

    /// XRPL error
    #[error("XRPL error: {0}")]
    Xrpl(String),

    /// NFT not found
    #[error("NFT not found: {0}")]
    NftNotFound(String),

    /// User is not the NFT owner
    #[error("You are not the owner of this NFT")]
    NotNftOwner,

    /// Oracle API error
    #[error("Oracle API error: {0}")]
    Oracle(String),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// File system error
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),

    /// File too large
    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    /// Keystore error
    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Keystore error: {0}")]
    Keystore(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Serialization(e.to_string())
    }
}

impl serde::Serialize for ClientError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
