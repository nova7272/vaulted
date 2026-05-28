//! Crypto module error types

use thiserror::Error;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    /// AES encryption error
    #[error("AES encryption failed: {0}")]
    AesEncryption(String),

    /// AES decryption error
    #[error("AES decryption failed: {0}")]
    AesDecryption(String),

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size in bytes
        actual: usize,
    },

    /// Invalid nonce size
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size in bytes
        actual: usize,
    },

    /// Proxy Re-Encryption error
    #[error("PRE operation failed: {0}")]
    PreError(String),

    /// PRE encryption error
    #[error("PRE encryption failed: {0}")]
    PreEncryption(String),

    /// PRE decryption error
    #[error("PRE decryption failed: {0}")]
    PreDecryption(String),

    /// PRE key generation error
    #[error("PRE key generation failed: {0}")]
    PreKeyGeneration(String),

    /// PRE re-encryption error
    #[error("PRE re-encryption failed: {0}")]
    PreReEncryption(String),

    /// Invalid key
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Re-encryption key generation error
    #[error("Failed to generate re-encryption key: {0}")]
    ReKeyGeneration(String),

    /// Re-encryption error
    #[error("Re-encryption failed: {0}")]
    ReEncryption(String),

    /// Invalid data format
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Signature verification error
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Random number generation error
    #[error("Random number generation failed: {0}")]
    Rng(String),

    /// Invalid cryptographic scheme version
    #[error("Unsupported crypto version: {0}")]
    UnsupportedVersion(u8),

    /// Key derivation failed
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Key derivation failed with context
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Invalid signature format
    #[error("Invalid signature format")]
    InvalidSignature,
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(_: aes_gcm::Error) -> Self {
        CryptoError::AesDecryption("AES-GCM authentication failed".to_string())
    }
}
impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Serialization(e.to_string())
    }
}
