//! Cryptographic operations for desktop client

pub mod decryptor;
pub mod encryptor;
pub mod keys;
pub mod transfer;

pub use decryptor::FileDecryptor;
pub use encryptor::{FileEncryptor, EncryptedFile};
pub use keys::KeyManager;
pub use transfer::LocalTransfer;

// Re-export common types from crypto-core
pub use xrpl_vault_crypto_core::{
    AesKey, AesStreamEncryptor,
    KeyCommitment, TransferProof,
    PreKeyPair, PrePublicKey, EncryptedPreData,
    EncryptedData, FileManifest,
};