//! XRPL Vault Crypto Core
//!
//! Cryptographic primitives for the XRPL NFT-based encrypted file vault.

#![warn(missing_docs)]

pub mod aes;
pub mod commitment;
pub mod error;
pub mod key_derivation;
pub mod pre;
pub mod transfer;
pub mod types;
pub mod hash;

// Константы
/// Размер AES-256 ключа в байтах
pub const AES_KEY_SIZE: usize = 32;
/// Размер nonce для AES-GCM
pub const AES_NONCE_SIZE: usize = 12;
/// Текущая версия криптографической схемы
pub const CRYPTO_VERSION: u8 = 1;

pub use aes::{AesKey, AesStreamEncryptor};
pub use commitment::KeyCommitment;
pub use error::{CryptoError, Result};
pub use key_derivation::{DerivedKeys, KeyDerivation};
pub use pre::{EncryptedPreData, PreKeyPair, PrePublicKey, ProxyReEncryption, ReEncryptionKey, ReEncryptedData};
pub use transfer::{TransferProof, TransferService, TransferVerification};
pub use types::*;