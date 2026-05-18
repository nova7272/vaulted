//! Типы ошибок криптографического модуля

use thiserror::Error;

/// Результат криптографических операций
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Ошибки криптографических операций
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Ошибка шифрования AES
    #[error("AES encryption failed: {0}")]
    AesEncryption(String),

    /// Ошибка расшифровки AES
    #[error("AES decryption failed: {0}")]
    AesDecryption(String),

    /// Неверный размер ключа
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Ожидаемый размер в байтах
        expected: usize,
        /// Фактический размер в байтах
        actual: usize,
    },

    /// Неверный размер nonce
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Ожидаемый размер в байтах
        expected: usize,
        /// Фактический размер в байтах
        actual: usize,
    },

    /// Ошибка Proxy Re-Encryption
    #[error("PRE operation failed: {0}")]
    PreError(String),

    /// Ошибка PRE шифрования
    #[error("PRE encryption failed: {0}")]
    PreEncryption(String),

    /// Ошибка PRE расшифровки
    #[error("PRE decryption failed: {0}")]
    PreDecryption(String),

    /// Ошибка генерации PRE ключа
    #[error("PRE key generation failed: {0}")]
    PreKeyGeneration(String),

    /// Ошибка PRE перешифровки
    #[error("PRE re-encryption failed: {0}")]
    PreReEncryption(String),

    /// Неверный ключ
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Неверные данные
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Ошибка генерации re-encryption key
    #[error("Failed to generate re-encryption key: {0}")]
    ReKeyGeneration(String),

    /// Ошибка перешифровки
    #[error("Re-encryption failed: {0}")]
    ReEncryption(String),

    /// Неверный формат данных
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    /// Ошибка сериализации
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Ошибка десериализации
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Ошибка верификации подписи
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Ошибка генерации случайных чисел
    #[error("Random number generation failed: {0}")]
    Rng(String),

    /// Неверная версия криптографической схемы
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
