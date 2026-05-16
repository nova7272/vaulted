//! Типы ошибок клиентского приложения

use thiserror::Error;

/// Результат операций клиента
pub type Result<T> = std::result::Result<T, ClientError>;

/// Ошибки клиентского приложения
#[derive(Error, Debug)]
pub enum ClientError {
    /// Ошибка авторизации
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Ошибка валидации
    #[error("Validation error: {0}")]
    Validation(String),

    /// Ошибка внешнего wallet/signing layer
    #[error("External wallet error: {0}")]
    ExternalWallet(String),

    /// Сессия не найдена
    #[error("No active session. Please login first.")]
    NoSession,

    /// Сессия истекла
    #[error("Session expired. Please login again.")]
    SessionExpired,

    /// Ошибка криптографии
    #[error("Crypto error: {0}")]
    Crypto(#[from] xrpl_vault_crypto_core::CryptoError),

    /// Ошибка XRPL
    #[error("XRPL error: {0}")]
    Xrpl(String),

    /// NFT не найден
    #[error("NFT not found: {0}")]
    NftNotFound(String),

    /// Пользователь не владелец NFT
    #[error("You are not the owner of this NFT")]
    NotNftOwner,

    /// Ошибка Oracle API
    #[error("Oracle API error: {0}")]
    Oracle(String),

    /// Ошибка HTTP
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Ошибка WebSocket
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Ошибка файловой системы
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),

    /// Файл слишком большой
    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    /// Ошибка keystore
    /// Неверные данные
    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Keystore error: {0}")]
    Keystore(String),

    /// Ошибка сериализации
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Неверная конфигурация
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
