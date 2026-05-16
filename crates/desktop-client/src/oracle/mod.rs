//! Модуль связи с Oracle сервером
//!
//! HTTP API для:
//! - Регистрации зашифрованных файлов
//! - Получения доступа к файлам по NFT
//! - Инициирования PRE перешифровки при передаче

pub mod api;

pub use api::{
    CreateVaultRequest, CreateVaultResponse, InitiateTransferResponse, OracleClient, OracleConfig,
    VaultFragment, VaultManifest,
};
