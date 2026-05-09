//! XRPL Vault Oracle Server
//!
//! Центральный сервер для управления зашифрованными файлами
//! с NFT-based access control.
//!
//! ## Ответственности Oracle
//!
//! 1. **Хранение метаданных** — связь NFT ↔ зашифрованные файлы
//! 2. **PRE перешифровка** — при передаче NFT трансформирует encrypted_aes_key
//! 3. **Координация хранения** — распределяет фрагменты по storage nodes
//! 4. **Верификация доступа** — проверяет владение NFT перед выдачей данных
//!
//! ## Что Oracle НЕ видит
//!
//! - Приватные ключи пользователей
//! - AES-ключи в открытом виде
//! - Расшифрованное содержимое файлов

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

pub use auth::{AuthenticatedUser, OptionalAuth, Claims, create_token, verify_token};
pub use config::Config;
pub use error::{ApiError, Result};
pub use migrations::{run_migrations, run_embedded_migrations};
pub use storage_token::{StorageToken, StorageUrlGenerator, sign_storage_token, verify_storage_token};
pub use sync::{XrplSyncService, SyncConfig, SyncStats, SyncAction};
pub use xrpl_verify::verify_xrpl_signature;