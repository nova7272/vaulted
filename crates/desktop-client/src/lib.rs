//! XRPL Vault Desktop Client
//!
//! Клиентское приложение для безопасного хранения файлов
//! с NFT-based access control на блокчейне XRPL.
//!
//! ## Архитектура
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Desktop Client                        │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐ │
//! │  │  Auth   │  │ Crypto  │  │  XRPL   │  │   Oracle    │ │
//! │  │ (Xaman) │  │ AES+PRE │  │  Client │  │   Client    │ │
//! │  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬──────┘ │
//! │       │            │            │              │         │
//! │       └────────────┴─────┬──────┴──────────────┘         │
//! │                          │                               │
//! │                    ┌─────┴─────┐                         │
//! │                    │  Keystore │                         │
//! │                    │  (secure) │                         │
//! │                    └───────────┘                         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Безопасность
//!
//! - Приватные ключи НИКОГДА не покидают устройство
//! - Шифрование/расшифровка происходит ТОЛЬКО локально
//! - Oracle получает только зашифрованные данные и re-encryption keys

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod auth;
pub mod commands;
pub mod crypto;
pub mod error;
pub mod oracle;
pub mod state;
pub mod storage;
pub mod xrpl;
pub mod nft_image;
pub mod archive;

pub use error::{ClientError, Result};
pub use state::AppState;
