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
//! │  │Vaulted │  │ AES+PRE │  │  Client │  │   Client    │ │
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

#![allow(missing_docs)]
#![warn(clippy::all)]

pub mod archive;
pub mod auth;
pub mod commands;
pub mod crypto;
pub mod error;
pub mod nft_image;
pub mod oracle;
pub mod state;
pub mod storage;
pub mod xrpl;

pub use error::{ClientError, Result};
pub use state::AppState;
