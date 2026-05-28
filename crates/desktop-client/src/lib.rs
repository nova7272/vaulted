//! XRPL Vault Desktop Client
//!
//! Client application for secure file storage
//! with NFT-based access control on the XRPL blockchain.
//!
//! ## Architecture
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
//! ## Security
//!
//! - Private keys NEVER leave the device
//! - Encryption/decryption happens ONLY locally
//! - Oracle receives only encrypted data and re-encryption keys

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
