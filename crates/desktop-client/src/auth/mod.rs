//! Vaulted authentication module.
//!
//! Primary auth is Vaulted seed identity + QR login.
//! The `wallet_signing` module contains disabled external-wallet compatibility shims.

pub mod session;
pub mod wallet_signing;

pub use session::Session;
pub use wallet_signing::{
    KeyDerivationResult, SignInResult, VaultedSigningRequest, WalletSigningAuth,
};
