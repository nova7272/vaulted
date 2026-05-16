//! Vaulted wallet signing compatibility types.
//!
//! Vaulted wallet mode does not use external wallet signatures for
//! authentication, key derivation, or encryption. This module keeps disabled
//! compatibility entry points until every caller uses Vaulted QR login and
//! local Vaulted XRPL wallet signing flows.

use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

/// Disabled external-wallet client placeholder.
#[derive(Debug, Clone)]
pub struct WalletSigningAuth;

impl WalletSigningAuth {
    /// Create a disabled legacy client placeholder.
    pub fn new(_api_key: String, _api_secret: String) -> Self {
        Self
    }

    /// Create a disabled legacy client placeholder.
    pub fn with_oracle_url(_api_key: String, _api_secret: String, _oracle_url: String) -> Self {
        Self
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_sign_in_request(&self) -> Result<VaultedSigningRequest> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_key_derivation_request(
        &self,
        _wallet_address: &str,
    ) -> Result<VaultedSigningRequest> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_sign_in(&self, _payload: &VaultedSigningRequest) -> Result<SignInResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_key_derivation(
        &self,
        _payload: &VaultedSigningRequest,
    ) -> Result<KeyDerivationResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_signature(
        &self,
        _payload: &VaultedSigningRequest,
        _timeout_secs: u64,
    ) -> Result<PayloadResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_payload<T: Serialize>(&self, _request: T) -> Result<VaultedSigningRequest> {
        Err(disabled())
    }
}

fn disabled() -> ClientError {
    ClientError::Auth(
        "External-wallet signing is disabled in Vaulted wallet mode; use Vaulted QR login or Vaulted XRPL wallet signing".to_string(),
    )
}

/// Vaulted signing request shape used for QR/mobile signing flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedSigningRequest {
    /// Signing request UUID.
    pub uuid: String,
    /// QR PNG.
    pub qr_png: String,
    /// QR URI.
    pub qr_uri: String,
    /// Websocket URL.
    pub websocket_url: String,
    /// Expiration timestamp.
    pub expires_at: Option<String>,
    /// Challenge.
    pub challenge: Option<String>,
}

/// Legacy sign-in result kept for temporary UI compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInResult {
    /// Wallet address.
    pub wallet_address: String,
    /// Public key, when available.
    pub public_key: Option<String>,
    /// Transaction signature, when available.
    pub txn_signature: Option<String>,
    /// Transaction id.
    pub txid: String,
}

/// Legacy key derivation result kept for temporary UI compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDerivationResult {
    /// Wallet address.
    pub wallet_address: String,
    /// Signature.
    pub signature: String,
}

/// Legacy generic payload result kept for temporary UI compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadResult {
    /// Wallet address.
    pub wallet_address: String,
    /// Public key, when available.
    pub public_key: Option<String>,
    /// Transaction signature, when available.
    pub txn_signature: Option<String>,
    /// Transaction id.
    pub txid: String,
}
