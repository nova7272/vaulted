//! Legacy Xaman compatibility types.
//!
//! Vaulted wallet mode does not use Xaman for authentication, key derivation,
//! transaction signing, or NFT operations. This module exists only so older
//! command signatures can compile until the UI is fully migrated to Vaulted QR
//! login and Vaulted XRPL wallet signing flows.

use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

/// Legacy Xaman client placeholder.
#[derive(Debug, Clone)]
pub struct XamanAuth;

impl XamanAuth {
    /// Create a disabled legacy client placeholder.
    pub fn new(_api_key: String, _api_secret: String) -> Self {
        Self
    }

    /// Create a disabled legacy client placeholder.
    pub fn with_oracle_url(_api_key: String, _api_secret: String, _oracle_url: String) -> Self {
        Self
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_sign_in_request(&self) -> Result<XamanPayload> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_key_derivation_request(
        &self,
        _wallet_address: &str,
    ) -> Result<XamanPayload> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_sign_in(&self, _payload: &XamanPayload) -> Result<SignInResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_key_derivation(
        &self,
        _payload: &XamanPayload,
    ) -> Result<KeyDerivationResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn wait_for_signature(
        &self,
        _payload: &XamanPayload,
        _timeout_secs: u64,
    ) -> Result<PayloadResult> {
        Err(disabled())
    }

    /// Disabled in Vaulted wallet mode.
    pub async fn create_payload<T: Serialize>(&self, _request: T) -> Result<XamanPayload> {
        Err(disabled())
    }
}

fn disabled() -> ClientError {
    ClientError::Auth(
        "Xaman is disabled in Vaulted wallet mode; use Vaulted QR login or Vaulted XRPL wallet signing".to_string(),
    )
}

/// Vaulted signing request shape used for QR/mobile signing flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedSigningRequest {
    /// Legacy payload UUID.
    pub uuid: String,
    /// Legacy QR PNG.
    pub qr_png: String,
    /// Legacy QR URI.
    pub qr_uri: String,
    /// Legacy websocket URL.
    pub websocket_url: String,
    /// Legacy expiration timestamp.
    pub expires_at: Option<String>,
    /// Legacy challenge.
    pub challenge: Option<String>,
}

/// Backward-compatible alias while remaining legacy call sites are migrated.
#[deprecated(note = "use VaultedSigningRequest instead")]
pub type XamanPayload = VaultedSigningRequest;

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
