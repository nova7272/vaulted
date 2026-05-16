//! HTTP клиент для Oracle API
//!
//! Все операции требуют JWT токен авторизации.

use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::crypto::FileManifest;
use crate::error::{ClientError, Result};

/// Конфигурация Oracle клиента
#[derive(Debug, Clone)]
pub struct OracleConfig {
    pub base_url: String,
    pub timeout_secs: u64,
    /// Path to Oracle's TLS certificate for pinning (optional)
    pub tls_cert_path: Option<String>,
    /// Minimum TLS version (default: TLS 1.2)
    pub min_tls_version: Option<String>,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".to_string(),
            timeout_secs: 120,
            tls_cert_path: None,
            min_tls_version: None,
        }
    }
}

/// HTTP клиент для Oracle API
pub struct OracleClient {
    client: Client,
    config: OracleConfig,
    auth_token: Option<String>,
    device_fingerprint: Option<String>,
}

impl OracleClient {
    /// Создаёт новый клиент с optional certificate pinning
    pub fn new(config: OracleConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .connect_timeout(std::time::Duration::from_secs(3));

        // Certificate pinning: if cert path is provided, pin to that certificate
        if let Some(ref cert_path) = config.tls_cert_path {
            match std::fs::read(cert_path) {
                Ok(cert_bytes) => {
                    let cert = reqwest::Certificate::from_pem(&cert_bytes)
                        .or_else(|_| reqwest::Certificate::from_der(&cert_bytes))
                        .map_err(|e| {
                            crate::error::ClientError::Config(format!(
                                "Invalid TLS certificate at {}: {}",
                                cert_path, e
                            ))
                        })?;

                    builder = builder
                        .add_root_certificate(cert)
                        .tls_built_in_root_certs(false);

                    tracing::info!("TLS certificate pinned from {}", cert_path);
                },
                Err(e) => {
                    tracing::warn!(
                        "Could not read TLS cert at {}: {} — proceeding without pinning",
                        cert_path,
                        e
                    );
                },
            }
        }

        if config.base_url.starts_with("https://") {
            builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);
        }

        let client = builder.build()?;

        Ok(Self {
            client,
            config,
            auth_token: None,
            device_fingerprint: None,
        })
    }

    /// Устанавливает токен авторизации
    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    /// Sets device fingerprint for request binding
    pub fn set_device_fingerprint(&mut self, fingerprint: String) {
        self.device_fingerprint = Some(fingerprint);
    }

    /// Возвращает базовый URL
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Adds common headers (auth + device fingerprint) to request
    fn apply_headers(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.auth_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(ref dfp) = self.device_fingerprint {
            request = request.header("X-Device-Fingerprint", dfp.as_str());
        }
        request
    }

    /// Выполняет GET запрос
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);
        let request = self.apply_headers(self.client.get(&url));

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Выполняет POST запрос
    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);
        let request = self.apply_headers(self.client.post(&url).json(body));

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Обрабатывает ответ
    async fn handle_response<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(ClientError::Oracle(format!(
                "HTTP {}: {}",
                status, error_text
            )))
        }
    }

    // ==================== Auth API ====================

    /// Get authentication challenge for wallet
    /// Get login challenge before wallet is known
    pub async fn get_login_challenge(&self) -> Result<AuthChallengeResponse> {
        self.get("/api/v1/auth/login-challenge").await
    }

    pub async fn get_auth_challenge(&self, wallet_address: &str) -> Result<AuthChallengeResponse> {
        self.get(&format!("/api/v1/auth/challenge/{}", wallet_address))
            .await
    }

    /// Exchange signed challenge for JWT token
    pub async fn get_auth_token(&self, request: &AuthTokenRequest) -> Result<AuthTokenResponse> {
        self.post("/api/v1/auth/token", request).await
    }

    /// Get current user info
    pub async fn get_me(&self) -> Result<UserInfoResponse> {
        self.get("/api/v1/auth/me").await
    }

    /// Logout (invalidate token)
    pub async fn logout(&self) -> Result<serde_json::Value> {
        self.post("/api/v1/auth/logout", &serde_json::json!({}))
            .await
    }

    // ==================== QR Login API ====================

    /// Starts QR login for mobile approval.
    pub async fn start_qr_login(
        &self,
        request: &QrLoginStartRequest,
    ) -> Result<QrLoginStartApiResponse> {
        self.post("/api/v1/auth/qr/start", request).await
    }

    /// Poll QR login status.
    pub async fn qr_login_status(&self, login_request_id: &str) -> Result<QrLoginStatusResponse> {
        self.get(&format!("/api/v1/auth/qr/status/{}", login_request_id))
            .await
    }

    /// Confirm QR login from a mobile/trusted device.
    pub async fn confirm_qr_login(
        &self,
        request: &QrLoginConfirmRequest,
    ) -> Result<QrLoginConfirmResponse> {
        self.post("/api/v1/auth/qr/confirm", request).await
    }

    /// Starts QR device pairing for mobile approval.
    pub async fn start_qr_device_pairing(
        &self,
        request: &QrPairDeviceStartRequest,
    ) -> Result<QrPairDeviceStartApiResponse> {
        self.post("/api/v1/auth/qr/pair/start", request).await
    }

    /// Poll QR device pairing status.
    pub async fn qr_device_pairing_status(
        &self,
        pairing_request_id: &str,
    ) -> Result<QrPairDeviceStatusResponse> {
        self.get(&format!(
            "/api/v1/auth/qr/pair/status/{}",
            pairing_request_id
        ))
        .await
    }

    /// Confirm QR device pairing from a trusted device.
    pub async fn confirm_qr_device_pairing(
        &self,
        request: &QrPairDeviceConfirmRequest,
    ) -> Result<QrPairDeviceConfirmResponse> {
        self.post("/api/v1/auth/qr/pair/confirm", request).await
    }

    /// Starts QR XRPL transaction signing for mobile/trusted-device approval.
    pub async fn start_qr_xrpl_signing(
        &self,
        request: &QrXrplSigningStartRequest,
    ) -> Result<QrXrplSigningStartApiResponse> {
        self.post("/api/v1/auth/qr/xrpl-sign/start", request).await
    }

    /// Poll QR XRPL signing status.
    pub async fn qr_xrpl_signing_status(
        &self,
        signing_request_id: &str,
    ) -> Result<QrXrplSigningStatusResponse> {
        self.get(&format!(
            "/api/v1/auth/qr/xrpl-sign/status/{}",
            signing_request_id
        ))
        .await
    }

    /// Confirm QR XRPL transaction signing from a trusted device.
    pub async fn confirm_qr_xrpl_signing(
        &self,
        request: &QrXrplSigningConfirmRequest,
    ) -> Result<QrXrplSigningConfirmResponse> {
        self.post("/api/v1/auth/qr/xrpl-sign/confirm", request)
            .await
    }

    /// Starts QR file grant approval for mobile/trusted-device approval.
    pub async fn start_qr_file_grant_approval(
        &self,
        request: &QrFileGrantStartRequest,
    ) -> Result<QrFileGrantStartApiResponse> {
        self.post("/api/v1/auth/qr/grant/start", request).await
    }

    /// Poll QR file grant approval status.
    pub async fn qr_file_grant_approval_status(
        &self,
        grant_request_id: &str,
    ) -> Result<QrFileGrantStatusResponse> {
        self.get(&format!(
            "/api/v1/auth/qr/grant/status/{}",
            grant_request_id
        ))
        .await
    }

    /// Confirm QR file grant approval from a trusted device.
    pub async fn confirm_qr_file_grant_approval(
        &self,
        request: &QrFileGrantConfirmRequest,
    ) -> Result<QrFileGrantConfirmResponse> {
        self.post("/api/v1/auth/qr/grant/confirm", request).await
    }

    // ==================== User API ====================

    /// Регистрирует пользователя (или обновляет PRE публичный ключ)
    pub async fn register_user(
        &self,
        request: &RegisterUserRequest,
    ) -> Result<RegisterUserResponse> {
        self.post("/api/v1/users/register", request).await
    }

    /// Получает публичный ключ PRE пользователя
    pub async fn get_user_public_key(&self, wallet_address: &str) -> Result<UserPublicKeyResponse> {
        self.get(&format!("/api/v1/users/{}/public-key", wallet_address))
            .await
    }

    // ==================== Vaulted Identity / Manifest API ====================

    /// Registers a seed-based Vaulted identity public record.
    pub async fn register_vaulted_identity(
        &self,
        request: &RegisterVaultedIdentityRequest,
    ) -> Result<RegisterVaultedIdentityResponse> {
        self.post("/api/v1/identity/register", request).await
    }

    /// Gets a public Vaulted identity record by id.
    pub async fn get_vaulted_identity_public(
        &self,
        identity_id: &str,
    ) -> Result<PublicVaultedIdentityResponse> {
        self.get(&format!("/api/v1/identity/{}", identity_id)).await
    }

    /// Stores a TOFU/manual trust decision for a recipient encryption key.
    pub async fn trust_recipient_key(
        &self,
        request: &TrustRecipientKeyRequest,
    ) -> Result<RecipientKeyTrustResponse> {
        self.post("/api/v1/identity/trust-recipient-key", request)
            .await
    }

    /// Revokes a TOFU/manual trust decision for a recipient encryption key.
    pub async fn revoke_recipient_key_trust(
        &self,
        request: &RevokeRecipientKeyTrustRequest,
    ) -> Result<RecipientKeyTrustResponse> {
        self.post("/api/v1/identity/trust-recipient-key/revoke", request)
            .await
    }

    /// Checks whether a recipient encryption key fingerprint is already trusted.
    pub async fn recipient_key_trust_status(
        &self,
        owner_identity_id: &str,
        recipient_identity_id: &str,
        fingerprint: Option<&str>,
    ) -> Result<RecipientKeyTrustResponse> {
        let path = match fingerprint {
            Some(fp) if !fp.trim().is_empty() => format!(
                "/api/v1/identity/trust-recipient-key?owner_identity_id={}&recipient_identity_id={}&fingerprint={}",
                owner_identity_id, recipient_identity_id, fp
            ),
            _ => format!(
                "/api/v1/identity/trust-recipient-key?owner_identity_id={}&recipient_identity_id={}",
                owner_identity_id, recipient_identity_id
            ),
        };
        self.get(&path).await
    }

    /// Lists registered devices for a Vaulted identity.
    pub async fn list_identity_devices(
        &self,
        identity_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<IdentityDeviceResponse>> {
        self.get(&format!(
            "/api/v1/identity/devices?identity_id={}&include_revoked={}",
            identity_id, include_revoked
        ))
        .await
    }

    /// Revokes/deactivates a registered device for a Vaulted identity.
    pub async fn revoke_identity_device(
        &self,
        device_id: &str,
        identity_id: &str,
    ) -> Result<IdentityDeviceResponse> {
        self.post(
            &format!("/api/v1/identity/devices/{}/revoke", device_id),
            &RevokeIdentityDeviceRequest {
                identity_id: identity_id.to_string(),
            },
        )
        .await
    }

    /// Gets a vault object by linked NFT token id.
    pub async fn get_vault_object_by_nft(&self, nft_token_id: &str) -> Result<VaultObjectResponse> {
        self.get(&format!("/api/v1/vault-objects/by-nft/{}", nft_token_id))
            .await
    }

    /// Registers a signed manifest pointer. Oracle is an index/cache only.
    pub async fn register_vault_object(
        &self,
        request: &RegisterVaultObjectRequest,
    ) -> Result<VaultObjectResponse> {
        self.post("/api/v1/vault-objects/register", request).await
    }

    /// Gets a signed manifest pointer.
    pub async fn get_vault_object(&self, vault_object_id: &str) -> Result<VaultObjectResponse> {
        self.get(&format!("/api/v1/vault-objects/{}", vault_object_id))
            .await
    }

    /// Creates a signed share grant.
    pub async fn create_grant(&self, request: &CreateGrantRequest) -> Result<GrantResponse> {
        self.post("/api/v1/grants", request).await
    }

    /// Lists incoming grants for a Vaulted identity.
    pub async fn incoming_grants(&self, identity_id: &str) -> Result<Vec<GrantResponse>> {
        self.get(&format!(
            "/api/v1/grants/incoming?identity_id={}",
            identity_id
        ))
        .await
    }

    /// Returns grant-scoped encrypted file metadata and fragment URLs.
    /// Lists active outgoing grants owned by a Vaulted identity.
    pub async fn outgoing_grants(&self, owner_identity_id: &str) -> Result<Vec<GrantResponse>> {
        self.get(&format!(
            "/api/v1/grants/outgoing?owner_identity_id={}",
            owner_identity_id
        ))
        .await
    }

    /// Revokes an active grant owned by a Vaulted identity.
    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        owner_identity_id: &str,
    ) -> Result<GrantResponse> {
        self.post(
            &format!("/api/v1/grants/{}/revoke", grant_id),
            &serde_json::json!({ "owner_identity_id": owner_identity_id }),
        )
        .await
    }

    pub async fn grant_file_access(
        &self,
        grant_id: &str,
        identity_id: &str,
    ) -> Result<FileAccessResponse> {
        self.get(&format!(
            "/api/v1/grants/{}/access?identity_id={}",
            grant_id, identity_id
        ))
        .await
    }

    // ==================== File API ====================

    /// Регистрирует зашифрованный файл с привязкой к NFT
    pub async fn register_file(
        &self,
        request: &RegisterFileRequest,
    ) -> Result<RegisterFileResponse> {
        self.post("/api/v1/files/register", request).await
    }

    /// Запрашивает доступ к файлу по NFT
    pub async fn request_file_access(&self, nft_token_id: &str) -> Result<FileAccessResponse> {
        self.get(&format!("/api/v1/files/{}/access", nft_token_id))
            .await
    }

    /// Получает URL для загрузки фрагмента
    pub async fn get_fragment_upload_url(
        &self,
        request: &FragmentUploadRequest,
    ) -> Result<FragmentUploadResponse> {
        self.post("/api/v1/files/fragments/upload-url", request)
            .await
    }

    /// Подтверждает загрузку фрагмента
    pub async fn confirm_fragment_upload(&self, request: &ConfirmUploadRequest) -> Result<()> {
        self.post("/api/v1/files/fragments/confirm", request).await
    }

    // ==================== Vault API ====================

    /// Prepares a vault record. Client performs local NFTokenMint separately.
    pub async fn create_vault(&self, request: &CreateVaultRequest) -> Result<CreateVaultResponse> {
        self.post("/api/v1/vault/create", request).await
    }

    /// Publishes the exact client-generated public NFT metadata before local minting.
    pub async fn publish_vault_metadata(
        &self,
        request: &PublishVaultMetadataRequest,
    ) -> Result<PublishVaultMetadataResponse> {
        self.post("/api/v1/vault/publish-metadata", request).await
    }

    /// Finalizes a locally minted Vaulted object after client-side XRPL signing/submission.
    pub async fn finalize_vault_mint(
        &self,
        request: &FinalizeVaultMintRequest,
    ) -> Result<FinalizeVaultMintResponse> {
        self.post("/api/v1/vault/finalize-mint", request).await
    }

    /// Получает статус vault
    pub async fn get_vault_status(&self, vault_id: &str) -> Result<VaultStatusResponse> {
        self.get(&format!("/api/v1/vault/{}", vault_id)).await
    }

    // ==================== Transfer API ====================

    /// Инициирует передачу NFT (PRE перешифровку)
    pub async fn initiate_transfer(
        &self,
        nft_token_id: &str,
        from_address: &str,
        to_address: &str,
        re_encryption_key: &str,
    ) -> Result<InitiateTransferResponse> {
        let request = TransferRequest {
            nft_token_id: nft_token_id.to_string(),
            from_address: from_address.to_string(),
            to_address: to_address.to_string(),
            re_encryption_key: re_encryption_key.to_string(),
        };
        self.post("/api/v1/transfers/initiate", &request).await
    }

    /// Проверяет статус передачи
    pub async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatusResponse> {
        self.get(&format!("/api/v1/transfers/{}/status", transfer_id))
            .await
    }

    /// Завершает передачу после подтверждения на блокчейне
    pub async fn complete_transfer(
        &self,
        request: &CompleteTransferRequest,
    ) -> Result<CompleteTransferResponse> {
        self.post("/api/v1/transfers/complete", request).await
    }

    // ==================== NFT API ====================

    /// Получает метаданные NFT
    pub async fn get_nft_metadata(&self, nft_token_id: &str) -> Result<NftMetadataResponse> {
        self.get(&format!("/api/v1/nfts/{}/metadata", nft_token_id))
            .await
    }
}

// ==================== Auth Types ====================

/// Response with auth challenge
#[derive(Debug, Deserialize)]
pub struct AuthChallengeResponse {
    pub challenge: String,
    pub expires_in: i64,
}

/// Request for auth token
#[derive(Debug, Serialize)]
pub struct AuthTokenRequest {
    pub wallet_address: String,
    pub public_key: String,
    pub signature: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,
}

/// Response with auth token
#[derive(Debug, Deserialize)]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

/// User info response
#[derive(Debug, Deserialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub wallet_address: String,
    pub public_key: String,
    pub created_at: String,
}

// ==================== QR Login Types ====================

/// QR login start request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStartRequest {
    pub desktop_device_name: Option<String>,
    pub desktop_device_public_key: Option<String>,
}

/// QR login start API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStartApiResponse {
    pub login_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub qr_payload: serde_json::Value,
}

/// QR login status response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStatusResponse {
    pub status: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub identity_id: Option<String>,
    pub expires_in: Option<i64>,
}

/// QR login confirmation request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginConfirmRequest {
    pub login_request_id: String,
    pub identity_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

/// QR login confirmation response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginConfirmResponse {
    pub approved: bool,
    pub status: String,
}

/// QR device pairing start request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStartRequest {
    pub identity_id: String,
    pub desktop_device_name: Option<String>,
    pub desktop_device_public_key: String,
}

/// QR device pairing start API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStartApiResponse {
    pub pairing_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub qr_payload: serde_json::Value,
}

/// QR device pairing status response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStatusResponse {
    pub status: String,
    pub identity_id: Option<String>,
    pub device_id: Option<String>,
    pub paired_at: Option<String>,
}

/// QR device pairing confirmation request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceConfirmRequest {
    pub pairing_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

/// QR device pairing confirmation response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub device_id: String,
}

/// QR XRPL signing start request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStartRequest {
    pub identity_id: String,
    pub xrpl_tx_json: serde_json::Value,
    pub expected_xrpl_account: String,
    pub requester_device_id: Option<String>,
    pub requester_device_name: Option<String>,
    pub human_summary: Option<String>,
}

/// QR XRPL signing start API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStartApiResponse {
    pub signing_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub tx_json_hash: String,
    pub qr_payload: serde_json::Value,
}

/// QR XRPL signing status response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStatusResponse {
    pub status: String,
    pub identity_id: Option<String>,
    pub tx_json_hash: Option<String>,
    pub expected_xrpl_account: Option<String>,
    pub approved_by_device_id: Option<String>,
    pub approval_signature: Option<String>,
    pub approved_at: Option<String>,
}

/// QR XRPL signing confirmation request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningConfirmRequest {
    pub signing_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

/// QR XRPL signing confirmation response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub tx_json_hash: String,
}

/// QR file grant approval start request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStartRequest {
    pub identity_id: String,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub key_envelope: serde_json::Value,
    /// Deprecated compatibility mirror of key_envelope.encrypted_file_key.
    pub encrypted_file_key: Option<String>,
    pub permissions: Vec<String>,
    pub grant_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub requester_device_id: Option<String>,
    pub requester_device_name: Option<String>,
    pub human_summary: Option<String>,
}

/// QR file grant approval start API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStartApiResponse {
    pub grant_request_id: String,
    pub grant_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub grant_context_hash: String,
    pub qr_payload: serde_json::Value,
}

/// QR file grant approval status response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStatusResponse {
    pub status: String,
    pub identity_id: Option<String>,
    pub vault_object_id: Option<String>,
    pub grant_id: Option<String>,
    pub recipient_identity_id: Option<String>,
    pub grant_context_hash: Option<String>,
    pub approved_by_device_id: Option<String>,
    pub approval_signature: Option<String>,
    pub created_grant_id: Option<String>,
    pub approved_at: Option<String>,
}

/// QR file grant approval confirmation request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantConfirmRequest {
    pub grant_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

/// QR file grant approval confirmation response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub grant_id: String,
}

// ==================== User Types ====================

/// Запрос регистрации пользователя
#[derive(Debug, Serialize)]
pub struct RegisterUserRequest {
    pub wallet_address: String,
    pub pre_public_key: String,
    pub signature: String,
}

/// Ответ регистрации пользователя
#[derive(Debug, Deserialize)]
pub struct RegisterUserResponse {
    pub user_id: String,
    pub wallet_address: String,
    pub created: bool,
}

/// Ответ с публичным ключом пользователя
#[derive(Debug, Deserialize)]
pub struct UserPublicKeyResponse {
    pub wallet_address: String,
    pub pre_public_key: String,
}

// ==================== Vaulted Identity / Manifest Types ====================

/// Register seed-based identity public keys with Oracle.
#[derive(Debug, Serialize)]
pub struct RegisterVaultedIdentityRequest {
    pub vaulted_identity_id: String,
    pub encryption_public_key: String,
    pub signing_public_key: String,
    pub device_public_key: String,
    pub linked_wallets: Vec<serde_json::Value>,
    pub protocol_version: String,
}

/// Register identity response.
#[derive(Debug, Deserialize)]
pub struct RegisterVaultedIdentityResponse {
    pub id: String,
    pub created: bool,
    pub protocol_version: String,
}

/// Public Vaulted identity record. Contains public keys only.
#[derive(Debug, Deserialize)]
pub struct PublicVaultedIdentityResponse {
    pub id: String,
    pub encryption_public_key: String,
    pub encryption_public_key_fingerprint: String,
    pub signing_public_key: String,
    pub protocol_version: String,
    pub status: String,
}

/// Request to trust a recipient key fingerprint.
#[derive(Debug, Serialize)]
pub struct TrustRecipientKeyRequest {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    pub recipient_encryption_public_key: String,
    pub recipient_encryption_public_key_fingerprint: String,
    pub trust_source: Option<String>,
    pub trust_level: Option<String>,
}

/// Request to revoke a recipient key trust decision.
#[derive(Debug, Serialize)]
pub struct RevokeRecipientKeyTrustRequest {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    pub recipient_encryption_public_key_fingerprint: Option<String>,
}

/// Recipient key trust response.
#[derive(Debug, Deserialize, Serialize)]
pub struct RecipientKeyTrustResponse {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    pub recipient_encryption_public_key: String,
    pub recipient_encryption_public_key_fingerprint: String,
    pub trusted: bool,
    pub trust_level: String,
    pub trust_source: String,
    pub trusted_at: Option<String>,
    pub revoked_at: Option<String>,
    pub active_recipient_encryption_public_key_fingerprint: Option<String>,
    pub key_rotation_detected: Option<bool>,
    pub trusted_different_key_fingerprint: Option<String>,
    pub trusted_different_key_at: Option<String>,
}

/// Registered identity device response.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IdentityDeviceResponse {
    pub id: String,
    pub identity_id: String,
    pub device_public_key: String,
    pub device_public_key_fingerprint: String,
    pub device_name: Option<String>,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Request to revoke an identity device.
#[derive(Debug, Serialize)]
pub struct RevokeIdentityDeviceRequest {
    pub identity_id: String,
}

/// Register vault object request.
#[derive(Debug, Serialize)]
pub struct RegisterVaultObjectRequest {
    pub id: String,
    pub owner_identity_id: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub nft_chain: Option<String>,
    pub nft_token_id: Option<String>,
    pub manifest: Option<xrpl_vault_crypto_core::VaultedManifest>,
}

/// Vault object response.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultObjectResponse {
    pub id: String,
    pub owner_identity_id: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub nft_chain: Option<String>,
    pub nft_token_id: Option<String>,
    pub status: String,
}

/// Create grant request.
#[derive(Debug, Serialize)]
pub struct CreateGrantRequest {
    pub grant_id: Option<String>,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
    pub key_envelope: serde_json::Value,
    /// Deprecated compatibility mirror of key_envelope.encrypted_file_key.
    pub encrypted_file_key: Option<String>,
    pub owner_signature: String,
}

/// Grant response.
#[derive(Debug, Deserialize)]
pub struct GrantResponse {
    pub id: String,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: serde_json::Value,
    pub expires_at: Option<String>,
    pub key_envelope: serde_json::Value,
    /// Deprecated compatibility mirror of key_envelope.encrypted_file_key.
    pub encrypted_file_key: String,
    pub owner_signature: String,
    pub status: String,
}

// ==================== File Types ====================

/// Запрос регистрации файла
#[derive(Debug, Serialize)]
pub struct RegisterFileRequest {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub manifest: FileManifest,
    pub metadata_hash: String,
}

/// Ответ регистрации файла
#[derive(Debug, Deserialize)]
pub struct RegisterFileResponse {
    pub file_id: String,
    pub nft_token_id: String,
    pub fragments_count: u32,
}

/// Ответ с доступом к файлу
#[derive(Debug, Deserialize)]
pub struct FileAccessResponse {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub manifest: FileManifest,
    pub fragment_urls: Vec<FragmentDownloadInfo>,
}

/// Информация для скачивания фрагмента
#[derive(Debug, Deserialize)]
pub struct FragmentDownloadInfo {
    pub index: u32,
    pub url: String,
    pub size: u64,
    pub hash: String,
}

/// Запрос URL для загрузки фрагмента
#[derive(Debug, Serialize)]
pub struct FragmentUploadRequest {
    pub file_id: String,
    pub fragment_index: u32,
    pub fragment_hash: String,
    pub fragment_size: u64,
}

/// Ответ с URL для загрузки
#[derive(Debug, Deserialize)]
pub struct FragmentUploadResponse {
    pub upload_url: String,
    pub storage_node_id: String,
    pub storage_key: String,
}

/// Подтверждение загрузки фрагмента
#[derive(Debug, Serialize)]
pub struct ConfirmUploadRequest {
    pub file_id: String,
    pub fragment_index: u32,
    pub storage_node_id: String,
    pub storage_key: String,
}

// ==================== Vault Types ====================

/// Запрос создания vault
#[derive(Debug, Serialize)]
pub struct CreateVaultRequest {
    pub wallet_address: String,
    pub pre_public_key: String,
    pub encrypted_aes_key: String,
    pub metadata_hash: String,
    pub manifest: VaultManifest,
}

/// Манифест для Vault API
#[derive(Debug, Serialize)]
pub struct VaultManifest {
    pub encrypted_filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragments: Vec<VaultFragment>,
}

/// Фрагмент для Vault API
#[derive(Debug, Serialize)]
pub struct VaultFragment {
    pub index: u32,
    pub storage_node_id: String,
    pub storage_key: String,
    pub encrypted_hash: String,
    pub size: u64,
}

/// Ответ подготовки vault. `nft_token_id` is a temporary upload key until local mint finalization.
#[derive(Debug, Deserialize)]
pub struct CreateVaultResponse {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub signing_request_uri: String,
    pub nft_uri: String,
}

#[derive(Debug, Serialize)]
pub struct PublishVaultMetadataRequest {
    pub vault_id: String,
    pub manifest_hash: String,
    pub metadata_uri: String,
    pub metadata_json: String,
    pub metadata_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishVaultMetadataResponse {
    pub vault_id: String,
    pub manifest_hash: String,
    pub metadata_uri: String,
    pub metadata_hash: String,
    pub published: bool,
}

#[derive(Debug, Serialize)]
pub struct FinalizeVaultMintRequest {
    pub vault_id: String,
    pub nft_token_id: String,
    pub tx_hash: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct FinalizeVaultMintResponse {
    pub vault_id: String,
    pub nft_token_id: String,
    pub status: String,
}

/// Статус vault
#[derive(Debug, Deserialize)]
pub struct VaultStatusResponse {
    pub vault_id: String,
    pub nft_token_id: String,
    pub status: String,
    pub offer_index: Option<String>,
}

// ==================== Transfer Types ====================

/// Запрос на передачу NFT
#[derive(Debug, Serialize)]
pub struct TransferRequest {
    pub nft_token_id: String,
    pub from_address: String,
    pub to_address: String,
    pub re_encryption_key: String,
}

/// Ответ инициирования трансфера
#[derive(Debug, Deserialize)]
pub struct InitiateTransferResponse {
    pub transfer_id: String,
    pub status: String,
    pub signing_request_uri: Option<String>,
}

/// Статус передачи
#[derive(Debug, Deserialize)]
pub struct TransferStatusResponse {
    pub transfer_id: String,
    pub status: String,
    pub re_encrypted_aes_key: Option<String>,
    pub error: Option<String>,
}

/// Завершение передачи
#[derive(Debug, Serialize)]
pub struct CompleteTransferRequest {
    pub transfer_id: String,
    pub xrpl_tx_hash: String,
}

/// Ответ завершения передачи
#[derive(Debug, Deserialize)]
pub struct CompleteTransferResponse {
    pub success: bool,
    pub new_owner: String,
}

// ==================== NFT Types ====================

/// Метаданные NFT
#[derive(Debug, Deserialize)]
pub struct NftMetadataResponse {
    pub nft_token_id: String,
    pub owner_address: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub manifest: FileManifest,
    pub created_at: String,
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_config_default() {
        let config = OracleConfig::default();
        assert_eq!(config.base_url, "http://localhost:3000");
        assert_eq!(config.timeout_secs, 120);
    }
}
