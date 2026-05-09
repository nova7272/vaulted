//! HTTP клиент для Oracle API
//!
//! Все операции требуют JWT токен авторизации.

use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{ClientError, Result};
use crate::crypto::FileManifest;

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
                        .map_err(|e| crate::error::ClientError::Config(
                            format!("Invalid TLS certificate at {}: {}", cert_path, e)
                        ))?;

                    builder = builder
                        .add_root_certificate(cert)
                        .tls_built_in_root_certs(false);

                    tracing::info!("TLS certificate pinned from {}", cert_path);
                }
                Err(e) => {
                    tracing::warn!("Could not read TLS cert at {}: {} — proceeding without pinning", cert_path, e);
                }
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
    pub async fn get_auth_challenge(&self, wallet_address: &str) -> Result<AuthChallengeResponse> {
        self.get(&format!("/api/v1/auth/challenge/{}", wallet_address)).await
    }

    /// Exchange signed challenge for JWT token
    pub async fn get_auth_token(&self, request: &AuthTokenRequest) -> Result<AuthTokenResponse> {
        self.post("/api/v1/auth/token", request).await
    }

    /// Exchange SignIn signature for JWT token (no challenge needed)
    pub async fn get_token_from_signin(&self, request: &SignInTokenRequest) -> Result<AuthTokenResponse> {
        self.post("/api/v1/auth/token-signin", request).await
    }

    /// Get current user info
    pub async fn get_me(&self) -> Result<UserInfoResponse> {
        self.get("/api/v1/auth/me").await
    }

    /// Logout (invalidate token)
    pub async fn logout(&self) -> Result<serde_json::Value> {
        self.post("/api/v1/auth/logout", &serde_json::json!({})).await
    }

    // ==================== User API ====================

    /// Регистрирует пользователя (или обновляет PRE публичный ключ)
    pub async fn register_user(&self, request: &RegisterUserRequest) -> Result<RegisterUserResponse> {
        self.post("/api/v1/users/register", request).await
    }

    /// Получает публичный ключ PRE пользователя
    pub async fn get_user_public_key(&self, wallet_address: &str) -> Result<UserPublicKeyResponse> {
        self.get(&format!("/api/v1/users/{}/public-key", wallet_address)).await
    }

    // ==================== File API ====================

    /// Регистрирует зашифрованный файл с привязкой к NFT
    pub async fn register_file(&self, request: &RegisterFileRequest) -> Result<RegisterFileResponse> {
        self.post("/api/v1/files/register", request).await
    }

    /// Запрашивает доступ к файлу по NFT
    pub async fn request_file_access(&self, nft_token_id: &str) -> Result<FileAccessResponse> {
        self.get(&format!("/api/v1/files/{}/access", nft_token_id)).await
    }

    /// Получает URL для загрузки фрагмента
    pub async fn get_fragment_upload_url(&self, request: &FragmentUploadRequest) -> Result<FragmentUploadResponse> {
        self.post("/api/v1/files/fragments/upload-url", request).await
    }

    /// Подтверждает загрузку фрагмента
    pub async fn confirm_fragment_upload(&self, request: &ConfirmUploadRequest) -> Result<()> {
        self.post("/api/v1/files/fragments/confirm", request).await
    }

    // ==================== Vault API ====================

    /// Создаёт vault (минтит NFT)
    pub async fn create_vault(&self, request: &CreateVaultRequest) -> Result<CreateVaultResponse> {
        self.post("/api/v1/vault/create", request).await
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
        self.get(&format!("/api/v1/transfers/{}/status", transfer_id)).await
    }

    /// Завершает передачу после подтверждения на блокчейне
    pub async fn complete_transfer(&self, request: &CompleteTransferRequest) -> Result<CompleteTransferResponse> {
        self.post("/api/v1/transfers/complete", request).await
    }

    // ==================== NFT API ====================

    /// Получает метаданные NFT
    pub async fn get_nft_metadata(&self, nft_token_id: &str) -> Result<NftMetadataResponse> {
        self.get(&format!("/api/v1/nfts/{}/metadata", nft_token_id)).await
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

/// Request for auth token from SignIn (no challenge)
#[derive(Debug, Serialize)]
pub struct SignInTokenRequest {
    pub wallet_address: String,
    pub public_key: String,
    pub signature: String,
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

/// Ответ создания vault
#[derive(Debug, Deserialize)]
pub struct CreateVaultResponse {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub xaman_link: String,
    pub nft_uri: String,
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
    pub xaman_link: Option<String>,
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