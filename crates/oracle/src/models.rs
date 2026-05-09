//! Модели данных Oracle

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Пользователь (кошелёк XRPL)
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub wallet_address: String,
    pub pre_public_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Метаданные NFT
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct NftMetadata {
    pub id: Uuid,
    pub nft_token_id: String,
    pub owner_id: Uuid,
    pub encrypted_aes_key: String,
    pub metadata_hash: String,
    pub crypto_version: i16,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Манифест файла
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FileManifestRow {
    pub id: Uuid,
    pub nft_metadata_id: Uuid,
    pub encrypted_filename: String,
    pub original_size: i64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragment_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Фрагмент файла
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FileFragment {
    pub id: Uuid,
    pub manifest_id: Uuid,
    pub fragment_index: i32,
    pub fragment_size: i64,
    pub encrypted_hash: String,
    pub storage_node_id: String,
    pub storage_key: String,
    pub replication_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Storage node
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct StorageNode {
    pub id: String,
    pub endpoint_url: String,
    pub region: String,
    pub status: String,
    pub total_space_bytes: i64,
    pub used_space_bytes: i64,
    pub last_health_check: Option<DateTime<Utc>>,
    pub health_check_failures: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Запрос на передачу NFT
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct TransferRequest {
    pub id: Uuid,
    pub nft_metadata_id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub status: String,
    pub re_encrypted_aes_key: Option<String>,
    pub error_message: Option<String>,
    pub xrpl_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Статус передачи
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferStatus::Pending => write!(f, "pending"),
            TransferStatus::Processing => write!(f, "processing"),
            TransferStatus::Completed => write!(f, "completed"),
            TransferStatus::Failed => write!(f, "failed"),
            TransferStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for TransferStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(TransferStatus::Pending),
            "processing" => Ok(TransferStatus::Processing),
            "completed" => Ok(TransferStatus::Completed),
            "failed" => Ok(TransferStatus::Failed),
            "cancelled" => Ok(TransferStatus::Cancelled),
            _ => Err(format!("Unknown transfer status: {}", s)),
        }
    }
}

/// Статус NFT
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NftStatus {
    Active,
    Transferring,
    Archived,
}

impl std::fmt::Display for NftStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftStatus::Active => write!(f, "active"),
            NftStatus::Transferring => write!(f, "transferring"),
            NftStatus::Archived => write!(f, "archived"),
        }
    }
}

/// Запись аудита
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub nft_token_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

// ==================== API DTOs ====================

/// Запрос регистрации пользователя
#[derive(Debug, Deserialize)]
pub struct RegisterUserRequest {
    pub wallet_address: String,
    pub pre_public_key: String,
    pub signature: String,
}

/// Ответ регистрации пользователя
#[derive(Debug, Serialize)]
pub struct RegisterUserResponse {
    pub user_id: Uuid,
    pub wallet_address: String,
    pub created: bool,
}

/// Запрос регистрации файла
#[derive(Debug, Deserialize)]
pub struct RegisterFileRequest {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub manifest: FileManifestDto,
    pub metadata_hash: String,
}

/// DTO манифеста файла
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestDto {
    pub encrypted_filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragments: Vec<FileFragmentDto>,
}

/// DTO фрагмента файла
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFragmentDto {
    pub index: u32,
    pub size: u64,
    pub encrypted_hash: String,
    #[serde(default)]
    pub storage_id: String,
    #[serde(default)]
    pub storage_key: String,
}

/// Ответ регистрации файла
#[derive(Debug, Serialize)]
pub struct RegisterFileResponse {
    pub file_id: Uuid,
    pub nft_token_id: String,
    pub fragments_count: u32,
}

/// Ответ с доступом к файлу
#[derive(Debug, Serialize)]
pub struct FileAccessResponse {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub manifest: FileManifestDto,
    pub fragment_urls: Vec<FragmentDownloadInfo>,
    pub created_at: Option<String>,
    /// True if on-chain NFT owner differs from PRE key holder in Oracle DB
    /// Client should show warning: "NFT was transferred outside the app"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_key_mismatch: Option<bool>,
    /// Wallet address that holds the PRE encryption key for this file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_key_owner: Option<String>,
    /// On-chain owner (may differ from pre_key_owner after external transfer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_owner: Option<String>,
}

/// Информация для скачивания фрагмента
#[derive(Debug, Serialize)]
pub struct FragmentDownloadInfo {
    pub index: u32,
    pub url: String,
    pub size: u64,
    pub hash: String,
}

/// Запрос URL для загрузки фрагмента
#[derive(Debug, Deserialize)]
pub struct FragmentUploadRequest {
    pub file_id: Uuid,
    pub fragment_index: u32,
    pub fragment_hash: String,
    pub fragment_size: u64,
}

/// Ответ с URL для загрузки
#[derive(Debug, Serialize)]
pub struct FragmentUploadResponse {
    pub upload_url: String,
    pub storage_node_id: String,
    pub storage_key: String,
}

/// Подтверждение загрузки
#[derive(Debug, Deserialize)]
pub struct ConfirmUploadRequest {
    pub file_id: Uuid,
    pub fragment_index: u32,
    pub storage_node_id: String,
    pub storage_key: String,
}

/// Запрос на передачу NFT
#[derive(Debug, Deserialize)]
pub struct InitiateTransferRequest {
    pub nft_token_id: String,
    pub from_address: String,
    pub to_address: String,
    /// Base64-encoded kfrag + sender_public_key
    pub re_encryption_key: String,
}

/// Ответ на инициацию передачи
#[derive(Debug, Serialize)]
pub struct InitiateTransferResponse {
    pub transfer_id: Uuid,
    pub status: String,
}

/// Статус передачи
#[derive(Debug, Serialize)]
pub struct TransferStatusResponse {
    pub transfer_id: Uuid,
    pub status: String,
    pub re_encrypted_aes_key: Option<String>,
    pub error: Option<String>,
}

/// Завершение передачи
#[derive(Debug, Deserialize)]
pub struct CompleteTransferRequest {
    pub transfer_id: Uuid,
    pub xrpl_tx_hash: String,
}

/// Ответ завершения передачи
#[derive(Debug, Serialize)]
pub struct CompleteTransferResponse {
    pub success: bool,
    pub new_owner: String,
}

/// Публичный ключ пользователя
#[derive(Debug, Serialize)]
pub struct UserPublicKeyResponse {
    pub wallet_address: String,
    pub pre_public_key: String,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: String,
}