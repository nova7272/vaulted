//! Модели данных Oracle

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// Пользователь (кошелёк XRPL)
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub wallet_address: String,
    pub pre_public_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Метаданные NFT
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
/// Seed-based Vaulted identity public record.
#[derive(Debug, Clone, Serialize)]
pub struct VaultedIdentity {
    pub id: String,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub protocol_version: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Registered device for a Vaulted identity.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityDevice {
    pub id: Uuid,
    pub identity_id: String,
    pub device_public_key: String,
    pub device_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// External wallet linked to a Vaulted identity.
#[derive(Debug, Clone, Serialize)]
pub struct LinkedWallet {
    pub id: Uuid,
    pub identity_id: String,
    pub chain: String,
    pub address: String,
    pub proof_signature: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Signed manifest pointer indexed by Oracle.
#[derive(Debug, Clone, Serialize)]
pub struct VaultObject {
    pub id: String,
    pub owner_identity_id: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub nft_chain: Option<String>,
    pub nft_token_id: Option<String>,
    pub manifest_version: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Signed access grant indexed by Oracle.
#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    pub id: Uuid,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub key_envelope: serde_json::Value,
    /// Deprecated compatibility mirror of key_envelope.encrypted_file_key.
    pub encrypted_file_key: String,
    pub permissions: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
    pub owner_signature: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// BEGIN GENERATED MANUAL SQLX FROMROW IMPLS

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for User {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            wallet_address: row.try_get("wallet_address")?,
            pre_public_key: row.try_get("pre_public_key")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for NftMetadata {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            nft_token_id: row.try_get("nft_token_id")?,
            owner_id: row.try_get("owner_id")?,
            encrypted_aes_key: row.try_get("encrypted_aes_key")?,
            metadata_hash: row.try_get("metadata_hash")?,
            crypto_version: row.try_get("crypto_version")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FileManifestRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            nft_metadata_id: row.try_get("nft_metadata_id")?,
            encrypted_filename: row.try_get("encrypted_filename")?,
            original_size: row.try_get("original_size")?,
            mime_type: row.try_get("mime_type")?,
            original_hash: row.try_get("original_hash")?,
            fragment_count: row.try_get("fragment_count")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FileFragment {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            manifest_id: row.try_get("manifest_id")?,
            fragment_index: row.try_get("fragment_index")?,
            fragment_size: row.try_get("fragment_size")?,
            encrypted_hash: row.try_get("encrypted_hash")?,
            storage_node_id: row.try_get("storage_node_id")?,
            storage_key: row.try_get("storage_key")?,
            replication_count: row.try_get("replication_count")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for StorageNode {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            endpoint_url: row.try_get("endpoint_url")?,
            region: row.try_get("region")?,
            status: row.try_get("status")?,
            total_space_bytes: row.try_get("total_space_bytes")?,
            used_space_bytes: row.try_get("used_space_bytes")?,
            last_health_check: row.try_get("last_health_check")?,
            health_check_failures: row.try_get("health_check_failures")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TransferRequest {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            nft_metadata_id: row.try_get("nft_metadata_id")?,
            from_user_id: row.try_get("from_user_id")?,
            to_user_id: row.try_get("to_user_id")?,
            status: row.try_get("status")?,
            re_encrypted_aes_key: row.try_get("re_encrypted_aes_key")?,
            error_message: row.try_get("error_message")?,
            xrpl_tx_hash: row.try_get("xrpl_tx_hash")?,
            created_at: row.try_get("created_at")?,
            processed_at: row.try_get("processed_at")?,
            completed_at: row.try_get("completed_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for VaultedIdentity {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            signing_public_key: row.try_get("signing_public_key")?,
            encryption_public_key: row.try_get("encryption_public_key")?,
            protocol_version: row.try_get("protocol_version")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for IdentityDevice {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            identity_id: row.try_get("identity_id")?,
            device_public_key: row.try_get("device_public_key")?,
            device_name: row.try_get("device_name")?,
            created_at: row.try_get("created_at")?,
            revoked_at: row.try_get("revoked_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for LinkedWallet {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            identity_id: row.try_get("identity_id")?,
            chain: row.try_get("chain")?,
            address: row.try_get("address")?,
            proof_signature: row.try_get("proof_signature")?,
            created_at: row.try_get("created_at")?,
            revoked_at: row.try_get("revoked_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for VaultObject {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            owner_identity_id: row.try_get("owner_identity_id")?,
            manifest_uri: row.try_get("manifest_uri")?,
            manifest_hash: row.try_get("manifest_hash")?,
            nft_chain: row.try_get("nft_chain")?,
            nft_token_id: row.try_get("nft_token_id")?,
            manifest_version: row.try_get("manifest_version")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for Grant {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            vault_object_id: row.try_get("vault_object_id")?,
            recipient_identity_id: row.try_get("recipient_identity_id")?,
            key_envelope: row.try_get("key_envelope")?,
            encrypted_file_key: row.try_get("encrypted_file_key")?,
            permissions: row.try_get("permissions")?,
            expires_at: row.try_get("expires_at")?,
            owner_signature: row.try_get("owner_signature")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
// END GENERATED MANUAL SQLX FROMROW IMPLS
