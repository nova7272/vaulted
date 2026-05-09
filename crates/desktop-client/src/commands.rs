//! Tauri Commands
//!
//! Мост между JavaScript UI и Rust backend.

use std::path::Path;
use std::sync::Arc;
use tauri::{State, Emitter, AppHandle, Manager};
use serde::{Deserialize, Serialize};
use xrpl_vault_crypto_core::KeyDerivation;

use crate::auth::{Session, XamanAuth, XamanPayload};
use crate::crypto::FileEncryptor;
use crate::error::{ClientError, Result};
use crate::oracle::api::{
    OracleClient, OracleConfig, CreateVaultRequest,
    VaultManifest, VaultFragment,
};
use crate::state::AppState;

// ==================== Progress Events ====================

/// Событие прогресса для upload/download
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    /// Идентификатор операции (nft_token_id или file_path)
    pub operation_id: String,
    /// Тип операции: "upload" или "download"
    pub operation_type: String,
    /// Текущий этап: "encrypting", "uploading", "minting", "downloading", "decrypting"
    pub stage: String,
    /// Прогресс текущего этапа (0-100)
    pub progress: u32,
    /// Общий прогресс операции (0-100)
    pub total_progress: u32,
    /// Описание текущего действия
    pub message: String,
    /// Обработано байт
    pub bytes_processed: u64,
    /// Всего байт
    pub bytes_total: u64,
}

impl ProgressEvent {
    fn new(operation_id: &str, operation_type: &str) -> Self {
        Self {
            operation_id: operation_id.to_string(),
            operation_type: operation_type.to_string(),
            stage: "starting".to_string(),
            progress: 0,
            total_progress: 0,
            message: "Starting...".to_string(),
            bytes_processed: 0,
            bytes_total: 0,
        }
    }

    fn emit(&self, app: &AppHandle) {
        let _ = app.emit("file-progress", self.clone());
    }
}

// ==================== Auth Commands ====================

/// Шаг 1: Создаёт SignIn request для QR-авторизации
#[tauri::command]
pub async fn start_xaman_auth(state: State<'_, Arc<AppState>>) -> Result<XamanPayload> {
    let xaman = XamanAuth::new(
        state.config.xaman_api_key.clone(),
        String::new(),
    );
    xaman.create_sign_in_request().await
}

/// Шаг 2: Ожидает SignIn, деривирует PRE ключи и возвращает сессию
///
/// SignIn подпись детерминистическая (не зависит от Sequence/Fee),
/// поэтому один и тот же wallet всегда получит одинаковый PRE keypair.
#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_auth(
    state: State<'_, Arc<AppState>>,
    payload_uuid: String,
    websocket_url: String,
) -> Result<Session> {
    let xaman = XamanAuth::new(
        state.config.xaman_api_key.clone(),
        String::new(),
    );

    let payload = XamanPayload {
        uuid: payload_uuid,
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url,
        expires_at: None,
    };

    // SignIn возвращает session + signature
    let sign_in_result = xaman.wait_for_sign_in(&payload, 24).await?;
    let session = sign_in_result.session;

    // Сохраняем сессию
    state.set_session(session.clone()).await;

    // Деривируем PRE keypair из SignIn signature
    // SignIn signature детерминистическая — один wallet = один keypair
    let mut signature_bytes = hex::decode(&sign_in_result.signature_hex)
        .map_err(|e| ClientError::Auth(format!("Invalid signature hex: {}", e)))?;

    let seed = KeyDerivation::derive_seed_from_signature(&signature_bytes, &session.wallet_address);

    // Зануляем signature bytes после использования
    use zeroize::Zeroize;
    signature_bytes.zeroize();

    state.init_keypair_from_seed(&session.wallet_address, seed).await?;

    let public_key_hex = state.get_public_key_hex().await?;

    tracing::info!(
        "User {} signed in, PRE keypair derived from SignIn signature, public_key: {}...",
        session.wallet_address,
        &public_key_hex[..16]
    );

    // Регистрируем пользователя в Oracle (или обновляем public key)
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    // Store signature for Oracle auth.
    // Xaman SignIn usually returns the full signed transaction in response.hex.
    // Oracle /auth/token-signin expects only DER-encoded ECDSA signature.
    let signin_signature = extract_xrpl_der_signature(&sign_in_result.signature_hex)
        .unwrap_or_else(|| sign_in_result.signature_hex.clone());
    let signin_public_key = session.public_key.clone();

    tracing::info!(
        "Prepared SignIn signature for Oracle auth: {} hex chars",
        signin_signature.len()
    );

    match oracle.register_user(&crate::oracle::api::RegisterUserRequest {
        wallet_address: session.wallet_address.clone(),
        pre_public_key: public_key_hex,
        signature: sign_in_result.signature_hex,
    }).await {
        Ok(r) => tracing::info!("User registered in Oracle: created={}", r.created),
        Err(e) => tracing::warn!("Oracle registration failed: {}", e),
    }

    // Автоматически получаем Oracle JWT используя SignIn signature
    match oracle.get_token_from_signin(&crate::oracle::api::SignInTokenRequest {
        wallet_address: session.wallet_address.clone(),
        public_key: signin_public_key,
        signature: signin_signature,
        device_fingerprint: Some(state.device_fingerprint().to_string()),
    }).await {
        Ok(token_response) => {
            state.save_oracle_tokens(
                token_response.access_token,
                token_response.expires_in,
                token_response.refresh_token,
                token_response.role,
            ).await?;
            tracing::info!(
                "Oracle JWT obtained automatically for {} (expires in {} hours)",
                session.wallet_address,
                token_response.expires_in / 3600
            );
        }
        Err(e) => {
            tracing::warn!("Failed to get Oracle JWT: {} - manual auth will be required", e);
        }
    }

    Ok(session)
}


fn extract_xrpl_der_signature(signed_tx_hex: &str) -> Option<String> {
    let hex = signed_tx_hex.trim().to_ascii_uppercase();

    // XRPL binary field 0x74 is TxnSignature.
    // It is followed by a one-byte variable length, then DER signature bytes.
    // Example: 74 46 30 44 02 20 ... 02 20 ...
    let bytes = hex.as_bytes();

    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if &hex[i..i + 2] == "74" {
            let len_hex = &hex[i + 2..i + 4];
            if let Ok(sig_len) = usize::from_str_radix(len_hex, 16) {
                let start = i + 4;
                let end = start + sig_len * 2;

                if end <= hex.len() {
                    let candidate = &hex[start..end];

                    // DER ECDSA signature starts with 0x30.
                    if candidate.starts_with("30") {
                        tracing::debug!(
                            "Extracted DER signature from XRPL tx hex: {} bytes",
                            sig_len
                        );
                        return Some(candidate.to_string());
                    }
                }
            }
        }

        i += 2;
    }

    tracing::warn!(
        "Could not extract DER signature from Xaman SignIn hex; falling back to original value"
    );
    None
}

/// Шаг 3: DEPRECATED - PRE ключи теперь деривируются автоматически при SignIn
/// Оставлено для совместимости с UI
#[tauri::command]
pub async fn start_key_derivation(state: State<'_, Arc<AppState>>) -> Result<XamanPayload> {
    // PRE ключи уже деривированы при SignIn
    // Возвращаем пустой payload — UI проверит has_pre_keys и увидит что ключи есть
    let session = state.get_session().await?;

    if state.has_keypair().await {
        tracing::info!("PRE keys already derived from SignIn for {}", session.wallet_address);
    }

    // Возвращаем dummy payload — UI не должен его использовать
    Ok(XamanPayload {
        uuid: "keys-already-derived".to_string(),
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url: String::new(),
        expires_at: None,
    })
}

/// Шаг 4: DEPRECATED - PRE ключи теперь деривируются автоматически при SignIn
/// Оставлено для совместимости с UI
#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_key_derivation(
    state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
) -> Result<KeyDerivationResponse> {
    let session = state.get_session().await?;

    // PRE ключи уже деривированы при SignIn
    let public_key_hex = state.get_public_key_hex().await?;

    tracing::info!(
        "PRE keys already derived for {} from SignIn, public_key: {}...",
        session.wallet_address,
        &public_key_hex[..16]
    );

    Ok(KeyDerivationResponse {
        public_key: public_key_hex,
        wallet_address: session.wallet_address,
    })
}

/// Проверяет наличие PRE ключей для текущего пользователя (в памяти)
#[tauri::command]
pub async fn has_pre_keys(state: State<'_, Arc<AppState>>) -> Result<bool> {
    let _session = state.get_session().await?;
    Ok(state.has_keypair().await)
}

/// Выходит из системы
#[tauri::command]
pub async fn logout(state: State<'_, Arc<AppState>>) -> Result<()> {
    state.clear_session().await;
    Ok(())
}

/// Проверяет статус авторизации
#[tauri::command]
pub async fn is_authenticated(state: State<'_, Arc<AppState>>) -> Result<bool> {
    Ok(state.is_authenticated().await)
}

/// Returns the Oracle base URL for frontend image loading
#[tauri::command]
pub async fn get_oracle_url(state: State<'_, Arc<AppState>>) -> Result<String> {
    Ok(state.config.oracle_url.clone())
}

/// Получает текущую сессию
#[tauri::command]
pub async fn get_current_session(state: State<'_, Arc<AppState>>) -> Result<Option<Session>> {
    match state.get_session().await {
        Ok(session) => Ok(Some(session)),
        Err(_) => Ok(None),
    }
}

/// Информация о пользователе
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub wallet_address: String,
    pub public_key: String,
    pub has_pre_keys: bool,
    pub expires_at: String,
}

/// Получает информацию о текущем пользователе
#[tauri::command]
pub async fn get_current_user(state: State<'_, Arc<AppState>>) -> Result<UserInfo> {
    let session = state.get_session().await?;
    let has_pre_keys = state.has_keypair().await;
    let public_key = if has_pre_keys {
        state.get_public_key_hex().await.unwrap_or_default()
    } else {
        String::new()
    };

    Ok(UserInfo {
        wallet_address: session.wallet_address,
        public_key,
        has_pre_keys,
        expires_at: session.expires_at.to_rfc3339(),
    })
}

/// Ответ на деривацию ключей
#[derive(Serialize)]
pub struct KeyDerivationResponse {
    pub public_key: String,
    pub wallet_address: String,
}

// ==================== File Upload Commands ====================

/// Результат загрузки файла
#[derive(Debug, Serialize)]
pub struct UploadResult {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub xaman_link: String,
    pub nft_uri: String,
    pub filename: String,
    pub file_size: u64,
    pub fragments_count: u32,
}

/// Прогресс загрузки
#[derive(Debug, Clone, Serialize)]
pub struct UploadProgress {
    pub stage: String,
    pub progress: u32,
    pub message: String,
}

/// Загружает файл: шифрует, отправляет на storage, минтит NFT
#[tauri::command]
pub async fn upload_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    file_path: String,
) -> Result<UploadResult> {
    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    // Проверяем что keypair есть в памяти
    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized. Please sign in again with Xaman.".to_string()));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());

    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(ClientError::FileSystem(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", file_path),
        )));
    }

    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len();

    if file_size > state.config.max_file_size {
        return Err(ClientError::FileTooLarge {
            size: file_size,
            max: state.config.max_file_size,
        });
    }

    let filename = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Инициализируем прогресс
    let mut progress = ProgressEvent::new(&file_path, "upload");
    progress.bytes_total = file_size;
    progress.emit(&app);

    tracing::info!("Uploading file: {} ({} bytes)", filename, file_size);

    // Этап 1: Шифрование (0-30%)
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting file...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_file(path, &public_key).await?;
    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.progress = 100;
    progress.message = "File encrypted".to_string();
    progress.emit(&app);

    tracing::info!("File encrypted: {} bytes", encrypted_bytes.len());

    // Этап 2: Создание Vault и минтинг NFT (30-60%)
    progress.stage = "minting".to_string();
    progress.progress = 0;
    progress.message = "Creating vault and minting NFT...".to_string();
    progress.total_progress = 35;
    progress.emit(&app);

    let metadata_hash = encrypted.manifest.compute_hash();

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    // Создаём vault с пустым storage info (будет заполнено после upload)
    let vault_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash,
        manifest: VaultManifest {
            encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
            original_size: encrypted.manifest.original_size,
            mime_type: encrypted.manifest.mime_type.clone(),
            original_hash: encrypted.manifest.original_hash.clone(),
            fragments: vec![VaultFragment {
                index: 0,
                storage_node_id: String::new(), // Будет заполнено Oracle
                storage_key: String::new(),     // Будет заполнено Oracle
                encrypted_hash: encrypted.encrypted_hash.clone(),
                size: encrypted_bytes.len() as u64,
            }],
        },
    };

    progress.total_progress = 50;
    progress.message = "Minting NFT on XRPL...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&vault_request).await?;

    progress.total_progress = 60;
    progress.message = "NFT minted!".to_string();
    progress.emit(&app);

    tracing::info!(
        "Vault created! NFT: {}, Offer: {}",
        vault_response.nft_token_id,
        vault_response.offer_index
    );

    // Этап 3: Загрузка через Oracle proxy (60-95%)
    progress.stage = "uploading".to_string();
    progress.progress = 0;
    progress.message = "Uploading encrypted data...".to_string();
    progress.total_progress = 65;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url,
        vault_response.nft_token_id
    );

    tracing::info!("Uploading to Oracle proxy: {}", upload_url);

    let response = state.create_authed_client().await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes.clone())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload file: {} - {}",
            status, error_text
        )));
    }

    let upload_result: serde_json::Value = response.json().await?;
    tracing::info!("Upload result: {:?}", upload_result);

    progress.total_progress = 95;
    progress.progress = 100;
    progress.bytes_processed = encrypted_bytes.len() as u64;
    progress.message = "Upload complete".to_string();
    progress.emit(&app);

    // Финальный прогресс
    progress.stage = "complete".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.message = "Upload complete!".to_string();
    progress.emit(&app);

    Ok(UploadResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        xaman_link: vault_response.xaman_link,
        nft_uri: vault_response.nft_uri,
        filename,
        file_size,
        fragments_count: 1,
    })
}

/// Загружает несколько файлов (автоматически архивирует в ZIP)
#[tauri::command]
pub async fn upload_files(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    file_paths: Vec<String>,
    custom_name: Option<String>,
) -> Result<UploadResult> {
    use crate::archive::{create_zip_archive, needs_archiving, generate_archive_name};

    if file_paths.is_empty() {
        return Err(ClientError::Validation("No files selected".to_string()));
    }

    // Если один файл и не папка - используем обычный upload
    if file_paths.len() == 1 && !needs_archiving(&file_paths) {
        // Если есть custom_name, используем upload_bytes
        if let Some(name) = custom_name {
            let path = Path::new(&file_paths[0]);
            let data = tokio::fs::read(path).await?;
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            return upload_bytes_internal(app, state, data, name, mime).await;
        }
        return upload_file(app, state, file_paths[0].clone()).await;
    }

    // Нужна архивация
    let archive_name = custom_name.unwrap_or_else(|| generate_archive_name(&file_paths));
    let archive_name = if !archive_name.ends_with(".zip") {
        format!("{}.zip", archive_name)
    } else {
        archive_name
    };

    tracing::info!("Creating ZIP archive: {} from {} files", archive_name, file_paths.len());

    // Создаём архив
    let zip_data = create_zip_archive(&file_paths, &archive_name)
        .map_err(|e| ClientError::Validation(e))?;

    tracing::info!("ZIP archive created: {} bytes", zip_data.len());

    // Загружаем архив
    upload_bytes_internal(app, state, zip_data, archive_name, "application/zip".to_string()).await
}

/// Внутренняя функция для загрузки байтов
async fn upload_bytes_internal(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    data: Vec<u8>,
    filename: String,
    mime_type: String,
) -> Result<UploadResult> {
    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized. Please sign in again with Xaman.".to_string()));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());
    let file_size = data.len() as u64;

    if file_size > state.config.max_file_size {
        return Err(ClientError::FileTooLarge {
            size: file_size,
            max: state.config.max_file_size,
        });
    }

    let mut progress = ProgressEvent::new(&filename, "upload");
    progress.bytes_total = file_size;
    progress.emit(&app);

    tracing::info!("Uploading data: {} ({} bytes)", filename, file_size);

    // Этап 1: Шифрование (0-30%)
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting data...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(&data, &filename, &mime_type, &public_key)?;
    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.progress = 100;
    progress.message = "Data encrypted".to_string();
    progress.emit(&app);

    tracing::info!("Data encrypted: {} bytes", encrypted_bytes.len());

    // Этап 2: Создание vault и минтинг NFT (30-60%)
    progress.stage = "minting".to_string();
    progress.progress = 0;
    progress.message = "Creating vault and minting NFT...".to_string();
    progress.total_progress = 35;
    progress.emit(&app);

    let encrypted_hash = format!("blake3:{}", &encrypted.encrypted_hash[..13]);
    let fragment = VaultFragment {
        index: 0,
        storage_node_id: String::new(), // Будет заполнено Oracle
        storage_key: String::new(),     // Будет заполнено Oracle
        encrypted_hash: encrypted_hash.clone(),
        size: encrypted_bytes.len() as u64,
    };

    let manifest = VaultManifest {
        encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type.clone(),
        original_hash: encrypted.manifest.original_hash.clone(),
        fragments: vec![fragment],
    };

    let create_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash: encrypted.manifest.compute_hash(),
        manifest,
    };

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    progress.total_progress = 50;
    progress.message = "Minting NFT on XRPL...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&create_request).await?;

    progress.total_progress = 60;
    progress.message = "NFT minted!".to_string();
    progress.emit(&app);

    tracing::info!(
        "Vault created! NFT: {}, Offer: {}",
        vault_response.nft_token_id,
        vault_response.offer_index
    );

    // Этап 3: Загрузка через Oracle proxy (60-95%)
    progress.stage = "uploading".to_string();
    progress.progress = 0;
    progress.message = "Uploading encrypted data...".to_string();
    progress.total_progress = 65;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url,
        vault_response.nft_token_id
    );

    tracing::info!("Uploading to Oracle proxy: {}", upload_url);

    let response = state.create_authed_client().await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes.clone())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload data: {} - {}",
            status, error_text
        )));
    }

    let upload_result: serde_json::Value = response.json().await?;
    tracing::info!("Upload result: {:?}", upload_result);

    progress.total_progress = 95;
    progress.progress = 100;
    progress.bytes_processed = encrypted_bytes.len() as u64;
    progress.message = "Upload complete".to_string();
    progress.emit(&app);

    // Финальный прогресс
    progress.stage = "complete".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.message = "Upload complete!".to_string();
    progress.emit(&app);

    Ok(UploadResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        xaman_link: vault_response.xaman_link,
        nft_uri: vault_response.nft_uri,
        filename,
        file_size,
        fragments_count: 1,
    })
}

/// Шифрует файл и возвращает зашифрованные данные (без загрузки)
#[tauri::command]
pub async fn encrypt_file(
    state: State<'_, Arc<AppState>>,
    file_path: String,
) -> Result<EncryptedFileInfo> {
    let _session = state.get_session().await?;

    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized. Please sign in again.".to_string()));
    }

    let public_key = state.get_public_key().await?;

    let path = Path::new(&file_path);
    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_file(path, &public_key).await?;
    let metadata_hash = encrypted.manifest.compute_hash();

    Ok(EncryptedFileInfo {
        filename: path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string(),
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type,
        original_hash: encrypted.manifest.original_hash,
        fragments_count: 1,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash,
    })
}

#[derive(Debug, Serialize)]
pub struct EncryptedFileInfo {
    pub filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragments_count: u32,
    pub encrypted_aes_key: String,
    pub metadata_hash: String,
}

#[tauri::command]
pub async fn encrypt_bytes(
    state: State<'_, Arc<AppState>>,
    data: Vec<u8>,
    filename: String,
    mime_type: String,
) -> Result<EncryptedFileInfo> {
    let _session = state.get_session().await?;

    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized. Please sign in again.".to_string()));
    }

    let public_key = state.get_public_key().await?;

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(&data, &filename, &mime_type, &public_key)?;
    let metadata_hash = encrypted.manifest.compute_hash();

    Ok(EncryptedFileInfo {
        filename,
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type,
        original_hash: encrypted.manifest.original_hash,
        fragments_count: 1,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash,
    })
}

// ==================== NFT & Files Commands ====================

#[tauri::command]
pub async fn get_xrp_balance(state: State<'_, Arc<AppState>>) -> Result<String> {
    let _session = state.get_session().await?;
    Ok("0".to_string())
}

/// Расшифровывает имя файла из encrypted_filename
async fn decrypt_filename(
    state: &State<'_, Arc<AppState>>,
    encrypted_aes_key: &str,
    encrypted_filename: &str,
    is_re_encrypted: bool,
) -> Result<String> {
    let keypair = state.get_keypair().await?;

    // Расшифровываем AES ключ
    let aes_key_bytes = if is_re_encrypted {
        let re_encrypted_data = xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        let encrypted_pre_data = xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;

    // Расшифровываем имя файла
    let decrypted_bytes = aes_key.decrypt_from_base64(encrypted_filename)
        .map_err(|e| ClientError::Crypto(e))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| ClientError::Config(format!("Invalid filename UTF-8: {}", e)))
}

#[tauri::command]
pub async fn list_my_nfts(state: State<'_, Arc<AppState>>) -> Result<Vec<NftInfo>> {
    let session = state.get_session().await?;

    let http_url = state.config.xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");

    let client = state.create_authed_client().await;
    let response = client
        .post(&http_url)
        .json(&serde_json::json!({
            "method": "account_nfts",
            "params": [{
                "account": session.wallet_address,
                "ledger_index": "validated"
            }]
        }))
        .send()
        .await?;

    let data: serde_json::Value = response.json().await?;

    let nfts = data
        .get("result")
        .and_then(|r| r.get("account_nfts"))
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();

    // Собираем базовую информацию о NFT
    // Фильтруем только NFT нашего проекта (URI: vaulted:// или .../nft/.../metadata.json)
    let mut nft_infos: Vec<NftInfo> = nfts.into_iter().filter_map(|nft| {
        let nft_token_id = nft.get("NFTokenID")?.as_str()?.to_string();
        let uri_hex = nft.get("URI").and_then(|u| u.as_str()).unwrap_or("");
        let uri = if !uri_hex.is_empty() {
            hex::decode(uri_hex).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| uri_hex.to_string())
        } else { String::new() };

        // Показываем только NFT нашего проекта
        let is_vault_nft = uri.starts_with("vaulted://")
            || (uri.contains("/nft/") && uri.contains("/metadata.json"));
        if !is_vault_nft {
            return None;
        }

        Some(NftInfo { nft_token_id, uri, filename: None, created_at: None, file_status: "unknown".to_string() })
    }).collect();

    // Запрашиваем и расшифровываем filename из Oracle для каждого NFT
    let oracle_url = &state.config.oracle_url;
    let has_keypair = state.has_keypair().await;

    // Parallel fetch: all /files/*/access requests at once instead of sequential
    let futures: Vec<_> = nft_infos.iter().map(|nft| {
        let url = format!("{}/api/v1/files/{}/access", oracle_url, nft.nft_token_id);
        let client = client.clone();
        async move {
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    resp.json::<serde_json::Value>().await.ok().map(|data| ("available".to_string(), data))
                }
                Ok(resp) if resp.status().as_u16() == 404 => {
                    Some(("deleted".to_string(), serde_json::Value::Null))
                }
                _ => None,
            }
        }
    }).collect();

    let results = futures_util::future::join_all(futures).await;

    for (nft, result) in nft_infos.iter_mut().zip(results.into_iter()) {
        match result {
            Some((status, data)) if status == "available" => {
                nft.file_status = "available".to_string();
                if let Some(created) = data["created_at"].as_str() {
                    nft.created_at = Some(created.to_string());
                }
                let encrypted_filename = data["manifest"]["encrypted_filename"].as_str().unwrap_or("");
                let encrypted_aes_key = data["encrypted_aes_key"].as_str().unwrap_or("");
                let is_re_encrypted = data["is_re_encrypted"].as_bool().unwrap_or(false);

                if has_keypair && !encrypted_filename.is_empty() && !encrypted_aes_key.is_empty() {
                    if let Ok(decrypted_name) = decrypt_filename(&state, encrypted_aes_key, encrypted_filename, is_re_encrypted).await {
                        nft.filename = Some(decrypted_name);
                    } else {
                        nft.filename = Some(format!("Vault #{}", &nft.nft_token_id[..8]));
                    }
                } else {
                    nft.filename = Some(format!("Vault #{}", &nft.nft_token_id[..8]));
                }
            }
            Some((status, _)) if status == "deleted" => {
                nft.file_status = "deleted".to_string();
                nft.filename = Some(format!("Deleted file #{}", &nft.nft_token_id[..8]));
            }
            _ => {
                nft.file_status = "unknown".to_string();
            }
        }
    }

    tracing::info!("Found {} NFTs for {}", nft_infos.len(), session.wallet_address);
    Ok(nft_infos)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NftInfo {
    pub nft_token_id: String,
    pub uri: String,
    pub filename: Option<String>,
    pub created_at: Option<String>,
    pub file_status: String, // "available" | "deleted" | "unknown"
}

#[tauri::command]
pub async fn get_my_nfts(state: State<'_, Arc<AppState>>) -> Result<Vec<NftInfo>> {
    list_my_nfts(state).await
}

#[tauri::command]
pub async fn get_my_files(state: State<'_, Arc<AppState>>) -> Result<Vec<FileInfo>> {
    let _session = state.get_session().await?;
    Ok(vec![])
}

#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub nft_token_id: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
    pub uploaded_at: String,
}

#[tauri::command]
pub async fn download_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    output_path: String,
) -> Result<String> {
    let _session = state.get_session().await?;
    tracing::info!("Downloading file for NFT: {}", nft_token_id);

    // Инициализируем прогресс
    let mut progress = ProgressEvent::new(&nft_token_id, "download");
    progress.emit(&app);

    let client = state.create_authed_client().await;

    // Получаем метаданные файла
    let oracle_url = format!("{}/api/v1/files/{}/access", state.config.oracle_url, nft_token_id);

    progress.stage = "fetching".to_string();
    progress.message = "Fetching file metadata...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let file_info: serde_json::Value = client
        .get(&oracle_url)
        .send()
        .await?
        .json()
        .await?;

    tracing::debug!("File info: {:?}", file_info);

    let encrypted_aes_key = file_info["encrypted_aes_key"]
        .as_str()
        .ok_or_else(|| ClientError::Oracle("Missing encrypted_aes_key".into()))?;

    // Проверяем был ли ключ перешифрован (после transfer)
    let is_re_encrypted = file_info["is_re_encrypted"]
        .as_bool()
        .unwrap_or(false);

    // Расшифровываем имя файла
    let encrypted_filename = file_info["manifest"]["encrypted_filename"]
        .as_str()
        .unwrap_or("");
    let original_filename = if !encrypted_filename.is_empty() {
        decrypt_filename(&state, encrypted_aes_key, encrypted_filename, is_re_encrypted)
            .await
            .unwrap_or_else(|_| "downloaded_file".to_string())
    } else {
        "downloaded_file".to_string()
    };

    let original_size = file_info["manifest"]["original_size"]
        .as_u64()
        .unwrap_or(0);

    progress.bytes_total = original_size;

    tracing::info!(
        "Downloading file: {}, is_re_encrypted: {}",
        original_filename,
        is_re_encrypted
    );

    // Этап: Скачивание через Oracle proxy (10-70%)
    progress.stage = "downloading".to_string();
    progress.message = "Downloading encrypted data...".to_string();
    progress.total_progress = 10;
    progress.emit(&app);

    // Используем новый Oracle proxy endpoint
    let download_url = format!("{}/api/v1/files/{}/download", state.config.oracle_url, nft_token_id);

    tracing::debug!("Downloading from Oracle proxy: {}", download_url);

    let response = client
        .get(&download_url)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to download file: {} - {}",
            status, error_text
        )));
    }

    let encrypted_data = response.bytes().await?.to_vec();

    progress.bytes_processed = encrypted_data.len() as u64;
    progress.total_progress = 70;
    progress.message = "Download complete".to_string();
    progress.emit(&app);

    tracing::info!("Downloaded {} bytes of encrypted data", encrypted_data.len());

    // Этап: Расшифровка (70-95%)
    progress.stage = "decrypting".to_string();
    progress.message = "Decrypting file...".to_string();
    progress.total_progress = 75;
    progress.progress = 0;
    progress.emit(&app);

    let keypair = state.get_keypair().await?;

    // Расшифровываем AES ключ в зависимости от типа данных
    let aes_key_bytes = if is_re_encrypted {
        // После transfer - ключ в формате ReEncryptedData
        tracing::info!("Decrypting re-encrypted AES key (post-transfer)");
        progress.message = "Decrypting transferred key...".to_string();
        progress.emit(&app);

        let re_encrypted_data = xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        // Оригинальный владелец - ключ в формате EncryptedPreData
        tracing::info!("Decrypting original AES key");
        let encrypted_pre_data = xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;

    tracing::info!("AES key decrypted successfully");

    progress.message = "Decrypting file content...".to_string();
    progress.total_progress = 85;
    progress.emit(&app);

    let encrypted_fragment = xrpl_vault_crypto_core::EncryptedData::from_bytes(&encrypted_data)?;
    let decrypted_data = aes_key.decrypt(&encrypted_fragment)?;

    tracing::info!("Decrypted {} bytes", decrypted_data.len());

    // Этап: Сохранение (95-100%)
    progress.stage = "saving".to_string();
    progress.message = "Saving file...".to_string();
    progress.total_progress = 95;
    progress.emit(&app);

    std::fs::write(&output_path, &decrypted_data)
        .map_err(|e| ClientError::Config(format!("Failed to write file: {}", e)))?;

    // Финальный прогресс
    progress.stage = "complete".to_string();
    progress.message = "Download complete!".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.bytes_processed = decrypted_data.len() as u64;
    progress.emit(&app);

    tracing::info!("File saved to {}", output_path);

    Ok(output_path)
}

#[tauri::command]
pub async fn request_file_access(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<FileAccessInfo> {
    let _session = state.get_session().await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let access = oracle.request_file_access(&nft_token_id).await?;

    // Расшифровываем имя файла до move
    let filename = decrypt_filename(
        &state,
        &access.encrypted_aes_key,
        &access.manifest.encrypted_filename,
        access.is_re_encrypted,
    ).await.unwrap_or_else(|_| format!("Vault #{}", &nft_token_id[..8]));

    Ok(FileAccessInfo {
        nft_token_id: access.nft_token_id,
        encrypted_aes_key: access.encrypted_aes_key,
        is_re_encrypted: access.is_re_encrypted,
        filename,
        size: access.manifest.original_size,
        fragments_count: 1,
    })
}

#[derive(Debug, Serialize)]
pub struct FileAccessInfo {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub filename: String,
    pub size: u64,
    pub fragments_count: u32,
}

// ==================== Transfer Commands ====================

#[tauri::command]
pub async fn create_mint_transaction(_state: State<'_, Arc<AppState>>) -> Result<String> {
    Err(ClientError::Config("Use upload_file instead".to_string()))
}

#[tauri::command]
pub async fn verify_nft_ownership(
    state: State<'_, Arc<AppState>>,
    _nft_token_id: String,
) -> Result<bool> {
    let _session = state.get_session().await?;
    Ok(false)
}

#[tauri::command]
pub async fn generate_transfer_key(
    state: State<'_, Arc<AppState>>,
    recipient_address: String,
) -> Result<TransferKeyInfo> {
    let session = state.get_session().await?;

    let sender_keypair = state.get_keypair().await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let recipient_info = oracle.get_user_public_key(&recipient_address).await?;
    let recipient_public_key = xrpl_vault_crypto_core::pre::PrePublicKey::from_hex(&recipient_info.pre_public_key)?;

    let re_key = state.pre().generate_re_key(&sender_keypair, &recipient_public_key)?;
    let re_key_base64 = re_key.to_base64_verified(&sender_keypair);

    Ok(TransferKeyInfo {
        re_encryption_key: re_key_base64,
        from_address: session.wallet_address,
        to_address: recipient_address,
    })
}

#[derive(Debug, Serialize)]
pub struct TransferKeyInfo {
    pub re_encryption_key: String,
    pub from_address: String,
    pub to_address: String,
}

#[tauri::command]
pub async fn get_user_public_key(
    state: State<'_, Arc<AppState>>,
    wallet_address: String,
) -> Result<String> {
    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let user_info = oracle.get_user_public_key(&wallet_address).await?;
    Ok(user_info.pre_public_key)
}

#[tauri::command]
pub async fn initiate_transfer(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    to_address: String,
) -> Result<InitiateTransferResult> {
    let session = state.get_session().await?;

    let transfer_key = generate_transfer_key(state.clone(), to_address.clone()).await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let response = oracle.initiate_transfer(
        &nft_token_id,
        &session.wallet_address,
        &to_address,
        &transfer_key.re_encryption_key,
    ).await?;

    let xaman_payload = match create_transfer_offer(
        state.clone(),
        nft_token_id.clone(),
        to_address.clone(),
    ).await {
        Ok(p) => { tracing::info!("Created XamanPayload: uuid={}", p.uuid); Some(p) }
        Err(e) => { tracing::error!("Failed to create offer: {}", e); None }
    };

    Ok(InitiateTransferResult {
        transfer_id: response.transfer_id,
        status: response.status,
        xaman_payload,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateTransferResult {
    pub transfer_id: String,
    pub status: String,
    pub xaman_payload: Option<crate::auth::xaman::XamanPayload>,
}

#[tauri::command]
pub async fn create_transfer_offer(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    to_address: String,
) -> Result<crate::auth::xaman::XamanPayload> {
    let session = state.get_session().await?;

    let tx_json = serde_json::json!({
        "TransactionType": "NFTokenCreateOffer",
        "Account": session.wallet_address,
        "NFTokenID": nft_token_id,
        "Amount": "0",
        "Flags": 1,
        "Destination": to_address
    });

    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);
    let payload = xaman.create_payload(serde_json::json!({"txjson": tx_json})).await?;

    tracing::info!("Transfer offer payload created for NFT {} -> {}", nft_token_id, to_address);
    Ok(payload)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_transfer_offer(
    state: State<'_, Arc<AppState>>,
    payload_uuid: String,
    websocket_url: String,
    transfer_id: String,
    nft_token_id: String,
) -> Result<TransferOfferResult> {
    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);

    let payload = crate::auth::xaman::XamanPayload {
        uuid: payload_uuid,
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url,
        expires_at: None,
    };

    let result = xaman.wait_for_signature(&payload, 300).await?;
    tracing::info!("Xaman signature received, txid: {}", result.txid);

    // Используем HTTP вместо WebSocket для получения offers
    let http_url = state.config.xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");

    let http_client = state.create_authed_client().await;
    let offers_response: serde_json::Value = http_client
        .post(&http_url)
        .json(&serde_json::json!({
            "method": "nft_sell_offers",
            "params": [{
                "nft_id": nft_token_id
            }]
        }))
        .send()
        .await?
        .json()
        .await?;

    let session = state.get_session().await?;

    let offer_index = offers_response
        .get("result")
        .and_then(|r| r.get("offers"))
        .and_then(|o| o.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|o| {
                let owner = o.get("owner")?.as_str()?;
                if owner == session.wallet_address {
                    o.get("nft_offer_index")?.as_str().map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| ClientError::Xrpl("Offer not found on XRPL".to_string()))?;

    tracing::info!("Transfer offer signed: {}, offer_index: {}", transfer_id, offer_index);

    // Уведомляем Oracle что offer подписан - статус NFT -> 'transferring'
    let confirm_url = format!("{}/api/v1/transfers/confirm-signed", state.config.oracle_url);
    match http_client.post(&confirm_url)
        .json(&serde_json::json!({
            "transfer_id": transfer_id,
            "offer_index": offer_index
        }))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("Oracle notified: NFT status -> transferring");
        }
        Ok(resp) => {
            tracing::warn!("confirm-signed failed: {}", resp.status());
        }
        Err(e) => {
            tracing::warn!("confirm-signed request failed: {}", e);
        }
    }

    Ok(TransferOfferResult {
        transfer_id,
        offer_index,
        tx_hash: result.txid,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferOfferResult {
    pub transfer_id: String,
    pub offer_index: String,
    pub tx_hash: String,
}

#[tauri::command]
pub async fn complete_transfer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
    xrpl_tx_hash: String,
) -> Result<bool> {
    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let request = crate::oracle::api::CompleteTransferRequest {
        transfer_id: transfer_id.clone(),
        xrpl_tx_hash,
    };

    let response = oracle.complete_transfer(&request).await?;
    tracing::info!("Transfer completed, new owner: {}", response.new_owner);

    Ok(response.success)
}

#[tauri::command]
pub async fn claim_nft(
    state: State<'_, Arc<AppState>>,
    offer_index: String,
) -> Result<crate::auth::xaman::XamanPayload> {
    let session = state.get_session().await?;

    let tx_json = serde_json::json!({
        "TransactionType": "NFTokenAcceptOffer",
        "Account": session.wallet_address,
        "NFTokenSellOffer": offer_index
    });

    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);
    let payload_request = serde_json::json!({"txjson": tx_json});
    let payload = xaman.create_payload(payload_request).await?;

    tracing::info!("Claim NFT payload created: {}", payload.uuid);
    Ok(payload)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    pub success: bool,
    pub tx_hash: String,
    pub nft_token_id: Option<String>,
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_claim(
    state: State<'_, Arc<AppState>>,
    payload_uuid: String,
    websocket_url: String,
    offer_index: Option<String>,
) -> Result<ClaimResult> {
    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();
    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);

    let payload = crate::auth::xaman::XamanPayload {
        uuid: payload_uuid,
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url,
        expires_at: None,
    };

    let result = xaman.wait_for_signature(&payload, 300).await?;
    tracing::info!("Claim signed: txid={}", result.txid);

    // === POST-PROCESSING: non-fatal — claim already succeeded on XRPL ===
    // Extract what we need before the timeout block
    let txid_for_post = result.txid.clone();
    let xrpl_url = state.config.xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");
    let oracle_url = state.config.oracle_url.clone();
    let client1 = state.create_authed_client().await;
    let client2 = state.create_authed_client().await;
    let offer_clone = offer_index.clone();

    let nft_token_id: Option<String> = match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        async move {
            // 1. Try to get NFT token ID from XRPL tx
            let nft_id: Option<String> = match client1
                .post(&xrpl_url)
                .timeout(std::time::Duration::from_secs(10))
                .json(&serde_json::json!({
                    "method": "tx",
                    "params": [{"transaction": &txid_for_post, "binary": false}]
                }))
                .send()
                .await
            {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(tx) => {
                            tx.get("result")
                                .and_then(|r| r.get("meta"))
                                .and_then(|m| m.get("AffectedNodes"))
                                .and_then(|nodes| nodes.as_array())
                                .and_then(|arr| {
                                    for node in arr {
                                        if let Some(deleted) = node.get("DeletedNode") {
                                            if deleted.get("LedgerEntryType").and_then(|t| t.as_str()) == Some("NFTokenOffer") {
                                                return deleted.get("FinalFields")
                                                    .and_then(|f| f.get("NFTokenID"))
                                                    .and_then(|id| id.as_str())
                                                    .map(|s| s.to_string());
                                            }
                                        }
                                    }
                                    None
                                })
                        }
                        Err(e) => { tracing::warn!("Failed to parse XRPL tx response: {}", e); None }
                    }
                }
                Err(e) => { tracing::warn!("Failed to fetch XRPL tx: {}", e); None }
            };

            // 2. Try to finalize transfer in Oracle (best-effort)
            if let Some(ref offer_idx) = offer_clone {
                tracing::info!("Looking for transfer by offer_index: {}", offer_idx);
                let transfer_url = format!("{}/api/v1/transfers/by-offer/{}", oracle_url, offer_idx);
                if let Ok(resp) = client2.get(&transfer_url).send().await {
                    if let Ok(info) = resp.json::<serde_json::Value>().await {
                        if let Some(tid) = info.get("transfer_id").and_then(|t| t.as_str()) {
                            tracing::info!("Found transfer_id: {}", tid);
                            let complete_url = format!("{}/api/v1/transfers/complete", oracle_url);
                            let body = serde_json::json!({"transfer_id": tid, "xrpl_tx_hash": &txid_for_post});
                            if let Ok(r) = client2.post(&complete_url).json(&body).send().await {
                                if r.status().is_success() { tracing::info!("Transfer completed"); }
                                else { tracing::warn!("complete_transfer failed: {}", r.status()); }
                            }
                        }
                    }
                }
                // Fallback finalize
                let finalize_url = format!("{}/api/v1/transfers/finalize-by-offer", oracle_url);
                let body = serde_json::json!({"offerIndex": offer_idx, "xrplTxHash": &txid_for_post});
                let _ = client2.post(&finalize_url).json(&body).send().await;
            }

            nft_id
        }
    ).await {
        Ok(id) => id,
        Err(_) => {
            tracing::warn!("Post-processing timed out after 20s (non-fatal, claim already on XRPL)");
            None
        }
    };

    Ok(ClaimResult {
        success: true,
        tx_hash: result.txid,
        nft_token_id,
    })
}
// ==================== Incoming Offers ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingOffer {
    pub offer_index: String,
    pub nft_token_id: String,
    pub from_address: String,
    pub amount: String,
}

#[tauri::command]
pub async fn get_incoming_offers(state: State<'_, Arc<AppState>>) -> Result<Vec<IncomingOffer>> {
    let session = state.get_session().await?;

    let http_url = state.config.xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");

    let client = state.create_authed_client().await;

    // Запрашиваем у Oracle pending transfers где мы получатель
    let oracle_url = format!("{}/api/v1/transfers/incoming/{}",
                             state.config.oracle_url,
                             session.wallet_address
    );

    let incoming: Vec<IncomingOffer> = match client.get(&oracle_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.json().await.unwrap_or_default()
        }
        _ => {
            tracing::warn!("Oracle incoming endpoint not available, using fallback");
            vec![]
        }
    };

    // Verify each offer still exists on XRPL — filter out already-claimed ones
    let mut valid_offers = Vec::new();
    for offer in &incoming {
        let check: serde_json::Value = match client
            .post(&http_url)
            .json(&serde_json::json!({
                "method": "ledger_entry",
                "params": [{
                    "index": offer.offer_index,
                    "ledger_index": "validated"
                }]
            }))
            .send()
            .await
        {
            Ok(resp) => resp.json().await.unwrap_or_default(),
            Err(_) => {
                // Can't verify — keep the offer to be safe
                valid_offers.push(offer.clone());
                continue;
            }
        };

        let exists = check.get("result")
            .and_then(|r| r.get("node"))
            .is_some();

        if exists {
            valid_offers.push(offer.clone());
        } else {
            // Offer no longer exists on XRPL — auto-finalize in Oracle
            tracing::info!("Offer {} no longer exists on XRPL, auto-finalizing", offer.offer_index);
            let finalize_url = format!("{}/api/v1/transfers/finalize-by-offer", state.config.oracle_url);
            let _ = client.post(&finalize_url)
                .json(&serde_json::json!({
                    "offerIndex": offer.offer_index,
                    "xrplTxHash": "auto-finalized-stale-offer"
                }))
                .send()
                .await;
        }
    }

    tracing::info!("Found {} incoming offers for {} ({} verified on XRPL)",
        incoming.len(), session.wallet_address, valid_offers.len());
    Ok(valid_offers)
}

// ==================== Outgoing Offers ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingOffer {
    pub offer_index: String,
    pub nft_token_id: String,
    pub to_address: String,
    pub filename: String,
    pub status: String,
    pub created_at: String,
}

#[tauri::command]
pub async fn get_outgoing_offers(state: State<'_, Arc<AppState>>) -> Result<Vec<OutgoingOffer>> {
    let session = state.get_session().await?;
    let client = state.create_authed_client().await;

    // Запрашиваем историю трансферов у Oracle
    let oracle_url = format!("{}/api/v1/transfers/history/{}",
                             state.config.oracle_url,
                             session.wallet_address
    );

    #[derive(Debug, Deserialize)]
    struct TransferHistory {
        sent: Vec<SentTransfer>,
        #[allow(dead_code)]
        received: Vec<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    struct SentTransfer {
        #[serde(default)]
        offer_index: Option<String>,
        nft_token_id: String,
        to_address: String,
        status: String,
        created_at: String,
        #[serde(default)]
        encrypted_filename: Option<String>,
    }

    let outgoing: Vec<OutgoingOffer> = match client.get(&oracle_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(history) = resp.json::<TransferHistory>().await {
                history.sent.into_iter().map(|t| OutgoingOffer {
                    offer_index: t.offer_index.unwrap_or_default(),
                    nft_token_id: t.nft_token_id,
                    to_address: t.to_address,
                    filename: t.encrypted_filename.unwrap_or_else(|| "Unknown".to_string()),
                    status: t.status,
                    created_at: t.created_at,
                }).collect()
            } else {
                vec![]
            }
        }
        _ => {
            tracing::warn!("Oracle history endpoint not available");
            vec![]
        }
    };

    tracing::info!("Found {} outgoing offers for {}", outgoing.len(), session.wallet_address);
    Ok(outgoing)
}

// ==================== Transfer History ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistoryItem {
    pub transfer_id: String,
    pub nft_token_id: String,
    pub other_party: String,
    pub direction: String,
    pub status: String,
    pub created_at: String,
    pub filename: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistory {
    pub sent: Vec<TransferHistoryItem>,
    pub received: Vec<TransferHistoryItem>,
}

#[tauri::command]
pub async fn get_transfer_history(state: State<'_, Arc<AppState>>) -> Result<TransferHistory> {
    let session = state.get_session().await?;

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/transfers/history/{}",
        state.config.oracle_url,
        session.wallet_address
    );

    let history: TransferHistory = client
        .get(&oracle_url)
        .send()
        .await?
        .json()
        .await
        .unwrap_or(TransferHistory { sent: vec![], received: vec![] });

    tracing::info!(
        "Transfer history: {} sent, {} received",
        history.sent.len(),
        history.received.len()
    );

    Ok(history)
}

// ==================== Cancel Transfer ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelTransferResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
}

#[tauri::command]
pub async fn cancel_transfer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
) -> Result<CancelTransferResponse> {
    let session = state.get_session().await?;

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/transfers/{}/cancel",
        state.config.oracle_url,
        transfer_id
    );

    let response = client
        .post(&oracle_url)
        .json(&serde_json::json!({
            "wallet_address": session.wallet_address
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(crate::error::ClientError::Oracle(format!(
            "Failed to cancel transfer: {}",
            error_text
        )));
    }

    let result: CancelTransferResponse = response.json().await?;

    tracing::info!(
        "Transfer {} cancelled: {}",
        transfer_id,
        result.message
    );

    Ok(result)
}

// ==================== Delete Vault ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteVaultResponse {
    pub success: bool,
    pub message: String,
    pub deleted_fragments: usize,
}

#[tauri::command]
pub async fn delete_vault(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<DeleteVaultResponse> {
    let session = state.get_session().await?;

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/vault/{}/delete",
        state.config.oracle_url,
        nft_token_id
    );

    let response = client
        .post(&oracle_url)
        .json(&serde_json::json!({
            "wallet_address": session.wallet_address
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(crate::error::ClientError::Oracle(format!(
            "Failed to delete vault: {}",
            error_text
        )));
    }

    let result: DeleteVaultResponse = response.json().await?;

    tracing::info!(
        "Vault {} deleted: {} fragments removed",
        nft_token_id,
        result.deleted_fragments
    );

    Ok(result)
}

// ==================== Burn NFT ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurnNftResult {
    pub success: bool,
    pub tx_hash: String,
    pub message: String,
}

#[tauri::command(rename_all = "camelCase")]
pub async fn burn_nft(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<crate::auth::xaman::XamanPayload> {
    let session = state.get_session().await?;

    // Создаём транзакцию NFTokenBurn
    let tx_json = serde_json::json!({
        "TransactionType": "NFTokenBurn",
        "Account": session.wallet_address,
        "NFTokenID": nft_token_id
    });

    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);
    let payload = xaman.create_payload(serde_json::json!({"txjson": tx_json})).await?;

    tracing::info!("Burn NFT payload created for {}", nft_token_id);
    Ok(payload)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_burn(
    state: State<'_, Arc<AppState>>,
    payload_uuid: String,
    websocket_url: String,
    nft_token_id: String,
) -> Result<BurnNftResult> {
    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);

    // Создаём payload структуру для wait_for_signature
    let payload = crate::auth::xaman::XamanPayload {
        uuid: payload_uuid,
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url: websocket_url,
        expires_at: None,
    };

    // Ждём подпись
    let sign_result = xaman.wait_for_signature(&payload, 300).await?;

    if sign_result.txid.is_empty() {
        return Err(ClientError::Auth("Burn transaction was rejected".into()));
    }

    tracing::info!("NFT {} burned, tx: {}", nft_token_id, sign_result.txid);

    // Удаляем данные из Oracle
    let session = state.get_session().await?;
    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/vault/{}/delete",
        state.config.oracle_url,
        nft_token_id
    );

    let response = client
        .post(&oracle_url)
        .json(&serde_json::json!({
            "wallet_address": session.wallet_address
        }))
        .send()
        .await;

    // Не критично если Oracle delete не сработал - NFT уже сожжён
    match response {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("Oracle data deleted for NFT {}", nft_token_id);
        }
        Ok(resp) => {
            tracing::warn!("Oracle delete returned {}: NFT burned but data may remain", resp.status());
        }
        Err(e) => {
            tracing::warn!("Oracle delete failed: {}. NFT burned but data may remain", e);
        }
    }

    Ok(BurnNftResult {
        success: true,
        tx_hash: sign_result.txid,
        message: "NFT burned successfully".to_string(),
    })
}

// ==================== Secure Notes ====================

/// Secure Note - зашифрованная заметка
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    pub nft_token_id: String,
    pub title: String,
    pub note_type: String, // "password", "seed", "key", "note"
    pub size: u64,
    pub created_at: String,
}

/// Результат создания secure note
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteResult {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub xaman_link: String,
    pub title: String,
    pub size: u64,
}

/// Шифрует и загружает текстовые данные (пароли, ключи, заметки)
/// Данные хранятся ТОЛЬКО в RAM и очищаются после шифрования
#[tauri::command]
pub async fn encrypt_secure_note(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    title: String,
    content: String,
    note_type: String,
) -> Result<SecureNoteResult> {
    use zeroize::Zeroize;

    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized".to_string()));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());

    // Размер данных
    let content_size = content.len() as u64;

    tracing::info!(
        "Creating secure note '{}' ({} bytes, type: {})",
        title, content_size, note_type
    );

    // Progress
    let mut progress = ProgressEvent::new(&title, "upload");
    progress.bytes_total = content_size;
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting secure note...".to_string();
    progress.total_progress = 10;
    progress.emit(&app);

    // Конвертируем в bytes для шифрования
    let mut content_bytes = content.into_bytes();

    // MIME type для заметок
    let mime_type = match note_type.as_str() {
        "password" => "application/x-password",
        "seed" => "application/x-seed-phrase",
        "key" => "application/x-api-key",
        _ => "text/plain",
    };

    // Шифруем
    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(
        &content_bytes,
        &format!("{}.secure", title),
        mime_type,
        &public_key
    )?;

    // 🔒 ВАЖНО: Очищаем plaintext из памяти
    content_bytes.zeroize();

    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.message = "Note encrypted".to_string();
    progress.emit(&app);

    tracing::info!("Secure note encrypted: {} bytes", encrypted_bytes.len());

    // Создаём vault (минтим NFT)
    progress.stage = "minting".to_string();
    progress.message = "Creating secure vault...".to_string();
    progress.total_progress = 40;
    progress.emit(&app);

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let vault_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash: encrypted.manifest.compute_hash(),
        manifest: VaultManifest {
            encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
            original_size: encrypted.manifest.original_size,
            mime_type: mime_type.to_string(),
            original_hash: encrypted.manifest.original_hash.clone(),
            fragments: vec![VaultFragment {
                index: 0,
                storage_node_id: String::new(),
                storage_key: String::new(),
                encrypted_hash: encrypted.encrypted_hash.clone(),
                size: encrypted_bytes.len() as u64,
            }],
        },
    };

    progress.total_progress = 50;
    progress.message = "Minting NFT...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&vault_request).await?;

    progress.total_progress = 70;
    progress.message = "NFT created!".to_string();
    progress.emit(&app);

    tracing::info!(
        "Secure note vault created: NFT {}",
        vault_response.nft_token_id
    );

    // Загружаем через Oracle proxy
    progress.stage = "uploading".to_string();
    progress.message = "Uploading encrypted note...".to_string();
    progress.total_progress = 75;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url,
        vault_response.nft_token_id
    );

    let response = state.create_authed_client().await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload note: {} - {}",
            status, error_text
        )));
    }

    progress.stage = "complete".to_string();
    progress.total_progress = 100;
    progress.message = "Secure note saved!".to_string();
    progress.emit(&app);

    tracing::info!("Secure note '{}' saved successfully", title);

    Ok(SecureNoteResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        xaman_link: vault_response.xaman_link,
        title,
        size: content_size,
    })
}

/// Расшифровывает и возвращает содержимое secure note
/// Данные возвращаются в UI и должны быть очищены там после использования
#[tauri::command]
pub async fn decrypt_secure_note(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<SecureNoteContent> {
    let _session = state.get_session().await?;

    tracing::info!("Decrypting secure note: {}", nft_token_id);

    // Получаем метаданные
    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/files/{}/access",
        state.config.oracle_url, nft_token_id
    );

    let file_info: serde_json::Value = client
        .get(&oracle_url)
        .send()
        .await?
        .json()
        .await?;

    let encrypted_aes_key = file_info["encrypted_aes_key"]
        .as_str()
        .ok_or_else(|| ClientError::Oracle("Missing encrypted_aes_key".into()))?;

    let is_re_encrypted = file_info["is_re_encrypted"]
        .as_bool()
        .unwrap_or(false);

    let mime_type = file_info["manifest"]["mime_type"]
        .as_str()
        .unwrap_or("text/plain")
        .to_string();

    // Скачиваем через Oracle proxy
    let download_url = format!(
        "{}/api/v1/files/{}/download",
        state.config.oracle_url, nft_token_id
    );

    let response = client.get(&download_url).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        tracing::error!(
            "Failed to download note {}: {} - {}",
            nft_token_id, status, error_body
        );
        return Err(ClientError::Oracle(format!(
            "Failed to download note ({}): {}",
            status,
            if error_body.contains("missing from all storage nodes") {
                "Encrypted data is missing from storage. The note may need to be re-created.".to_string()
            } else {
                error_body
            }
        )));
    }

    let encrypted_data = response.bytes().await?.to_vec();

    // Расшифровываем AES ключ
    let keypair = state.get_keypair().await?;

    let aes_key_bytes = if is_re_encrypted {
        tracing::info!("Decrypting re-encrypted AES key");
        let re_encrypted_data = xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        tracing::info!("Decrypting original AES key");
        let encrypted_pre_data = xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
            .map_err(|e| ClientError::Crypto(e))?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    // Расшифровываем данные
    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;
    let encrypted_fragment = xrpl_vault_crypto_core::EncryptedData::from_bytes(&encrypted_data)?;
    let decrypted = aes_key.decrypt(&encrypted_fragment)?;

    // Конвертируем в строку
    let content = String::from_utf8(decrypted)
        .map_err(|_| ClientError::Config("Invalid UTF-8 in note".to_string()))?;

    // Определяем тип по MIME
    let note_type = match mime_type.as_str() {
        "application/x-password" => "password",
        "application/x-seed-phrase" => "seed",
        "application/x-api-key" => "key",
        _ => "note",
    }.to_string();

    tracing::info!("Secure note decrypted: {} bytes", content.len());

    Ok(SecureNoteContent {
        nft_token_id,
        content,
        note_type,
        mime_type,
    })
}

/// Содержимое расшифрованной заметки
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteContent {
    pub nft_token_id: String,
    pub content: String,
    pub note_type: String,
    pub mime_type: String,
}

/// Получить список secure notes пользователя
#[tauri::command]
pub async fn list_secure_notes(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<SecureNote>> {
    let _session = state.get_session().await?;

    // Получаем все файлы и фильтруем по MIME type
    let files = get_my_files(state.clone()).await?;

    let secure_notes: Vec<SecureNote> = files
        .into_iter()
        .filter(|f| {
            f.mime_type.starts_with("application/x-") ||
                f.mime_type == "text/plain"
        })
        .filter(|f| f.filename.ends_with(".secure"))
        .map(|f| {
            let note_type = match f.mime_type.as_str() {
                "application/x-password" => "password",
                "application/x-seed-phrase" => "seed",
                "application/x-api-key" => "key",
                _ => "note",
            }.to_string();

            let title = f.filename
                .strip_suffix(".secure")
                .unwrap_or(&f.filename)
                .to_string();

            SecureNote {
                nft_token_id: f.nft_token_id,
                title,
                note_type,
                size: f.size,
                created_at: f.uploaded_at,
            }
        })
        .collect();

    tracing::info!("Found {} secure notes", secure_notes.len());

    Ok(secure_notes)
}

/// Статус claim NFT
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimStatus {
    pub claimed: bool,
    pub expired: bool,
    pub owner_address: Option<String>,
}

/// Проверка статуса claim NFT
/// Проверяет, был ли NFT получен пользователем (offer принят)
#[tauri::command]
pub async fn check_claim_status(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    offer_index: String,
) -> Result<ClaimStatus> {
    tracing::info!("Checking claim status for NFT: {}, offer: {}", nft_token_id, offer_index);

    let _session = state.get_session().await?;

    let url = format!(
        "{}/api/v1/vault/claim-status/{}/{}",
        state.config.oracle_url, nft_token_id, offer_index
    );

    let response = state.create_authed_client().await
        .get(&url)
        .send()
        .await?;

    if response.status().is_success() {
        let status: ClaimStatus = response.json().await
            .map_err(|e| ClientError::Oracle(format!("Failed to parse claim status: {}", e)))?;

        tracing::info!("Claim status: claimed={}, expired={}", status.claimed, status.expired);
        Ok(status)
    } else {
        tracing::warn!("Oracle claim-status endpoint error, assuming not claimed");
        Ok(ClaimStatus {
            claimed: false,
            expired: false,
            owner_address: None,
        })
    }
}

/// Отмена offer и сжигание NFT
/// Вызывается когда пользователь отменяет операцию или истекло время
#[tauri::command]
pub async fn cancel_secure_note_offer(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    offer_index: String,
) -> Result<()> {
    tracing::info!("Cancelling secure note offer: NFT={}, offer={}", nft_token_id, offer_index);

    let _session = state.get_session().await?;

    let url = format!("{}/api/v1/vault/cancel-offer", state.config.oracle_url);

    let response = state.create_authed_client().await
        .post(&url)
        .json(&serde_json::json!({
            "nft_token_id": nft_token_id,
            "offer_index": offer_index,
        }))
        .send()
        .await?;

    if response.status().is_success() {
        tracing::info!("Offer cancelled and NFT burned successfully");
        Ok(())
    } else {
        let error_text = response.text().await.unwrap_or_default();
        tracing::error!("Failed to cancel offer: {}", error_text);
        Err(ClientError::Oracle(format!("Failed to cancel offer: {}", error_text)))
    }
}

// ==================== Oracle Auth Commands ====================

/// Check if user is authenticated with Oracle
#[tauri::command]
pub async fn check_oracle_auth(state: State<'_, Arc<AppState>>) -> Result<bool> {
    Ok(state.has_oracle_token().await)
}

/// Get Oracle auth status with user info
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleAuthStatus {
    pub authenticated: bool,
    pub wallet_address: Option<String>,
    pub expires_at: Option<String>,
}

/// Track if Oracle was ever authenticated (for session expiry detection)
static WAS_EVER_ORACLE_AUTHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Reset the "was ever authenticated" flag (called on logout)
pub fn reset_oracle_auth_flag() {
    WAS_EVER_ORACLE_AUTHED.store(false, std::sync::atomic::Ordering::Relaxed);
}

#[tauri::command]
pub async fn get_oracle_auth_status(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<OracleAuthStatus> {
    let has_token = state.has_oracle_token().await;
    tracing::info!("[AUTH_CHECK] has_oracle_token={}", has_token);

    // First try: do we have a valid (non-expired) token?
    if has_token {
        // Token is valid, verify with Oracle
        match state.get_oracle_client_with_timeout(10).await {
            Ok(oracle) => {
                if let Ok(user) = oracle.get_me().await {
                    tracing::info!("[AUTH_CHECK] → authenticated=true (get_me OK)");
                    WAS_EVER_ORACLE_AUTHED.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(OracleAuthStatus {
                        authenticated: true,
                        wallet_address: Some(user.wallet_address),
                        expires_at: None,
                    });
                }
                tracing::warn!("[AUTH_CHECK] get_me failed, falling through to refresh");
            }
            Err(e) => {
                tracing::warn!("[AUTH_CHECK] get_oracle_client failed: {}, falling through to refresh", e);
            }
        }
    }

    // Token expired or invalid — try to refresh
    match state.try_refresh_oracle_token().await {
        Ok(true) => {
            tracing::info!("[AUTH_CHECK] Oracle token auto-refreshed during status check");
            WAS_EVER_ORACLE_AUTHED.store(true, std::sync::atomic::Ordering::Relaxed);
            // Re-check with refreshed token
            if let Ok(oracle) = state.get_oracle_client_with_timeout(10).await {
                if let Ok(user) = oracle.get_me().await {
                    tracing::info!("[AUTH_CHECK] → authenticated=true (after refresh)");
                    return Ok(OracleAuthStatus {
                        authenticated: true,
                        wallet_address: Some(user.wallet_address),
                        expires_at: None,
                    });
                }
            }
            Ok(OracleAuthStatus { authenticated: true, wallet_address: None, expires_at: None })
        }
        _ => {
            tracing::warn!("[AUTH_CHECK] → authenticated=false (no token, refresh failed)");
            // If was ever authenticated → session expired → force logout
            if WAS_EVER_ORACLE_AUTHED.load(std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!("[AUTH_CHECK] SESSION EXPIRED — forcing full logout and page reload");
                WAS_EVER_ORACLE_AUTHED.store(false, std::sync::atomic::Ordering::Relaxed);

                // Clear ALL session state on Rust side
                state.clear_session().await;

                // Force frontend to reload — bypasses all React/Vite issues
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.eval("window.location.reload();");
                }
            }
            Ok(OracleAuthStatus { authenticated: false, wallet_address: None, expires_at: None })
        }
    }
}

/// Start Oracle login - returns Xaman payload for signing
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleLoginPayload {
    pub challenge: String,
    pub xaman_payload: crate::auth::xaman::XamanPayload,
}

#[tauri::command]
pub async fn oracle_login_start(
    state: State<'_, Arc<AppState>>,
) -> Result<OracleLoginPayload> {
    let session = state.get_session().await?;
    let wallet_address = &session.wallet_address;

    // Get challenge from Oracle
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    let challenge_response = oracle.get_auth_challenge(wallet_address).await?;
    let challenge = challenge_response.challenge;

    // Create Xaman SignIn payload
    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);

    // SignIn request with custom instruction
    let payload_request = serde_json::json!({
        "txjson": {
            "TransactionType": "SignIn"
        },
        "options": {
            "instruction": format!("Sign to authenticate: {}", challenge)
        }
    });

    let payload = xaman.create_payload(payload_request).await?;

    tracing::info!("Oracle login started for {}, challenge: {}", wallet_address, challenge);

    Ok(OracleLoginPayload {
        challenge,
        xaman_payload: payload,
    })
}

/// Complete Oracle login - exchange signature for JWT
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleLoginComplete {
    pub challenge: String,
    pub public_key: String,
    pub signature: String,
}

#[tauri::command]
pub async fn oracle_login_complete(
    state: State<'_, Arc<AppState>>,
    login_data: OracleLoginComplete,
) -> Result<bool> {
    let session = state.get_session().await?;

    // Exchange signature for JWT
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    let token_response = oracle.get_auth_token(&crate::oracle::api::AuthTokenRequest {
        wallet_address: session.wallet_address.clone(),
        public_key: login_data.public_key,
        signature: login_data.signature,
        challenge: login_data.challenge,
        device_fingerprint: Some(state.device_fingerprint().to_string()),
    }).await?;

    // Save all tokens
    let expires_in = token_response.expires_in;
    state.save_oracle_tokens(
        token_response.access_token,
        expires_in,
        token_response.refresh_token,
        token_response.role,
    ).await?;

    tracing::info!(
        "Oracle login successful for {} (expires in {}s)",
        session.wallet_address,
        expires_in
    );

    Ok(true)
}

/// Wait for Xaman SignIn and complete Oracle login
#[tauri::command]
pub async fn oracle_login_wait(
    state: State<'_, Arc<AppState>>,
    payload_uuid: String,
    websocket_url: String,
    qr_png: String,
    challenge: String,
) -> Result<bool> {
    let session = state.get_session().await?;

    // Wait for Xaman signature
    let api_key = std::env::var("XAMAN_API_KEY")
        .map_err(|_| ClientError::Auth("XAMAN_API_KEY not set".into()))?;
    let api_secret = String::new();

    let xaman = crate::auth::xaman::XamanAuth::new(api_key, api_secret);

    // Create XamanPayload from parameters
    let payload = crate::auth::xaman::XamanPayload {
        uuid: payload_uuid,
        qr_png,
        qr_uri: String::new(),
        websocket_url,
        expires_at: None,
    };

    // This will wait for the user to sign
    let sign_result = xaman.wait_for_signature(&payload, 300).await?;

    let public_key = sign_result.public_key
        .ok_or_else(|| ClientError::Auth("No public key in Xaman response".into()))?;
    let signature = sign_result.txn_signature
        .ok_or_else(|| ClientError::Auth("No signature in Xaman response".into()))?;

    // Exchange for JWT
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    let token_response = oracle.get_auth_token(&crate::oracle::api::AuthTokenRequest {
        wallet_address: session.wallet_address.clone(),
        public_key,
        signature,
        challenge,
        device_fingerprint: Some(state.device_fingerprint().to_string()),
    }).await?;

    // Save all tokens (access + refresh + device fingerprint + role)
    let expires_in = token_response.expires_in;
    let has_refresh = token_response.refresh_token.is_some();
    state.save_oracle_tokens(
        token_response.access_token,
        token_response.expires_in,
        token_response.refresh_token,
        token_response.role,
    ).await?;

    tracing::info!(
        "Oracle login successful for {} (expires in {}s, has refresh: {})",
        session.wallet_address,
        expires_in,
        has_refresh
    );

    Ok(true)
}
#[tauri::command]
pub async fn oracle_logout(state: State<'_, Arc<AppState>>) -> Result<bool> {
    // Try to call logout endpoint
    if state.has_oracle_token().await {
        if let Ok(oracle) = state.get_oracle_client().await {
            let _ = oracle.logout().await; // Ignore errors
        }
    }

    // Clear token from state
    state.set_oracle_token(String::new()).await?;

    // Reset the "was ever authenticated" flag
    reset_oracle_auth_flag();

    tracing::info!("Oracle logout completed");

    Ok(true)
}

/// Refresh Oracle token using stored refresh token
#[tauri::command]
pub async fn oracle_refresh_token(state: State<'_, Arc<AppState>>) -> Result<bool> {
    state.try_refresh_oracle_token().await
}

/// Get device fingerprint (for debugging/display)
#[tauri::command]
pub async fn get_device_fingerprint(state: State<'_, Arc<AppState>>) -> Result<String> {
    Ok(state.device_fingerprint().to_string())
}

/// Get Oracle auth status with extended info
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleAuthStatusExtended {
    pub authenticated: bool,
    pub wallet_address: Option<String>,
    pub expires_at: Option<String>,
    pub has_refresh_token: bool,
    pub role: Option<String>,
    pub device_fingerprint: String,
    pub needs_refresh: bool,
}

#[tauri::command]
pub async fn get_oracle_auth_status_extended(state: State<'_, Arc<AppState>>) -> Result<OracleAuthStatusExtended> {
    let dfp = state.device_fingerprint().to_string();

    if let Ok(session) = state.get_session().await {
        let authenticated = session.oracle_token.is_some() && !session.oracle_token_is_expired();
        let needs_refresh = session.oracle_token_needs_refresh();
        let has_refresh = session.refresh_token.is_some();
        Ok(OracleAuthStatusExtended {
            authenticated,
            wallet_address: Some(session.wallet_address.clone()),
            expires_at: session.oracle_token_expires_at.map(|dt| dt.to_rfc3339()),
            has_refresh_token: has_refresh,
            role: session.role.clone(),
            device_fingerprint: dfp,
            needs_refresh,
        })
    } else {
        Ok(OracleAuthStatusExtended {
            authenticated: false,
            wallet_address: None,
            expires_at: None,
            has_refresh_token: false,
            role: None,
            device_fingerprint: dfp,
            needs_refresh: false,
        })
    }
}