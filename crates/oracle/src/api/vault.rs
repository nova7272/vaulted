//! Vault API - регистрация зашифрованных данных и получение NFT
//!
//! Oracle НЕ шифрует данные! Клиент делает это сам.

use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    services::AppState,
};

/// Запрос на создание vault
/// Клиент уже зашифровал файл и загрузил на storage nodes
#[derive(Debug, Deserialize)]
pub struct CreateVaultRequest {
    /// XRPL адрес владельца
    pub wallet_address: String,
    /// PRE публичный ключ владельца
    pub pre_public_key: String,
    /// AES ключ, зашифрованный PRE публичным ключом (base64)
    pub encrypted_aes_key: String,
    /// Hash манифеста (для URI)
    pub metadata_hash: String,
    /// Манифест с информацией о файле
    pub manifest: VaultManifest,
}

/// Манифест файла (метаданные)
#[derive(Debug, Deserialize, Serialize)]
pub struct VaultManifest {
    /// Оригинальное имя файла
    pub encrypted_filename: String,
    /// Размер до шифрования
    pub original_size: u64,
    /// MIME тип
    pub mime_type: String,
    /// Hash оригинального файла
    pub original_hash: String,
    /// Фрагменты на storage nodes
    pub fragments: Vec<FragmentInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FragmentInfo {
    pub index: u32,
    pub storage_node_id: String,
    pub storage_key: String,
    pub encrypted_hash: String,
    pub size: u64,
}

/// Ответ с данными для получения NFT
#[derive(Debug, Serialize)]
pub struct CreateVaultResponse {
    /// ID записи в Oracle
    pub vault_id: Uuid,
    /// NFT Token ID (уже заминчен)
    pub nft_token_id: String,
    /// Offer index для AcceptOffer
    pub offer_index: String,
    /// Deep link для Xaman
    pub xaman_link: String,
    /// URI в NFT
    pub nft_uri: String,
}

/// POST /api/v1/vault/create
///
/// Регистрирует vault: минтит NFT и создаёт offer для пользователя.
/// Файл УЖЕ зашифрован и загружен клиентом!
///
/// **Requires authentication** - wallet_address must match JWT
pub async fn create_vault(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<CreateVaultResponse>> {
    // Verify that authenticated user matches request
    if !auth.wallet_address.eq_ignore_ascii_case(&req.wallet_address) {
        tracing::warn!(
            "Auth mismatch: JWT wallet {} != request wallet {}",
            auth.wallet_address,
            req.wallet_address
        );
        return Err(ApiError::Forbidden(
            "Cannot create vault for different wallet".into()
        ));
    }

    // Валидация
    if !req.wallet_address.starts_with('r') {
        return Err(ApiError::Validation("Invalid XRPL address".into()));
    }

    if req.encrypted_aes_key.is_empty() {
        return Err(ApiError::Validation("encrypted_aes_key required".into()));
    }

    if req.metadata_hash.is_empty() {
        return Err(ApiError::Validation("metadata_hash required".into()));
    }

    tracing::info!(
        "Creating vault for {} (file: {}, {} bytes)",
        req.wallet_address,
        req.manifest.encrypted_filename,
        req.manifest.original_size
    );

    // 1. URI для NFT — public metadata URL for wallet resolution
    // We use metadata_hash as identifier because nft_token_id is not known until after minting
    let nft_uri = if let Some(ref public_url) = state.config.public_url {
        format!("{}/nft/{}/metadata.json", public_url.trim_end_matches('/'), &req.metadata_hash)
    } else {
        format!("vaulted://{}", &req.metadata_hash)
    };

    // 2. Получаем или создаём user
    let user_id = get_or_create_user(&state, &req.wallet_address, &req.pre_public_key).await?;

    // 3. Минтим NFT (Oracle подписывает)
    let mint_result = state.xrpl.mint_nft(&nft_uri, 0).await?;

    // 4. Создаём sell offer для user (бесплатно)
    let offer_result = state.xrpl.create_sell_offer(
        &mint_result.nft_token_id,
        &req.wallet_address,
    ).await?;

    // 5. Сохраняем в БД
    let vault_id = Uuid::new_v4();
    let manifest_json = serde_json::to_value(&req.manifest)
        .map_err(|e| ApiError::Internal(format!("JSON error: {}", e)))?;

    // Store manifest — encrypt if key available, keep plain JSON as fallback
    if let Some(ref enc_key) = state.config.db_encryption_key {
        sqlx::query(r#"
            INSERT INTO nft_metadata 
            (id, nft_token_id, owner_id, encrypted_aes_key, metadata_hash, manifest, encrypted_manifest, offer_index, status, created_at)
            VALUES ($1, $2, $3, $4, $5, NULL, vault_encrypt($6::text, $7), $8, 'active', NOW())
        "#)
            .bind(vault_id)
            .bind(&mint_result.nft_token_id)
            .bind(user_id)
            .bind(&req.encrypted_aes_key)
            .bind(&req.metadata_hash)
            .bind(&manifest_json.to_string())
            .bind(enc_key)
            .bind(&offer_result.offer_index)
            .execute(&state.db)
            .await?;
    } else {
        sqlx::query(r#"
            INSERT INTO nft_metadata 
            (id, nft_token_id, owner_id, encrypted_aes_key, metadata_hash, manifest, offer_index, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', NOW())
        "#)
            .bind(vault_id)
            .bind(&mint_result.nft_token_id)
            .bind(user_id)
            .bind(&req.encrypted_aes_key)
            .bind(&req.metadata_hash)
            .bind(&manifest_json)
            .bind(&offer_result.offer_index)
            .execute(&state.db)
            .await?;
    }

    // 6. Xaman deep link для AcceptOffer
    let xaman_link = format!(
        "https://xumm.app/sign/NFTokenAcceptOffer?NFTokenSellOffer={}",
        offer_result.offer_index
    );

    tracing::info!(
        "Vault {} created. NFT: {}, Offer: {}",
        vault_id, mint_result.nft_token_id, offer_result.offer_index
    );

    // Аудит
    state
        .audit_log(
            Some(user_id),
            "vault_created",
            Some(&mint_result.nft_token_id),
            Some(serde_json::json!({
                "vault_id": vault_id,
                "filename": req.manifest.encrypted_filename,
                "size": req.manifest.original_size,
                "offer_index": offer_result.offer_index,
            })),
        )
        .await;

    Ok(Json(CreateVaultResponse {
        vault_id,
        nft_token_id: mint_result.nft_token_id,
        offer_index: offer_result.offer_index,
        xaman_link,
        nft_uri,
    }))
}

/// Получает или создаёт пользователя
async fn get_or_create_user(
    state: &AppState,
    wallet: &str,
    pre_key: &str,
) -> Result<Uuid> {
    // Проверяем существует ли
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE wallet_address = $1"
    )
        .bind(wallet)
        .fetch_optional(&state.db)
        .await? {
        return Ok(id);
    }

    // Создаём нового
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, wallet_address, pre_public_key, created_at) VALUES ($1, $2, $3, NOW())"
    )
        .bind(id)
        .bind(wallet)
        .bind(pre_key)
        .execute(&state.db)
        .await?;

    Ok(id)
}

/// GET /api/v1/vault/:id - статус vault
#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub vault_id: Uuid,
    pub status: String,
    pub nft_token_id: String,
    pub offer_index: Option<String>,
    pub owner_address: String,
    pub nft_uri: String,
    pub created_at: String,
}

pub async fn get_vault(
    _auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
    axum::extract::Path(vault_id): axum::extract::Path<Uuid>,
) -> Result<Json<VaultStatus>> {
    let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT nm.nft_token_id, nm.status, nm.offer_index, u.wallet_address, nm.metadata_hash, nm.created_at
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.id = $1
        "#
    )
        .bind(vault_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Vault {} not found", vault_id)))?;

    Ok(Json(VaultStatus {
        vault_id,
        nft_token_id: row.0,
        status: row.1,
        offer_index: row.2,
        owner_address: row.3,
        nft_uri: format!("vaulted://{}", row.4),
        created_at: row.5.to_rfc3339(),
    }))
}
/// Получение информации о файле по NFT token ID
#[derive(Debug, Serialize)]
pub struct FileDownloadInfo {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub encrypted_filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragments: Vec<FragmentInfo>,
}

pub async fn get_file_by_nft(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
    axum::extract::Path(nft_token_id): axum::extract::Path<String>,
) -> Result<Json<FileDownloadInfo>> {
    // Verify NFT ownership (CRIT-03)
    let owner_wallet: Option<String> = sqlx::query_scalar(
        r#"
        SELECT u.wallet_address FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#
    )
        .bind(&nft_token_id)
        .fetch_optional(&state.db)
        .await?;

    match owner_wallet {
        Some(ref wallet) if !auth.wallet_address.eq_ignore_ascii_case(wallet) => {
            return Err(ApiError::Forbidden(
                "Only the NFT owner can access file data".into()
            ));
        }
        None => {
            return Err(ApiError::NotFound(format!("NFT {} not found", nft_token_id)));
        }
        _ => {}
    }

    // Получаем метаданные NFT включая манифест
    let row = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT encrypted_aes_key, manifest FROM nft_metadata WHERE nft_token_id = $1"
    )
        .bind(&nft_token_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("NFT {} not found", nft_token_id)))?;

    let encrypted_aes_key = row.0;
    let manifest_json = row.1;

    // Парсим манифест из JSON
    let manifest: VaultManifest = serde_json::from_value(manifest_json)
        .map_err(|e| ApiError::Internal(format!("Failed to parse manifest: {}", e)))?;

    Ok(Json(FileDownloadInfo {
        nft_token_id,
        encrypted_aes_key,
        encrypted_filename: manifest.encrypted_filename,
        original_size: manifest.original_size,
        mime_type: manifest.mime_type,
        original_hash: manifest.original_hash,
        fragments: manifest.fragments,
    }))
}

/// DELETE /api/v1/vault/:nft_token_id - удалить vault
///
/// Удаляет vault и связанные данные. NFT должен быть сожжён пользователем.
/// Oracle удаляет: метаданные из БД, файлы со storage nodes.
///
/// **Requires authentication** - only owner can delete
#[derive(Debug, Serialize)]
pub struct DeleteVaultResponse {
    pub success: bool,
    pub message: String,
    pub deleted_fragments: usize,
}

#[derive(Debug, Deserialize)]
pub struct DeleteVaultRequest {
    pub wallet_address: String,
}

pub async fn delete_vault(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    axum::extract::Path(nft_token_id): axum::extract::Path<String>,
    Json(request): Json<DeleteVaultRequest>,
) -> Result<Json<DeleteVaultResponse>> {
    // Verify authenticated user matches request
    if !auth.wallet_address.eq_ignore_ascii_case(&request.wallet_address) {
        return Err(ApiError::Forbidden(
            "Cannot delete vault for different wallet".into()
        ));
    }

    // Получаем информацию о vault
    let vault = sqlx::query_as::<_, (Uuid, Uuid, String, serde_json::Value)>(
        r#"
        SELECT nm.id, nm.owner_id, nm.status, nm.manifest
        FROM nft_metadata nm
        WHERE nm.nft_token_id = $1
        "#,
    )
        .bind(&nft_token_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Vault with NFT {} not found", nft_token_id)))?;

    let (nft_metadata_id, owner_id, status, manifest_json) = vault;

    // Проверяем что запрос от владельца (DB check)
    let owner_wallet = sqlx::query_scalar::<_, String>(
        "SELECT wallet_address FROM users WHERE id = $1"
    )
        .bind(owner_id)
        .fetch_one(&state.db)
        .await?;

    if !owner_wallet.eq_ignore_ascii_case(&request.wallet_address) {
        return Err(ApiError::Forbidden(
            "Only the owner can delete vault".to_string(),
        ));
    }

    // CRIT-03 FIX: Verify NFT ownership on-chain before allowing deletion.
    // Without this, a previous owner (still in DB) could delete files after
    // the NFT was transferred externally (outside the app).
    match state.xrpl.verify_nft_owner(&nft_token_id, &auth.wallet_address).await {
        Ok(true) => {
            tracing::debug!("On-chain NFT ownership verified for delete: {}", nft_token_id);
        }
        Ok(false) => {
            tracing::warn!(
                "BLOCKED: delete_vault for NFT {} — wallet {} is DB owner but NOT on-chain owner",
                nft_token_id, auth.wallet_address
            );
            return Err(ApiError::Forbidden(
                "NFT ownership could not be verified on XRPL ledger. \
                 The NFT may have been transferred outside the app.".into()
            ));
        }
        Err(e) => {
            // XRPL node may be down — deny deletion to be safe (fail-closed)
            tracing::warn!(
                "On-chain verification failed for delete of NFT {}: {} — denying deletion",
                nft_token_id, e
            );
            return Err(ApiError::Internal(
                "Unable to verify NFT ownership on-chain. Please try again later.".into()
            ));
        }
    }

    // Проверяем статус - нельзя удалить vault в процессе передачи
    if status == "transferring" {
        return Err(ApiError::BadRequest(
            "Cannot delete vault while transfer is in progress".to_string(),
        ));
    }

    // Парсим манифест для получения информации о фрагментах
    let manifest: VaultManifest = serde_json::from_value(manifest_json)
        .map_err(|e| ApiError::Internal(format!("Failed to parse manifest: {}", e)))?;

    let fragment_count = manifest.fragments.len();

    // CRIT-04 FIX: Use signed StorageToken for fragment deletion instead of
    // unauthenticated HTTP DELETE. This ensures storage nodes verify the request
    // was authorized by Oracle.
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut deleted_fragments = 0;

    // PERF FIX: Preload all node endpoints in one query
    let node_endpoints: std::collections::HashMap<String, String> = sqlx::query_as::<_, (String, String)>(
        "SELECT id, endpoint_url FROM storage_nodes"
    )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .collect();

    for fragment in &manifest.fragments {
        let endpoint_url = if !fragment.storage_node_id.is_empty() {
            node_endpoints.get(&fragment.storage_node_id)
                .cloned()
                .unwrap_or_else(|| "http://localhost:9001".to_string())
        } else {
            std::env::var("STORAGE_NODE_URL")
                .unwrap_or_else(|_| "http://localhost:9001".to_string())
        };

        // Create signed delete token
        let token = crate::storage_token::StorageToken::new_delete(
            &nft_token_id, &fragment.storage_key, 5,
        );
        let signed = crate::storage_token::sign_storage_token(&token, &state.signing_key);
        let url = format!(
            "{}/fragments/{}?token={}",
            endpoint_url, fragment.storage_key, signed
        );

        match http_client.delete(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == 404 => {
                deleted_fragments += 1;
                tracing::debug!("Deleted fragment {} from storage", fragment.storage_key);
            }
            Ok(resp) => {
                tracing::warn!(
                    "Failed to delete fragment {}: HTTP {}",
                    fragment.storage_key,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to delete fragment {}: {}", fragment.storage_key, e);
            }
        }
    }

    // Удаляем связанные transfer_requests
    sqlx::query("DELETE FROM transfer_requests WHERE nft_metadata_id = $1")
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await?;

    // Удаляем file_manifests (если есть отдельная таблица)
    let _ = sqlx::query("DELETE FROM file_manifests WHERE nft_metadata_id = $1")
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await;

    // Удаляем nft_metadata
    sqlx::query("DELETE FROM nft_metadata WHERE id = $1")
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await?;

    // Аудит
    state
        .audit_log(
            Some(owner_id),
            "vault_deleted",
            Some(&nft_token_id),
            Some(serde_json::json!({
                "fragments_deleted": deleted_fragments,
                "total_fragments": fragment_count,
            })),
        )
        .await;

    tracing::info!(
        "Vault {} deleted by {}. Fragments: {}/{}",
        nft_token_id,
        request.wallet_address,
        deleted_fragments,
        fragment_count
    );

    Ok(Json(DeleteVaultResponse {
        success: true,
        message: format!(
            "Vault deleted. {} of {} fragments removed from storage.",
            deleted_fragments, fragment_count
        ),
        deleted_fragments,
    }))
}

// =============================================================================
// CLAIM STATUS & CANCEL OFFER
// =============================================================================

/// Ответ на проверку статуса claim
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimStatusResponse {
    pub claimed: bool,
    pub expired: bool,
    pub owner_address: Option<String>,
}

/// GET /api/vault/claim-status/{nft_token_id}/{offer_index}
///
/// Проверяет, был ли NFT получен (offer принят)
pub async fn check_claim_status(
    State(state): State<AppState>,
    axum::extract::Path((nft_token_id, offer_index)): axum::extract::Path<(String, String)>,
) -> Result<Json<ClaimStatusResponse>> {
    tracing::info!("Checking claim status: NFT={}, offer={}", nft_token_id, offer_index);

    let xrpl = &state.xrpl;

    // Проверяем есть ли NFT на Oracle кошельке
    match xrpl.check_nft_on_oracle(&nft_token_id).await {
        Ok(on_oracle) => {
            if on_oracle {
                // NFT всё ещё на Oracle - не claimed
                tracing::info!("NFT {} still on Oracle wallet", nft_token_id);
                Ok(Json(ClaimStatusResponse {
                    claimed: false,
                    expired: false,
                    owner_address: None,
                }))
            } else {
                // NFT не на Oracle - значит claimed!
                tracing::info!("NFT {} claimed (not on Oracle)", nft_token_id);
                Ok(Json(ClaimStatusResponse {
                    claimed: true,
                    expired: false,
                    owner_address: None, // Не знаем точно кому
                }))
            }
        }
        Err(e) => {
            // Ошибка проверки
            tracing::warn!("Error checking NFT {}: {}", nft_token_id, e);
            Ok(Json(ClaimStatusResponse {
                claimed: false,
                expired: true,
                owner_address: None,
            }))
        }
    }
}

/// Запрос на отмену offer
#[derive(Debug, Deserialize)]
pub struct CancelOfferRequest {
    pub nft_token_id: String,
    pub offer_index: String,
    pub wallet_address: String,
}

/// Ответ на отмену offer
#[derive(Debug, Serialize)]
pub struct CancelOfferResponse {
    pub success: bool,
    pub message: String,
}

/// POST /api/vault/cancel-offer
///
/// Отменяет offer и сжигает NFT (если он ещё на Oracle)
///
/// **Requires authentication** - only original creator can cancel
pub async fn cancel_offer(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<CancelOfferRequest>,
) -> Result<Json<CancelOfferResponse>> {
    // Verify authenticated user matches request
    if !auth.wallet_address.eq_ignore_ascii_case(&req.wallet_address) {
        return Err(ApiError::Forbidden(
            "Cannot cancel offer for different wallet".into()
        ));
    }

    // Verify the user is the intended recipient of this offer
    let owner_wallet = sqlx::query_scalar::<_, String>(
        r#"
        SELECT u.wallet_address FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#
    )
        .bind(&req.nft_token_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("NFT not found".into()))?;

    if !owner_wallet.eq_ignore_ascii_case(&req.wallet_address) {
        return Err(ApiError::Forbidden(
            "Only the intended recipient can cancel this offer".into()
        ));
    }

    tracing::info!("Cancelling offer: NFT={}, offer={}", req.nft_token_id, req.offer_index);

    let xrpl = &state.xrpl;

    // 1. Проверяем, что NFT всё ещё на Oracle
    let on_oracle = match xrpl.check_nft_on_oracle(&req.nft_token_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Error checking NFT {}: {}", req.nft_token_id, e);
            return Ok(Json(CancelOfferResponse {
                success: true,
                message: "NFT not found (already burned or claimed)".to_string(),
            }));
        }
    };

    if !on_oracle {
        tracing::info!("NFT {} not on Oracle (already claimed or burned)", req.nft_token_id);
        return Ok(Json(CancelOfferResponse {
            success: false,
            message: "NFT already claimed or burned".to_string(),
        }));
    }

    // 2. Отменяем offer
    match xrpl.cancel_offer(&req.offer_index).await {
        Ok(_) => {
            tracing::info!("Offer {} cancelled", req.offer_index);
        }
        Err(e) => {
            // Offer может быть уже отменён или принят
            tracing::warn!("Failed to cancel offer {}: {}", req.offer_index, e);
        }
    }

    // 3. Сжигаем NFT
    match xrpl.burn_nft(&req.nft_token_id).await {
        Ok(_) => {
            tracing::info!("NFT {} burned", req.nft_token_id);

            // Обновляем статус в БД
            let _ = sqlx::query(
                "UPDATE nft_metadata SET status = 'burned' WHERE nft_token_id = $1"
            )
                .bind(&req.nft_token_id)
                .execute(&state.db)
                .await;

            // Аудит
            state
                .audit_log(
                    None,
                    "offer_cancelled_nft_burned",
                    Some(&req.nft_token_id),
                    Some(serde_json::json!({
                        "offer_index": req.offer_index,
                        "reason": "user_cancelled_or_timeout",
                    })),
                )
                .await;

            Ok(Json(CancelOfferResponse {
                success: true,
                message: "Offer cancelled and NFT burned".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to burn NFT {}: {}", req.nft_token_id, e);
            Err(ApiError::Internal(format!("Failed to burn NFT: {}", e)))
        }
    }
}