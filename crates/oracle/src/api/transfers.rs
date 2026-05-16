//! Endpoints для передачи NFT
//!
//! Oracle выполняет PRE re-encryption с использованием kfrag от клиента

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xrpl_vault_crypto_core::pre::{EncryptedPreData, ProxyReEncryption, ReEncryptedData};

use crate::{
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    models::{
        CompleteTransferRequest, CompleteTransferResponse, InitiateTransferRequest,
        InitiateTransferResponse, TransferStatus, TransferStatusResponse,
    },
    services::AppState,
};

/// POST /api/v1/transfers/initiate - инициировать передачу NFT
///
/// Oracle получает kfrag от клиента и выполняет re-encryption.
/// Статус NFT НЕ меняется здесь - он изменится только после подтверждения на XRPL.
///
/// **Requires authentication** - from_address must match JWT
pub async fn initiate_transfer(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<InitiateTransferRequest>,
) -> Result<Json<InitiateTransferResponse>> {
    // Verify authenticated user matches request
    if !auth
        .wallet_address
        .eq_ignore_ascii_case(&request.from_address)
    {
        return Err(ApiError::Forbidden(
            "Cannot initiate transfer from different wallet".into(),
        ));
    }

    // Валидация
    if !request.from_address.starts_with('r') || !request.to_address.starts_with('r') {
        return Err(ApiError::Validation("Invalid wallet address".to_string()));
    }

    if request.re_encryption_key.is_empty() {
        return Err(ApiError::Validation(
            "re_encryption_key is required".to_string(),
        ));
    }

    // Получаем NFT metadata с encrypted_aes_key
    let nft_row = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        r#"
        SELECT nm.id, nm.owner_id, nm.encrypted_aes_key
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1 AND nm.status = 'active'
        "#,
    )
    .bind(&request.nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NftNotFound(request.nft_token_id.clone()))?;

    let (nft_metadata_id, from_user_id, encrypted_aes_key_base64) = nft_row;

    // Проверяем что from_address совпадает с owner
    let from_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(from_user_id)
            .fetch_one(&state.db)
            .await?;

    if !from_wallet.eq_ignore_ascii_case(&request.from_address) {
        return Err(ApiError::Forbidden(
            "Only the owner can initiate transfer".to_string(),
        ));
    }

    // Получаем to_user_id и pre_public_key получателя
    let to_user = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, pre_public_key FROM users WHERE wallet_address = $1",
    )
    .bind(&request.to_address)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        ApiError::NotFound(format!("Recipient {} not registered", request.to_address))
    })?;

    let (to_user_id, recipient_pre_public_key_hex) = to_user;

    // Парсим публичный ключ получателя для верификации kfrag
    let recipient_pk_bytes = hex::decode(&recipient_pre_public_key_hex)
        .map_err(|e| ApiError::Internal(format!("Invalid recipient pre_public_key hex: {}", e)))?;

    // Десериализуем encrypted_aes_key
    let encrypted_data = EncryptedPreData::from_base64(&encrypted_aes_key_base64)
        .map_err(|e| ApiError::Internal(format!("Failed to parse encrypted_aes_key: {}", e)))?;

    // Десериализуем kfrag из request
    let re_key_data = deserialize_re_key(&request.re_encryption_key)
        .map_err(|e| ApiError::Validation(format!("Invalid re_encryption_key: {}", e)))?;

    // Выполняем re-encryption с публичным ключом получателя для верификации
    let pre = ProxyReEncryption::new();
    let re_encrypted = perform_reencryption(
        &pre,
        &encrypted_data,
        &re_key_data,
        Some(&recipient_pk_bytes),
    )
    .map_err(|e| ApiError::Internal(format!("Re-encryption failed: {}", e)))?;

    // Сериализуем результат
    let re_encrypted_base64 = re_encrypted
        .to_base64()
        .map_err(|e| ApiError::Internal(format!("Failed to serialize re-encrypted data: {}", e)))?;

    // НЕ меняем статус NFT здесь!
    // Статус изменится на 'transferring' когда offer будет подписан,
    // и на 'active' с новым owner когда transfer будет завершён.

    // Создаём запрос на передачу со статусом 'pending'
    let transfer_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO transfer_requests
        (nft_metadata_id, from_user_id, to_user_id, re_encryption_key, re_encrypted_aes_key, status, completed_at)
        VALUES ($1, $2, $3, 'done', $4, 'pending', NULL)
        RETURNING id
        "#,
    )
        .bind(nft_metadata_id)
        .bind(from_user_id)
        .bind(to_user_id)
        .bind(&re_encrypted_base64)
        .fetch_one(&state.db)
        .await?;

    tracing::info!(
        "Transfer initiated: {} -> {}, NFT: {}, transfer_id: {}",
        request.from_address,
        request.to_address,
        request.nft_token_id,
        transfer_id
    );

    // Аудит
    state
        .audit_log(
            Some(from_user_id),
            "transfer_initiated",
            Some(&request.nft_token_id),
            Some(serde_json::json!({
                "to_address": request.to_address,
                "transfer_id": transfer_id,
            })),
        )
        .await;

    Ok(Json(InitiateTransferResponse {
        transfer_id,
        status: TransferStatus::Pending.to_string(),
    }))
}

/// Десериализует re_encryption_key (kfrag + sender_pk + sender_verifying_key)
fn deserialize_re_key(base64_data: &str) -> std::result::Result<ReKeyData, String> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("JSON parse error: {}", e))?;

    let kfrags: Vec<Vec<u8>> = json["kfrags"]
        .as_array()
        .ok_or("Missing kfrags")?
        .iter()
        .map(|v| {
            v.as_array().ok_or("Invalid kfrag format").map(|arr| {
                arr.iter()
                    .filter_map(|n| n.as_u64().map(|n| n as u8))
                    .collect()
            })
        })
        .collect::<std::result::Result<_, _>>()?;

    let sender_pk: Vec<u8> = json["sender_pk"]
        .as_array()
        .ok_or("Missing sender_pk")?
        .iter()
        .filter_map(|n| n.as_u64().map(|n| n as u8))
        .collect();

    // MED-04: sender_verifying_key for kfrag verification
    let sender_verifying_key: Option<Vec<u8>> =
        json["sender_verifying_key"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|n| n.as_u64().map(|n| n as u8))
                .collect()
        });

    Ok(ReKeyData {
        kfrags,
        sender_pk,
        sender_verifying_key,
    })
}

struct ReKeyData {
    kfrags: Vec<Vec<u8>>,
    sender_pk: Vec<u8>,
    /// Sender's signer verifying key for kfrag verification (MED-04)
    sender_verifying_key: Option<Vec<u8>>,
}

/// Выполняет re-encryption с обязательной верификацией kfrag (CRIT-01)
///
/// sender_verifying_key ОБЯЗАТЕЛЕН — без него невозможно верифицировать
/// kfrag и cfrag, что позволяет MITM-подмену данных.
fn perform_reencryption(
    pre: &ProxyReEncryption,
    encrypted_data: &EncryptedPreData,
    re_key_data: &ReKeyData,
    receiving_pk_bytes: Option<&[u8]>,
) -> std::result::Result<ReEncryptedData, String> {
    use umbral_pre::{DefaultDeserialize, KeyFrag, PublicKey as UmbralPublicKey};
    use xrpl_vault_crypto_core::pre::PrePublicKey;

    // CRIT-01: sender_verifying_key обязателен для верификации kfrag и cfrag
    let vk_bytes = re_key_data.sender_verifying_key.as_ref().ok_or(
        "Missing sender_verifying_key — required for cryptographic verification. \
                Please update client to send verifying key with re-encryption request.",
    )?;

    // Восстанавливаем sender public key
    let sender_pk = PrePublicKey::from_bytes(&re_key_data.sender_pk)
        .map_err(|e| format!("Invalid sender_pk: {}", e))?;

    // Восстанавливаем первый kfrag
    let kfrag_bytes = re_key_data.kfrags.first().ok_or("No kfrags provided")?;

    let kfrag = KeyFrag::from_bytes(kfrag_bytes).map_err(|e| format!("Invalid kfrag: {:?}", e))?;

    // Parse the verifying key
    let verifying_pk = UmbralPublicKey::try_from_compressed_bytes(vk_bytes)
        .map_err(|e| format!("Invalid sender_verifying_key: {}", e))?;

    // Parse delegating key (sender's public key) for additional verification
    let delegating_pk = UmbralPublicKey::try_from_compressed_bytes(&re_key_data.sender_pk)
        .map_err(|e| format!("Invalid delegating key: {}", e))?;

    // Parse receiving key if provided (required when kfrag was signed with sign_receiving=true)
    let receiving_pk = receiving_pk_bytes
        .map(|bytes| {
            UmbralPublicKey::try_from_compressed_bytes(bytes)
                .map_err(|e| format!("Invalid receiving key: {}", e))
        })
        .transpose()?;

    // Verify kfrag with sender's verifying key, delegating key, and receiving key
    let verified_kfrag =
        match kfrag.verify(&verifying_pk, Some(&delegating_pk), receiving_pk.as_ref()) {
            Ok(vkf) => {
                tracing::debug!("kfrag verified successfully with sender's verifying key");
                vkf
            },
            Err((_, err)) => {
                tracing::warn!("kfrag verification failed: {:?}", err);
                return Err(format!(
                    "kfrag verification failed — re-encryption key may be tampered: {:?}",
                    err
                ));
            },
        };

    // Выполняем re-encryption
    let mut re_encrypted = pre
        .perform_reencryption_with_kfrag(encrypted_data, verified_kfrag, &sender_pk)
        .map_err(|e| format!("Re-encryption error: {}", e))?;

    // CRIT-01: Прокидываем sender_verifying_key в результат,
    // чтобы получатель мог верифицировать cfrag при расшифровке
    re_encrypted.sender_verifying_key = Some(vk_bytes.clone());

    Ok(re_encrypted)
}

/// POST /api/v1/transfers/confirm-signed - подтвердить подписание offer
///
/// Вызывается после успешного подписания NFTokenCreateOffer через Vaulted wallet signing.
/// Меняет статус NFT на 'transferring'.
///
/// **Requires authentication** - must be from_address of the transfer
pub async fn confirm_offer_signed(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<ConfirmOfferSignedRequest>,
) -> Result<Json<serde_json::Value>> {
    // Получаем transfer с from_user для проверки авторизации
    let transfer = sqlx::query_as::<_, (Uuid, String, String)>(
        r#"
        SELECT tr.nft_metadata_id, tr.status, u.wallet_address as from_wallet
        FROM transfer_requests tr
        JOIN users u ON tr.from_user_id = u.id
        WHERE tr.id = $1
        "#,
    )
    .bind(request.transfer_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Transfer {} not found", request.transfer_id)))?;

    let (nft_metadata_id, status, from_wallet) = transfer;

    // Verify the authenticated user is the sender
    if !auth.wallet_address.eq_ignore_ascii_case(&from_wallet) {
        return Err(ApiError::Forbidden(
            "Only the transfer sender can confirm".into(),
        ));
    }

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "Transfer is not pending: status = {}",
            status
        )));
    }

    // Обновляем статус NFT на 'transferring'
    sqlx::query("UPDATE nft_metadata SET status = 'transferring' WHERE id = $1")
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await?;

    // Обновляем transfer_request
    sqlx::query(
        "UPDATE transfer_requests SET status = 'completed', nft_offer_index = $1, completed_at = NOW() WHERE id = $2"
    )
        .bind(&request.offer_index)
        .bind(request.transfer_id)
        .execute(&state.db)
        .await?;

    // Получаем nft_token_id для audit log
    let nft_token_id =
        sqlx::query_scalar::<_, String>("SELECT nft_token_id FROM nft_metadata WHERE id = $1")
            .bind(nft_metadata_id)
            .fetch_optional(&state.db)
            .await?;

    // Аудит
    state
        .audit_log(
            None,
            "transfer_offer_signed",
            nft_token_id.as_deref(),
            Some(serde_json::json!({
                "transfer_id": request.transfer_id,
                "offer_index": request.offer_index,
            })),
        )
        .await;

    tracing::info!(
        "Transfer {} confirmed, offer_index: {}",
        request.transfer_id,
        request.offer_index
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "status": "transferring"
    })))
}

#[derive(serde::Deserialize)]
pub struct ConfirmOfferSignedRequest {
    pub transfer_id: Uuid,
    pub offer_index: String,
}

/// GET /api/v1/transfers/:transfer_id/status
/// **Requires authentication** - only sender or recipient can view (HIGH-03)
pub async fn get_status(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(transfer_id): Path<Uuid>,
) -> Result<Json<TransferStatusResponse>> {
    // Verify user is sender or recipient (HIGH-03)
    let participant_check = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM transfer_requests tr
            JOIN users u_from ON tr.from_user_id = u_from.id
            JOIN users u_to ON tr.to_user_id = u_to.id
            WHERE tr.id = $1
            AND (u_from.wallet_address = $2 OR u_to.wallet_address = $2)
        )
        "#,
    )
    .bind(transfer_id)
    .bind(&auth.wallet_address)
    .fetch_one(&state.db)
    .await?;

    if !participant_check {
        return Err(ApiError::Forbidden(
            "Only the sender or recipient can view transfer status".into(),
        ));
    }

    let row = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
        r#"
        SELECT status, re_encrypted_aes_key, error_message
        FROM transfer_requests
        WHERE id = $1
        "#,
    )
    .bind(transfer_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Transfer {} not found", transfer_id)))?;

    Ok(Json(TransferStatusResponse {
        transfer_id,
        status: row.0,
        re_encrypted_aes_key: row.1,
        error: row.2,
    }))
}

/// POST /api/v1/transfers/finalize-by-offer - простая финализация по offer_index
///
/// Вызывается после успешного claim NFT для пометки transfer как завершённого
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeByOfferRequest {
    pub offer_index: String,
    pub xrpl_tx_hash: String,
}

pub async fn finalize_transfer_by_offer(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<FinalizeByOfferRequest>,
) -> Result<Json<serde_json::Value>> {
    // Находим transfer по offer_index
    let transfer = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, status FROM transfer_requests WHERE nft_offer_index = $1",
    )
    .bind(&request.offer_index)
    .fetch_optional(&state.db)
    .await?;

    match transfer {
        Some((transfer_id, status)) => {
            if status == "completed" {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "message": "Already completed"
                })));
            }

            // Просто меняем статус на finalized
            sqlx::query(
                "UPDATE transfer_requests SET status = 'completed', xrpl_tx_hash = $1, nft_offer_index = NULL WHERE id = $2"
            )
                .bind(&request.xrpl_tx_hash)
                .bind(transfer_id)
                .execute(&state.db)
                .await?;

            tracing::info!(
                "Transfer {} finalized by offer_index {}",
                transfer_id,
                request.offer_index
            );

            Ok(Json(serde_json::json!({
                "success": true,
                "transfer_id": transfer_id,
                "message": "Completed"
            })))
        },
        None => {
            // Нет transfer для этого offer — возможно это claim собственного NFT
            tracing::info!(
                "No transfer found for offer_index {}, ignoring",
                request.offer_index
            );
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "No transfer to finalize"
            })))
        },
    }
}

/// POST /api/v1/transfers/complete - завершить передачу
///
/// Вызывается после подтверждения передачи NFT на блокчейне (claim)
/// **Requires authentication** - must be the recipient (CRIT-04)
pub async fn complete_transfer(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<CompleteTransferRequest>,
) -> Result<Json<CompleteTransferResponse>> {
    // Получаем данные передачи
    let transfer = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
        r#"
        SELECT nft_metadata_id, to_user_id, status, re_encrypted_aes_key
        FROM transfer_requests
        WHERE id = $1
        "#,
    )
    .bind(request.transfer_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Transfer {} not found", request.transfer_id)))?;

    let (nft_metadata_id, to_user_id, status, re_encrypted_aes_key) = transfer;

    // Verify the authenticated user is the intended recipient (CRIT-04)
    let to_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(to_user_id)
            .fetch_one(&state.db)
            .await?;

    if !auth.wallet_address.eq_ignore_ascii_case(&to_wallet) {
        return Err(ApiError::Forbidden(
            "Only the intended recipient can complete the transfer".into(),
        ));
    }

    // Проверяем статус - должен быть 'completed' (offer подписан)
    if status != "completed" {
        return Err(ApiError::BadRequest(format!(
            "Transfer is not ready: status = {}",
            status
        )));
    }

    let re_encrypted = re_encrypted_aes_key
        .ok_or_else(|| ApiError::Internal("Missing re-encrypted key".to_string()))?;

    // Обновляем NFT metadata - новый владелец, новый ключ, флаг re-encrypted
    sqlx::query(
        r#"
        UPDATE nft_metadata
        SET owner_id = $1, encrypted_aes_key = $2, is_re_encrypted = true, status = 'active', updated_at = NOW()
        WHERE id = $3
        "#,
    )
        .bind(to_user_id)
        .bind(&re_encrypted)
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await?;

    // Обновляем transfer request
    sqlx::query(
        "UPDATE transfer_requests SET xrpl_tx_hash = $1, status = 'completed' WHERE id = $2",
    )
    .bind(&request.xrpl_tx_hash)
    .bind(request.transfer_id)
    .execute(&state.db)
    .await?;

    // Получаем адрес нового владельца
    let new_owner =
        sqlx::query_scalar::<_, String>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(to_user_id)
            .fetch_one(&state.db)
            .await?;

    tracing::info!(
        "Transfer {} finalized, new owner: {}",
        request.transfer_id,
        new_owner
    );

    // Аудит
    state
        .audit_log(
            Some(to_user_id),
            "nft_transfer_complete",
            None,
            Some(serde_json::json!({
                "transfer_id": request.transfer_id,
                "xrpl_tx_hash": request.xrpl_tx_hash,
            })),
        )
        .await;

    Ok(Json(CompleteTransferResponse {
        success: true,
        new_owner,
    }))
}

/// GET /api/v1/transfers/by-nft/:nft_token_id - найти последний transfer по NFT
pub async fn get_transfer_by_nft(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let transfer = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT tr.id, tr.status
        FROM transfer_requests tr
        JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
        WHERE nm.nft_token_id = $1
        ORDER BY tr.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("No transfer found for NFT {}", nft_token_id)))?;

    Ok(Json(serde_json::json!({
        "transfer_id": transfer.0,
        "status": transfer.1
    })))
}

/// GET /api/v1/transfers/by-offer/:offer_index - найти transfer по offer_index
pub async fn get_transfer_by_offer(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(offer_index): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let transfer = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT id, status
        FROM transfer_requests
        WHERE nft_offer_index = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&offer_index)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("No transfer found for offer {}", offer_index)))?;

    Ok(Json(serde_json::json!({
        "transfer_id": transfer.0,
        "status": transfer.1
    })))
}
/// GET /api/v1/transfers/incoming/:wallet_address
/// Возвращает pending transfers где пользователь - получатель
/// **Requires authentication** - can only view own transfers (HIGH-03)
pub async fn get_incoming_transfers(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(wallet_address): Path<String>,
) -> Result<Json<Vec<IncomingTransferInfo>>> {
    // Verify the authenticated user is requesting their own transfers (HIGH-03)
    if !auth.wallet_address.eq_ignore_ascii_case(&wallet_address) {
        return Err(ApiError::Forbidden(
            "Can only view your own incoming transfers".into(),
        ));
    }
    // Находим user_id по wallet
    let user = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE wallet_address = $1")
        .bind(&wallet_address)
        .fetch_optional(&state.db)
        .await?;

    let user_id = match user {
        Some((id,)) => id,
        None => return Ok(Json(vec![])),
    };

    // Ищем completed transfers (offer подписан, ждёт claim)
    let transfers = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT
            tr.nft_offer_index,
            nm.nft_token_id,
            u.wallet_address as from_address,
            '0' as amount
        FROM transfer_requests tr
        JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
        JOIN users u ON tr.from_user_id = u.id
        WHERE tr.to_user_id = $1
        AND tr.status = 'completed'
        AND tr.nft_offer_index IS NOT NULL
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let result: Vec<IncomingTransferInfo> = transfers
        .into_iter()
        .map(
            |(offer_index, nft_token_id, from_address, amount)| IncomingTransferInfo {
                offer_index,
                nft_token_id,
                from_address,
                amount,
            },
        )
        .collect();

    Ok(Json(result))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingTransferInfo {
    pub offer_index: String,
    pub nft_token_id: String,
    pub from_address: String,
    pub amount: String,
}

/// GET /api/v1/transfers/history/:wallet_address
/// Возвращает историю всех transfers пользователя (отправленных и полученных)
/// **Requires authentication** - can only view own history (HIGH-03)
pub async fn get_transfer_history(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(wallet_address): Path<String>,
) -> Result<Json<TransferHistory>> {
    // Verify the authenticated user is requesting their own history (HIGH-03)
    if !auth.wallet_address.eq_ignore_ascii_case(&wallet_address) {
        return Err(ApiError::Forbidden(
            "Can only view your own transfer history".into(),
        ));
    }
    // Находим user_id по wallet
    let user = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE wallet_address = $1")
        .bind(&wallet_address)
        .fetch_optional(&state.db)
        .await?;

    let user_id = match user {
        Some((id,)) => id,
        None => {
            return Ok(Json(TransferHistory {
                sent: vec![],
                received: vec![],
            }))
        },
    };

    // Получаем отправленные transfers
    let sent = sqlx::query_as::<_, (Uuid, String, String, String, String, Option<String>)>(
        r#"
        SELECT
            tr.id,
            nm.nft_token_id,
            u.wallet_address as to_address,
            tr.status,
            tr.created_at::text,
            fm.encrypted_filename
        FROM transfer_requests tr
        JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
        JOIN users u ON tr.to_user_id = u.id
        LEFT JOIN file_manifests fm ON fm.nft_metadata_id = nm.id
        WHERE tr.from_user_id = $1
        ORDER BY tr.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    // Получаем полученные transfers
    let received = sqlx::query_as::<_, (Uuid, String, String, String, String, Option<String>)>(
        r#"
        SELECT
            tr.id,
            nm.nft_token_id,
            u.wallet_address as from_address,
            tr.status,
            tr.created_at::text,
            fm.encrypted_filename
        FROM transfer_requests tr
        JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
        JOIN users u ON tr.from_user_id = u.id
        LEFT JOIN file_manifests fm ON fm.nft_metadata_id = nm.id
        WHERE tr.to_user_id = $1
        ORDER BY tr.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let sent_items: Vec<TransferHistoryItem> = sent
        .into_iter()
        .map(
            |(id, nft_token_id, to_address, status, created_at, filename)| TransferHistoryItem {
                transfer_id: id.to_string(),
                nft_token_id,
                other_party: to_address,
                direction: "sent".to_string(),
                status,
                created_at,
                filename,
            },
        )
        .collect();

    let received_items: Vec<TransferHistoryItem> = received
        .into_iter()
        .map(
            |(id, nft_token_id, from_address, status, created_at, filename)| TransferHistoryItem {
                transfer_id: id.to_string(),
                nft_token_id,
                other_party: from_address,
                direction: "received".to_string(),
                status,
                created_at,
                filename,
            },
        )
        .collect();

    Ok(Json(TransferHistory {
        sent: sent_items,
        received: received_items,
    }))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistory {
    pub sent: Vec<TransferHistoryItem>,
    pub received: Vec<TransferHistoryItem>,
}

#[derive(Debug, Serialize)]
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

/// POST /api/v1/transfers/:transfer_id/cancel - отменить трансфер
///
/// Только отправитель может отменить трансфер до того как получатель примет offer.
#[derive(Debug, serde::Deserialize)]
pub struct CancelTransferRequest {
    pub wallet_address: String,
}

#[derive(Debug, Serialize)]
pub struct CancelTransferResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
}

/// POST /api/v1/transfers/:transfer_id/cancel
///
/// **Requires authentication** - only sender can cancel
pub async fn cancel_transfer(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(transfer_id): Path<Uuid>,
    Json(request): Json<CancelTransferRequest>,
) -> Result<Json<CancelTransferResponse>> {
    // Verify authenticated user matches request
    if !auth
        .wallet_address
        .eq_ignore_ascii_case(&request.wallet_address)
    {
        return Err(ApiError::Forbidden(
            "Cannot cancel transfer for different wallet".into(),
        ));
    }

    // Получаем информацию о трансфере
    let transfer = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>, String)>(
        r#"
        SELECT
            tr.from_user_id,
            tr.nft_metadata_id,
            tr.status,
            tr.nft_offer_index,
            nm.nft_token_id
        FROM transfer_requests tr
        JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
        WHERE tr.id = $1
        "#,
    )
    .bind(transfer_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Transfer {} not found", transfer_id)))?;

    let (from_user_id, nft_metadata_id, status, offer_index, nft_token_id) = transfer;

    // Проверяем что запрос от владельца
    let from_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(from_user_id)
            .fetch_one(&state.db)
            .await?;

    if !from_wallet.eq_ignore_ascii_case(&request.wallet_address) {
        return Err(ApiError::Forbidden(
            "Only the sender can cancel transfer".to_string(),
        ));
    }

    // Проверяем статус - можно отменить только pending или completed (до finalize)
    if status != "pending" && status != "completed" {
        return Err(ApiError::BadRequest(format!(
            "Cannot cancel transfer with status: {}",
            status
        )));
    }

    let tx_hash = None;

    // Если есть offer_index и статус completed - нужно отменить offer на XRPL
    // НО: offer принадлежит отправителю (пользователю), не Oracle!
    // Oracle не может отменить чужой offer.
    // Пользователь должен сам отменить offer через Vaulted wallet signing.
    //
    // Что мы можем сделать:
    // 1. Обновить статус в БД на 'cancelled'
    // 2. Вернуть NFT в статус 'active'
    // 3. Сообщить пользователю что нужно отменить offer через активный wallet

    // Обновляем статус трансфера
    sqlx::query(
        "UPDATE transfer_requests SET status = 'cancelled', completed_at = NOW() WHERE id = $1",
    )
    .bind(transfer_id)
    .execute(&state.db)
    .await?;

    // Возвращаем NFT в активный статус
    sqlx::query("UPDATE nft_metadata SET status = 'active' WHERE id = $1")
        .bind(nft_metadata_id)
        .execute(&state.db)
        .await?;

    // Аудит
    state
        .audit_log(
            Some(from_user_id),
            "transfer_cancelled",
            Some(&nft_token_id),
            Some(serde_json::json!({
                "transfer_id": transfer_id,
                "offer_index": offer_index,
            })),
        )
        .await;

    tracing::info!(
        "Transfer {} cancelled by {}",
        transfer_id,
        request.wallet_address
    );

    let message = if offer_index.is_some() {
        "Transfer cancelled. Please also cancel the offer with the active wallet.".to_string()
    } else {
        "Transfer cancelled successfully.".to_string()
    };

    Ok(Json(CancelTransferResponse {
        success: true,
        message,
        tx_hash,
    }))
}
