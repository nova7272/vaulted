//! Vault API - регистрация зашифрованных данных и получение NFT
//!
//! Oracle НЕ шифрует данные! Клиент делает это сам.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// Ответ подготовки vault.
///
/// Oracle больше не минтит NFT и не создаёт XRPL offer. `nft_token_id` здесь —
/// временный 64-hex storage key для upload proxy до локального минта клиентом.
#[derive(Debug, Serialize)]
pub struct CreateVaultResponse {
    /// ID записи в Oracle
    pub vault_id: Uuid,
    /// Temporary 64-hex storage token id until local XRPL mint is finalized.
    pub nft_token_id: String,
    /// Legacy compatibility field. Empty in Vaulted local-mint mode.
    pub offer_index: String,
    /// Legacy compatibility field. Empty in Vaulted local-mint mode.
    pub signing_request_uri: String,
    /// URI candidate for locally minted NFT metadata.
    pub nft_uri: String,
}

/// POST /api/v1/vault/create
///
/// Подготавливает vault record для upload. Клиент сам генерирует metadata,
/// локально подписывает NFTokenMint и затем вызывает finalize endpoint.
/// Файл УЖЕ зашифрован клиентом!
///
/// **Requires authentication** - wallet_address must match JWT
pub async fn create_vault(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<CreateVaultResponse>> {
    // Verify that authenticated user matches request
    if !auth
        .wallet_address
        .eq_ignore_ascii_case(&req.wallet_address)
    {
        tracing::warn!(
            "Auth mismatch: JWT wallet {} != request wallet {}",
            auth.wallet_address,
            req.wallet_address
        );
        return Err(ApiError::Forbidden(
            "Cannot create vault for different wallet".into(),
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
        "Preparing Vaulted vault for {} ({} encrypted fragments)",
        req.wallet_address,
        req.manifest.fragments.len()
    );

    // Public metadata URI candidate for the locally minted NFT.
    // We use metadata_hash as identifier because nft_token_id is not known until after client-side minting.
    let nft_uri = public_metadata_uri(&state, &req.metadata_hash);

    // Получаем или создаём user
    let user_id = get_or_create_user(&state, &req.wallet_address, &req.pre_public_key).await?;

    // Local-mint-first model: create an Oracle row with a temporary 64-hex token id.
    // This keeps legacy upload proxy working before the real XRPL NFTokenID is known.
    let vault_id = Uuid::new_v4();
    let pending_token_id = pending_token_id_for_vault(vault_id);
    let manifest_json = serde_json::to_value(&req.manifest)
        .map_err(|e| ApiError::Internal(format!("JSON error: {}", e)))?;

    // Store manifest — encrypt if key available, keep plain JSON as fallback
    if let Some(ref enc_key) = state.config.db_encryption_key {
        sqlx::query(r#"
            INSERT INTO nft_metadata 
            (id, nft_token_id, owner_id, encrypted_aes_key, metadata_hash, manifest, encrypted_manifest, offer_index, status, created_at)
            VALUES ($1, $2, $3, $4, $5, NULL, vault_encrypt($6::text, $7), NULL, 'pending_claim', NOW())
        "#)
            .bind(vault_id)
            .bind(&pending_token_id)
            .bind(user_id)
            .bind(&req.encrypted_aes_key)
            .bind(&req.metadata_hash)
            .bind(&manifest_json.to_string())
            .bind(enc_key)
            .execute(&state.db)
            .await?;
    } else {
        sqlx::query(r#"
            INSERT INTO nft_metadata 
            (id, nft_token_id, owner_id, encrypted_aes_key, metadata_hash, manifest, offer_index, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NULL, 'pending_claim', NOW())
        "#)
            .bind(vault_id)
            .bind(&pending_token_id)
            .bind(user_id)
            .bind(&req.encrypted_aes_key)
            .bind(&req.metadata_hash)
            .bind(&manifest_json)
            .execute(&state.db)
            .await?;
    }

    tracing::info!(
        "Vault {} prepared for local XRPL mint. Pending token key: {}",
        vault_id,
        pending_token_id
    );

    // Аудит — avoid plaintext filename/mime logging in Vaulted privacy mode.
    state
        .audit_log(
            Some(user_id),
            "vault_prepared",
            Some(&pending_token_id),
            Some(serde_json::json!({
                "vault_id": vault_id,
                "metadata_hash": req.metadata_hash,
                "fragments": req.manifest.fragments.len(),
                "mode": "local_mint"
            })),
        )
        .await;

    Ok(Json(CreateVaultResponse {
        vault_id,
        nft_token_id: pending_token_id,
        offer_index: String::new(),
        signing_request_uri: String::new(),
        nft_uri,
    }))
}

fn pending_token_id_for_vault(vault_id: Uuid) -> String {
    let digest = Sha256::digest(format!("vaulted-pending-nft:{}", vault_id).as_bytes());
    hex::encode(digest)
}

#[derive(Debug, Deserialize)]
pub struct PublishVaultMetadataRequest {
    pub vault_id: Uuid,
    /// Manifest hash used as the public metadata URI key: /nft/{manifest_hash}/metadata.json.
    pub manifest_hash: String,
    /// Public metadata URI that will be embedded in the locally signed NFTokenMint.
    pub metadata_uri: String,
    /// Client-generated XLS-24 style JSON. Must be privacy-preserving and hash to metadata_hash.
    pub metadata_json: String,
    /// SHA-256 hash of metadata_json, hex encoded.
    pub metadata_hash: String,
}

#[derive(Debug, Serialize)]
pub struct PublishVaultMetadataResponse {
    pub vault_id: Uuid,
    pub manifest_hash: String,
    pub metadata_uri: String,
    pub metadata_hash: String,
    pub published: bool,
}

/// POST /api/v1/vault/publish-metadata
///
/// Stores the exact client-generated public NFT metadata JSON before local minting.
/// This makes the ledger URI durable/resolvable while keeping Oracle out of mint
/// authority. The metadata must not contain plaintext filenames, MIME types,
/// seed phrases, private keys, or other sensitive material.
pub async fn publish_vault_metadata(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<PublishVaultMetadataRequest>,
) -> Result<Json<PublishVaultMetadataResponse>> {
    if req.manifest_hash.is_empty() || req.metadata_uri.is_empty() {
        return Err(ApiError::Validation(
            "manifest_hash and metadata_uri are required".into(),
        ));
    }
    if req.metadata_json.len() > 128 * 1024 {
        return Err(ApiError::Validation("metadata_json is too large".into()));
    }
    if req.metadata_hash.len() != 64 || !req.metadata_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::Validation(
            "metadata_hash must be 64 hex characters".into(),
        ));
    }

    let computed_hash = hex::encode(Sha256::digest(req.metadata_json.as_bytes()));
    if !computed_hash.eq_ignore_ascii_case(&req.metadata_hash) {
        return Err(ApiError::Validation(
            "metadata_hash does not match metadata_json".into(),
        ));
    }

    let metadata: serde_json::Value = serde_json::from_str(&req.metadata_json)
        .map_err(|_| ApiError::Validation("metadata_json must be valid JSON".into()))?;
    validate_public_metadata_safety(&metadata, &req.manifest_hash, &req.metadata_uri)?;

    let row = sqlx::query_as::<_, (uuid::Uuid, String, String, Option<String>, Option<String>)>(
        r#"
        SELECT
            nm.owner_id,
            u.wallet_address,
            nm.metadata_hash,
            nm.manifest #>> '{public_metadata,metadata_uri}',
            nm.manifest #>> '{public_metadata,metadata_hash}'
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.id = $1
        "#,
    )
    .bind(req.vault_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Vault {} not found", req.vault_id)))?;

    let (
        owner_id,
        owner_wallet,
        prepared_manifest_hash,
        existing_metadata_uri,
        existing_metadata_hash,
    ) = row;
    if !auth.wallet_address.eq_ignore_ascii_case(&owner_wallet) {
        return Err(ApiError::Forbidden(
            "Only the vault owner can publish metadata".into(),
        ));
    }
    if prepared_manifest_hash != req.manifest_hash {
        return Err(ApiError::Validation(
            "manifest_hash does not match prepared vault".into(),
        ));
    }

    let expected_uri = public_metadata_uri(&state, &req.manifest_hash);
    if req.metadata_uri != expected_uri {
        return Err(ApiError::Validation(
            "metadata_uri does not match prepared public URI".into(),
        ));
    }

    // Published NFT metadata is treated as immutable because the XRPL NFTokenMint
    // URI points to it. Replays with the exact same URI/hash are idempotent; any
    // attempt to replace already-published metadata is rejected.
    if let Some(existing_uri) = existing_metadata_uri {
        let existing_hash = existing_metadata_hash.unwrap_or_default();
        if existing_uri == req.metadata_uri
            && existing_hash.eq_ignore_ascii_case(&req.metadata_hash)
        {
            return Ok(Json(PublishVaultMetadataResponse {
                vault_id: req.vault_id,
                manifest_hash: req.manifest_hash,
                metadata_uri: req.metadata_uri,
                metadata_hash: req.metadata_hash,
                published: true,
            }));
        }

        return Err(ApiError::Conflict(
            "Public metadata is already published and immutable".into(),
        ));
    }

    let public_metadata_patch = serde_json::json!({
        "public_metadata": {
            "metadata_uri": req.metadata_uri,
            "metadata_hash": req.metadata_hash.to_ascii_lowercase(),
            "metadata_json": metadata,
            "published_at": chrono::Utc::now().to_rfc3339(),
            "storage": "oracle_db_jsonb",
            "immutable": true
        }
    });

    sqlx::query(
        r#"
        UPDATE nft_metadata
        SET manifest = COALESCE(manifest, '{}'::jsonb) || $1::jsonb,
            updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(&public_metadata_patch)
    .bind(req.vault_id)
    .execute(&state.db)
    .await?;

    state
        .audit_log(
            Some(owner_id),
            "vault_metadata_published",
            Some(&req.manifest_hash),
            Some(serde_json::json!({
                "vault_id": req.vault_id,
                "metadata_uri": req.metadata_uri,
                "metadata_hash": req.metadata_hash,
                "mode": "client_generated_public_metadata"
            })),
        )
        .await;

    Ok(Json(PublishVaultMetadataResponse {
        vault_id: req.vault_id,
        manifest_hash: req.manifest_hash,
        metadata_uri: req.metadata_uri,
        metadata_hash: req.metadata_hash,
        published: true,
    }))
}

fn public_metadata_uri(state: &AppState, manifest_hash: &str) -> String {
    if let Some(ref public_url) = state.config.public_url {
        format!(
            "{}/nft/{}/metadata.json",
            public_url.trim_end_matches('/'),
            manifest_hash
        )
    } else {
        format!("vaulted://{}", manifest_hash)
    }
}

fn validate_public_metadata_safety(
    metadata: &serde_json::Value,
    manifest_hash: &str,
    metadata_uri: &str,
) -> Result<()> {
    let obj = metadata
        .as_object()
        .ok_or_else(|| ApiError::Validation("metadata_json must be a JSON object".into()))?;

    if obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .is_empty()
    {
        return Err(ApiError::Validation(
            "metadata_json.name is required".into(),
        ));
    }
    if obj
        .get("image")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .is_empty()
    {
        return Err(ApiError::Validation(
            "metadata_json.image is required".into(),
        ));
    }

    let external_url = obj
        .get("external_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if external_url != metadata_uri {
        return Err(ApiError::Validation(
            "metadata_json.external_url must match metadata_uri".into(),
        ));
    }

    let embedded_manifest_hash = metadata
        .pointer("/properties/manifest_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if embedded_manifest_hash != manifest_hash {
        return Err(ApiError::Validation(
            "metadata_json.properties.manifest_hash must match manifest_hash".into(),
        ));
    }

    reject_sensitive_public_metadata_keys(metadata)?;

    Ok(())
}

fn reject_sensitive_public_metadata_keys(value: &serde_json::Value) -> Result<()> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "mnemonic",
        "seed_phrase",
        "private_key",
        "privatekey",
        "secret_key",
        "secretkey",
        "plaintext_filename",
        "filename",
        "mime_type",
        "original_hash",
        "original_size",
    ];

    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN_KEYS
                    .iter()
                    .any(|forbidden| lower.contains(forbidden))
                {
                    return Err(ApiError::Validation(format!(
                        "metadata_json contains forbidden sensitive key: {}",
                        key
                    )));
                }
                reject_sensitive_public_metadata_keys(nested)?;
            }
        },
        serde_json::Value::Array(items) => {
            for item in items {
                reject_sensitive_public_metadata_keys(item)?;
            }
        },
        _ => {},
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct FinalizeVaultMintRequest {
    pub vault_id: Uuid,
    pub nft_token_id: String,
    pub tx_hash: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub owner_identity_id: String,
}

#[derive(Debug, Serialize)]
pub struct FinalizeVaultMintResponse {
    pub vault_id: Uuid,
    pub nft_token_id: String,
    pub status: String,
}

/// POST /api/v1/vault/finalize-mint
///
/// Финализирует vault после локального client-side NFTokenMint. Oracle обновляет
/// pending storage key на реальный NFTokenID и остаётся registry/index service.
pub async fn finalize_vault_mint(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<FinalizeVaultMintRequest>,
) -> Result<Json<FinalizeVaultMintResponse>> {
    if req.nft_token_id.len() != 64 || !req.nft_token_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::Validation("Invalid minted NFTokenID".into()));
    }
    if req.tx_hash.len() != 64 || !req.tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::Validation("Invalid XRPL transaction hash".into()));
    }
    if req.manifest_hash.is_empty() || req.manifest_uri.is_empty() {
        return Err(ApiError::Validation(
            "manifest_uri and manifest_hash are required".into(),
        ));
    }
    if req.owner_identity_id.trim().is_empty() {
        return Err(ApiError::Validation("owner_identity_id is required".into()));
    }

    let row = sqlx::query_as::<_, (String, uuid::Uuid, String)>(
        r#"
        SELECT nm.nft_token_id, nm.owner_id, u.wallet_address
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.id = $1
        "#,
    )
    .bind(req.vault_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Vault {} not found", req.vault_id)))?;

    let (previous_token_id, owner_id, owner_wallet) = row;
    if !auth.wallet_address.eq_ignore_ascii_case(&owner_wallet) {
        return Err(ApiError::Forbidden(
            "Only the vault owner can finalize mint".into(),
        ));
    }

    let identity_exists = sqlx::query_scalar::<_, String>(
        "SELECT id FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.owner_identity_id)
    .fetch_optional(&state.db)
    .await?;
    if identity_exists.is_none() {
        return Err(ApiError::Validation(
            "owner_identity_id is not an active Vaulted identity".into(),
        ));
    }

    let existing = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM nft_metadata WHERE nft_token_id = $1 AND id <> $2",
    )
    .bind(&req.nft_token_id)
    .bind(req.vault_id)
    .fetch_optional(&state.db)
    .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(format!(
            "NFT {} is already registered",
            req.nft_token_id
        )));
    }

    let published_metadata_uri = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT manifest #>> '{public_metadata,metadata_uri}'
        FROM nft_metadata
        WHERE id = $1
        "#,
    )
    .bind(req.vault_id)
    .fetch_one(&state.db)
    .await?;
    if published_metadata_uri.as_deref() != Some(req.manifest_uri.as_str()) {
        return Err(ApiError::Validation(
            "Public metadata must be published before finalize-mint".into(),
        ));
    }

    // Ledger verification is mandatory before Oracle finalizes the local mint.
    // The client is allowed to sign/submit, but Oracle still verifies that the
    // validated XRPL transaction actually minted the requested NFTokenID for the
    // authenticated wallet and the prepared metadata/manifest URI.
    let ledger_verification = state
        .xrpl
        .verify_local_nft_mint(
            &req.tx_hash,
            &req.nft_token_id,
            &owner_wallet,
            &req.manifest_uri,
        )
        .await?;

    let manifest_patch = serde_json::json!({
        "manifest_uri": &req.manifest_uri,
        "manifest_hash": &req.manifest_hash,
        "xrpl_tx_hash": &req.tx_hash,
        "mint_authority": "client_local_vaulted_wallet",
        "ledger_verified": true,
        "ledger_owner": ledger_verification.owner,
        "ledger_uri": ledger_verification.uri
    });

    let mut tx = state.db.begin().await?;
    sqlx::query(
        r#"
        UPDATE nft_metadata
        SET nft_token_id = $1,
            metadata_hash = $2,
            offer_index = NULL,
            status = 'active',
            manifest = COALESCE(manifest, '{}'::jsonb) || $3::jsonb,
            updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(&req.nft_token_id)
    .bind(&req.manifest_hash)
    .bind(&manifest_patch)
    .bind(req.vault_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE file_replicas
        SET nft_token_id = $1,
            updated_at = NOW()
        WHERE nft_token_id = $2
        "#,
    )
    .bind(&req.nft_token_id)
    .bind(&previous_token_id)
    .execute(&mut *tx)
    .await
    .ok();

    sqlx::query(finalize_vault_object_link_sql())
        .bind(req.vault_id.to_string())
        .bind(&req.owner_identity_id)
        .bind(&req.manifest_uri)
        .bind(&req.manifest_hash)
        .bind(&req.nft_token_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::info!(
        nft_token_id = %req.nft_token_id,
        tx_hash = %req.tx_hash,
        metadata_hash = %req.manifest_hash,
        metadata_uri_len = req.manifest_uri.len(),
        lookup_key_type = "nft_token_id",
        status = "active",
        "Finalized Vaulted mint and linked vault object"
    );

    state
        .audit_log(
            Some(owner_id),
            "vault_mint_finalized",
            Some(&req.nft_token_id),
            Some(serde_json::json!({
                "vault_id": req.vault_id,
                "previous_token_id": previous_token_id,
                "tx_hash": req.tx_hash,
                "manifest_hash": req.manifest_hash,
                "ledger_verified": true,
                "mode": "local_mint"
            })),
        )
        .await;

    Ok(Json(FinalizeVaultMintResponse {
        vault_id: req.vault_id,
        nft_token_id: req.nft_token_id,
        status: "active".to_string(),
    }))
}

fn finalize_vault_object_link_sql() -> &'static str {
    r#"
    INSERT INTO vault_objects
        (id, owner_identity_id, manifest_uri, manifest_hash, nft_chain, nft_token_id, status)
    VALUES ($1, $2, $3, $4, 'xrpl:testnet', $5, 'active')
    ON CONFLICT (id) DO UPDATE SET
        owner_identity_id = EXCLUDED.owner_identity_id,
        manifest_uri = EXCLUDED.manifest_uri,
        manifest_hash = EXCLUDED.manifest_hash,
        nft_chain = EXCLUDED.nft_chain,
        nft_token_id = EXCLUDED.nft_token_id,
        status = 'active',
        updated_at = now()
    "#
}

/// Получает или создаёт пользователя
async fn get_or_create_user(state: &AppState, wallet: &str, pre_key: &str) -> Result<Uuid> {
    // Проверяем существует ли
    if let Some(id) =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE wallet_address = $1")
            .bind(wallet)
            .fetch_optional(&state.db)
            .await?
    {
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
        "#,
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?;

    match owner_wallet {
        Some(ref wallet) if !auth.wallet_address.eq_ignore_ascii_case(wallet) => {
            return Err(ApiError::Forbidden(
                "Only the NFT owner can access file data".into(),
            ));
        },
        None => {
            return Err(ApiError::NotFound(format!(
                "NFT {} not found",
                nft_token_id
            )));
        },
        _ => {},
    }

    // Получаем метаданные NFT включая манифест
    let row = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT encrypted_aes_key, manifest FROM nft_metadata WHERE nft_token_id = $1",
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
    if !auth
        .wallet_address
        .eq_ignore_ascii_case(&request.wallet_address)
    {
        return Err(ApiError::Forbidden(
            "Cannot delete vault for different wallet".into(),
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
    let owner_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_address FROM users WHERE id = $1")
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
    match state
        .xrpl
        .verify_nft_owner(&nft_token_id, &auth.wallet_address)
        .await
    {
        Ok(true) => {
            tracing::debug!(
                "On-chain NFT ownership verified for delete: {}",
                nft_token_id
            );
        },
        Ok(false) => {
            tracing::warn!(
                "BLOCKED: delete_vault for NFT {} — wallet {} is DB owner but NOT on-chain owner",
                nft_token_id,
                auth.wallet_address
            );
            return Err(ApiError::Forbidden(
                "NFT ownership could not be verified on XRPL ledger. \
                 The NFT may have been transferred outside the app."
                    .into(),
            ));
        },
        Err(e) => {
            // XRPL node may be down — deny deletion to be safe (fail-closed)
            tracing::warn!(
                "On-chain verification failed for delete of NFT {}: {} — denying deletion",
                nft_token_id,
                e
            );
            return Err(ApiError::Internal(
                "Unable to verify NFT ownership on-chain. Please try again later.".into(),
            ));
        },
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
    let node_endpoints: std::collections::HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT id, endpoint_url FROM storage_nodes")
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();

    for fragment in &manifest.fragments {
        let endpoint_url = if !fragment.storage_node_id.is_empty() {
            node_endpoints
                .get(&fragment.storage_node_id)
                .cloned()
                .unwrap_or_else(|| "http://localhost:9001".to_string())
        } else {
            std::env::var("STORAGE_NODE_URL")
                .unwrap_or_else(|_| "http://localhost:9001".to_string())
        };

        // Create signed delete token
        let token =
            crate::storage_token::StorageToken::new_delete(&nft_token_id, &fragment.storage_key, 5);
        let signed = crate::storage_token::sign_storage_token(&token, &state.signing_key);
        let url = format!(
            "{}/fragments/{}?token={}",
            endpoint_url, fragment.storage_key, signed
        );

        match http_client.delete(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == 404 => {
                deleted_fragments += 1;
                tracing::debug!("Deleted fragment {} from storage", fragment.storage_key);
            },
            Ok(resp) => {
                tracing::warn!(
                    "Failed to delete fragment {}: HTTP {}",
                    fragment.storage_key,
                    resp.status()
                );
            },
            Err(e) => {
                tracing::warn!("Failed to delete fragment {}: {}", fragment.storage_key, e);
            },
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
    tracing::info!(
        "Checking claim status: NFT={}, offer={}",
        nft_token_id,
        offer_index
    );

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
        },
        Err(e) => {
            // Ошибка проверки
            tracing::warn!("Error checking NFT {}: {}", nft_token_id, e);
            Ok(Json(ClaimStatusResponse {
                claimed: false,
                expired: true,
                owner_address: None,
            }))
        },
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
    if !auth
        .wallet_address
        .eq_ignore_ascii_case(&req.wallet_address)
    {
        return Err(ApiError::Forbidden(
            "Cannot cancel offer for different wallet".into(),
        ));
    }

    // Verify the user is the intended recipient of this offer
    let owner_wallet = sqlx::query_scalar::<_, String>(
        r#"
        SELECT u.wallet_address FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#,
    )
    .bind(&req.nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("NFT not found".into()))?;

    if !owner_wallet.eq_ignore_ascii_case(&req.wallet_address) {
        return Err(ApiError::Forbidden(
            "Only the intended recipient can cancel this offer".into(),
        ));
    }

    tracing::info!(
        "Cancelling offer: NFT={}, offer={}",
        req.nft_token_id,
        req.offer_index
    );

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
        },
    };

    if !on_oracle {
        tracing::info!(
            "NFT {} not on Oracle (already claimed or burned)",
            req.nft_token_id
        );
        return Ok(Json(CancelOfferResponse {
            success: false,
            message: "NFT already claimed or burned".to_string(),
        }));
    }

    // 2. Отменяем offer
    match xrpl.cancel_offer(&req.offer_index).await {
        Ok(_) => {
            tracing::info!("Offer {} cancelled", req.offer_index);
        },
        Err(e) => {
            // Offer может быть уже отменён или принят
            tracing::warn!("Failed to cancel offer {}: {}", req.offer_index, e);
        },
    }

    // 3. Сжигаем NFT
    match xrpl.burn_nft(&req.nft_token_id).await {
        Ok(_) => {
            tracing::info!("NFT {} burned", req.nft_token_id);

            // Обновляем статус в БД
            let _ =
                sqlx::query("UPDATE nft_metadata SET status = 'burned' WHERE nft_token_id = $1")
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
        },
        Err(e) => {
            tracing::error!("Failed to burn NFT {}: {}", req.nft_token_id, e);
            Err(ApiError::Internal(format!("Failed to burn NFT: {}", e)))
        },
    }
}

#[cfg(test)]
mod local_mint_metadata_tests {
    use super::*;

    fn valid_metadata(manifest_hash: &str, metadata_uri: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "Vaulted Object test",
            "description": "Privacy-preserving Vaulted NFT metadata",
            "image": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
            "external_url": metadata_uri,
            "properties": {
                "protocol": "vaulted-wallet-mode-v1",
                "manifest_hash": manifest_hash,
                "privacy": "metadata-minimized"
            },
            "attributes": [
                {"trait_type": "Encryption", "value": "AES-256-GCM"}
            ]
        })
    }

    #[test]
    fn pending_token_id_is_64_hex_and_deterministic() {
        let vault_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let a = pending_token_id_for_vault(vault_id);
        let b = pending_token_id_for_vault(vault_id);

        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn metadata_safety_accepts_minimized_vaulted_metadata() {
        let manifest_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let metadata_uri = "https://oracle.example/nft/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/metadata.json";
        let metadata = valid_metadata(manifest_hash, metadata_uri);

        validate_public_metadata_safety(&metadata, manifest_hash, metadata_uri).unwrap();
    }

    #[test]
    fn metadata_safety_rejects_manifest_hash_mismatch() {
        let manifest_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let metadata_uri = "https://oracle.example/nft/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/metadata.json";
        let mut metadata = valid_metadata(manifest_hash, metadata_uri);
        metadata["properties"]["manifest_hash"] =
            serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        assert!(validate_public_metadata_safety(&metadata, manifest_hash, metadata_uri).is_err());
    }

    #[test]
    fn metadata_safety_rejects_external_url_mismatch() {
        let manifest_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let metadata_uri = "https://oracle.example/nft/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/metadata.json";
        let mut metadata = valid_metadata(manifest_hash, metadata_uri);
        metadata["external_url"] = serde_json::json!("https://attacker.example/metadata.json");

        assert!(validate_public_metadata_safety(&metadata, manifest_hash, metadata_uri).is_err());
    }

    #[test]
    fn metadata_safety_rejects_sensitive_nested_keys() {
        let manifest_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let metadata_uri = "https://oracle.example/nft/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/metadata.json";
        let mut metadata = valid_metadata(manifest_hash, metadata_uri);
        metadata["properties"]["plaintext_filename"] = serde_json::json!("secret.pdf");

        assert!(validate_public_metadata_safety(&metadata, manifest_hash, metadata_uri).is_err());
    }

    #[test]
    fn finalize_vault_object_link_sql_updates_by_nft_lookup_key() {
        let sql = finalize_vault_object_link_sql();

        assert!(sql.contains("INSERT INTO vault_objects"));
        assert!(sql.contains("nft_token_id"));
        assert!(sql.contains("ON CONFLICT (id) DO UPDATE"));
        assert!(sql.contains("nft_token_id = EXCLUDED.nft_token_id"));
        assert!(sql.contains("status = 'active'"));
    }
}
