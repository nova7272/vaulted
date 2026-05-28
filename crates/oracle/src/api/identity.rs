//! Vaulted identity endpoints.
//!
//! These endpoints implement the seed-based Vaulted identity layer.  Oracle stores
//! only public keys, device public keys, linked wallets and manifest pointers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use xrpl_vault_crypto_core::encryption_public_key_fingerprint_hex;

use crate::{
    auth::{self, Claims},
    error::{ApiError, Result},
    services::AppState,
};

/// Register seed-based Vaulted identity public keys.
#[derive(Debug, Deserialize)]
pub struct RegisterIdentityRequest {
    pub vaulted_identity_id: Option<String>,
    pub encryption_public_key: String,
    pub signing_public_key: String,
    pub device_public_key: Option<String>,
    #[serde(default)]
    pub linked_wallets: Vec<LinkedWalletRequest>,
    pub protocol_version: Option<String>,
}

/// Linked external wallet record.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinkedWalletRequest {
    pub chain: String,
    pub address: String,
    pub proof_signature: Option<String>,
}

/// Identity response.
#[derive(Debug, Serialize)]
pub struct RegisterIdentityResponse {
    pub id: String,
    pub created: bool,
    pub protocol_version: String,
}

/// Public identity record response. Contains public keys only.
#[derive(Debug, Serialize)]
pub struct PublicIdentityResponse {
    pub id: String,
    pub encryption_public_key: String,
    pub encryption_public_key_fingerprint: String,
    pub signing_public_key: String,
    pub protocol_version: String,
    pub status: String,
}

/// Request to persist a TOFU/manual trust decision for a recipient encryption key.
#[derive(Debug, Deserialize)]
pub struct TrustRecipientKeyRequest {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    pub recipient_encryption_public_key: String,
    pub recipient_encryption_public_key_fingerprint: String,
    pub trust_source: Option<String>,
    pub trust_level: Option<String>,
}

/// Query for a recipient key trust record.
#[derive(Debug, Deserialize)]
pub struct RecipientKeyTrustQuery {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    pub fingerprint: Option<String>,
}

/// Request to revoke a TOFU/manual trust decision for a recipient encryption key.
#[derive(Debug, Deserialize)]
pub struct RevokeRecipientKeyTrustRequest {
    pub owner_identity_id: String,
    pub recipient_identity_id: String,
    /// If omitted, revokes trust for the recipient identity's current encryption key.
    /// Supplying a fingerprint allows old trusted keys to be revoked after rotation.
    pub recipient_encryption_public_key_fingerprint: Option<String>,
}

/// Query for registered devices belonging to a Vaulted identity.
#[derive(Debug, Deserialize)]
pub struct IdentityDevicesQuery {
    pub identity_id: String,
    /// Include revoked devices for audit/history views. Defaults to false.
    pub include_revoked: Option<bool>,
}

/// Request to revoke/deactivate a registered device.
#[derive(Debug, Deserialize)]
pub struct RevokeIdentityDeviceRequest {
    pub identity_id: String,
}

/// Registered device response. Contains public key material only.
#[derive(Debug, Serialize)]
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

/// TOFU/manual trust state for a recipient encryption key.
#[derive(Debug, Serialize)]
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
    /// Fingerprint of the recipient identity's currently active encryption key.
    pub active_recipient_encryption_public_key_fingerprint: String,
    /// True when the active key is untrusted but an older key for this recipient is still trusted.
    pub key_rotation_detected: bool,
    /// Most recent older trusted fingerprint for this owner/recipient pair, if one exists.
    pub trusted_different_key_fingerprint: Option<String>,
    pub trusted_different_key_at: Option<String>,
}

/// Challenge response for seed-based identity login.
#[derive(Debug, Serialize)]
pub struct IdentityChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub expires_at: String,
}

/// Token request using an Ed25519 identity signature.
#[derive(Debug, Deserialize)]
pub struct IdentityTokenRequest {
    pub identity_id: String,
    pub wallet_address: String,
    pub challenge: String,
    pub signature: String,
    pub device_public_key: Option<String>,
}

/// Token response for Vaulted identity login.
#[derive(Debug, Serialize)]
pub struct IdentityTokenResponse {
    pub identity_id: String,
    pub verified: bool,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub role: Option<String>,
}

/// Register a Vaulted identity. Private keys/seed/mnemonic/file keys are never accepted.
pub async fn register_identity(
    State(state): State<AppState>,
    Json(req): Json<RegisterIdentityRequest>,
) -> Result<Json<RegisterIdentityResponse>> {
    validate_hex_key(&req.encryption_public_key, 32, "encryption_public_key")?;
    validate_hex_key(&req.signing_public_key, 32, "signing_public_key")?;
    if let Some(device_pk) = &req.device_public_key {
        validate_hex_key(device_pk, 32, "device_public_key")?;
    }

    let identity_id = req
        .vaulted_identity_id
        .unwrap_or_else(|| derive_identity_id(&req.signing_public_key, &req.encryption_public_key));
    let protocol = req
        .protocol_version
        .unwrap_or_else(|| "vaulted-v1".to_string());

    let result = sqlx::query(
        r#"INSERT INTO vaulted_identities (id, signing_public_key, encryption_public_key, protocol_version, status)
           VALUES ($1, $2, $3, $4, 'active')
           ON CONFLICT (id) DO UPDATE SET
             signing_public_key = EXCLUDED.signing_public_key,
             encryption_public_key = EXCLUDED.encryption_public_key,
             protocol_version = EXCLUDED.protocol_version
           RETURNING (xmax = 0) AS created"#,
    )
    .bind(&identity_id)
    .bind(&req.signing_public_key)
    .bind(&req.encryption_public_key)
    .bind(&protocol)
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to register Vaulted identity: {e}")))?;
    let created: bool = result.try_get("created").unwrap_or(false);

    if let Some(device_pk) = req.device_public_key {
        let _ = sqlx::query(
            r#"INSERT INTO identity_devices (id, identity_id, device_public_key, device_name)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (identity_id, device_public_key) DO NOTHING"#,
        )
        .bind(Uuid::new_v4())
        .bind(&identity_id)
        .bind(&device_pk)
        .bind("default device")
        .execute(&state.db)
        .await;
    }

    for wallet in req.linked_wallets {
        let _ = sqlx::query(
            r#"INSERT INTO linked_wallets (id, identity_id, chain, address, proof_signature)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (identity_id, chain, address) DO UPDATE SET proof_signature = EXCLUDED.proof_signature"#,
        )
        .bind(Uuid::new_v4())
        .bind(&identity_id)
        .bind(wallet.chain)
        .bind(wallet.address)
        .bind(wallet.proof_signature)
        .execute(&state.db)
        .await;
    }

    Ok(Json(RegisterIdentityResponse {
        id: identity_id,
        created,
        protocol_version: protocol,
    }))
}

/// Returns a public Vaulted identity record by id.
pub async fn get_identity(
    State(state): State<AppState>,
    Path(identity_id): Path<String>,
) -> Result<Json<PublicIdentityResponse>> {
    let row = sqlx::query(
        r#"SELECT id, encryption_public_key, signing_public_key, protocol_version, status
           FROM vaulted_identities
           WHERE id = $1 AND status = 'active'"#,
    )
    .bind(&identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load Vaulted identity: {e}")))?
    .ok_or_else(|| ApiError::NotFound("Vaulted identity not found".into()))?;

    let encryption_public_key: String = row.try_get("encryption_public_key")?;
    let encryption_public_key_fingerprint =
        encryption_public_key_fingerprint_hex(&encryption_public_key)
            .map_err(|e| ApiError::Database(format!("Malformed identity encryption key: {e}")))?;

    Ok(Json(PublicIdentityResponse {
        id: row.try_get("id")?,
        encryption_public_key,
        encryption_public_key_fingerprint,
        signing_public_key: row.try_get("signing_public_key")?,
        protocol_version: row.try_get("protocol_version")?,
        status: row.try_get("status")?,
    }))
}

/// Persists a TOFU/manual trust decision for a recipient encryption key.
pub async fn trust_recipient_key(
    State(state): State<AppState>,
    Json(req): Json<TrustRecipientKeyRequest>,
) -> Result<Json<RecipientKeyTrustResponse>> {
    validate_hex_key(
        &req.recipient_encryption_public_key,
        32,
        "recipient_encryption_public_key",
    )?;
    let computed = encryption_public_key_fingerprint_hex(&req.recipient_encryption_public_key)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient encryption key: {e}")))?;
    if computed != req.recipient_encryption_public_key_fingerprint {
        return Err(ApiError::BadRequest(
            "recipient encryption public key fingerprint mismatch".into(),
        ));
    }

    let row = sqlx::query(
        r#"SELECT encryption_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'"#,
    )
    .bind(&req.recipient_identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load recipient identity: {e}")))?
    .ok_or_else(|| ApiError::NotFound("recipient identity not found".into()))?;
    let current_key: String = row.try_get("encryption_public_key")?;
    if current_key != req.recipient_encryption_public_key {
        return Err(ApiError::BadRequest(
            "recipient encryption public key does not match current identity record".into(),
        ));
    }

    let trust_level = req.trust_level.unwrap_or_else(|| "tofu".to_string());
    if !matches!(trust_level.as_str(), "tofu" | "manual" | "qr_verified") {
        return Err(ApiError::BadRequest("invalid trust_level".into()));
    }
    let trust_source = req.trust_source.unwrap_or_else(|| "desktop".to_string());

    let row = sqlx::query(
        r#"INSERT INTO identity_trusted_recipient_keys (
             id, owner_identity_id, recipient_identity_id, recipient_encryption_public_key,
             recipient_encryption_public_key_fingerprint, trust_level, trust_source, trusted_at, revoked_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, now(), NULL)
           ON CONFLICT (owner_identity_id, recipient_identity_id, recipient_encryption_public_key_fingerprint)
           DO UPDATE SET
             recipient_encryption_public_key = EXCLUDED.recipient_encryption_public_key,
             trust_level = EXCLUDED.trust_level,
             trust_source = EXCLUDED.trust_source,
             trusted_at = now(),
             revoked_at = NULL
           RETURNING owner_identity_id, recipient_identity_id, recipient_encryption_public_key,
                     recipient_encryption_public_key_fingerprint, trust_level, trust_source, trusted_at, revoked_at"#,
    )
    .bind(Uuid::new_v4())
    .bind(&req.owner_identity_id)
    .bind(&req.recipient_identity_id)
    .bind(&req.recipient_encryption_public_key)
    .bind(&req.recipient_encryption_public_key_fingerprint)
    .bind(&trust_level)
    .bind(&trust_source)
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to store recipient key trust: {e}")))?;

    Ok(Json(row_to_trust_response(
        row,
        true,
        req.recipient_encryption_public_key_fingerprint.clone(),
        false,
        None,
        None,
    )?))
}

/// Returns the current trust state for a recipient encryption key.
pub async fn recipient_key_trust_status(
    State(state): State<AppState>,
    Query(q): Query<RecipientKeyTrustQuery>,
) -> Result<Json<RecipientKeyTrustResponse>> {
    let recipient = sqlx::query(
        r#"SELECT encryption_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'"#,
    )
    .bind(&q.recipient_identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load recipient identity: {e}")))?
    .ok_or_else(|| ApiError::NotFound("recipient identity not found".into()))?;
    let recipient_key: String = recipient.try_get("encryption_public_key")?;
    let active_fingerprint = encryption_public_key_fingerprint_hex(&recipient_key)
        .map_err(|e| ApiError::Database(format!("Malformed identity encryption key: {e}")))?;
    let fingerprint = match q.fingerprint {
        Some(fp) if !fp.trim().is_empty() => fp,
        _ => active_fingerprint.clone(),
    };

    let row = sqlx::query(
        r#"SELECT owner_identity_id, recipient_identity_id, recipient_encryption_public_key,
                  recipient_encryption_public_key_fingerprint, trust_level, trust_source, trusted_at, revoked_at
           FROM identity_trusted_recipient_keys
           WHERE owner_identity_id = $1
             AND recipient_identity_id = $2
             AND recipient_encryption_public_key_fingerprint = $3"#,
    )
    .bind(&q.owner_identity_id)
    .bind(&q.recipient_identity_id)
    .bind(&fingerprint)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load recipient key trust: {e}")))?;

    if let Some(row) = row {
        let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("revoked_at")?;
        let is_trusted = revoked_at.is_none();
        let different = load_latest_trusted_different_key(
            &state,
            &q.owner_identity_id,
            &q.recipient_identity_id,
            &active_fingerprint,
        )
        .await?;
        return Ok(Json(row_to_trust_response(
            row,
            is_trusted,
            active_fingerprint,
            !is_trusted && different.is_some(),
            different.as_ref().map(|v| v.0.clone()),
            different.map(|v| v.1),
        )?));
    }

    let different = load_latest_trusted_different_key(
        &state,
        &q.owner_identity_id,
        &q.recipient_identity_id,
        &active_fingerprint,
    )
    .await?;

    Ok(Json(RecipientKeyTrustResponse {
        owner_identity_id: q.owner_identity_id,
        recipient_identity_id: q.recipient_identity_id,
        recipient_encryption_public_key: recipient_key,
        recipient_encryption_public_key_fingerprint: fingerprint,
        trusted: false,
        trust_level: if different.is_some() {
            "key_rotated".into()
        } else {
            "untrusted".into()
        },
        trust_source: "none".into(),
        trusted_at: None,
        revoked_at: None,
        active_recipient_encryption_public_key_fingerprint: active_fingerprint,
        key_rotation_detected: different.is_some(),
        trusted_different_key_fingerprint: different.as_ref().map(|v| v.0.clone()),
        trusted_different_key_at: different.map(|v| v.1),
    }))
}

/// Revokes a stored TOFU/manual trust decision for a recipient encryption key.
pub async fn revoke_recipient_key_trust(
    State(state): State<AppState>,
    Json(req): Json<RevokeRecipientKeyTrustRequest>,
) -> Result<Json<RecipientKeyTrustResponse>> {
    let recipient = sqlx::query(
        r#"SELECT encryption_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'"#,
    )
    .bind(&req.recipient_identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load recipient identity: {e}")))?
    .ok_or_else(|| ApiError::NotFound("recipient identity not found".into()))?;
    let current_recipient_key: String = recipient.try_get("encryption_public_key")?;
    let fingerprint = match req.recipient_encryption_public_key_fingerprint {
        Some(fp) if !fp.trim().is_empty() => fp,
        _ => encryption_public_key_fingerprint_hex(&current_recipient_key)
            .map_err(|e| ApiError::Database(format!("Malformed identity encryption key: {e}")))?,
    };

    let row = sqlx::query(
        r#"UPDATE identity_trusted_recipient_keys
           SET revoked_at = now()
           WHERE owner_identity_id = $1
             AND recipient_identity_id = $2
             AND recipient_encryption_public_key_fingerprint = $3
           RETURNING owner_identity_id, recipient_identity_id, recipient_encryption_public_key,
                     recipient_encryption_public_key_fingerprint, trust_level, trust_source, trusted_at, revoked_at"#,
    )
    .bind(&req.owner_identity_id)
    .bind(&req.recipient_identity_id)
    .bind(&fingerprint)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to revoke recipient key trust: {e}")))?;

    if let Some(row) = row {
        return Ok(Json(row_to_trust_response(
            row,
            false,
            encryption_public_key_fingerprint_hex(&current_recipient_key).map_err(|e| {
                ApiError::Database(format!("Malformed identity encryption key: {e}"))
            })?,
            false,
            None,
            None,
        )?));
    }

    let active_fingerprint = encryption_public_key_fingerprint_hex(&current_recipient_key)
        .map_err(|e| ApiError::Database(format!("Malformed identity encryption key: {e}")))?;
    Ok(Json(RecipientKeyTrustResponse {
        owner_identity_id: req.owner_identity_id,
        recipient_identity_id: req.recipient_identity_id,
        recipient_encryption_public_key: current_recipient_key,
        recipient_encryption_public_key_fingerprint: fingerprint,
        trusted: false,
        trust_level: "untrusted".into(),
        trust_source: "none".into(),
        trusted_at: None,
        revoked_at: Some(Utc::now().to_rfc3339()),
        active_recipient_encryption_public_key_fingerprint: active_fingerprint,
        key_rotation_detected: false,
        trusted_different_key_fingerprint: None,
        trusted_different_key_at: None,
    }))
}

fn row_to_trust_response(
    row: sqlx::postgres::PgRow,
    trusted: bool,
    active_recipient_encryption_public_key_fingerprint: String,
    key_rotation_detected: bool,
    trusted_different_key_fingerprint: Option<String>,
    trusted_different_key_at: Option<String>,
) -> Result<RecipientKeyTrustResponse> {
    let trusted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("trusted_at")?;
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("revoked_at")?;
    Ok(RecipientKeyTrustResponse {
        owner_identity_id: row.try_get("owner_identity_id")?,
        recipient_identity_id: row.try_get("recipient_identity_id")?,
        recipient_encryption_public_key: row.try_get("recipient_encryption_public_key")?,
        recipient_encryption_public_key_fingerprint: row
            .try_get("recipient_encryption_public_key_fingerprint")?,
        trusted,
        trust_level: row.try_get("trust_level")?,
        trust_source: row.try_get("trust_source")?,
        trusted_at: trusted_at.map(|v| v.to_rfc3339()),
        revoked_at: revoked_at.map(|v| v.to_rfc3339()),
        active_recipient_encryption_public_key_fingerprint,
        key_rotation_detected,
        trusted_different_key_fingerprint,
        trusted_different_key_at,
    })
}

async fn load_latest_trusted_different_key(
    state: &AppState,
    owner_identity_id: &str,
    recipient_identity_id: &str,
    active_fingerprint: &str,
) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        r#"SELECT recipient_encryption_public_key_fingerprint, trusted_at
           FROM identity_trusted_recipient_keys
           WHERE owner_identity_id = $1
             AND recipient_identity_id = $2
             AND recipient_encryption_public_key_fingerprint <> $3
             AND revoked_at IS NULL
           ORDER BY trusted_at DESC
           LIMIT 1"#,
    )
    .bind(owner_identity_id)
    .bind(recipient_identity_id)
    .bind(active_fingerprint)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to check recipient key rotation: {e}")))?;

    let Some(row) = row else {
        return Ok(None);
    };
    let fingerprint: String = row.try_get("recipient_encryption_public_key_fingerprint")?;
    let trusted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("trusted_at")?;
    Ok(Some((
        fingerprint,
        trusted_at.map(|v| v.to_rfc3339()).unwrap_or_default(),
    )))
}

/// Lists registered devices for a Vaulted identity.
pub async fn list_identity_devices(
    State(state): State<AppState>,
    Query(q): Query<IdentityDevicesQuery>,
) -> Result<Json<Vec<IdentityDeviceResponse>>> {
    let include_revoked = q.include_revoked.unwrap_or(false);
    let rows = if include_revoked {
        sqlx::query(
            r#"SELECT id, identity_id, device_public_key, device_name, created_at, revoked_at
               FROM identity_devices
               WHERE identity_id = $1
               ORDER BY revoked_at IS NULL DESC, created_at DESC"#,
        )
        .bind(&q.identity_id)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            r#"SELECT id, identity_id, device_public_key, device_name, created_at, revoked_at
               FROM identity_devices
               WHERE identity_id = $1 AND revoked_at IS NULL
               ORDER BY created_at DESC"#,
        )
        .bind(&q.identity_id)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| ApiError::Database(format!("Failed to list identity devices: {e}")))?;

    rows.into_iter()
        .map(row_to_device_response)
        .collect::<Result<Vec<_>>>()
        .map(Json)
}

/// Revokes/deactivates a registered identity device.
///
/// This foundation endpoint blocks future device-list UX from treating the device as active.
/// Existing token-family revocation can be connected later once per-device token ids are stored.
pub async fn revoke_identity_device(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(req): Json<RevokeIdentityDeviceRequest>,
) -> Result<Json<IdentityDeviceResponse>> {
    let device_uuid = Uuid::parse_str(&device_id)
        .map_err(|_| ApiError::BadRequest("invalid device id".into()))?;

    let row = sqlx::query(
        r#"UPDATE identity_devices
           SET revoked_at = COALESCE(revoked_at, now())
           WHERE id = $1 AND identity_id = $2
           RETURNING id, identity_id, device_public_key, device_name, created_at, revoked_at"#,
    )
    .bind(device_uuid)
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to revoke identity device: {e}")))?
    .ok_or_else(|| ApiError::NotFound("identity device not found".into()))?;

    Ok(Json(row_to_device_response(row)?))
}

fn row_to_device_response(row: sqlx::postgres::PgRow) -> Result<IdentityDeviceResponse> {
    let id: Uuid = row.try_get("id")?;
    let device_public_key: String = row.try_get("device_public_key")?;
    let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("revoked_at")?;
    let fingerprint = device_public_key_fingerprint_hex(&device_public_key);

    Ok(IdentityDeviceResponse {
        id: id.to_string(),
        identity_id: row.try_get("identity_id")?,
        device_public_key,
        device_public_key_fingerprint: fingerprint,
        device_name: row.try_get("device_name")?,
        status: if revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        }
        .to_string(),
        created_at: created_at.to_rfc3339(),
        revoked_at: revoked_at.map(|v| v.to_rfc3339()),
    })
}

fn device_public_key_fingerprint_hex(device_public_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"vaulted-device-public-key-fingerprint-v1");
    hasher.update(device_public_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Creates a challenge that must be signed by the Vaulted identity signing key.
pub async fn identity_challenge(
    Path(identity_id): Path<String>,
) -> Result<Json<IdentityChallengeResponse>> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = format!(
        "Vaulted identity login:vaulted-v1:{identity_id}:{}",
        hex::encode(nonce)
    );
    Ok(Json(IdentityChallengeResponse {
        challenge_id: Uuid::new_v4().to_string(),
        challenge,
        expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
    }))
}

/// Verifies an identity challenge signature. A production JWT can be issued after this verifier.
pub async fn identity_token(
    State(state): State<AppState>,
    Json(req): Json<IdentityTokenRequest>,
) -> Result<Json<IdentityTokenResponse>> {
    let row = sqlx::query(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;
    let signing_public_key: String = row
        .try_get("signing_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed identity row: {e}")))?;
    let wallet_address = req.wallet_address.trim().to_string();
    if wallet_address.is_empty() {
        return Err(ApiError::BadRequest("wallet_address is required".into()));
    }
    if !req
        .challenge
        .contains(&format!("vaulted-v1:{}", req.identity_id))
    {
        return Err(ApiError::Unauthorized(
            "Challenge is not bound to this identity".into(),
        ));
    }
    if !req
        .challenge
        .contains(&format!("wallet_address:{}", wallet_address))
    {
        return Err(ApiError::Unauthorized(
            "Challenge is not bound to the requested wallet".into(),
        ));
    }

    verify_ed25519_hex(
        &signing_public_key,
        req.challenge.as_bytes(),
        &req.signature,
    )?;

    if let Some(device_pk) = req.device_public_key {
        validate_hex_key(&device_pk, 32, "device_public_key")?;
        let _ = sqlx::query(
            r#"INSERT INTO identity_devices (id, identity_id, device_public_key, device_name)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (identity_id, device_public_key) DO NOTHING"#,
        )
        .bind(Uuid::new_v4())
        .bind(&req.identity_id)
        .bind(&device_pk)
        .bind("restored device")
        .execute(&state.db)
        .await;
    }

    let role = "user".to_string();
    let claims = Claims::new_access_with_role(&wallet_address, 1, &role);
    let access_token = auth::create_token(&claims, &state.signing_key);

    let refresh_claims = Claims::new_refresh(&wallet_address, 7);
    let refresh_token = auth::create_token(&refresh_claims, &state.signing_key);

    state
        .audit_log(
            None,
            "identity_token_issued",
            None,
            Some(serde_json::json!({
                "identity_id": req.identity_id,
                "wallet_address": wallet_address,
                "token_id": claims.jti,
                "expires_at": claims.exp,
                "auth_mode": "vaulted_identity_signature"
            })),
        )
        .await;

    Ok(Json(IdentityTokenResponse {
        identity_id: req.identity_id,
        verified: true,
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        role: Some(role),
    }))
}

fn derive_identity_id(signing_public_key: &str, encryption_public_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"Vaulted v1 identity id");
    h.update(signing_public_key.as_bytes());
    h.update(encryption_public_key.as_bytes());
    hex::encode(h.finalize())
}

fn validate_hex_key(value: &str, expected_bytes: usize, field: &str) -> Result<()> {
    let bytes =
        hex::decode(value).map_err(|_| ApiError::BadRequest(format!("{field} must be hex")))?;
    if bytes.len() != expected_bytes {
        return Err(ApiError::BadRequest(format!(
            "{field} must be {expected_bytes} bytes"
        )));
    }
    Ok(())
}

fn verify_ed25519_hex(
    public_key_hex: &str,
    message: &[u8],
    signature_hex_or_b64: &str,
) -> Result<()> {
    let pk = hex::decode(public_key_hex)
        .map_err(|_| ApiError::Unauthorized("Invalid identity public key".into()))?;
    if pk.len() != 32 {
        return Err(ApiError::Unauthorized(
            "Invalid identity public key length".into(),
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Unauthorized("Invalid identity public key".into()))?;

    let sig_bytes = hex::decode(signature_hex_or_b64)
        .or_else(|_| {
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature_hex_or_b64,
            )
        })
        .map_err(|_| ApiError::Unauthorized("Invalid identity signature encoding".into()))?;
    if sig_bytes.len() != 64 {
        return Err(ApiError::Unauthorized(
            "Invalid identity signature length".into(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|_| ApiError::Unauthorized("Invalid identity signature".into()))
}

#[cfg(test)]
mod trust_tests {
    use super::*;

    #[test]
    fn derives_expected_fingerprint_for_valid_key() {
        let key = "00".repeat(32);
        let fp = encryption_public_key_fingerprint_hex(&key).unwrap();
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, encryption_public_key_fingerprint_hex(&key).unwrap());
    }

    #[test]
    fn rejects_invalid_public_key_for_fingerprint() {
        assert!(encryption_public_key_fingerprint_hex("deadbeef").is_err());
    }
}
