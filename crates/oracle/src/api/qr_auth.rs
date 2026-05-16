//! Vaulted QR login / device pairing endpoints.
//!
//! QR payloads contain only a one-time challenge.  Seed phrases, private keys,
//! file keys and refresh tokens must never be encoded into QR data.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use xrpl_vault_crypto_core::VaultedQrPayloadBody;

use crate::{
    auth::{create_token, Claims},
    error::{ApiError, Result},
    services::AppState,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStartRequest {
    pub desktop_device_name: Option<String>,
    pub desktop_device_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStartResponse {
    pub login_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub qr_payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginConfirmRequest {
    pub login_request_id: String,
    pub identity_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginConfirmResponse {
    pub approved: bool,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStartRequest {
    pub identity_id: String,
    pub desktop_device_name: Option<String>,
    pub desktop_device_public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStartResponse {
    pub pairing_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub qr_payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceConfirmRequest {
    pub pairing_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub device_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStartRequest {
    pub identity_id: String,
    pub xrpl_tx_json: serde_json::Value,
    pub expected_xrpl_account: String,
    pub requester_device_id: Option<String>,
    pub requester_device_name: Option<String>,
    pub human_summary: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStartResponse {
    pub signing_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub tx_json_hash: String,
    pub qr_payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningConfirmRequest {
    pub signing_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub tx_json_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrXrplSigningStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_json_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_xrpl_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStartRequest {
    pub identity_id: String,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    /// Canonical recipient key envelope. Legacy callers may still send encryptedFileKey.
    #[serde(default)]
    pub key_envelope: Option<serde_json::Value>,
    /// Deprecated compatibility field. Use keyEnvelope instead.
    #[serde(default)]
    pub encrypted_file_key: Option<String>,
    pub permissions: Vec<String>,
    pub grant_expires_at: Option<chrono::DateTime<Utc>>,
    pub requester_device_id: Option<String>,
    pub requester_device_name: Option<String>,
    pub human_summary: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStartResponse {
    pub grant_request_id: String,
    pub grant_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub grant_context_hash: String,
    pub qr_payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantConfirmRequest {
    pub grant_request_id: String,
    pub identity_id: String,
    pub authorizing_device_id: String,
    pub signing_public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantConfirmResponse {
    pub approved: bool,
    pub status: String,
    pub grant_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFileGrantStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_context_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPairDeviceStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paired_at: Option<String>,
}

pub async fn start_qr_login(
    State(state): State<AppState>,
    Json(req): Json<QrLoginStartRequest>,
) -> Result<Json<QrLoginStartResponse>> {
    let id = Uuid::new_v4();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = hex::encode(nonce);
    let expires_at = Utc::now() + Duration::minutes(2);
    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));

    sqlx::query(
        r#"INSERT INTO qr_login_requests
           (id, challenge, status, desktop_device_name, desktop_device_public_key, created_at, expires_at)
           VALUES ($1, $2, 'pending', $3, $4, NOW(), $5)"#,
    )
    .bind(id)
    .bind(&challenge)
    .bind(&req.desktop_device_name)
    .bind(&req.desktop_device_public_key)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create QR login request: {e}")))?;

    let canonical_payload = VaultedQrPayloadBody::scan_to_login(
        id.to_string(),
        challenge.clone(),
        oracle_url.clone(),
        expires_at.to_rfc3339(),
        None,
        req.desktop_device_name.clone(),
        req.desktop_device_public_key.clone(),
    );

    let qr_payload = serde_json::json!({
        "type": "vaulted-login-v1",
        "loginRequestId": id.to_string(),
        "challenge": challenge,
        "oracleUrl": oracle_url,
        "expiresAt": expires_at.to_rfc3339(),
        "desktopDeviceName": req.desktop_device_name,
        "desktopDevicePublicKey": req.desktop_device_public_key,
        "canonicalPayload": canonical_payload,
    });

    Ok(Json(QrLoginStartResponse {
        login_request_id: id.to_string(),
        challenge: qr_payload["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        oracle_url,
        expires_at: expires_at.to_rfc3339(),
        qr_payload,
    }))
}

pub async fn confirm_qr_login(
    State(state): State<AppState>,
    Json(req): Json<QrLoginConfirmRequest>,
) -> Result<Json<QrLoginConfirmResponse>> {
    let login_id = Uuid::parse_str(&req.login_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid login_request_id".into()))?;

    let qr_row =
        sqlx::query("SELECT challenge, status, expires_at FROM qr_login_requests WHERE id = $1")
            .bind(login_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to load QR login request: {e}")))?
            .ok_or_else(|| ApiError::NotFound("QR login request not found".into()))?;

    let status: String = qr_row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed QR login status: {e}")))?;
    let challenge: String = qr_row
        .try_get("challenge")
        .map_err(|e| ApiError::Database(format!("Malformed QR login challenge: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = qr_row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed QR login expiration: {e}")))?;

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "QR login request is {status}"
        )));
    }
    if expires_at < Utc::now() {
        let _ = sqlx::query("UPDATE qr_login_requests SET status = 'expired' WHERE id = $1")
            .bind(login_id)
            .execute(&state.db)
            .await;
        return Err(ApiError::Unauthorized("QR login request expired".into()));
    }

    let identity_row = sqlx::query(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;

    let stored_pk: String = identity_row
        .try_get("signing_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed identity: {e}")))?;
    if stored_pk != req.signing_public_key {
        return Err(ApiError::Unauthorized(
            "Signing public key does not match identity".into(),
        ));
    }

    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    let message = format!(
        "Vaulted QR Login v1\nlogin_request_id:{}\nchallenge:{}\noracle_url:{}\ndevice_id:{}",
        req.login_request_id, challenge, oracle_url, req.device_id
    );
    verify_ed25519_hex(&req.signing_public_key, message.as_bytes(), &req.signature)?;

    let access_claims = Claims::new_access_device_bound(
        &req.identity_id,
        state.config.jwt_expiration_hours,
        "user",
        &req.device_id,
    );
    let refresh_claims = Claims::new_refresh_device_bound(&req.identity_id, 30, &req.device_id);
    let access_token = create_token(&access_claims, &state.signing_key);
    let refresh_token = create_token(&refresh_claims, &state.signing_key);

    sqlx::query(
        r#"UPDATE qr_login_requests
           SET status = 'approved', identity_id = $2, approved_by_device_id = $3,
               access_token = $4, refresh_token = $5, approved_at = NOW()
           WHERE id = $1"#,
    )
    .bind(login_id)
    .bind(&req.identity_id)
    .bind(&req.device_id)
    .bind(&access_token)
    .bind(&refresh_token)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to approve QR login: {e}")))?;

    Ok(Json(QrLoginConfirmResponse {
        approved: true,
        status: "approved".into(),
    }))
}

pub async fn qr_login_status(
    State(state): State<AppState>,
    Path(login_request_id): Path<String>,
) -> Result<Json<QrLoginStatusResponse>> {
    let login_id = Uuid::parse_str(&login_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid login_request_id".into()))?;

    let row = sqlx::query(
        "SELECT status, identity_id, access_token, refresh_token, expires_at FROM qr_login_requests WHERE id = $1",
    )
    .bind(login_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR login status: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR login request not found".into()))?;

    let mut status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed QR login status: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed QR login expiration: {e}")))?;

    if status == "pending" && expires_at < Utc::now() {
        status = "expired".to_string();
        let _ = sqlx::query("UPDATE qr_login_requests SET status = 'expired' WHERE id = $1")
            .bind(login_id)
            .execute(&state.db)
            .await;
    }

    let approved = status == "approved";
    let identity_id: Option<String> = row.try_get("identity_id").ok();
    let access_token: Option<String> = if approved {
        row.try_get("access_token").ok()
    } else {
        None
    };
    let refresh_token: Option<String> = if approved {
        row.try_get("refresh_token").ok()
    } else {
        None
    };

    if approved {
        let _ = sqlx::query(
            "UPDATE qr_login_requests SET status = 'consumed', consumed_at = NOW() WHERE id = $1",
        )
        .bind(login_id)
        .execute(&state.db)
        .await;
    }

    Ok(Json(QrLoginStatusResponse {
        status,
        access_token,
        refresh_token,
        identity_id,
        expires_in: if approved {
            Some(state.config.jwt_expiration_hours * 3600)
        } else {
            None
        },
    }))
}

pub async fn start_qr_device_pairing(
    State(state): State<AppState>,
    Json(req): Json<QrPairDeviceStartRequest>,
) -> Result<Json<QrPairDeviceStartResponse>> {
    validate_hex_public_key(&req.desktop_device_public_key, "desktop_device_public_key")?;

    let exists =
        sqlx::query("SELECT 1 FROM vaulted_identities WHERE id = $1 AND status = 'active'")
            .bind(&req.identity_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?;
    if exists.is_none() {
        return Err(ApiError::Unauthorized("Unknown Vaulted identity".into()));
    }

    let id = Uuid::new_v4();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = hex::encode(nonce);
    let expires_at = Utc::now() + Duration::minutes(5);
    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));

    sqlx::query(
        r#"INSERT INTO qr_device_pairing_requests
           (id, identity_id, challenge, status, desktop_device_name, desktop_device_public_key, created_at, expires_at)
           VALUES ($1, $2, $3, 'pending', $4, $5, NOW(), $6)"#,
    )
    .bind(id)
    .bind(&req.identity_id)
    .bind(&challenge)
    .bind(&req.desktop_device_name)
    .bind(&req.desktop_device_public_key)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create QR device pairing request: {e}")))?;

    let canonical_payload = VaultedQrPayloadBody::scan_to_pair_device(
        id.to_string(),
        challenge.clone(),
        oracle_url.clone(),
        expires_at.to_rfc3339(),
        req.identity_id.clone(),
        req.desktop_device_public_key.clone(),
        req.desktop_device_name.clone(),
    );

    let qr_payload = serde_json::json!({
        "type": "vaulted-pair-device-v1",
        "pairingRequestId": id.to_string(),
        "identityId": req.identity_id,
        "challenge": challenge,
        "oracleUrl": oracle_url,
        "expiresAt": expires_at.to_rfc3339(),
        "desktopDeviceName": req.desktop_device_name,
        "desktopDevicePublicKey": req.desktop_device_public_key,
        "canonicalPayload": canonical_payload,
    });

    Ok(Json(QrPairDeviceStartResponse {
        pairing_request_id: id.to_string(),
        challenge: qr_payload["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        oracle_url,
        expires_at: expires_at.to_rfc3339(),
        qr_payload,
    }))
}

pub async fn confirm_qr_device_pairing(
    State(state): State<AppState>,
    Json(req): Json<QrPairDeviceConfirmRequest>,
) -> Result<Json<QrPairDeviceConfirmResponse>> {
    let pairing_id = Uuid::parse_str(&req.pairing_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid pairing_request_id".into()))?;

    let row = sqlx::query(
        "SELECT identity_id, challenge, status, expires_at, desktop_device_name, desktop_device_public_key FROM qr_device_pairing_requests WHERE id = $1",
    )
    .bind(pairing_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR device pairing request: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR device pairing request not found".into()))?;

    let identity_id: String = row
        .try_get("identity_id")
        .map_err(|e| ApiError::Database(format!("Malformed pairing identity: {e}")))?;
    if identity_id != req.identity_id {
        return Err(ApiError::Unauthorized("Pairing identity mismatch".into()));
    }
    let status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed pairing status: {e}")))?;
    let challenge: String = row
        .try_get("challenge")
        .map_err(|e| ApiError::Database(format!("Malformed pairing challenge: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed pairing expiration: {e}")))?;
    let device_public_key: String = row
        .try_get("desktop_device_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed pairing device key: {e}")))?;
    let device_name: Option<String> = row.try_get("desktop_device_name").ok();

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "QR device pairing request is {status}"
        )));
    }
    if expires_at < Utc::now() {
        let _ =
            sqlx::query("UPDATE qr_device_pairing_requests SET status = 'expired' WHERE id = $1")
                .bind(pairing_id)
                .execute(&state.db)
                .await;
        return Err(ApiError::Unauthorized(
            "QR device pairing request expired".into(),
        ));
    }

    let identity_row = sqlx::query(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;

    let stored_pk: String = identity_row
        .try_get("signing_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed identity: {e}")))?;
    if stored_pk != req.signing_public_key {
        return Err(ApiError::Unauthorized(
            "Signing public key does not match identity".into(),
        ));
    }

    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    let message = pair_device_signature_message(
        &req.pairing_request_id,
        &challenge,
        &oracle_url,
        &device_public_key,
        device_name.as_deref(),
        &req.authorizing_device_id,
    );
    verify_ed25519_hex(&req.signing_public_key, message.as_bytes(), &req.signature)?;

    let proposed_device_id = Uuid::new_v4();
    let device_row = sqlx::query(
        r#"INSERT INTO identity_devices (id, identity_id, device_public_key, device_name)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (identity_id, device_public_key) DO UPDATE SET
               device_name = EXCLUDED.device_name,
               revoked_at = NULL
           RETURNING id"#,
    )
    .bind(proposed_device_id)
    .bind(&req.identity_id)
    .bind(&device_public_key)
    .bind(
        device_name
            .clone()
            .unwrap_or_else(|| "paired device".to_string()),
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to register paired device: {e}")))?;
    let device_id: Uuid = device_row
        .try_get("id")
        .map_err(|e| ApiError::Database(format!("Malformed paired device id: {e}")))?;

    sqlx::query(
        r#"UPDATE qr_device_pairing_requests
           SET status = 'approved', approved_by_device_id = $2, paired_device_id = $3, approved_at = NOW()
           WHERE id = $1"#,
    )
    .bind(pairing_id)
    .bind(&req.authorizing_device_id)
    .bind(device_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to approve device pairing: {e}")))?;

    Ok(Json(QrPairDeviceConfirmResponse {
        approved: true,
        status: "approved".into(),
        device_id: device_id.to_string(),
    }))
}

pub async fn qr_device_pairing_status(
    State(state): State<AppState>,
    Path(pairing_request_id): Path<String>,
) -> Result<Json<QrPairDeviceStatusResponse>> {
    let pairing_id = Uuid::parse_str(&pairing_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid pairing_request_id".into()))?;

    let row = sqlx::query(
        "SELECT status, identity_id, paired_device_id, expires_at, approved_at FROM qr_device_pairing_requests WHERE id = $1",
    )
    .bind(pairing_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR device pairing status: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR device pairing request not found".into()))?;

    let mut status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed pairing status: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed pairing expiration: {e}")))?;

    if status == "pending" && expires_at < Utc::now() {
        status = "expired".to_string();
        let _ =
            sqlx::query("UPDATE qr_device_pairing_requests SET status = 'expired' WHERE id = $1")
                .bind(pairing_id)
                .execute(&state.db)
                .await;
    }

    let identity_id: Option<String> = row.try_get("identity_id").ok();
    let device_id: Option<Uuid> = row.try_get("paired_device_id").ok();
    let paired_at: Option<chrono::DateTime<Utc>> = row.try_get("approved_at").ok();

    Ok(Json(QrPairDeviceStatusResponse {
        status,
        identity_id,
        device_id: device_id.map(|id| id.to_string()),
        paired_at: paired_at.map(|ts| ts.to_rfc3339()),
    }))
}

pub async fn start_qr_xrpl_signing(
    State(state): State<AppState>,
    Json(req): Json<QrXrplSigningStartRequest>,
) -> Result<Json<QrXrplSigningStartResponse>> {
    if req.identity_id.trim().is_empty() {
        return Err(ApiError::BadRequest("identity_id is required".into()));
    }
    if req.expected_xrpl_account.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "expected_xrpl_account is required".into(),
        ));
    }
    if req.xrpl_tx_json.is_null() {
        return Err(ApiError::BadRequest("xrpl_tx_json is required".into()));
    }

    sqlx::query("SELECT id FROM vaulted_identities WHERE id = $1 AND status = 'active'")
        .bind(&req.identity_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
        .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;

    let id = Uuid::new_v4();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = hex::encode(nonce);
    let expires_at = Utc::now() + Duration::minutes(2);
    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    let tx_json_hash = stable_json_sha256_hex(&req.xrpl_tx_json)?;

    sqlx::query(
        r#"INSERT INTO qr_xrpl_signing_requests
           (id, identity_id, challenge, status, xrpl_tx_json, xrpl_tx_hash, expected_xrpl_account,
            requester_device_id, requester_device_name, created_at, expires_at)
           VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, $8, NOW(), $9)"#,
    )
    .bind(id)
    .bind(&req.identity_id)
    .bind(&challenge)
    .bind(&req.xrpl_tx_json)
    .bind(&tx_json_hash)
    .bind(&req.expected_xrpl_account)
    .bind(&req.requester_device_id)
    .bind(&req.requester_device_name)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create QR XRPL signing request: {e}")))?;

    let mut canonical_payload = VaultedQrPayloadBody::scan_to_sign_xrpl_transaction(
        id.to_string(),
        challenge.clone(),
        oracle_url.clone(),
        expires_at.to_rfc3339(),
        req.xrpl_tx_json.clone(),
        req.expected_xrpl_account.clone(),
        req.human_summary.clone(),
    );
    canonical_payload.identity_id = Some(req.identity_id.clone());
    canonical_payload.requester_device_id = req.requester_device_id.clone();
    canonical_payload.requester_device_name = req.requester_device_name.clone();

    let qr_payload = serde_json::json!({
        "type": "vaulted-xrpl-sign-v1",
        "signingRequestId": id.to_string(),
        "identityId": req.identity_id,
        "challenge": challenge,
        "oracleUrl": oracle_url,
        "expiresAt": expires_at.to_rfc3339(),
        "txJsonHash": tx_json_hash,
        "expectedXrplAccount": req.expected_xrpl_account,
        "requesterDeviceId": req.requester_device_id,
        "requesterDeviceName": req.requester_device_name,
        "canonicalPayload": canonical_payload,
    });

    Ok(Json(QrXrplSigningStartResponse {
        signing_request_id: id.to_string(),
        challenge: qr_payload["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        oracle_url,
        expires_at: expires_at.to_rfc3339(),
        tx_json_hash: qr_payload["txJsonHash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        qr_payload,
    }))
}

pub async fn confirm_qr_xrpl_signing(
    State(state): State<AppState>,
    Json(req): Json<QrXrplSigningConfirmRequest>,
) -> Result<Json<QrXrplSigningConfirmResponse>> {
    let signing_id = Uuid::parse_str(&req.signing_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid signing_request_id".into()))?;

    let row = sqlx::query(
        "SELECT identity_id, challenge, status, expires_at, xrpl_tx_hash, expected_xrpl_account, requester_device_id, requester_device_name FROM qr_xrpl_signing_requests WHERE id = $1",
    )
    .bind(signing_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR XRPL signing request: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR XRPL signing request not found".into()))?;

    let identity_id: String = row
        .try_get("identity_id")
        .map_err(|e| ApiError::Database(format!("Malformed signing identity: {e}")))?;
    if identity_id != req.identity_id {
        return Err(ApiError::Unauthorized(
            "XRPL signing identity mismatch".into(),
        ));
    }
    let status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed signing status: {e}")))?;
    let challenge: String = row
        .try_get("challenge")
        .map_err(|e| ApiError::Database(format!("Malformed signing challenge: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed signing expiration: {e}")))?;
    let tx_json_hash: String = row
        .try_get("xrpl_tx_hash")
        .map_err(|e| ApiError::Database(format!("Malformed tx hash: {e}")))?;
    let expected_xrpl_account: String = row
        .try_get("expected_xrpl_account")
        .map_err(|e| ApiError::Database(format!("Malformed expected XRPL account: {e}")))?;
    let requester_device_id: Option<String> = row.try_get("requester_device_id").ok();
    let requester_device_name: Option<String> = row.try_get("requester_device_name").ok();

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "QR XRPL signing request is {status}"
        )));
    }
    if expires_at < Utc::now() {
        let _ = sqlx::query("UPDATE qr_xrpl_signing_requests SET status = 'expired' WHERE id = $1")
            .bind(signing_id)
            .execute(&state.db)
            .await;
        return Err(ApiError::Unauthorized(
            "QR XRPL signing request expired".into(),
        ));
    }

    let identity_row = sqlx::query(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;

    let stored_pk: String = identity_row
        .try_get("signing_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed identity: {e}")))?;
    if stored_pk != req.signing_public_key {
        return Err(ApiError::Unauthorized(
            "Signing public key does not match identity".into(),
        ));
    }

    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    let message = xrpl_signing_approval_message(
        &req.signing_request_id,
        &challenge,
        &oracle_url,
        &tx_json_hash,
        &expected_xrpl_account,
        requester_device_id.as_deref(),
        requester_device_name.as_deref(),
        &req.authorizing_device_id,
    );
    verify_ed25519_hex(&req.signing_public_key, message.as_bytes(), &req.signature)?;

    sqlx::query(
        r#"UPDATE qr_xrpl_signing_requests
           SET status = 'approved', approved_by_device_id = $2,
               approval_signing_public_key = $3, approval_signature = $4, approved_at = NOW()
           WHERE id = $1"#,
    )
    .bind(signing_id)
    .bind(&req.authorizing_device_id)
    .bind(&req.signing_public_key)
    .bind(&req.signature)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to approve QR XRPL signing: {e}")))?;

    Ok(Json(QrXrplSigningConfirmResponse {
        approved: true,
        status: "approved".into(),
        tx_json_hash,
    }))
}

pub async fn qr_xrpl_signing_status(
    State(state): State<AppState>,
    Path(signing_request_id): Path<String>,
) -> Result<Json<QrXrplSigningStatusResponse>> {
    let signing_id = Uuid::parse_str(&signing_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid signing_request_id".into()))?;

    let row = sqlx::query(
        "SELECT status, identity_id, xrpl_tx_hash, expected_xrpl_account, approved_by_device_id, approval_signature, expires_at, approved_at FROM qr_xrpl_signing_requests WHERE id = $1",
    )
    .bind(signing_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR XRPL signing status: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR XRPL signing request not found".into()))?;

    let mut status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed signing status: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed signing expiration: {e}")))?;

    if status == "pending" && expires_at < Utc::now() {
        status = "expired".to_string();
        let _ = sqlx::query("UPDATE qr_xrpl_signing_requests SET status = 'expired' WHERE id = $1")
            .bind(signing_id)
            .execute(&state.db)
            .await;
    }

    let approved_at: Option<chrono::DateTime<Utc>> = row.try_get("approved_at").ok();
    Ok(Json(QrXrplSigningStatusResponse {
        status,
        identity_id: row.try_get("identity_id").ok(),
        tx_json_hash: row.try_get("xrpl_tx_hash").ok(),
        expected_xrpl_account: row.try_get("expected_xrpl_account").ok(),
        approved_by_device_id: row.try_get("approved_by_device_id").ok(),
        approval_signature: row.try_get("approval_signature").ok(),
        approved_at: approved_at.map(|ts| ts.to_rfc3339()),
    }))
}

pub async fn start_qr_file_grant_approval(
    State(state): State<AppState>,
    Json(req): Json<QrFileGrantStartRequest>,
) -> Result<Json<QrFileGrantStartResponse>> {
    if req.identity_id.trim().is_empty() {
        return Err(ApiError::BadRequest("identity_id is required".into()));
    }
    if req.vault_object_id.trim().is_empty() {
        return Err(ApiError::BadRequest("vault_object_id is required".into()));
    }
    if req.recipient_identity_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "recipient_identity_id is required".into(),
        ));
    }
    if req.permissions.is_empty() {
        return Err(ApiError::BadRequest("permissions must not be empty".into()));
    }

    let owner_row = sqlx::query(
        "SELECT owner_identity_id FROM vault_objects WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.vault_object_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load vault object: {e}")))?
    .ok_or_else(|| ApiError::NotFound("Vault object not found".into()))?;
    let owner_identity_id: String = owner_row
        .try_get("owner_identity_id")
        .map_err(|e| ApiError::Database(format!("Malformed vault object owner: {e}")))?;
    if owner_identity_id != req.identity_id {
        return Err(ApiError::Unauthorized(
            "Vault object is not owned by this identity".into(),
        ));
    }

    sqlx::query("SELECT id FROM vaulted_identities WHERE id = $1 AND status = 'active'")
        .bind(&req.recipient_identity_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to load recipient identity: {e}")))?
        .ok_or_else(|| ApiError::BadRequest("Unknown recipient identity".into()))?;

    let id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = hex::encode(nonce);
    let expires_at = Utc::now() + Duration::minutes(5);
    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    if let Some(grant_expires_at) = req.grant_expires_at.as_ref() {
        if *grant_expires_at <= Utc::now() {
            return Err(ApiError::BadRequest(
                "grant expiration must be in the future".into(),
            ));
        }
    }

    let permissions_json = serde_json::to_value(&req.permissions)
        .map_err(|e| ApiError::BadRequest(format!("Invalid permissions: {e}")))?;
    let (key_envelope, encrypted_file_key) = normalize_qr_grant_key_envelope(
        req.key_envelope,
        req.encrypted_file_key,
        &req.recipient_identity_id,
    )?;
    let grant_context_hash = file_grant_context_hash(
        &req.vault_object_id,
        &grant_id.to_string(),
        &req.recipient_identity_id,
        &key_envelope,
        &permissions_json,
        req.grant_expires_at.as_ref(),
    )?;

    sqlx::query(
        r#"INSERT INTO qr_file_grant_requests
           (id, identity_id, challenge, status, vault_object_id, grant_id, recipient_identity_id,
            encrypted_file_key, key_envelope, key_envelope_version, permissions, grant_expires_at, grant_context_hash,
            requester_device_id, requester_device_name, created_at, expires_at)
           VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, $8, 'vaulted-key-envelope-v1', $9, $10, $11, $12, $13, NOW(), $14)"#,
    )
    .bind(id)
    .bind(&req.identity_id)
    .bind(&challenge)
    .bind(&req.vault_object_id)
    .bind(grant_id)
    .bind(&req.recipient_identity_id)
    .bind(&encrypted_file_key)
    .bind(&key_envelope)
    .bind(&permissions_json)
    .bind(req.grant_expires_at)
    .bind(&grant_context_hash)
    .bind(&req.requester_device_id)
    .bind(&req.requester_device_name)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create QR file grant request: {e}")))?;

    let mut canonical_payload = VaultedQrPayloadBody::scan_to_approve_file_grant(
        id.to_string(),
        challenge.clone(),
        oracle_url.clone(),
        expires_at.to_rfc3339(),
        req.vault_object_id.clone(),
        grant_id.to_string(),
        req.recipient_identity_id.clone(),
        req.permissions.clone(),
    );
    canonical_payload.identity_id = Some(req.identity_id.clone());
    canonical_payload.requester_device_id = req.requester_device_id.clone();
    canonical_payload.requester_device_name = req.requester_device_name.clone();
    if let Some(summary) = req.human_summary.clone() {
        canonical_payload.human_summary = Some(summary);
    }

    let qr_payload = serde_json::json!({
        "type": "vaulted-file-grant-approval-v1",
        "grantRequestId": id.to_string(),
        "grantId": grant_id.to_string(),
        "identityId": req.identity_id,
        "vaultObjectId": req.vault_object_id,
        "recipientIdentityId": req.recipient_identity_id,
        "challenge": challenge,
        "oracleUrl": oracle_url,
        "expiresAt": expires_at.to_rfc3339(),
        "grantContextHash": grant_context_hash,
        "permissions": req.permissions,
        "requesterDeviceId": req.requester_device_id,
        "requesterDeviceName": req.requester_device_name,
        "canonicalPayload": canonical_payload,
    });

    Ok(Json(QrFileGrantStartResponse {
        grant_request_id: id.to_string(),
        grant_id: grant_id.to_string(),
        challenge: qr_payload["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        oracle_url,
        expires_at: expires_at.to_rfc3339(),
        grant_context_hash: qr_payload["grantContextHash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        qr_payload,
    }))
}

pub async fn confirm_qr_file_grant_approval(
    State(state): State<AppState>,
    Json(req): Json<QrFileGrantConfirmRequest>,
) -> Result<Json<QrFileGrantConfirmResponse>> {
    let grant_request_id = Uuid::parse_str(&req.grant_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid grant_request_id".into()))?;

    let row = sqlx::query(
        r#"SELECT identity_id, challenge, status, expires_at, vault_object_id, grant_id,
                  recipient_identity_id, encrypted_file_key,
                  COALESCE(key_envelope, jsonb_build_object(
                      'protocol', 'vaulted-key-envelope-v1',
                      'alg', 'legacy-pre-aes-key',
                      'recipient_type', 'grant-recipient',
                      'recipient_identity_id', recipient_identity_id,
                      'encrypted_file_key', encrypted_file_key
                  )) AS key_envelope,
                  permissions, grant_expires_at, grant_context_hash, requester_device_id, requester_device_name
           FROM qr_file_grant_requests WHERE id = $1"#,
    )
    .bind(grant_request_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR file grant request: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR file grant request not found".into()))?;

    let identity_id: String = row
        .try_get("identity_id")
        .map_err(|e| ApiError::Database(format!("Malformed grant identity: {e}")))?;
    if identity_id != req.identity_id {
        return Err(ApiError::Unauthorized(
            "File grant identity mismatch".into(),
        ));
    }
    let status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed grant request status: {e}")))?;
    let challenge: String = row
        .try_get("challenge")
        .map_err(|e| ApiError::Database(format!("Malformed grant challenge: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed grant request expiration: {e}")))?;
    let vault_object_id: String = row
        .try_get("vault_object_id")
        .map_err(|e| ApiError::Database(format!("Malformed vault object id: {e}")))?;
    let grant_id: Uuid = row
        .try_get("grant_id")
        .map_err(|e| ApiError::Database(format!("Malformed grant id: {e}")))?;
    let recipient_identity_id: String = row
        .try_get("recipient_identity_id")
        .map_err(|e| ApiError::Database(format!("Malformed recipient identity: {e}")))?;
    let encrypted_file_key: String = row
        .try_get("encrypted_file_key")
        .map_err(|e| ApiError::Database(format!("Malformed encrypted file key: {e}")))?;
    let key_envelope: serde_json::Value = row
        .try_get("key_envelope")
        .map_err(|e| ApiError::Database(format!("Malformed key envelope: {e}")))?;
    let permissions: serde_json::Value = row
        .try_get("permissions")
        .map_err(|e| ApiError::Database(format!("Malformed permissions: {e}")))?;
    let grant_expires_at: Option<chrono::DateTime<Utc>> = row.try_get("grant_expires_at").ok();
    let grant_context_hash: String = row
        .try_get("grant_context_hash")
        .map_err(|e| ApiError::Database(format!("Malformed grant context hash: {e}")))?;
    let requester_device_id: Option<String> = row.try_get("requester_device_id").ok();
    let requester_device_name: Option<String> = row.try_get("requester_device_name").ok();

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "QR file grant request is {status}"
        )));
    }
    if expires_at < Utc::now() {
        let _ = sqlx::query("UPDATE qr_file_grant_requests SET status = 'expired' WHERE id = $1")
            .bind(grant_request_id)
            .execute(&state.db)
            .await;
        return Err(ApiError::Unauthorized(
            "QR file grant request expired".into(),
        ));
    }
    if let Some(grant_expires_at) = grant_expires_at.as_ref() {
        if *grant_expires_at <= Utc::now() {
            let _ =
                sqlx::query("UPDATE qr_file_grant_requests SET status = 'expired' WHERE id = $1")
                    .bind(grant_request_id)
                    .execute(&state.db)
                    .await;
            return Err(ApiError::Unauthorized(
                "requested grant expiration has passed".into(),
            ));
        }
    }

    let identity_row = sqlx::query(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(&req.identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted identity".into()))?;

    let stored_pk: String = identity_row
        .try_get("signing_public_key")
        .map_err(|e| ApiError::Database(format!("Malformed identity: {e}")))?;
    if stored_pk != req.signing_public_key {
        return Err(ApiError::Unauthorized(
            "Signing public key does not match identity".into(),
        ));
    }

    let oracle_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.host, state.config.port));
    let message = file_grant_approval_message(
        &req.grant_request_id,
        &challenge,
        &oracle_url,
        &vault_object_id,
        &grant_id.to_string(),
        &recipient_identity_id,
        &grant_context_hash,
        requester_device_id.as_deref(),
        requester_device_name.as_deref(),
        &req.authorizing_device_id,
    );
    verify_ed25519_hex(&req.signing_public_key, message.as_bytes(), &req.signature)?;

    sqlx::query(
        r#"INSERT INTO grants (id, vault_object_id, recipient_identity_id, encrypted_file_key, key_envelope, key_envelope_version, permissions, expires_at, owner_signature, status)
           VALUES ($1, $2, $3, $4, $5, 'vaulted-key-envelope-v1', $6, $7, $8, 'active')
           ON CONFLICT (id) DO UPDATE SET
             encrypted_file_key = EXCLUDED.encrypted_file_key,
             key_envelope = EXCLUDED.key_envelope,
             key_envelope_version = EXCLUDED.key_envelope_version,
             permissions = EXCLUDED.permissions,
             expires_at = EXCLUDED.expires_at,
             owner_signature = EXCLUDED.owner_signature,
             status = 'active'"#,
    )
    .bind(grant_id)
    .bind(&vault_object_id)
    .bind(&recipient_identity_id)
    .bind(&encrypted_file_key)
    .bind(&key_envelope)
    .bind(&permissions)
    .bind(grant_expires_at)
    .bind(&req.signature)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create approved file grant: {e}")))?;

    sqlx::query(
        r#"UPDATE qr_file_grant_requests
           SET status = 'approved', approved_by_device_id = $2,
               approval_signing_public_key = $3, approval_signature = $4,
               created_grant_id = $5, approved_at = NOW()
           WHERE id = $1"#,
    )
    .bind(grant_request_id)
    .bind(&req.authorizing_device_id)
    .bind(&req.signing_public_key)
    .bind(&req.signature)
    .bind(grant_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to approve QR file grant: {e}")))?;

    Ok(Json(QrFileGrantConfirmResponse {
        approved: true,
        status: "approved".into(),
        grant_id: grant_id.to_string(),
    }))
}

pub async fn qr_file_grant_approval_status(
    State(state): State<AppState>,
    Path(grant_request_id): Path<String>,
) -> Result<Json<QrFileGrantStatusResponse>> {
    let request_id = Uuid::parse_str(&grant_request_id)
        .map_err(|_| ApiError::BadRequest("Invalid grant_request_id".into()))?;

    let row = sqlx::query(
        r#"SELECT status, identity_id, vault_object_id, grant_id, recipient_identity_id,
                  grant_context_hash, approved_by_device_id, approval_signature,
                  created_grant_id, expires_at, approved_at
           FROM qr_file_grant_requests WHERE id = $1"#,
    )
    .bind(request_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load QR file grant status: {e}")))?
    .ok_or_else(|| ApiError::NotFound("QR file grant request not found".into()))?;

    let mut status: String = row
        .try_get("status")
        .map_err(|e| ApiError::Database(format!("Malformed file grant status: {e}")))?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| ApiError::Database(format!("Malformed grant request expiration: {e}")))?;
    if status == "pending" && expires_at < Utc::now() {
        status = "expired".to_string();
        let _ = sqlx::query("UPDATE qr_file_grant_requests SET status = 'expired' WHERE id = $1")
            .bind(request_id)
            .execute(&state.db)
            .await;
    }
    let grant_id: Option<Uuid> = row.try_get("grant_id").ok();
    let created_grant_id: Option<Uuid> = row.try_get("created_grant_id").ok();
    let approved_at: Option<chrono::DateTime<Utc>> = row.try_get("approved_at").ok();

    Ok(Json(QrFileGrantStatusResponse {
        status,
        identity_id: row.try_get("identity_id").ok(),
        vault_object_id: row.try_get("vault_object_id").ok(),
        grant_id: grant_id.map(|id| id.to_string()),
        recipient_identity_id: row.try_get("recipient_identity_id").ok(),
        grant_context_hash: row.try_get("grant_context_hash").ok(),
        approved_by_device_id: row.try_get("approved_by_device_id").ok(),
        approval_signature: row.try_get("approval_signature").ok(),
        created_grant_id: created_grant_id.map(|id| id.to_string()),
        approved_at: approved_at.map(|ts| ts.to_rfc3339()),
    }))
}

fn pair_device_signature_message(
    pairing_request_id: &str,
    challenge: &str,
    oracle_url: &str,
    desktop_device_public_key: &str,
    desktop_device_name: Option<&str>,
    authorizing_device_id: &str,
) -> String {
    format!(
        "Vaulted QR Pair Device v1\npairing_request_id:{}\nchallenge:{}\noracle_url:{}\ndesktop_device_public_key:{}\ndesktop_device_name:{}\nauthorizing_device_id:{}",
        pairing_request_id,
        challenge,
        oracle_url,
        desktop_device_public_key,
        desktop_device_name.unwrap_or(""),
        authorizing_device_id,
    )
}

fn xrpl_signing_approval_message(
    signing_request_id: &str,
    challenge: &str,
    oracle_url: &str,
    tx_json_hash: &str,
    expected_xrpl_account: &str,
    requester_device_id: Option<&str>,
    requester_device_name: Option<&str>,
    authorizing_device_id: &str,
) -> String {
    format!(
        "Vaulted QR XRPL Sign v1\nsigning_request_id:{}\nchallenge:{}\noracle_url:{}\ntx_json_hash:{}\nexpected_xrpl_account:{}\nrequester_device_id:{}\nrequester_device_name:{}\nauthorizing_device_id:{}",
        signing_request_id,
        challenge,
        oracle_url,
        tx_json_hash,
        expected_xrpl_account,
        requester_device_id.unwrap_or(""),
        requester_device_name.unwrap_or(""),
        authorizing_device_id,
    )
}

fn file_grant_approval_message(
    grant_request_id: &str,
    challenge: &str,
    oracle_url: &str,
    vault_object_id: &str,
    grant_id: &str,
    recipient_identity_id: &str,
    grant_context_hash: &str,
    requester_device_id: Option<&str>,
    requester_device_name: Option<&str>,
    authorizing_device_id: &str,
) -> String {
    format!(
        "Vaulted QR File Grant v1\ngrant_request_id:{}\nchallenge:{}\noracle_url:{}\nvault_object_id:{}\ngrant_id:{}\nrecipient_identity_id:{}\ngrant_context_hash:{}\nrequester_device_id:{}\nrequester_device_name:{}\nauthorizing_device_id:{}",
        grant_request_id,
        challenge,
        oracle_url,
        vault_object_id,
        grant_id,
        recipient_identity_id,
        grant_context_hash,
        requester_device_id.unwrap_or(""),
        requester_device_name.unwrap_or(""),
        authorizing_device_id,
    )
}

fn normalize_qr_grant_key_envelope(
    key_envelope: Option<serde_json::Value>,
    encrypted_file_key: Option<String>,
    recipient_identity_id: &str,
) -> Result<(serde_json::Value, String)> {
    if let Some(value) = key_envelope {
        if !value.is_object() {
            return Err(ApiError::BadRequest(
                "keyEnvelope must be a JSON object".into(),
            ));
        }
        validate_recipient_key_envelope(&value, recipient_identity_id)?;
        let encrypted = value
            .get("encrypted_file_key")
            .or_else(|| value.get("encryptedFileKey"))
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| ApiError::BadRequest("keyEnvelope.encryptedFileKey is required".into()))?
            .to_string();
        return Ok((value, encrypted));
    }

    let encrypted = encrypted_file_key
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::BadRequest("keyEnvelope is required".into()))?;
    let envelope = serde_json::json!({
        "protocol": "vaulted-key-envelope-v1",
        "alg": "legacy-pre-aes-key",
        "recipient_type": "grant-recipient",
        "recipient_identity_id": recipient_identity_id,
        "encrypted_file_key": encrypted,
    });
    Ok((envelope, encrypted))
}

fn validate_recipient_key_envelope(
    value: &serde_json::Value,
    recipient_identity_id: &str,
) -> Result<()> {
    let envelope_recipient = value
        .get("recipient_identity_id")
        .or_else(|| value.get("recipientIdentityId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::BadRequest("key envelope recipient_identity_id is required".into())
        })?;
    if envelope_recipient != recipient_identity_id {
        return Err(ApiError::BadRequest(
            "key envelope recipient_identity_id mismatch".into(),
        ));
    }

    let alg = value
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("key envelope alg is required".into()))?;
    if alg == "X25519-HKDF-SHA256-XCHACHA20POLY1305" {
        for field in [
            "recipient_public_key_id",
            "ephemeral_public_key",
            "nonce",
            "encrypted_file_key",
        ] {
            let present = value
                .get(field)
                .or_else(|| match field {
                    "recipient_public_key_id" => value.get("recipientPublicKeyId"),
                    "ephemeral_public_key" => value.get("ephemeralPublicKey"),
                    "encrypted_file_key" => value.get("encryptedFileKey"),
                    _ => None,
                })
                .and_then(|v| v.as_str())
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !present {
                return Err(ApiError::BadRequest(format!(
                    "key envelope {field} is required"
                )));
            }
        }
    }
    Ok(())
}

fn file_grant_context_hash(
    vault_object_id: &str,
    grant_id: &str,
    recipient_identity_id: &str,
    key_envelope: &serde_json::Value,
    permissions: &serde_json::Value,
    grant_expires_at: Option<&chrono::DateTime<Utc>>,
) -> Result<String> {
    let context = serde_json::json!({
        "protocol": "vaulted-file-grant-context-v1",
        "vaultObjectId": vault_object_id,
        "grantId": grant_id,
        "recipientIdentityId": recipient_identity_id,
        "keyEnvelope": key_envelope,
        "permissions": permissions,
        "grantExpiresAt": grant_expires_at.map(|ts| ts.to_rfc3339()),
    });
    let bytes = serde_json::to_vec(&context)
        .map_err(|e| ApiError::BadRequest(format!("Invalid file grant context: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn stable_json_sha256_hex(value: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| ApiError::BadRequest(format!("Invalid XRPL transaction JSON: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_hex_public_key(value: &str, field: &str) -> Result<()> {
    let bytes =
        hex::decode(value).map_err(|_| ApiError::BadRequest(format!("{field} must be hex")))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!("{field} must be 32 bytes")));
    }
    Ok(())
}

fn verify_ed25519_hex(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let pk = hex::decode(public_key_hex)
        .map_err(|_| ApiError::Unauthorized("Invalid signing public key".into()))?;
    if pk.len() != 32 {
        return Err(ApiError::Unauthorized(
            "Invalid signing public key length".into(),
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Unauthorized("Invalid signing public key".into()))?;

    let sig = hex::decode(signature_hex)
        .map_err(|_| ApiError::Unauthorized("Invalid signature encoding".into()))?;
    if sig.len() != 64 {
        return Err(ApiError::Unauthorized("Invalid signature length".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|_| ApiError::Unauthorized("Invalid QR login signature".into()))
}

#[cfg(test)]
mod pair_device_tests {
    use super::*;

    #[test]
    fn pair_device_signature_message_is_stable_and_domain_separated() {
        let msg = pair_device_signature_message(
            "pair-1",
            "challenge-1",
            "https://oracle.example",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("Desktop"),
            "mobile-device-1",
        );
        assert!(msg.starts_with("Vaulted QR Pair Device v1\n"));
        assert!(msg.contains("pairing_request_id:pair-1"));
        assert!(msg.contains("desktop_device_public_key:aaaaaaaa"));
        assert!(msg.contains("authorizing_device_id:mobile-device-1"));
    }

    #[test]
    fn pair_device_public_key_validation_requires_32_byte_hex() {
        assert!(validate_hex_public_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "device_public_key"
        )
        .is_ok());
        assert!(validate_hex_public_key("abcd", "device_public_key").is_err());
        assert!(validate_hex_public_key("not-hex", "device_public_key").is_err());
    }

    #[test]
    fn xrpl_signing_approval_message_is_stable_and_domain_separated() {
        let msg = xrpl_signing_approval_message(
            "sign-1",
            "challenge",
            "https://oracle.example",
            "aa",
            "rExpected",
            Some("desktop-1"),
            Some("Vaulted Desktop"),
            "mobile-1",
        );
        assert!(msg.starts_with("Vaulted QR XRPL Sign v1\n"));
        assert!(msg.contains("tx_json_hash:aa"));
        assert!(msg.contains("expected_xrpl_account:rExpected"));
        assert!(msg.contains("authorizing_device_id:mobile-1"));
    }

    #[test]
    fn stable_json_hash_is_deterministic() {
        let value = serde_json::json!({"TransactionType":"NFTokenMint","Account":"rA"});
        assert_eq!(
            stable_json_sha256_hex(&value).unwrap(),
            stable_json_sha256_hex(&value).unwrap()
        );
        assert_ne!(
            stable_json_sha256_hex(&value).unwrap(),
            stable_json_sha256_hex(
                &serde_json::json!({"TransactionType":"Payment","Account":"rA"})
            )
            .unwrap()
        );
    }

    #[test]
    fn file_grant_context_hash_is_deterministic_and_context_bound() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({
            "protocol": "vaulted-key-envelope-v1",
            "alg": "X25519-HKDF-SHA256-XCHACHA20POLY1305",
            "recipient_identity_id": "recipient-1",
            "encrypted_file_key": "encrypted-file-key"
        });
        let first = file_grant_context_hash(
            "vault-1",
            "grant-1",
            "recipient-1",
            &key_envelope,
            &permissions,
            None,
        )
        .unwrap();
        let second = file_grant_context_hash(
            "vault-1",
            "grant-1",
            "recipient-1",
            &key_envelope,
            &permissions,
            None,
        )
        .unwrap();
        let changed_envelope = serde_json::json!({
            "protocol": "vaulted-key-envelope-v1",
            "alg": "X25519-HKDF-SHA256-XCHACHA20POLY1305",
            "recipient_identity_id": "recipient-2",
            "encrypted_file_key": "encrypted-file-key"
        });
        let changed = file_grant_context_hash(
            "vault-1",
            "grant-1",
            "recipient-2",
            &changed_envelope,
            &permissions,
            None,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn real_file_grant_key_envelope_is_accepted_and_bound_to_recipient() {
        let envelope = serde_json::json!({
            "recipient_type": "grant-recipient",
            "recipient_identity_id": "recipient-1",
            "recipient_public_key_id": "pk-id",
            "alg": "X25519-HKDF-SHA256-XCHACHA20POLY1305",
            "ephemeral_public_key": "aa",
            "nonce": "nonce",
            "encrypted_file_key": "ciphertext"
        });
        let (normalized, mirror) =
            normalize_qr_grant_key_envelope(Some(envelope.clone()), None, "recipient-1").unwrap();
        assert_eq!(normalized, envelope);
        assert_eq!(mirror, "ciphertext");
    }

    #[test]
    fn file_grant_key_envelope_rejects_recipient_mismatch() {
        let envelope = serde_json::json!({
            "recipient_type": "grant-recipient",
            "recipient_identity_id": "recipient-2",
            "recipient_public_key_id": "pk-id",
            "alg": "X25519-HKDF-SHA256-XCHACHA20POLY1305",
            "ephemeral_public_key": "aa",
            "nonce": "nonce",
            "encrypted_file_key": "ciphertext"
        });
        assert!(normalize_qr_grant_key_envelope(Some(envelope), None, "recipient-1").is_err());
    }

    #[test]
    fn file_grant_approval_message_is_stable_and_domain_separated() {
        let msg = file_grant_approval_message(
            "grant-request-1",
            "challenge",
            "https://oracle.example",
            "vault-1",
            "grant-1",
            "recipient-1",
            "aa",
            Some("desktop-1"),
            Some("Vaulted Desktop"),
            "mobile-1",
        );
        assert!(msg.starts_with("Vaulted QR File Grant v1\n"));
        assert!(msg.contains("vault_object_id:vault-1"));
        assert!(msg.contains("grant_context_hash:aa"));
        assert!(msg.contains("authorizing_device_id:mobile-1"));
    }
}
