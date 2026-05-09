//! Xaman API proxy endpoints.
//!
//! Security goal:
//! XAMAN_API_SECRET must live only on the Oracle/backend.
//! The desktop client must never talk to Xaman Platform API with the secret.

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::Value;

use crate::error::{ApiError, Result};
use crate::services::AppState;

const XAMAN_API_URL: &str = "https://xumm.app/api/v1";

/// Create a Xaman payload through Oracle.
pub async fn create_payload(
    State(state): State<AppState>,
    Json(mut request): Json<Value>,
) -> Result<Json<Value>> {
    validate_payload_request(&request)?;

    apply_forced_network(&state, &mut request)?;

    let api_key = require_xaman_api_key(&state)?;
    let api_secret = require_xaman_api_secret(&state)?;

    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/platform/payload", XAMAN_API_URL))
        .header("X-API-Key", api_key)
        .header("X-API-Secret", api_secret)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Xaman create payload request failed: {}", e)))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ApiError::Internal(format!("Xaman create payload response read failed: {}", e)))?;

    if !status.is_success() {
        tracing::warn!("Xaman create payload failed: status={}, body={}", status, text);
        return Err(ApiError::BadRequest(format!(
            "Xaman failed to create payload: {}",
            text
        )));
    }

    let json: Value = serde_json::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("Invalid Xaman JSON response: {}", e)))?;

    Ok(Json(json))
}

/// Get a Xaman payload status through Oracle.
pub async fn get_payload(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<Json<Value>> {
    if uuid.trim().is_empty() || uuid.len() > 128 {
        return Err(ApiError::BadRequest("Invalid Xaman payload UUID".to_string()));
    }

    let api_key = require_xaman_api_key(&state)?;
    let api_secret = require_xaman_api_secret(&state)?;

    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/platform/payload/{}", XAMAN_API_URL, uuid))
        .header("X-API-Key", api_key)
        .header("X-API-Secret", api_secret)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Xaman get payload request failed: {}", e)))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ApiError::Internal(format!("Xaman get payload response read failed: {}", e)))?;

    if !status.is_success() {
        tracing::warn!("Xaman get payload failed: status={}, body={}", status, text);
        return Err(ApiError::BadRequest(format!(
            "Xaman failed to get payload: {}",
            text
        )));
    }

    let json: Value = serde_json::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("Invalid Xaman JSON response: {}", e)))?;

    Ok(Json(json))
}

fn require_xaman_api_key(state: &AppState) -> Result<&str> {
    state
        .config
        .xaman_api_key
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::Internal("XAMAN_API_KEY is not configured on Oracle".to_string()))
}

fn require_xaman_api_secret(state: &AppState) -> Result<&str> {
    state
        .config
        .xaman_api_secret
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::Internal("XAMAN_API_SECRET is not configured on Oracle".to_string()))
}

fn apply_forced_network(state: &AppState, request: &mut Value) -> Result<()> {
    let Some(force_network) = state.config.xaman_force_network.as_deref() else {
        return Ok(());
    };

    if force_network.trim().is_empty() {
        return Ok(());
    }

    let obj = request
        .as_object_mut()
        .ok_or_else(|| ApiError::BadRequest("Xaman request must be a JSON object".to_string()))?;

    let options = obj
        .entry("options")
        .or_insert_with(|| serde_json::json!({}));

    let options_obj = options
        .as_object_mut()
        .ok_or_else(|| ApiError::BadRequest("Xaman options must be a JSON object".to_string()))?;

    options_obj.insert(
        "force_network".to_string(),
        Value::String(force_network.trim().to_string()),
    );

    Ok(())
}

fn validate_payload_request(request: &Value) -> Result<()> {
    let txjson = request
        .get("txjson")
        .and_then(|v| v.as_object())
        .ok_or_else(|| ApiError::BadRequest("Missing txjson object".to_string()))?;

    let tx_type = txjson
        .get("TransactionType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("Missing txjson.TransactionType".to_string()))?;

    // Allow only transaction types used by the desktop client.
    // This prevents the public proxy endpoint from becoming a generic Xaman payload creator.
    let allowed = matches!(
        tx_type,
        "SignIn"
            | "Payment"
            | "NFTokenAcceptOffer"
            | "NFTokenCreateOffer"
            | "NFTokenBurn"
    );

    if !allowed {
        return Err(ApiError::Forbidden(format!(
            "Xaman TransactionType is not allowed: {}",
            tx_type
        )));
    }

    Ok(())
}
