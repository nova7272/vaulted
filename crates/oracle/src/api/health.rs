//! Health check endpoints

use axum::{extract::State, Json};

use crate::{db, error::Result, models::HealthResponse, services::AppState};

/// GET /health - базовый health check
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: "unknown".to_string(),
    })
}

/// GET /ready - readiness check (включая БД)
pub async fn ready_check(State(state): State<AppState>) -> Result<Json<HealthResponse>> {
    // Проверяем подключение к БД
    db::check_connection(&state.db).await?;

    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: "connected".to_string(),
    }))
}

/// GET /public-key - Oracle's Ed25519 public key for token verification
///
/// Storage nodes use this to fetch the key they need to verify signed tokens.
pub async fn public_key(State(state): State<AppState>) -> Json<serde_json::Value> {
    let verifying_key = state.signing_key.verifying_key();
    Json(serde_json::json!({
        "public_key": hex::encode(verifying_key.as_bytes())
    }))
}
