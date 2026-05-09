//! Endpoints для пользователей

use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    models::{RegisterUserRequest, RegisterUserResponse, UserPublicKeyResponse},
    services::AppState,
};

/// POST /api/v1/users/register - регистрация нового пользователя
/// 
/// PUBLIC endpoint - new users can register without auth.
/// CANNOT update existing user's pre_public_key (HIGH-06 protection).
/// Use PUT /api/v1/users/update-key (authenticated) to update keys.
pub async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>> {
    // Валидация адреса кошелька (должен начинаться с 'r')
    if !request.wallet_address.starts_with('r') || request.wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".to_string()));
    }

    // Валидация публичного ключа (должен быть hex, 66 or 128 символов)
    if (request.pre_public_key.len() != 66 && request.pre_public_key.len() != 128)
        || !request.pre_public_key.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ApiError::Validation(
            "Invalid PRE public key format".to_string(),
        ));
    }

    // Check if user already exists (HIGH-06: block public key overwrite)
    let existing = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM users WHERE wallet_address = $1",
    )
    .bind(&request.wallet_address)
    .fetch_optional(&state.db)
    .await?;

    if let Some((user_id,)) = existing {
        // User exists — do NOT overwrite pre_public_key without auth (HIGH-06)
        tracing::warn!(
            "Registration attempt for existing user {}: pre_public_key NOT updated (requires auth)",
            request.wallet_address
        );

        return Ok(Json(RegisterUserResponse {
            user_id,
            wallet_address: request.wallet_address,
            created: false,
        }));
    }

    // Создаём нового пользователя
    let user_id = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        INSERT INTO users (wallet_address, pre_public_key)
        VALUES ($1, $2)
        RETURNING id
        "#,
    )
    .bind(&request.wallet_address)
    .bind(&request.pre_public_key)
    .fetch_one(&state.db)
    .await?;

    tracing::info!("Registered new user: {}", request.wallet_address);

    // Аудит
    state
        .audit_log(
            Some(user_id),
            "user_register",
            None,
            Some(serde_json::json!({
                "wallet_address": request.wallet_address,
            })),
        )
        .await;

    Ok(Json(RegisterUserResponse {
        user_id,
        wallet_address: request.wallet_address,
        created: true,
    }))
}

/// PUT /api/v1/users/update-key - update PRE public key (requires auth)
/// **Requires authentication** (HIGH-06)
pub async fn update_public_key(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<UpdateKeyRequest>,
) -> Result<Json<serde_json::Value>> {
    // Validate key format
    if (request.pre_public_key.len() != 66 && request.pre_public_key.len() != 128)
        || !request.pre_public_key.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ApiError::Validation(
            "Invalid PRE public key format".to_string(),
        ));
    }

    // Only update own key
    let updated = sqlx::query(
        "UPDATE users SET pre_public_key = $1, updated_at = NOW() WHERE wallet_address = $2",
    )
    .bind(&request.pre_public_key)
    .bind(&auth.wallet_address)
    .execute(&state.db)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound("User not found".to_string()));
    }

    tracing::info!("Updated PRE key for authenticated user {}", auth.wallet_address);

    state
        .audit_log(
            None,
            "user_key_updated",
            None,
            Some(serde_json::json!({
                "wallet_address": auth.wallet_address,
            })),
        )
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Public key updated"
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateKeyRequest {
    pub pre_public_key: String,
}

/// GET /api/v1/users/:wallet_address/public-key - получить публичный ключ
pub async fn get_public_key(
    State(state): State<AppState>,
    Path(wallet_address): Path<String>,
) -> Result<Json<UserPublicKeyResponse>> {
    let user = sqlx::query_as::<_, (String,)>(
        "SELECT pre_public_key FROM users WHERE wallet_address = $1",
    )
    .bind(&wallet_address)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("User {} not found", wallet_address)))?;

    Ok(Json(UserPublicKeyResponse {
        wallet_address,
        pre_public_key: user.0,
    }))
}
