//! Authentication API endpoints

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{self, Claims, TokenResponse},
    error::{ApiError, Result},
    services::AppState,
    xrpl_verify,
};

/// Request for authentication token.
///
/// Legacy XRPL signature auth.
/// In Vaulted wallet mode this endpoint should not be used for primary login.
/// Prefer Vaulted identity login or QR login.
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    /// XRPL wallet address
    pub wallet_address: String,
    /// XRPL public key hex
    pub public_key: String,
    /// Signed challenge hex
    pub signature: String,
    /// Challenge that was signed
    pub challenge: String,
    /// Device fingerprint for token binding
    #[serde(default)]
    pub device_fingerprint: Option<String>,
}

/// Request for refresh token rotation.
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// POST /api/v1/auth/token
///
/// Legacy endpoint. Exchanges signed XRPL challenge for JWT access token.
/// In Vaulted wallet mode, use /api/v1/auth/qr/* or /api/v1/identity/token.
pub async fn get_token(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<TokenResponse>> {
    if !req.wallet_address.starts_with('r') || req.wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".into()));
    }

    if !req.challenge.starts_with("xrpl-vault-auth:")
        && !req.challenge.starts_with("xrpl-vault-auth-login:")
    {
        return Err(ApiError::Validation("Invalid challenge format".into()));
    }

    if !state
        .verify_and_consume_challenge(&req.challenge, &req.wallet_address)
        .await
    {
        return Err(ApiError::Unauthorized(
            "Challenge not found, expired, or already used. Please request a new challenge.".into(),
        ));
    }

    let user_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE wallet_address = $1)",
    )
    .bind(&req.wallet_address)
    .fetch_one(&state.db)
    .await?;

    if !user_exists {
        return Err(ApiError::NotFound(format!(
            "User {} not registered. Please register first.",
            req.wallet_address
        )));
    }

    let is_valid =
        xrpl_verify::verify_xrpl_signature(&req.public_key, &req.challenge, &req.signature)
            .map_err(|e| {
                tracing::warn!(
                    "Signature verification error for {}: {}",
                    req.wallet_address,
                    e
                );
                ApiError::Unauthorized(format!("Invalid signature: {}", e))
            })?;

    if !is_valid {
        tracing::warn!("Invalid signature for wallet {}", req.wallet_address);
        return Err(ApiError::Unauthorized(
            "Signature verification failed".into(),
        ));
    }

    tracing::debug!("Signature verified for wallet {}", req.wallet_address);

    let user_role = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(role, 'user') FROM users WHERE wallet_address = $1",
    )
    .bind(&req.wallet_address)
    .fetch_one(&state.db)
    .await
    .unwrap_or_else(|_| "user".to_string());

    let claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_access_device_bound(&req.wallet_address, 1, &user_role, dfp)
    } else {
        Claims::new_access_with_role(&req.wallet_address, 1, &user_role)
    };
    let access_token = auth::create_token(&claims, &state.signing_key);

    let refresh_claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_refresh_device_bound(&req.wallet_address, 7, dfp)
    } else {
        Claims::new_refresh(&req.wallet_address, 7)
    };
    let refresh_token = auth::create_token(&refresh_claims, &state.signing_key);

    state
        .audit_log(
            None,
            "auth_token_issued",
            None,
            Some(serde_json::json!({
                "wallet_address": req.wallet_address,
                "token_id": claims.jti,
                "expires_at": claims.exp,
                "public_key_prefix": &req.public_key[..8.min(req.public_key.len())],
                "auth_mode": "legacy_xrpl_signature"
            })),
        )
        .await;

    tracing::info!("Token issued for wallet {}", req.wallet_address);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        role: Some(user_role),
    }))
}

/// Response for auth challenge.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub expires_in: i64,
}

/// GET /api/v1/auth/login-challenge
///
/// Legacy login challenge.
/// In Vaulted wallet mode, QR login should be used instead.
pub async fn get_login_challenge(State(state): State<AppState>) -> Result<Json<ChallengeResponse>> {
    let nonce = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let challenge = format!("xrpl-vault-auth-login:{}:{}", nonce, timestamp);

    state.store_challenge(&nonce, &challenge, "*").await;

    Ok(Json(ChallengeResponse {
        challenge,
        expires_in: 300,
    }))
}

/// GET /api/v1/auth/challenge/:wallet_address
///
/// Legacy challenge endpoint.
pub async fn get_challenge(
    State(state): State<AppState>,
    axum::extract::Path(wallet_address): axum::extract::Path<String>,
) -> Result<Json<ChallengeResponse>> {
    if !wallet_address.starts_with('r') || wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".into()));
    }

    let nonce = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let challenge = format!("xrpl-vault-auth:{}:{}:{}", wallet_address, nonce, timestamp);

    state
        .store_challenge(&nonce, &challenge, &wallet_address)
        .await;

    Ok(Json(ChallengeResponse {
        challenge,
        expires_in: 300,
    }))
}

/// POST /api/v1/auth/logout
///
/// Invalidate current token by blacklisting its JTI.
pub async fn logout(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    let exp = chrono::Utc::now().timestamp() + 3600;
    state.blacklist_token(&auth.token_id, exp).await;

    state
        .audit_log(
            None,
            "auth_logout",
            None,
            Some(serde_json::json!({
                "wallet_address": auth.wallet_address,
                "token_id": auth.token_id,
            })),
        )
        .await;

    tracing::info!(
        "Logout for wallet {} — token {} blacklisted",
        auth.wallet_address,
        auth.token_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully. Token has been revoked."
    })))
}

/// GET /api/v1/auth/me
///
/// Get current authenticated user info.
pub async fn get_me(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<UserInfoResponse>> {
    let user = sqlx::query_as::<_, (Uuid, String, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, wallet_address, pre_public_key, created_at FROM users WHERE wallet_address = $1",
    )
        .bind(&auth.wallet_address)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;

    Ok(Json(UserInfoResponse {
        id: user.0.to_string(),
        wallet_address: user.1,
        public_key: user.2,
        created_at: user.3.to_rfc3339(),
    }))
}

#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub wallet_address: String,
    pub public_key: String,
    pub created_at: String,
}

/// POST /api/v1/auth/refresh
///
/// Rotate refresh token and issue a new access token.
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>> {
    let verifying_key = state.signing_key.verifying_key();
    let claims = auth::verify_token(&req.refresh_token, &verifying_key)
        .map_err(|e| ApiError::Unauthorized(format!("Invalid refresh token: {}", e)))?;

    if claims.typ != "refresh" {
        return Err(ApiError::Unauthorized("Not a refresh token".into()));
    }

    if state.is_token_blacklisted(&claims.jti).await {
        tracing::error!(
            "SECURITY: Refresh token reuse detected for wallet {}. JTI: {}",
            claims.sub,
            claims.jti
        );

        state
            .audit_log(
                None,
                "security_refresh_token_reuse",
                None,
                Some(serde_json::json!({
                    "wallet_address": claims.sub,
                    "reused_jti": claims.jti,
                    "action": "all_tokens_revoked",
                })),
            )
            .await;

        return Err(ApiError::Unauthorized(
            "Refresh token has been revoked. Possible token theft detected — please re-authenticate."
                .into(),
        ));
    }

    state.blacklist_token(&claims.jti, claims.exp).await;

    let user_role = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(role, 'user') FROM users WHERE wallet_address = $1",
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("User no longer exists".into()))?;

    let new_claims = auth::Claims::new_access_with_role(&claims.sub, 1, &user_role);
    let access_token = auth::create_token(&new_claims, &state.signing_key);

    let new_refresh = auth::Claims::new_refresh(&claims.sub, 7);
    let new_refresh_token = auth::create_token(&new_refresh, &state.signing_key);

    tracing::info!("Token refreshed for wallet {}", claims.sub);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(new_refresh_token),
        role: Some(user_role),
    }))
}
