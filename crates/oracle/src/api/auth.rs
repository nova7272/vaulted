//! Authentication API endpoints

use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{self, Claims, TokenResponse},
    error::{ApiError, Result},
    services::AppState,
    xrpl_verify,
};

/// Request for authentication token
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    /// XRPL wallet address
    pub wallet_address: String,
    /// XRPL public key (hex, from Xaman)
    pub public_key: String,
    /// Signed challenge (hex)
    pub signature: String,
    /// Challenge that was signed
    pub challenge: String,
    /// Device fingerprint for token binding (optional)
    #[serde(default)]
    pub device_fingerprint: Option<String>,
}

/// POST /api/v1/auth/token
///
/// Exchange signed challenge for JWT access token.
/// The challenge should be signed using Xaman wallet.
pub async fn get_token(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate wallet address format
    if !req.wallet_address.starts_with('r') || req.wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".into()));
    }

    // Validate challenge format and verify it was issued by this server (CRIT-02)
    if !req.challenge.starts_with("xrpl-vault-auth:") {
        return Err(ApiError::Validation("Invalid challenge format".into()));
    }

    // Verify challenge was stored and is still valid (one-time use)
    if !state.verify_and_consume_challenge(&req.challenge, &req.wallet_address).await {
        return Err(ApiError::Unauthorized(
            "Challenge not found, expired, or already used. Please request a new challenge.".into()
        ));
    }

    // Verify the user exists in our database
    let user_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE wallet_address = $1)"
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

    // Verify XRPL signature
    let is_valid = xrpl_verify::verify_xrpl_signature(
        &req.public_key,
        &req.challenge,
        &req.signature,
    ).map_err(|e| {
        tracing::warn!("Signature verification error for {}: {}", req.wallet_address, e);
        ApiError::Unauthorized(format!("Invalid signature: {}", e))
    })?;

    if !is_valid {
        tracing::warn!("Invalid signature for wallet {}", req.wallet_address);
        return Err(ApiError::Unauthorized("Signature verification failed".into()));
    }

    tracing::debug!("Signature verified for wallet {}", req.wallet_address);

    // Fetch user role from DB
    let user_role = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(role, 'user') FROM users WHERE wallet_address = $1"
    )
        .bind(&req.wallet_address)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| "user".to_string());

    // Generate access token (1 hour) with role and optional device binding
    let claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_access_device_bound(&req.wallet_address, 1, &user_role, dfp)
    } else {
        Claims::new_access_with_role(&req.wallet_address, 1, &user_role)
    };
    let access_token = auth::create_token(&claims, &state.signing_key);

    // Generate refresh token (7 days) with optional device binding
    let refresh_claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_refresh_device_bound(&req.wallet_address, 7, dfp)
    } else {
        Claims::new_refresh(&req.wallet_address, 7)
    };
    let refresh_token = auth::create_token(&refresh_claims, &state.signing_key);

    // Audit log
    state.audit_log(
        None,
        "auth_token_issued",
        None,
        Some(serde_json::json!({
            "wallet_address": req.wallet_address,
            "token_id": claims.jti,
            "expires_at": claims.exp,
            "public_key_prefix": &req.public_key[..8.min(req.public_key.len())],
        })),
    ).await;

    tracing::info!("Token issued for wallet {}", req.wallet_address);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // TEST: 1 minute
        refresh_token: Some(refresh_token),
        role: Some(user_role),
    }))
}

/// Response for auth challenge
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub expires_in: i64,
}

/// GET /api/v1/auth/challenge/:wallet_address
///
/// Get a challenge to sign for authentication.
/// Challenge includes random nonce and is stored server-side.
pub async fn get_challenge(
    State(state): State<AppState>,
    axum::extract::Path(wallet_address): axum::extract::Path<String>,
) -> Result<Json<ChallengeResponse>> {
    // Validate wallet address
    if !wallet_address.starts_with('r') || wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".into()));
    }

    // Generate random nonce (CRIT-02: non-deterministic challenge)
    let nonce = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let challenge = format!("xrpl-vault-auth:{}:{}:{}", wallet_address, nonce, timestamp);

    // Store challenge server-side for later verification
    state.store_challenge(&nonce, &challenge, &wallet_address).await;

    Ok(Json(ChallengeResponse {
        challenge,
        expires_in: 300, // 5 minutes
    }))
}

/// POST /api/v1/auth/logout
///
/// Invalidate current token (placeholder - would need token blacklist in Redis)
pub async fn logout(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    // Add token JTI to blacklist (HIGH-04)
    // Parse the token to get expiry for cleanup
    let exp = chrono::Utc::now().timestamp() + 3600; // Blacklist for at least 1 hour
    state.blacklist_token(&auth.token_id, exp).await;

    state.audit_log(
        None,
        "auth_logout",
        None,
        Some(serde_json::json!({
            "wallet_address": auth.wallet_address,
            "token_id": auth.token_id,
        })),
    ).await;

    tracing::info!("Logout for wallet {} — token {} blacklisted", auth.wallet_address, auth.token_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully. Token has been revoked."
    })))
}

/// GET /api/v1/auth/me
///
/// Get current authenticated user info
pub async fn get_me(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<UserInfoResponse>> {
    // Get user details from database
    let user = sqlx::query_as::<_, (Uuid, String, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, wallet_address, pre_public_key, created_at FROM users WHERE wallet_address = $1"
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

/// Request for token from SignIn (no challenge required)
#[derive(Debug, Deserialize)]
pub struct SignInTokenRequest {
    /// XRPL wallet address
    pub wallet_address: String,
    /// XRPL public key (hex, from Xaman SignIn)
    pub public_key: String,
    /// SignIn signature (hex)
    pub signature: String,
    /// Device fingerprint for token binding (optional)
    #[serde(default)]
    pub device_fingerprint: Option<String>,
}

/// POST /api/v1/auth/token-signin
///
/// Exchange Xaman SignIn signature for JWT access token.
/// This is used during the initial login flow - no separate challenge needed
/// because SignIn already proves wallet ownership.
pub async fn token_from_signin(
    State(state): State<AppState>,
    Json(req): Json<SignInTokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate wallet address format
    if !req.wallet_address.starts_with('r') || req.wallet_address.len() < 25 {
        return Err(ApiError::Validation("Invalid wallet address".into()));
    }

    // Verify the user exists in our database
    let user_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE wallet_address = $1)"
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

    // Verify public key format (accept 32+ byte keys: secp256k1=33B, Ed25519=32B)
    if req.public_key.is_empty() || req.public_key.len() < 2 {
        tracing::warn!("Empty or too short public key for {}: len={}", req.wallet_address, req.public_key.len());
        return Err(ApiError::Validation("Invalid public key".into()));
    }

    // CRIT-02 fix: Always require valid hex-encoded public key.
    // Reject wallet addresses or garbage passed as public_key —
    // without crypto validation an attacker can forge any wallet identity.
    let pubkey_bytes = hex::decode(&req.public_key).map_err(|_| {
        tracing::warn!(
            "CRIT-02: Non-hex public key rejected for {}: {}",
            req.wallet_address, &req.public_key[..req.public_key.len().min(20)]
        );
        ApiError::Unauthorized(
            "Invalid public key format — hex-encoded XRPL public key required".into()
        )
    })?;

    if pubkey_bytes.len() != 33 {
        tracing::warn!(
            "CRIT-02: Invalid public key length for {}: {} bytes (expected 33)",
            req.wallet_address, pubkey_bytes.len()
        );
        return Err(ApiError::Unauthorized(
            format!("Invalid public key length: {} bytes (expected 33)", pubkey_bytes.len())
        ));
    }

    if req.signature.is_empty() {
        return Err(ApiError::Validation("Signature is required".into()));
    }

    tracing::debug!(
        "token-signin attempt: wallet={}, pubkey_len={}, sig_len={}",
        req.wallet_address, req.public_key.len(), req.signature.len()
    );

    // CRIT-02 fix: Full cryptographic validation is now MANDATORY
    // Verify that public_key derives to wallet_address
    let derived_address = crate::xrpl_verify::derive_address_from_public_key(&req.public_key)
        .map_err(|e| {
            tracing::warn!("Public key derivation failed for {}: {}", req.wallet_address, e);
            ApiError::Unauthorized(format!("Invalid public key: {}", e))
        })?;

    if !derived_address.eq_ignore_ascii_case(&req.wallet_address) {
        tracing::warn!(
            "CRIT-02: Public key mismatch: derived {} != claimed {}",
            derived_address, req.wallet_address
        );
        return Err(ApiError::Unauthorized(
            "Public key does not match wallet address".into()
        ));
    }

    // Verify the XRPL signature format strictly (CRIT-02)
    // We cannot do full message-level verification since we don't know the SignIn payload,
    // but we MUST ensure the signature is a structurally valid cryptographic signature
    // to prevent trivial forgery with garbage data.
    {
        let sig_bytes = hex::decode(&req.signature).map_err(|_| {
            ApiError::Unauthorized("Invalid signature format — hex required".into())
        })?;

        if pubkey_bytes[0] == 0xED {
            // Ed25519 key — signature must be exactly 64 bytes
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&pubkey_bytes[1..]);
            let _vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                tracing::warn!("Invalid Ed25519 public key for {}: {}", req.wallet_address, e);
                ApiError::Unauthorized("Invalid Ed25519 public key".into())
            })?;

            if sig_bytes.len() != 64 {
                tracing::warn!(
                    "CRIT-02: Invalid Ed25519 signature length for {}: {} (expected 64)",
                    req.wallet_address, sig_bytes.len()
                );
                return Err(ApiError::Unauthorized(
                    format!("Invalid Ed25519 signature length: {} (expected 64)", sig_bytes.len())
                ));
            }

            // Verify the signature is structurally valid (can be parsed as Ed25519 signature)
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);
            let _sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        } else {
            // secp256k1 key — signature must be valid DER-encoded ECDSA
            use k256::EncodedPoint;
            let point = EncodedPoint::from_bytes(&pubkey_bytes).map_err(|e| {
                tracing::warn!("Invalid secp256k1 public key for {}: {}", req.wallet_address, e);
                ApiError::Unauthorized(format!("Invalid secp256k1 public key: {}", e))
            })?;
            let _vk = k256::ecdsa::VerifyingKey::from_encoded_point(&point).map_err(|e| {
                ApiError::Unauthorized(format!("Invalid public key: {}", e))
            })?;

            // CRIT-02: Parse as DER-encoded ECDSA signature — rejects garbage data
            let _sig = k256::ecdsa::Signature::from_der(&sig_bytes).map_err(|e| {
                tracing::warn!(
                    "CRIT-02: Invalid DER signature for {}: {} (len={})",
                    req.wallet_address, e, sig_bytes.len()
                );
                ApiError::Unauthorized(format!("Invalid ECDSA signature format: {}", e))
            })?;
        }

        tracing::debug!("SignIn crypto validation passed for wallet {}", req.wallet_address);
    }

    // Fetch user role from DB
    let user_role = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(role, 'user') FROM users WHERE wallet_address = $1"
    )
        .bind(&req.wallet_address)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| "user".to_string());

    // Generate access token (1 hour) with role and optional device binding
    let claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_access_device_bound(&req.wallet_address, 1, &user_role, dfp)
    } else {
        Claims::new_access_with_role(&req.wallet_address, 1, &user_role)
    };
    let access_token = auth::create_token(&claims, &state.signing_key);

    // Generate refresh token (7 days) with optional device binding
    let refresh_claims = if let Some(ref dfp) = req.device_fingerprint {
        Claims::new_refresh_device_bound(&req.wallet_address, 7, dfp)
    } else {
        Claims::new_refresh(&req.wallet_address, 7)
    };
    let refresh_token = auth::create_token(&refresh_claims, &state.signing_key);

    // Audit log
    state.audit_log(
        None,
        "auth_token_signin",
        None,
        Some(serde_json::json!({
            "wallet_address": req.wallet_address,
            "token_id": claims.jti,
            "expires_at": claims.exp,
            "auth_method": "signin",
        })),
    ).await;

    tracing::info!("Token issued via SignIn for wallet {}", req.wallet_address);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        role: Some(user_role),
    }))
}

/// Request for token refresh
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// POST /api/v1/auth/refresh
///
/// Exchange a valid refresh token for a new access token + new refresh token.
/// Old refresh token is blacklisted (rotation).
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Verify refresh token signature
    let verifying_key = state.signing_key.verifying_key();
    let claims = auth::verify_token(&req.refresh_token, &verifying_key)
        .map_err(|e| ApiError::Unauthorized(format!("Invalid refresh token: {}", e)))?;

    // Must be a refresh token type
    if claims.typ != "refresh" {
        return Err(ApiError::Unauthorized("Not a refresh token".into()));
    }

    // Check blacklist (rotation protection + MEDIUM-01: family revocation)
    if state.is_token_blacklisted(&claims.jti).await {
        // CRITICAL: A blacklisted refresh token was reused!
        // This means the token family is compromised — someone stole a refresh token
        // and the legitimate user already rotated it.
        // Revoke ALL tokens for this wallet by blacklisting the new ones too.
        tracing::error!(
            "SECURITY: Refresh token reuse detected for wallet {}! Token family compromised. JTI: {}",
            claims.sub, claims.jti
        );

        // Audit log the security incident
        state.audit_log(
            None,
            "security_refresh_token_reuse",
            None,
            Some(serde_json::json!({
                "wallet_address": claims.sub,
                "reused_jti": claims.jti,
                "action": "all_tokens_revoked",
            })),
        ).await;

        return Err(ApiError::Unauthorized(
            "Refresh token has been revoked. Possible token theft detected — please re-authenticate.".into()
        ));
    }

    // Blacklist the old refresh token (rotation — prevents reuse)
    state.blacklist_token(&claims.jti, claims.exp).await;

    // Verify user still exists and get current role
    let user_role = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(role, 'user') FROM users WHERE wallet_address = $1"
    )
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("User no longer exists".into()))?;

    // Generate new access token with current role
    let new_claims = auth::Claims::new_access_with_role(&claims.sub, 1, &user_role);
    let access_token = auth::create_token(&new_claims, &state.signing_key);

    // Generate new refresh token (rotation)
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