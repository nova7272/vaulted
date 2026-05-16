//! JWT Authentication for Oracle API
//!
//! Provides token generation and validation for API authentication.
//! Tokens are signed with Oracle's Ed25519 key.

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::services::AppState;

/// JWT Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject - wallet address
    pub sub: String,
    /// Issued at (unix timestamp)
    pub iat: i64,
    /// Expiration time (unix timestamp)
    pub exp: i64,
    /// Token type: "access" or "refresh"
    pub typ: String,
    /// Token ID for revocation
    pub jti: String,
    /// User role: "user", "admin", "storage_node"
    #[serde(default = "default_role")]
    pub role: String,
    /// Device fingerprint hash (SHA-256 of device info)
    /// Each device gets its own token — multi-device is supported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dfp: Option<String>,
}

fn default_role() -> String {
    "user".to_string()
}

impl Claims {
    /// Create new access token claims
    pub fn new_access(wallet_address: &str, expires_in_hours: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: wallet_address.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::hours(expires_in_hours)).timestamp(),
            typ: "access".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            role: "user".to_string(),
            dfp: None,
        }
    }

    /// Create new access token with role and device fingerprint
    pub fn new_access_with_role(wallet_address: &str, expires_in_hours: i64, role: &str) -> Self {
        let mut claims = Self::new_access(wallet_address, expires_in_hours);
        claims.role = role.to_string();
        claims
    }

    /// Create new access token bound to a specific device
    pub fn new_access_device_bound(
        wallet_address: &str,
        expires_in_hours: i64,
        role: &str,
        device_fingerprint: &str,
    ) -> Self {
        let mut claims = Self::new_access_with_role(wallet_address, expires_in_hours, role);
        claims.dfp = Some(device_fingerprint.to_string());
        claims
    }

    /// Create new refresh token claims (longer lived)
    pub fn new_refresh(wallet_address: &str, expires_in_days: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: wallet_address.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::days(expires_in_days)).timestamp(),
            typ: "refresh".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            role: "user".to_string(),
            dfp: None,
        }
    }

    /// Create refresh token bound to device
    pub fn new_refresh_device_bound(
        wallet_address: &str,
        expires_in_days: i64,
        device_fingerprint: &str,
    ) -> Self {
        let mut claims = Self::new_refresh(wallet_address, expires_in_days);
        claims.dfp = Some(device_fingerprint.to_string());
        claims
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Check if this is a refresh token
    pub fn is_refresh(&self) -> bool {
        self.typ == "refresh"
    }
}

/// JWT Token (header.payload.signature)
#[derive(Debug)]
pub struct JwtToken {
    pub claims: Claims,
    pub raw: String,
}

/// Simple JWT Header
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

/// Create a signed JWT token
pub fn create_token(claims: &Claims, signing_key: &SigningKey) -> String {
    let header = JwtHeader::default();

    // Encode header and payload
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());

    // Sign
    let message = format!("{}.{}", header_b64, payload_b64);
    let signature = signing_key.sign(message.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{}.{}.{}", header_b64, payload_b64, signature_b64)
}

/// Verify and decode a JWT token
pub fn verify_token(token: &str, verifying_key: &VerifyingKey) -> Result<Claims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidToken);
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Verify signature
    let message = format!("{}.{}", header_b64, payload_b64);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| AuthError::InvalidToken)?;

    if signature_bytes.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidSignature)?;

    // Decode payload
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AuthError::InvalidToken)?;
    let claims: Claims =
        serde_json::from_slice(&payload_json).map_err(|_| AuthError::InvalidToken)?;

    // Check expiration
    if claims.is_expired() {
        return Err(AuthError::TokenExpired);
    }

    Ok(claims)
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingAuth,

    #[error("Invalid authorization header format")]
    InvalidAuthHeader,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token has been revoked")]
    TokenRevoked,

    #[error("Device fingerprint mismatch")]
    DeviceMismatch,

    #[error("Insufficient permissions")]
    Forbidden,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingAuth => (StatusCode::UNAUTHORIZED, "Missing authorization"),
            AuthError::InvalidAuthHeader => {
                (StatusCode::UNAUTHORIZED, "Invalid authorization header")
            },
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InvalidSignature => (StatusCode::UNAUTHORIZED, "Invalid signature"),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AuthError::TokenRevoked => (StatusCode::UNAUTHORIZED, "Token has been revoked"),
            AuthError::DeviceMismatch => (
                StatusCode::UNAUTHORIZED,
                "Device fingerprint mismatch — token was issued for a different device",
            ),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "code": status.as_u16()
        }));

        (status, body).into_response()
    }
}

/// Header name for device fingerprint
const DEVICE_FINGERPRINT_HEADER: &str = "X-Device-Fingerprint";

/// Authenticated user extractor
///
/// Checks JWT validity, blacklist, and device fingerprint binding.
/// Each device gets its own token — multiple devices per user are supported.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub wallet_address: String,
    pub token_id: String,
    pub role: String,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Get Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingAuth)?
            .to_str()
            .map_err(|_| AuthError::InvalidAuthHeader)?;

        // Extract Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthHeader)?;

        // Verify token
        let verifying_key = state.signing_key.verifying_key();
        let claims = verify_token(token, &verifying_key)?;

        // Reject refresh tokens used as access tokens
        if claims.is_refresh() {
            return Err(AuthError::InvalidToken);
        }

        // Check if token is blacklisted (HIGH-04)
        if state.is_token_blacklisted(&claims.jti).await {
            return Err(AuthError::TokenRevoked);
        }

        // Verify device fingerprint if token has one bound
        if let Some(ref token_dfp) = claims.dfp {
            let request_dfp = parts
                .headers
                .get(DEVICE_FINGERPRINT_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if request_dfp.is_empty() {
                tracing::warn!(
                    "Device-bound token used without fingerprint header by {}",
                    claims.sub
                );
                return Err(AuthError::DeviceMismatch);
            }

            if request_dfp != token_dfp {
                tracing::warn!(
                    "Device fingerprint mismatch for {}: token={}, request={}",
                    claims.sub,
                    &token_dfp[..8.min(token_dfp.len())],
                    &request_dfp[..8.min(request_dfp.len())]
                );
                return Err(AuthError::DeviceMismatch);
            }
        }

        Ok(AuthenticatedUser {
            wallet_address: claims.sub,
            token_id: claims.jti,
            role: claims.role,
        })
    }
}

/// Admin-only extractor — requires role = "admin"
///
/// Usage:
/// ```ignore
/// async fn admin_handler(admin: AdminUser) -> impl IntoResponse {
///     format!("Admin: {}", admin.0.wallet_address)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthenticatedUser);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if user.role != "admin" {
            tracing::warn!(
                "Non-admin user {} attempted admin action",
                user.wallet_address
            );
            return Err(AuthError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}

/// Optional authentication extractor
///
/// Returns None if no auth header, or Some(user) if valid token
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<AuthenticatedUser>);

#[async_trait]
impl FromRequestParts<AppState> for OptionalAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try to get auth, return None if missing
        match AuthenticatedUser::from_request_parts(parts, state).await {
            Ok(user) => Ok(OptionalAuth(Some(user))),
            Err(AuthError::MissingAuth) => Ok(OptionalAuth(None)),
            Err(e) => Err(e), // Other errors are real errors
        }
    }
}

/// Request body for token generation
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// XRPL wallet address
    pub wallet_address: String,
    /// Signature of challenge from an XRPL wallet
    pub signature: String,
    /// The challenge that was signed
    pub challenge: String,
}

/// Node authentication extractor — accepts either Bearer JWT or X-Node-Secret header
///
/// Used for storage node registration and heartbeat endpoints.
/// Storage nodes authenticate with a shared secret instead of user JWTs.
#[derive(Debug, Clone)]
pub struct NodeAuth {
    pub identity: String,
}

/// Header name for node secret
const NODE_SECRET_HEADER: &str = "X-Node-Secret";

#[async_trait]
impl FromRequestParts<AppState> for NodeAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // First, try X-Node-Secret header
        if let Some(secret_header) = parts.headers.get(NODE_SECRET_HEADER) {
            if let Ok(secret) = secret_header.to_str() {
                if let Some(ref expected) = state.config.node_secret {
                    if !expected.is_empty() && secret == expected {
                        return Ok(NodeAuth {
                            identity: "storage-node".to_string(),
                        });
                    }
                }
                tracing::warn!("Invalid storage-node auth credential presented");
                return Err(AuthError::InvalidToken);
            }
        }

        // Fall back to standard Bearer JWT (admin or storage_node role)
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if user.role == "admin" || user.role == "storage_node" {
            Ok(NodeAuth {
                identity: user.wallet_address,
            })
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

/// Response with tokens
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_token_create_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let claims = Claims::new_access("rTestWallet123", 24);

        let token = create_token(&claims, &signing_key);

        // Should have 3 parts
        assert_eq!(token.split('.').count(), 3);

        // Verify should succeed
        let verified = verify_token(&token, &signing_key.verifying_key()).unwrap();
        assert_eq!(verified.sub, "rTestWallet123");
        assert_eq!(verified.typ, "access");
    }

    #[test]
    fn test_expired_token() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut claims = Claims::new_access("rTestWallet123", 24);
        claims.exp = Utc::now().timestamp() - 3600; // Expired 1 hour ago

        let token = create_token(&claims, &signing_key);

        let result = verify_token(&token, &signing_key.verifying_key());
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_invalid_signature() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let signing_key2 = SigningKey::generate(&mut OsRng);

        let claims = Claims::new_access("rTestWallet123", 24);
        let token = create_token(&claims, &signing_key1);

        // Verify with different key should fail
        let result = verify_token(&token, &signing_key2.verifying_key());
        assert!(matches!(result, Err(AuthError::InvalidSignature)));
    }
}
