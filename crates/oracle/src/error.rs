//! Oracle API error types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// API operation result
pub type Result<T> = std::result::Result<T, ApiError>;

/// API errors
#[derive(Error, Debug)]
pub enum ApiError {
    /// Unauthorized
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Conflict
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Too many requests
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// File too large
    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    /// Cryptography error
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// PRE error
    #[error("PRE error: {0}")]
    PreError(String),

    /// XRPL error
    #[error("XRPL error: {0}")]
    Xrpl(String),

    /// NFT not found
    #[error("NFT not found: {0}")]
    NftNotFound(String),

    /// User is not the NFT owner
    #[error("Not NFT owner")]
    NotNftOwner,

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Storage node error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    // === Transfer-related errors ===
    /// Transfer not found
    #[error("Transfer not found: {0}")]
    TransferNotFound(uuid::Uuid),

    /// Transfer already exists for this NFT
    #[error("Active transfer already exists for this NFT")]
    TransferAlreadyExists,

    /// Invalid transfer status
    #[error("Invalid transfer status: expected {expected}, got {actual}")]
    InvalidTransferStatus { expected: String, actual: String },

    /// Not authorized for this operation
    #[error("Unauthorized for this transfer operation")]
    TransferUnauthorized,
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound("Resource not found".to_string()),
            _ => ApiError::Database(e.to_string()),
        }
    }
}

impl From<xrpl_vault_crypto_core::CryptoError> for ApiError {
    fn from(e: xrpl_vault_crypto_core::CryptoError) -> Self {
        ApiError::Crypto(e.to_string())
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        ApiError::Storage(e.to_string())
    }
}

/// Error response
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            ApiError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "Too many requests".to_string(),
            ),
            ApiError::FileTooLarge { size, max } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "file_too_large",
                format!("File size {} exceeds maximum {}", size, max),
            ),
            ApiError::Crypto(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "crypto_error",
                msg.clone(),
            ),
            ApiError::PreError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "pre_error", msg.clone())
            },
            ApiError::Xrpl(msg) => (StatusCode::BAD_GATEWAY, "xrpl_error", msg.clone()),
            ApiError::NftNotFound(id) => (
                StatusCode::NOT_FOUND,
                "nft_not_found",
                format!("NFT {} not found", id),
            ),
            ApiError::NotNftOwner => (
                StatusCode::FORBIDDEN,
                "not_nft_owner",
                "You are not the owner of this NFT".to_string(),
            ),
            ApiError::Database(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                msg.clone(),
            ),
            ApiError::Storage(msg) => (StatusCode::BAD_GATEWAY, "storage_error", msg.clone()),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                msg.clone(),
            ),
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, "validation_error", msg.clone()),
            // Transfer errors
            ApiError::TransferNotFound(id) => (
                StatusCode::NOT_FOUND,
                "transfer_not_found",
                format!("Transfer {} not found", id),
            ),
            ApiError::TransferAlreadyExists => (
                StatusCode::CONFLICT,
                "transfer_already_exists",
                "Active transfer already exists for this NFT".to_string(),
            ),
            ApiError::InvalidTransferStatus { expected, actual } => (
                StatusCode::BAD_REQUEST,
                "invalid_transfer_status",
                format!("Expected status '{}', got '{}'", expected, actual),
            ),
            ApiError::TransferUnauthorized => (
                StatusCode::FORBIDDEN,
                "transfer_unauthorized",
                "Unauthorized for this transfer operation".to_string(),
            ),
        };

        let body = Json(ErrorResponse {
            error: error_type.to_string(),
            message,
            details: None,
        });

        (status, body).into_response()
    }
}
