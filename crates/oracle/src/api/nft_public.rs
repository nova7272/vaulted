//! Public NFT metadata and image endpoints
//!
//! These endpoints are public (no auth) so wallets like Xaman can resolve NFT URIs.
//! No sensitive data is exposed — only generic metadata and deterministic pixel art.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::nft_image;
use crate::services::AppState;

/// GET /nft/{id}/metadata.json
///
/// Returns XLS-24 compatible metadata JSON.
/// ID can be metadata_hash (from URI) or nft_token_id.
/// Public — no auth required, no sensitive data exposed.
pub async fn nft_metadata(
    State(state): State<AppState>,
    Path(nft_id): Path<String>,
) -> Response {
    // Validate ID format (hex string, reasonable length)
    if nft_id.len() < 8 || nft_id.len() > 128 || !nft_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "Invalid NFT ID").into_response();
    }

    // Build image URL
    let image_url = if let Some(ref public_url) = state.config.public_url {
        format!("{}/nft/{}/image.svg", public_url.trim_end_matches('/'), nft_id)
    } else {
        format!("/nft/{}/image.svg", nft_id)
    };

    let metadata = nft_image::generate_nft_metadata(&nft_id, &image_url);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        metadata,
    ).into_response()
}

/// GET /nft/{id}/image.svg
///
/// Returns deterministic pixel-art SVG generated from ID hash.
/// Public — no auth required, fully deterministic (same ID = same image).
pub async fn nft_image_svg(
    Path(nft_id): Path<String>,
) -> Response {
    // Validate ID format
    if nft_id.len() < 8 || nft_id.len() > 128 || !nft_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "Invalid NFT ID").into_response();
    }

    let svg = nft_image::generate_nft_svg(&nft_id);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        svg,
    ).into_response()
}