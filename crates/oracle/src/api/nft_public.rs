//! Public NFT metadata and image endpoints
//!
//! These endpoints are public (no auth) so XRPL wallets can resolve NFT URIs.
//! No sensitive data is exposed — only generic metadata and deterministic pixel art.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use base64::Engine as _;

use crate::nft_image;
use crate::services::AppState;

/// GET /nft/{id}/metadata.json
///
/// Returns XLS-24 compatible metadata JSON.
/// ID can be metadata_hash (from URI) or nft_token_id.
/// Public — no auth required, no sensitive data exposed.
pub async fn nft_metadata(State(state): State<AppState>, Path(nft_id): Path<String>) -> Response {
    // Accept both legacy/public hash IDs and algorithm-prefixed manifest hashes.
    let Some(normalized_id) = normalize_public_nft_id(&nft_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid NFT ID").into_response();
    };

    // Prefer exact client-published metadata when available. This is what the
    // locally signed NFTokenMint URI points to. It keeps Oracle as a durable
    // registry/storage layer rather than a mint authority.
    match sqlx::query_scalar::<_, Option<serde_json::Value>>(
        r#"
        SELECT manifest #> '{public_metadata,metadata_json}'
        FROM nft_metadata
        WHERE metadata_hash = $1
           OR nft_token_id = $1
           OR manifest #>> '{public_metadata,metadata_json,properties,manifest_hash}' = $2
           OR manifest #>> '{public_metadata,metadata_json,properties,manifest_hash}' = $1
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .bind(&normalized_id)
    .bind(&nft_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(Some(metadata))) => {
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                ],
                metadata.to_string(),
            )
                .into_response();
        },
        Ok(_) => {},
        Err(err) => {
            tracing::warn!(
                "Failed to load published NFT metadata for {}: {}",
                nft_id,
                err
            );
        },
    }

    // Fallback: deterministic public metadata generated from id only. This is
    // retained for legacy/unpublished objects and does not expose sensitive data.
    let image_url = if let Some(ref public_url) = state.config.public_url {
        format!(
            "{}/nft/{}/image.svg",
            public_url.trim_end_matches('/'),
            normalized_id
        )
    } else {
        format!("/nft/{}/image.svg", normalized_id)
    };

    let metadata = nft_image::generate_nft_metadata(&normalized_id, &image_url);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        metadata,
    )
        .into_response()
}

/// GET /nft/{id}/image.svg
///
/// Returns deterministic pixel-art SVG generated from ID hash.
/// Public — no auth required, fully deterministic (same ID = same image).
pub async fn nft_image_svg(State(state): State<AppState>, Path(nft_id): Path<String>) -> Response {
    let Some(normalized_id) = normalize_public_nft_id(&nft_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid NFT ID").into_response();
    };

    // If metadata was published with an embedded data:image/svg+xml;base64 image,
    // serve the exact client-generated SVG as a convenience endpoint too.
    if let Ok(Some(Some(image))) = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT manifest #>> '{public_metadata,metadata_json,image}'
        FROM nft_metadata
        WHERE metadata_hash = $1
           OR nft_token_id = $1
           OR manifest #>> '{public_metadata,metadata_json,properties,manifest_hash}' = $2
           OR manifest #>> '{public_metadata,metadata_json,properties,manifest_hash}' = $1
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .bind(&normalized_id)
    .bind(&nft_id)
    .fetch_optional(&state.db)
    .await
    {
        if let Some(svg) = decode_svg_data_uri(&image) {
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "image/svg+xml"),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                ],
                svg,
            )
                .into_response();
        }
    }

    let svg = nft_image::generate_nft_svg(&normalized_id);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        svg,
    )
        .into_response()
}

fn normalize_public_nft_id(id: &str) -> Option<String> {
    let normalized = id.strip_prefix("sha256:").unwrap_or(id);

    if normalized.len() < 8
        || normalized.len() > 128
        || !normalized.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }

    Some(normalized.to_ascii_lowercase())
}

fn decode_svg_data_uri(uri: &str) -> Option<String> {
    let encoded = uri.strip_prefix("data:image/svg+xml;base64,")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()?;
    let svg = String::from_utf8(bytes).ok()?;
    if svg.starts_with("<svg") && svg.contains("</svg>") {
        Some(svg)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn decodes_valid_svg_data_uri() {
        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        let uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(svg.as_bytes())
        );

        assert_eq!(decode_svg_data_uri(&uri).as_deref(), Some(svg));
    }

    #[test]
    fn rejects_non_svg_data_uri() {
        let html = "<html></html>";
        let uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(html.as_bytes())
        );

        assert!(decode_svg_data_uri(&uri).is_none());
    }

    #[test]
    fn normalizes_plain_hex_public_nft_id() {
        assert_eq!(
            normalize_public_nft_id("ABCDEF1234567890").as_deref(),
            Some("abcdef1234567890")
        );
    }

    #[test]
    fn normalizes_sha256_prefixed_public_nft_id() {
        assert_eq!(
            normalize_public_nft_id("sha256:ABCDEF1234567890").as_deref(),
            Some("abcdef1234567890")
        );
    }

    #[test]
    fn rejects_non_hex_public_nft_id() {
        assert!(normalize_public_nft_id("sha256:not-hex").is_none());
        assert!(normalize_public_nft_id("not-hex").is_none());
    }

    #[test]
    fn rejects_wrong_data_uri_prefix() {
        let svg = "<svg></svg>";
        let uri = format!("data:text/plain;base64,{}", STANDARD.encode(svg.as_bytes()));

        assert!(decode_svg_data_uri(&uri).is_none());
    }
}
