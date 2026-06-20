//! NFT endpoints

use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    api::ownership::require_verified_nft_owner,
    error::{ApiError, Result},
    models::FileManifestDto,
    services::AppState,
};

/// NFT metadata
#[derive(serde::Serialize)]
pub struct NftMetadataResponse {
    pub nft_token_id: String,
    pub owner_address: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub manifest: FileManifestDto,
    pub created_at: String,
    pub updated_at: String,
}

/// GET /api/v1/nfts/:nft_token_id/metadata
/// **Requires authentication** - only NFT owner can see encrypted keys (CRIT-03)
pub async fn get_metadata(
    auth: crate::auth::AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<NftMetadataResponse>> {
    require_verified_nft_owner(
        &state,
        &nft_token_id,
        &auth.wallet_address,
        "Only the NFT owner can view full metadata",
    )
    .await?;

    // Get metadata
    let row = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT 
            nm.encrypted_aes_key,
            u.wallet_address,
            nm.created_at::text,
            nm.updated_at::text
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NftNotFound(nft_token_id.clone()))?;

    let (encrypted_aes_key, owner_address, created_at, updated_at) = row;

    // Get the manifest
    let manifest_row = sqlx::query_as::<_, (String, i64, String, String)>(
        r#"
        SELECT fm.encrypted_filename, fm.original_size, fm.mime_type, fm.original_hash
        FROM file_manifests fm
        JOIN nft_metadata nm ON fm.nft_metadata_id = nm.id
        WHERE nm.nft_token_id = $1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_one(&state.db)
    .await?;

    // Get fragments
    let fragments = sqlx::query_as::<_, (i32, i64, String, String, String)>(
        r#"
        SELECT ff.fragment_index, ff.fragment_size, ff.encrypted_hash, ff.storage_node_id, ff.storage_key
        FROM file_fragments ff
        JOIN file_manifests fm ON ff.manifest_id = fm.id
        JOIN nft_metadata nm ON fm.nft_metadata_id = nm.id
        WHERE nm.nft_token_id = $1
        ORDER BY ff.fragment_index
        "#,
    )
    .bind(&nft_token_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(NftMetadataResponse {
        nft_token_id,
        owner_address,
        encrypted_aes_key,
        is_re_encrypted: false, // TODO: Add a flag
        manifest: FileManifestDto {
            encrypted_filename: manifest_row.0,
            original_size: manifest_row.1 as u64,
            mime_type: manifest_row.2,
            original_hash: manifest_row.3,
            fragments: fragments
                .into_iter()
                .map(|(index, size, hash, storage_id, storage_key)| {
                    crate::models::FileFragmentDto {
                        index: index as u32,
                        size: size as u64,
                        encrypted_hash: hash,
                        storage_id,
                        storage_key,
                    }
                })
                .collect(),
        },
        created_at,
        updated_at,
    }))
}

/// Verification result
#[derive(serde::Serialize)]
pub struct VerifyOwnershipResponse {
    pub nft_token_id: String,
    pub owner_address: String,
    pub is_owner: bool,
}

/// GET /api/v1/nfts/:nft_token_id/verify?wallet=rXXX
pub async fn verify_ownership(
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<VerifyParams>,
) -> Result<Json<VerifyOwnershipResponse>> {
    // Get the current owner from the database
    let owner = sqlx::query_scalar::<_, String>(
        r#"
        SELECT u.wallet_address
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NftNotFound(nft_token_id.clone()))?;

    // TODO: Also verify through XRPL
    // state.xrpl.verify_nft_owner(&nft_token_id, &params.wallet).await?

    let is_owner = owner.eq_ignore_ascii_case(&params.wallet);

    Ok(Json(VerifyOwnershipResponse {
        nft_token_id,
        owner_address: owner,
        is_owner,
    }))
}

#[derive(serde::Deserialize)]
pub struct VerifyParams {
    pub wallet: String,
}
