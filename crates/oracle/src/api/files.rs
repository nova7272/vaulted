//! File endpoints

use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    api::ownership::require_verified_nft_owner,
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    models::{
        ConfirmUploadRequest, FileAccessResponse, FileFragmentDto, FileListItemDto,
        FileListManifestDto, FileListResponse, FileManifestDto, FragmentDownloadInfo,
        FragmentUploadRequest, FragmentUploadResponse, RegisterFileRequest, RegisterFileResponse,
    },
    services::AppState,
};

const LIST_MY_FILES_ENCRYPTED_SQL: &str = r#"
            SELECT nm.nft_token_id,
                   nm.encrypted_aes_key,
                   COALESCE(nm.is_re_encrypted, false),
                   nm.status,
                   vault_decrypt(nm.encrypted_manifest, $2),
                   nm.manifest,
                   nm.created_at
            FROM nft_metadata nm
            JOIN users u ON nm.owner_id = u.id
            WHERE lower(u.wallet_address) = lower($1)
              AND nm.status IN ('active', 'pending_claim')
            ORDER BY nm.created_at DESC
            "#;

const LIST_MY_FILES_PLAIN_SQL: &str = r#"
            SELECT nm.nft_token_id,
                   nm.encrypted_aes_key,
                   COALESCE(nm.is_re_encrypted, false),
                   nm.status,
                   NULL::text,
                   nm.manifest,
                   nm.created_at
            FROM nft_metadata nm
            JOIN users u ON nm.owner_id = u.id
            WHERE lower(u.wallet_address) = lower($1)
              AND nm.status IN ('active', 'pending_claim')
            ORDER BY nm.created_at DESC
            "#;

/// POST /api/v1/files/register - register a file
/// **Requires authentication**
pub async fn register_file(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<RegisterFileRequest>,
) -> Result<Json<RegisterFileResponse>> {
    // Validate the NFT Token ID
    if request.nft_token_id.len() != 64
        || !request.nft_token_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ApiError::Validation("Invalid NFT Token ID".to_string()));
    }

    // Get the user by NFT (through XRPL verification)
    // TODO: Implement real verification through XRPL
    // Use a placeholder for now

    // Check whether this NFT is already registered
    let existing =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM nft_metadata WHERE nft_token_id = $1")
            .bind(&request.nft_token_id)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Err(ApiError::Conflict(format!(
            "NFT {} already registered",
            request.nft_token_id
        )));
    }

    // Get owner_id from authenticated user (CRIT-04: was using SELECT LIMIT 1)
    let owner_id =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE wallet_address = $1")
            .bind(&auth.wallet_address)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound("Authenticated user not found in database".to_string())
            })?;

    // Start a transaction
    let mut tx = state.db.begin().await?;

    // Create the NFT metadata record
    let nft_metadata_id = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        INSERT INTO nft_metadata (nft_token_id, owner_id, encrypted_aes_key, metadata_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(&request.nft_token_id)
    .bind(owner_id)
    .bind(&request.encrypted_aes_key)
    .bind(&request.metadata_hash)
    .fetch_one(&mut *tx)
    .await?;

    // Create the manifest
    let manifest_id = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        INSERT INTO file_manifests (nft_metadata_id, encrypted_filename, original_size, mime_type, original_hash, fragment_count)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
        .bind(nft_metadata_id)
        .bind(&request.manifest.encrypted_filename)
        .bind(request.manifest.original_size as i64)
        .bind(&request.manifest.mime_type)
        .bind(&request.manifest.original_hash)
        .bind(request.manifest.fragments.len() as i32)
        .fetch_one(&mut *tx)
        .await?;

    // Create fragment records (without storage info for now)
    for fragment in &request.manifest.fragments {
        sqlx::query(
            r#"
            INSERT INTO file_fragments (manifest_id, fragment_index, fragment_size, encrypted_hash, storage_node_id, storage_key)
            VALUES ($1, $2, $3, $4, '', '')
            "#,
        )
            .bind(manifest_id)
            .bind(fragment.index as i32)
            .bind(fragment.size as i64)
            .bind(&fragment.encrypted_hash)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    tracing::info!(
        "Registered file for NFT {}: {} fragments",
        request.nft_token_id,
        request.manifest.fragments.len()
    );

    Ok(Json(RegisterFileResponse {
        file_id: manifest_id,
        nft_token_id: request.nft_token_id,
        fragments_count: request.manifest.fragments.len() as u32,
    }))
}

/// GET /api/v1/files - list encrypted files owned by the authenticated user
/// **Requires authentication**
pub async fn list_my_files(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<FileListResponse>> {
    let rows = if let Some(ref enc_key) = state.config.db_encryption_key {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                bool,
                String,
                Option<String>,
                Option<serde_json::Value>,
                chrono::DateTime<chrono::Utc>,
            ),
        >(LIST_MY_FILES_ENCRYPTED_SQL)
        .bind(&auth.wallet_address)
        .bind(enc_key)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                bool,
                String,
                Option<String>,
                Option<serde_json::Value>,
                chrono::DateTime<chrono::Utc>,
            ),
        >(LIST_MY_FILES_PLAIN_SQL)
        .bind(&auth.wallet_address)
        .fetch_all(&state.db)
        .await?
    };

    let files = rows
        .into_iter()
        .map(
            |(
                nft_token_id,
                encrypted_aes_key,
                is_re_encrypted,
                status,
                encrypted_manifest,
                plain_manifest,
                created_at,
            )| {
                let manifest_json = manifest_json_from_parts(encrypted_manifest, plain_manifest)?;

                Ok(FileListItemDto {
                    nft_token_id,
                    encrypted_aes_key,
                    is_re_encrypted,
                    status,
                    manifest: file_list_manifest_from_json(&manifest_json),
                    created_at: created_at.to_rfc3339(),
                })
            },
        )
        .collect::<Result<Vec<_>>>()?;

    tracing::debug!(
        files_count = files.len(),
        "Listed owned encrypted file metadata"
    );

    Ok(Json(FileListResponse { files }))
}

/// GET /api/v1/files/:nft_token_id/access - request file access
/// **Requires authentication** - verifies NFT ownership (CRIT-03)
pub async fn request_access(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<FileAccessResponse>> {
    let nft_owner_wallet = require_verified_nft_owner(
        &state,
        &nft_token_id,
        &auth.wallet_address,
        "Only the NFT owner can access this file",
    )
    .await?;

    // Get NFT metadata including the manifest (encrypted or plain)
    let manifest_json: serde_json::Value = if let Some(ref enc_key) = state.config.db_encryption_key
    {
        // Try encrypted manifest first
        let row = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<serde_json::Value>,
                bool,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            r#"
            SELECT encrypted_aes_key,
                   vault_decrypt(encrypted_manifest, $2),
                   manifest,
                   COALESCE(is_re_encrypted, false),
                   created_at
            FROM nft_metadata
            WHERE nft_token_id = $1 AND status IN ('active', 'pending_claim')
            "#,
        )
        .bind(&nft_token_id)
        .bind(enc_key)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NftNotFound(nft_token_id.clone()))?;

        let (enc_key_val, decrypted_manifest_str, plain_manifest, is_re_enc, created) = row;
        // Use decrypted manifest if available, otherwise fall back to plain
        let manifest = if let Some(ref decrypted) = decrypted_manifest_str {
            serde_json::from_str(decrypted)
                .unwrap_or_else(|_| plain_manifest.unwrap_or(serde_json::json!({})))
        } else {
            plain_manifest.unwrap_or(serde_json::json!({}))
        };

        // Store these for later use
        // (We need to break out some variables for the rest of the function)
        let _ = (enc_key_val, is_re_enc, created); // Used below via separate query
        manifest
    } else {
        serde_json::json!({}) // Will be overwritten below
    };

    // Unified query that works for both paths
    let nft_meta = sqlx::query_as::<
        _,
        (
            String,
            serde_json::Value,
            bool,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        r#"
        SELECT encrypted_aes_key,
               COALESCE(manifest, '{}'::jsonb),
               COALESCE(is_re_encrypted, false),
               created_at
        FROM nft_metadata
        WHERE nft_token_id = $1 AND status IN ('active', 'pending_claim')
        "#,
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NftNotFound(nft_token_id.clone()))?;

    let (encrypted_aes_key, plain_manifest_json, is_re_encrypted, created_at) = nft_meta;

    // Use decrypted manifest if encryption was active, otherwise plain
    let final_manifest =
        if state.config.db_encryption_key.is_some() && manifest_json != serde_json::json!({}) {
            manifest_json
        } else {
            plain_manifest_json
        };

    // Parse the manifest from JSON
    let encrypted_filename = final_manifest["encrypted_filename"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let original_size = final_manifest["original_size"].as_u64().unwrap_or(0);
    let mime_type = final_manifest["mime_type"]
        .as_str()
        .unwrap_or("application/octet-stream")
        .to_string();
    let original_hash = final_manifest["original_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Get fragments from JSON
    let fragments_json = final_manifest["fragments"].as_array();

    let mut fragment_urls = Vec::new();
    let mut fragment_dtos = Vec::new();

    if let Some(fragments) = fragments_json {
        // PERF FIX: Preload all storage node endpoints in a single query
        // instead of querying per-fragment in a loop (was O(N) queries, now O(1))
        let node_endpoints: std::collections::HashMap<String, String> =
            sqlx::query_as::<_, (String, String)>("SELECT id, endpoint_url FROM storage_nodes")
                .fetch_all(&state.db)
                .await?
                .into_iter()
                .collect();

        for frag in fragments {
            let index = frag["index"].as_u64().unwrap_or(0) as u32;
            let size = frag["size"].as_u64().unwrap_or(0);
            let encrypted_hash = frag["encrypted_hash"].as_str().unwrap_or("").to_string();
            let storage_node_id = frag["storage_node_id"].as_str().unwrap_or("").to_string();
            let storage_key = frag["storage_key"].as_str().unwrap_or("").to_string();

            // Lookup endpoint from preloaded map (O(1) per fragment)
            let endpoint = if storage_node_id.is_empty() {
                "http://localhost:9001".to_string()
            } else {
                node_endpoints
                    .get(&storage_node_id)
                    .cloned()
                    .unwrap_or_else(|| "http://localhost:9001".to_string())
            };

            fragment_urls.push(FragmentDownloadInfo {
                index,
                url: format!("{}/fragments/{}", endpoint, storage_key),
                size,
                hash: encrypted_hash.clone(),
            });

            fragment_dtos.push(FileFragmentDto {
                index,
                size,
                encrypted_hash,
                storage_id: storage_node_id,
                storage_key,
            });
        }
    }

    // Audit file access
    state
        .audit_log(
            None,
            "file_access_requested",
            Some(&nft_token_id),
            Some(serde_json::json!({
                "fragments_count": fragment_urls.len(),
                "original_size": original_size,
            })),
        )
        .await;

    // PRE key mismatch detection:
    // If the current owner received this NFT without going through
    // the in-app transfer flow (re-encryption), they can't decrypt the file.
    // This happens when NFT is transferred via DEX, direct XRPL offer, etc.
    let (pre_key_mismatch, pre_key_owner_addr, onchain_owner_addr) = {
        let db_owner = nft_owner_wallet.clone();

        // Check: was there a finalized transfer_request where current owner is to_user?
        // If yes → re-encryption happened, keys match
        // If no, and there was a previous owner → external transfer, keys DON'T match
        let nft_meta_id = sqlx::query_scalar::<_, uuid::Uuid>(
            "SELECT id FROM nft_metadata WHERE nft_token_id = $1",
        )
        .bind(&nft_token_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let has_proper_transfer = if let Some(meta_id) = nft_meta_id {
            // Check if current owner received via in-app transfer
            let current_owner_id = sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT owner_id FROM nft_metadata WHERE id = $1",
            )
            .bind(meta_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

            if let Some(owner_id) = current_owner_id {
                sqlx::query_scalar::<_, bool>(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM transfer_requests
                        WHERE nft_metadata_id = $1
                          AND to_user_id = $2
                          AND status IN ('finalized', 'completed')
                    )
                    "#,
                )
                .bind(meta_id)
                .bind(owner_id)
                .fetch_one(&state.db)
                .await
                .unwrap_or(true) // Assume ok if query fails
            } else {
                true // No owner = original creator, keys match
            }
        } else {
            true
        };

        // Original creator always has matching keys
        let is_original_creator = if let Some(meta_id) = nft_meta_id {
            sqlx::query_scalar::<_, bool>(
                r#"
                SELECT NOT EXISTS(
                    SELECT 1 FROM transfer_requests WHERE nft_metadata_id = $1
                )
                "#,
            )
            .bind(meta_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(true)
        } else {
            true
        };

        let mismatch = !is_original_creator && !has_proper_transfer;
        if mismatch {
            tracing::warn!(
                "PRE key mismatch for NFT {}: owner {} received NFT outside the app",
                nft_token_id,
                db_owner
            );
        }

        (Some(mismatch), Some(db_owner), None::<String>)
    };

    Ok(Json(FileAccessResponse {
        nft_token_id,
        encrypted_aes_key,
        is_re_encrypted,
        manifest: FileManifestDto {
            encrypted_filename,
            original_size,
            mime_type,
            original_hash,
            fragments: fragment_dtos,
        },
        fragment_urls,
        created_at: Some(created_at.to_rfc3339()),
        pre_key_mismatch,
        pre_key_owner: pre_key_owner_addr,
        onchain_owner: onchain_owner_addr,
    }))
}

fn manifest_json_from_parts(
    encrypted_manifest: Option<String>,
    plain_manifest: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    if let Some(manifest) = encrypted_manifest {
        serde_json::from_str(&manifest)
            .map_err(|e| ApiError::Internal(format!("Failed to parse encrypted manifest: {e}")))
    } else {
        Ok(plain_manifest.unwrap_or_else(|| serde_json::json!({})))
    }
}

fn file_list_manifest_from_json(manifest: &serde_json::Value) -> FileListManifestDto {
    FileListManifestDto {
        encrypted_filename: manifest["encrypted_filename"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        original_size: manifest["original_size"].as_u64().unwrap_or(0),
        mime_type: manifest["mime_type"]
            .as_str()
            .unwrap_or("application/octet-stream")
            .to_string(),
        original_hash: manifest["original_hash"].as_str().unwrap_or("").to_string(),
    }
}

pub async fn get_upload_url(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<FragmentUploadRequest>,
) -> Result<Json<FragmentUploadResponse>> {
    // Select the storage node with the lowest load
    let storage_node = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT id, endpoint_url
        FROM storage_nodes
        WHERE status IN ('active', 'pending_claim')
        ORDER BY (used_space_bytes::float / NULLIF(total_space_bytes, 0)) ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Storage("No active storage nodes".to_string()))?;

    let (storage_node_id, endpoint_url) = storage_node;

    // Generate a unique storage key
    let storage_key = format!(
        "{}/{}/{}",
        request.file_id,
        request.fragment_index,
        uuid::Uuid::new_v4()
    );

    // Build the upload URL
    let upload_url = format!("{}/upload/{}", endpoint_url, storage_key);

    Ok(Json(FragmentUploadResponse {
        upload_url,
        storage_node_id,
        storage_key,
    }))
}

/// POST /api/v1/files/fragments/confirm - confirm upload
/// **Requires authentication**
pub async fn confirm_upload(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<ConfirmUploadRequest>,
) -> Result<Json<()>> {
    // Update fragment information
    let updated = sqlx::query(
        r#"
        UPDATE file_fragments
        SET storage_node_id = $1, storage_key = $2, replication_count = 1
        WHERE manifest_id = $3 AND fragment_index = $4
        "#,
    )
    .bind(&request.storage_node_id)
    .bind(&request.storage_key)
    .bind(request.file_id)
    .bind(request.fragment_index as i32)
    .execute(&state.db)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound("Fragment not found".to_string()));
    }

    // Update storage node statistics
    // TODO: Get the real fragment size
    sqlx::query(
        r#"
        UPDATE storage_nodes
        SET used_space_bytes = used_space_bytes + 1048576
        WHERE id = $1
        "#,
    )
    .bind(&request.storage_node_id)
    .execute(&state.db)
    .await?;

    tracing::debug!(
        "Confirmed upload: file={}, fragment={}",
        request.file_id,
        request.fragment_index
    );

    Ok(Json(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_list_manifest_projects_only_safe_list_fields() {
        let manifest = serde_json::json!({
            "encrypted_filename": "ciphertext-name",
            "original_size": 42,
            "mime_type": "application/x-password",
            "original_hash": "hash",
            "fragments": [
                {
                    "storage_key": "storage/path",
                    "encrypted_hash": "fragment-hash",
                    "size": 100
                }
            ]
        });

        let projected = file_list_manifest_from_json(&manifest);

        assert_eq!(projected.encrypted_filename, "ciphertext-name");
        assert_eq!(projected.original_size, 42);
        assert_eq!(projected.mime_type, "application/x-password");
        assert_eq!(projected.original_hash, "hash");
    }

    #[test]
    fn encrypted_manifest_takes_precedence_for_list_projection() {
        let manifest = manifest_json_from_parts(
            Some(r#"{"encrypted_filename":"enc","original_size":7}"#.to_string()),
            Some(serde_json::json!({"encrypted_filename":"plain","original_size":1})),
        )
        .expect("encrypted manifest JSON should parse");

        assert_eq!(manifest["encrypted_filename"], "enc");
        assert_eq!(manifest["original_size"], 7);
    }

    #[test]
    fn file_list_query_filters_to_authenticated_owner_and_pending_or_active() {
        for sql in [LIST_MY_FILES_ENCRYPTED_SQL, LIST_MY_FILES_PLAIN_SQL] {
            assert!(sql.contains("JOIN users u ON nm.owner_id = u.id"));
            assert!(sql.contains("lower(u.wallet_address) = lower($1)"));
            assert!(sql.contains("nm.status IN ('active', 'pending_claim')"));
        }
    }
}
