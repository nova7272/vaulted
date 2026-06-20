//! File Proxy API
//!
//! Oracle acts as a proxy for uploading and downloading encrypted files.
//! Handles replication to multiple storage nodes.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    api::ownership::require_verified_nft_owner,
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    services::{AppState, ReplicationService},
    storage_token::{sign_storage_token, StorageToken},
};

// ==================== Types ====================

#[derive(Debug, Deserialize)]
pub struct UploadFileQuery {
    /// NFT Token ID
    pub nft_token_id: String,
}

#[derive(Debug, Serialize)]
pub struct UploadFileResponse {
    pub nft_token_id: String,
    pub size: u64,
    pub replicas: Vec<ReplicaInfo>,
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct ReplicaInfo {
    pub node_id: String,
    pub region: String,
    pub status: String,
}

fn classify_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_status() {
        "status"
    } else {
        "unknown"
    }
}

fn storage_node_scope(node_id: &str) -> &str {
    if node_id.is_empty() {
        "node-local-1"
    } else {
        node_id
    }
}

fn sha256_fragment_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

// ==================== Handlers ====================

/// POST /api/v1/files/upload?nft_token_id=...
///
/// Upload an encrypted file. Oracle will replicate it to multiple storage nodes.
/// Body contains the raw encrypted file bytes.
///
/// **Requires authentication** - must be NFT owner
pub async fn upload_file(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(params): Query<UploadFileQuery>,
    body: Bytes,
) -> Result<Json<UploadFileResponse>> {
    let file_size = body.len() as i64;

    tracing::info!(
        "Uploading file for NFT {}: {} bytes",
        params.nft_token_id,
        file_size
    );

    // Verify NFT exists and user is owner
    let nft_owner: Option<(uuid::Uuid, String)> = sqlx::query_as(
        r#"
        SELECT nm.id, u.wallet_address
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1
        "#,
    )
    .bind(&params.nft_token_id)
    .fetch_optional(&state.db)
    .await?;

    match nft_owner {
        None => {
            return Err(ApiError::NotFound(format!(
                "NFT not found: {}",
                params.nft_token_id
            )));
        },
        Some((_, owner_wallet)) => {
            if !auth.wallet_address.eq_ignore_ascii_case(&owner_wallet) {
                return Err(ApiError::Forbidden(
                    "Only the NFT owner can upload files".into(),
                ));
            }
        },
    }

    // Get replication settings and select nodes
    let replication_service = ReplicationService::new(state.db.clone());
    let settings = replication_service
        .get_settings()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let nodes = replication_service
        .select_nodes_for_upload(file_size, None)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    if nodes.is_empty() {
        return Err(ApiError::Storage(
            "No active storage nodes available".to_string(),
        ));
    }

    tracing::info!(
        "Selected {} nodes for replication (factor={}): {:?}",
        nodes.len(),
        settings.replication_factor,
        nodes.iter().map(|n| &n.id).collect::<Vec<_>>()
    );

    // Upload to each selected node
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let mut replicas = Vec::new();
    let mut successful_uploads = 0;
    let storage_key = format!("file_{}", params.nft_token_id);
    let mut successful_fragment_infos: Vec<serde_json::Value> = Vec::new();
    let encrypted_hash = sha256_fragment_hash(&body);

    for (replica_idx, node) in nodes.iter().enumerate() {
        let node_storage_key = format!("{}_r{}", storage_key, replica_idx);
        let upload_url = {
            let token = StorageToken::new_scoped(
                &params.nft_token_id,
                &node_storage_key,
                "write",
                10,
                Some(&node.id),
                Some(&encrypted_hash),
            );
            let signed = sign_storage_token(&token, &state.signing_key);
            format!(
                "{}/fragments/{}?token={}&fragment_hash={}",
                node.endpoint_url, node_storage_key, signed, encrypted_hash
            )
        };

        tracing::debug!(
            storage_node_id = %node.id,
            nft_token_id = %params.nft_token_id,
            "Uploading encrypted file fragment to storage node"
        );

        let upload_result = client.put(&upload_url).body(body.clone()).send().await;

        let status = match upload_result {
            Ok(resp) if resp.status().is_success() => {
                successful_uploads += 1;

                // Track for manifest update
                successful_fragment_infos.push(serde_json::json!({
                    "index": replica_idx,
                    "storage_node_id": node.id,
                    "storage_key": node_storage_key,
                    "encrypted_hash": encrypted_hash.clone(),
                    "size": file_size
                }));

                // Record replica in DB
                sqlx::query(
                    r#"
                    INSERT INTO file_replicas (nft_token_id, storage_node_id, storage_key, size_bytes, status)
                    VALUES ($1, $2, $3, $4, 'active')
                    ON CONFLICT (nft_token_id, storage_node_id) DO UPDATE SET
                        storage_key = EXCLUDED.storage_key,
                        size_bytes = EXCLUDED.size_bytes,
                        status = 'active',
                        updated_at = NOW()
                    "#
                )
                    .bind(&params.nft_token_id)
                    .bind(&node.id)
                    .bind(&node_storage_key)
                    .bind(file_size)
                    .execute(&state.db)
                    .await
                    .ok();

                // Update storage node used space
                sqlx::query(
                    "UPDATE storage_nodes SET used_space_bytes = used_space_bytes + $1 WHERE id = $2"
                )
                    .bind(file_size)
                    .bind(&node.id)
                    .execute(&state.db)
                    .await
                    .ok();

                "active".to_string()
            },
            Ok(resp) => {
                tracing::warn!(
                    operation = "upload",
                    storage_node_id = %node.id,
                    nft_token_id = %params.nft_token_id,
                    endpoint_status = resp.status().as_u16(),
                    bytes = file_size,
                    "Upload to storage node returned non-success"
                );
                "failed".to_string()
            },
            Err(e) => {
                tracing::warn!(
                    operation = "upload",
                    storage_node_id = %node.id,
                    nft_token_id = %params.nft_token_id,
                    error_class = classify_reqwest_error(&e),
                    bytes = file_size,
                    "Upload to storage node failed"
                );
                "failed".to_string()
            },
        };

        replicas.push(ReplicaInfo {
            node_id: node.id.clone(),
            region: node.region.clone(),
            status,
        });
    }

    // Need at least one successful upload
    if successful_uploads == 0 {
        return Err(ApiError::Storage(
            "Failed to upload to any storage node".to_string(),
        ));
    }

    // Update NFT metadata with file info and actual storage locations
    let fragments_json = serde_json::Value::Array(successful_fragment_infos);
    sqlx::query(
        r#"
        UPDATE nft_metadata
        SET manifest = jsonb_set(
            jsonb_set(
                COALESCE(manifest, '{}'::jsonb),
                '{file_size}',
                to_jsonb($1::bigint)
            ),
            '{fragments}',
            $3::jsonb
        ),
        updated_at = NOW()
        WHERE nft_token_id = $2
        "#,
    )
    .bind(file_size)
    .bind(&params.nft_token_id)
    .bind(&fragments_json)
    .execute(&state.db)
    .await?;

    tracing::info!(
        "File uploaded for NFT {}: {}/{} replicas successful",
        params.nft_token_id,
        successful_uploads,
        replicas.len()
    );

    Ok(Json(UploadFileResponse {
        nft_token_id: params.nft_token_id,
        size: file_size as u64,
        replicas,
        success: true,
    }))
}

/// GET /api/v1/files/:nft_token_id/download
///
/// Download an encrypted file. Oracle fetches from an available storage node.
/// **Requires authentication** - must be NFT owner (CRIT-03)
pub async fn download_file(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Response> {
    tracing::debug!("Downloading file for NFT: {}", nft_token_id);

    require_verified_nft_owner(
        &state,
        &nft_token_id,
        &auth.wallet_address,
        "Only the NFT owner can download this file",
    )
    .await?;

    // Get active replicas for this file
    let mut replicas: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT fr.storage_node_id, fr.storage_key, sn.endpoint_url
        FROM file_replicas fr
        JOIN storage_nodes sn ON sn.id = fr.storage_node_id
        WHERE fr.nft_token_id = $1
          AND fr.status = 'active'
          AND sn.status = 'active'
        ORDER BY sn.health_check_failures ASC, sn.used_space_bytes ASC
        "#,
    )
    .bind(&nft_token_id)
    .fetch_all(&state.db)
    .await?;

    // Fallback: if file_replicas is empty, try reading fragment info from nft_metadata.manifest
    if replicas.is_empty() {
        tracing::warn!(
            "No file_replicas for NFT {}, trying manifest fragments fallback",
            nft_token_id
        );

        let manifest_opt: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT COALESCE(manifest, '{}'::jsonb) FROM nft_metadata WHERE nft_token_id = $1",
        )
        .bind(&nft_token_id)
        .fetch_optional(&state.db)
        .await?;

        if let Some(manifest) = manifest_opt {
            if let Some(fragments) = manifest.get("fragments").and_then(|f| f.as_array()) {
                // PERF FIX: Preload all node endpoints in one query
                let node_endpoints: std::collections::HashMap<String, String> =
                    sqlx::query_as::<_, (String, String)>(
                        "SELECT id, endpoint_url FROM storage_nodes",
                    )
                    .fetch_all(&state.db)
                    .await?
                    .into_iter()
                    .collect();

                for frag in fragments {
                    let storage_key = frag["storage_key"].as_str().unwrap_or("").to_string();
                    let storage_node_id =
                        frag["storage_node_id"].as_str().unwrap_or("").to_string();
                    if storage_key.is_empty() {
                        continue;
                    }
                    let endpoint = if storage_node_id.is_empty() {
                        "http://localhost:9001".to_string()
                    } else {
                        node_endpoints
                            .get(&storage_node_id)
                            .cloned()
                            .unwrap_or_else(|| "http://localhost:9001".to_string())
                    };
                    replicas.push((storage_node_id, storage_key, endpoint));
                }
            }
        }
    }

    if replicas.is_empty() {
        return Err(ApiError::NotFound(format!(
            "No file found for NFT: {}",
            nft_token_id
        )));
    }

    // Try each replica until one succeeds
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    for (node_id, storage_key, endpoint_url) in &replicas {
        let url = {
            let token = StorageToken::new_scoped(
                &nft_token_id,
                storage_key,
                "read",
                10,
                Some(storage_node_scope(node_id)),
                None,
            );
            let signed = sign_storage_token(&token, &state.signing_key);
            format!(
                "{}/fragments/{}?token={}",
                endpoint_url, storage_key, signed
            )
        };
        tracing::debug!(
            storage_node_id = %node_id,
            nft_token_id = %nft_token_id,
            "Trying storage node for encrypted file download"
        );

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| ApiError::Storage(format!("Failed to read response: {}", e)))?;

                tracing::info!(
                    "Downloaded file for NFT {} from node {}: {} bytes",
                    nft_token_id,
                    node_id,
                    bytes.len()
                );

                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    bytes,
                )
                    .into_response());
            },
            Ok(resp) => {
                let status = resp.status();
                tracing::warn!(
                    storage_node_id = %node_id,
                    nft_token_id = %nft_token_id,
                    endpoint_status = status.as_u16(),
                    "Storage node returned non-success for encrypted file download"
                );
                // If storage node says fragment not found, mark replica as missing
                if status == StatusCode::NOT_FOUND {
                    tracing::warn!(
                        storage_node_id = %node_id,
                        nft_token_id = %nft_token_id,
                        "Encrypted file fragment missing from storage node, marking replica as stale"
                    );
                    sqlx::query(
                        "UPDATE file_replicas SET status = 'missing' WHERE nft_token_id = $1 AND storage_node_id = $2"
                    )
                        .bind(&nft_token_id)
                        .bind(node_id)
                        .execute(&state.db)
                        .await
                        .ok();
                }
            },
            Err(e) => {
                tracing::warn!(
                    operation = "download",
                    storage_node_id = %node_id,
                    nft_token_id = %nft_token_id,
                    error_class = classify_reqwest_error(&e),
                    "Failed to fetch encrypted file fragment from storage node"
                );
            },
        }
    }

    Err(ApiError::Storage(format!(
        "File fragment missing from all storage nodes for NFT {}. The encrypted data may need to be re-uploaded.",
        nft_token_id
    )))
}

/// DELETE /api/v1/files/:nft_token_id/storage
///
/// Delete file from all storage nodes (called when NFT is burned)
///
/// **Requires authentication** - must be NFT owner
pub async fn delete_file_storage(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<DeleteFileResponse>> {
    tracing::info!("Deleting file storage for NFT: {}", nft_token_id);

    require_verified_nft_owner(
        &state,
        &nft_token_id,
        &auth.wallet_address,
        "Only the NFT owner can delete files",
    )
    .await?;

    // Get all replicas
    let replicas: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT fr.storage_node_id, fr.storage_key, sn.endpoint_url
        FROM file_replicas fr
        JOIN storage_nodes sn ON sn.id = fr.storage_node_id
        WHERE fr.nft_token_id = $1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_all(&state.db)
    .await?;

    if replicas.is_empty() {
        return Ok(Json(DeleteFileResponse {
            nft_token_id,
            deleted_replicas: 0,
            success: true,
        }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let mut deleted_count = 0;

    for (node_id, storage_key, endpoint_url) in &replicas {
        let url = {
            let token = StorageToken::new_scoped(
                &nft_token_id,
                storage_key,
                "delete",
                10,
                Some(storage_node_scope(node_id)),
                None,
            );
            let signed = sign_storage_token(&token, &state.signing_key);
            format!(
                "{}/fragments/{}?token={}",
                endpoint_url, storage_key, signed
            )
        };

        match client.delete(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND => {
                deleted_count += 1;
                tracing::debug!(
                    storage_node_id = %node_id,
                    nft_token_id = %nft_token_id,
                    "Deleted encrypted file fragment from storage node"
                );
            },
            Ok(resp) => {
                tracing::warn!(
                    operation = "delete",
                    storage_node_id = %node_id,
                    nft_token_id = %nft_token_id,
                    endpoint_status = resp.status().as_u16(),
                    "Delete from storage node returned non-success"
                );
            },
            Err(e) => {
                tracing::warn!(
                    operation = "delete",
                    storage_node_id = %node_id,
                    nft_token_id = %nft_token_id,
                    error_class = classify_reqwest_error(&e),
                    "Failed to delete from storage node"
                );
            },
        }
    }

    // Remove replica records from DB
    sqlx::query("DELETE FROM file_replicas WHERE nft_token_id = $1")
        .bind(&nft_token_id)
        .execute(&state.db)
        .await?;

    tracing::info!(
        "Deleted {} replicas for NFT {}",
        deleted_count,
        nft_token_id
    );

    Ok(Json(DeleteFileResponse {
        nft_token_id,
        deleted_replicas: deleted_count,
        success: true,
    }))
}

#[derive(Debug, Serialize)]
pub struct DeleteFileResponse {
    pub nft_token_id: String,
    pub deleted_replicas: u32,
    pub success: bool,
}

/// GET /api/v1/files/:nft_token_id/status
///
/// Get file storage status (replicas info)
/// **Requires authentication**
pub async fn get_file_status(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<FileStatusResponse>> {
    let replicas: Vec<(String, String, i64, String)> = sqlx::query_as(
        r#"
        SELECT fr.storage_node_id, sn.region, fr.size_bytes, fr.status
        FROM file_replicas fr
        JOIN storage_nodes sn ON sn.id = fr.storage_node_id
        WHERE fr.nft_token_id = $1
        "#,
    )
    .bind(&nft_token_id)
    .fetch_all(&state.db)
    .await?;

    let replication_service = ReplicationService::new(state.db.clone());
    let settings = replication_service
        .get_settings()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let active_count = replicas.iter().filter(|(_, _, _, s)| s == "active").count();
    let total_size = replicas.first().map(|(_, _, size, _)| *size).unwrap_or(0);

    Ok(Json(FileStatusResponse {
        nft_token_id,
        size_bytes: total_size,
        replicas: replicas
            .into_iter()
            .map(|(node_id, region, _, status)| ReplicaInfo {
                node_id,
                region,
                status,
            })
            .collect(),
        active_replicas: active_count,
        target_replicas: settings.replication_factor as usize,
        healthy: active_count >= settings.min_active_replicas as usize,
    }))
}

#[derive(Debug, Serialize)]
pub struct FileStatusResponse {
    pub nft_token_id: String,
    pub size_bytes: i64,
    pub replicas: Vec<ReplicaInfo>,
    pub active_replicas: usize,
    pub target_replicas: usize,
    pub healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::classify_reqwest_error;

    fn assert_safe_error_class(label: &str) {
        const ALLOWED: &[&str] = &[
            "timeout", "connect", "request", "body", "decode", "status", "unknown",
        ];

        assert!(ALLOWED.contains(&label));
        assert!(!label.contains("token="));
        assert!(!label.contains("/fragments/"));
        assert!(!label.contains("file_nft_r0"));
    }

    #[tokio::test]
    async fn classify_reqwest_error_returns_only_safe_labels() {
        let error = reqwest::Client::new()
            .get("http://127.0.0.1:9/fragments/file_nft_r0?token=secret")
            .send()
            .await
            .expect_err("unused local port should fail");

        let label = classify_reqwest_error(&error);
        assert_safe_error_class(label);
    }
}
