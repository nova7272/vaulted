//! Vault object and signed grant endpoints for the manifest layer.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xrpl_vault_crypto_core::VaultedManifest;

use crate::{
    api::grant_signature::{
        verify_grant_owner_signature, GrantSignatureContext, GRANT_CREATE_ACTION,
    },
    auth::AuthenticatedUser,
    error::{ApiError, Result},
    models::{FileAccessResponse, FileFragmentDto, FileManifestDto, FragmentDownloadInfo},
    services::AppState,
};

/// Register a signed manifest pointer. Oracle acts as index/cache, not source of truth.
#[derive(Debug, Deserialize)]
pub struct RegisterVaultObjectRequest {
    pub id: String,
    pub owner_identity_id: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub nft_chain: Option<String>,
    pub nft_token_id: Option<String>,
    pub manifest: Option<VaultedManifest>,
}

/// Vault object response.
#[derive(Debug, Serialize)]
pub struct VaultObjectResponse {
    pub id: String,
    pub owner_identity_id: String,
    pub manifest_uri: String,
    pub manifest_hash: String,
    pub nft_chain: Option<String>,
    pub nft_token_id: Option<String>,
    pub status: String,
}

/// Signed grant request.
#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub grant_id: Option<Uuid>,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Canonical recipient key envelope. Legacy callers may still send encrypted_file_key.
    #[serde(default)]
    pub key_envelope: Option<serde_json::Value>,
    /// Deprecated compatibility field. Use key_envelope instead.
    #[serde(default)]
    pub encrypted_file_key: Option<String>,
    pub owner_signature: String,
}

/// Incoming grants query.
#[derive(Debug, Deserialize)]
pub struct IncomingGrantsQuery {
    pub identity_id: Option<String>,
}

/// Grant-scoped file access query.
#[derive(Debug, Deserialize)]
pub struct GrantAccessQuery {
    pub identity_id: Option<String>,
}

/// Outgoing grants query.
#[derive(Debug, Deserialize)]
pub struct OutgoingGrantsQuery {
    pub owner_identity_id: Option<String>,
}

/// Revoke grant request.
#[derive(Debug, Deserialize)]
pub struct RevokeGrantRequest {
    pub owner_identity_id: Option<String>,
}

/// Grant response.
#[derive(Debug, Serialize)]
pub struct GrantResponse {
    pub id: Uuid,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: serde_json::Value,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub key_envelope: serde_json::Value,
    /// Deprecated compatibility mirror of key_envelope.encrypted_file_key.
    pub encrypted_file_key: String,
    pub owner_signature: String,
    pub status: String,
}

/// Registers a vault object manifest pointer after optional signature/hash verification.
pub async fn register_vault_object(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<RegisterVaultObjectRequest>,
) -> Result<Json<VaultObjectResponse>> {
    let caller_identity_id = authenticated_identity_for_request(
        &state,
        &auth,
        Some(req.owner_identity_id.as_str()),
        "owner_identity_id",
    )
    .await?;

    if let Some(manifest) = &req.manifest {
        manifest.verify_signature()?;
        let computed = manifest.manifest_hash()?;
        if computed != req.manifest_hash {
            return Err(ApiError::BadRequest(format!(
                "manifest_hash mismatch: request={}, computed={}",
                req.manifest_hash, computed
            )));
        }
        if manifest.vault_object_id != req.id || manifest.owner_identity_id != req.owner_identity_id
        {
            return Err(ApiError::BadRequest(
                "manifest object/owner does not match request".into(),
            ));
        }
    }

    sqlx::query(
        r#"INSERT INTO vault_objects (id, owner_identity_id, manifest_uri, manifest_hash, nft_chain, nft_token_id, status)
           VALUES ($1, $2, $3, $4, $5, $6, 'active')
           ON CONFLICT (id) DO UPDATE SET
             owner_identity_id = EXCLUDED.owner_identity_id,
             manifest_uri = EXCLUDED.manifest_uri,
             manifest_hash = EXCLUDED.manifest_hash,
             nft_chain = EXCLUDED.nft_chain,
             nft_token_id = EXCLUDED.nft_token_id,
             updated_at = now()"#,
    )
    .bind(&req.id)
    .bind(&caller_identity_id)
    .bind(&req.manifest_uri)
    .bind(&req.manifest_hash)
    .bind(&req.nft_chain)
    .bind(&req.nft_token_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to register vault object: {e}")))?;

    Ok(Json(VaultObjectResponse {
        id: req.id,
        owner_identity_id: caller_identity_id,
        manifest_uri: req.manifest_uri,
        manifest_hash: req.manifest_hash,
        nft_chain: req.nft_chain,
        nft_token_id: req.nft_token_id,
        status: "active".into(),
    }))
}

/// Reads the manifest pointer for a vault object.
pub async fn get_vault_object(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<VaultObjectResponse>> {
    let caller_identity_id =
        authenticated_identity_for_request(&state, &auth, None, "identity_id").await?;
    let row = sqlx::query(
        "SELECT id, owner_identity_id, manifest_uri, manifest_hash, nft_chain, nft_token_id, status FROM vault_objects WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("vault object not found: {id}")))?;

    let owner_identity_id: String = row.try_get("owner_identity_id")?;
    authorize_vault_object_access(&state, &id, &owner_identity_id, &caller_identity_id).await?;

    Ok(Json(VaultObjectResponse {
        id: row.try_get("id")?,
        owner_identity_id,
        manifest_uri: row.try_get("manifest_uri")?,
        manifest_hash: row.try_get("manifest_hash")?,
        nft_chain: row.try_get("nft_chain")?,
        nft_token_id: row.try_get("nft_token_id")?,
        status: row.try_get("status")?,
    }))
}

/// Reads the manifest pointer for a vault object by linked NFT token id.
pub async fn get_vault_object_by_nft(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<VaultObjectResponse>> {
    let caller_identity_id =
        authenticated_identity_for_request(&state, &auth, None, "identity_id").await?;
    let row = sqlx::query(
        "SELECT id, owner_identity_id, manifest_uri, manifest_hash, nft_chain, nft_token_id, status FROM vault_objects WHERE nft_token_id = $1 AND status = 'active' ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(&nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("vault object not found for nft: {nft_token_id}")))?;

    let id: String = row.try_get("id")?;
    let owner_identity_id: String = row.try_get("owner_identity_id")?;
    authorize_vault_object_access(&state, &id, &owner_identity_id, &caller_identity_id).await?;

    Ok(Json(VaultObjectResponse {
        id,
        owner_identity_id,
        manifest_uri: row.try_get("manifest_uri")?,
        manifest_hash: row.try_get("manifest_hash")?,
        nft_chain: row.try_get("nft_chain")?,
        nft_token_id: row.try_get("nft_token_id")?,
        status: row.try_get("status")?,
    }))
}

/// Creates a signed read grant. Owner signature is stored and must be verified by clients.
pub async fn create_grant(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(req): Json<CreateGrantRequest>,
) -> Result<Json<GrantResponse>> {
    let caller_identity_id =
        authenticated_identity_for_request(&state, &auth, None, "identity_id").await?;
    let vault_object =
        load_active_vault_object_for_owner(&state, &req.vault_object_id, &caller_identity_id)
            .await?;
    let owner_signing_public_key =
        load_identity_signing_public_key(&state, &caller_identity_id).await?;

    let id = req.grant_id.unwrap_or_else(Uuid::new_v4);
    let permissions = serde_json::to_value(&req.permissions)
        .map_err(|e| ApiError::BadRequest(format!("invalid permissions: {e}")))?;
    if let Some(expires_at) = req.expires_at.as_ref() {
        if *expires_at <= chrono::Utc::now() {
            return Err(ApiError::BadRequest(
                "grant expiration must be in the future".into(),
            ));
        }
    }

    let (key_envelope, encrypted_file_key) = normalize_grant_key_envelope(
        req.key_envelope,
        req.encrypted_file_key,
        &req.recipient_identity_id,
    )?;
    let signature_context = GrantSignatureContext {
        action: GRANT_CREATE_ACTION,
        grant_id: &id,
        vault_object_id: &req.vault_object_id,
        nft_token_id: vault_object.nft_token_id.as_deref(),
        owner_identity_id: &caller_identity_id,
        recipient_identity_id: &req.recipient_identity_id,
        permissions: &permissions,
        expires_at: req.expires_at.as_ref(),
        key_envelope: &key_envelope,
    };
    verify_grant_owner_signature(
        &owner_signing_public_key,
        &signature_context,
        &req.owner_signature,
    )?;

    sqlx::query(
        r#"INSERT INTO grants (id, vault_object_id, recipient_identity_id, encrypted_file_key, key_envelope, key_envelope_version, permissions, expires_at, owner_signature, status)
           VALUES ($1, $2, $3, $4, $5, 'vaulted-key-envelope-v1', $6, $7, $8, 'active')
           ON CONFLICT (id) DO UPDATE SET
             encrypted_file_key = EXCLUDED.encrypted_file_key,
             key_envelope = EXCLUDED.key_envelope,
             key_envelope_version = EXCLUDED.key_envelope_version,
             permissions = EXCLUDED.permissions,
             expires_at = EXCLUDED.expires_at,
             owner_signature = EXCLUDED.owner_signature,
             status = 'active'"#,
    )
    .bind(id)
    .bind(&req.vault_object_id)
    .bind(&req.recipient_identity_id)
    .bind(&encrypted_file_key)
    .bind(&key_envelope)
    .bind(&permissions)
    .bind(req.expires_at)
    .bind(&req.owner_signature)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to create grant: {e}")))?;

    Ok(Json(GrantResponse {
        id,
        vault_object_id: req.vault_object_id,
        recipient_identity_id: req.recipient_identity_id,
        permissions,
        expires_at: req.expires_at,
        key_envelope,
        encrypted_file_key,
        owner_signature: req.owner_signature,
        status: "active".into(),
    }))
}

/// Lists incoming active grants for a recipient identity.
pub async fn incoming_grants(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(q): Query<IncomingGrantsQuery>,
) -> Result<Json<Vec<GrantResponse>>> {
    let caller_identity_id =
        authenticated_identity_for_request(&state, &auth, q.identity_id.as_deref(), "identity_id")
            .await?;
    let rows = sqlx::query(
        r#"SELECT id, vault_object_id, recipient_identity_id, permissions, expires_at, encrypted_file_key,
                  COALESCE(key_envelope, jsonb_build_object(
                      'protocol', 'vaulted-key-envelope-v1',
                      'alg', 'legacy-pre-aes-key',
                      'recipient_type', 'grant-recipient',
                      'recipient_identity_id', recipient_identity_id,
                      'encrypted_file_key', encrypted_file_key
                  )) AS key_envelope,
                  owner_signature, status
           FROM grants
           WHERE recipient_identity_id = $1
             AND status = 'active'
             AND (expires_at IS NULL OR expires_at > now())
           ORDER BY created_at DESC"#,
    )
    .bind(&caller_identity_id)
    .fetch_all(&state.db)
    .await?;

    let grants = rows
        .into_iter()
        .map(|row| -> std::result::Result<GrantResponse, sqlx::Error> {
            Ok(GrantResponse {
                id: row.try_get("id")?,
                vault_object_id: row.try_get("vault_object_id")?,
                recipient_identity_id: row.try_get("recipient_identity_id")?,
                permissions: row.try_get("permissions")?,
                expires_at: row.try_get("expires_at")?,
                key_envelope: row.try_get("key_envelope")?,
                encrypted_file_key: row.try_get("encrypted_file_key")?,
                owner_signature: row.try_get("owner_signature")?,
                status: row.try_get("status")?,
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(Json(grants))
}

/// Lists active outgoing grants owned by an identity.
pub async fn outgoing_grants(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(q): Query<OutgoingGrantsQuery>,
) -> Result<Json<Vec<GrantResponse>>> {
    let caller_identity_id = authenticated_identity_for_request(
        &state,
        &auth,
        q.owner_identity_id.as_deref(),
        "owner_identity_id",
    )
    .await?;
    let rows = sqlx::query(
        r#"SELECT g.id, g.vault_object_id, g.recipient_identity_id, g.permissions, g.expires_at, g.encrypted_file_key,
                  COALESCE(g.key_envelope, jsonb_build_object(
                      'protocol', 'vaulted-key-envelope-v1',
                      'alg', 'legacy-pre-aes-key',
                      'recipient_type', 'grant-recipient',
                      'recipient_identity_id', g.recipient_identity_id,
                      'encrypted_file_key', g.encrypted_file_key
                  )) AS key_envelope,
                  g.owner_signature, g.status
           FROM grants g
           JOIN vault_objects vo ON vo.id = g.vault_object_id
           WHERE vo.owner_identity_id = $1
             AND g.status = 'active'
             AND (g.expires_at IS NULL OR g.expires_at > now())
           ORDER BY g.created_at DESC"#,
    )
    .bind(&caller_identity_id)
    .fetch_all(&state.db)
    .await?;

    let grants = rows
        .into_iter()
        .map(|row| -> std::result::Result<GrantResponse, sqlx::Error> {
            Ok(GrantResponse {
                id: row.try_get("id")?,
                vault_object_id: row.try_get("vault_object_id")?,
                recipient_identity_id: row.try_get("recipient_identity_id")?,
                permissions: row.try_get("permissions")?,
                expires_at: row.try_get("expires_at")?,
                key_envelope: row.try_get("key_envelope")?,
                encrypted_file_key: row.try_get("encrypted_file_key")?,
                owner_signature: row.try_get("owner_signature")?,
                status: row.try_get("status")?,
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(Json(grants))
}

/// Revokes an active grant. Revocation is enforced by incoming list/access endpoints.
pub async fn revoke_grant(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(grant_id): Path<Uuid>,
    Json(req): Json<RevokeGrantRequest>,
) -> Result<Json<GrantResponse>> {
    let caller_identity_id = authenticated_identity_for_request(
        &state,
        &auth,
        req.owner_identity_id.as_deref(),
        "owner_identity_id",
    )
    .await?;
    let row = sqlx::query(
        r#"UPDATE grants g
           SET status = 'revoked'
           FROM vault_objects vo
           WHERE g.id = $1
             AND g.vault_object_id = vo.id
             AND vo.owner_identity_id = $2
             AND g.status = 'active'
           RETURNING g.id, g.vault_object_id, g.recipient_identity_id, g.permissions, g.expires_at,
                     g.encrypted_file_key,
                     COALESCE(g.key_envelope, jsonb_build_object(
                         'protocol', 'vaulted-key-envelope-v1',
                         'alg', 'legacy-pre-aes-key',
                         'recipient_type', 'grant-recipient',
                         'recipient_identity_id', g.recipient_identity_id,
                         'encrypted_file_key', g.encrypted_file_key
                     )) AS key_envelope,
                     g.owner_signature, g.status"#,
    )
    .bind(grant_id)
    .bind(&caller_identity_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("active grant not found for owner: {grant_id}")))?;

    let grant = GrantResponse {
        id: row.try_get("id")?,
        vault_object_id: row.try_get("vault_object_id")?,
        recipient_identity_id: row.try_get("recipient_identity_id")?,
        permissions: row.try_get("permissions")?,
        expires_at: row.try_get("expires_at")?,
        key_envelope: row.try_get("key_envelope")?,
        encrypted_file_key: row.try_get("encrypted_file_key")?,
        owner_signature: row.try_get("owner_signature")?,
        status: row.try_get("status")?,
    };

    state
        .audit_log(
            None,
            "grant_revoked",
            None,
            Some(serde_json::json!({
                "grant_id": grant_id,
                "owner_identity_id": caller_identity_id,
                "vault_object_id": grant.vault_object_id,
                "recipient_identity_id": grant.recipient_identity_id,
            })),
        )
        .await;

    Ok(Json(grant))
}

/// Returns encrypted file metadata and fragment URLs for an active recipient grant.
///
/// This intentionally does not return the owner's PRE-wrapped file key. The recipient
/// must unwrap the grant's KeyEnvelope locally with their Vaulted identity private key.
pub async fn grant_file_access(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(grant_id): Path<Uuid>,
    Query(q): Query<GrantAccessQuery>,
) -> Result<Json<FileAccessResponse>> {
    let caller_identity_id =
        authenticated_identity_for_request(&state, &auth, q.identity_id.as_deref(), "identity_id")
            .await?;
    let row = sqlx::query(
        r#"SELECT g.recipient_identity_id,
                  g.encrypted_file_key,
                  COALESCE(g.key_envelope, jsonb_build_object(
                      'protocol', 'vaulted-key-envelope-v1',
                      'alg', 'legacy-pre-aes-key',
                      'recipient_type', 'grant-recipient',
                      'recipient_identity_id', g.recipient_identity_id,
                      'encrypted_file_key', g.encrypted_file_key
                  )) AS key_envelope,
                  vo.nft_token_id,
                  COALESCE(nm.manifest, '{}'::jsonb) AS manifest
           FROM grants g
           JOIN vault_objects vo ON vo.id = g.vault_object_id
           JOIN nft_metadata nm ON nm.nft_token_id = vo.nft_token_id
           WHERE g.id = $1
             AND g.status = 'active'
             AND (g.expires_at IS NULL OR g.expires_at > now())
             AND vo.status = 'active'
             AND nm.status IN ('active', 'pending_claim')"#,
    )
    .bind(grant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("active grant not found: {grant_id}")))?;

    let recipient_identity_id: String = row.try_get("recipient_identity_id")?;
    if recipient_identity_id != caller_identity_id {
        return Err(ApiError::Forbidden(
            "grant recipient identity mismatch".into(),
        ));
    }

    let nft_token_id: String = row
        .try_get::<Option<String>, _>("nft_token_id")?
        .ok_or_else(|| ApiError::NotFound("grant vault object is not linked to an NFT".into()))?;
    let manifest_json: serde_json::Value = row.try_get("manifest")?;
    let encrypted_file_key: String = row.try_get("encrypted_file_key")?;

    let encrypted_filename = manifest_json["encrypted_filename"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let original_size = manifest_json["original_size"].as_u64().unwrap_or(0);
    let mime_type = manifest_json["mime_type"]
        .as_str()
        .unwrap_or("application/octet-stream")
        .to_string();
    let original_hash = manifest_json["original_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let node_endpoints: std::collections::HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT id, endpoint_url FROM storage_nodes")
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();

    let mut fragment_urls = Vec::new();
    let mut fragment_dtos = Vec::new();
    if let Some(fragments) = manifest_json["fragments"].as_array() {
        for frag in fragments {
            let index = frag["index"].as_u64().unwrap_or(0) as u32;
            let size = frag["size"].as_u64().unwrap_or(0);
            let encrypted_hash = frag["encrypted_hash"].as_str().unwrap_or("").to_string();
            let storage_node_id = frag["storage_node_id"].as_str().unwrap_or("").to_string();
            let storage_key = frag["storage_key"].as_str().unwrap_or("").to_string();
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

    state
        .audit_log(
            None,
            "grant_file_access_requested",
            Some(&nft_token_id),
            Some(serde_json::json!({
                "grant_id": grant_id,
                "recipient_identity_id": recipient_identity_id,
                "fragments_count": fragment_urls.len(),
            })),
        )
        .await;

    Ok(Json(FileAccessResponse {
        nft_token_id,
        encrypted_aes_key: encrypted_file_key,
        is_re_encrypted: false,
        manifest: FileManifestDto {
            encrypted_filename,
            original_size,
            mime_type,
            original_hash,
            fragments: fragment_dtos,
        },
        fragment_urls,
        created_at: None,
        pre_key_mismatch: None,
        pre_key_owner: None,
        onchain_owner: None,
    }))
}

async fn authenticated_identity_for_request(
    state: &AppState,
    auth: &AuthenticatedUser,
    requested_identity_id: Option<&str>,
    field_name: &str,
) -> Result<String> {
    let requested = requested_identity_id
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if let Some(identity_id) = requested {
        if identity_id == auth.wallet_address {
            return Ok(identity_id.to_string());
        }

        if is_canonical_vaulted_identity_id(&auth.wallet_address) {
            return Err(ApiError::Forbidden(format!(
                "{field_name} does not match authenticated identity"
            )));
        }

        let linked = sqlx::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM linked_wallets lw
                   JOIN vaulted_identities vi ON vi.id = lw.identity_id
                   WHERE lw.identity_id = $1
                     AND lw.chain = 'xrpl'
                     AND lw.address = $2
                     AND lw.revoked_at IS NULL
                     AND vi.status = 'active'
               )"#,
        )
        .bind(identity_id)
        .bind(&auth.wallet_address)
        .fetch_one(&state.db)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to verify linked identity: {e}")))?;

        if linked {
            return Ok(identity_id.to_string());
        }

        return Err(ApiError::Forbidden(format!(
            "{field_name} does not match authenticated identity"
        )));
    }

    if is_canonical_vaulted_identity_id(&auth.wallet_address) {
        return Ok(auth.wallet_address.clone());
    }

    let rows = sqlx::query_scalar::<_, String>(
        r#"SELECT vi.id
           FROM linked_wallets lw
           JOIN vaulted_identities vi ON vi.id = lw.identity_id
           WHERE lw.chain = 'xrpl'
             AND lw.address = $1
             AND lw.revoked_at IS NULL
             AND vi.status = 'active'
           ORDER BY lw.created_at DESC
           LIMIT 2"#,
    )
    .bind(&auth.wallet_address)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to resolve authenticated identity: {e}")))?;

    match rows.as_slice() {
        [identity_id] => Ok(identity_id.clone()),
        [] => Err(ApiError::Forbidden(
            "authenticated subject is not linked to a Vaulted identity".into(),
        )),
        _ => Err(ApiError::Forbidden(
            "authenticated subject is linked to multiple Vaulted identities".into(),
        )),
    }
}

struct ActiveVaultObject {
    nft_token_id: Option<String>,
}

async fn load_active_vault_object_for_owner(
    state: &AppState,
    vault_object_id: &str,
    caller_identity_id: &str,
) -> Result<ActiveVaultObject> {
    let row = sqlx::query(
        "SELECT owner_identity_id, nft_token_id FROM vault_objects WHERE id = $1 AND status = 'active'",
    )
    .bind(vault_object_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("vault object not found: {vault_object_id}")))?;

    let owner_identity_id: String = row.try_get("owner_identity_id")?;
    if owner_identity_id != caller_identity_id {
        return Err(ApiError::Forbidden(
            "vault object owner identity mismatch".into(),
        ));
    }

    Ok(ActiveVaultObject {
        nft_token_id: row.try_get("nft_token_id")?,
    })
}

async fn load_identity_signing_public_key(state: &AppState, identity_id: &str) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT signing_public_key FROM vaulted_identities WHERE id = $1 AND status = 'active'",
    )
    .bind(identity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Database(format!("Failed to load owner identity: {e}")))?
    .ok_or_else(|| ApiError::Unauthorized("Unknown Vaulted owner identity".into()))
}

async fn authorize_vault_object_access(
    state: &AppState,
    vault_object_id: &str,
    owner_identity_id: &str,
    caller_identity_id: &str,
) -> Result<()> {
    if owner_identity_id == caller_identity_id {
        return Ok(());
    }

    let has_active_grant = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
               SELECT 1
               FROM grants
               WHERE vault_object_id = $1
                 AND recipient_identity_id = $2
                 AND status = 'active'
                 AND (expires_at IS NULL OR expires_at > now())
           )"#,
    )
    .bind(vault_object_id)
    .bind(caller_identity_id)
    .fetch_one(&state.db)
    .await?;

    if has_active_grant {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "authenticated identity cannot access vault object".into(),
        ))
    }
}

fn is_canonical_vaulted_identity_id(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn normalize_grant_key_envelope(
    key_envelope: Option<serde_json::Value>,
    encrypted_file_key: Option<String>,
    recipient_identity_id: &str,
) -> Result<(serde_json::Value, String)> {
    if let Some(value) = key_envelope {
        if !value.is_object() {
            return Err(ApiError::BadRequest(
                "key_envelope must be a JSON object".into(),
            ));
        }
        validate_recipient_key_envelope(&value, recipient_identity_id)?;
        let encrypted = value
            .get("encrypted_file_key")
            .or_else(|| value.get("encryptedFileKey"))
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest("key_envelope.encrypted_file_key is required".into())
            })?
            .to_string();
        return Ok((value, encrypted));
    }

    let encrypted = encrypted_file_key
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::BadRequest("key_envelope is required".into()))?;
    let envelope = serde_json::json!({
        "protocol": "vaulted-key-envelope-v1",
        "alg": "legacy-pre-aes-key",
        "recipient_type": "grant-recipient",
        "recipient_identity_id": recipient_identity_id,
        "encrypted_file_key": encrypted,
    });
    Ok((envelope, encrypted))
}

fn validate_recipient_key_envelope(
    value: &serde_json::Value,
    recipient_identity_id: &str,
) -> Result<()> {
    let envelope_recipient = value
        .get("recipient_identity_id")
        .or_else(|| value.get("recipientIdentityId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::BadRequest("key envelope recipient_identity_id is required".into())
        })?;
    if envelope_recipient != recipient_identity_id {
        return Err(ApiError::BadRequest(
            "key envelope recipient_identity_id mismatch".into(),
        ));
    }

    let alg = value
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("key envelope alg is required".into()))?;
    if alg == "X25519-HKDF-SHA256-XCHACHA20POLY1305" {
        for field in [
            "recipient_public_key_id",
            "ephemeral_public_key",
            "nonce",
            "encrypted_file_key",
        ] {
            let present = value
                .get(field)
                .or_else(|| match field {
                    "recipient_public_key_id" => value.get("recipientPublicKeyId"),
                    "ephemeral_public_key" => value.get("ephemeralPublicKey"),
                    "encrypted_file_key" => value.get("encryptedFileKey"),
                    _ => None,
                })
                .and_then(|v| v.as_str())
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !present {
                return Err(ApiError::BadRequest(format!(
                    "key envelope {field} is required"
                )));
            }
        }
    }
    Ok(())
}

use sqlx::Row;
