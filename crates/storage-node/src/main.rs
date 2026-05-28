//! XRPL Vault Storage Node
//!
//! Service for storing and serving encrypted file fragments.
//! Supports self-registration with Oracle, periodic heartbeat,
//! and token-based authentication for fragment access.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, put},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ==================== Types ====================

/// Application state
struct AppState {
    node_id: String,
    storage_dir: PathBuf,
    oracle_url: Option<String>,
    region: String,
    /// Oracle's public key for verifying tokens
    oracle_public_key: Option<VerifyingKey>,
    /// Whether to require token authentication
    require_auth: bool,
    /// In-memory index of stored fragments
    fragments: RwLock<HashMap<String, FragmentInfo>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct FragmentInfo {
    key: String,
    size: u64,
    created_at: String,
    encrypted_hash: Option<String>,
}

/// Storage access token payload (must match Oracle's StorageToken)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageToken {
    nft_token_id: String,
    storage_key: String,
    operation: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize)]
struct TokenQuery {
    token: Option<String>,
    /// Optional declared encrypted fragment hash (sha256:... or blake3:...).
    fragment_hash: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    node_id: String,
    fragments_count: usize,
    used_space_bytes: u64,
    auth_enabled: bool,
}

#[derive(Serialize)]
struct UploadResponse {
    key: String,
    size: u64,
    node_id: String,
    encrypted_hash: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct RegisterRequest {
    node_id: String,
    endpoint_url: String,
    region: String,
    total_space_bytes: i64,
}

#[derive(Serialize)]
struct HeartbeatRequest {
    node_id: String,
    fragments_count: i64,
    used_space_bytes: i64,
    total_space_bytes: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "storage_node=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from environment
    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-local-1".to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "9001".to_string())
        .parse()
        .unwrap_or(9001);
    let storage_dir = PathBuf::from(
        std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./data/fragments".to_string()),
    );
    let oracle_url = std::env::var("ORACLE_URL").ok();
    let region = std::env::var("REGION").unwrap_or_else(|_| "local".to_string());
    let public_url =
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| format!("http://localhost:{}", port));

    // Load Oracle public key for token verification
    let mut oracle_public_key = load_oracle_public_key();
    let require_auth = std::env::var("REQUIRE_AUTH")
        .map(|v| v == "false" || v == "0")
        .map(|is_false| !is_false)
        .unwrap_or(true); // HIGH-01: Default to TRUE (was false)

    // If ORACLE_PUBLIC_KEY not set but ORACLE_URL is available, fetch it automatically
    if oracle_public_key.is_none() {
        if let Some(ref oracle) = oracle_url {
            tracing::info!(
                "ORACLE_PUBLIC_KEY not set, fetching from Oracle at {}",
                oracle
            );
            match fetch_oracle_public_key(oracle).await {
                Ok(key) => {
                    tracing::info!("Successfully fetched Oracle public key");
                    oracle_public_key = Some(key);
                },
                Err(e) => {
                    tracing::warn!("Failed to fetch Oracle public key: {}", e);
                },
            }
        }
    }

    // Max fragment size (MED-05)
    let max_fragment_size: usize = std::env::var("MAX_FRAGMENT_SIZE")
        .unwrap_or_else(|_| "104857600".to_string()) // 100MB
        .parse()
        .unwrap_or(104857600);

    // Shared secret for Oracle authentication
    let node_secret: Option<String> = std::env::var("NODE_SECRET").ok();

    // Create storage directory
    fs::create_dir_all(&storage_dir).await?;

    tracing::info!("Starting storage node {} on port {}", node_id, port);
    tracing::info!("Storage directory: {:?}", storage_dir);
    tracing::info!("Region: {}", region);
    tracing::info!("Auth required: {}", require_auth);
    if oracle_public_key.is_some() {
        tracing::info!("Oracle public key loaded - token verification enabled");
    } else if require_auth {
        tracing::warn!("⚠️  REQUIRE_AUTH=true but ORACLE_PUBLIC_KEY not set!");
    }

    // Load existing fragments
    let fragments = load_existing_fragments(&storage_dir).await?;
    let fragments_count = fragments.len();

    let state = Arc::new(AppState {
        node_id: node_id.clone(),
        storage_dir: storage_dir.clone(),
        oracle_url: oracle_url.clone(),
        region: region.clone(),
        oracle_public_key,
        require_auth,
        fragments: RwLock::new(fragments),
    });

    tracing::info!("Loaded {} existing fragments", fragments_count);

    // Register with Oracle if configured
    if let Some(ref oracle) = oracle_url {
        let register_state = state.clone();
        let oracle_clone = oracle.clone();
        let public_url_clone = public_url.clone();
        let node_secret_clone = node_secret.clone();

        tokio::spawn(async move {
            // Wait a bit for server to start
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if let Err(e) = register_with_oracle(
                &oracle_clone,
                &register_state.node_id,
                &public_url_clone,
                &register_state.region,
                &node_secret_clone,
            )
            .await
            {
                tracing::error!("Failed to register with Oracle: {}", e);
            }
        });

        // Start heartbeat loop
        let heartbeat_state = state.clone();
        let oracle_clone = oracle.clone();
        let node_secret_clone = node_secret.clone();

        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(30);
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                let fragments = heartbeat_state.fragments.read().await;
                let fragments_count = fragments.len() as i64;
                let used_space: u64 = fragments.values().map(|f| f.size).sum();
                drop(fragments);

                if let Err(e) = send_heartbeat(
                    &oracle_clone,
                    &heartbeat_state.node_id,
                    fragments_count,
                    used_space as i64,
                    &node_secret_clone,
                )
                .await
                {
                    tracing::warn!("Heartbeat failed: {}", e);
                }
            }
        });
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/fragments/:key", get(get_fragment))
        .route("/fragments/:key", put(put_fragment))
        .route("/fragments/:key", delete(delete_fragment))
        .route("/stats", get(stats))
        .layer(TraceLayer::new_for_http())
        .layer(axum::extract::DefaultBodyLimit::max(max_fragment_size)) // MED-05: body size limit
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("Storage node {} listening on http://{}", node_id, addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Register with Oracle
async fn register_with_oracle(
    oracle_url: &str,
    node_id: &str,
    public_url: &str,
    region: &str,
    node_secret: &Option<String>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/storage/register", oracle_url);

    let request = RegisterRequest {
        node_id: node_id.to_string(),
        endpoint_url: public_url.to_string(),
        region: region.to_string(),
        total_space_bytes: 107_374_182_400, // 100GB default
    };

    let mut req_builder = client.post(&url).json(&request);
    if let Some(ref secret) = node_secret {
        req_builder = req_builder.header("X-Node-Secret", secret);
    }

    let response = req_builder.send().await?;

    if response.status().is_success() {
        tracing::info!("Registered with Oracle at {}", oracle_url);
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Oracle registration failed: {} - {}", status, body);
    }

    Ok(())
}

/// Send heartbeat to Oracle
async fn send_heartbeat(
    oracle_url: &str,
    node_id: &str,
    fragments_count: i64,
    used_space_bytes: i64,
    node_secret: &Option<String>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let url = format!("{}/api/v1/storage/heartbeat", oracle_url);

    let request = HeartbeatRequest {
        node_id: node_id.to_string(),
        fragments_count,
        used_space_bytes,
        total_space_bytes: 107_374_182_400,
    };

    let mut req_builder = client.post(&url).json(&request);
    if let Some(ref secret) = node_secret {
        req_builder = req_builder.header("X-Node-Secret", secret);
    }

    let response = req_builder.send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Heartbeat returned {}", response.status());
    }

    tracing::debug!(
        "Heartbeat sent: {} fragments, {} bytes",
        fragments_count,
        used_space_bytes
    );
    Ok(())
}

/// Load existing fragments from disk
async fn load_existing_fragments(
    storage_dir: &PathBuf,
) -> anyhow::Result<HashMap<String, FragmentInfo>> {
    let mut fragments = HashMap::new();

    let mut entries = fs::read_dir(storage_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(key) = path.file_name().and_then(|n| n.to_str()) {
                let metadata = fs::metadata(&path).await?;
                fragments.insert(
                    key.to_string(),
                    FragmentInfo {
                        key: key.to_string(),
                        size: metadata.len(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        encrypted_hash: None,
                    },
                );
            }
        }
    }

    Ok(fragments)
}

/// Health check endpoint
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let fragments = state.fragments.read().await;
    let used_space: u64 = fragments.values().map(|f| f.size).sum();

    Json(HealthResponse {
        status: "healthy".to_string(),
        node_id: state.node_id.clone(),
        fragments_count: fragments.len(),
        used_space_bytes: used_space,
        auth_enabled: state.require_auth,
    })
}

/// Stats endpoint
async fn stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let fragments = state.fragments.read().await;
    let used_space: u64 = fragments.values().map(|f| f.size).sum();

    Json(serde_json::json!({
        "node_id": state.node_id,
        "region": state.region,
        "fragments_count": fragments.len(),
        "used_space_bytes": used_space,
        "oracle_connected": state.oracle_url.is_some(),
        "auth_enabled": state.require_auth,
    }))
}

/// Validate storage key to prevent path traversal (HIGH-02)
fn validate_storage_key(key: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Block path traversal characters
    if key.contains("..") || key.contains('/') || key.contains('\\') || key.contains('\0') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid fragment key: path traversal characters not allowed".to_string(),
            }),
        ));
    }
    // Key must be non-empty and reasonable length
    if key.is_empty() || key.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid fragment key length".to_string(),
            }),
        ));
    }
    Ok(())
}

/// Get a fragment by key (with token verification)
async fn get_fragment(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(params): Query<TokenQuery>,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    // Path traversal protection (HIGH-02)
    validate_storage_key(&key)?;
    // Verify token if required
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "read")?;
    }

    let path = state.storage_dir.join(&key);

    // Second defense: verify canonical path stays within storage_dir (HIGH-02)
    let canonical_storage = state
        .storage_dir
        .canonicalize()
        .unwrap_or_else(|_| state.storage_dir.clone());
    if let Ok(canonical_path) = path.canonicalize() {
        if !canonical_path.starts_with(&canonical_storage) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Access denied: path outside storage directory".to_string(),
                }),
            ));
        }
    }

    match fs::read(&path).await {
        Ok(data) => {
            tracing::debug!(
                storage_key_hash = %safe_storage_key_label(&key),
                bytes = data.len(),
                "Serving encrypted fragment"
            );
            Ok(data)
        },
        Err(_) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Fragment not found".to_string(),
            }),
        )),
    }
}

/// Store a fragment (with token verification)
async fn put_fragment(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(params): Query<TokenQuery>,
    body: Bytes,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Path traversal protection (HIGH-02)
    validate_storage_key(&key)?;
    // Verify token if required
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "write")?;
    }

    let path = state.storage_dir.join(&key);
    let size = body.len() as u64;
    let computed_hash = format!("sha256:{}", sha256_hex(&body));

    if let Some(ref declared_hash) = params.fragment_hash {
        if !fragment_hash_matches(declared_hash, &body) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Fragment hash mismatch: declared {declared_hash}, computed {computed_hash}"),
                }),
            ));
        }
    }

    // Second defense: verify path stays within storage_dir (HIGH-02)
    let canonical_storage = state
        .storage_dir
        .canonicalize()
        .unwrap_or_else(|_| state.storage_dir.clone());
    if let Some(parent) = path.parent() {
        let canonical_parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if !canonical_parent.starts_with(&canonical_storage) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Access denied: path outside storage directory".to_string(),
                }),
            ));
        }
    }

    match fs::write(&path, &body).await {
        Ok(_) => {
            // Update index
            let mut fragments = state.fragments.write().await;
            fragments.insert(
                key.clone(),
                FragmentInfo {
                    key: key.clone(),
                    size,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    encrypted_hash: params
                        .fragment_hash
                        .clone()
                        .or_else(|| Some(computed_hash.clone())),
                },
            );

            tracing::info!(
                storage_key_hash = %safe_storage_key_label(&key),
                bytes = size,
                "Stored encrypted fragment"
            );

            Ok(Json(UploadResponse {
                key,
                size,
                node_id: state.node_id.clone(),
                encrypted_hash: params.fragment_hash.unwrap_or(computed_hash),
            }))
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to store fragment: {}", e),
            }),
        )),
    }
}

/// Delete a fragment (with token verification)
async fn delete_fragment(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(params): Query<TokenQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Path traversal protection (HIGH-02)
    validate_storage_key(&key)?;
    // Verify token if required
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "delete")?;
    }

    let path = state.storage_dir.join(&key);

    match fs::remove_file(&path).await {
        Ok(_) => {
            // Update index
            let mut fragments = state.fragments.write().await;
            fragments.remove(&key);

            tracing::info!(
                storage_key_hash = %safe_storage_key_label(&key),
                "Deleted encrypted fragment"
            );
            Ok(StatusCode::NO_CONTENT)
        },
        Err(_) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Fragment not found".to_string(),
            }),
        )),
    }
}

// ==================== Token Verification ====================

/// Load Oracle public key from environment
fn load_oracle_public_key() -> Option<VerifyingKey> {
    let key_hex = std::env::var("ORACLE_PUBLIC_KEY").ok()?;

    let key_bytes = match hex_decode(&key_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::error!("Failed to decode ORACLE_PUBLIC_KEY as hex");
            return None;
        },
    };

    if key_bytes.len() != 32 {
        tracing::error!("ORACLE_PUBLIC_KEY must be 32 bytes (64 hex chars)");
        return None;
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);

    match VerifyingKey::from_bytes(&arr) {
        Ok(key) => Some(key),
        Err(e) => {
            tracing::error!("Failed to parse ORACLE_PUBLIC_KEY: {}", e);
            None
        },
    }
}

/// Fetch Oracle's public key from its /public-key endpoint
async fn fetch_oracle_public_key(oracle_url: &str) -> anyhow::Result<VerifyingKey> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let url = format!("{}/public-key", oracle_url);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Oracle returned {}", response.status());
    }

    let body: serde_json::Value = response.json().await?;
    let key_hex = body["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing public_key field in response"))?;

    let key_bytes =
        hex_decode(key_hex).map_err(|_| anyhow::anyhow!("Failed to decode public key hex"))?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Public key must be 32 bytes, got {}", key_bytes.len());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);

    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))
}

/// Verify a storage token for the given operation
fn verify_token_for_operation(
    state: &AppState,
    token: &Option<String>,
    storage_key: &str,
    operation: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let token_str = token.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token parameter".to_string(),
            }),
        )
    })?;

    let verifying_key = state.oracle_public_key.as_ref().ok_or_else(|| {
        tracing::error!("Token verification required but ORACLE_PUBLIC_KEY not configured");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Server misconfigured: missing Oracle public key".to_string(),
            }),
        )
    })?;

    // Parse token (format: payload_b64.signature_b64)
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 2 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token format".to_string(),
            }),
        ));
    }

    let payload_b64 = parts[0];
    let signature_b64 = parts[1];

    // Verify signature
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token signature encoding".to_string(),
            }),
        )
    })?;

    if signature_bytes.len() != 64 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid signature length".to_string(),
            }),
        ));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| {
            tracing::warn!(
                storage_key_hash = %safe_storage_key_label(storage_key),
                "Invalid token signature for storage key"
            );
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid token signature".to_string(),
                }),
            )
        })?;

    // Decode and validate payload
    let payload_json = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token payload encoding".to_string(),
            }),
        )
    })?;

    let token: StorageToken = serde_json::from_slice(&payload_json).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token payload".to_string(),
            }),
        )
    })?;

    // Check expiration
    let now = chrono::Utc::now().timestamp();
    if now > token.exp {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Token expired".to_string(),
            }),
        ));
    }

    // Check storage key matches
    if token.storage_key != storage_key {
        tracing::warn!(
            expected_storage_key_hash = %safe_storage_key_label(storage_key),
            token_storage_key_hash = %safe_storage_key_label(&token.storage_key),
            "Token storage key mismatch"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Token not valid for this fragment".to_string(),
            }),
        ));
    }

    // Check operation matches
    if token.operation != operation {
        tracing::warn!(
            "Token operation mismatch: expected {}, got {}",
            operation,
            token.operation
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Token not valid for {} operation", operation),
            }),
        ));
    }

    tracing::debug!(
        operation,
        storage_key_hash = %safe_storage_key_label(storage_key),
        "Token verified for storage operation"
    );
    Ok(())
}

/// Computes SHA-256 hex for an encrypted fragment.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn safe_storage_key_label(storage_key: &str) -> String {
    let digest = sha256_hex(storage_key.as_bytes());
    format!("sha256:{}", &digest[..12])
}

/// Verifies declared hash before accepting upload. Supports sha256: and blake3:.
fn fragment_hash_matches(declared_hash: &str, data: &[u8]) -> bool {
    if let Some(expected) = declared_hash.strip_prefix("sha256:") {
        return expected.eq_ignore_ascii_case(&sha256_hex(data));
    }
    if let Some(expected) = declared_hash.strip_prefix("blake3:") {
        return expected.eq_ignore_ascii_case(blake3::hash(data).to_hex().as_ref());
    }
    false
}

/// Hex decode helper
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{fragment_hash_matches, safe_storage_key_label};

    #[test]
    fn safe_storage_key_label_does_not_include_raw_key() {
        let storage_key = "file_secret_frag_0_r0";
        let label = safe_storage_key_label(storage_key);

        assert!(label.starts_with("sha256:"));
        assert_eq!(label.len(), "sha256:".len() + 12);
        assert!(!label.contains(storage_key));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn fragment_hash_matches_sha256() {
        let data = b"encrypted fragment bytes";
        let declared = format!("sha256:{}", super::sha256_hex(data));
        assert!(fragment_hash_matches(&declared, data));
    }
}
