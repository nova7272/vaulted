//! XRPL Vault Storage Node
//!
//! Service for storing and serving encrypted file fragments.
//! Supports self-registration with Oracle, periodic heartbeat,
//! and token-based authentication for fragment access.

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{Request, StatusCode},
    response::Json,
    routing::{delete, get, put},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
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
    /// Maximum encrypted fragment size accepted by upload endpoint.
    max_fragment_size: usize,
    /// In-memory index of stored fragments
    fragments: RwLock<HashMap<String, FragmentInfo>>,
    /// In-memory replay cache for mutating token IDs.
    consumed_token_ids: RwLock<HashMap<String, i64>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct FragmentInfo {
    key: String,
    size: u64,
    created_at: String,
    encrypted_hash: Option<String>,
}

/// Storage access token payload (must match Oracle's StorageToken)
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct StorageToken {
    nft_token_id: String,
    storage_key: String,
    operation: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    storage_node_id: Option<String>,
    #[serde(default)]
    fragment_hash: Option<String>,
    #[serde(default)]
    jti: Option<String>,
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
        max_fragment_size,
        fragments: RwLock::new(fragments),
        consumed_token_ids: RwLock::new(HashMap::new()),
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
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                tracing::debug_span!(
                    "http_request",
                    method = %request.method(),
                    path = %request.uri().path()
                )
            }),
        )
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
    storage_dir: &Path,
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

/// Validate storage key to prevent path traversal and fragment ID confusion.
fn validate_storage_key(key: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if key.is_empty() || key.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid fragment key length".to_string(),
            }),
        ));
    }

    let path = Path::new(key);
    if path.is_absolute()
        || key.starts_with('.')
        || key.contains("..")
        || key.contains('/')
        || key.contains('\\')
        || key.contains('%')
        || key.contains(':')
        || key.contains('?')
        || key.contains('#')
        || key.chars().any(|c| c.is_control())
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid fragment key".to_string(),
            }),
        ));
    }

    Ok(())
}

fn validate_fragment_size(
    size: usize,
    max_size: usize,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if size > max_size {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "Encrypted fragment exceeds maximum allowed size".to_string(),
            }),
        ));
    }

    Ok(())
}

async fn canonical_storage_root(
    storage_dir: &Path,
) -> Result<PathBuf, (StatusCode, Json<ErrorResponse>)> {
    fs::create_dir_all(storage_dir).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Storage root unavailable".to_string(),
            }),
        )
    })?;

    fs::canonicalize(storage_dir).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Storage root unavailable".to_string(),
            }),
        )
    })
}

async fn fragment_path_for_create(
    storage_dir: &Path,
    key: &str,
) -> Result<(PathBuf, PathBuf), (StatusCode, Json<ErrorResponse>)> {
    validate_storage_key(key)?;
    let root = canonical_storage_root(storage_dir).await?;
    let path = root.join(key);
    if path.parent() != Some(root.as_path()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
            }),
        ));
    }
    Ok((root, path))
}

async fn existing_fragment_path(
    storage_dir: &Path,
    key: &str,
) -> Result<PathBuf, (StatusCode, Json<ErrorResponse>)> {
    let (root, path) = fragment_path_for_create(storage_dir, key).await?;
    let metadata = fs::symlink_metadata(&path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Fragment not found".to_string(),
            }),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
            }),
        ));
    }

    let canonical_path = fs::canonicalize(&path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Fragment not found".to_string(),
            }),
        )
    })?;

    if !canonical_path.starts_with(&root) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
            }),
        ));
    }

    Ok(canonical_path)
}

/// Get a fragment by key (with token verification)
async fn get_fragment(
    State(state): State<Arc<AppState>>,
    AxumPath(key): AxumPath<String>,
    Query(params): Query<TokenQuery>,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    // Verify token if required
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "read", None).await?;
    }

    let path = existing_fragment_path(&state.storage_dir, &key).await?;

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
    AxumPath(key): AxumPath<String>,
    Query(params): Query<TokenQuery>,
    body: Bytes,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_fragment_size(body.len(), state.max_fragment_size)?;

    let size = body.len() as u64;
    let computed_hash = format!("sha256:{}", sha256_hex(&body));

    // Verify token before touching the filesystem.
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "write", Some(&computed_hash))
            .await?;
    }

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

    let (root, path) = fragment_path_for_create(&state.storage_dir, &key).await?;

    if let Ok(metadata) = fs::symlink_metadata(&path).await {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Access denied".to_string(),
                }),
            ));
        }

        let existing = fs::read(&path).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to inspect existing fragment".to_string(),
                }),
            )
        })?;
        if existing.as_slice() != body.as_ref() {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Encrypted fragment already exists with different content".to_string(),
                }),
            ));
        }
    } else {
        atomic_write_new_fragment(&root, &path, &key, &body).await?;
    }

    {
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
    }

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
}

async fn atomic_write_new_fragment(
    root: &Path,
    path: &Path,
    key: &str,
    body: &[u8],
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let temp_path = root.join(format!(
        ".upload-{}-{}",
        safe_storage_key_label(key).replace(':', "_"),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let write_result = async {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;
        file.write_all(body).await?;
        file.sync_all().await?;
        drop(file);
        fs::hard_link(&temp_path, path).await?;
        fs::remove_file(&temp_path).await
    }
    .await;

    match write_result {
        Ok(_) => {
            if let Err(_e) = fs::symlink_metadata(path).await {
                let _ = fs::remove_file(&temp_path).await;
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to store fragment".to_string(),
                    }),
                ));
            }
            Ok(())
        },
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Encrypted fragment already exists".to_string(),
            }),
        )),
        Err(_) => {
            let _ = fs::remove_file(&temp_path).await;
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to store fragment".to_string(),
                }),
            ))
        },
    }
}

/// Delete a fragment (with token verification)
async fn delete_fragment(
    State(state): State<Arc<AppState>>,
    AxumPath(key): AxumPath<String>,
    Query(params): Query<TokenQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Verify token if required
    if state.require_auth {
        verify_token_for_operation(&state, &params.token, &key, "delete", None).await?;
    }

    let path = existing_fragment_path(&state.storage_dir, &key).await?;

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

/// Verify a storage token for the given operation.
async fn verify_token_for_operation(
    state: &AppState,
    token: &Option<String>,
    storage_key: &str,
    operation: &str,
    computed_fragment_hash: Option<&str>,
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

    if token.storage_node_id.as_deref() != Some(state.node_id.as_str()) {
        tracing::warn!(
            storage_key_hash = %safe_storage_key_label(storage_key),
            "Token storage node mismatch"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Token not valid for this storage node".to_string(),
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

    if let Some(expected_hash) = token.fragment_hash.as_deref() {
        if let Some(computed_hash) = computed_fragment_hash {
            if !expected_hash.eq_ignore_ascii_case(computed_hash) {
                tracing::warn!(
                    storage_key_hash = %safe_storage_key_label(storage_key),
                    "Token fragment hash mismatch"
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Token not valid for this encrypted fragment".to_string(),
                    }),
                ));
            }
        }
    }

    if matches!(operation, "write" | "delete") {
        let jti = token.jti.as_deref().ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Token missing replay protection".to_string(),
                }),
            )
        })?;
        consume_token_id(state, jti, token.exp, now).await?;
    }

    tracing::debug!(
        operation,
        storage_key_hash = %safe_storage_key_label(storage_key),
        "Token verified for storage operation"
    );
    Ok(())
}

async fn consume_token_id(
    state: &AppState,
    jti: &str,
    exp: i64,
    now: i64,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if jti.is_empty() || jti.len() > 128 || jti.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token payload".to_string(),
            }),
        ));
    }

    let mut consumed = state.consumed_token_ids.write().await;
    consumed.retain(|_, expires_at| *expires_at >= now);
    if consumed.contains_key(jti) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Token has already been used".to_string(),
            }),
        ));
    }
    consumed.insert(jti.to_string(), exp);
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
    use super::*;
    use axum::extract::{Path as AxumPath, Query, State};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed_token_for(
        signing_key: &SigningKey,
        operation: &str,
        storage_key: &str,
        node_id: &str,
        exp_offset_seconds: i64,
        fragment_hash: Option<&str>,
        jti: &str,
    ) -> String {
        let now = chrono::Utc::now().timestamp();
        let token = StorageToken {
            nft_token_id: "nft123".to_string(),
            storage_key: storage_key.to_string(),
            operation: operation.to_string(),
            exp: now + exp_offset_seconds,
            iat: now,
            storage_node_id: Some(node_id.to_string()),
            fragment_hash: fragment_hash.map(ToOwned::to_owned),
            jti: Some(jti.to_string()),
        };
        let payload = serde_json::to_string(&token).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signature = signing_key.sign(payload_b64.as_bytes());
        format!(
            "{}.{}",
            payload_b64,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn temp_storage_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vaulted-storage-node-test-{name}-{suffix}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_state(
        storage_dir: PathBuf,
        signing_key: &SigningKey,
        require_auth: bool,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "node-a".to_string(),
            storage_dir,
            oracle_url: None,
            region: "local".to_string(),
            oracle_public_key: Some(signing_key.verifying_key()),
            require_auth,
            max_fragment_size: 16,
            fragments: RwLock::new(HashMap::new()),
            consumed_token_ids: RwLock::new(HashMap::new()),
        })
    }

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

    #[tokio::test]
    async fn valid_scoped_write_token_is_accepted_once() {
        let key = signing_key();
        let state = test_state(temp_storage_dir("valid-token"), &key, true);
        let token = signed_token_for(&key, "write", "fragment_a", "node-a", 60, None, "jti-valid");

        assert!(verify_token_for_operation(
            &state,
            &Some(token.clone()),
            "fragment_a",
            "write",
            None
        )
        .await
        .is_ok());

        let err = verify_token_for_operation(&state, &Some(token), "fragment_a", "write", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(err.1 .0.error, "Token has already been used");
    }

    #[tokio::test]
    async fn scoped_tokens_reject_wrong_action_fragment_node_expiry_and_malformed() {
        let key = signing_key();
        let state = test_state(temp_storage_dir("scope"), &key, true);

        let upload = signed_token_for(
            &key,
            "write",
            "fragment_a",
            "node-a",
            60,
            None,
            "jti-upload",
        );
        let err = verify_token_for_operation(&state, &Some(upload), "fragment_a", "read", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let download = signed_token_for(&key, "read", "fragment_a", "node-a", 60, None, "jti-read");
        let err = verify_token_for_operation(&state, &Some(download), "fragment_a", "delete", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let fragment_a =
            signed_token_for(&key, "read", "fragment_a", "node-a", 60, None, "jti-frag");
        let err = verify_token_for_operation(&state, &Some(fragment_a), "fragment_b", "read", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let wrong_node =
            signed_token_for(&key, "read", "fragment_a", "node-b", 60, None, "jti-node");
        let err = verify_token_for_operation(&state, &Some(wrong_node), "fragment_a", "read", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let expired = signed_token_for(
            &key,
            "read",
            "fragment_a",
            "node-a",
            -60,
            None,
            "jti-expired",
        );
        let err = verify_token_for_operation(&state, &Some(expired), "fragment_a", "read", None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let raw = "raw-secret-token-value".to_string();
        let err =
            verify_token_for_operation(&state, &Some(raw.clone()), "fragment_a", "read", None)
                .await
                .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert!(!err.1 .0.error.contains(&raw));
    }

    #[tokio::test]
    async fn upload_token_fragment_hash_must_match_body() {
        let key = signing_key();
        let state = test_state(temp_storage_dir("hash-token"), &key, true);
        let token = signed_token_for(
            &key,
            "write",
            "fragment_a",
            "node-a",
            60,
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "jti-hash",
        );

        let err = verify_token_for_operation(
            &state,
            &Some(token),
            "fragment_a",
            "write",
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn path_traversal_and_unsafe_keys_are_rejected() {
        for key in [
            "../secret",
            "..\\secret",
            "/tmp/secret",
            "C:\\secret",
            "%2e%2e%2fsecret",
            "fragment\nid",
            ".hidden",
        ] {
            assert!(
                validate_storage_key(key).is_err(),
                "{key} should be rejected"
            );
        }
        assert!(validate_storage_key("fragment_01-A.sha256").is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_is_rejected_and_delete_does_not_remove_target() {
        use std::os::unix::fs::symlink;

        let key = signing_key();
        let storage_dir = temp_storage_dir("symlink");
        let outside = temp_storage_dir("outside").join("target");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, storage_dir.join("fragment_link")).unwrap();
        let state = test_state(storage_dir, &key, true);
        let token = signed_token_for(
            &key,
            "delete",
            "fragment_link",
            "node-a",
            60,
            None,
            "jti-delete-link",
        );

        let err = delete_fragment(
            State(state),
            AxumPath("fragment_link".to_string()),
            Query(TokenQuery {
                token: Some(token),
                fragment_hash: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    #[tokio::test]
    async fn oversized_upload_and_hash_mismatch_are_rejected() {
        let key = signing_key();
        let state = test_state(temp_storage_dir("upload"), &key, false);

        let oversized = match put_fragment(
            State(state.clone()),
            AxumPath("fragment_big".to_string()),
            Query(TokenQuery {
                token: None,
                fragment_hash: None,
            }),
            Bytes::from(vec![1u8; 17]),
        )
        .await
        {
            Ok(_) => panic!("oversized upload should be rejected"),
            Err(err) => err,
        };
        assert_eq!(oversized.0, StatusCode::PAYLOAD_TOO_LARGE);

        let mismatch = match put_fragment(
            State(state),
            AxumPath("fragment_hash".to_string()),
            Query(TokenQuery {
                token: None,
                fragment_hash: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
            }),
            Bytes::from_static(b"ciphertext"),
        )
        .await
        {
            Ok(_) => panic!("hash mismatch should be rejected"),
            Err(err) => err,
        };
        assert_eq!(mismatch.0, StatusCode::BAD_REQUEST);
    }
}
