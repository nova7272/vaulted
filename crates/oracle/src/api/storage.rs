//! Storage Nodes Management API

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::IpAddr;

use crate::auth::{AdminUser, AuthenticatedUser, NodeAuth};
use crate::services::{
    AppState, FileReplicationStatus, ReplicationService, ReplicationSettings, UploadTarget,
};

/// Check if a URL points to a private/internal network (HIGH-07: SSRF protection)
fn is_private_url(url: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            // Block localhost variants
            if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
                return true;
            }
            // Block metadata endpoints
            if host == "169.254.169.254" || host == "metadata.google.internal" {
                return true;
            }
            // Block private IP ranges
            if let Ok(ip) = host.parse::<IpAddr>() {
                return match ip {
                    IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                    IpAddr::V6(v6) => v6.is_loopback(),
                };
            }
            // Block .internal, .local domains
            if host.ends_with(".internal") || host.ends_with(".local") {
                return true;
            }
        }
    }
    false
}

// ==================== Types ====================

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    pub node_id: String,
    pub endpoint_url: String,
    pub region: String,
    #[serde(default)]
    pub total_space_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct RegisterNodeResponse {
    pub node_id: String,
    pub registered: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StorageNodeInfo {
    pub id: String,
    pub endpoint_url: String,
    pub region: String,
    pub status: String,
    pub total_space_bytes: i64,
    pub used_space_bytes: i64,
    pub health_check_failures: i32,
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct StorageNodesResponse {
    pub nodes: Vec<StorageNodeInfo>,
    pub total: usize,
    pub active: usize,
}

#[derive(Debug, Serialize)]
pub struct HealthCheckResult {
    pub node_id: String,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthCheckAllResponse {
    pub results: Vec<HealthCheckResult>,
    pub healthy_count: usize,
    pub unhealthy_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub fragments_count: i64,
    pub used_space_bytes: i64,
    pub total_space_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub acknowledged: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateReplicationSettingsRequest {
    pub replication_factor: Option<i32>,
    pub strategy: Option<String>,
    pub min_active_replicas: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct UploadTargetsResponse {
    pub targets: Vec<UploadTarget>,
    pub replication_factor: i32,
}

// ==================== Handlers ====================

/// POST /api/v1/storage/register - Register a new storage node
/// **Requires authentication** (CRIT-04) — accepts admin JWT or X-Node-Secret
pub async fn register_node(
    _node: NodeAuth,
    State(state): State<AppState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<RegisterNodeResponse>, (StatusCode, String)> {
    tracing::info!(
        "Registering storage node: {} at {}",
        request.node_id,
        request.endpoint_url
    );

    // SSRF protection: block private/internal URLs (HIGH-07)
    if is_private_url(&request.endpoint_url) && state.config.is_production() {
        tracing::warn!("Blocked SSRF attempt: {}", request.endpoint_url);
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid endpoint URL: private/internal addresses not allowed".to_string(),
        ));
    }

    // Проверяем доступность node
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let health_url = format!("{}/health", request.endpoint_url);
    let health_check = client.get(&health_url).send().await;

    let is_healthy = match health_check {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            tracing::warn!(
                "Node {} health check returned {}",
                request.node_id,
                resp.status()
            );
            false
        },
        Err(e) => {
            tracing::warn!("Node {} health check failed: {}", request.node_id, e);
            false
        },
    };

    // Upsert в БД
    let result = sqlx::query(
        r#"
        INSERT INTO storage_nodes (id, endpoint_url, region, status, total_space_bytes, last_health_check)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (id) DO UPDATE SET
            endpoint_url = EXCLUDED.endpoint_url,
            region = EXCLUDED.region,
            status = CASE WHEN $4 = 'active' THEN 'active' ELSE storage_nodes.status END,
            total_space_bytes = EXCLUDED.total_space_bytes,
            last_health_check = NOW(),
            health_check_failures = CASE WHEN $4 = 'active' THEN 0 ELSE storage_nodes.health_check_failures END,
            updated_at = NOW()
        "#,
    )
        .bind(&request.node_id)
        .bind(&request.endpoint_url)
        .bind(&request.region)
        .bind(if is_healthy { "active" } else { "offline" })
        .bind(request.total_space_bytes)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let registered = result.rows_affected() > 0;

    tracing::info!(
        "Storage node {} registered: healthy={}, rows_affected={}",
        request.node_id,
        is_healthy,
        result.rows_affected()
    );

    Ok(Json(RegisterNodeResponse {
        node_id: request.node_id,
        registered,
        message: if is_healthy {
            "Node registered and active".to_string()
        } else {
            "Node registered but offline (health check failed)".to_string()
        },
    }))
}

/// GET /api/v1/storage/nodes - List all storage nodes
pub async fn list_nodes(
    State(state): State<AppState>,
) -> Result<Json<StorageNodesResponse>, (StatusCode, String)> {
    let nodes: Vec<StorageNodeInfo> = sqlx::query_as(
        r#"
        SELECT id, endpoint_url, region, status,
               total_space_bytes, used_space_bytes,
               health_check_failures, last_health_check
        FROM storage_nodes
        ORDER BY region, id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total = nodes.len();
    let active = nodes.iter().filter(|n| n.status == "active").count();

    Ok(Json(StorageNodesResponse {
        nodes,
        total,
        active,
    }))
}

/// GET /api/v1/storage/nodes/:node_id - Get specific node info
pub async fn get_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<StorageNodeInfo>, (StatusCode, String)> {
    let node: StorageNodeInfo = sqlx::query_as(
        r#"
        SELECT id, endpoint_url, region, status,
               total_space_bytes, used_space_bytes,
               health_check_failures, last_health_check
        FROM storage_nodes
        WHERE id = $1
        "#,
    )
    .bind(&node_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Node not found".to_string()))?;

    Ok(Json(node))
}

/// DELETE /api/v1/storage/nodes/:node_id - Remove a storage node
/// **Requires authentication** (CRIT-04)
pub async fn remove_node(
    _admin: AdminUser,
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Проверяем что нет фрагментов на этом node
    let fragments_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM file_fragments WHERE storage_node_id = $1")
            .bind(&node_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if fragments_count.0 > 0 {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Cannot remove node with {} fragments. Migrate data first.",
                fragments_count.0
            ),
        ));
    }

    let result = sqlx::query("DELETE FROM storage_nodes WHERE id = $1")
        .bind(&node_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Node not found".to_string()));
    }

    tracing::info!("Storage node {} removed", node_id);
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/storage/heartbeat - Node heartbeat (called by storage nodes)
/// **Requires authentication** (CRIT-04) — accepts admin JWT or X-Node-Secret
pub async fn heartbeat(
    _node: NodeAuth,
    State(state): State<AppState>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
    let result = sqlx::query(
        r#"
        UPDATE storage_nodes
        SET status = 'active',
            used_space_bytes = $2,
            total_space_bytes = $3,
            last_health_check = NOW(),
            health_check_failures = 0,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&request.node_id)
    .bind(request.used_space_bytes)
    .bind(request.total_space_bytes)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Node not registered".to_string()));
    }

    tracing::debug!(
        "Heartbeat from {}: {} fragments, {}/{} bytes",
        request.node_id,
        request.fragments_count,
        request.used_space_bytes,
        request.total_space_bytes
    );

    Ok(Json(HeartbeatResponse { acknowledged: true }))
}

/// POST /api/v1/storage/health-check - Trigger health check for all nodes
/// **Requires authentication** (CRIT-04)
pub async fn health_check_all(
    _admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<HealthCheckAllResponse>, (StatusCode, String)> {
    let nodes: Vec<(String, String)> = sqlx::query_as("SELECT id, endpoint_url FROM storage_nodes")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut results = Vec::new();

    for (node_id, endpoint_url) in nodes {
        let health_url = format!("{}/health", endpoint_url);
        let start = std::time::Instant::now();

        let check_result = client.get(&health_url).send().await;

        let (healthy, latency_ms, error) = match check_result {
            Ok(resp) if resp.status().is_success() => {
                (true, Some(start.elapsed().as_millis() as u64), None)
            },
            Ok(resp) => (false, None, Some(format!("HTTP {}", resp.status()))),
            Err(e) => (false, None, Some(e.to_string())),
        };

        // Обновляем статус в БД
        if healthy {
            sqlx::query(
                r#"
                UPDATE storage_nodes
                SET status = 'active', health_check_failures = 0, last_health_check = NOW()
                WHERE id = $1
                "#,
            )
            .bind(&node_id)
            .execute(&state.db)
            .await
            .ok();
        } else {
            sqlx::query(
                r#"
                UPDATE storage_nodes
                SET health_check_failures = health_check_failures + 1,
                    status = CASE WHEN health_check_failures >= 3 THEN 'offline' ELSE status END,
                    last_health_check = NOW()
                WHERE id = $1
                "#,
            )
            .bind(&node_id)
            .execute(&state.db)
            .await
            .ok();
        }

        results.push(HealthCheckResult {
            node_id,
            healthy,
            latency_ms,
            error,
        });
    }

    let healthy_count = results.iter().filter(|r| r.healthy).count();
    let unhealthy_count = results.len() - healthy_count;

    tracing::info!(
        "Health check complete: {}/{} nodes healthy",
        healthy_count,
        results.len()
    );

    Ok(Json(HealthCheckAllResponse {
        results,
        healthy_count,
        unhealthy_count,
    }))
}

// ==================== Replication API ====================

/// GET /api/v1/storage/replication/settings - Get replication settings
pub async fn get_replication_settings(
    State(state): State<AppState>,
) -> Result<Json<ReplicationSettings>, (StatusCode, String)> {
    let service = ReplicationService::new(state.db.clone());
    let settings = service
        .get_settings()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(settings))
}

/// PUT /api/v1/storage/replication/settings - Update replication settings
/// **Requires authentication** (CRIT-04)
pub async fn update_replication_settings(
    _admin: AdminUser,
    State(state): State<AppState>,
    Json(request): Json<UpdateReplicationSettingsRequest>,
) -> Result<Json<ReplicationSettings>, (StatusCode, String)> {
    // Build update query dynamically
    let mut updates = Vec::new();
    let mut bind_idx = 1;

    if request.replication_factor.is_some() {
        updates.push(format!("replication_factor = ${}", bind_idx));
        bind_idx += 1;
    }
    if request.strategy.is_some() {
        updates.push(format!("strategy = ${}", bind_idx));
        bind_idx += 1;
    }
    if request.min_active_replicas.is_some() {
        updates.push(format!("min_active_replicas = ${}", bind_idx));
    }

    if updates.is_empty() {
        let service = ReplicationService::new(state.db.clone());
        return Ok(Json(service.get_settings().await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?));
    }

    let query = format!(
        "UPDATE replication_settings SET {}, updated_at = NOW() WHERE id = 'default'",
        updates.join(", ")
    );

    let mut q = sqlx::query(&query);

    if let Some(rf) = request.replication_factor {
        q = q.bind(rf);
    }
    if let Some(ref s) = request.strategy {
        q = q.bind(s);
    }
    if let Some(mar) = request.min_active_replicas {
        q = q.bind(mar);
    }

    q.execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let service = ReplicationService::new(state.db.clone());
    Ok(Json(service.get_settings().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?))
}

/// GET /api/v1/storage/replication/status/:nft_token_id - Get file replication status
pub async fn get_file_replication_status(
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<FileReplicationStatus>, (StatusCode, String)> {
    let service = ReplicationService::new(state.db.clone());
    let status = service
        .check_file_replication(&nft_token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(status))
}

/// POST /api/v1/storage/replication/upload-targets - Get upload targets for a fragment
#[derive(Debug, Deserialize)]
pub struct GetUploadTargetsRequest {
    pub file_id: String,
    pub fragment_index: u32,
    pub fragment_size: i64,
}

pub async fn get_upload_targets(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<GetUploadTargetsRequest>,
) -> Result<Json<UploadTargetsResponse>, (StatusCode, String)> {
    let service = ReplicationService::new(state.db.clone());

    let settings = service
        .get_settings()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let targets = service
        .create_upload_targets(
            &request.file_id,
            request.fragment_index,
            request.fragment_size,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UploadTargetsResponse {
        targets,
        replication_factor: settings.replication_factor,
    }))
}

// BEGIN GENERATED MANUAL SQLX FROMROW IMPLS

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for StorageNodeInfo {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            endpoint_url: row.try_get("endpoint_url")?,
            region: row.try_get("region")?,
            status: row.try_get("status")?,
            total_space_bytes: row.try_get("total_space_bytes")?,
            used_space_bytes: row.try_get("used_space_bytes")?,
            health_check_failures: row.try_get("health_check_failures")?,
            last_health_check: row.try_get("last_health_check")?,
        })
    }
}
// END GENERATED MANUAL SQLX FROMROW IMPLS
