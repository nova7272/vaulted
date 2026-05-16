//! Sync API endpoints

use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    auth::AdminUser,
    error::Result,
    services::AppState,
    sync::{SyncAction, SyncConfig, XrplSyncService},
};

/// POST /api/v1/sync/trigger - запустить синхронизацию вручную
/// **Requires admin role** (CRIT-04)
pub async fn trigger_sync(
    _admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    let sync_service =
        XrplSyncService::new(state.db.clone(), state.xrpl.clone(), SyncConfig::default());

    let stats = sync_service.trigger_sync().await?;
    Ok(Json(stats.to_json()))
}

/// POST /api/v1/sync/nft/:nft_token_id - синхронизировать конкретный NFT
/// **Requires authentication** (CRIT-04)
pub async fn sync_nft(
    _admin: AdminUser,
    State(state): State<AppState>,
    Path(nft_token_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let sync_service =
        XrplSyncService::new(state.db.clone(), state.xrpl.clone(), SyncConfig::default());

    let action = sync_service.sync_nft(&nft_token_id).await?;

    let result = match action {
        SyncAction::NoChange => serde_json::json!({
            "status": "no_change",
            "message": "Owner unchanged"
        }),
        SyncAction::OwnerUpdated { old, new } => serde_json::json!({
            "status": "updated",
            "old_owner": old,
            "new_owner": new
        }),
        SyncAction::NotFoundOnXrpl => serde_json::json!({
            "status": "not_found",
            "message": "NFT not found on XRPL"
        }),
        SyncAction::NewOwnerNotRegistered(addr) => serde_json::json!({
            "status": "unregistered_owner",
            "new_owner_wallet": addr,
            "message": "New owner is not registered in Oracle"
        }),
    };

    Ok(Json(result))
}

/// GET /api/v1/sync/status - получить статус синхронизации
/// **Requires authentication** (CRIT-04)
pub async fn sync_status(
    _admin: AdminUser,
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "enabled": true,
        "interval_secs": 300,
        "message": "Sync available via API"
    })))
}
