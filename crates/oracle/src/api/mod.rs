//! REST API endpoints

mod auth;
mod file_proxy;
mod files;
mod health;
mod identity;
mod nft_public;
mod nfts;
mod qr_auth;
mod storage;
mod sync;
mod transfers;
mod users;
mod vault;
mod vault_objects;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::middleware::RateLimiter;
use crate::services::AppState;

/// Создаёт роутер API
pub fn create_router(auth_rate_limiter: RateLimiter) -> Router<AppState> {
    Router::new()
        // Health
        .route("/health", get(health::health_check))
        .route("/ready", get(health::ready_check))
        .route("/public-key", get(health::public_key))
        // Public NFT metadata & image (for wallet URI resolution)
        .route(
            "/nft/:token_id/metadata.json",
            get(nft_public::nft_metadata),
        )
        .route("/nft/:token_id/image.svg", get(nft_public::nft_image_svg))
        // API v1
        .nest("/api/v1", api_v1_routes(auth_rate_limiter))
}

fn api_v1_routes(auth_rate_limiter: RateLimiter) -> Router<AppState> {
    // Auth routes with stricter rate limiting
    let auth_public_routes = Router::new()
        .route("/auth/login-challenge", get(auth::get_login_challenge))
        .route("/auth/challenge/:wallet_address", get(auth::get_challenge))
        .route("/auth/token", post(auth::get_token))
        .route("/auth/refresh", post(auth::refresh_token))
        .route("/auth/qr/start", post(qr_auth::start_qr_login))
        .route(
            "/auth/qr/status/:login_request_id",
            get(qr_auth::qr_login_status),
        )
        .route("/auth/qr/confirm", post(qr_auth::confirm_qr_login))
        .route(
            "/auth/qr/pair/start",
            post(qr_auth::start_qr_device_pairing),
        )
        .route(
            "/auth/qr/pair/status/:pairing_request_id",
            get(qr_auth::qr_device_pairing_status),
        )
        .route(
            "/auth/qr/pair/confirm",
            post(qr_auth::confirm_qr_device_pairing),
        )
        .route(
            "/auth/qr/xrpl-sign/start",
            post(qr_auth::start_qr_xrpl_signing),
        )
        .route(
            "/auth/qr/xrpl-sign/status/:signing_request_id",
            get(qr_auth::qr_xrpl_signing_status),
        )
        .route(
            "/auth/qr/xrpl-sign/confirm",
            post(qr_auth::confirm_qr_xrpl_signing),
        )
        .route(
            "/auth/qr/grant/start",
            post(qr_auth::start_qr_file_grant_approval),
        )
        .route(
            "/auth/qr/grant/status/:grant_request_id",
            get(qr_auth::qr_file_grant_approval_status),
        )
        .route(
            "/auth/qr/grant/confirm",
            post(qr_auth::confirm_qr_file_grant_approval),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_rate_limiter,
            crate::middleware::auth_rate_limit_middleware,
        ));

    Router::new()
        // === PUBLIC ROUTES (no auth required) ===
        // Auth - with dedicated stricter rate limiter
        .merge(auth_public_routes)
        // Seed-based Vaulted identity registration - public (new users can't auth yet)
        .route("/identity/register", post(identity::register_identity))
        .route(
            "/identity/trust-recipient-key",
            post(identity::trust_recipient_key),
        )
        .route(
            "/identity/trust-recipient-key",
            get(identity::recipient_key_trust_status),
        )
        .route(
            "/identity/trust-recipient-key/revoke",
            post(identity::revoke_recipient_key_trust),
        )
        .route("/identity/devices", get(identity::list_identity_devices))
        .route(
            "/identity/devices/:device_id/revoke",
            post(identity::revoke_identity_device),
        )
        .route("/identity/:identity_id", get(identity::get_identity))
        .route(
            "/identity/challenge/:identity_id",
            get(identity::identity_challenge),
        )
        .route("/identity/token", post(identity::identity_token))
        // User/linked wallet registration - public (legacy compatibility)
        .route("/users/register", post(users::register_user))
        // Public key lookup - public (public key is public by definition)
        .route(
            "/users/:wallet_address/public-key",
            get(users::get_public_key),
        )
        // NFT verify ownership - public (on-chain data, no sensitive info)
        .route("/nfts/:nft_token_id/verify", get(nfts::verify_ownership))
        // Vault claim status only - public (needed for claim flow, minimal data)
        .route(
            "/vault/claim-status/:nft_token_id/:offer_index",
            get(vault::check_claim_status),
        )
        // Storage nodes list - public (needed for client setup, no sensitive data)
        .route("/storage/nodes", get(storage::list_nodes))
        .route("/storage/nodes/:node_id", get(storage::get_node))
        .route(
            "/storage/replication/settings",
            get(storage::get_replication_settings),
        )
        .route(
            "/storage/replication/status/:nft_token_id",
            get(storage::get_file_replication_status),
        )
        // === PROTECTED ROUTES (require JWT auth via AuthenticatedUser extractor) ===
        // Auth - protected
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::get_me))
        // External wallet payload proxy removed in Vaulted wallet mode.
        // User key management - protected (HIGH-06)
        .route("/users/update-key", put(users::update_public_key))
        // Vault objects / manifest layer
        .route(
            "/vault-objects/register",
            post(vault_objects::register_vault_object),
        )
        .route(
            "/vault-objects/by-nft/:nft_token_id",
            get(vault_objects::get_vault_object_by_nft),
        )
        .route("/vault-objects/:id", get(vault_objects::get_vault_object))
        .route("/grants", post(vault_objects::create_grant))
        .route("/grants/incoming", get(vault_objects::incoming_grants))
        .route("/grants/outgoing", get(vault_objects::outgoing_grants))
        .route(
            "/grants/:grant_id/revoke",
            post(vault_objects::revoke_grant),
        )
        .route(
            "/grants/:grant_id/access",
            get(vault_objects::grant_file_access),
        )
        // Vault - protected (HIGH-01: moved from public — exposes filenames)
        .route("/vault/:vault_id", get(vault::get_vault))
        // Transfer lookups - protected (HIGH-01: moved from public — exposes from/to addresses)
        .route(
            "/transfers/by-nft/:nft_token_id",
            get(transfers::get_transfer_by_nft),
        )
        .route(
            "/transfers/by-offer/:offer_index",
            get(transfers::get_transfer_by_offer),
        )
        // Files - protected (CRIT-03: access/download now require auth + NFT ownership)
        .route("/files/:nft_token_id/access", get(files::request_access))
        .route(
            "/files/:nft_token_id/download",
            get(file_proxy::download_file),
        )
        .route("/files/register", post(files::register_file))
        .route("/files/fragments/upload-url", post(files::get_upload_url))
        .route("/files/fragments/confirm", post(files::confirm_upload))
        .route("/files/upload", post(file_proxy::upload_file))
        .route(
            "/files/:nft_token_id/storage",
            delete(file_proxy::delete_file_storage),
        )
        .route(
            "/files/:nft_token_id/status",
            get(file_proxy::get_file_status),
        )
        // NFT metadata - protected (CRIT-03: contains encrypted_aes_key)
        .route("/nfts/:nft_token_id/metadata", get(nfts::get_metadata))
        .route("/file/:nft_token_id", get(vault::get_file_by_nft))
        // Transfers - protected (CRIT-04 + HIGH-03)
        .route("/transfers/:transfer_id/status", get(transfers::get_status))
        .route("/transfers/initiate", post(transfers::initiate_transfer))
        .route(
            "/transfers/confirm-signed",
            post(transfers::confirm_offer_signed),
        )
        .route(
            "/transfers/:transfer_id/cancel",
            post(transfers::cancel_transfer),
        )
        .route("/transfers/complete", post(transfers::complete_transfer))
        .route(
            "/transfers/finalize-by-offer",
            post(transfers::finalize_transfer_by_offer),
        )
        .route(
            "/transfers/incoming/:wallet_address",
            get(transfers::get_incoming_transfers),
        )
        .route(
            "/transfers/history/:wallet_address",
            get(transfers::get_transfer_history),
        )
        // Vault - protected
        .route("/vault/create", post(vault::create_vault))
        .route(
            "/vault/publish-metadata",
            post(vault::publish_vault_metadata),
        )
        .route("/vault/finalize-mint", post(vault::finalize_vault_mint))
        .route("/vault/:nft_token_id/delete", post(vault::delete_vault))
        .route("/vault/cancel-offer", post(vault::cancel_offer))
        // Storage management - protected (CRIT-04: admin operations)
        .route("/storage/register", post(storage::register_node))
        .route("/storage/nodes/:node_id", delete(storage::remove_node))
        .route("/storage/heartbeat", post(storage::heartbeat))
        .route("/storage/health-check", post(storage::health_check_all))
        .route(
            "/storage/replication/settings",
            put(storage::update_replication_settings),
        )
        .route(
            "/storage/replication/upload-targets",
            post(storage::get_upload_targets),
        )
        // Sync - protected (CRIT-04: admin operations)
        .route("/sync/trigger", post(sync::trigger_sync))
        .route("/sync/nft/:nft_token_id", post(sync::sync_nft))
        .route("/sync/status", get(sync::sync_status))
}
