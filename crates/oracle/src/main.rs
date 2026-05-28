//! XRPL Vault Oracle Server
//!
//! Central server for managing encrypted file storage
//! with NFT-based access control.

use axum::http::{header, Method};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use xrpl_vault_oracle::{
    api, config::Config, db, middleware, run_embedded_migrations, services::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "xrpl_vault_oracle=debug,tower_http=debug,sqlx=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting XRPL Vault Oracle v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Loaded configuration (env: {})", config.environment);

    // Connect to the database
    tracing::info!("Connecting to database...");
    let db_pool = db::create_pool(&config.database_url).await?;
    db::check_connection(&db_pool).await?;
    tracing::info!("Database connected");

    // Run migrations
    tracing::info!("Running database migrations...");
    let migration_result = run_embedded_migrations(&db_pool).await?;
    tracing::info!(
        "Migrations complete: {} total, {} applied, {} skipped",
        migration_result.total,
        migration_result.applied,
        migration_result.skipped
    );

    // Load or generate the Oracle signing key
    let signing_key = load_or_generate_signing_key(&config)?;
    let verifying_key = signing_key.verifying_key();
    tracing::info!(
        "Oracle signing public key: {}",
        hex::encode(verifying_key.as_bytes())
    );

    // Build CORS layer based on environment
    let cors = build_cors_layer(&config);

    // Create rate limiter with trusted proxies (HIGH-01)
    let rate_limiter = middleware::RateLimiter::with_trusted_proxies(
        config.rate_limit_rpm,
        config.trusted_proxies.clone(),
    );
    if !config.trusted_proxies.is_empty() {
        tracing::info!("Trusted proxies: {:?}", config.trusted_proxies);
    } else {
        tracing::info!(
            "No trusted proxies configured — proxy headers will be ignored for rate limiting"
        );
    }

    // Auth-specific rate limiter (stricter)
    let auth_rate_limiter = middleware::RateLimiter::with_trusted_proxies(
        config.auth_rate_limit_rpm,
        config.trusted_proxies.clone(),
    );
    tracing::info!(
        "Rate limits: general={}/min, auth={}/min",
        config.rate_limit_rpm,
        config.auth_rate_limit_rpm
    );

    // Create application state
    let mut state = AppState::new(config.clone(), db_pool, signing_key);

    // CRIT-03: Log wallet seed source for security awareness
    if config.xrpl_wallet_seed.is_some() {
        if config.xrpl_wallet_seed_file.is_some() {
            tracing::info!("🔑 XRPL wallet material loaded from file");
        } else if config.is_production() {
            // This should not happen — load_wallet_seed blocks it in production
            tracing::error!("🚨 XRPL wallet material loaded from env var in PRODUCTION!");
        } else {
            tracing::warn!(
                "⚠️  XRPL wallet seed loaded from XRPL_WALLET_SEED env var. \
                 Use XRPL_WALLET_SEED_FILE in production!"
            );
        }
    } else {
        tracing::info!("XRPL wallet not configured — Oracle runs in read-only mode");
    }

    // Connect to Redis if configured
    if let Some(ref redis_url) = config.redis_url {
        state = state.with_redis(redis_url).await;
    } else {
        tracing::info!("Redis not configured — using in-memory blacklist/challenges");
    }

    // Spawn cleanup task for rate limiter, challenges, and token blacklist
    let cleanup_limiter = rate_limiter.clone();
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup().await;
            // Also cleanup expired challenges and blacklisted tokens
            cleanup_state.cleanup_expired().await;
        }
    });

    // Create the router with the middleware stack
    let app = api::create_router(auth_rate_limiter)
        .layer(
            ServiceBuilder::new()
                // Security headers
                .layer(axum::middleware::from_fn(
                    middleware::security_headers_middleware,
                ))
                // Logging with IP
                .layer(axum::middleware::from_fn(middleware::logging_middleware))
                // Rate limiting
                .layer(axum::middleware::from_fn_with_state(
                    rate_limiter.clone(),
                    middleware::rate_limit_middleware,
                ))
                // Request body size limit (config.max_file_size + 1MB for headers/metadata)
                .layer(RequestBodyLimitLayer::new(
                    (config.max_file_size + 1_048_576) as usize,
                ))
                // Tracing
                .layer(TraceLayer::new_for_http())
                // CORS
                .layer(cors),
        )
        .with_state(state);

    // Start the server
    let addr: SocketAddr = config.listen_addr().parse()?;
    tracing::info!("Oracle listening on http://{}", addr);

    if config.is_production() {
        tracing::info!("🔒 Running in PRODUCTION mode");
        if config.cors_origins.is_empty() {
            tracing::warn!("⚠️  CORS_ORIGINS not set in production! API may be inaccessible.");
        }
    } else {
        tracing::warn!("⚠️  Running in DEVELOPMENT mode - CORS is permissive");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Build CORS layer based on configuration
fn build_cors_layer(config: &Config) -> CorsLayer {
    if config.is_production() && !config.cors_origins.is_empty() {
        // Production: strict CORS
        let origins: Vec<_> = config
            .cors_origins
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        tracing::info!("CORS: Allowing origins: {:?}", config.cors_origins);

        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    } else {
        // Development: restricted CORS — allow localhost only (MED-01)
        let dev_origins: Vec<_> = vec![
            "http://localhost:1420", // Tauri dev
            "http://localhost:3000", // Oracle
            "http://localhost:5173", // Vite dev
            "http://127.0.0.1:1420",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "tauri://localhost", // Tauri app
        ]
        .into_iter()
        .filter_map(|s| s.parse().ok())
        .collect();

        tracing::info!("CORS: Development mode — allowing localhost origins only");

        CorsLayer::new()
            .allow_origin(dev_origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
            .max_age(Duration::from_secs(3600))
    }
}

/// Loads the signing key from configuration or generates a new one
fn load_or_generate_signing_key(config: &Config) -> anyhow::Result<SigningKey> {
    // Try to load from env
    if let Ok(key_hex) = std::env::var("ORACLE_SIGNING_KEY") {
        let key_bytes = hex::decode(&key_hex)?;
        if key_bytes.len() != 32 {
            anyhow::bail!("ORACLE_SIGNING_KEY must be 32 bytes (64 hex chars)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        tracing::info!("Loaded signing key from ORACLE_SIGNING_KEY env");
        return Ok(SigningKey::from_bytes(&arr));
    }

    // Production check
    if config.is_production() {
        anyhow::bail!("ORACLE_SIGNING_KEY must be set in production!");
    }

    // Generate a new one (dev only)
    tracing::warn!("⚠️  Generating random signing key. Set ORACLE_SIGNING_KEY in production!");
    let signing_key = SigningKey::generate(&mut OsRng);

    // Print it for saving
    tracing::info!(
        "Generated signing key (save this!): {}",
        hex::encode(signing_key.to_bytes())
    );

    Ok(signing_key)
}
