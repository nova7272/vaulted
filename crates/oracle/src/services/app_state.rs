//! Oracle application state

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::{Config, DEFAULT_XRPL_RPC_URL};
use crate::xrpl::{XrplConfig, XrplService};

fn redis_error_kind(error: &redis::RedisError) -> String {
    format!("{:?}", error.kind())
}

/// Stored challenge with expiry
#[derive(Clone)]
pub struct StoredChallenge {
    pub challenge: String,
    pub wallet_address: String,
    pub created_at: Instant,
}

/// Application state
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub xrpl: Arc<XrplService>,
    pub signing_key: Arc<SigningKey>,
    /// Challenge store: nonce -> StoredChallenge (in-memory, CRIT-02)
    pub challenge_store: Arc<RwLock<HashMap<String, StoredChallenge>>>,
    /// Token blacklist: in-memory fallback (HIGH-04)
    pub token_blacklist: Arc<RwLock<HashMap<String, i64>>>,
    /// Redis connection manager (optional — falls back to in-memory)
    pub redis: Option<redis::aio::ConnectionManager>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool, signing_key: SigningKey) -> Self {
        let xrpl_rpc_url = config
            .xrpl_rpc_url
            .as_deref()
            .unwrap_or(DEFAULT_XRPL_RPC_URL);
        tracing::info!(
            xrpl_endpoint_scheme = xrpl_rpc_url.split(':').next().unwrap_or("unknown"),
            request_phase = "oracle_startup",
            status = "configured",
            "Oracle XRPL JSON-RPC endpoint configured"
        );

        let xrpl = if let Some(wallet_seed) = &config.xrpl_wallet_seed {
            let xrpl_config = XrplConfig {
                node_url: xrpl_rpc_url.to_string(),
                node_urls: vec![],
                wallet_seed: Some(wallet_seed.clone()),
            };
            XrplService::with_wallet(xrpl_config)
                .expect("Failed to create XRPL service with wallet")
        } else {
            XrplService::new(xrpl_rpc_url).expect("Failed to create XRPL service")
        };

        Self {
            config,
            db,
            xrpl: Arc::new(xrpl),
            signing_key: Arc::new(signing_key),
            challenge_store: Arc::new(RwLock::new(HashMap::new())),
            token_blacklist: Arc::new(RwLock::new(HashMap::new())),
            redis: None,
        }
    }

    /// Initialize Redis connection (call after construction)
    pub async fn with_redis(mut self, redis_url: &str) -> Self {
        match redis::Client::open(redis_url) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(mgr) => {
                    tracing::info!(
                        redis_configured = true,
                        "Redis connected for Oracle state cache"
                    );
                    self.redis = Some(mgr);
                },
                Err(e) => {
                    tracing::warn!(
                        error_kind = %redis_error_kind(&e),
                        "Redis connection failed; using in-memory fallback"
                    );
                },
            },
            Err(e) => {
                tracing::warn!(
                    error_kind = %redis_error_kind(&e),
                    "Redis client setup failed; using in-memory fallback"
                );
            },
        }
        self
    }

    /// Store a challenge for later verification
    pub async fn store_challenge(&self, nonce: &str, challenge: &str, wallet: &str) {
        let key = format!("challenge:{}", nonce);

        // Try Redis first
        if let Some(ref redis) = self.redis {
            let value = serde_json::json!({
                "challenge": challenge,
                "wallet": wallet
            })
            .to_string();

            let mut conn = redis.clone();
            let result: Result<(), redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg(&value)
                .arg("EX")
                .arg(300) // 5 minute TTL
                .query_async(&mut conn)
                .await;

            if result.is_ok() {
                return;
            }
            tracing::warn!("Redis SET failed for challenge, falling back to in-memory");
        }

        // In-memory fallback
        let mut store = self.challenge_store.write().await;
        store.insert(
            nonce.to_string(),
            StoredChallenge {
                challenge: challenge.to_string(),
                wallet_address: wallet.to_string(),
                created_at: Instant::now(),
            },
        );
    }

    fn challenge_nonce(challenge: &str) -> Option<&str> {
        let parts: Vec<&str> = challenge.split(':').collect();

        // Existing wallet-bound format:
        // xrpl-vault-auth:{wallet}:{nonce}:{timestamp}
        if parts.len() >= 4 && parts[0] == "xrpl-vault-auth" {
            return Some(parts[2]);
        }

        // Legacy login format where wallet was not known before wallet approval:
        // xrpl-vault-auth-login:{nonce}:{timestamp}
        if parts.len() >= 3 && parts[0] == "xrpl-vault-auth-login" {
            return Some(parts[1]);
        }

        None
    }

    fn challenge_wallet_matches(stored_wallet: &str, wallet: &str) -> bool {
        // "*" means wallet is intentionally unknown at challenge creation time.
        stored_wallet == "*" || stored_wallet.eq_ignore_ascii_case(wallet)
    }

    /// Verify and consume a challenge (one-time use)
    pub async fn verify_and_consume_challenge(&self, challenge: &str, wallet: &str) -> bool {
        // Try Redis first
        if let Some(ref redis) = self.redis {
            if let Some(nonce) = Self::challenge_nonce(challenge) {
                let key = format!("challenge:{}", nonce);

                let mut conn = redis.clone();
                let result: Result<Option<String>, redis::RedisError> =
                    redis::cmd("GET").arg(&key).query_async(&mut conn).await;

                if let Ok(Some(value)) = result {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&value) {
                        let stored_challenge = data["challenge"].as_str().unwrap_or("");
                        let stored_wallet = data["wallet"].as_str().unwrap_or("");

                        if stored_challenge == challenge
                            && Self::challenge_wallet_matches(stored_wallet, wallet)
                        {
                            // Consume: delete from Redis
                            let _: Result<(), redis::RedisError> =
                                redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        // In-memory fallback
        let mut store = self.challenge_store.write().await;
        let challenge_ttl = std::time::Duration::from_secs(300);

        let found_key = store
            .iter()
            .find(|(_, v)| {
                v.challenge == challenge
                    && Self::challenge_wallet_matches(&v.wallet_address, wallet)
                    && v.created_at.elapsed() < challenge_ttl
            })
            .map(|(k, _)| k.clone());

        if let Some(key) = found_key {
            store.remove(&key);
            true
        } else {
            false
        }
    }

    /// Add token JTI to blacklist
    pub async fn blacklist_token(&self, jti: &str, exp: i64) {
        let ttl = (exp - chrono::Utc::now().timestamp()).max(1);

        // Try Redis first
        if let Some(ref redis) = self.redis {
            let key = format!("blacklist:{}", jti);
            let mut conn = redis.clone();
            let result: Result<(), redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut conn)
                .await;

            if result.is_ok() {
                return;
            }
            tracing::warn!("Redis SET failed for blacklist, falling back to PostgreSQL");
        }

        // HIGH-02: PostgreSQL fallback — survives restarts
        let pg_result = sqlx::query(
            "INSERT INTO token_blacklist (jti, expires_at) VALUES ($1, to_timestamp($2)) \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(exp as f64)
        .execute(&self.db)
        .await;

        match pg_result {
            Ok(_) => {},
            Err(e) => {
                // Table might not exist yet — fall back to in-memory
                tracing::debug!(
                    "PostgreSQL blacklist insert failed (table may not exist): {}",
                    e
                );
                let mut blacklist = self.token_blacklist.write().await;
                blacklist.insert(jti.to_string(), exp);
            },
        }
    }

    /// Check if token JTI is blacklisted
    pub async fn is_token_blacklisted(&self, jti: &str) -> bool {
        // Try Redis first
        if let Some(ref redis) = self.redis {
            let key = format!("blacklist:{}", jti);
            let mut conn = redis.clone();
            let result: Result<bool, redis::RedisError> =
                redis::cmd("EXISTS").arg(&key).query_async(&mut conn).await;

            if let Ok(exists) = result {
                return exists;
            }
            tracing::warn!("Redis EXISTS failed, falling back to PostgreSQL");
        }

        // HIGH-02: PostgreSQL fallback
        let pg_result: Result<Option<(i32,)>, _> =
            sqlx::query_as("SELECT 1 FROM token_blacklist WHERE jti = $1 AND expires_at > NOW()")
                .bind(jti)
                .fetch_optional(&self.db)
                .await;

        match pg_result {
            Ok(Some(_)) => true,
            Ok(None) => {
                // Also check in-memory (for entries added before table existed)
                let blacklist = self.token_blacklist.read().await;
                blacklist.contains_key(jti)
            },
            Err(_) => {
                // Table doesn't exist — check in-memory
                let blacklist = self.token_blacklist.read().await;
                blacklist.contains_key(jti)
            },
        }
    }

    /// Cleanup expired challenges and blacklisted tokens
    pub async fn cleanup_expired(&self) {
        // Cleanup challenges older than 10 minutes
        {
            let mut store = self.challenge_store.write().await;
            let max_age = std::time::Duration::from_secs(600);
            store.retain(|_, v| v.created_at.elapsed() < max_age);
        }

        // Cleanup expired blacklisted tokens (in-memory)
        {
            let now = chrono::Utc::now().timestamp();
            let mut blacklist = self.token_blacklist.write().await;
            blacklist.retain(|_, exp| *exp > now);
        }

        // HIGH-02: Cleanup expired entries in PostgreSQL
        let _ = sqlx::query("DELETE FROM token_blacklist WHERE expires_at < NOW()")
            .execute(&self.db)
            .await;
    }

    /// Logs an audit event with sensitive data encryption
    pub async fn audit_log(
        &self,
        user_id: Option<Uuid>,
        action: &str,
        nft_token_id: Option<&str>,
        details: Option<serde_json::Value>,
    ) {
        let result = if let Some(ref enc_key) = self.config.audit_encryption_key {
            // Encrypt sensitive details, store action as plain text for querying
            sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, action, nft_token_id, details, encrypted_details, created_at)
                VALUES ($1, $2, $3, NULL, encrypt_audit_details($4, $5), NOW())
                "#,
            )
                .bind(user_id)
                .bind(action)
                .bind(nft_token_id)
                .bind(&details)
                .bind(enc_key)
                .execute(&self.db)
                .await
        } else {
            // No encryption key — store as plain JSON (backward compatible)
            sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, action, nft_token_id, details, created_at)
                VALUES ($1, $2, $3, $4, NOW())
                "#,
            )
            .bind(user_id)
            .bind(action)
            .bind(nft_token_id)
            .bind(&details)
            .execute(&self.db)
            .await
        };

        if let Err(e) = result {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }

    /// Logs an audit event with IP and User-Agent
    pub async fn audit_log_full(
        &self,
        user_id: Option<Uuid>,
        action: &str,
        nft_token_id: Option<&str>,
        details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let result = if let Some(ref enc_key) = self.config.audit_encryption_key {
            sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, action, nft_token_id, details, encrypted_details, ip_address, user_agent, created_at)
                VALUES ($1, $2, $3, NULL, encrypt_audit_details($4, $5), $6::inet, $7, NOW())
                "#,
            )
                .bind(user_id)
                .bind(action)
                .bind(nft_token_id)
                .bind(&details)
                .bind(enc_key)
                .bind(ip_address)
                .bind(user_agent)
                .execute(&self.db)
                .await
        } else {
            sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, action, nft_token_id, details, ip_address, user_agent, created_at)
                VALUES ($1, $2, $3, $4, $5::inet, $6, NOW())
                "#,
            )
                .bind(user_id)
                .bind(action)
                .bind(nft_token_id)
                .bind(&details)
                .bind(ip_address)
                .bind(user_agent)
                .execute(&self.db)
                .await
        };

        if let Err(e) = result {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redis_error_kind;

    #[test]
    fn redis_error_kind_does_not_echo_url_or_secret() {
        let err = redis::Client::open("redis://:secret-token-value@")
            .expect_err("invalid Redis URL should produce an error");
        let label = redis_error_kind(&err);

        assert!(!label.contains("secret-token-value"));
        assert!(!label.contains("redis://"));
    }
}
