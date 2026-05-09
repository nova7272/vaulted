//! Конфигурация Oracle сервера

use std::env;

/// Конфигурация приложения
#[derive(Debug, Clone)]
pub struct Config {
    /// Хост сервера
    pub host: String,
    /// Порт сервера
    pub port: u16,
    /// URL базы данных PostgreSQL
    pub database_url: String,
    /// URL Redis (опционально)
    pub redis_url: Option<String>,
    /// URL XRPL ноды (JSON-RPC)
    pub xrpl_node_url: Option<String>,
    /// XRPL wallet seed для минтинга NFT (опционально)
    pub xrpl_wallet_seed: Option<String>,
    /// Секретный ключ для JWT
    pub jwt_secret: String,
    /// Время жизни JWT токена (часы)
    pub jwt_expiration_hours: i64,
    /// Максимальный размер файла (bytes)
    pub max_file_size: u64,
    /// Минимальный фактор репликации
    pub min_replication: u32,
    /// Rate limit (запросов в минуту)
    pub rate_limit_rpm: u32,
    /// Allowed CORS origins (comma-separated, empty = permissive in dev)
    pub cors_origins: Vec<String>,
    /// Environment: "development" or "production"
    pub environment: String,
    /// Encryption key for audit log sensitive data (optional)
    pub audit_encryption_key: Option<String>,
    /// Encryption key for DB column encryption (manifest, etc.)
    /// Falls back to audit_encryption_key if not set separately
    pub db_encryption_key: Option<String>,
    /// Public URL of this Oracle (used in NFT URI for wallet metadata resolution)
    /// Example: https://vault.example.com
    pub public_url: Option<String>,
    /// Shared secret for storage node authentication (register/heartbeat)
    pub node_secret: Option<String>,
    /// Xaman API key. Backend-only.
    pub xaman_api_key: Option<String>,
    /// Xaman API secret. Backend-only; must never be bundled into desktop-client.
    pub xaman_api_secret: Option<String>,
    /// Forced Xaman network, for example TESTNET or MAINNET.
    pub xaman_force_network: Option<String>,
    /// Path to file containing XRPL wallet seed (CRIT-03: preferred over env var)
    /// File must have permissions 0600 (owner read/write only)
    pub xrpl_wallet_seed_file: Option<String>,
    /// HIGH-01: Trusted reverse proxy IPs (only these may set X-Forwarded-For, X-Real-IP)
    /// Comma-separated list. If empty, proxy headers are never trusted.
    pub trusted_proxies: Vec<String>,
    /// Auth-specific rate limit (requests per minute per IP), stricter than general
    pub auth_rate_limit_rpm: u32,
}

impl Config {
    /// Загружает конфигурацию из переменных окружения
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string());

        let cors_origins: Vec<String> = env::var("CORS_ORIGINS")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| Vec::new());

        Ok(Self {
            host: env::var("ORACLE_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("ORACLE_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("ORACLE_PORT".to_string()))?,
            database_url: env::var("DATABASE_URL")
                .map_err(|_| ConfigError::Missing("DATABASE_URL".to_string()))?,
            redis_url: env::var("REDIS_URL").ok(),
            xrpl_node_url: env::var("XRPL_NODE_URL").ok(),
            // CRIT-03: Wallet seed loading with security priority:
            // 1. File (XRPL_WALLET_SEED_FILE) — preferred, checked for permissions
            // 2. Env var (XRPL_WALLET_SEED) — only in development
            xrpl_wallet_seed: Self::load_wallet_seed(&environment)?,
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| {
                    if environment == "production" {
                        panic!("JWT_SECRET must be set in production!");
                    }
                    uuid::Uuid::new_v4().to_string() // Random per-instance in dev
                }),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .unwrap_or(24),
            max_file_size: env::var("MAX_FILE_SIZE")
                .unwrap_or_else(|_| "104857600".to_string()) // 100MB
                .parse()
                .unwrap_or(104857600),
            min_replication: env::var("MIN_REPLICATION")
                .unwrap_or_else(|_| "2".to_string())
                .parse()
                .unwrap_or(2),
            rate_limit_rpm: env::var("RATE_LIMIT_RPM")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            cors_origins,
            environment,
            audit_encryption_key: env::var("AUDIT_ENCRYPTION_KEY").ok(),
            // DB_ENCRYPTION_KEY must be set separately — no fallback to audit key (MEDIUM-03)
            db_encryption_key: env::var("DB_ENCRYPTION_KEY").ok(),
            public_url: env::var("ORACLE_PUBLIC_URL").ok(),
            node_secret: env::var("NODE_SECRET").ok(),
            xaman_api_key: env::var("XAMAN_API_KEY").ok(),
            xaman_api_secret: env::var("XAMAN_API_SECRET").ok(),
            xaman_force_network: env::var("XAMAN_FORCE_NETWORK").ok(),
            xrpl_wallet_seed_file: env::var("XRPL_WALLET_SEED_FILE").ok(),
            // HIGH-01: Trusted proxy IPs (comma-separated)
            // Example: TRUSTED_PROXIES=10.0.0.1,10.0.0.2,172.17.0.1
            trusted_proxies: env::var("TRUSTED_PROXIES")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_else(|_| Vec::new()),
            // Auth rate limit: default 10 req/min (stricter than general 60 req/min)
            auth_rate_limit_rpm: env::var("AUTH_RATE_LIMIT_RPM")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
        })
    }

    /// CRIT-03: Securely load wallet seed
    ///
    /// Priority:
    /// 1. XRPL_WALLET_SEED_FILE — read from file with permission check
    /// 2. XRPL_WALLET_SEED env var — only in development (BLOCKED in production)
    ///
    /// In production, env vars are visible via /proc/environ, crash dumps,
    /// logging frameworks, and container inspection. File-based secrets
    /// with strict permissions (0600) are significantly more secure.
    fn load_wallet_seed(environment: &str) -> Result<Option<String>, ConfigError> {
        let is_production = environment == "production";

        // Priority 1: File-based seed
        if let Ok(seed_file_path) = env::var("XRPL_WALLET_SEED_FILE") {
            let path = std::path::Path::new(&seed_file_path);

            if !path.exists() {
                return Err(ConfigError::InvalidValue(format!(
                    "XRPL_WALLET_SEED_FILE points to non-existent file: {}",
                    seed_file_path
                )));
            }

            // Check file permissions on Unix (must be 0600 — owner r/w only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(path).map_err(|e| {
                    ConfigError::InvalidValue(format!(
                        "Cannot read XRPL_WALLET_SEED_FILE metadata: {}", e
                    ))
                })?;
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o600 && mode != 0o400 {
                    return Err(ConfigError::InvalidValue(format!(
                        "XRPL_WALLET_SEED_FILE has unsafe permissions: {:o} (must be 0600 or 0400). \
                         Fix with: chmod 600 {}",
                        mode, seed_file_path
                    )));
                }
            }

            let seed = std::fs::read_to_string(path)
                .map_err(|e| ConfigError::InvalidValue(format!(
                    "Failed to read XRPL_WALLET_SEED_FILE: {}", e
                )))?
                .trim()
                .to_string();

            if seed.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "XRPL_WALLET_SEED_FILE is empty".to_string()
                ));
            }

            return Ok(Some(seed));
        }

        // Priority 2: Env var (development only)
        if let Ok(seed) = env::var("XRPL_WALLET_SEED") {
            if is_production {
                // CRIT-03: BLOCK env-based seed in production
                return Err(ConfigError::InvalidValue(
                    "XRPL_WALLET_SEED via environment variable is BLOCKED in production. \
                     Use XRPL_WALLET_SEED_FILE instead (a file with chmod 600). \
                     Environment variables are visible via /proc/environ, crash dumps, \
                     and container inspection, making them insecure for wallet seeds."
                        .to_string(),
                ));
            }
            return Ok(Some(seed));
        }

        // No seed configured — Oracle will run in read-only mode
        Ok(None)
    }

    /// Возвращает адрес для прослушивания
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}

/// Ошибки конфигурации
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(String),
    #[error("Invalid value for environment variable: {0}")]
    InvalidValue(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listen_addr() {
        let config = Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            database_url: "postgres://localhost/test".to_string(),
            redis_url: None,
            xrpl_node_url: None,
            xrpl_wallet_seed: None,
            jwt_secret: "secret".to_string(),
            jwt_expiration_hours: 24,
            max_file_size: 1000,
            min_replication: 2,
            rate_limit_rpm: 60,
            cors_origins: Vec::new(),
            environment: "development".to_string(),
            audit_encryption_key: None,
            db_encryption_key: None,
            public_url: None,
            node_secret: None,
            xrpl_wallet_seed_file: None,
            trusted_proxies: Vec::new(),
            auth_rate_limit_rpm: 10,
        };
        assert_eq!(config.listen_addr(), "127.0.0.1:8080");
    }
}