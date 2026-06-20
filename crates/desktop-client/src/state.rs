//! Application state
//!
//! Stores the current session, keys, and configuration.
//!
//! Vaulted identity keys are derived from the Vaulted seed phrase and kept only in memory.
//! The bundled wallet layer derives XRPL signing keys from the Vaulted seed with a separate domain; external wallet signing is not required.

use std::sync::Arc;
use tokio::sync::RwLock;
use xrpl_vault_crypto_core::{
    pre::{PreKeyPair, PrePublicKey, ProxyReEncryption},
    VaultedIdentityKeys, VaultedXrplWallet,
};

use crate::{
    auth::Session,
    error::{ClientError, Result},
};

/// Application configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Oracle server URL
    pub oracle_url: String,
    /// XRPL node URL (WebSocket)
    pub xrpl_node_url: String,
    /// Maximum file size (bytes)
    pub max_file_size: u64,
    /// Fragment size (bytes)
    pub fragment_size: usize,
    /// URL Storage Node
    pub storage_node_url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            oracle_url: "http://localhost:3000".to_string(),
            xrpl_node_url: "wss://s.altnet.rippletest.net:51233".to_string(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            fragment_size: 1024 * 1024,       // 1MB
            storage_node_url: "http://localhost:9001".to_string(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use xrpl_vault_crypto_core::{SeedManager, DEFAULT_MNEMONIC_WORDS};

    #[tokio::test]
    async fn app_state_starts_locked_and_unlocks_from_mnemonic() {
        let state = AppState::new(AppConfig::default()).unwrap();

        assert!(!state.has_active_session().await);
        assert!(!state.has_vaulted_identity().await);
        assert!(!state.has_xrpl_wallet().await);

        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        state
            .init_vaulted_identity_from_mnemonic(&mnemonic, None)
            .await
            .unwrap();

        assert!(state.has_vaulted_identity().await);
        assert!(state.has_xrpl_wallet().await);
    }

    #[tokio::test]
    async fn clear_session_locks_memory_only_wallet_state() {
        let state = AppState::new(AppConfig::default()).unwrap();
        let fingerprint = state.device_fingerprint().to_string();
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        state
            .init_vaulted_identity_from_mnemonic(&mnemonic, None)
            .await
            .unwrap();

        assert!(state.has_vaulted_identity().await);
        assert!(state.has_xrpl_wallet().await);

        state.clear_session().await;

        assert!(!state.has_active_session().await);
        assert!(!state.has_vaulted_identity().await);
        assert!(!state.has_xrpl_wallet().await);
        assert_eq!(state.device_fingerprint(), fingerprint);
    }
}

impl AppConfig {
    /// Loads configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            oracle_url: std::env::var("ORACLE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            xrpl_node_url: std::env::var("XRPL_NODE_URL")
                .unwrap_or_else(|_| "wss://s.altnet.rippletest.net:51233".to_string()),
            max_file_size: std::env::var("MAX_FILE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024),
            fragment_size: std::env::var("FRAGMENT_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024),
            storage_node_url: std::env::var("STORAGE_NODE_URL")
                .unwrap_or_else(|_| "http://localhost:9001".to_string()),
        }
    }
}

/// Application state (thread-safe)
pub struct AppState {
    /// Configuration
    pub config: AppConfig,
    /// Current user session
    session: RwLock<Option<Session>>,
    /// PRE context (thread-safe)
    pre: ProxyReEncryption,
    /// Legacy PRE keypair - derived from Vaulted seed only for compatibility/migration.
    keypair: RwLock<Option<PreKeyPair>>,
    /// Vaulted seed-based identity keys - stored only in memory.
    vaulted_identity: RwLock<Option<VaultedIdentityKeys>>,
    /// Vaulted-owned XRPL wallet keys - stored only in memory after unlock.
    xrpl_wallet: RwLock<Option<VaultedXrplWallet>>,
    /// HTTP client
    http_client: reqwest::Client,
    /// Device fingerprint (unique per app instance, persisted)
    device_fingerprint: String,
}

impl AppState {
    /// Creates new application state
    pub fn new(config: AppConfig) -> Result<Arc<Self>> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let device_fingerprint = Self::load_or_generate_fingerprint();

        Ok(Arc::new(Self {
            config,
            session: RwLock::new(None),
            pre: ProxyReEncryption::new(),
            keypair: RwLock::new(None),
            vaulted_identity: RwLock::new(None),
            xrpl_wallet: RwLock::new(None),
            http_client,
            device_fingerprint,
        }))
    }

    /// Generate or load persistent device fingerprint
    fn load_or_generate_fingerprint() -> String {
        use sha2::{Digest, Sha256};

        // Try to load saved fingerprint
        if let Some(project_dirs) = directories::ProjectDirs::from("com", "xrplvault", "xrplvault")
        {
            let fp_path = project_dirs.data_dir().join("device.fingerprint");
            let obfuscation_key = Self::derive_obfuscation_key(project_dirs.data_dir());

            if let Ok(raw_bytes) = std::fs::read(&fp_path) {
                // Deobfuscate: XOR with machine-specific key
                let fp_bytes: Vec<u8> = raw_bytes
                    .iter()
                    .zip(obfuscation_key.iter().cycle())
                    .map(|(a, b)| a ^ b)
                    .collect();
                if let Ok(fp) = String::from_utf8(fp_bytes) {
                    let fp = fp.trim().to_string();
                    if fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
                        tracing::debug!("Loaded device fingerprint: {}...", &fp[..8]);
                        return fp;
                    }
                }
            }

            // Generate new fingerprint from system info
            let mut hasher = Sha256::new();

            // Hostname
            if let Ok(hostname) = hostname::get() {
                hasher.update(hostname.to_string_lossy().as_bytes());
            }

            // OS info
            hasher.update(std::env::consts::OS.as_bytes());
            hasher.update(std::env::consts::ARCH.as_bytes());

            // Persistent random component (survives reboots)
            let random_component = uuid::Uuid::new_v4().to_string();
            hasher.update(random_component.as_bytes());

            // Data directory path (unique per user/OS install)
            hasher.update(project_dirs.data_dir().to_string_lossy().as_bytes());

            let fp = hex::encode(hasher.finalize());

            // Save obfuscated (XOR with machine key) + restrictive permissions
            let _ = std::fs::create_dir_all(project_dirs.data_dir());
            let obfuscated: Vec<u8> = fp
                .as_bytes()
                .iter()
                .zip(obfuscation_key.iter().cycle())
                .map(|(a, b)| a ^ b)
                .collect();
            let _ = std::fs::write(&fp_path, &obfuscated);

            // Set restrictive permissions (Unix: owner read/write only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&fp_path, std::fs::Permissions::from_mode(0o600));
            }

            tracing::info!("Generated new device fingerprint: {}...", &fp[..8]);
            return fp;
        }

        // Fallback: random per session
        let fp = hex::encode(uuid::Uuid::new_v4().as_bytes());
        tracing::warn!("Using ephemeral device fingerprint (no persistent storage)");
        fp
    }

    /// Derive a machine-specific obfuscation key for fingerprint storage
    fn derive_obfuscation_key(data_dir: &std::path::Path) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"xrpl-vault-dfp-obfuscation-v1");
        hasher.update(data_dir.to_string_lossy().as_bytes());
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Returns device fingerprint
    pub fn device_fingerprint(&self) -> &str {
        &self.device_fingerprint
    }

    /// Returns the PRE context
    pub fn pre(&self) -> &ProxyReEncryption {
        &self.pre
    }

    /// Returns the HTTP client
    pub fn http(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Checks whether an active session exists
    pub async fn is_authenticated(&self) -> bool {
        let session = self.session.read().await;
        session.as_ref().map(|s| !s.is_expired()).unwrap_or(false)
    }

    /// Checks whether an active, non-expired session exists in memory.
    pub async fn has_active_session(&self) -> bool {
        self.is_authenticated().await
    }

    /// Returns the current session
    pub async fn get_session(&self) -> Result<Session> {
        let session = self.session.read().await;
        match session.as_ref() {
            Some(s) if !s.is_expired() => Ok(s.clone()),
            Some(_) => Err(ClientError::SessionExpired),
            None => Err(ClientError::NoSession),
        }
    }

    /// Sets the session after authorization
    pub async fn set_session(&self, session: Session) {
        let mut guard = self.session.write().await;
        *guard = Some(session);
    }

    /// Clears the session (logout)
    pub async fn clear_session(&self) {
        let mut session_guard = self.session.write().await;
        *session_guard = None;
        let mut keypair_guard = self.keypair.write().await;
        *keypair_guard = None;
        let mut identity_guard = self.vaulted_identity.write().await;
        *identity_guard = None;
        let mut wallet_guard = self.xrpl_wallet.write().await;
        *wallet_guard = None;
        tracing::info!("Session, Vaulted identity, Vaulted XRPL wallet and legacy PRE keypair cleared from memory");
    }

    /// Returns the current user wallet address
    pub async fn wallet_address(&self) -> Result<String> {
        let session = self.get_session().await?;
        Ok(session.wallet_address)
    }

    /// Initializes legacy PRE keys from a Vaulted-seed-derived migration seed.
    ///
    /// This must never be called with external-wallet DER/signature material. It exists only
    /// to keep current upload/download flows operational while manifests/key envelopes
    /// are rolled out across the app.
    pub async fn init_keypair_from_seed(
        &self,
        wallet_address: &str,
        mut seed: [u8; 32],
    ) -> Result<()> {
        // Generate a keypair from the seed
        let keypair = self.pre.generate_keypair_from_seed(&seed)?;

        // Zeroize the seed immediately after use
        use zeroize::Zeroize;
        seed.zeroize();

        // Store ONLY in memory
        let mut guard = self.keypair.write().await;
        *guard = Some(keypair);

        tracing::info!(
            "Legacy PRE keypair initialized from Vaulted identity for {} (session-only, not persisted to disk)", 
            wallet_address
        );
        Ok(())
    }

    /// Initializes Vaulted identity and compatibility PRE state from a BIP-39 mnemonic.
    pub async fn init_vaulted_identity_from_mnemonic(
        &self,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> Result<VaultedIdentityKeys> {
        let identity = VaultedIdentityKeys::from_mnemonic(mnemonic, passphrase)?;
        let xrpl_wallet = VaultedXrplWallet::from_mnemonic(mnemonic, passphrase)?;
        let mut legacy_seed = identity.legacy_pre_seed();
        let legacy_keypair = self.pre.generate_keypair_from_seed(&legacy_seed)?;
        use zeroize::Zeroize;
        legacy_seed.zeroize();

        {
            let mut guard = self.vaulted_identity.write().await;
            *guard = Some(identity.clone());
        }
        {
            let mut guard = self.keypair.write().await;
            *guard = Some(legacy_keypair);
        }
        {
            let mut guard = self.xrpl_wallet.write().await;
            *guard = Some(xrpl_wallet);
        }

        tracing::info!(
            "Vaulted identity and XRPL wallet unlocked: identity_id={}, signing_pk={}..., encryption_pk={}...",
            identity.identity_id_hex(),
            &identity.signing_public_key_hex()[..16],
            &identity.encryption_public_key_hex()[..16]
        );
        Ok(identity)
    }

    /// Returns current Vaulted identity if unlocked.
    pub async fn get_vaulted_identity(&self) -> Result<VaultedIdentityKeys> {
        let guard = self.vaulted_identity.read().await;
        guard.clone().ok_or_else(|| {
            ClientError::Auth(
                "Vaulted wallet is locked. Create or restore it from seed phrase first."
                    .to_string(),
            )
        })
    }

    /// Checks whether seed-based Vaulted identity is loaded.
    pub async fn has_vaulted_identity(&self) -> bool {
        self.vaulted_identity.read().await.is_some()
    }

    /// Returns current Vaulted-owned XRPL wallet if unlocked.
    pub async fn get_xrpl_wallet(&self) -> Result<VaultedXrplWallet> {
        let guard = self.xrpl_wallet.read().await;
        guard.clone().ok_or_else(|| {
            ClientError::Auth(
                "Vaulted wallet is locked. Create or restore it from seed phrase first."
                    .to_string(),
            )
        })
    }

    /// Checks whether the Vaulted-owned XRPL wallet is loaded in memory.
    pub async fn has_xrpl_wallet(&self) -> bool {
        self.xrpl_wallet.read().await.is_some()
    }

    /// Checks whether a keypair is in memory
    pub async fn has_keypair(&self) -> bool {
        let guard = self.keypair.read().await;
        guard.is_some()
    }

    /// Returns the keypair from memory (cloned)
    pub async fn get_keypair(&self) -> Result<PreKeyPair> {
        let guard = self.keypair.read().await;
        guard.clone().ok_or_else(|| {
            ClientError::Auth(
                "Vaulted wallet is locked. Create or restore it from seed phrase first."
                    .to_string(),
            )
        })
    }

    /// Returns the PRE public key in hex format
    pub async fn get_public_key_hex(&self) -> Result<String> {
        let keypair = self.get_keypair().await?;
        Ok(hex::encode(keypair.export_public_key_bytes()))
    }

    /// Returns the PRE public key
    pub async fn get_public_key(&self) -> Result<PrePublicKey> {
        let keypair = self.get_keypair().await?;
        Ok(keypair.public_key())
    }

    /// Returns Oracle JWT token for API authentication
    pub async fn get_oracle_token(&self) -> Result<String> {
        let session = self.get_session().await?;
        session.oracle_token.ok_or_else(|| {
            ClientError::Auth("Oracle token not available. Please sign in again.".to_string())
        })
    }

    /// Sets Oracle token in current session
    pub async fn set_oracle_token(&self, token: String) -> Result<()> {
        let mut guard = self.session.write().await;
        if let Some(ref mut session) = *guard {
            session.set_oracle_token(token);
            Ok(())
        } else {
            Err(ClientError::NoSession)
        }
    }

    /// Sets Oracle token with custom expiry (in seconds)
    pub async fn set_oracle_token_with_expiry(
        &self,
        token: String,
        expires_in_secs: i64,
    ) -> Result<()> {
        let mut guard = self.session.write().await;
        if let Some(ref mut session) = *guard {
            session.set_oracle_token_with_expiry(token, expires_in_secs);
            Ok(())
        } else {
            Err(ClientError::NoSession)
        }
    }

    /// Saves complete token response (access + refresh + device_fingerprint + role)
    pub async fn save_oracle_tokens(
        &self,
        access_token: String,
        expires_in: i64,
        refresh_token: Option<String>,
        role: Option<String>,
    ) -> Result<()> {
        let mut guard = self.session.write().await;
        if let Some(ref mut session) = *guard {
            session.set_oracle_token_with_expiry(access_token, expires_in);
            if let Some(rt) = refresh_token {
                session.set_refresh_token(rt);
            }
            if let Some(r) = role {
                session.set_role(r);
            }
            // Always save device fingerprint
            session.set_device_fingerprint(self.device_fingerprint.clone());
            Ok(())
        } else {
            Err(ClientError::NoSession)
        }
    }

    /// Attempt to refresh the Oracle token using stored refresh token
    pub async fn try_refresh_oracle_token(&self) -> Result<bool> {
        let refresh_tok = {
            let session = self.session.read().await;
            match session.as_ref() {
                Some(s) => s.refresh_token.clone(),
                None => return Err(ClientError::NoSession),
            }
        };

        let refresh_tok = match refresh_tok {
            Some(rt) => rt,
            None => return Err(ClientError::Auth("No refresh token available".into())),
        };

        match self.refresh_oracle_token_internal(&refresh_tok).await {
            Ok((new_access, new_refresh, expires_in, role)) => {
                let mut guard = self.session.write().await;
                if let Some(ref mut s) = *guard {
                    s.update_tokens(new_access, new_refresh, expires_in, role);
                }
                tracing::info!("Oracle token refreshed successfully");
                Ok(true)
            },
            Err(e) => {
                tracing::warn!("Token refresh failed: {}", e);
                Err(ClientError::Auth(format!("Token refresh failed: {}", e)))
            },
        }
    }

    /// Returns Authorization header value for Oracle API
    pub async fn get_auth_header(&self) -> Result<String> {
        let token = self.get_oracle_token().await?;
        Ok(format!("Bearer {}", token))
    }

    /// Creates an HTTP client with Authorization header pre-configured.
    /// If the access token is missing/expired, attempts refresh before falling back.
    pub async fn create_authed_client(&self) -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();

        if !self.has_oracle_token().await {
            if let Err(e) = self.try_refresh_oracle_token().await {
                tracing::warn!("Oracle token refresh before request failed: {}", e);
            }
        }

        match self.get_auth_header().await {
            Ok(auth) => {
                if let Ok(val) = reqwest::header::HeaderValue::from_str(&auth) {
                    headers.insert(reqwest::header::AUTHORIZATION, val);
                } else {
                    tracing::warn!("Invalid Oracle authorization header");
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Creating HTTP client without Oracle Authorization header: {}",
                    e
                );
            },
        }

        if let Ok(dfp) = self.device_fingerprint_header() {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&dfp) {
                headers.insert("X-Device-Fingerprint", val);
            }
        }

        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    fn device_fingerprint_header(&self) -> Result<String> {
        Ok(self.device_fingerprint.clone())
    }

    /// Check if we have a valid Oracle token
    pub async fn has_oracle_token(&self) -> bool {
        if let Ok(session) = self.get_session().await {
            session.oracle_token.is_some() && !session.oracle_token_is_expired()
        } else {
            false
        }
    }

    /// Check if Oracle token needs refresh (expires in < 5 minutes)
    pub async fn oracle_token_needs_refresh(&self) -> bool {
        if let Ok(session) = self.get_session().await {
            session.oracle_token_needs_refresh()
        } else {
            false
        }
    }

    /// Creates OracleClient with auth token (if available)
    pub async fn get_oracle_client(&self) -> Result<crate::oracle::OracleClient> {
        self.get_oracle_client_with_timeout(60).await
    }

    /// Creates OracleClient with custom timeout and auth token (if available)
    /// Auto-refreshes token if it's about to expire (< 5 minutes)
    pub async fn get_oracle_client_with_timeout(
        &self,
        timeout_secs: u64,
    ) -> Result<crate::oracle::OracleClient> {
        let config = crate::oracle::OracleConfig {
            base_url: self.config.oracle_url.clone(),
            timeout_secs,
            ..Default::default()
        };
        let mut client = crate::oracle::OracleClient::new(config)?;

        // Set device fingerprint for all requests
        client.set_device_fingerprint(self.device_fingerprint.clone());

        // Check token status and auto-refresh if needed
        if let Ok(session) = self.get_session().await {
            if let Some(ref token) = session.oracle_token {
                if session.oracle_token_is_expired() {
                    // Token expired — try refresh
                    if let Some(ref refresh_tok) = session.refresh_token {
                        tracing::info!("Access token expired, attempting refresh...");
                        match self.refresh_oracle_token_internal(refresh_tok).await {
                            Ok((new_access, new_refresh, expires_in, role)) => {
                                // Update session
                                let mut session_guard = self.session.write().await;
                                if let Some(ref mut s) = *session_guard {
                                    s.update_tokens(
                                        new_access.clone(),
                                        new_refresh,
                                        expires_in,
                                        role,
                                    );
                                }
                                client.set_auth_token(new_access);
                                tracing::info!("Token refreshed successfully");
                            },
                            Err(e) => {
                                tracing::warn!("Token refresh failed: {} — clearing session", e);
                                // Clear tokens so has_oracle_token() returns false
                                let mut session_guard = self.session.write().await;
                                if let Some(ref mut s) = *session_guard {
                                    s.oracle_token = None;
                                    s.oracle_token_expires_at = None;
                                    s.refresh_token = None;
                                }
                                return Err(ClientError::Auth(
                                    "Token expired and refresh failed. Please sign in again."
                                        .to_string(),
                                ));
                            },
                        }
                    } else {
                        // No refresh token — clear expired access token
                        let mut session_guard = self.session.write().await;
                        if let Some(ref mut s) = *session_guard {
                            s.oracle_token = None;
                            s.oracle_token_expires_at = None;
                        }
                        return Err(ClientError::Auth(
                            "Oracle token expired. Please sign in again.".to_string(),
                        ));
                    }
                } else if session.oracle_token_needs_refresh() {
                    // Token expires soon — refresh in background, use current token
                    if let Some(ref refresh_tok) = session.refresh_token {
                        let refresh_tok = refresh_tok.clone();
                        tracing::info!("Token expires soon, refreshing proactively...");
                        match self.refresh_oracle_token_internal(&refresh_tok).await {
                            Ok((new_access, new_refresh, expires_in, role)) => {
                                let mut session_guard = self.session.write().await;
                                if let Some(ref mut s) = *session_guard {
                                    s.update_tokens(
                                        new_access.clone(),
                                        new_refresh,
                                        expires_in,
                                        role,
                                    );
                                }
                                client.set_auth_token(new_access);
                                tracing::info!("Token proactively refreshed");
                            },
                            Err(e) => {
                                tracing::warn!("Proactive session refresh failed: {} — clearing stored refresh credential to stop retries", e);
                                // Clear refresh token so we don't keep hammering the server
                                {
                                    let mut session_guard = self.session.write().await;
                                    if let Some(ref mut s) = *session_guard {
                                        s.refresh_token = None;
                                    }
                                }
                                // Still use current access token if not expired
                                if !session.oracle_token_is_expired() {
                                    client.set_auth_token(token.clone());
                                } else {
                                    // Access token also expired — clear everything
                                    let mut session_guard = self.session.write().await;
                                    if let Some(ref mut s) = *session_guard {
                                        s.oracle_token = None;
                                        s.oracle_token_expires_at = None;
                                    }
                                    return Err(ClientError::Auth(
                                        "Session expired. Please sign in again.".to_string(),
                                    ));
                                }
                            },
                        }
                    } else {
                        client.set_auth_token(token.clone());
                    }
                } else {
                    client.set_auth_token(token.clone());
                }
            }
        }

        Ok(client)
    }

    /// Internal: call Oracle /auth/refresh endpoint
    async fn refresh_oracle_token_internal(
        &self,
        refresh_token: &str,
    ) -> std::result::Result<(String, Option<String>, i64, Option<String>), String> {
        let url = format!("{}/api/v1/auth/refresh", self.config.oracle_url);

        let response = self
            .http_client
            .post(&url)
            .header("X-Device-Fingerprint", &self.device_fingerprint)
            .json(&serde_json::json!({
                "refresh_token": refresh_token
            }))
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(format!("Refresh failed: HTTP {}", status));
        }

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        let access_token = data["access_token"]
            .as_str()
            .ok_or("Missing access_token in refresh response")?
            .to_string();
        let new_refresh = data["refresh_token"].as_str().map(|s| s.to_string());
        let expires_in = data["expires_in"].as_i64().unwrap_or(3600);
        let role = data["role"].as_str().map(|s| s.to_string());

        Ok((access_token, new_refresh, expires_in, role))
    }
}
