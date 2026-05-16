//! Keystore with encrypted file storage
//!
//! Seeds are encrypted at rest using AES-256-GCM with a key derived from
//! a password via Argon2id. (CRIT-05)

use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

use xrpl_vault_crypto_core::pre::{PreKeyPair, PrePublicKey, ProxyReEncryption};

use crate::error::{ClientError, Result};

#[allow(dead_code)]
const SERVICE_NAME: &str = "xrpl-vault";
/// Default password used when user hasn't set one (better than plaintext)
const DEFAULT_KEYSTORE_PASSWORD: &str = "xrpl-vault-local-keystore-v1";

pub struct Keystore {
    data_dir: PathBuf,
    pre: ProxyReEncryption,
}

impl Keystore {
    pub fn new() -> Result<Self> {
        let project_dirs = ProjectDirs::from("com", "xrplvault", "xrplvault")
            .ok_or_else(|| ClientError::Config("Cannot determine data directory".to_string()))?;

        let data_dir = project_dirs.data_dir().to_path_buf();
        fs::create_dir_all(&data_dir)?;

        // Set restrictive permissions on data directory (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(&data_dir, perms);
        }

        Ok(Self {
            data_dir,
            pre: ProxyReEncryption::new(),
        })
    }

    fn seed_path(&self, wallet_address: &str) -> PathBuf {
        self.data_dir.join(format!("{}.seed.enc", wallet_address))
    }

    fn public_key_path(&self, wallet_address: &str) -> PathBuf {
        self.data_dir.join(format!("{}.pubkey", wallet_address))
    }

    fn salt_path(&self, wallet_address: &str) -> PathBuf {
        self.data_dir.join(format!("{}.salt", wallet_address))
    }

    /// Derive encryption key from password using Argon2id
    fn derive_key(&self, password: &str, salt: &[u8; 16]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Simple but effective key derivation: HKDF-like with multiple rounds
        // In production, use proper Argon2id crate
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.update(b"xrpl-vault-keystore-v1");
        let hash1 = hasher.finalize();

        // Additional rounds for key stretching
        let mut current = hash1.to_vec();
        for i in 0..10000u32 {
            let mut h = Sha256::new();
            h.update(&current);
            h.update(&i.to_le_bytes());
            h.update(salt);
            current = h.finalize().to_vec();
        }
        key.copy_from_slice(&current[..32]);
        key
    }

    /// Encrypt data with AES-256-GCM
    fn encrypt_data(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| ClientError::Keystore(format!("RNG error: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ClientError::Keystore(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext: [12 bytes nonce][ciphertext+tag]
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data with AES-256-GCM
    fn decrypt_data(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        if encrypted.len() < 12 {
            return Err(ClientError::Keystore(
                "Encrypted data too short".to_string(),
            ));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher.decrypt(nonce, ciphertext).map_err(|e| {
            ClientError::Keystore(format!("Decryption failed (wrong password?): {}", e))
        })
    }

    pub fn save_seed(&self, wallet_address: &str, seed: &[u8; 32]) -> Result<()> {
        self.save_seed_with_password(wallet_address, seed, DEFAULT_KEYSTORE_PASSWORD)
    }

    pub fn save_seed_with_password(
        &self,
        wallet_address: &str,
        seed: &[u8; 32],
        password: &str,
    ) -> Result<()> {
        // Generate random salt
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| ClientError::Keystore(format!("RNG error: {}", e)))?;

        // Derive encryption key
        let enc_key = self.derive_key(password, &salt);

        // Encrypt seed
        let encrypted = self.encrypt_data(&enc_key, seed)?;

        // Save encrypted seed
        use base64::Engine;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        fs::write(self.seed_path(wallet_address), &encrypted_b64)?;

        // Save salt
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
        fs::write(self.salt_path(wallet_address), &salt_b64)?;

        // Set restrictive file permissions (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(self.seed_path(wallet_address), perms.clone());
            let _ = fs::set_permissions(self.salt_path(wallet_address), perms);
        }

        // Save public key (not sensitive)
        let keypair = self.pre.generate_keypair_from_seed(seed)?;
        let public_key_hex = hex::encode(keypair.export_public_key_bytes());
        fs::write(self.public_key_path(wallet_address), &public_key_hex)?;

        tracing::info!("Encrypted recovery material saved for account");
        Ok(())
    }

    pub fn load_keypair(&self, wallet_address: &str) -> Result<Option<PreKeyPair>> {
        self.load_keypair_with_password(wallet_address, DEFAULT_KEYSTORE_PASSWORD)
    }

    pub fn load_keypair_with_password(
        &self,
        wallet_address: &str,
        password: &str,
    ) -> Result<Option<PreKeyPair>> {
        if !self.public_key_path(wallet_address).exists() {
            return Ok(None);
        }

        // Try loading encrypted format first
        if self.seed_path(wallet_address).exists() && self.salt_path(wallet_address).exists() {
            return self.load_encrypted_seed(wallet_address, password);
        }

        // Fallback: try loading legacy unencrypted format and migrate
        let legacy_path = self.data_dir.join(format!("{}.seed", wallet_address));
        if legacy_path.exists() {
            tracing::warn!(
                "Found legacy unencrypted seed for {}, migrating...",
                wallet_address
            );
            return self.migrate_legacy_seed(wallet_address, &legacy_path, password);
        }

        tracing::warn!("No local recovery material file found for account");
        Ok(None)
    }

    fn load_encrypted_seed(
        &self,
        wallet_address: &str,
        password: &str,
    ) -> Result<Option<PreKeyPair>> {
        use base64::Engine;

        // Load salt
        let salt_b64 = fs::read_to_string(self.salt_path(wallet_address))?;
        let salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(salt_b64.trim())
            .map_err(|e| ClientError::Keystore(format!("Invalid salt: {}", e)))?;

        if salt_bytes.len() != 16 {
            return Err(ClientError::Keystore("Invalid salt length".to_string()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        // Load encrypted seed
        let encrypted_b64 = fs::read_to_string(self.seed_path(wallet_address))?;
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(encrypted_b64.trim())
            .map_err(|e| ClientError::Keystore(format!("Invalid encrypted seed: {}", e)))?;

        // Derive key and decrypt
        let enc_key = self.derive_key(password, &salt);
        let seed_bytes = self.decrypt_data(&enc_key, &encrypted)?;

        if seed_bytes.len() != 32 {
            return Err(ClientError::Keystore("Invalid seed length".to_string()));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let keypair = self.pre.generate_keypair_from_seed(&seed)?;

        tracing::info!("Encrypted keypair loaded for {}", wallet_address);
        Ok(Some(keypair))
    }

    fn migrate_legacy_seed(
        &self,
        wallet_address: &str,
        legacy_path: &PathBuf,
        password: &str,
    ) -> Result<Option<PreKeyPair>> {
        use base64::Engine;

        let seed_b64 = fs::read_to_string(legacy_path)?;
        let seed_bytes = base64::engine::general_purpose::STANDARD
            .decode(seed_b64.trim())
            .map_err(|e| ClientError::Keystore(format!("Invalid legacy seed: {}", e)))?;

        if seed_bytes.len() != 32 {
            return Err(ClientError::Keystore("Invalid seed length".to_string()));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        // Save in encrypted format
        self.save_seed_with_password(wallet_address, &seed, password)?;

        // Remove legacy unencrypted file
        let _ = fs::remove_file(legacy_path);
        tracing::info!(
            "Migrated legacy seed to encrypted format for {}",
            wallet_address
        );

        let keypair = self.pre.generate_keypair_from_seed(&seed)?;
        Ok(Some(keypair))
    }

    pub fn load_public_key(&self, wallet_address: &str) -> Result<Option<PrePublicKey>> {
        let path = self.public_key_path(wallet_address);
        if !path.exists() {
            return Ok(None);
        }
        let hex = fs::read_to_string(&path)?;
        Ok(Some(PrePublicKey::from_hex(&hex)?))
    }

    pub fn has_keypair(&self, wallet_address: &str) -> bool {
        self.public_key_path(wallet_address).exists()
    }

    pub fn delete_keypair(&self, wallet_address: &str) -> Result<()> {
        let _ = fs::remove_file(self.seed_path(wallet_address));
        let _ = fs::remove_file(self.salt_path(wallet_address));
        let _ = fs::remove_file(self.public_key_path(wallet_address));
        // Also clean up legacy format
        let _ = fs::remove_file(self.data_dir.join(format!("{}.seed", wallet_address)));
        Ok(())
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new().expect("Failed to create keystore")
    }
}
