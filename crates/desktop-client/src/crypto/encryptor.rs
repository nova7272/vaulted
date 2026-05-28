//! File encryption
//!
//! Process:
//! 1. Generate an AES-256 key
//! 2. Encrypt the whole file
//! 3. Encrypt the AES key through PRE (with the public key)
//! 4. Create a manifest with a hash

use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use xrpl_vault_crypto_core::{
    aes::AesKey,
    hash::{blake3_prefixed, sha256_prefixed},
    pre::{EncryptedPreData, PrePublicKey, ProxyReEncryption},
    types::{EncryptedData, FileManifest},
};

use crate::error::Result;

/// File encryption result
#[derive(Debug)]
pub struct EncryptedFile {
    /// Encrypted AES key (for storage in NFT metadata)
    pub encrypted_aes_key: EncryptedPreData,
    /// File manifest
    pub manifest: FileManifest,
    /// Encrypted data (one blob)
    pub encrypted_data: EncryptedData,
    /// Encrypted data hash
    pub encrypted_hash: String,
}

/// File encryptor
pub struct FileEncryptor {
    pre: ProxyReEncryption,
}

impl FileEncryptor {
    /// Creates a new encryptor
    pub fn new(_fragment_size: usize) -> Self {
        // fragment_size ignored - kept for API compatibility
        Self {
            pre: ProxyReEncryption::new(),
        }
    }

    /// Encrypts the whole file
    ///
    /// # Arguments
    /// * `file_path` - path to the file
    /// * `owner_public_key` - owner PRE public key
    ///
    /// # Returns
    /// Encrypted file with manifest
    pub async fn encrypt_file(
        &self,
        file_path: &Path,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        // Get file metadata
        let metadata = tokio::fs::metadata(file_path).await?;
        let file_size = metadata.len();

        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mime_type = mime_guess::from_path(file_path)
            .first_or_octet_stream()
            .to_string();

        tracing::info!(
            "Encrypting file: {} ({} bytes, {})",
            filename,
            file_size,
            mime_type
        );

        // Read the whole file
        let mut file = File::open(file_path).await?;
        let mut data = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut data).await?;

        // Encrypt
        self.encrypt_data(&data, &filename, &mime_type, owner_public_key)
    }

    /// Encrypts data from memory
    pub fn encrypt_bytes(
        &self,
        data: &[u8],
        filename: &str,
        mime_type: &str,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        self.encrypt_data(data, filename, mime_type, owner_public_key)
    }

    /// Internal data encryption method
    fn encrypt_data(
        &self,
        data: &[u8],
        filename: &str,
        mime_type: &str,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        // Generate an AES key
        let aes_key = AesKey::generate();

        // Original hash
        let original_hash = sha256_prefixed(data);

        // Encrypt all data
        let encrypted_data = aes_key.encrypt(data)?;
        let encrypted_bytes = encrypted_data.to_bytes()?;
        let encrypted_hash = blake3_prefixed(&encrypted_bytes);
        let encrypted_size = encrypted_bytes.len() as u64;

        tracing::info!(
            "File encrypted: {} bytes -> {} bytes, hash: {}",
            data.len(),
            encrypted_size,
            &encrypted_hash[..20]
        );

        // Encrypt the file name with the same AES key
        let encrypted_filename = aes_key.encrypt_to_base64(filename.as_bytes())?;

        // Create a manifest (without storage info - Oracle will add it)
        let manifest = FileManifest {
            encrypted_filename,
            original_size: data.len() as u64,
            mime_type: mime_type.to_string(),
            original_hash,
            encrypted_size,
            encrypted_hash: encrypted_hash.clone(),
        };

        // Encrypt the AES key with the owner public key
        let encrypted_aes_key = self.pre.encrypt(owner_public_key, aes_key.as_bytes())?;

        Ok(EncryptedFile {
            encrypted_aes_key,
            manifest,
            encrypted_data,
            encrypted_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_bytes() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let encryptor = FileEncryptor::new(1024);
        let data = b"Hello, XRPL Vault!";

        let encrypted = encryptor
            .encrypt_bytes(data, "test.txt", "text/plain", &keypair.public_key())
            .unwrap();

        // Privacy model: filename must not be stored as plaintext in the manifest.
        assert_ne!(encrypted.manifest.encrypted_filename, "test.txt");
        assert!(!encrypted.manifest.encrypted_filename.is_empty());

        // Recover AES file key and verify encrypted filename roundtrip.
        let aes_key_bytes = pre.decrypt(&keypair, &encrypted.encrypted_aes_key).unwrap();
        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let decrypted_filename = aes_key
            .decrypt_from_base64(&encrypted.manifest.encrypted_filename)
            .unwrap();

        assert_eq!(String::from_utf8(decrypted_filename).unwrap(), "test.txt");
        assert_eq!(encrypted.manifest.original_size, data.len() as u64);
        assert!(encrypted.manifest.original_hash.starts_with("sha256:"));
        assert!(encrypted.encrypted_hash.starts_with("blake3:"));
    }

    #[test]
    fn test_encrypt_large_data() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let encryptor = FileEncryptor::new(100);
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

        let encrypted = encryptor
            .encrypt_bytes(
                &data,
                "large.bin",
                "application/octet-stream",
                &keypair.public_key(),
            )
            .unwrap();

        // Now one blob instead of fragments
        assert_eq!(encrypted.manifest.original_size, 500);
        assert!(encrypted.manifest.encrypted_size > 500); // encrypted is larger due to nonce+tag
    }
}
