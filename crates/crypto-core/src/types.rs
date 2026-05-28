//! Shared types for the crypto module

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Encrypted data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Cryptographic scheme version
    pub version: u8,
    /// Nonce (IV) for AES-GCM
    pub nonce: Vec<u8>,
    /// Encrypted data with authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Creates a new encrypted data container
    pub fn new(version: u8, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            version,
            nonce,
            ciphertext,
        }
    }

    /// Serializes to binary format
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| crate::CryptoError::Serialization(e.to_string()))
    }

    /// Deserializes from binary format
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::CryptoError::Deserialization(e.to_string()))
    }

    /// Serializes to base64 (for storage in JSON/NFT metadata)
    pub fn to_base64(&self) -> crate::Result<String> {
        let bytes = self.to_bytes()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    /// Deserializes from base64
    pub fn from_base64(s: &str) -> crate::Result<Self> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
            .map_err(|e| crate::CryptoError::Deserialization(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Secret bytes that are automatically zeroized on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates from a byte vector
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks whether it is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED, {} bytes])", self.0.len())
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// NFT metadata with cryptographic information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCryptoMetadata {
    /// Scheme version
    pub version: u8,
    /// NFT ID in XRPL
    pub nft_id: String,
    /// Encrypted AES key (ECIES/PRE) - base64 encoded
    pub encrypted_aes_key: String,
    /// File manifest (fragment hashes)
    pub file_manifest: FileManifest,
    /// Current owner public key
    pub owner_public_key: String,
    /// Creation timestamp
    pub created_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
}

/// File manifest (fragment information)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Encrypted file name (AES-256-GCM, base64)
    pub encrypted_filename: String,
    /// Original file size in bytes
    pub original_size: u64,
    /// MIME type
    pub mime_type: String,
    /// Original file hash (for verification after decryption)
    pub original_hash: String,
    /// Encrypted data size
    pub encrypted_size: u64,
    /// Encrypted data hash (blake3)
    pub encrypted_hash: String,
}

impl FileManifest {
    /// Computes the manifest hash (for the NFT URI)
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let json = serde_json::to_string(self).unwrap_or_default();
        let hash = Sha256::digest(json.as_bytes());
        format!("sha256:{}", hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_data_roundtrip() {
        let data = EncryptedData::new(1, vec![1, 2, 3], vec![4, 5, 6, 7, 8]);

        let bytes = data.to_bytes().unwrap();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(data.version, restored.version);
        assert_eq!(data.nonce, restored.nonce);
        assert_eq!(data.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_encrypted_data_base64_roundtrip() {
        let data = EncryptedData::new(1, vec![1, 2, 3], vec![4, 5, 6, 7, 8]);

        let b64 = data.to_base64().unwrap();
        let restored = EncryptedData::from_base64(&b64).unwrap();

        assert_eq!(data.version, restored.version);
        assert_eq!(data.nonce, restored.nonce);
        assert_eq!(data.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        // Values will be zeroized on drop
    }

    #[test]
    fn test_file_manifest_hash() {
        let manifest = FileManifest {
            encrypted_filename: "test_encrypted_base64".to_string(),
            original_size: 1024,
            mime_type: "application/pdf".to_string(),
            original_hash: "sha256:abc123".to_string(),
            encrypted_size: 1040,
            encrypted_hash: "blake3:def456".to_string(),
        };

        let hash = manifest.compute_hash();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }
}
