//! AES-256-GCM encryption for files
//!
//! Uses authenticated encryption to protect confidentiality
//! and data integrity.
//!
//! ## Example
//!
//! ```rust,ignore
//! use xrpl_vault_crypto_core::aes::AesKey;
//!
//! // Generate a key
//! let key = AesKey::generate();
//!
//! // Encrypt
//! let plaintext = b"Hello, XRPL!";
//! let encrypted = key.encrypt(plaintext).unwrap();
//!
//! // Decrypt
//! let decrypted = key.decrypt(&encrypted).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::{
    error::{CryptoError, Result},
    types::{EncryptedData, SecretBytes},
    AES_KEY_SIZE, AES_NONCE_SIZE, CRYPTO_VERSION,
};

/// AES-256 key with secure memory handling
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct AesKey {
    key: [u8; AES_KEY_SIZE],
}

impl AesKey {
    /// Generates a new random AES-256 key
    pub fn generate() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Creates a key from bytes
    ///
    /// # Errors
    /// Returns an error if the size is not 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AES_KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: AES_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Returns the key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Returns the key as SecretBytes (for safe transfer)
    pub fn to_secret_bytes(&self) -> SecretBytes {
        SecretBytes::new(self.key.to_vec())
    }

    /// Encrypts data with AES-256-GCM
    ///
    /// # Arguments
    /// * `plaintext` - data to encrypt
    ///
    /// # Returns
    /// Encrypted data including the nonce and authentication tag
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        // Generate a random nonce (12 bytes for GCM)
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt (ciphertext includes the authentication tag)
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::AesEncryption(e.to_string()))?;

        Ok(EncryptedData::new(
            CRYPTO_VERSION,
            nonce_bytes.to_vec(),
            ciphertext,
        ))
    }

    /// Encrypts data with AAD (associated authenticated data) to bind the ciphertext to context.
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::AesEncryption(e.to_string()))?;

        Ok(EncryptedData::new(
            CRYPTO_VERSION,
            nonce_bytes.to_vec(),
            ciphertext,
        ))
    }

    /// Decrypts data with AAD and authentication tag verification.
    pub fn decrypt_with_aad(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.version != CRYPTO_VERSION {
            return Err(CryptoError::UnsupportedVersion(encrypted.version));
        }
        if encrypted.nonce.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: AES_NONCE_SIZE,
                actual: encrypted.nonce.len(),
            });
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&encrypted.nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted.ciphertext.as_ref(),
                    aad,
                },
            )
            .map_err(|_| CryptoError::AesDecryption("Authentication failed".to_string()))
    }

    /// Decrypts data
    ///
    /// # Arguments
    /// * `encrypted` - encrypted data
    ///
    /// # Returns
    /// Decrypted data
    ///
    /// # Errors
    /// - Invalid scheme version
    /// - Authentication error (data was modified)
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        // Check version
        if encrypted.version != CRYPTO_VERSION {
            return Err(CryptoError::UnsupportedVersion(encrypted.version));
        }

        // Check nonce size
        if encrypted.nonce.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: AES_NONCE_SIZE,
                actual: encrypted.nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Decrypt and verify the authentication tag
        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| CryptoError::AesDecryption("Authentication failed".to_string()))
    }

    /// Encrypts data and returns it as base64
    pub fn encrypt_to_base64(&self, plaintext: &[u8]) -> Result<String> {
        let encrypted = self.encrypt(plaintext)?;
        encrypted.to_base64()
    }

    /// Decrypts data from base64
    pub fn decrypt_from_base64(&self, base64_data: &str) -> Result<Vec<u8>> {
        let encrypted = EncryptedData::from_base64(base64_data)?;
        self.decrypt(&encrypted)
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesKey([REDACTED])")
    }
}

/// Utility for encrypting files in chunks (streaming)
pub struct AesStreamEncryptor {
    key: AesKey,
    chunk_size: usize,
}

impl AesStreamEncryptor {
    /// Creates a new streaming encryptor
    ///
    /// # Arguments
    /// * `key` - AES key
    /// * `chunk_size` - chunk size in bytes (defaults to 1 MB)
    pub fn new(key: AesKey, chunk_size: Option<usize>) -> Self {
        Self {
            key,
            chunk_size: chunk_size.unwrap_or(1024 * 1024), // 1MB default
        }
    }

    /// Encrypts data in chunks
    ///
    /// # Returns
    /// Vector of encrypted chunks
    pub fn encrypt_chunks(&self, data: &[u8]) -> Result<Vec<EncryptedData>> {
        data.chunks(self.chunk_size)
            .map(|chunk| self.key.encrypt(chunk))
            .collect()
    }

    /// Decrypts chunks and combines them into a single vector
    pub fn decrypt_chunks(&self, chunks: &[EncryptedData]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for chunk in chunks {
            let decrypted = self.key.decrypt(chunk)?;
            result.extend(decrypted);
        }
        Ok(result)
    }

    /// Returns a reference to the key
    pub fn key(&self) -> &AesKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = AesKey::generate();
        let key2 = AesKey::generate();

        // Keys must be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), AES_KEY_SIZE);
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [42u8; AES_KEY_SIZE];
        let key = AesKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_uniqueness_for_generated_chunks() {
        let key = AesKey::generate();
        let mut seen = std::collections::HashSet::new();
        for i in 0..256u16 {
            let encrypted = key.encrypt_with_aad(b"chunk", &i.to_be_bytes()).unwrap();
            assert!(seen.insert(encrypted.nonce));
        }
    }

    #[test]
    fn test_aad_tamper_verification_fails() {
        let key = AesKey::generate();
        let encrypted = key.encrypt_with_aad(b"secret", b"vault:1:chunk:0").unwrap();
        assert!(key
            .decrypt_with_aad(&encrypted, b"vault:1:chunk:1")
            .is_err());
    }

    #[test]
    fn test_key_from_bytes_invalid_size() {
        let bytes = [42u8; 16]; // Invalid size
        let result = AesKey::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = AesKey::generate();
        let plaintext = b"Hello, XRPL Vault! This is a test message.";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = AesKey::generate();
        let plaintext = b"";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large() {
        let key = AesKey::generate();
        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let encrypted = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = AesKey::generate();
        let key2 = AesKey::generate();
        let plaintext = b"Secret message";

        let encrypted = key1.encrypt(plaintext).unwrap();
        let result = key2.decrypt(&encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = AesKey::generate();
        let plaintext = b"Secret message";

        let mut encrypted = key.encrypt(plaintext).unwrap();
        // Modify the ciphertext
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = key.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let key = AesKey::generate();
        let plaintext = b"Base64 test data";

        let base64 = key.encrypt_to_base64(plaintext).unwrap();
        let decrypted = key.decrypt_from_base64(&base64).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_stream_encryptor() {
        let key = AesKey::generate();
        let encryptor = AesStreamEncryptor::new(key, Some(100));

        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let chunks = encryptor.encrypt_chunks(&data).unwrap();

        // Should be 5 chunks (500 / 100)
        assert_eq!(chunks.len(), 5);

        let decrypted = encryptor.decrypt_chunks(&chunks).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_different_nonces() {
        let key = AesKey::generate();
        let plaintext = b"Same message";

        let encrypted1 = key.encrypt(plaintext).unwrap();
        let encrypted2 = key.encrypt(plaintext).unwrap();

        // Nonces must be different
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        // Ciphertext is also different (because of different nonces)
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }
}
