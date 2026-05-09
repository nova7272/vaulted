//! AES-256-GCM шифрование для файлов
//!
//! Использует authenticated encryption для защиты конфиденциальности
//! и целостности данных.
//!
//! ## Пример
//!
//! ```rust,ignore
//! use xrpl_vault_crypto_core::aes::AesKey;
//!
//! // Генерируем ключ
//! let key = AesKey::generate();
//!
//! // Шифруем
//! let plaintext = b"Hello, XRPL!";
//! let encrypted = key.encrypt(plaintext).unwrap();
//!
//! // Расшифровываем
//! let decrypted = key.decrypt(&encrypted).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::{
    error::{CryptoError, Result},
    types::{EncryptedData, SecretBytes},
    AES_KEY_SIZE, AES_NONCE_SIZE, CRYPTO_VERSION,
};

/// AES-256 ключ с безопасным управлением памятью
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct AesKey {
    key: [u8; AES_KEY_SIZE],
}

impl AesKey {
    /// Генерирует новый случайный AES-256 ключ
    pub fn generate() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Создаёт ключ из байтов
    ///
    /// # Errors
    /// Возвращает ошибку если размер не равен 32 байтам
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

    /// Возвращает ключ как байты
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Возвращает ключ как SecretBytes (для безопасной передачи)
    pub fn to_secret_bytes(&self) -> SecretBytes {
        SecretBytes::new(self.key.to_vec())
    }

    /// Шифрует данные с помощью AES-256-GCM
    ///
    /// # Arguments
    /// * `plaintext` - данные для шифрования
    ///
    /// # Returns
    /// Зашифрованные данные включая nonce и authentication tag
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        // Генерируем случайный nonce (12 байт для GCM)
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Шифруем (ciphertext включает authentication tag)
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::AesEncryption(e.to_string()))?;

        Ok(EncryptedData::new(
            CRYPTO_VERSION,
            nonce_bytes.to_vec(),
            ciphertext,
        ))
    }

    /// Расшифровывает данные
    ///
    /// # Arguments
    /// * `encrypted` - зашифрованные данные
    ///
    /// # Returns
    /// Расшифрованные данные
    ///
    /// # Errors
    /// - Неверная версия схемы
    /// - Ошибка аутентификации (данные были изменены)
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        // Проверяем версию
        if encrypted.version != CRYPTO_VERSION {
            return Err(CryptoError::UnsupportedVersion(encrypted.version));
        }

        // Проверяем размер nonce
        if encrypted.nonce.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: AES_NONCE_SIZE,
                actual: encrypted.nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Расшифровываем и верифицируем authentication tag
        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| CryptoError::AesDecryption("Authentication failed".to_string()))
    }

    /// Шифрует данные и возвращает как base64
    pub fn encrypt_to_base64(&self, plaintext: &[u8]) -> Result<String> {
        let encrypted = self.encrypt(plaintext)?;
        encrypted.to_base64()
    }

    /// Расшифровывает данные из base64
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

/// Утилита для шифрования файлов по частям (streaming)
pub struct AesStreamEncryptor {
    key: AesKey,
    chunk_size: usize,
}

impl AesStreamEncryptor {
    /// Создаёт новый streaming encryptor
    ///
    /// # Arguments
    /// * `key` - AES ключ
    /// * `chunk_size` - размер чанка в байтах (по умолчанию 1MB)
    pub fn new(key: AesKey, chunk_size: Option<usize>) -> Self {
        Self {
            key,
            chunk_size: chunk_size.unwrap_or(1024 * 1024), // 1MB default
        }
    }

    /// Шифрует данные по чанкам
    ///
    /// # Returns
    /// Вектор зашифрованных чанков
    pub fn encrypt_chunks(&self, data: &[u8]) -> Result<Vec<EncryptedData>> {
        data.chunks(self.chunk_size)
            .map(|chunk| self.key.encrypt(chunk))
            .collect()
    }

    /// Расшифровывает чанки и собирает в единый вектор
    pub fn decrypt_chunks(&self, chunks: &[EncryptedData]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for chunk in chunks {
            let decrypted = self.key.decrypt(chunk)?;
            result.extend(decrypted);
        }
        Ok(result)
    }

    /// Возвращает ссылку на ключ
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

        // Ключи должны быть разными
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
    fn test_key_from_bytes_invalid_size() {
        let bytes = [42u8; 16]; // Неверный размер
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
        // Изменяем ciphertext
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

        // Должно быть 5 чанков (500 / 100)
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

        // Nonces должны быть разными
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        // Ciphertext тоже разный (из-за разных nonces)
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }
}
