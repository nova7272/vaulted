//! Расшифровка файлов
//!
//! Процесс:
//! 1. Расшифровываем AES-ключ
//! 2. Расшифровываем данные
//! 3. Верифицируем хеш

use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use xrpl_vault_crypto_core::{
    aes::AesKey,
    hash::verify_hash,
    pre::{EncryptedPreData, PreKeyPair, ProxyReEncryption},
    types::EncryptedData,
    AES_KEY_SIZE,
};

use crate::error::{ClientError, Result};

/// Расшифровщик файлов
pub struct FileDecryptor {
    pre: ProxyReEncryption,
}

impl FileDecryptor {
    /// Создаёт новый расшифровщик
    pub fn new() -> Self {
        Self {
            pre: ProxyReEncryption::new(),
        }
    }

    /// Расшифровывает AES-ключ
    ///
    /// Используется когда пользователь сам зашифровал файл
    /// или получил ключ после transfer
    pub fn decrypt_aes_key(
        &self,
        keypair: &PreKeyPair,
        encrypted_key: &EncryptedPreData,
    ) -> Result<AesKey> {
        let key_bytes = self.pre.decrypt(keypair, encrypted_key)?;

        if key_bytes.len() != AES_KEY_SIZE {
            return Err(ClientError::Crypto(
                xrpl_vault_crypto_core::CryptoError::InvalidKeySize {
                    expected: AES_KEY_SIZE,
                    actual: key_bytes.len(),
                },
            ));
        }

        AesKey::from_bytes(&key_bytes).map_err(|e| ClientError::Crypto(e))
    }

    /// Расшифровывает данные
    pub fn decrypt_data(&self, aes_key: &AesKey, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        aes_key
            .decrypt(encrypted)
            .map_err(|e| ClientError::Crypto(e))
    }

    /// Расшифровывает файл и сохраняет на диск
    pub async fn decrypt_file(
        &self,
        aes_key: &AesKey,
        encrypted_data: &EncryptedData,
        expected_hash: &str,
        output_path: &Path,
    ) -> Result<()> {
        // Расшифровываем
        let decrypted = self.decrypt_data(aes_key, encrypted_data)?;

        // Верифицируем хеш
        if !verify_hash(&decrypted, expected_hash) {
            return Err(ClientError::Crypto(
                xrpl_vault_crypto_core::CryptoError::InvalidData(
                    "Hash verification failed".to_string(),
                ),
            ));
        }

        // Сохраняем файл
        let mut file = File::create(output_path).await?;
        file.write_all(&decrypted).await?;
        file.flush().await?;

        tracing::info!(
            "File decrypted successfully: {} ({} bytes)",
            output_path.display(),
            decrypted.len()
        );

        Ok(())
    }

    /// Расшифровывает данные в память
    pub fn decrypt_bytes(
        &self,
        aes_key: &AesKey,
        encrypted_data: &EncryptedData,
        expected_hash: &str,
    ) -> Result<Vec<u8>> {
        let decrypted = self.decrypt_data(aes_key, encrypted_data)?;

        // Верифицируем хеш
        if !verify_hash(&decrypted, expected_hash) {
            return Err(ClientError::Crypto(
                xrpl_vault_crypto_core::CryptoError::InvalidData(
                    "Hash verification failed".to_string(),
                ),
            ));
        }

        Ok(decrypted)
    }
}

impl Default for FileDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xrpl_vault_crypto_core::hash::sha256_prefixed;

    #[test]
    fn test_decrypt_data() {
        let decryptor = FileDecryptor::new();
        let aes_key = AesKey::generate();

        let plaintext = b"Hello, XRPL Vault!";
        let encrypted = aes_key.encrypt(plaintext).unwrap();

        let decrypted = decryptor.decrypt_data(&aes_key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_bytes_with_hash() {
        let decryptor = FileDecryptor::new();
        let aes_key = AesKey::generate();

        let plaintext: Vec<u8> = (0..250).map(|i| (i % 256) as u8).collect();
        let original_hash = sha256_prefixed(&plaintext);

        let encrypted = aes_key.encrypt(&plaintext).unwrap();

        let decrypted = decryptor
            .decrypt_bytes(&aes_key, &encrypted, &original_hash)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_bytes_invalid_hash() {
        let decryptor = FileDecryptor::new();
        let aes_key = AesKey::generate();

        let plaintext = b"Hello!";
        let encrypted = aes_key.encrypt(plaintext).unwrap();

        let result = decryptor.decrypt_bytes(&aes_key, &encrypted, "sha256:invalid");
        assert!(result.is_err());
    }
}
