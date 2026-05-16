//! Шифрование файлов
//!
//! Процесс:
//! 1. Генерируем AES-256 ключ
//! 2. Шифруем файл целиком
//! 3. Шифруем AES-ключ через PRE (публичным ключом)
//! 4. Создаём манифест с хешем

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

/// Результат шифрования файла
#[derive(Debug)]
pub struct EncryptedFile {
    /// Зашифрованный AES-ключ (для хранения в метаданных NFT)
    pub encrypted_aes_key: EncryptedPreData,
    /// Манифест файла
    pub manifest: FileManifest,
    /// Зашифрованные данные (один blob)
    pub encrypted_data: EncryptedData,
    /// Hash зашифрованных данных
    pub encrypted_hash: String,
}

/// Шифровальщик файлов
pub struct FileEncryptor {
    pre: ProxyReEncryption,
}

impl FileEncryptor {
    /// Создаёт новый шифровальщик
    pub fn new(_fragment_size: usize) -> Self {
        // fragment_size ignored - kept for API compatibility
        Self {
            pre: ProxyReEncryption::new(),
        }
    }

    /// Шифрует файл целиком
    ///
    /// # Arguments
    /// * `file_path` - путь к файлу
    /// * `owner_public_key` - публичный ключ PRE владельца
    ///
    /// # Returns
    /// Зашифрованный файл с манифестом
    pub async fn encrypt_file(
        &self,
        file_path: &Path,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        // Получаем метаданные файла
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

        // Читаем весь файл
        let mut file = File::open(file_path).await?;
        let mut data = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut data).await?;

        // Шифруем
        self.encrypt_data(&data, &filename, &mime_type, owner_public_key)
    }

    /// Шифрует данные из памяти
    pub fn encrypt_bytes(
        &self,
        data: &[u8],
        filename: &str,
        mime_type: &str,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        self.encrypt_data(data, filename, mime_type, owner_public_key)
    }

    /// Внутренний метод шифрования данных
    fn encrypt_data(
        &self,
        data: &[u8],
        filename: &str,
        mime_type: &str,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedFile> {
        // Генерируем AES ключ
        let aes_key = AesKey::generate();

        // Хеш оригинала
        let original_hash = sha256_prefixed(data);

        // Шифруем данные целиком
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

        // Шифруем имя файла тем же AES ключом
        let encrypted_filename = aes_key.encrypt_to_base64(filename.as_bytes())?;

        // Создаём манифест (без storage info - это добавит Oracle)
        let manifest = FileManifest {
            encrypted_filename,
            original_size: data.len() as u64,
            mime_type: mime_type.to_string(),
            original_hash,
            encrypted_size,
            encrypted_hash: encrypted_hash.clone(),
        };

        // Шифруем AES-ключ публичным ключом владельца
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

        // Теперь 1 blob вместо фрагментов
        assert_eq!(encrypted.manifest.original_size, 500);
        assert!(encrypted.manifest.encrypted_size > 500); // encrypted is larger due to nonce+tag
    }
}
