//! Общие типы для криптографического модуля

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Зашифрованные данные с метаданными
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Версия криптографической схемы
    pub version: u8,
    /// Nonce (IV) для AES-GCM
    pub nonce: Vec<u8>,
    /// Зашифрованные данные с authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Создаёт новый контейнер зашифрованных данных
    pub fn new(version: u8, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            version,
            nonce,
            ciphertext,
        }
    }

    /// Сериализует в бинарный формат
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Десериализует из бинарного формата
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    /// Сериализует в base64 (для хранения в JSON/метаданных NFT)
    pub fn to_base64(&self) -> crate::Result<String> {
        let bytes = self.to_bytes()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    /// Десериализует из base64
    pub fn from_base64(s: &str) -> crate::Result<Self> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
            .map_err(|e| crate::CryptoError::Deserialization(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Секретные байты с автоматическим обнулением при drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Создаёт из вектора байт
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Возвращает срез байт
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Возвращает длину
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Проверяет на пустоту
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

/// Метаданные NFT с криптографической информацией
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCryptoMetadata {
    /// Версия схемы
    pub version: u8,
    /// ID NFT в XRPL
    pub nft_id: String,
    /// Зашифрованный AES-ключ (ECIES/PRE) - base64 encoded
    pub encrypted_aes_key: String,
    /// Манифест файлов (хеши фрагментов)
    pub file_manifest: FileManifest,
    /// Публичный ключ текущего владельца
    pub owner_public_key: String,
    /// Временная метка создания
    pub created_at: i64,
    /// Временная метка последнего обновления
    pub updated_at: i64,
}

/// Манифест файлов (информация о фрагментах)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Зашифрованное имя файла (AES-256-GCM, base64)
    pub encrypted_filename: String,
    /// Размер оригинального файла в байтах
    pub original_size: u64,
    /// MIME тип
    pub mime_type: String,
    /// Хеш оригинального файла (для верификации после расшифровки)
    pub original_hash: String,
    /// Размер зашифрованных данных
    pub encrypted_size: u64,
    /// Хеш зашифрованных данных (blake3)
    pub encrypted_hash: String,
}

impl FileManifest {
    /// Вычисляет хеш манифеста (для URI NFT)
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
        // При drop значения будут обнулены
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