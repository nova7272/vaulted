//! Commitment scheme для верификации AES-ключа
//!
//! Используется для проверки что полученный ключ соответствует
//! тому, что был использован при создании vault.

use crate::aes::AesKey;
use crate::error::{CryptoError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Размер nonce в байтах
pub const NONCE_SIZE: usize = 16;

/// Размер commitment (SHA256 hash)
pub const COMMITMENT_SIZE: usize = 32;

/// Commitment для AES-ключа
///
/// commitment = SHA256(aes_key || nonce)
///
/// Записывается в NFT URI при создании vault.
/// Позволяет получателю проверить что ключ правильный.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCommitment {
    /// SHA256(aes_key || nonce)
    commitment: [u8; COMMITMENT_SIZE],
    /// Случайный nonce
    nonce: [u8; NONCE_SIZE],
}

impl KeyCommitment {
    /// Создаёт commitment для AES-ключа
    ///
    /// # Arguments
    /// * `aes_key` - AES-256 ключ для которого создаётся commitment
    ///
    /// # Returns
    /// * KeyCommitment с случайным nonce
    pub fn create(aes_key: &AesKey) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        let commitment = Self::compute_hash(aes_key.as_bytes(), &nonce);

        Self { commitment, nonce }
    }

    /// Создаёт commitment с заданным nonce (для тестов)
    pub fn create_with_nonce(aes_key: &AesKey, nonce: [u8; NONCE_SIZE]) -> Self {
        let commitment = Self::compute_hash(aes_key.as_bytes(), &nonce);
        Self { commitment, nonce }
    }

    /// Вычисляет SHA256(aes_key || nonce)
    fn compute_hash(aes_key: &[u8], nonce: &[u8]) -> [u8; COMMITMENT_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(aes_key);
        hasher.update(nonce);
        hasher.finalize().into()
    }

    /// Проверяет что AES-ключ соответствует commitment
    ///
    /// # Arguments
    /// * `aes_key` - ключ для проверки
    ///
    /// # Returns
    /// * true если ключ соответствует commitment
    pub fn verify(&self, aes_key: &AesKey) -> bool {
        let computed = Self::compute_hash(aes_key.as_bytes(), &self.nonce);
        // MED-01 FIX: Use subtle crate for constant-time comparison.
        // The compiler cannot optimize this away, unlike a hand-rolled XOR loop.
        computed.ct_eq(&self.commitment).into()
    }

    /// Возвращает commitment как hex строку
    pub fn commitment_hex(&self) -> String {
        hex::encode(self.commitment)
    }

    /// Возвращает nonce как hex строку
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }

    /// Возвращает commitment bytes
    pub fn commitment_bytes(&self) -> &[u8; COMMITMENT_SIZE] {
        &self.commitment
    }

    /// Возвращает nonce bytes
    pub fn nonce_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Формирует URI для NFT
    ///
    /// Format: "xvault:{commitment_hex}"
    pub fn to_nft_uri(&self) -> String {
        format!("xvault:{}", self.commitment_hex())
    }

    /// Создаёт из hex строк
    pub fn from_hex(commitment_hex: &str, nonce_hex: &str) -> Result<Self> {
        let commitment_bytes = hex::decode(commitment_hex)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid commitment hex: {}", e)))?;

        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid nonce hex: {}", e)))?;

        if commitment_bytes.len() != COMMITMENT_SIZE {
            return Err(CryptoError::InvalidData(format!(
                "Commitment must be {} bytes, got {}",
                COMMITMENT_SIZE,
                commitment_bytes.len()
            )));
        }

        if nonce_bytes.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidData(format!(
                "Nonce must be {} bytes, got {}",
                NONCE_SIZE,
                nonce_bytes.len()
            )));
        }

        let mut commitment = [0u8; COMMITMENT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];

        commitment.copy_from_slice(&commitment_bytes);
        nonce.copy_from_slice(&nonce_bytes);

        Ok(Self { commitment, nonce })
    }

    /// Парсит commitment из NFT URI
    ///
    /// Format: "xvault:{commitment_hex}"
    pub fn parse_nft_uri(uri: &str) -> Result<[u8; COMMITMENT_SIZE]> {
        let prefix = "xvault:";
        if !uri.starts_with(prefix) {
            return Err(CryptoError::InvalidData(
                "NFT URI must start with 'xvault:'".into(),
            ));
        }

        let commitment_hex = &uri[prefix.len()..];
        let commitment_bytes = hex::decode(commitment_hex)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid commitment hex: {}", e)))?;

        if commitment_bytes.len() != COMMITMENT_SIZE {
            return Err(CryptoError::InvalidData(format!(
                "Commitment must be {} bytes",
                COMMITMENT_SIZE
            )));
        }

        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&commitment_bytes);

        Ok(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let aes_key = AesKey::generate();
        let commitment = KeyCommitment::create(&aes_key);

        // Верификация должна пройти
        assert!(commitment.verify(&aes_key));
    }

    #[test]
    fn test_wrong_key_fails() {
        let aes_key1 = AesKey::generate();
        let aes_key2 = AesKey::generate();
        let commitment = KeyCommitment::create(&aes_key1);

        // С другим ключом не пройдёт
        assert!(!commitment.verify(&aes_key2));
    }

    #[test]
    fn test_deterministic_with_same_nonce() {
        let aes_key = AesKey::generate();
        let nonce = [1u8; NONCE_SIZE];

        let c1 = KeyCommitment::create_with_nonce(&aes_key, nonce);
        let c2 = KeyCommitment::create_with_nonce(&aes_key, nonce);

        assert_eq!(c1.commitment_hex(), c2.commitment_hex());
    }

    #[test]
    fn test_different_nonce_different_commitment() {
        let aes_key = AesKey::generate();

        let c1 = KeyCommitment::create(&aes_key);
        let c2 = KeyCommitment::create(&aes_key);

        // Разные nonce → разные commitment
        assert_ne!(c1.commitment_hex(), c2.commitment_hex());

        // Но оба верифицируют тот же ключ
        assert!(c1.verify(&aes_key));
        assert!(c2.verify(&aes_key));
    }

    #[test]
    fn test_hex_serialization() {
        let aes_key = AesKey::generate();
        let commitment = KeyCommitment::create(&aes_key);

        let commitment_hex = commitment.commitment_hex();
        let nonce_hex = commitment.nonce_hex();

        let restored = KeyCommitment::from_hex(&commitment_hex, &nonce_hex).unwrap();

        assert!(restored.verify(&aes_key));
    }

    #[test]
    fn test_nft_uri() {
        let aes_key = AesKey::generate();
        let commitment = KeyCommitment::create(&aes_key);

        let uri = commitment.to_nft_uri();
        assert!(uri.starts_with("xvault:"));

        let parsed = KeyCommitment::parse_nft_uri(&uri).unwrap();
        assert_eq!(parsed, *commitment.commitment_bytes());
    }

    #[test]
    fn test_commitment_size() {
        let aes_key = AesKey::generate();
        let commitment = KeyCommitment::create(&aes_key);

        // 32 bytes = 64 hex chars
        assert_eq!(commitment.commitment_hex().len(), 64);
        // 16 bytes = 32 hex chars
        assert_eq!(commitment.nonce_hex().len(), 32);
    }
}
