//! Transfer proof для передачи файлов между пользователями
//!
//! При передаче файла User A → User B:
//! 1. A расшифровывает AES-ключ своим sk_A
//! 2. A шифрует AES-ключ для pk_B
//! 3. A создаёт TransferProof
//! 4. TransferProof записывается в XRPL Memo
//! 5. B извлекает proof, расшифровывает ключ, проверяет commitment

use crate::aes::AesKey;
use crate::commitment::KeyCommitment;
use crate::error::{CryptoError, Result};
use crate::pre::{EncryptedPreData, PreKeyPair, ProxyReEncryption};
use serde::{Deserialize, Serialize};

/// Версия протокола transfer
pub const TRANSFER_PROTOCOL_VERSION: u8 = 1;

/// Proof передачи файла
///
/// Содержит всю информацию для получателя:
/// - Зашифрованный AES-ключ
/// - Nonce для верификации commitment
/// - Метаданные
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    /// Версия протокола
    pub version: u8,

    /// Зашифрованный AES-ключ для получателя (base64)
    pub encrypted_key: String,

    /// Nonce из оригинального commitment (hex)
    pub nonce: String,

    /// Commitment из NFT URI для проверки (hex)
    pub commitment: String,

    /// Публичный ключ получателя (hex) - для верификации
    pub recipient_public_key: String,

    /// Timestamp создания proof
    pub created_at: u64,
}

impl TransferProof {
    /// Создаёт новый TransferProof
    ///
    /// # Arguments
    /// * `encrypted_key` - AES-ключ зашифрованный для получателя
    /// * `commitment` - оригинальный KeyCommitment из vault
    /// * `recipient_pk_hex` - публичный ключ получателя
    pub fn new(
        encrypted_key: &EncryptedPreData,
        commitment: &KeyCommitment,
        recipient_pk_hex: &str,
    ) -> Result<Self> {
        let encrypted_key_base64 = encrypted_key.to_base64()?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            version: TRANSFER_PROTOCOL_VERSION,
            encrypted_key: encrypted_key_base64,
            nonce: commitment.nonce_hex(),
            commitment: commitment.commitment_hex(),
            recipient_public_key: recipient_pk_hex.to_string(),
            created_at: timestamp,
        })
    }

    /// Сериализует для записи в XRPL Memo
    pub fn to_memo_data(&self) -> Result<String> {
        let json =
            serde_json::to_string(self).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(hex::encode(json.as_bytes()))
    }

    /// Десериализует из XRPL Memo
    pub fn from_memo_data(memo_hex: &str) -> Result<Self> {
        let json_bytes = hex::decode(memo_hex)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid memo hex: {}", e)))?;

        let json_str = String::from_utf8(json_bytes)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid UTF-8: {}", e)))?;

        serde_json::from_str(&json_str).map_err(|e| CryptoError::Deserialization(e.to_string()))
    }

    /// Возвращает encrypted_key как EncryptedPreData
    pub fn encrypted_key_data(&self) -> Result<EncryptedPreData> {
        EncryptedPreData::from_base64(&self.encrypted_key)
    }
}

/// Сервис для выполнения transfer операций
pub struct TransferService<'a> {
    pre: &'a ProxyReEncryption,
}

impl<'a> TransferService<'a> {
    /// Создаёт новый сервис с заданным PRE контекстом
    pub fn new(pre: &'a ProxyReEncryption) -> Self {
        Self { pre }
    }

    /// Перешифровывает AES-ключ для нового получателя
    ///
    /// Выполняется ЛОКАЛЬНО на устройстве отправителя.
    ///
    /// # Arguments
    /// * `encrypted_aes_key` - текущий зашифрованный ключ (для sender)
    /// * `sender_keypair` - keypair отправителя
    /// * `recipient_pk` - публичный ключ получателя (bytes)
    /// * `commitment` - оригинальный commitment
    ///
    /// # Returns
    /// * TransferProof для записи в XRPL Memo
    pub fn create_transfer_proof(
        &self,
        encrypted_aes_key: &EncryptedPreData,
        sender_keypair: &PreKeyPair,
        recipient_pk: &[u8],
        commitment: &KeyCommitment,
    ) -> Result<TransferProof> {
        // 1. Расшифровываем AES-ключ (порядок: keypair, encrypted)
        let aes_key_bytes = self.pre.decrypt(sender_keypair, encrypted_aes_key)?;

        // 2. Проверяем что ключ соответствует commitment
        let aes_key = AesKey::from_bytes(&aes_key_bytes)?;
        if !commitment.verify(&aes_key) {
            return Err(CryptoError::InvalidData(
                "AES key doesn't match commitment".into(),
            ));
        }

        // 3. Шифруем для получателя
        let recipient_public_key = crate::pre::PrePublicKey::from_bytes(recipient_pk)?;
        let encrypted_for_recipient = self.pre.encrypt(&recipient_public_key, &aes_key_bytes)?;

        // 4. Создаём proof
        let recipient_pk_hex = hex::encode(recipient_pk);
        TransferProof::new(&encrypted_for_recipient, commitment, &recipient_pk_hex)
    }

    /// Принимает transfer и извлекает AES-ключ
    ///
    /// Выполняется ЛОКАЛЬНО на устройстве получателя.
    ///
    /// # Arguments
    /// * `proof` - TransferProof из XRPL Memo
    /// * `recipient_keypair` - keypair получателя
    /// * `expected_commitment` - commitment из NFT URI
    ///
    /// # Returns
    /// * (AesKey, is_valid) - ключ и результат верификации
    pub fn accept_transfer(
        &self,
        proof: &TransferProof,
        recipient_keypair: &PreKeyPair,
        expected_commitment: &[u8; 32],
    ) -> Result<(AesKey, bool)> {
        // 1. Декодируем encrypted key
        let encrypted_data = proof.encrypted_key_data()?;

        // 2. Расшифровываем (порядок: keypair, encrypted)
        let aes_key_bytes = self.pre.decrypt(recipient_keypair, &encrypted_data)?;
        let aes_key = AesKey::from_bytes(&aes_key_bytes)?;

        // 3. Восстанавливаем commitment для проверки
        let nonce_bytes = hex::decode(&proof.nonce)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid nonce hex: {}", e)))?;

        if nonce_bytes.len() != 16 {
            return Err(CryptoError::InvalidData("Nonce must be 16 bytes".into()));
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_bytes);

        let commitment = KeyCommitment::create_with_nonce(&aes_key, nonce);

        // 4. Проверяем commitment
        let is_valid = commitment.commitment_bytes() == expected_commitment;

        Ok((aes_key, is_valid))
    }
}

/// Результат верификации transfer
#[derive(Debug, Clone)]
pub struct TransferVerification {
    /// AES-ключ (если расшифровка успешна)
    pub aes_key: Option<AesKey>,
    /// Commitment совпадает?
    pub commitment_valid: bool,
    /// Сообщение об ошибке (если есть)
    pub error: Option<String>,
}

impl TransferVerification {
    /// Успешная верификация
    pub fn success(aes_key: AesKey) -> Self {
        Self {
            aes_key: Some(aes_key),
            commitment_valid: true,
            error: None,
        }
    }

    /// Неуспешная верификация
    pub fn failure(reason: &str) -> Self {
        Self {
            aes_key: None,
            commitment_valid: false,
            error: Some(reason.to_string()),
        }
    }

    /// Ключ расшифрован, но commitment не совпадает
    pub fn commitment_mismatch(aes_key: AesKey) -> Self {
        Self {
            aes_key: Some(aes_key),
            commitment_valid: false,
            error: Some("Commitment mismatch - sender may have provided wrong key".into()),
        }
    }

    /// Проверка успешна?
    pub fn is_valid(&self) -> bool {
        self.aes_key.is_some() && self.commitment_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_proof_serialization() {
        let pre = ProxyReEncryption::new();
        let sender = pre.generate_keypair();
        let recipient = pre.generate_keypair();

        // Используем фиксированные данные для стабильности
        let aes_key_bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create(&aes_key);

        // Шифруем для sender
        let encrypted = pre
            .encrypt(&sender.public_key(), aes_key.as_bytes())
            .unwrap();

        // Создаём transfer proof
        let service = TransferService::new(&pre);
        let proof = service
            .create_transfer_proof(
                &encrypted,
                &sender,
                &recipient.export_public_key_bytes(),
                &commitment,
            )
            .unwrap();

        // Сериализуем в memo
        let memo = proof.to_memo_data().unwrap();

        // Десериализуем
        let restored = TransferProof::from_memo_data(&memo).unwrap();

        assert_eq!(proof.version, restored.version);
        assert_eq!(proof.nonce, restored.nonce);
        assert_eq!(proof.commitment, restored.commitment);
    }

    #[test]
    fn test_full_transfer_flow() {
        // NOTE: recrypt библиотека имеет нестабильный RNG.
        // В реальном приложении используется retry логика.
        // Здесь используем фиксированные данные для стабильности теста.

        let pre = ProxyReEncryption::new();
        let alice = pre.generate_keypair();
        let bob = pre.generate_keypair();

        // Используем фиксированные данные вместо случайных
        let aes_key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create(&aes_key);

        // Alice шифрует AES-ключ для себя
        let encrypted_for_alice = pre
            .encrypt(&alice.public_key(), aes_key.as_bytes())
            .unwrap();

        // Alice передаёт Bob
        let service = TransferService::new(&pre);
        let proof = service
            .create_transfer_proof(
                &encrypted_for_alice,
                &alice,
                &bob.export_public_key_bytes(),
                &commitment,
            )
            .unwrap();

        // Bob принимает transfer
        let (received_key, is_valid) = service
            .accept_transfer(&proof, &bob, commitment.commitment_bytes())
            .unwrap();

        // Проверяем
        assert!(is_valid, "Commitment should be valid");
        assert_eq!(
            received_key.as_bytes(),
            aes_key.as_bytes(),
            "Keys should match"
        );
    }

    #[test]
    fn test_invalid_commitment_detected() {
        // Этот тест проверяет только логику верификации commitment,
        // без использования PRE операций

        let aes_key_bytes: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let nonce: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create_with_nonce(&aes_key, nonce);

        // Правильный commitment должен пройти проверку
        assert!(commitment.verify(&aes_key), "Correct key should verify");

        // Неправильный ключ не должен пройти
        let wrong_key_bytes: [u8; 32] = [0xff; 32];
        let wrong_key = AesKey::from_bytes(&wrong_key_bytes).unwrap();
        assert!(
            !commitment.verify(&wrong_key),
            "Wrong key should not verify"
        );
    }
}
