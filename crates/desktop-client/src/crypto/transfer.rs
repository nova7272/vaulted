//! Secure file transfer with local re-encryption
//!
//! ВСЯ КРИПТОГРАФИЯ ВЫПОЛНЯЕТСЯ ЛОКАЛЬНО.
//! Oracle НЕ участвует в перешифровке.
//!
//! Использует типы из crypto-core.

use crate::error::Result;
use xrpl_vault_crypto_core::{
    AesKey, EncryptedPreData, KeyCommitment, PreKeyPair, PrePublicKey, ProxyReEncryption,
    TransferProof, TransferService,
};

/// Сервис локальной перешифровки
///
/// Обёртка над crypto-core::TransferService для desktop client
pub struct LocalTransfer {
    pre: ProxyReEncryption,
}

impl LocalTransfer {
    /// Создаёт новый сервис
    pub fn new() -> Self {
        Self {
            pre: ProxyReEncryption::new(),
        }
    }

    /// Создаёт commitment для нового файла
    pub fn create_commitment(&self, aes_key: &AesKey) -> KeyCommitment {
        KeyCommitment::create(aes_key)
    }

    /// Шифрует AES-ключ для владельца
    pub fn encrypt_aes_key(
        &self,
        aes_key: &AesKey,
        owner_public_key: &PrePublicKey,
    ) -> Result<EncryptedPreData> {
        Ok(self.pre.encrypt(owner_public_key, aes_key.as_bytes())?)
    }

    /// Перешифровывает AES-ключ для нового получателя
    pub fn re_encrypt_for_recipient(
        &self,
        encrypted_aes_key: &EncryptedPreData,
        my_keypair: &PreKeyPair,
        recipient_public_key_bytes: &[u8],
        original_commitment: &KeyCommitment,
    ) -> Result<TransferProof> {
        let service = TransferService::new(&self.pre);

        Ok(service.create_transfer_proof(
            encrypted_aes_key,
            my_keypair,
            recipient_public_key_bytes,
            original_commitment,
        )?)
    }

    /// Получатель проверяет и извлекает AES-ключ из transfer proof
    pub fn accept_transfer(
        &self,
        proof: &TransferProof,
        my_keypair: &PreKeyPair,
        expected_commitment: &[u8; 32],
    ) -> Result<(AesKey, bool)> {
        let service = TransferService::new(&self.pre);

        Ok(service.accept_transfer(proof, my_keypair, expected_commitment)?)
    }

    /// Расшифровывает AES-ключ (для владельца файла)
    pub fn decrypt_aes_key(
        &self,
        encrypted_aes_key: &EncryptedPreData,
        my_keypair: &PreKeyPair,
    ) -> Result<AesKey> {
        let bytes = self.pre.decrypt(my_keypair, encrypted_aes_key)?;

        Ok(AesKey::from_bytes(&bytes)?)
    }
}

impl Default for LocalTransfer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes_key() {
        let transfer = LocalTransfer::new();
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let aes_key = AesKey::generate();
        let encrypted = transfer
            .encrypt_aes_key(&aes_key, &keypair.public_key())
            .unwrap();
        let decrypted = transfer.decrypt_aes_key(&encrypted, &keypair).unwrap();

        assert_eq!(aes_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_commitment_create_verify() {
        let transfer = LocalTransfer::new();
        let aes_key = AesKey::generate();
        let commitment = transfer.create_commitment(&aes_key);

        // Верификация должна пройти
        assert!(commitment.verify(&aes_key));

        // С другим ключом - нет
        let other_key = AesKey::generate();
        assert!(!commitment.verify(&other_key));
    }

    #[test]
    fn test_full_transfer_flow() {
        let transfer = LocalTransfer::new();
        let pre = ProxyReEncryption::new();

        // Alice создаёт файл
        let alice = pre.generate_keypair();
        let bob = pre.generate_keypair();

        let aes_key = AesKey::generate();
        let commitment = transfer.create_commitment(&aes_key);
        let encrypted_for_alice = transfer
            .encrypt_aes_key(&aes_key, &alice.public_key())
            .unwrap();

        // Alice передаёт Bob
        let proof = transfer
            .re_encrypt_for_recipient(
                &encrypted_for_alice,
                &alice,
                &bob.export_public_key_bytes(),
                &commitment,
            )
            .unwrap();

        // Bob принимает
        let (received_key, is_valid) = transfer
            .accept_transfer(&proof, &bob, commitment.commitment_bytes())
            .unwrap();

        assert!(is_valid);
        assert_eq!(aes_key.as_bytes(), received_key.as_bytes());
    }
}
