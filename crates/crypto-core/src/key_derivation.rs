//! Key derivation from XRPL wallet signatures
//!
//! PRE-ключи деривируются из подписи Xaman, а не из seed.
//! Это позволяет восстановить ключи на новом устройстве
//! без раскрытия seed клиентскому приложению.

use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use crate::error::{CryptoError, Result};
use crate::pre::{ProxyReEncryption, PreKeyPair};

/// Константы для деривации
const DERIVATION_SALT: &[u8] = b"xrpl-vault-v1";
const PRE_KEY_INFO: &[u8] = b"pre-encryption-keypair";
const DERIVATION_CHALLENGE: &str = "xrpl-vault-key-derivation-v1";

/// Key derivation service
pub struct KeyDerivation;

impl KeyDerivation {
    /// Challenge который пользователь подписывает в Xaman
    ///
    /// Этот challenge фиксированный - одна и та же подпись
    /// на любом устройстве даст одинаковые PRE-ключи.
    pub fn get_derivation_challenge() -> &'static str {
        DERIVATION_CHALLENGE
    }

    /// Генерирует derivation challenge с дополнительным контекстом
    ///
    /// Формат: "xrpl-vault-key-derivation-v1:{wallet_address}"
    pub fn get_challenge_for_wallet(wallet_address: &str) -> String {
        format!("{}:{}", DERIVATION_CHALLENGE, wallet_address)
    }

    /// Деривация PRE keypair из подписи Xaman
    ///
    /// # Arguments
    /// * `signature` - Подпись challenge от Xaman (hex или bytes)
    /// * `wallet_address` - XRPL адрес для дополнительной привязки
    ///
    /// # Returns
    /// * Детерминистичный PRE keypair
    ///
    /// # Security
    /// * Подпись детерминистична для данного private key
    /// * Один и тот же wallet даст одинаковые PRE-ключи
    /// * Seed никогда не покидает Xaman
    pub fn derive_pre_keypair_from_signature(
        signature: &[u8],
        wallet_address: &str,
    ) -> Result<PreKeyPair> {
        use zeroize::Zeroize;

        // Комбинируем signature + wallet для уникальности
        let mut input = Vec::with_capacity(signature.len() + wallet_address.len());
        input.extend_from_slice(signature);
        input.extend_from_slice(wallet_address.as_bytes());

        // HKDF extract
        let hkdf = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), &input);

        // Зануляем input buffer
        input.zeroize();

        // HKDF expand - получаем 32 bytes для seed
        let mut seed = [0u8; 32];
        hkdf.expand(PRE_KEY_INFO, &mut seed)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // Используем ProxyReEncryption для генерации keypair из seed
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair_from_seed(&seed)?;

        // Зануляем seed
        seed.zeroize();

        Ok(keypair)
    }

    /// Деривация из hex-encoded signature
    pub fn derive_from_hex_signature(
        signature_hex: &str,
        wallet_address: &str,
    ) -> Result<PreKeyPair> {
        let signature = hex::decode(signature_hex)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Self::derive_pre_keypair_from_signature(&signature, wallet_address)
    }

    /// Вычисляет fingerprint публичного ключа для отображения пользователю
    pub fn public_key_fingerprint(public_key: &[u8]) -> String {
        let hash = Sha256::digest(public_key);
        // Первые 8 символов hex
        hex::encode(&hash[..4]).to_uppercase()
    }

    /// Проверяет что деривированные ключи совпадают с ожидаемыми
    pub fn verify_derivation(
        signature: &[u8],
        wallet_address: &str,
        expected_public_key: &[u8],
    ) -> Result<bool> {
        let derived = Self::derive_pre_keypair_from_signature(signature, wallet_address)?;
        Ok(derived.export_public_key_bytes() == expected_public_key)
    }

    /// Возвращает seed из подписи (для сохранения в keystore)
    ///
    /// Этот seed можно использовать для восстановления PRE keypair
    pub fn derive_seed_from_signature(
        signature: &[u8],
        wallet_address: &str,
    ) -> [u8; 32] {
        use zeroize::Zeroize;

        let mut input = Vec::with_capacity(signature.len() + wallet_address.len());
        input.extend_from_slice(signature);
        input.extend_from_slice(wallet_address.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), &input);

        // Зануляем input buffer
        input.zeroize();

        let mut seed = [0u8; 32];
        hkdf.expand(PRE_KEY_INFO, &mut seed).expect("HKDF expand failed");

        seed
    }
}

/// Результат деривации с метаданными

pub struct DerivedKeys {
    /// PRE keypair
    pub keypair: PreKeyPair,
    /// Fingerprint для отображения пользователю
    pub fingerprint: String,
    /// Wallet address с которого деривировано
    pub wallet_address: String,
}

impl DerivedKeys {
    /// Создаёт DerivedKeys из подписи
    pub fn from_signature(
        signature: &[u8],
        wallet_address: &str,
    ) -> Result<Self> {
        let keypair = KeyDerivation::derive_pre_keypair_from_signature(
            signature,
            wallet_address,
        )?;
        let fingerprint = KeyDerivation::public_key_fingerprint(
            &keypair.export_public_key_bytes()
        );

        Ok(Self {
            keypair,
            fingerprint,
            wallet_address: wallet_address.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let signature = b"test_signature_bytes_here_12345678901234567890";
        let wallet = "rTestWallet123";

        // Деривируем дважды
        let keys1 = KeyDerivation::derive_pre_keypair_from_signature(signature, wallet).unwrap();
        let keys2 = KeyDerivation::derive_pre_keypair_from_signature(signature, wallet).unwrap();

        // Должны получить одинаковые ключи
        assert_eq!(
            keys1.export_public_key_bytes(),
            keys2.export_public_key_bytes()
        );
    }

    #[test]
    fn test_different_signatures_different_keys() {
        let sig1 = b"signature_one_1234567890123456789012345678901234";
        let sig2 = b"signature_two_1234567890123456789012345678901234";
        let wallet = "rTestWallet123";

        let keys1 = KeyDerivation::derive_pre_keypair_from_signature(sig1, wallet).unwrap();
        let keys2 = KeyDerivation::derive_pre_keypair_from_signature(sig2, wallet).unwrap();

        // Разные подписи → разные ключи
        assert_ne!(
            keys1.export_public_key_bytes(),
            keys2.export_public_key_bytes()
        );
    }

    #[test]
    fn test_different_wallets_different_keys() {
        let signature = b"same_signature_for_both_wallets_1234567890123456";
        let wallet1 = "rWallet1";
        let wallet2 = "rWallet2";

        let keys1 = KeyDerivation::derive_pre_keypair_from_signature(signature, wallet1).unwrap();
        let keys2 = KeyDerivation::derive_pre_keypair_from_signature(signature, wallet2).unwrap();

        // Разные wallets → разные ключи
        assert_ne!(
            keys1.export_public_key_bytes(),
            keys2.export_public_key_bytes()
        );
    }

    #[test]
    fn test_fingerprint() {
        let pk = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let fp = KeyDerivation::public_key_fingerprint(&pk);

        // Fingerprint должен быть 8 hex символов
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_challenge_format() {
        let challenge = KeyDerivation::get_challenge_for_wallet("rMyWallet123");
        assert!(challenge.starts_with("xrpl-vault-key-derivation-v1:"));
        assert!(challenge.contains("rMyWallet123"));
    }
}