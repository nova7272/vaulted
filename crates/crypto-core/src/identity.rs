//! Vaulted identity derivation.
//!
//! A Vaulted mnemonic deterministically derives independent keys for signing,
//! encryption, device authentication, metadata encryption and legacy migration.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{seed::SeedManager, CryptoError, Result};

const ROOT_SALT: &[u8] = b"Vaulted v1 root";
const INFO_SIGNING: &[u8] = b"Vaulted v1 signing";
const INFO_ENCRYPTION: &[u8] = b"Vaulted v1 encryption";
const INFO_DEVICE: &[u8] = b"Vaulted v1 auth";
const INFO_METADATA: &[u8] = b"Vaulted v1 metadata";
const INFO_LEGACY_PRE: &[u8] = b"Vaulted v1 legacy pre migration";

/// Long-lived Vaulted identity. Private fields are zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultedIdentityKeys {
    signing_private: [u8; 32],
    encryption_private: [u8; 32],
    device_auth_key: [u8; 32],
    metadata_key: [u8; 32],
    legacy_pre_seed: [u8; 32],
    identity_id: [u8; 32],
}

impl VaultedIdentityKeys {
    /// Derives all Vaulted v1 keys from a BIP-39 mnemonic.
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let mut seed = SeedManager::mnemonic_to_seed(mnemonic, passphrase)?;
        let keys = Self::from_bip39_seed(&seed)?;
        seed.zeroize();
        Ok(keys)
    }

    /// Derives all Vaulted v1 keys from a BIP-39 seed.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Result<Self> {
        let root = Hkdf::<Sha256>::new(Some(ROOT_SALT), seed);
        let signing_private = expand32(&root, INFO_SIGNING)?;
        let encryption_private = expand32(&root, INFO_ENCRYPTION)?;
        let device_auth_key = expand32(&root, INFO_DEVICE)?;
        let metadata_key = expand32(&root, INFO_METADATA)?;
        let legacy_pre_seed = expand32(&root, INFO_LEGACY_PRE)?;

        let signing = SigningKey::from_bytes(&signing_private);
        let signing_public = signing.verifying_key();
        let encryption_public = X25519PublicKey::from(&StaticSecret::from(encryption_private));

        let mut hasher = Sha256::new();
        hasher.update(b"Vaulted v1 identity id");
        hasher.update(signing_public.as_bytes());
        hasher.update(encryption_public.as_bytes());
        let identity_id: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            signing_private,
            encryption_private,
            device_auth_key,
            metadata_key,
            legacy_pre_seed,
            identity_id,
        })
    }

    /// Stable identity id, hex encoded for protocol payloads.
    pub fn identity_id_hex(&self) -> String {
        hex::encode(self.identity_id)
    }

    /// Ed25519 signing key.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_private)
    }

    /// Ed25519 public key.
    pub fn signing_public_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Ed25519 public key as hex.
    pub fn signing_public_key_hex(&self) -> String {
        hex::encode(self.signing_public_key().as_bytes())
    }

    /// X25519 encryption private key.
    pub fn encryption_private_key(&self) -> StaticSecret {
        StaticSecret::from(self.encryption_private)
    }

    /// X25519 encryption public key.
    pub fn encryption_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.encryption_private_key())
    }

    /// X25519 public key as hex.
    pub fn encryption_public_key_hex(&self) -> String {
        hex::encode(self.encryption_public_key().as_bytes())
    }

    /// Device authentication public key, derived as an Ed25519 public key.
    pub fn device_public_key_hex(&self) -> String {
        hex::encode(
            SigningKey::from_bytes(&self.device_auth_key)
                .verifying_key()
                .as_bytes(),
        )
    }

    /// Metadata encryption key for local/client-side metadata encryption.
    pub fn metadata_key(&self) -> [u8; 32] {
        self.metadata_key
    }

    /// Deterministic seed used only to read/migrate legacy PRE records.
    pub fn legacy_pre_seed(&self) -> [u8; 32] {
        self.legacy_pre_seed
    }
}

/// Computes a privacy-safe display fingerprint for a Vaulted X25519 encryption public key.
///
/// This fingerprint is intended for TOFU / QR / manual verification UX. It is
/// deterministic, domain-separated, and does not reveal private material.
pub fn encryption_public_key_fingerprint_hex(public_key_hex: &str) -> Result<String> {
    let bytes = hex::decode(public_key_hex)
        .map_err(|e| CryptoError::InvalidKey(format!("bad encryption public key hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "encryption public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"Vaulted v1 encryption public key fingerprint");
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Short human-readable groups for displaying a key fingerprint in UI.
pub fn format_fingerprint_groups(fingerprint_hex: &str) -> String {
    fingerprint_hex
        .chars()
        .take(32)
        .collect::<String>()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

impl std::fmt::Debug for VaultedIdentityKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultedIdentityKeys")
            .field("identity_id", &self.identity_id_hex())
            .field("signing_public_key", &self.signing_public_key_hex())
            .field("encryption_public_key", &self.encryption_public_key_hex())
            .finish()
    }
}

fn expand32(root: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    root.expand(info, &mut out)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{SeedManager, DEFAULT_MNEMONIC_WORDS};
    use crate::xrpl_wallet::VaultedXrplWallet;

    #[test]
    fn derivation_is_deterministic_and_domain_separated() {
        let m = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let a = VaultedIdentityKeys::from_mnemonic(&m, None).unwrap();
        let b = VaultedIdentityKeys::from_mnemonic(&m, None).unwrap();
        assert_eq!(a.identity_id_hex(), b.identity_id_hex());
        assert_ne!(a.signing_public_key_hex(), a.encryption_public_key_hex());
    }

    #[test]
    fn same_12_word_phrase_restores_same_identity_and_xrpl_wallet() {
        let m = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let identity_a = VaultedIdentityKeys::from_mnemonic(&m, None).unwrap();
        let identity_b = VaultedIdentityKeys::from_mnemonic(&m, None).unwrap();
        let wallet_a = VaultedXrplWallet::from_mnemonic(&m, None).unwrap();
        let wallet_b = VaultedXrplWallet::from_mnemonic(&m, None).unwrap();

        assert_eq!(identity_a.identity_id_hex(), identity_b.identity_id_hex());
        assert_eq!(
            wallet_a.classic_address().unwrap(),
            wallet_b.classic_address().unwrap()
        );
    }

    #[test]
    fn encryption_public_key_fingerprint_is_deterministic_and_displayable() {
        let m = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let identity = VaultedIdentityKeys::from_mnemonic(&m, None).unwrap();
        let fingerprint_a =
            encryption_public_key_fingerprint_hex(&identity.encryption_public_key_hex()).unwrap();
        let fingerprint_b =
            encryption_public_key_fingerprint_hex(&identity.encryption_public_key_hex()).unwrap();
        assert_eq!(fingerprint_a, fingerprint_b);
        assert_eq!(fingerprint_a.len(), 64);
        let display = format_fingerprint_groups(&fingerprint_a);
        assert_eq!(display.len(), 39);
        assert!(display.contains('-'));
        assert!(encryption_public_key_fingerprint_hex("deadbeef").is_err());
    }
}
