//! Cryptographic key management
//!
//! Integration with crypto-core for PRE operations.

use xrpl_vault_crypto_core::{
    DerivedKeys, EncryptedPreData, PreKeyPair, PrePublicKey, ProxyReEncryption,
};

use crate::error::Result;

/// Key manager
pub struct KeyManager {
    pre: ProxyReEncryption,
}

impl KeyManager {
    /// Creates a new manager
    pub fn new() -> Self {
        Self {
            pre: ProxyReEncryption::new(),
        }
    }

    /// Generates a random PRE keypair
    pub fn generate_keypair(&self) -> PreKeyPair {
        self.pre.generate_keypair()
    }

    /// Generates a keypair from a seed (deterministically)
    pub fn generate_keypair_from_seed(&self, seed: &[u8; 32]) -> Result<PreKeyPair> {
        self.pre
            .generate_keypair_from_seed(seed)
            .map_err(Into::into)
    }

    /// Derives PRE keys from an XRPL wallet signature
    pub fn derive_keys_from_signature(
        &self,
        signature: &[u8],
        wallet_address: &str,
    ) -> Result<DerivedKeys> {
        DerivedKeys::from_signature(signature, wallet_address).map_err(Into::into)
    }

    /// Imports a public key from bytes
    pub fn import_public_key(&self, bytes: &[u8]) -> Result<PrePublicKey> {
        PrePublicKey::from_bytes(bytes).map_err(Into::into)
    }

    /// Imports a public key from hex
    pub fn import_public_key_hex(&self, hex_str: &str) -> Result<PrePublicKey> {
        PrePublicKey::from_hex(hex_str).map_err(Into::into)
    }

    /// Encrypts data for the recipient
    pub fn encrypt(&self, public_key: &PrePublicKey, data: &[u8]) -> Result<EncryptedPreData> {
        self.pre.encrypt(public_key, data).map_err(Into::into)
    }

    /// Decrypts data
    pub fn decrypt(&self, keypair: &PreKeyPair, encrypted: &EncryptedPreData) -> Result<Vec<u8>> {
        self.pre.decrypt(keypair, encrypted).map_err(Into::into)
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// NFT transfer information
#[derive(Debug, Clone)]
pub struct TransferInfo {
    /// NFT Token ID
    pub nft_token_id: String,
    /// Current owner address
    pub from_address: String,
    /// New owner address
    pub to_address: String,
    /// New owner PRE public key (hex)
    pub to_public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let manager = KeyManager::new();
        let keypair = manager.generate_keypair();

        let public_key_bytes = keypair.export_public_key_bytes();
        assert_eq!(public_key_bytes.len(), 33);
    }

    #[test]
    fn test_deterministic_keypair() {
        let manager = KeyManager::new();
        let seed = [42u8; 32];

        let kp1 = manager.generate_keypair_from_seed(&seed).unwrap();
        let kp2 = manager.generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(kp1.export_public_key_bytes(), kp2.export_public_key_bytes());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let manager = KeyManager::new();
        let keypair = manager.generate_keypair();

        let plaintext = b"secret message";
        let encrypted = manager.encrypt(&keypair.public_key(), plaintext).unwrap();
        let decrypted = manager.decrypt(&keypair, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
