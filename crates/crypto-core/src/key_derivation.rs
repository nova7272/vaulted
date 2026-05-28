//! Legacy key derivation compatibility module.
//!
//! SECURITY: Vaulted v1 no longer derives encryption/PRE keys from external wallet/XRPL
//! signatures. Use `SeedManager` + `VaultedIdentityKeys` instead.

use crate::error::{CryptoError, Result};
use crate::pre::PreKeyPair;
use sha2::{Digest, Sha256};

const DERIVATION_CHALLENGE: &str = "xrpl-vault-key-derivation-v1";

/// Key derivation service
pub struct KeyDerivation;

impl KeyDerivation {
    /// Challenge that the user signs in an external wallet
    ///
    /// This challenge is fixed - the same signature
    /// on any device will produce the same PRE keys.
    pub fn get_derivation_challenge() -> &'static str {
        DERIVATION_CHALLENGE
    }

    /// Generates a derivation challenge with additional context
    ///
    /// Format: "xrpl-vault-key-derivation-v1:{wallet_address}"
    pub fn get_challenge_for_wallet(wallet_address: &str) -> String {
        format!("{}:{}", DERIVATION_CHALLENGE, wallet_address)
    }

    /// Derives a PRE keypair from an external wallet signature
    ///
    /// # Arguments
    /// * `signature` - challenge signature from the external wallet (hex or bytes)
    /// * `wallet_address` - XRPL address for additional binding
    ///
    /// # Returns
    /// * Deterministic PRE keypair
    ///
    /// # Security
    /// * The signature is deterministic for the given private key
    /// * The same wallet will produce the same PRE keys
    /// * The seed never leaves the wallet
    pub fn derive_pre_keypair_from_signature(
        _signature: &[u8],
        _wallet_address: &str,
    ) -> Result<PreKeyPair> {
        Err(CryptoError::InvalidKey(
            "External wallet/XRPL signatures are not valid Vaulted encryption key material; create or restore a Vaulted seed phrase".to_string(),
        ))
    }

    /// Derivation from a hex-encoded signature
    pub fn derive_from_hex_signature(
        signature_hex: &str,
        wallet_address: &str,
    ) -> Result<PreKeyPair> {
        let signature = hex::decode(signature_hex).map_err(|_| CryptoError::InvalidSignature)?;
        Self::derive_pre_keypair_from_signature(&signature, wallet_address)
    }

    /// Computes the public key fingerprint for display to the user
    pub fn public_key_fingerprint(public_key: &[u8]) -> String {
        let hash = Sha256::digest(public_key);
        // First 8 hex characters
        hex::encode(&hash[..4]).to_uppercase()
    }

    /// Checks that derived keys match the expected value
    pub fn verify_derivation(
        signature: &[u8],
        wallet_address: &str,
        expected_public_key: &[u8],
    ) -> Result<bool> {
        let derived = Self::derive_pre_keypair_from_signature(signature, wallet_address)?;
        Ok(derived.export_public_key_bytes() == expected_public_key)
    }

    /// Returns the seed from the signature (for storing in the keystore)
    ///
    /// This seed can be used to restore the PRE keypair
    pub fn derive_seed_from_signature(_signature: &[u8], _wallet_address: &str) -> [u8; 32] {
        panic!(
            "External wallet/XRPL signatures must not be used as Vaulted encryption seed material"
        )
    }
}

/// Derivation result with metadata

pub struct DerivedKeys {
    /// PRE keypair
    pub keypair: PreKeyPair,
    /// Fingerprint for display to the user
    pub fingerprint: String,
    /// Wallet address from which it was derived
    pub wallet_address: String,
}

impl DerivedKeys {
    /// Creates DerivedKeys from a signature
    pub fn from_signature(signature: &[u8], wallet_address: &str) -> Result<Self> {
        let keypair = KeyDerivation::derive_pre_keypair_from_signature(signature, wallet_address)?;
        let fingerprint = KeyDerivation::public_key_fingerprint(&keypair.export_public_key_bytes());

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
    fn test_signature_derivation_is_disabled() {
        match KeyDerivation::derive_pre_keypair_from_signature(b"sig", "rWallet") {
            Ok(_) => panic!("External wallet signature derivation must be disabled"),
            Err(err) => {
                assert!(err
                    .to_string()
                    .contains("not valid Vaulted encryption key material"));
            },
        }
    }

    #[test]
    fn test_fingerprint() {
        let pk = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let fp = KeyDerivation::public_key_fingerprint(&pk);
        assert_eq!(fp.len(), 8);
    }
}
