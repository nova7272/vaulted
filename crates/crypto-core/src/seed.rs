//! Vaulted seed phrase management.
//!
//! This module is the new root of user recovery.  It uses BIP-39 mnemonics and
//! never depends on reusable external wallet/XRPL signatures for encryption key material.

use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{CryptoError, Result};

/// Default Vaulted mnemonic length for standard UX.
pub const DEFAULT_MNEMONIC_WORDS: usize = 12;
/// Shortest supported Vaulted mnemonic length.  Never use fewer than 12 words.
pub const MIN_MNEMONIC_WORDS: usize = 12;

/// BIP-39 seed manager.
pub struct SeedManager;

impl SeedManager {
    /// Generates a new BIP-39 mnemonic. Vaulted MVP supports exactly 12 words.
    pub fn generate_mnemonic(word_count: usize) -> Result<String> {
        let entropy_len = match word_count {
            12 => 16,
            _ => {
                return Err(CryptoError::InvalidData(
                    "Vaulted recovery phrase must be exactly 12 words".to_string(),
                ))
            },
        };

        let mut entropy = vec![0u8; entropy_len];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        entropy.zeroize();
        Ok(mnemonic.to_string())
    }

    /// Validates a BIP-39 mnemonic without returning secret seed material.
    pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
        let word_count = mnemonic.split_whitespace().count();
        if word_count != DEFAULT_MNEMONIC_WORDS {
            return Err(CryptoError::InvalidData(
                "Vaulted recovery phrase must be exactly 12 words".to_string(),
            ));
        }
        Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        Ok(())
    }

    /// Converts a mnemonic to a BIP-39 seed. The returned bytes must be zeroized by caller.
    pub fn mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> Result<[u8; 64]> {
        Self::validate_mnemonic(mnemonic)?;
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        Ok(mnemonic.to_seed(passphrase.unwrap_or("")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_12_word_mnemonic_by_default_policy() {
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), DEFAULT_MNEMONIC_WORDS);
        SeedManager::validate_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn rejects_24_word_mnemonic_generation_under_mvp_policy() {
        let err = SeedManager::generate_mnemonic(24).unwrap_err();
        assert!(err.to_string().contains("exactly 12 words"));
    }

    #[test]
    fn rejects_non_12_word_mnemonic_restore_policy() {
        for phrase in [repeated_words(6), repeated_words(18), repeated_words(24)] {
            let err = SeedManager::validate_mnemonic(&phrase).unwrap_err();
            assert!(err.to_string().contains("exactly 12 words"));
        }
    }

    fn repeated_words(count: usize) -> String {
        std::iter::repeat_n("abandon", count)
            .collect::<Vec<_>>()
            .join(" ")
    }
}
