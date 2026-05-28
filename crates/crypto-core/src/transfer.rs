//! Transfer proof for transferring files between users
//!
//! When transferring a file from User A to User B:
//! 1. A decrypts the AES key with sk_A
//! 2. A encrypts the AES key for pk_B
//! 3. A creates a TransferProof
//! 4. TransferProof is written to the XRPL Memo
//! 5. B extracts the proof, decrypts the key, and verifies the commitment

use crate::aes::AesKey;
use crate::commitment::KeyCommitment;
use crate::error::{CryptoError, Result};
use crate::pre::{EncryptedPreData, PreKeyPair, ProxyReEncryption};
use serde::{Deserialize, Serialize};

/// Transfer protocol version
pub const TRANSFER_PROTOCOL_VERSION: u8 = 1;

/// File transfer proof
///
/// Contains all information for the recipient:
/// - Encrypted AES key
/// - Nonce for commitment verification
/// - Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    /// Protocol version
    pub version: u8,

    /// Encrypted AES key for the recipient (base64)
    pub encrypted_key: String,

    /// Nonce from the original commitment (hex)
    pub nonce: String,

    /// Commitment from the NFT URI for verification (hex)
    pub commitment: String,

    /// Recipient public key (hex) - for verification
    pub recipient_public_key: String,

    /// Proof creation timestamp
    pub created_at: u64,
}

impl TransferProof {
    /// Creates a new TransferProof
    ///
    /// # Arguments
    /// * `encrypted_key` - AES key encrypted for the recipient
    /// * `commitment` - original KeyCommitment from the vault
    /// * `recipient_pk_hex` - recipient public key
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

    /// Serializes for writing to an XRPL Memo
    pub fn to_memo_data(&self) -> Result<String> {
        let json =
            serde_json::to_string(self).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(hex::encode(json.as_bytes()))
    }

    /// Deserializes from an XRPL Memo
    pub fn from_memo_data(memo_hex: &str) -> Result<Self> {
        let json_bytes = hex::decode(memo_hex)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid memo hex: {}", e)))?;

        let json_str = String::from_utf8(json_bytes)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid UTF-8: {}", e)))?;

        serde_json::from_str(&json_str).map_err(|e| CryptoError::Deserialization(e.to_string()))
    }

    /// Returns encrypted_key as EncryptedPreData
    pub fn encrypted_key_data(&self) -> Result<EncryptedPreData> {
        EncryptedPreData::from_base64(&self.encrypted_key)
    }
}

/// Service for performing transfer operations
pub struct TransferService<'a> {
    pre: &'a ProxyReEncryption,
}

impl<'a> TransferService<'a> {
    /// Creates a new service with the given PRE context
    pub fn new(pre: &'a ProxyReEncryption) -> Self {
        Self { pre }
    }

    /// Re-encrypts the AES key for a new recipient
    ///
    /// Runs LOCALLY on the sender device.
    ///
    /// # Arguments
    /// * `encrypted_aes_key` - current encrypted key (for the sender)
    /// * `sender_keypair` - sender keypair
    /// * `recipient_pk` - recipient public key (bytes)
    /// * `commitment` - original commitment
    ///
    /// # Returns
    /// * TransferProof for writing to an XRPL Memo
    pub fn create_transfer_proof(
        &self,
        encrypted_aes_key: &EncryptedPreData,
        sender_keypair: &PreKeyPair,
        recipient_pk: &[u8],
        commitment: &KeyCommitment,
    ) -> Result<TransferProof> {
        // 1. Decrypt the AES key (order: keypair, encrypted)
        let aes_key_bytes = self.pre.decrypt(sender_keypair, encrypted_aes_key)?;

        // 2. Check that the key matches the commitment
        let aes_key = AesKey::from_bytes(&aes_key_bytes)?;
        if !commitment.verify(&aes_key) {
            return Err(CryptoError::InvalidData(
                "AES key doesn't match commitment".into(),
            ));
        }

        // 3. Encrypt for the recipient
        let recipient_public_key = crate::pre::PrePublicKey::from_bytes(recipient_pk)?;
        let encrypted_for_recipient = self.pre.encrypt(&recipient_public_key, &aes_key_bytes)?;

        // 4. Create the proof
        let recipient_pk_hex = hex::encode(recipient_pk);
        TransferProof::new(&encrypted_for_recipient, commitment, &recipient_pk_hex)
    }

    /// Accepts a transfer and extracts the AES key
    ///
    /// Runs LOCALLY on the recipient device.
    ///
    /// # Arguments
    /// * `proof` - TransferProof from the XRPL Memo
    /// * `recipient_keypair` - recipient keypair
    /// * `expected_commitment` - commitment from the NFT URI
    ///
    /// # Returns
    /// * (AesKey, is_valid) - key and verification result
    pub fn accept_transfer(
        &self,
        proof: &TransferProof,
        recipient_keypair: &PreKeyPair,
        expected_commitment: &[u8; 32],
    ) -> Result<(AesKey, bool)> {
        // 1. Decode encrypted key
        let encrypted_data = proof.encrypted_key_data()?;

        // 2. Decrypt (order: keypair, encrypted)
        let aes_key_bytes = self.pre.decrypt(recipient_keypair, &encrypted_data)?;
        let aes_key = AesKey::from_bytes(&aes_key_bytes)?;

        // 3. Recreate the commitment for verification
        let nonce_bytes = hex::decode(&proof.nonce)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid nonce hex: {}", e)))?;

        if nonce_bytes.len() != 16 {
            return Err(CryptoError::InvalidData("Nonce must be 16 bytes".into()));
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_bytes);

        let commitment = KeyCommitment::create_with_nonce(&aes_key, nonce);

        // 4. Verify the commitment
        let is_valid = commitment.commitment_bytes() == expected_commitment;

        Ok((aes_key, is_valid))
    }
}

/// Transfer verification result
#[derive(Debug, Clone)]
pub struct TransferVerification {
    /// AES key (if decryption succeeds)
    pub aes_key: Option<AesKey>,
    /// Does the commitment match?
    pub commitment_valid: bool,
    /// Error message (if any)
    pub error: Option<String>,
}

impl TransferVerification {
    /// Successful verification
    pub fn success(aes_key: AesKey) -> Self {
        Self {
            aes_key: Some(aes_key),
            commitment_valid: true,
            error: None,
        }
    }

    /// Failed verification
    pub fn failure(reason: &str) -> Self {
        Self {
            aes_key: None,
            commitment_valid: false,
            error: Some(reason.to_string()),
        }
    }

    /// Key decrypted, but commitment does not match
    pub fn commitment_mismatch(aes_key: AesKey) -> Self {
        Self {
            aes_key: Some(aes_key),
            commitment_valid: false,
            error: Some("Commitment mismatch - sender may have provided wrong key".into()),
        }
    }

    /// Was verification successful?
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

        // Use fixed data for stability
        let aes_key_bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create(&aes_key);

        // Encrypt for the sender
        let encrypted = pre
            .encrypt(&sender.public_key(), aes_key.as_bytes())
            .unwrap();

        // Create the transfer proof
        let service = TransferService::new(&pre);
        let proof = service
            .create_transfer_proof(
                &encrypted,
                &sender,
                &recipient.export_public_key_bytes(),
                &commitment,
            )
            .unwrap();

        // Serialize to memo
        let memo = proof.to_memo_data().unwrap();

        // Deserialize
        let restored = TransferProof::from_memo_data(&memo).unwrap();

        assert_eq!(proof.version, restored.version);
        assert_eq!(proof.nonce, restored.nonce);
        assert_eq!(proof.commitment, restored.commitment);
    }

    #[test]
    fn test_full_transfer_flow() {
        // NOTE: the recrypt library has an unstable RNG.
        // A real application uses retry logic.
        // Here we use fixed data for test stability.

        let pre = ProxyReEncryption::new();
        let alice = pre.generate_keypair();
        let bob = pre.generate_keypair();

        // Use fixed data instead of random data
        let aes_key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create(&aes_key);

        // Alice encrypts the AES key for herself
        let encrypted_for_alice = pre
            .encrypt(&alice.public_key(), aes_key.as_bytes())
            .unwrap();

        // Alice transfers to Bob
        let service = TransferService::new(&pre);
        let proof = service
            .create_transfer_proof(
                &encrypted_for_alice,
                &alice,
                &bob.export_public_key_bytes(),
                &commitment,
            )
            .unwrap();

        // Bob accepts the transfer
        let (received_key, is_valid) = service
            .accept_transfer(&proof, &bob, commitment.commitment_bytes())
            .unwrap();

        // Verify
        assert!(is_valid, "Commitment should be valid");
        assert_eq!(
            received_key.as_bytes(),
            aes_key.as_bytes(),
            "Keys should match"
        );
    }

    #[test]
    fn test_invalid_commitment_detected() {
        // This test checks only the commitment verification logic,
        // without using PRE operations

        let aes_key_bytes: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let nonce: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let aes_key = AesKey::from_bytes(&aes_key_bytes).unwrap();
        let commitment = KeyCommitment::create_with_nonce(&aes_key, nonce);

        // The correct commitment should pass verification
        assert!(commitment.verify(&aes_key), "Correct key should verify");

        // The wrong key should not pass
        let wrong_key_bytes: [u8; 32] = [0xff; 32];
        let wrong_key = AesKey::from_bytes(&wrong_key_bytes).unwrap();
        assert!(
            !commitment.verify(&wrong_key),
            "Wrong key should not verify"
        );
    }
}
