//! Proxy Re-Encryption (PRE) module
//!
//! Uses the umbral-pre (NuCypher) library to implement the PRE scheme.
//! Allows encrypted data to be shared without revealing the key.

use crate::error::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, decrypt_reencrypted, encrypt, reencrypt, Capsule, CapsuleFrag,
    DefaultDeserialize, DefaultSerialize, PublicKey as UmbralPublicKey, SecretKey,
    SecretKeyFactory, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};

/// PRE keypair
#[derive(Clone)]
pub struct PreKeyPair {
    secret_key: SecretKey,
    public_key: UmbralPublicKey,
    signer: Signer,
}

impl PreKeyPair {
    /// Creates a keypair from a seed (deterministically)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let factory = SecretKeyFactory::from_secure_randomness(seed)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid seed: {:?}", e)))?;

        let secret_key = factory.make_key(b"main");
        let public_key = secret_key.public_key();

        // Create the signer from the same factory
        let signer_key = factory.make_key(b"signer");
        let signer = Signer::new(signer_key);

        Ok(Self {
            secret_key,
            public_key,
            signer,
        })
    }

    /// Returns the public key
    pub fn public_key(&self) -> PrePublicKey {
        PrePublicKey {
            inner: self.public_key.clone(),
        }
    }

    /// Exports the public key as bytes (33 compressed bytes)
    pub fn export_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone().to_compressed_bytes().to_vec()
    }

    /// Export signer's verifying key bytes (for kfrag verification)
    pub fn export_verifying_key_bytes(&self) -> Vec<u8> {
        self.signer.verifying_key().to_compressed_bytes().to_vec()
    }
}

/// PRE public key
#[derive(Clone)]
pub struct PrePublicKey {
    inner: UmbralPublicKey,
}

impl PrePublicKey {
    /// Creates from bytes (33 compressed bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let pk = UmbralPublicKey::try_from_compressed_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;

        Ok(Self { inner: pk })
    }

    /// Creates from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Exports as bytes (33 compressed bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.clone().to_compressed_bytes().to_vec()
    }

    /// Exports as hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// PRE encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPreData {
    /// Capsule (serialized)
    pub capsule: Vec<u8>,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
}

impl EncryptedPreData {
    fn new(capsule: &Capsule, ciphertext: &[u8]) -> Self {
        Self {
            capsule: capsule.clone().to_bytes().unwrap().to_vec(),
            ciphertext: ciphertext.to_vec(),
        }
    }

    /// Extracts the Capsule from encrypted data
    pub fn get_capsule(&self) -> Result<Capsule> {
        Capsule::from_bytes(&self.capsule)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid capsule: {:?}", e)))
    }

    /// Serializes to base64
    pub fn to_base64(&self) -> Result<String> {
        use base64::Engine;
        let json =
            serde_json::to_string(self).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json.as_bytes()))
    }

    /// Deserializes from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let json =
            String::from_utf8(bytes).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Serializes to bytes (JSON)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes (JSON)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| CryptoError::Deserialization(e.to_string()))
    }
}

/// Proxy Re-Encryption context
pub struct ProxyReEncryption;

/// Re-encryption key for access transfer
pub struct ReEncryptionKey {
    kfrags: Vec<VerifiedKeyFrag>,
}

impl ReEncryptionKey {
    /// Serializes to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize each kfrag
        let kfrag_bytes: Vec<Vec<u8>> = self
            .kfrags
            .iter()
            .map(|kf| kf.clone().to_bytes().unwrap().to_vec())
            .collect();

        serde_json::to_vec(&kfrag_bytes).unwrap_or_default()
    }

    /// Deserializes from bytes
    /// TODO: Full implementation requires kfrag verification
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
        // VerifiedKeyFrag cannot be deserialized directly without verification
        // A full implementation must store KeyFrag and verify it on load
        Err(CryptoError::Deserialization(
            "ReEncryptionKey deserialization not yet implemented".to_string(),
        ))
    }

    /// Returns kfrags
    pub fn kfrags(&self) -> &[VerifiedKeyFrag] {
        &self.kfrags
    }

    /// Returns the first kfrag
    pub fn first_kfrag(&self) -> Option<VerifiedKeyFrag> {
        self.kfrags.first().cloned()
    }

    /// Serializes to base64 with the sender public key
    /// DEPRECATED: Use to_base64_verified instead
    pub fn to_base64(&self, sender_public_key: &PrePublicKey) -> String {
        self.to_base64_impl(sender_public_key, None)
    }

    /// Serializes to base64 with the sender public key and verifying key (MED-04)
    pub fn to_base64_verified(&self, sender_keypair: &PreKeyPair) -> String {
        let verifying_key_bytes = sender_keypair.export_verifying_key_bytes();
        self.to_base64_impl(&sender_keypair.public_key(), Some(verifying_key_bytes))
    }

    fn to_base64_impl(
        &self,
        sender_public_key: &PrePublicKey,
        sender_verifying_key: Option<Vec<u8>>,
    ) -> String {
        use base64::Engine;
        let kfrag_bytes: Vec<Vec<u8>> = self
            .kfrags
            .iter()
            .map(|kf| kf.clone().unverify().to_bytes().unwrap().to_vec())
            .collect();
        let mut data = serde_json::json!({
            "kfrags": kfrag_bytes,
            "sender_pk": sender_public_key.to_bytes()
        });
        if let Some(vk) = sender_verifying_key {
            data["sender_verifying_key"] = serde_json::json!(vk);
        }
        let bytes = serde_json::to_vec(&data).unwrap_or_default();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }
}

impl ProxyReEncryption {
    /// Creates a new PRE context
    pub fn new() -> Self {
        Self
    }

    /// Generates a new random keypair
    pub fn generate_keypair(&self) -> PreKeyPair {
        let secret_key = SecretKey::random();
        let public_key = secret_key.public_key();
        let signer = Signer::new(SecretKey::random());

        PreKeyPair {
            secret_key,
            public_key,
            signer,
        }
    }

    /// Generates a keypair from a seed (deterministically)
    pub fn generate_keypair_from_seed(&self, seed: &[u8; 32]) -> Result<PreKeyPair> {
        PreKeyPair::from_seed(seed)
    }

    /// Generates a re-encryption key to transfer access from one user to another
    pub fn generate_re_key(
        &self,
        from_keypair: &PreKeyPair,
        to_public_key: &PrePublicKey,
    ) -> Result<ReEncryptionKey> {
        // Use threshold=1 and shares=1 for simplicity
        let kfrags = self.generate_kfrags(from_keypair, to_public_key, 1, 1);
        Ok(ReEncryptionKey { kfrags })
    }

    /// Encrypts data for a recipient
    pub fn encrypt(&self, public_key: &PrePublicKey, plaintext: &[u8]) -> Result<EncryptedPreData> {
        let (capsule, ciphertext) = encrypt(&public_key.inner, plaintext)
            .map_err(|e| CryptoError::PreEncryption(format!("Encryption failed: {:?}", e)))?;

        Ok(EncryptedPreData::new(&capsule, &ciphertext))
    }

    /// Decrypts data
    pub fn decrypt(&self, keypair: &PreKeyPair, encrypted: &EncryptedPreData) -> Result<Vec<u8>> {
        let capsule = encrypted.get_capsule()?;

        let plaintext = decrypt_original(&keypair.secret_key, &capsule, &encrypted.ciphertext)
            .map_err(|e| CryptoError::PreDecryption(format!("Decryption failed: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }

    /// Generates key fragments for re-encryption
    pub fn generate_kfrags(
        &self,
        from_keypair: &PreKeyPair,
        to_public_key: &PrePublicKey,
        threshold: usize,
        shares: usize,
    ) -> Vec<VerifiedKeyFrag> {
        umbral_pre::generate_kfrags(
            &from_keypair.secret_key,
            &to_public_key.inner,
            &from_keypair.signer,
            threshold,
            shares,
            true,
            true,
        )
        .to_vec()
    }

    /// Re-encrypts the capsule (performed by the proxy)
    pub fn reencrypt_capsule(
        &self,
        capsule: &Capsule,
        kfrag: VerifiedKeyFrag,
    ) -> VerifiedCapsuleFrag {
        reencrypt(capsule, kfrag)
    }

    /// Decrypts re-encrypted data
    pub fn decrypt_reencrypted(
        &self,
        to_keypair: &PreKeyPair,
        from_public_key: &PrePublicKey,
        capsule: &Capsule,
        cfrags: Vec<VerifiedCapsuleFrag>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let plaintext = decrypt_reencrypted(
            &to_keypair.secret_key,
            &from_public_key.inner,
            capsule,
            cfrags,
            ciphertext,
        )
        .map_err(|e| CryptoError::PreDecryption(format!("Re-decryption failed: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }
}

impl Default for ProxyReEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::AesKey;

    #[test]
    fn test_encrypt_decrypt() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let plaintext = b"Hello, World!";

        let encrypted = pre.encrypt(&keypair.public_key(), plaintext).unwrap();
        let decrypted = pre.decrypt(&keypair, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_aes_key() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let aes_key = AesKey::generate();

        let encrypted = pre
            .encrypt(&keypair.public_key(), aes_key.as_bytes())
            .unwrap();
        let decrypted = pre.decrypt(&keypair, &encrypted).unwrap();

        assert_eq!(aes_key.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_deterministic_keypair() {
        let pre = ProxyReEncryption::new();
        let seed = [42u8; 32];

        let kp1 = pre.generate_keypair_from_seed(&seed).unwrap();
        let kp2 = pre.generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(kp1.export_public_key_bytes(), kp2.export_public_key_bytes());
    }

    #[test]
    fn test_public_key_export_import() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let pk_bytes = keypair.export_public_key_bytes();
        let restored = PrePublicKey::from_bytes(&pk_bytes).unwrap();

        assert_eq!(pk_bytes, restored.to_bytes());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let pre = ProxyReEncryption::new();
        let keypair = pre.generate_keypair();

        let plaintext = b"Test data for serialization";
        let encrypted = pre.encrypt(&keypair.public_key(), plaintext).unwrap();

        let base64 = encrypted.to_base64().unwrap();
        let restored = EncryptedPreData::from_base64(&base64).unwrap();

        let decrypted = pre.decrypt(&keypair, &restored).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_stability_with_random_data() {
        let pre = ProxyReEncryption::new();

        for _ in 0..10 {
            let alice = pre.generate_keypair();
            let _bob = pre.generate_keypair();

            let aes_key = AesKey::generate();

            let encrypted = pre
                .encrypt(&alice.public_key(), aes_key.as_bytes())
                .unwrap();
            let decrypted = pre.decrypt(&alice, &encrypted).unwrap();

            assert_eq!(aes_key.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_re_encryption() {
        let pre = ProxyReEncryption::new();
        let alice = pre.generate_keypair();
        let bob = pre.generate_keypair();

        let plaintext = b"Secret message for Bob";
        let encrypted = pre.encrypt(&alice.public_key(), plaintext).unwrap();

        let kfrags = pre.generate_kfrags(&alice, &bob.public_key(), 1, 1);

        let capsule = encrypted.get_capsule().unwrap();
        let cfrag = pre.reencrypt_capsule(&capsule, kfrags.into_iter().next().unwrap());

        let decrypted = pre
            .decrypt_reencrypted(
                &bob,
                &alice.public_key(),
                &capsule,
                vec![cfrag],
                &encrypted.ciphertext,
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}

/// Re-encrypted data (for the recipient after transfer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReEncryptedData {
    /// Original capsule
    pub capsule: Vec<u8>,
    /// Capsule fragment (after re-encryption)
    pub cfrag: Vec<u8>,
    /// Encrypted data (unchanged)
    pub ciphertext: Vec<u8>,
    /// Sender public key (required for decryption)
    pub sender_public_key: Vec<u8>,
    /// Sender verifying key (required to verify the cfrag)
    /// None only for backward compatibility with pre-v0.2 data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_verifying_key: Option<Vec<u8>>,
}

impl ReEncryptedData {
    /// Serializes to base64
    pub fn to_base64(&self) -> Result<String> {
        use base64::Engine;
        let json =
            serde_json::to_string(self).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json.as_bytes()))
    }

    /// Deserializes from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let json =
            String::from_utf8(bytes).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| CryptoError::Deserialization(e.to_string()))
    }
}

impl ProxyReEncryption {
    /// Performs capsule re-encryption using kfrag
    /// Returns ReEncryptedData for the recipient
    pub fn perform_reencryption_with_kfrag(
        &self,
        encrypted_data: &EncryptedPreData,
        kfrag: VerifiedKeyFrag,
        sender_public_key: &PrePublicKey,
    ) -> Result<ReEncryptedData> {
        self.perform_reencryption_with_kfrag_verified(
            encrypted_data,
            kfrag,
            sender_public_key,
            None,
        )
    }

    /// Performs re-encryption while preserving the verifying key for later cfrag verification
    pub fn perform_reencryption_with_kfrag_verified(
        &self,
        encrypted_data: &EncryptedPreData,
        kfrag: VerifiedKeyFrag,
        sender_public_key: &PrePublicKey,
        sender_verifying_key: Option<Vec<u8>>,
    ) -> Result<ReEncryptedData> {
        let capsule = encrypted_data.get_capsule()?;
        let cfrag = self.reencrypt_capsule(&capsule, kfrag);

        Ok(ReEncryptedData {
            capsule: encrypted_data.capsule.clone(),
            cfrag: cfrag.to_bytes().unwrap().to_vec(),
            ciphertext: encrypted_data.ciphertext.clone(),
            sender_public_key: sender_public_key.to_bytes(),
            sender_verifying_key,
        })
    }

    /// Decrypts ReEncryptedData (for the recipient)
    pub fn decrypt_reencrypted_data(
        &self,
        recipient_keypair: &PreKeyPair,
        re_encrypted: &ReEncryptedData,
    ) -> Result<Vec<u8>> {
        let capsule = Capsule::from_bytes(&re_encrypted.capsule)
            .map_err(|e| CryptoError::Deserialization(format!("Invalid capsule: {:?}", e)))?;

        let cfrag_unverified = CapsuleFrag::from_bytes(&re_encrypted.cfrag)
            .map_err(|e| CryptoError::Deserialization(format!("Invalid cfrag: {:?}", e)))?;

        let sender_pk = PrePublicKey::from_bytes(&re_encrypted.sender_public_key)?;

        // CRIT-01 FIX: Verify cfrag cryptographically when verifying key is available
        let cfrag = if let Some(ref vk_bytes) = re_encrypted.sender_verifying_key {
            let verifying_pk = UmbralPublicKey::try_from_compressed_bytes(vk_bytes)
                .map_err(|e| CryptoError::InvalidKey(format!("Invalid verifying key: {}", e)))?;

            let delegating_pk =
                UmbralPublicKey::try_from_compressed_bytes(&re_encrypted.sender_public_key)
                    .map_err(|e| {
                        CryptoError::InvalidKey(format!("Invalid delegating key: {}", e))
                    })?;

            let receiving_pk = recipient_keypair.public_key();
            let receiving_umbral = UmbralPublicKey::try_from_compressed_bytes(
                &receiving_pk.to_bytes(),
            )
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid receiving key: {}", e)))?;

            match cfrag_unverified.verify(
                &capsule,
                &verifying_pk,
                &delegating_pk,
                &receiving_umbral,
            ) {
                Ok(verified) => verified,
                Err((_, err)) => {
                    return Err(CryptoError::PreDecryption(
                        format!("Capsule fragment verification failed: {:?}. Data may have been tampered with.", err)
                    ));
                },
            }
        } else {
            // Backward compatibility: legacy data without verifying key.
            // TODO: Remove this path after migrating all ReEncryptedData to include
            //       sender_verifying_key. Until then, cfrag is accepted unverified
            //       for old transfers only.
            #[cfg(debug_assertions)]
            eprintln!("[WARN] cfrag verification skipped: no sender_verifying_key (legacy data)");
            cfrag_unverified.skip_verification()
        };

        self.decrypt_reencrypted(
            recipient_keypair,
            &sender_pk,
            &capsule,
            vec![cfrag],
            &re_encrypted.ciphertext,
        )
    }
}
