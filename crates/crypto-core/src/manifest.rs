//! Signed Vaulted manifest layer.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{envelope::KeyEnvelope, CryptoError, Result};

/// Current protocol identifier.
pub const VAULTED_PROTOCOL_V1: &str = "vaulted-v1";

/// Encrypted fragment descriptor stored in a signed manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFragment {
    /// Chunk index.
    pub index: u32,
    /// Opaque storage key or content-addressed object id.
    pub storage_key: String,
    /// Hash of encrypted fragment, for example sha256:...
    pub encrypted_fragment_hash: String,
    /// Encrypted fragment size.
    pub size: u64,
    /// AEAD nonce for this fragment, base64/hex depending on cipher implementation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Optional NFT anchor stored in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ManifestNftRef {
    /// Chain name, e.g. xrpl.
    pub chain: String,
    /// NFT token id after mint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Metadata URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Ed25519 signature object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignature {
    /// Signature algorithm.
    pub alg: String,
    /// Signer public key, hex.
    pub signer: String,
    /// Signature value, base64.
    pub value: String,
}

/// Vaulted v1 manifest. Sensitive metadata is encrypted client-side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultedManifest {
    /// Protocol version.
    pub protocol: String,
    /// Random object id.
    pub vault_object_id: String,
    /// Owner identity id.
    pub owner_identity_id: String,
    /// Owner signing public key, hex.
    pub owner_signing_public_key: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Monotonic manifest version.
    pub manifest_version: u64,
    /// Cipher identifier.
    pub cipher: String,
    /// Encrypted metadata blob.
    pub metadata_encrypted: String,
    /// Encrypted fragment descriptors.
    pub fragments: Vec<ManifestFragment>,
    /// Key envelopes for owner/grants.
    pub key_envelopes: Vec<KeyEnvelope>,
    /// Optional NFT anchor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nft: Option<ManifestNftRef>,
    /// Manifest signature. Excluded while hashing/signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
}

impl VaultedManifest {
    /// Serializes manifest without signature for hashing and signing.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Computes sha256 hash over canonical unsigned manifest bytes.
    pub fn manifest_hash(&self) -> Result<String> {
        let bytes = self.canonical_unsigned_bytes()?;
        let hash = Sha256::digest(&bytes);
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    /// Signs the manifest hash/content with Ed25519.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let bytes = self.canonical_unsigned_bytes()?;
        let sig = signing_key.sign(&bytes);
        self.signature = Some(ManifestSignature {
            alg: "ed25519".to_string(),
            signer: hex::encode(signing_key.verifying_key().as_bytes()),
            value: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                sig.to_bytes(),
            ),
        });
        Ok(())
    }

    /// Verifies the manifest Ed25519 signature and signer binding.
    pub fn verify_signature(&self) -> Result<()> {
        let signature = self
            .signature
            .as_ref()
            .ok_or(CryptoError::SignatureVerification)?;
        if signature.alg != "ed25519" || signature.signer != self.owner_signing_public_key {
            return Err(CryptoError::SignatureVerification);
        }

        let pub_bytes =
            hex::decode(&signature.signer).map_err(|_| CryptoError::SignatureVerification)?;
        if pub_bytes.len() != 32 {
            return Err(CryptoError::SignatureVerification);
        }
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&pub_arr).map_err(|_| CryptoError::SignatureVerification)?;

        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature.value)
                .map_err(|_| CryptoError::SignatureVerification)?;
        if sig_bytes.len() != 64 {
            return Err(CryptoError::SignatureVerification);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&self.canonical_unsigned_bytes()?, &sig)
            .map_err(|_| CryptoError::SignatureVerification)
    }
}

/// NFT metadata points to a content-addressed manifest and never contains secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultedNftMetadata {
    /// Generic name.
    pub name: String,
    /// Generic description.
    pub description: String,
    /// Generic image URI.
    pub image: String,
    /// Metadata properties.
    pub properties: VaultedNftProperties,
}

/// NFT metadata properties.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultedNftProperties {
    /// Protocol version.
    pub protocol: String,
    /// Vault object id.
    pub vault_object_id: String,
    /// Manifest URI.
    pub manifest_uri: String,
    /// Manifest hash.
    pub manifest_hash: String,
    /// Whether plaintext metadata is encrypted.
    pub metadata_encrypted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn manifest_sign_verify_and_tamper_detection() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut m = VaultedManifest {
            protocol: VAULTED_PROTOCOL_V1.to_string(),
            vault_object_id: "object".into(),
            owner_identity_id: "owner".into(),
            owner_signing_public_key: hex::encode(sk.verifying_key().as_bytes()),
            created_at: "2026-05-12T00:00:00Z".into(),
            manifest_version: 1,
            cipher: "AES-256-GCM".into(),
            metadata_encrypted: "base64...".into(),
            fragments: vec![],
            key_envelopes: vec![],
            nft: None,
            signature: None,
        };
        m.sign(&sk).unwrap();
        m.verify_signature().unwrap();
        m.vault_object_id = "other".into();
        assert!(m.verify_signature().is_err());
    }
}
