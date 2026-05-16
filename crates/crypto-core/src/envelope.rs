//! Key envelope API for wrapping per-file and per-note keys.
//!
//! Vaulted uses a random content key per object and wraps it for each recipient.
//! This replaces deriving encryption private keys from wallet signatures.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{CryptoError, Result};

const ENVELOPE_INFO: &[u8] = b"Vaulted v1 key envelope";

/// Encrypted file/note key for a recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEnvelope {
    /// Recipient semantic type: owner, grant-recipient, device, etc.
    pub recipient_type: String,
    /// Recipient Vaulted identity id.
    pub recipient_identity_id: String,
    /// Recipient public key id or fingerprint.
    pub recipient_public_key_id: String,
    /// Algorithm identifier.
    pub alg: String,
    /// Ephemeral X25519 public key, hex.
    pub ephemeral_public_key: String,
    /// AEAD nonce, base64.
    pub nonce: String,
    /// Wrapped content key, base64.
    pub encrypted_file_key: String,
}

/// Wraps a content key to a recipient X25519 public key.
pub fn seal_key_for_recipient(
    file_key: &[u8],
    recipient_public_key: &X25519PublicKey,
    recipient_identity_id: impl Into<String>,
    recipient_public_key_id: impl Into<String>,
    recipient_type: impl Into<String>,
    aad: &[u8],
) -> Result<KeyEnvelope> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_public_key);
    let mut wrap_key = derive_wrap_key(shared.as_bytes())?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: file_key, aad },
        )
        .map_err(|e| CryptoError::AesEncryption(format!("key envelope encryption failed: {e}")))?;
    wrap_key.zeroize();

    Ok(KeyEnvelope {
        recipient_type: recipient_type.into(),
        recipient_identity_id: recipient_identity_id.into(),
        recipient_public_key_id: recipient_public_key_id.into(),
        alg: "X25519-HKDF-SHA256-XCHACHA20POLY1305".to_string(),
        ephemeral_public_key: hex::encode(ephemeral_public.as_bytes()),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
        encrypted_file_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext,
        ),
    })
}

/// Wraps a content key to a recipient X25519 public key encoded as 32-byte hex.
pub fn seal_key_for_recipient_hex(
    file_key: &[u8],
    recipient_public_key_hex: &str,
    recipient_identity_id: impl Into<String>,
    recipient_public_key_id: impl Into<String>,
    recipient_type: impl Into<String>,
    aad: &[u8],
) -> Result<KeyEnvelope> {
    let bytes = hex::decode(recipient_public_key_hex).map_err(|e| {
        CryptoError::InvalidKey(format!("bad recipient encryption public key hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "recipient encryption public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let public_key = X25519PublicKey::from(arr);
    seal_key_for_recipient(
        file_key,
        &public_key,
        recipient_identity_id,
        recipient_public_key_id,
        recipient_type,
        aad,
    )
}

/// Opens a content key envelope with the recipient X25519 private key.
pub fn open_key_envelope(
    envelope: &KeyEnvelope,
    recipient_private_key: &StaticSecret,
    aad: &[u8],
) -> Result<Vec<u8>> {
    if envelope.alg != "X25519-HKDF-SHA256-XCHACHA20POLY1305" {
        return Err(CryptoError::InvalidData(format!(
            "unsupported key envelope algorithm: {}",
            envelope.alg
        )));
    }

    let eph = hex::decode(&envelope.ephemeral_public_key)
        .map_err(|e| CryptoError::InvalidData(format!("bad envelope public key: {e}")))?;
    if eph.len() != 32 {
        return Err(CryptoError::InvalidKey(
            "bad X25519 public key size".to_string(),
        ));
    }
    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(&eph);
    let eph_public = X25519PublicKey::from(eph_arr);

    let nonce = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.nonce)
        .map_err(|e| CryptoError::InvalidData(format!("bad envelope nonce: {e}")))?;
    if nonce.len() != 24 {
        return Err(CryptoError::InvalidNonceSize {
            expected: 24,
            actual: nonce.len(),
        });
    }

    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &envelope.encrypted_file_key,
    )
    .map_err(|e| CryptoError::InvalidData(format!("bad envelope ciphertext: {e}")))?;

    let shared = recipient_private_key.diffie_hellman(&eph_public);
    let mut wrap_key = derive_wrap_key(shared.as_bytes())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            CryptoError::AesDecryption("key envelope authentication failed".to_string())
        })?;
    wrap_key.zeroize();
    Ok(plaintext)
}

fn derive_wrap_key(shared_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"Vaulted v1 envelope salt"), shared_secret);
    let mut out = [0u8; 32];
    hkdf.expand(ENVELOPE_INFO, &mut out)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_envelope_roundtrip_and_tamper_failure() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let key = [7u8; 32];
        let aad = b"vault_object_id:test";
        let env =
            seal_key_for_recipient(&key, &recipient_public, "id", "pk", "owner", aad).unwrap();
        assert_eq!(
            open_key_envelope(&env, &recipient_secret, aad).unwrap(),
            key
        );
        assert!(open_key_envelope(&env, &recipient_secret, b"other aad").is_err());
    }

    #[test]
    fn key_envelope_from_hex_public_key_roundtrips() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let recipient_public_hex = hex::encode(recipient_public.as_bytes());
        let key = [9u8; 32];
        let aad = b"vaulted-grant-envelope-v1:object:recipient";
        let env = seal_key_for_recipient_hex(
            &key,
            &recipient_public_hex,
            "recipient-id",
            "recipient-key-id",
            "grant-recipient",
            aad,
        )
        .unwrap();
        assert_eq!(env.recipient_identity_id, "recipient-id");
        assert_eq!(env.recipient_public_key_id, "recipient-key-id");
        assert_eq!(env.recipient_type, "grant-recipient");
        assert_eq!(
            open_key_envelope(&env, &recipient_secret, aad).unwrap(),
            key
        );
    }
}
