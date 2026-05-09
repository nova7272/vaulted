//! XRPL Signature Verification
//!
//! Verifies signatures created by XRPL wallets (via Xaman/XUMM).
//! XRPL uses secp256k1 ECDSA with SHA-512 first-half hashing.

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use sha2::{Digest, Sha256, Sha512};

/// Verify an XRPL signature
///
/// # Arguments
/// * `public_key_hex` - Compressed secp256k1 public key (33 bytes, hex)
/// * `message` - The message that was signed
/// * `signature_hex` - DER-encoded ECDSA signature (hex)
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err` if inputs are malformed
pub fn verify_xrpl_signature(
    public_key_hex: &str,
    message: &str,
    signature_hex: &str,
) -> Result<bool, SignatureError> {
    // Decode public key
    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|_| SignatureError::InvalidPublicKey("Invalid hex encoding".into()))?;

    // XRPL public keys can be 33 bytes (compressed secp256k1) or 33 bytes with ED prefix
    let verifying_key = if pubkey_bytes.len() == 33 {
        // Check if it's Ed25519 (starts with 0xED)
        if pubkey_bytes[0] == 0xED {
            return verify_ed25519_signature(&pubkey_bytes[1..], message, signature_hex);
        }

        // secp256k1 compressed key
        let point = EncodedPoint::from_bytes(&pubkey_bytes)
            .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

        VerifyingKey::from_encoded_point(&point)
            .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?
    } else {
        return Err(SignatureError::InvalidPublicKey(
            format!("Invalid public key length: {} (expected 33)", pubkey_bytes.len())
        ));
    };

    // Decode signature (DER format)
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| SignatureError::InvalidSignature("Invalid hex encoding".into()))?;

    let signature = Signature::from_der(&sig_bytes)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?;

    // XRPL uses SHA-512 first-half for hashing
    let message_hash = sha512_first_half(message.as_bytes());

    // Verify
    match verifying_key.verify(&message_hash, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify Ed25519 signature (for accounts with Ed25519 keys)
fn verify_ed25519_signature(
    public_key: &[u8],
    message: &str,
    signature_hex: &str,
) -> Result<bool, SignatureError> {
    use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey as Ed25519VerifyingKey};

    if public_key.len() != 32 {
        return Err(SignatureError::InvalidPublicKey(
            format!("Invalid Ed25519 key length: {}", public_key.len())
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key);

    let verifying_key = Ed25519VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| SignatureError::InvalidSignature("Invalid hex encoding".into()))?;

    if sig_bytes.len() != 64 {
        return Err(SignatureError::InvalidSignature(
            format!("Invalid Ed25519 signature length: {}", sig_bytes.len())
        ));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Ed25519Signature::from_bytes(&sig_arr);

    // XRPL uses SHA-512 first-half for Ed25519 too
    let message_hash = sha512_first_half(message.as_bytes());

    match verifying_key.verify(&message_hash, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// SHA-512 first half (32 bytes) - XRPL's hashing scheme
fn sha512_first_half(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Signature verification errors
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
}

/// Derive XRPL wallet address from a public key (hex-encoded)
///
/// XRPL address = base58check(0x00 + RIPEMD160(SHA256(pubkey_bytes)))
pub fn derive_address_from_public_key(public_key_hex: &str) -> Result<String, SignatureError> {
    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|_| SignatureError::InvalidPublicKey("Invalid hex encoding".into()))?;

    if pubkey_bytes.len() != 33 {
        return Err(SignatureError::InvalidPublicKey(
            format!("Invalid public key length: {} (expected 33)", pubkey_bytes.len())
        ));
    }

    // Step 1: SHA-256 hash of public key
    let sha256_hash = Sha256::digest(&pubkey_bytes);

    // Step 2: RIPEMD-160 of SHA-256 hash (Account ID)
    use ripemd::Ripemd160;
    let account_id = Ripemd160::digest(&sha256_hash);

    // Step 3: Add version byte (0x00 for mainnet)
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00); // XRPL account prefix
    payload.extend_from_slice(&account_id);

    // Step 4: Double SHA-256 checksum
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];

    // Step 5: Append checksum
    payload.extend_from_slice(checksum);

    // Step 6: Base58 encode using XRPL alphabet
    const XRPL_ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    let alphabet = bs58::Alphabet::new(XRPL_ALPHABET)
        .expect("valid XRPL alphabet");

    Ok(bs58::encode(&payload).with_alphabet(&alphabet).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_first_half() {
        let data = b"test message";
        let hash = sha512_first_half(data);
        assert_eq!(hash.len(), 32);
    }

    // Note: Real signature tests would need actual XRPL key pairs
    // These are placeholder tests for the hash function

    #[test]
    fn test_invalid_pubkey_hex() {
        let result = verify_xrpl_signature("not-hex", "message", "sig");
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let result = verify_xrpl_signature("aabbcc", "message", "aabbcc");
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }
}