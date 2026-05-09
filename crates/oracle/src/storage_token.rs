//! Storage Access Tokens
//!
//! Signed tokens for accessing file fragments on storage nodes.
//! Oracle signs tokens, storage nodes verify them.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Storage access token payload
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageToken {
    /// NFT Token ID (identifies the file)
    pub nft_token_id: String,
    /// Storage key (fragment identifier)
    pub storage_key: String,
    /// Allowed operation: "read", "write", "delete"
    pub operation: String,
    /// Token expiration (unix timestamp)
    pub exp: i64,
    /// Issued at (unix timestamp)
    pub iat: i64,
}

impl StorageToken {
    /// Create a new read token
    pub fn new_read(nft_token_id: &str, storage_key: &str, expires_in_minutes: i64) -> Self {
        let now = Utc::now();
        Self {
            nft_token_id: nft_token_id.to_string(),
            storage_key: storage_key.to_string(),
            operation: "read".to_string(),
            exp: (now + Duration::minutes(expires_in_minutes)).timestamp(),
            iat: now.timestamp(),
        }
    }

    /// Create a new write token
    pub fn new_write(nft_token_id: &str, storage_key: &str, expires_in_minutes: i64) -> Self {
        let now = Utc::now();
        Self {
            nft_token_id: nft_token_id.to_string(),
            storage_key: storage_key.to_string(),
            operation: "write".to_string(),
            exp: (now + Duration::minutes(expires_in_minutes)).timestamp(),
            iat: now.timestamp(),
        }
    }

    /// Create a new delete token
    pub fn new_delete(nft_token_id: &str, storage_key: &str, expires_in_minutes: i64) -> Self {
        let now = Utc::now();
        Self {
            nft_token_id: nft_token_id.to_string(),
            storage_key: storage_key.to_string(),
            operation: "delete".to_string(),
            exp: (now + Duration::minutes(expires_in_minutes)).timestamp(),
            iat: now.timestamp(),
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Check if operation matches
    pub fn allows(&self, operation: &str) -> bool {
        self.operation == operation
    }
}

/// Sign a storage token
pub fn sign_storage_token(token: &StorageToken, signing_key: &SigningKey) -> String {
    let payload = serde_json::to_string(token).expect("Failed to serialize token");
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    
    let signature = signing_key.sign(payload_b64.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    
    format!("{}.{}", payload_b64, signature_b64)
}

/// Verify and decode a storage token
pub fn verify_storage_token(
    token_str: &str,
    verifying_key: &VerifyingKey,
) -> Result<StorageToken, StorageTokenError> {
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 2 {
        return Err(StorageTokenError::InvalidFormat);
    }

    let payload_b64 = parts[0];
    let signature_b64 = parts[1];

    // Verify signature
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)
        .map_err(|_| StorageTokenError::InvalidFormat)?;
    
    if signature_bytes.len() != 64 {
        return Err(StorageTokenError::InvalidSignature);
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| StorageTokenError::InvalidSignature)?;

    // Decode payload
    let payload_json = URL_SAFE_NO_PAD.decode(payload_b64)
        .map_err(|_| StorageTokenError::InvalidFormat)?;
    
    let token: StorageToken = serde_json::from_slice(&payload_json)
        .map_err(|_| StorageTokenError::InvalidFormat)?;

    // Check expiration
    if token.is_expired() {
        return Err(StorageTokenError::Expired);
    }

    Ok(token)
}

#[derive(Debug, thiserror::Error)]
pub enum StorageTokenError {
    #[error("Invalid token format")]
    InvalidFormat,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Token expired")]
    Expired,
    
    #[error("Operation not allowed")]
    OperationNotAllowed,
    
    #[error("Storage key mismatch")]
    KeyMismatch,
}

/// Helper to generate download URLs with tokens
pub struct StorageUrlGenerator {
    signing_key: SigningKey,
    token_validity_minutes: i64,
}

impl StorageUrlGenerator {
    pub fn new(signing_key: SigningKey, token_validity_minutes: i64) -> Self {
        Self {
            signing_key,
            token_validity_minutes,
        }
    }

    /// Generate a signed download URL
    pub fn download_url(
        &self,
        node_endpoint: &str,
        nft_token_id: &str,
        storage_key: &str,
    ) -> String {
        let token = StorageToken::new_read(
            nft_token_id,
            storage_key,
            self.token_validity_minutes,
        );
        let signed = sign_storage_token(&token, &self.signing_key);
        
        format!("{}/fragments/{}?token={}", node_endpoint, storage_key, signed)
    }

    /// Generate a signed upload URL
    pub fn upload_url(
        &self,
        node_endpoint: &str,
        nft_token_id: &str,
        storage_key: &str,
    ) -> String {
        let token = StorageToken::new_write(
            nft_token_id,
            storage_key,
            self.token_validity_minutes,
        );
        let signed = sign_storage_token(&token, &self.signing_key);
        
        format!("{}/fragments/{}?token={}", node_endpoint, storage_key, signed)
    }

    /// Generate a signed delete URL
    pub fn delete_url(
        &self,
        node_endpoint: &str,
        nft_token_id: &str,
        storage_key: &str,
    ) -> String {
        let token = StorageToken::new_delete(
            nft_token_id,
            storage_key,
            self.token_validity_minutes,
        );
        let signed = sign_storage_token(&token, &self.signing_key);
        
        format!("{}/fragments/{}?token={}", node_endpoint, storage_key, signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_storage_token_sign_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let token = StorageToken::new_read("nft123", "fragment456", 5);
        
        let signed = sign_storage_token(&token, &signing_key);
        
        // Should have 2 parts
        assert_eq!(signed.split('.').count(), 2);
        
        // Verify should succeed
        let verified = verify_storage_token(&signed, &signing_key.verifying_key()).unwrap();
        assert_eq!(verified.nft_token_id, "nft123");
        assert_eq!(verified.storage_key, "fragment456");
        assert_eq!(verified.operation, "read");
    }

    #[test]
    fn test_expired_token() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut token = StorageToken::new_read("nft123", "fragment456", 5);
        token.exp = Utc::now().timestamp() - 60; // Expired 1 minute ago
        
        let signed = sign_storage_token(&token, &signing_key);
        
        let result = verify_storage_token(&signed, &signing_key.verifying_key());
        assert!(matches!(result, Err(StorageTokenError::Expired)));
    }

    #[test]
    fn test_invalid_signature() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let signing_key2 = SigningKey::generate(&mut OsRng);
        
        let token = StorageToken::new_read("nft123", "fragment456", 5);
        let signed = sign_storage_token(&token, &signing_key1);
        
        // Verify with different key should fail
        let result = verify_storage_token(&signed, &signing_key2.verifying_key());
        assert!(matches!(result, Err(StorageTokenError::InvalidSignature)));
    }

    #[test]
    fn test_url_generator() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let generator = StorageUrlGenerator::new(signing_key.clone(), 5);
        
        let url = generator.download_url(
            "http://storage.example.com",
            "nft123",
            "fragment456"
        );
        
        assert!(url.starts_with("http://storage.example.com/fragments/fragment456?token="));
        
        // Extract and verify token
        let token_str = url.split("token=").nth(1).unwrap();
        let verified = verify_storage_token(token_str, &signing_key.verifying_key()).unwrap();
        assert_eq!(verified.operation, "read");
    }
}
