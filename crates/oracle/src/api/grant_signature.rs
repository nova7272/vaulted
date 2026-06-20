use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ApiError, Result};

pub(crate) const GRANT_SIGNATURE_DOMAIN: &str = "vaulted-grant-v1";
pub(crate) const GRANT_CREATE_ACTION: &str = "create";

pub(crate) struct GrantSignatureContext<'a> {
    pub action: &'a str,
    pub grant_id: &'a Uuid,
    pub vault_object_id: &'a str,
    pub nft_token_id: Option<&'a str>,
    pub owner_identity_id: &'a str,
    pub recipient_identity_id: &'a str,
    pub permissions: &'a Value,
    pub expires_at: Option<&'a DateTime<Utc>>,
    pub key_envelope: &'a Value,
}

pub(crate) fn grant_signature_message(ctx: &GrantSignatureContext<'_>) -> Result<String> {
    let permissions_hash = stable_json_sha256_hex(ctx.permissions, "permissions")?;
    let key_envelope_hash = stable_json_sha256_hex(ctx.key_envelope, "key_envelope")?;
    Ok(format!(
        "{domain}\nversion:1\naction:{action}\ngrant_id:{grant_id}\nvault_object_id:{vault_object_id}\nnft_token_id:{nft_token_id}\nowner_identity_id:{owner_identity_id}\nrecipient_identity_id:{recipient_identity_id}\npermissions_sha256:{permissions_hash}\nexpires_at:{expires_at}\nkey_envelope_sha256:{key_envelope_hash}",
        domain = GRANT_SIGNATURE_DOMAIN,
        action = ctx.action,
        grant_id = ctx.grant_id,
        vault_object_id = ctx.vault_object_id,
        nft_token_id = ctx.nft_token_id.unwrap_or(""),
        owner_identity_id = ctx.owner_identity_id,
        recipient_identity_id = ctx.recipient_identity_id,
        expires_at = ctx.expires_at.map(DateTime::to_rfc3339).unwrap_or_default(),
    ))
}

pub(crate) fn grant_context_hash(ctx: &GrantSignatureContext<'_>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        grant_signature_message(ctx)?.as_bytes(),
    )))
}

pub(crate) fn verify_grant_owner_signature(
    signing_public_key_hex: &str,
    ctx: &GrantSignatureContext<'_>,
    signature_hex_or_b64: &str,
) -> Result<()> {
    if signature_hex_or_b64.trim().is_empty() {
        return Err(ApiError::Unauthorized(
            "Missing grant owner signature".into(),
        ));
    }
    verify_ed25519_hex_or_b64(
        signing_public_key_hex,
        grant_signature_message(ctx)?.as_bytes(),
        signature_hex_or_b64,
    )
}

pub(crate) fn stable_json_sha256_hex(value: &Value, field_name: &str) -> Result<String> {
    let normalized = canonical_json(value);
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|e| ApiError::BadRequest(format!("invalid {field_name}: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(value) = map.get(key) {
                    out.insert(key.clone(), canonical_json(value));
                }
            }
            Value::Object(out)
        },
        _ => value.clone(),
    }
}

fn verify_ed25519_hex_or_b64(
    public_key_hex: &str,
    message: &[u8],
    signature_hex_or_b64: &str,
) -> Result<()> {
    let pk = hex::decode(public_key_hex)
        .map_err(|_| ApiError::Unauthorized("Invalid grant owner public key".into()))?;
    if pk.len() != 32 {
        return Err(ApiError::Unauthorized(
            "Invalid grant owner public key length".into(),
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Unauthorized("Invalid grant owner public key".into()))?;

    let sig_bytes = hex::decode(signature_hex_or_b64)
        .or_else(|_| {
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature_hex_or_b64,
            )
        })
        .map_err(|_| ApiError::Unauthorized("Invalid grant owner signature encoding".into()))?;
    if sig_bytes.len() != 64 {
        return Err(ApiError::Unauthorized(
            "Invalid grant owner signature length".into(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|_| ApiError::Unauthorized("Invalid grant owner signature".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_context<'a>(
        grant_id: &'a Uuid,
        recipient_identity_id: &'a str,
        vault_object_id: &'a str,
        permissions: &'a Value,
        expires_at: Option<&'a DateTime<Utc>>,
        key_envelope: &'a Value,
    ) -> GrantSignatureContext<'a> {
        GrantSignatureContext {
            action: GRANT_CREATE_ACTION,
            grant_id,
            vault_object_id,
            nft_token_id: Some("nft-1"),
            owner_identity_id: "owner-1",
            recipient_identity_id,
            permissions,
            expires_at,
            key_envelope,
        }
    }

    fn signed_context(
        permissions: &Value,
        expires_at: Option<&DateTime<Utc>>,
        key_envelope: &Value,
    ) -> (SigningKey, Uuid, String) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let grant_id = Uuid::new_v4();
        let ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            permissions,
            expires_at,
            key_envelope,
        );
        let message = grant_signature_message(&ctx).unwrap();
        let signature = signing_key.sign(message.as_bytes());
        (signing_key, grant_id, hex::encode(signature.to_bytes()))
    }

    #[test]
    fn valid_grant_signature_is_accepted() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({
            "protocol": "vaulted-key-envelope-v1",
            "alg": "legacy-pre-aes-key",
            "recipient_identity_id": "recipient-a",
            "encrypted_file_key": "ciphertext"
        });
        let expires_at = DateTime::parse_from_rfc3339("2035-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let (signing_key, grant_id, signature) =
            signed_context(&permissions, Some(&expires_at), &key_envelope);
        let ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            Some(&expires_at),
            &key_envelope,
        );

        verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &ctx,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn missing_grant_signature_is_rejected() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let grant_id = Uuid::new_v4();
        let ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            None,
            &key_envelope,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &ctx,
            "",
        )
        .is_err());
    }

    #[test]
    fn invalid_grant_signature_is_rejected() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let grant_id = Uuid::new_v4();
        let ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            None,
            &key_envelope,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &ctx,
            &hex::encode([9u8; 64]),
        )
        .is_err());
    }

    #[test]
    fn signature_for_recipient_a_is_rejected_for_recipient_b() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let (signing_key, grant_id, signature) = signed_context(&permissions, None, &key_envelope);
        let changed = test_context(
            &grant_id,
            "recipient-b",
            "vault-object-a",
            &permissions,
            None,
            &key_envelope,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &changed,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn signature_for_vault_object_a_is_rejected_for_vault_object_b() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let (signing_key, grant_id, signature) = signed_context(&permissions, None, &key_envelope);
        let changed = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-b",
            &permissions,
            None,
            &key_envelope,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &changed,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn signature_for_permissions_or_expiry_a_is_rejected_for_modified_values() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let expires_at = DateTime::parse_from_rfc3339("2035-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let (signing_key, grant_id, signature) =
            signed_context(&permissions, Some(&expires_at), &key_envelope);
        let changed_permissions = serde_json::json!(["read", "write"]);
        let changed_expiry = DateTime::parse_from_rfc3339("2036-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let changed_permissions_ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &changed_permissions,
            Some(&expires_at),
            &key_envelope,
        );
        let changed_expiry_ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            Some(&changed_expiry),
            &key_envelope,
        );

        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        assert!(
            verify_grant_owner_signature(&public_key, &changed_permissions_ctx, &signature)
                .is_err()
        );
        assert!(
            verify_grant_owner_signature(&public_key, &changed_expiry_ctx, &signature).is_err()
        );
    }

    #[test]
    fn replay_with_same_signature_but_changed_grant_id_is_rejected() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope = serde_json::json!({"encrypted_file_key": "ciphertext"});
        let (signing_key, _grant_id, signature) = signed_context(&permissions, None, &key_envelope);
        let replay_grant_id = Uuid::new_v4();
        let replay_ctx = test_context(
            &replay_grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            None,
            &key_envelope,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &replay_ctx,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn key_envelope_hash_changes_when_envelope_changes() {
        let permissions = serde_json::json!(["read"]);
        let key_envelope_a = serde_json::json!({"encrypted_file_key": "ciphertext-a"});
        let key_envelope_b = serde_json::json!({"encrypted_file_key": "ciphertext-b"});
        let (signing_key, grant_id, signature) =
            signed_context(&permissions, None, &key_envelope_a);
        let changed_ctx = test_context(
            &grant_id,
            "recipient-a",
            "vault-object-a",
            &permissions,
            None,
            &key_envelope_b,
        );

        assert!(verify_grant_owner_signature(
            &hex::encode(signing_key.verifying_key().as_bytes()),
            &changed_ctx,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn stable_json_hash_is_object_key_order_independent() {
        let first = serde_json::json!({
            "b": 2,
            "a": {
                "d": 4,
                "c": 3
            }
        });
        let second = serde_json::json!({
            "a": {
                "c": 3,
                "d": 4
            },
            "b": 2
        });

        assert_eq!(
            stable_json_sha256_hex(&first, "test").unwrap(),
            stable_json_sha256_hex(&second, "test").unwrap()
        );
    }
}
