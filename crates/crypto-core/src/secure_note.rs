//! Secure note encryption flow for high-risk secrets.

use serde::{Deserialize, Serialize};

use crate::{
    aes::AesKey,
    envelope::{seal_key_for_recipient, KeyEnvelope},
    identity::VaultedIdentityKeys,
    types::EncryptedData,
    Result,
};

/// Encrypted secure note payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecureNote {
    /// Encrypted note body.
    pub encrypted_note: EncryptedData,
    /// Wrapped note key for the owner.
    pub note_key_envelope: KeyEnvelope,
}

/// Encrypts a secure note with a random note key and owner key envelope.
pub fn encrypt_secure_note_for_owner(
    note_plaintext: &[u8],
    owner: &VaultedIdentityKeys,
    aad: &[u8],
) -> Result<EncryptedSecureNote> {
    let note_key = AesKey::generate();
    let encrypted_note = note_key.encrypt_with_aad(note_plaintext, aad)?;
    let envelope = seal_key_for_recipient(
        note_key.as_bytes(),
        &owner.encryption_public_key(),
        owner.identity_id_hex(),
        owner.encryption_public_key_hex(),
        "owner",
        aad,
    )?;
    Ok(EncryptedSecureNote {
        encrypted_note,
        note_key_envelope: envelope,
    })
}
