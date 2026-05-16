//! Vaulted-owned XRPL wallet derivation and local XRPL transaction signing.
//!
//! This module deliberately does not depend on external wallet providers. XRPL keys are derived
//! from the Vaulted BIP-39 seed with a dedicated domain separator so blockchain signing keys never
//! overlap with Vaulted encryption/signing identity keys.
//!
//! The XRPL serializer implemented here intentionally covers the transaction subset Vaulted needs
//! for its MVP: locally signing XLS-20 `NFTokenMint` transactions. Unsupported fields fail closed
//! instead of being silently omitted.

use hkdf::Hkdf;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::{seed::SeedManager, CryptoError, Result};

const XRPL_ROOT_SALT: &[u8] = b"Vaulted v1 wallet xrpl";
const XRPL_SECP256K1_INFO: &[u8] = b"Vaulted v1 wallet xrpl secp256k1 signing";
const XRPL_SIGNING_PREFIX: [u8; 4] = *b"STX\0";
const XRPL_TX_ID_PREFIX: [u8; 4] = *b"TXN\0";
const NF_TOKEN_MINT_TRANSACTION_TYPE: u16 = 25;
const TF_TRANSFERABLE: u32 = 0x0000_0008;

/// Vaulted-derived XRPL wallet. Private key material is zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultedXrplWallet {
    private_key: [u8; 32],
}

impl VaultedXrplWallet {
    /// Derives the XRPL wallet from a BIP-39 mnemonic with a separate XRPL domain.
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let mut seed = SeedManager::mnemonic_to_seed(mnemonic, passphrase)?;
        let wallet = Self::from_bip39_seed(&seed)?;
        seed.zeroize();
        Ok(wallet)
    }

    /// Derives the XRPL wallet from a BIP-39 seed.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Result<Self> {
        let root = Hkdf::<Sha256>::new(Some(XRPL_ROOT_SALT), seed);
        let mut candidate = [0u8; 32];
        root.expand(XRPL_SECP256K1_INFO, &mut candidate)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // k256 rejects zero/out-of-range scalars. Re-hash with a counter until valid.
        for counter in 0u8..=32 {
            let material = if counter == 0 {
                candidate
            } else {
                let mut h = Sha256::new();
                h.update(b"Vaulted XRPL secp256k1 retry");
                h.update(candidate);
                h.update([counter]);
                h.finalize().into()
            };
            if SigningKey::from_bytes((&material).into()).is_ok() {
                candidate.zeroize();
                return Ok(Self {
                    private_key: material,
                });
            }
        }

        candidate.zeroize();
        Err(CryptoError::KeyDerivation(
            "Could not derive a valid XRPL secp256k1 key".to_string(),
        ))
    }

    /// Returns the secp256k1 signing key.
    pub fn signing_key(&self) -> Result<SigningKey> {
        SigningKey::from_bytes((&self.private_key).into())
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))
    }

    /// Compressed secp256k1 public key hex.
    pub fn public_key_hex(&self) -> Result<String> {
        let verifying = VerifyingKey::from(&self.signing_key()?);
        Ok(hex::encode_upper(
            verifying.to_encoded_point(true).as_bytes(),
        ))
    }

    /// XRPL classic address derived from the compressed public key.
    pub fn classic_address(&self) -> Result<String> {
        let public_key = hex::decode(self.public_key_hex()?)
            .map_err(|e| CryptoError::InvalidData(e.to_string()))?;
        Ok(classic_address_from_public_key(&public_key))
    }

    /// Signs a 32-byte digest and returns canonical DER signature hex.
    pub fn sign_digest_hex(&self, digest: &[u8; 32]) -> Result<String> {
        let key = self.signing_key()?;
        let sig: Signature = key
            .sign_prehash(digest)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(hex::encode_upper(sig.to_der().as_bytes()))
    }

    /// Signs a canonical JSON transaction payload for QR/offline handoff.
    ///
    /// This is an application-level signature payload. Prefer [`sign_xrpl_transaction_json`] when
    /// a real XRPL binary `tx_blob` is required for network submission.
    pub fn sign_transaction_json(
        &self,
        tx_json: &serde_json::Value,
    ) -> Result<VaultedSignedXrplTransaction> {
        let canonical =
            serde_json::to_vec(tx_json).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let digest = sha512_half(&canonical);
        Ok(VaultedSignedXrplTransaction {
            tx_json: tx_json.clone(),
            signing_public_key: self.public_key_hex()?,
            classic_address: self.classic_address()?,
            signature_der_hex: self.sign_digest_hex(&digest)?,
            digest_hex: hex::encode_upper(digest),
            protocol: "vaulted-xrpl-json-signature-v1".to_string(),
            tx_blob: None,
            tx_hash: None,
        })
    }

    /// Locally signs a Vaulted-supported XRPL transaction and returns a submission-ready tx_blob.
    ///
    /// Currently supported: `NFTokenMint`. The transaction must include the common network fields
    /// `Fee`, `Sequence`, and `LastLedgerSequence`. This function rejects mismatched Account fields
    /// and unsupported transaction types.
    pub fn sign_xrpl_transaction_json(
        &self,
        tx_json: &serde_json::Value,
    ) -> Result<VaultedSignedXrplTransaction> {
        let mut tx = tx_json.clone();
        validate_supported_signable_tx(&tx)?;

        let account = string_field(&tx, "Account")?;
        let wallet_address = self.classic_address()?;
        if account != wallet_address {
            return Err(CryptoError::InvalidData(
                "XRPL transaction Account does not match Vaulted wallet".to_string(),
            ));
        }

        let signing_public_key = self.public_key_hex()?;
        tx["SigningPubKey"] = serde_json::Value::String(signing_public_key.clone());
        if let Some(obj) = tx.as_object_mut() {
            obj.remove("TxnSignature");
            obj.remove("hash");
        }

        let signing_blob = serialize_supported_xrpl_tx(&tx, false)?;
        let mut signing_preimage = Vec::with_capacity(4 + signing_blob.len());
        signing_preimage.extend_from_slice(&XRPL_SIGNING_PREFIX);
        signing_preimage.extend_from_slice(&signing_blob);
        let digest = sha512_half(&signing_preimage);
        let signature_der_hex = self.sign_digest_hex(&digest)?;

        tx["TxnSignature"] = serde_json::Value::String(signature_der_hex.clone());
        let final_blob = serialize_supported_xrpl_tx(&tx, true)?;
        let mut hash_preimage = Vec::with_capacity(4 + final_blob.len());
        hash_preimage.extend_from_slice(&XRPL_TX_ID_PREFIX);
        hash_preimage.extend_from_slice(&final_blob);
        let tx_hash = hex::encode_upper(sha512_half(&hash_preimage));

        Ok(VaultedSignedXrplTransaction {
            protocol: "vaulted-xrpl-tx-blob-v1".to_string(),
            tx_json: tx,
            signing_public_key,
            classic_address: wallet_address,
            signature_der_hex,
            digest_hex: hex::encode_upper(digest),
            tx_blob: Some(hex::encode_upper(final_blob)),
            tx_hash: Some(tx_hash),
        })
    }
}

impl std::fmt::Debug for VaultedXrplWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultedXrplWallet")
            .field(
                "classic_address",
                &self
                    .classic_address()
                    .unwrap_or_else(|_| "<invalid>".to_string()),
            )
            .finish()
    }
}

/// Public XRPL wallet details safe for UI/API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedXrplWalletPublic {
    /// XRPL classic account address.
    pub classic_address: String,
    /// Compressed secp256k1 public key, hex.
    pub public_key: String,
    /// Protocol version.
    pub protocol: String,
}

/// QR payload for a mobile/offline signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedQrSigningRequest {
    /// Payload type marker.
    pub r#type: String,
    /// Unique request id generated by desktop/oracle.
    pub request_id: String,
    /// XRPL transaction JSON to review/sign.
    pub tx_json: serde_json::Value,
    /// Oracle/network endpoint expected by the client.
    pub oracle_url: String,
    /// ISO timestamp after which the request must be rejected.
    pub expires_at: String,
    /// Optional human-readable explanation displayed before signing.
    pub human_summary: Option<String>,
}

/// Signed QR response that can be scanned/imported by desktop for submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedSignedXrplTransaction {
    /// Application protocol marker.
    pub protocol: String,
    /// Original transaction JSON. For real XRPL signing this includes SigningPubKey and TxnSignature.
    pub tx_json: serde_json::Value,
    /// Compressed secp256k1 public key, hex.
    pub signing_public_key: String,
    /// XRPL classic address derived from the signing key.
    pub classic_address: String,
    /// DER ECDSA signature hex.
    pub signature_der_hex: String,
    /// Digest hex that was signed.
    pub digest_hex: String,
    /// Submission-ready XRPL transaction blob, present for `vaulted-xrpl-tx-blob-v1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_blob: Option<String>,
    /// Locally calculated XRPL transaction hash, present for `vaulted-xrpl-tx-blob-v1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// XRPL NFTokenMint builder for Vaulted encrypted object metadata pointers.
pub fn build_nftoken_mint_tx(
    account: &str,
    metadata_uri: &str,
    nftoken_taxon: u32,
    flags: Option<u32>,
    transfer_fee: Option<u16>,
) -> serde_json::Value {
    let mut tx = serde_json::json!({
        "TransactionType": "NFTokenMint",
        "Account": account,
        "URI": hex::encode_upper(metadata_uri.as_bytes()),
        "NFTokenTaxon": nftoken_taxon,
        "Flags": flags.unwrap_or(TF_TRANSFERABLE)
    });
    if let Some(fee) = transfer_fee {
        tx["TransferFee"] = serde_json::json!(fee);
    }
    tx
}

/// Adds network-specific common fields required before local XRPL signing.
pub fn add_xrpl_signing_fields(
    mut tx_json: serde_json::Value,
    fee_drops: impl Into<String>,
    sequence: u32,
    last_ledger_sequence: u32,
) -> serde_json::Value {
    tx_json["Fee"] = serde_json::Value::String(fee_drops.into());
    tx_json["Sequence"] = serde_json::json!(sequence);
    tx_json["LastLedgerSequence"] = serde_json::json!(last_ledger_sequence);
    tx_json
}

fn validate_supported_signable_tx(tx: &serde_json::Value) -> Result<()> {
    let transaction_type = string_field(tx, "TransactionType")?;
    if transaction_type != "NFTokenMint" {
        return Err(CryptoError::InvalidData(format!(
            "Unsupported XRPL transaction type: {}",
            transaction_type
        )));
    }
    let _ = string_field(tx, "Account")?;
    let _ = string_field(tx, "URI")?;
    let _ = u32_field(tx, "NFTokenTaxon")?;
    let _ = string_field(tx, "Fee")?;
    let _ = u32_field(tx, "Sequence")?;
    let _ = u32_field(tx, "LastLedgerSequence")?;
    Ok(())
}

fn serialize_supported_xrpl_tx(tx: &serde_json::Value, include_signature: bool) -> Result<Vec<u8>> {
    validate_supported_signable_tx(tx)?;

    let mut out = Vec::new();

    // Canonical field order: type id, then field id.
    write_u16_field(&mut out, 2, NF_TOKEN_MINT_TRANSACTION_TYPE); // TransactionType
    if let Some(fee) = tx.get("TransferFee").and_then(|v| v.as_u64()) {
        write_u16_field(&mut out, 11, fee as u16); // TransferFee
    }
    write_u32_field(
        &mut out,
        2,
        tx.get("Flags").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
    ); // Flags
    write_u32_field(&mut out, 4, u32_field(tx, "Sequence")?); // Sequence
    write_u32_field(&mut out, 26, u32_field(tx, "NFTokenTaxon")?); // NFTokenTaxon
    write_u32_field(&mut out, 27, u32_field(tx, "LastLedgerSequence")?); // LastLedgerSequence
    write_xrp_amount_field(
        &mut out,
        8,
        string_field(tx, "Fee")?
            .parse::<u64>()
            .map_err(|e| CryptoError::InvalidData(format!("Invalid XRPL Fee drops: {}", e)))?,
    ); // Fee

    let signing_pub_key = string_field(tx, "SigningPubKey")?;
    write_blob_field(&mut out, 3, &hex_bytes(&signing_pub_key, "SigningPubKey")?); // SigningPubKey
    if include_signature {
        let sig = string_field(tx, "TxnSignature")?;
        write_blob_field(&mut out, 4, &hex_bytes(&sig, "TxnSignature")?); // TxnSignature
    }
    write_blob_field(&mut out, 45, &hex_bytes(&string_field(tx, "URI")?, "URI")?); // URI
    write_account_field(
        &mut out,
        1,
        &decode_classic_address(&string_field(tx, "Account")?)?,
    ); // Account

    Ok(out)
}

fn string_field(tx: &serde_json::Value, field: &str) -> Result<String> {
    tx.get(field)
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            CryptoError::InvalidData(format!("Missing or invalid XRPL field: {}", field))
        })
}

fn u32_field(tx: &serde_json::Value, field: &str) -> Result<u32> {
    let value = tx.get(field).and_then(|v| v.as_u64()).ok_or_else(|| {
        CryptoError::InvalidData(format!("Missing or invalid XRPL field: {}", field))
    })?;
    if value > u32::MAX as u64 {
        return Err(CryptoError::InvalidData(format!(
            "XRPL field {} exceeds u32 range",
            field
        )));
    }
    Ok(value as u32)
}

fn write_field_header(out: &mut Vec<u8>, type_code: u8, field_code: u8) {
    match (type_code < 16, field_code < 16) {
        (true, true) => out.push((type_code << 4) | field_code),
        (true, false) => {
            out.push(type_code << 4);
            out.push(field_code);
        },
        (false, true) => {
            out.push(field_code);
            out.push(type_code);
        },
        (false, false) => {
            out.push(0);
            out.push(type_code);
            out.push(field_code);
        },
    }
}

fn write_u16_field(out: &mut Vec<u8>, field_code: u8, value: u16) {
    write_field_header(out, 1, field_code);
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32_field(out: &mut Vec<u8>, field_code: u8, value: u32) {
    write_field_header(out, 2, field_code);
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_xrp_amount_field(out: &mut Vec<u8>, field_code: u8, drops: u64) {
    write_field_header(out, 6, field_code);
    let encoded = drops | 0x4000_0000_0000_0000;
    out.extend_from_slice(&encoded.to_be_bytes());
}

fn write_blob_field(out: &mut Vec<u8>, field_code: u8, bytes: &[u8]) {
    write_field_header(out, 7, field_code);
    write_variable_length(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_account_field(out: &mut Vec<u8>, field_code: u8, account_id: &[u8; 20]) {
    write_field_header(out, 8, field_code);
    out.extend_from_slice(account_id);
}

fn write_variable_length(out: &mut Vec<u8>, len: usize) {
    if len <= 192 {
        out.push(len as u8);
    } else if len <= 12_480 {
        let len = len - 193;
        out.push(193 + ((len >> 8) as u8));
        out.push((len & 0xff) as u8);
    } else {
        let len = len - 12_481;
        out.push(241 + ((len >> 16) as u8));
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

fn hex_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    hex::decode(value)
        .map_err(|e| CryptoError::InvalidData(format!("Invalid {} hex: {}", field, e)))
}

fn classic_address_from_public_key(public_key: &[u8]) -> String {
    let sha = Sha256::digest(public_key);
    let ripe = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00); // account id prefix
    payload.extend_from_slice(&ripe);
    encode_xrpl_base58_check(&payload)
}

fn decode_classic_address(address: &str) -> Result<[u8; 20]> {
    let data = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .map_err(|e| CryptoError::InvalidData(format!("Invalid XRPL address: {}", e)))?;
    if data.len() != 25 || data[0] != 0x00 {
        return Err(CryptoError::InvalidData(
            "Invalid XRPL classic address length/prefix".to_string(),
        ));
    }
    let (payload, checksum) = data.split_at(21);
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    if &second[..4] != checksum {
        return Err(CryptoError::InvalidData(
            "Invalid XRPL classic address checksum".to_string(),
        ));
    }
    let mut account_id = [0u8; 20];
    account_id.copy_from_slice(&payload[1..]);
    Ok(account_id)
}

fn encode_xrpl_base58_check(payload: &[u8]) -> String {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(payload);
    data.extend_from_slice(&second[..4]);
    bs58::encode(data)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

fn sha512_half(data: &[u8]) -> [u8; 32] {
    Sha512::digest(data)[..32]
        .try_into()
        .expect("SHA-512 half is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{SeedManager, DEFAULT_MNEMONIC_WORDS};

    #[test]
    fn xrpl_wallet_derivation_is_deterministic() {
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let a = VaultedXrplWallet::from_mnemonic(&mnemonic, None).unwrap();
        let b = VaultedXrplWallet::from_mnemonic(&mnemonic, None).unwrap();
        assert_eq!(a.classic_address().unwrap(), b.classic_address().unwrap());
        assert!(a.classic_address().unwrap().starts_with('r'));
    }

    #[test]
    fn nftoken_mint_uri_is_hex_encoded() {
        let tx = build_nftoken_mint_tx("rTest", "ipfs://manifest", 0, None, None);
        assert_eq!(tx["TransactionType"], "NFTokenMint");
        assert_eq!(tx["URI"], hex::encode_upper("ipfs://manifest"));
    }

    #[test]
    fn signs_nftoken_mint_as_xrpl_tx_blob() {
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let wallet = VaultedXrplWallet::from_mnemonic(&mnemonic, None).unwrap();
        let account = wallet.classic_address().unwrap();
        let tx = build_nftoken_mint_tx(&account, "ipfs://manifest", 0, None, None);
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert!(signed.tx_blob.as_ref().unwrap().starts_with("120019"));
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert_eq!(
            signed.tx_json["SigningPubKey"],
            wallet.public_key_hex().unwrap()
        );
        assert!(signed.tx_json.get("TxnSignature").is_some());
    }

    #[test]
    fn rejects_mismatched_account_for_local_signing() {
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let wallet = VaultedXrplWallet::from_mnemonic(&mnemonic, None).unwrap();
        let tx = build_nftoken_mint_tx(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            "ipfs://manifest",
            0,
            None,
            None,
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }
}
