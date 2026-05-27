//! Vaulted-owned XRPL wallet derivation and local XRPL transaction signing.
//!
//! This module deliberately does not depend on external wallet providers. XRPL keys are derived
//! from the Vaulted BIP-39 seed with a dedicated domain separator so blockchain signing keys never
//! overlap with Vaulted encryption/signing identity keys.
//!
//! The XRPL serializer implemented here intentionally covers the transaction subset Vaulted needs
//! for its MVP: locally signing XLS-20 `NFTokenMint`, `NFTokenCreateOffer`,
//! `NFTokenAcceptOffer`, and testnet XRP `Payment` transactions.
//! Unsupported fields fail closed instead of being silently omitted.

use hkdf::Hkdf;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use xrpl_mithril_codec::{serializer, signing as xrpl_signing};
use zeroize::Zeroize;

use crate::{seed::SeedManager, CryptoError, Result};

const XRPL_ROOT_SALT: &[u8] = b"Vaulted v1 wallet xrpl";
const XRPL_SECP256K1_INFO: &[u8] = b"Vaulted v1 wallet xrpl secp256k1 signing";
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
    /// Currently supported: `NFTokenMint`, `NFTokenCreateOffer`, `NFTokenAcceptOffer`, and XRP
    /// `Payment`. The transaction must include the common network fields `Fee`, `Sequence`, and
    /// `LastLedgerSequence`. This function rejects mismatched Account fields and unsupported
    /// transaction types.
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

        let digest = xrpl_signing::signing_hash(tx_object(&tx)?)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let signature_der_hex = self.sign_digest_hex(&digest)?;

        tx["TxnSignature"] = serde_json::Value::String(signature_der_hex.clone());
        let final_blob = serialize_supported_xrpl_tx(&tx, true)?;
        let tx_hash = xrpl_signing::transaction_id_hex(tx_object(&tx)?)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

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

/// XRPL XRP Payment builder for sending drops from a Vaulted-derived account.
pub fn build_xrp_payment_tx(
    account: &str,
    destination: &str,
    amount_drops: &str,
    destination_tag: Option<u32>,
) -> serde_json::Value {
    let mut tx = serde_json::json!({
        "TransactionType": "Payment",
        "Account": account,
        "Destination": destination,
        "Amount": amount_drops,
    });
    if let Some(tag) = destination_tag {
        tx["DestinationTag"] = serde_json::json!(tag);
    }
    tx
}

/// XRPL NFTokenCreateOffer builder for a zero-amount destination transfer offer.
pub fn build_nftoken_create_offer_tx(
    account: &str,
    nftoken_id: &str,
    destination: &str,
    amount_drops: &str,
) -> serde_json::Value {
    serde_json::json!({
        "TransactionType": "NFTokenCreateOffer",
        "Account": account,
        "NFTokenID": nftoken_id,
        "Amount": amount_drops,
        "Flags": 1,
        "Destination": destination,
    })
}

/// XRPL NFTokenAcceptOffer builder for accepting a sell offer.
pub fn build_nftoken_accept_offer_tx(account: &str, nftoken_sell_offer: &str) -> serde_json::Value {
    serde_json::json!({
        "TransactionType": "NFTokenAcceptOffer",
        "Account": account,
        "NFTokenSellOffer": nftoken_sell_offer,
    })
}

/// Validates an XRPL classic address checksum and account-id shape.
pub fn is_valid_xrpl_classic_address(address: &str) -> bool {
    let Ok(decoded) = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
    else {
        return false;
    };
    if decoded.len() != 25 || decoded[0] != 0x00 {
        return false;
    }

    let payload = &decoded[..21];
    let checksum = &decoded[21..];
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    checksum == &second[..4]
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
    match transaction_type.as_str() {
        "NFTokenMint" => validate_nftoken_mint_tx(tx)?,
        "NFTokenCreateOffer" => validate_nftoken_create_offer_tx(tx)?,
        "NFTokenAcceptOffer" => validate_nftoken_accept_offer_tx(tx)?,
        "Payment" => validate_xrp_payment_tx(tx)?,
        _ => {
            return Err(CryptoError::InvalidData(format!(
                "Unsupported XRPL transaction type: {}",
                transaction_type
            )));
        },
    }
    validate_common_signing_fields(tx)?;
    Ok(())
}

fn validate_common_signing_fields(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "Account")?;
    let _ = string_field(tx, "Fee")?;
    let _ = u32_field(tx, "Sequence")?;
    let _ = u32_field(tx, "LastLedgerSequence")?;
    Ok(())
}

fn validate_nftoken_mint_tx(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "URI")?;
    let _ = u32_field(tx, "NFTokenTaxon")?;
    Ok(())
}

fn validate_xrp_payment_tx(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "Destination")?;
    let _ = string_field(tx, "Amount")?;
    if tx.get("DestinationTag").is_some() {
        let _ = u32_field(tx, "DestinationTag")?;
    }
    Ok(())
}

fn validate_nftoken_create_offer_tx(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "NFTokenID")?;
    let _ = string_field(tx, "Amount")?;
    let _ = u32_field(tx, "Flags")?;
    if tx.get("Destination").is_some() {
        let _ = string_field(tx, "Destination")?;
    }
    Ok(())
}

fn validate_nftoken_accept_offer_tx(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "NFTokenSellOffer")?;
    Ok(())
}

fn serialize_supported_xrpl_tx(tx: &serde_json::Value, include_signature: bool) -> Result<Vec<u8>> {
    validate_supported_signable_tx(tx)?;
    let mut out = Vec::new();
    serializer::serialize_json_object(tx_object(tx)?, &mut out, !include_signature)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(out)
}

fn tx_object(tx: &serde_json::Value) -> Result<&serde_json::Map<String, serde_json::Value>> {
    tx.as_object().ok_or_else(|| {
        CryptoError::InvalidData("XRPL transaction must be a JSON object".to_string())
    })
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

fn classic_address_from_public_key(public_key: &[u8]) -> String {
    let sha = Sha256::digest(public_key);
    let ripe = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00); // account id prefix
    payload.extend_from_slice(&ripe);
    encode_xrpl_base58_check(&payload)
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
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

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
        let tx_blob = signed.tx_blob.as_ref().unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert_eq!(tx_blob.len() % 2, 0);
        assert!(hex::decode(tx_blob).is_ok());
        assert!(!tx_blob.is_empty());
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert!(signed.tx_json.get("TxnSignature").is_some());
    }

    #[test]
    fn signs_xrp_payment_as_xrpl_tx_blob() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();
        let tx = build_xrp_payment_tx(&account, &destination, "1000000", Some(123));
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let tx_blob = signed.tx_blob.as_ref().unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert_eq!(tx_blob.len() % 2, 0);
        assert!(hex::decode(tx_blob).is_ok());
        assert!(!tx_blob.is_empty());
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert_eq!(signed.tx_json["TransactionType"], "Payment");
        assert!(signed.tx_json.get("TxnSignature").is_some());
    }

    #[test]
    fn signs_nftoken_create_offer_as_xrpl_tx_blob() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();
        let tx = build_nftoken_create_offer_tx(
            &account,
            "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
            &destination,
            "0",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let tx_blob = signed.tx_blob.as_ref().unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert_eq!(tx_blob.len() % 2, 0);
        assert!(hex::decode(tx_blob).is_ok());
        assert!(!tx_blob.is_empty());
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert_eq!(signed.tx_json["TransactionType"], "NFTokenCreateOffer");
        assert!(signed.tx_json.get("TxnSignature").is_some());
    }

    #[test]
    fn signs_nftoken_accept_offer_as_xrpl_tx_blob() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = build_nftoken_accept_offer_tx(
            &account,
            "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let tx_blob = signed.tx_blob.as_ref().unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert_eq!(tx_blob.len() % 2, 0);
        assert!(hex::decode(tx_blob).is_ok());
        assert!(!tx_blob.is_empty());
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert_eq!(signed.tx_json["TransactionType"], "NFTokenAcceptOffer");
        assert!(signed.tx_json.get("TxnSignature").is_some());
    }

    #[test]
    fn rejects_mismatched_account_for_payment_signing() {
        let wallet = deterministic_wallet();
        let destination = VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();
        let tx = build_xrp_payment_tx("rrrrrrrrrrrrrrrrrrrrrhoLvTp", &destination, "1000000", None);
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }

    #[test]
    fn rejects_mismatched_account_for_nftoken_create_offer_signing() {
        let wallet = deterministic_wallet();
        let destination = VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();
        let tx = build_nftoken_create_offer_tx(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
            &destination,
            "0",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }

    #[test]
    fn rejects_mismatched_account_for_nftoken_accept_offer_signing() {
        let wallet = deterministic_wallet();
        let tx = build_nftoken_accept_offer_tx(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }

    #[test]
    fn rejects_nftoken_create_offer_missing_required_fields() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();

        for missing_field in ["NFTokenID", "Amount"] {
            let mut tx = build_nftoken_create_offer_tx(
                &account,
                "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                &destination,
                "0",
            );
            tx.as_object_mut().unwrap().remove(missing_field);
            let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

            assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
        }
    }

    #[test]
    fn rejects_nftoken_accept_offer_missing_required_fields() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let mut tx = build_nftoken_accept_offer_tx(
            &account,
            "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
        );
        tx.as_object_mut().unwrap().remove("NFTokenSellOffer");
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }

    #[test]
    fn validates_xrpl_classic_address_checksum() {
        let address = deterministic_wallet().classic_address().unwrap();
        assert!(is_valid_xrpl_classic_address(&address));
        assert!(!is_valid_xrpl_classic_address("rInvalid"));
    }

    #[test]
    fn codec_serializes_nftoken_mint_as_non_empty_binary() {
        let mnemonic = SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS).unwrap();
        let wallet = VaultedXrplWallet::from_mnemonic(&mnemonic, None).unwrap();
        let account = wallet.classic_address().unwrap();
        let tx = add_xrpl_signing_fields(
            build_nftoken_mint_tx(&account, "ipfs://manifest", 0, None, None),
            "12",
            1,
            100,
        );
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let final_blob = serialize_supported_xrpl_tx(&signed.tx_json, true).unwrap();

        assert!(!final_blob.is_empty());
        assert_eq!(signed.tx_json["TransactionType"], "NFTokenMint");
    }

    #[test]
    fn nftoken_mint_uri_uses_hex_json_and_codec_binary_for_111_byte_uri() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let metadata_uri = "u".repeat(111);
        let metadata_uri_len = metadata_uri.len();
        let tx = build_nftoken_mint_tx(&account, &metadata_uri, 0, None, None);
        let stored_uri = string_field(&tx, "URI").unwrap();
        let stored_uri_is_hex = hex::decode(&stored_uri).is_ok();

        assert_eq!(metadata_uri_len, 111);
        assert_eq!(stored_uri.len(), metadata_uri_len * 2);
        assert!(stored_uri_is_hex);

        let tx = add_xrpl_signing_fields(tx, "10", 1, 100);
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let final_blob = serialize_supported_xrpl_tx(&signed.tx_json, true).unwrap();

        assert!(!final_blob.is_empty());
    }

    #[test]
    fn xrpl_codec_signing_hash_and_local_signature_verify() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = add_xrpl_signing_fields(
            build_nftoken_mint_tx(&account, &"u".repeat(111), 0, None, None),
            "10",
            1,
            100,
        );
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let signing_blob = serialize_supported_xrpl_tx(&signed.tx_json, false).unwrap();
        let final_blob = serialize_supported_xrpl_tx(&signed.tx_json, true).unwrap();

        assert!(final_blob.len() > signing_blob.len());

        let signing_hash = xrpl_signing::signing_hash(tx_object(&signed.tx_json).unwrap()).unwrap();
        let signature_bytes = hex::decode(&signed.signature_der_hex).unwrap();
        let signature = Signature::from_der(&signature_bytes).unwrap();
        let verifying_key = VerifyingKey::from(&wallet.signing_key().unwrap());
        verifying_key
            .verify_prehash(&signing_hash, &signature)
            .unwrap();
    }

    #[test]
    fn codec_signing_serialization_excludes_txn_signature_and_final_includes_it() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = add_xrpl_signing_fields(
            build_nftoken_mint_tx(&account, &"u".repeat(111), 0, None, None),
            "10",
            1,
            100,
        );
        let signed = wallet.sign_xrpl_transaction_json(&tx).unwrap();
        let signing_blob = serialize_supported_xrpl_tx(&signed.tx_json, false).unwrap();
        let final_blob = serialize_supported_xrpl_tx(&signed.tx_json, true).unwrap();

        assert!(signed.tx_json.get("TxnSignature").is_some());
        assert!(final_blob.len() > signing_blob.len());
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

    fn deterministic_wallet() -> VaultedXrplWallet {
        VaultedXrplWallet::from_bip39_seed(&[7u8; 64]).unwrap()
    }
}
