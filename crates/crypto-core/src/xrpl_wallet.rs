//! Vaulted-owned XRPL wallet derivation and local XRPL transaction signing.
//!
//! This module deliberately does not depend on external wallet providers. XRPL keys are derived
//! from the Vaulted BIP-39 seed using standard XRP BIP-44 so the account matches other XRP wallets.
//!
//! The XRPL serializer implemented here intentionally covers the transaction subset Vaulted needs
//! for its MVP: locally signing XLS-20 `NFTokenMint`, `NFTokenCreateOffer`,
//! `NFTokenAcceptOffer`, and testnet XRP `Payment` transactions.
//! Unsupported fields fail closed instead of being silently omitted.

use hmac::{Hmac, Mac};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use xrpl_mithril_codec::{serializer, signing as xrpl_signing};
use zeroize::Zeroize;

use crate::{seed::SeedManager, CryptoError, Result};

type HmacSha512 = Hmac<Sha512>;

const BIP32_MASTER_KEY: &[u8] = b"Bitcoin seed";
const BIP32_HARDENED_OFFSET: u32 = 0x8000_0000;
const XRP_BIP44_PATH: [u32; 5] = [
    BIP32_HARDENED_OFFSET + 44,
    BIP32_HARDENED_OFFSET + 144,
    BIP32_HARDENED_OFFSET,
    0,
    0,
];
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const TF_TRANSFERABLE: u32 = 0x0000_0008;
const TF_NFTOKEN_SELL_OFFER: u32 = 0x0000_0001;
const MAX_SIGNING_FEE_DROPS: u64 = 100_000;
const MAX_TRANSFER_FEE_BPS: u16 = 50_000;

/// High-level user-approved XRPL signing intent.
///
/// Vaulted only signs a transaction when the JSON exactly matches one of these
/// reviewed intents. This prevents hidden XRPL fields or unrelated transaction
/// types from reaching the local signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrplSigningIntent {
    /// Send native XRP drops to a reviewed destination.
    SendXrp {
        /// Reviewed destination classic address.
        destination: String,
        /// Reviewed native XRP amount in drops.
        amount_drops: String,
        /// Reviewed destination tag, when supplied by the user.
        destination_tag: Option<u32>,
    },
    /// Mint a Vaulted NFT with a Vaulted-generated metadata URI.
    MintVaultNft {
        /// Reviewed/generated metadata URI before XRPL hex encoding.
        metadata_uri: String,
        /// Reviewed NFT taxon.
        nftoken_taxon: u32,
        /// Reviewed NFT flags.
        flags: u32,
        /// Reviewed transfer fee, if any.
        transfer_fee: Option<u16>,
    },
    /// Create a private zero-amount NFT transfer sell offer.
    CreateNftTransferOffer {
        /// Selected Vaulted NFT token id.
        nftoken_id: String,
        /// Reviewed recipient classic address.
        destination: String,
    },
    /// Accept a verified NFT transfer sell offer.
    AcceptNftTransferOffer {
        /// Verified NFToken sell offer ledger index.
        offer_index: String,
    },
    /// Burn the selected Vaulted NFT after explicit confirmation.
    BurnVaultNft {
        /// Selected Vaulted NFT token id.
        nftoken_id: String,
    },
}

/// Vaulted-derived XRPL wallet. Private key material is zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultedXrplWallet {
    private_key: [u8; 32],
}

impl VaultedXrplWallet {
    /// Derives the XRPL wallet from a BIP-39 mnemonic using XRP BIP-44.
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let mut seed = SeedManager::mnemonic_to_seed(mnemonic, passphrase)?;
        let wallet = Self::from_bip39_seed(&seed)?;
        seed.zeroize();
        Ok(wallet)
    }

    /// Derives the XRPL wallet from a BIP-39 seed using m/44'/144'/0'/0/0.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Result<Self> {
        Ok(Self {
            private_key: derive_xrp_bip44_private_key(seed)?,
        })
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
        let account = self.classic_address()?;
        validate_qr_xrpl_signing_request(tx_json, &account)?;
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
        _tx_json: &serde_json::Value,
    ) -> Result<VaultedSignedXrplTransaction> {
        Err(CryptoError::InvalidData(
            "XRPL transaction signing requires an explicit Vaulted signing intent".to_string(),
        ))
    }

    /// Locally signs a Vaulted-supported XRPL transaction after intent policy validation.
    pub fn sign_xrpl_transaction_for_intent(
        &self,
        intent: &XrplSigningIntent,
        tx_json: &serde_json::Value,
    ) -> Result<VaultedSignedXrplTransaction> {
        let mut tx = tx_json.clone();
        let wallet_address = self.classic_address()?;
        validate_xrpl_transaction_for_intent(intent, &tx, &wallet_address)?;

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

/// XRPL NFTokenBurn builder for deleting a Vaulted-owned NFT.
pub fn build_nftoken_burn_tx(account: &str, nftoken_id: &str) -> serde_json::Value {
    serde_json::json!({
        "TransactionType": "NFTokenBurn",
        "Account": account,
        "NFTokenID": nftoken_id,
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

/// Validates a signable XRPL transaction against a reviewed Vaulted intent.
pub fn validate_xrpl_transaction_for_intent(
    intent: &XrplSigningIntent,
    tx: &serde_json::Value,
    wallet_address: &str,
) -> Result<()> {
    validate_common_signing_fields(tx, wallet_address)?;
    match intent {
        XrplSigningIntent::SendXrp {
            destination,
            amount_drops,
            destination_tag,
        } => validate_xrp_payment_policy(tx, destination, amount_drops, *destination_tag),
        XrplSigningIntent::MintVaultNft {
            metadata_uri,
            nftoken_taxon,
            flags,
            transfer_fee,
        } => validate_nftoken_mint_policy(tx, metadata_uri, *nftoken_taxon, *flags, *transfer_fee),
        XrplSigningIntent::CreateNftTransferOffer {
            nftoken_id,
            destination,
        } => validate_nftoken_create_offer_policy(tx, nftoken_id, destination),
        XrplSigningIntent::AcceptNftTransferOffer { offer_index } => {
            validate_nftoken_accept_offer_policy(tx, offer_index)
        },
        XrplSigningIntent::BurnVaultNft { nftoken_id } => {
            validate_nftoken_burn_policy(tx, nftoken_id)
        },
    }
}

/// Validates an unsigned QR XRPL signing request before the wallet signs its digest.
///
/// Current QR handoff support is intentionally limited to Vaulted NFTokenMint
/// requests. It does not accept arbitrary transaction JSON.
pub fn validate_qr_xrpl_signing_request(
    tx: &serde_json::Value,
    wallet_address: &str,
) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "URI",
            "NFTokenTaxon",
            "Flags",
            "TransferFee",
        ],
    )?;
    require_transaction_type(tx, "NFTokenMint")?;
    require_account(tx, wallet_address)?;
    let flags = u32_field(tx, "Flags")?;
    if flags != TF_TRANSFERABLE {
        return Err(CryptoError::InvalidData(
            "QR NFTokenMint flags are not allowlisted".to_string(),
        ));
    }
    let _ = string_field(tx, "URI")?;
    let _ = u32_field(tx, "NFTokenTaxon")?;
    if tx.get("TransferFee").is_some() {
        let fee = u32_field(tx, "TransferFee")?;
        if fee > MAX_TRANSFER_FEE_BPS as u32 {
            return Err(CryptoError::InvalidData(
                "QR NFTokenMint TransferFee exceeds Vaulted policy".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_supported_signable_tx(tx: &serde_json::Value) -> Result<()> {
    let transaction_type = string_field(tx, "TransactionType")?;
    match transaction_type.as_str() {
        "NFTokenMint" => validate_nftoken_mint_tx(tx)?,
        "NFTokenCreateOffer" => validate_nftoken_create_offer_tx(tx)?,
        "NFTokenAcceptOffer" => validate_nftoken_accept_offer_tx(tx)?,
        "NFTokenBurn" => validate_nftoken_burn_tx(tx)?,
        "Payment" => validate_xrp_payment_tx(tx)?,
        _ => {
            return Err(CryptoError::InvalidData(format!(
                "Unsupported XRPL transaction type: {}",
                transaction_type
            )));
        },
    }
    validate_common_shape_fields(tx)?;
    Ok(())
}

fn validate_common_shape_fields(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "Account")?;
    let _ = string_field(tx, "Fee")?;
    let _ = u32_field(tx, "Sequence")?;
    let _ = u32_field(tx, "LastLedgerSequence")?;
    Ok(())
}

fn validate_common_signing_fields(tx: &serde_json::Value, wallet_address: &str) -> Result<()> {
    reject_forbidden_fields(tx)?;
    require_account(tx, wallet_address)?;
    let fee = string_field(tx, "Fee")?;
    let fee = parse_drops(&fee, "Fee")?;
    if fee == 0 || fee > MAX_SIGNING_FEE_DROPS {
        return Err(CryptoError::InvalidData(
            "XRPL transaction Fee exceeds Vaulted policy".to_string(),
        ));
    }
    let sequence = u32_field(tx, "Sequence")?;
    if sequence == 0 {
        return Err(CryptoError::InvalidData(
            "XRPL transaction Sequence must be populated from account_info".to_string(),
        ));
    }
    let last_ledger_sequence = u32_field(tx, "LastLedgerSequence")?;
    if last_ledger_sequence == 0 {
        return Err(CryptoError::InvalidData(
            "XRPL transaction LastLedgerSequence is required".to_string(),
        ));
    }
    Ok(())
}

fn require_account(tx: &serde_json::Value, wallet_address: &str) -> Result<()> {
    let account = string_field(tx, "Account")?;
    if account != wallet_address {
        return Err(CryptoError::InvalidData(
            "XRPL transaction Account does not match Vaulted wallet".to_string(),
        ));
    }
    Ok(())
}

fn validate_xrp_payment_policy(
    tx: &serde_json::Value,
    destination: &str,
    amount_drops: &str,
    destination_tag: Option<u32>,
) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "Destination",
            "Amount",
            "DestinationTag",
            "Fee",
            "Sequence",
            "LastLedgerSequence",
        ],
    )?;
    require_transaction_type(tx, "Payment")?;
    require_string_equals(tx, "Destination", destination)?;
    require_string_equals(tx, "Amount", amount_drops)?;
    if parse_drops(amount_drops, "Amount")? == 0 {
        return Err(CryptoError::InvalidData(
            "XRP payment Amount must be greater than zero".to_string(),
        ));
    }
    match (destination_tag, tx.get("DestinationTag")) {
        (Some(expected), Some(_)) => {
            let actual = u32_field(tx, "DestinationTag")?;
            if actual != expected {
                return Err(CryptoError::InvalidData(
                    "XRP payment DestinationTag does not match intent".to_string(),
                ));
            }
        },
        (None, None) => {},
        (Some(_), None) | (None, Some(_)) => {
            return Err(CryptoError::InvalidData(
                "XRP payment DestinationTag does not match intent".to_string(),
            ));
        },
    }
    Ok(())
}

fn validate_nftoken_mint_policy(
    tx: &serde_json::Value,
    metadata_uri: &str,
    nftoken_taxon: u32,
    flags: u32,
    transfer_fee: Option<u16>,
) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "URI",
            "NFTokenTaxon",
            "Flags",
            "TransferFee",
            "Fee",
            "Sequence",
            "LastLedgerSequence",
        ],
    )?;
    require_transaction_type(tx, "NFTokenMint")?;
    require_string_equals(tx, "URI", &hex::encode_upper(metadata_uri.as_bytes()))?;
    require_u32_equals(tx, "NFTokenTaxon", nftoken_taxon)?;
    require_u32_equals(tx, "Flags", flags)?;
    if flags != TF_TRANSFERABLE {
        return Err(CryptoError::InvalidData(
            "NFTokenMint flags are not allowlisted".to_string(),
        ));
    }
    match (transfer_fee, tx.get("TransferFee")) {
        (Some(expected), Some(_)) => {
            let actual = u32_field(tx, "TransferFee")?;
            if actual != expected as u32 || actual > MAX_TRANSFER_FEE_BPS as u32 {
                return Err(CryptoError::InvalidData(
                    "NFTokenMint TransferFee does not match Vaulted policy".to_string(),
                ));
            }
        },
        (None, None) => {},
        (Some(_), None) | (None, Some(_)) => {
            return Err(CryptoError::InvalidData(
                "NFTokenMint TransferFee does not match intent".to_string(),
            ));
        },
    }
    Ok(())
}

fn validate_nftoken_create_offer_policy(
    tx: &serde_json::Value,
    nftoken_id: &str,
    destination: &str,
) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "NFTokenID",
            "Amount",
            "Flags",
            "Destination",
            "Fee",
            "Sequence",
            "LastLedgerSequence",
        ],
    )?;
    require_transaction_type(tx, "NFTokenCreateOffer")?;
    require_string_equals(tx, "NFTokenID", nftoken_id)?;
    require_string_equals(tx, "Amount", "0")?;
    require_u32_equals(tx, "Flags", TF_NFTOKEN_SELL_OFFER)?;
    require_string_equals(tx, "Destination", destination)?;
    Ok(())
}

fn validate_nftoken_accept_offer_policy(tx: &serde_json::Value, offer_index: &str) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "NFTokenSellOffer",
            "Fee",
            "Sequence",
            "LastLedgerSequence",
        ],
    )?;
    require_transaction_type(tx, "NFTokenAcceptOffer")?;
    require_string_equals(tx, "NFTokenSellOffer", offer_index)?;
    Ok(())
}

fn validate_nftoken_burn_policy(tx: &serde_json::Value, nftoken_id: &str) -> Result<()> {
    require_exact_fields(
        tx,
        &[
            "TransactionType",
            "Account",
            "NFTokenID",
            "Fee",
            "Sequence",
            "LastLedgerSequence",
        ],
    )?;
    require_transaction_type(tx, "NFTokenBurn")?;
    require_string_equals(tx, "NFTokenID", nftoken_id)?;
    Ok(())
}

fn require_transaction_type(tx: &serde_json::Value, expected: &str) -> Result<()> {
    require_string_equals(tx, "TransactionType", expected)
}

fn require_string_equals(tx: &serde_json::Value, field: &str, expected: &str) -> Result<()> {
    let actual = string_field(tx, field)?;
    if actual != expected {
        return Err(CryptoError::InvalidData(format!(
            "XRPL field {field} does not match signing intent"
        )));
    }
    Ok(())
}

fn require_u32_equals(tx: &serde_json::Value, field: &str, expected: u32) -> Result<()> {
    let actual = u32_field(tx, field)?;
    if actual != expected {
        return Err(CryptoError::InvalidData(format!(
            "XRPL field {field} does not match signing intent"
        )));
    }
    Ok(())
}

fn require_exact_fields(tx: &serde_json::Value, allowed: &[&str]) -> Result<()> {
    let obj = tx_object(tx)?;
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(CryptoError::InvalidData(format!(
                "Unexpected XRPL transaction field: {key}"
            )));
        }
    }
    for field in allowed {
        if matches!(
            *field,
            "DestinationTag" | "TransferFee" | "SigningPubKey" | "TxnSignature" | "hash"
        ) {
            continue;
        }
        if !obj.contains_key(*field) {
            return Err(CryptoError::InvalidData(format!(
                "Missing XRPL transaction field: {field}"
            )));
        }
    }
    Ok(())
}

fn reject_forbidden_fields(tx: &serde_json::Value) -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "SigningPubKey",
        "TxnSignature",
        "hash",
        "Memos",
        "Memo",
        "HookParameters",
        "Delegate",
        "Signers",
        "SignerEntries",
        "SignerQuorum",
        "TicketSequence",
        "SourceTag",
        "AccountTxnID",
        "NetworkID",
        "Paths",
        "SendMax",
        "DeliverMin",
        "DeliverMax",
        "CredentialIDs",
        "Authorize",
        "Unauthorize",
        "RegularKey",
        "Domain",
        "SetFlag",
        "ClearFlag",
    ];
    let obj = tx_object(tx)?;
    for field in FORBIDDEN {
        if obj.contains_key(*field) {
            return Err(CryptoError::InvalidData(format!(
                "Forbidden XRPL transaction field: {field}"
            )));
        }
    }
    Ok(())
}

fn parse_drops(value: &str, field: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CryptoError::InvalidData(format!(
            "XRPL field {field} must be a native XRP drops string"
        )));
    }
    value.parse::<u64>().map_err(|_| {
        CryptoError::InvalidData(format!("XRPL field {field} is outside supported range"))
    })
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

fn validate_nftoken_burn_tx(tx: &serde_json::Value) -> Result<()> {
    let _ = string_field(tx, "NFTokenID")?;
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

fn derive_xrp_bip44_private_key(seed: &[u8; 64]) -> Result<[u8; 32]> {
    let master = hmac_sha512(BIP32_MASTER_KEY, seed)?;
    let mut private_key: [u8; 32] = master[..32]
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let mut chain_code: [u8; 32] = master[32..]
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    if !is_valid_secp256k1_private_key(&private_key) {
        private_key.zeroize();
        chain_code.zeroize();
        return Err(CryptoError::KeyDerivation(
            "Invalid BIP32 master key for secp256k1".to_string(),
        ));
    }

    for index in XRP_BIP44_PATH {
        let (child_private_key, child_chain_code) =
            derive_bip32_private_child(&private_key, &chain_code, index)?;
        private_key.zeroize();
        chain_code.zeroize();
        private_key = child_private_key;
        chain_code = child_chain_code;
    }

    chain_code.zeroize();
    Ok(private_key)
}

fn derive_bip32_private_child(
    parent_private_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    let mut data = Vec::with_capacity(37);
    if index >= BIP32_HARDENED_OFFSET {
        data.push(0);
        data.extend_from_slice(parent_private_key);
    } else {
        let signing_key = SigningKey::from_bytes(parent_private_key.into())
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        let public_key = VerifyingKey::from(&signing_key);
        data.extend_from_slice(public_key.to_encoded_point(true).as_bytes());
    }
    data.extend_from_slice(&index.to_be_bytes());

    let derived = hmac_sha512(parent_chain_code, &data)?;
    let mut tweak: [u8; 32] = derived[..32]
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let child_chain_code: [u8; 32] = derived[32..]
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let child_private_key = add_secp256k1_scalars_mod_order(&tweak, parent_private_key)?;
    tweak.zeroize();

    if !is_valid_secp256k1_private_key(&child_private_key) {
        return Err(CryptoError::KeyDerivation(
            "Invalid BIP32 child key for secp256k1".to_string(),
        ));
    }

    Ok((child_private_key, child_chain_code))
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn add_secp256k1_scalars_mod_order(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    if !is_less_than_order(left) {
        return Err(CryptoError::KeyDerivation(
            "BIP32 child tweak is out of secp256k1 range".to_string(),
        ));
    }
    if !is_nonzero_less_than_order(right) {
        return Err(CryptoError::KeyDerivation(
            "BIP32 parent private key is out of secp256k1 range".to_string(),
        ));
    }

    let (sum, carry) = add_256(left, right);
    let reduced = if carry || bytes_ge(&sum, &SECP256K1_ORDER) {
        sub_256(&sum, &SECP256K1_ORDER)
    } else {
        sum
    };

    if is_zero_256(&reduced) {
        return Err(CryptoError::KeyDerivation(
            "BIP32 child private key is zero".to_string(),
        ));
    }

    Ok(reduced)
}

fn add_256(left: &[u8; 32], right: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = left[i] as u16 + right[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    (out, carry != 0)
}

fn sub_256(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = left[i] as i16 - right[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

fn is_valid_secp256k1_private_key(private_key: &[u8; 32]) -> bool {
    is_nonzero_less_than_order(private_key) && SigningKey::from_bytes(private_key.into()).is_ok()
}

fn is_nonzero_less_than_order(value: &[u8; 32]) -> bool {
    !is_zero_256(value) && is_less_than_order(value)
}

fn is_less_than_order(value: &[u8; 32]) -> bool {
    !bytes_ge(value, &SECP256K1_ORDER)
}

fn is_zero_256(value: &[u8; 32]) -> bool {
    value.iter().all(|&byte| byte == 0)
}

fn bytes_ge(left: &[u8; 32], right: &[u8; 32]) -> bool {
    for (a, b) in left.iter().zip(right.iter()) {
        if a > b {
            return true;
        }
        if a < b {
            return false;
        }
    }
    true
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
    fn derives_standard_xrp_bip44_wallet_from_test_mnemonic() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = VaultedXrplWallet::from_mnemonic(mnemonic, None).unwrap();

        assert_eq!(
            wallet.classic_address().unwrap(),
            "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"
        );
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(&mint_intent("ipfs://manifest"), &tx)
            .unwrap();
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(
                &payment_intent(&destination, "1000000", Some(123)),
                &tx,
            )
            .unwrap();
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(
                &create_offer_intent(
                    "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                    &destination,
                ),
                &tx,
            )
            .unwrap();
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(
                &accept_offer_intent(
                    "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                ),
                &tx,
            )
            .unwrap();
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
    fn nftoken_burn_builder_sets_required_fields() {
        let tx = build_nftoken_burn_tx("rTest", "00080000BURN");

        assert_eq!(tx["TransactionType"], "NFTokenBurn");
        assert_eq!(tx["Account"], "rTest");
        assert_eq!(tx["NFTokenID"], "00080000BURN");
    }

    #[test]
    fn signs_nftoken_burn_as_xrpl_tx_blob() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = build_nftoken_burn_tx(
            &account,
            "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);
        let signed = wallet
            .sign_xrpl_transaction_for_intent(
                &burn_intent("00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC"),
                &tx,
            )
            .unwrap();
        let tx_blob = signed.tx_blob.as_ref().unwrap();

        assert_eq!(signed.protocol, "vaulted-xrpl-tx-blob-v1");
        assert_eq!(tx_blob.len() % 2, 0);
        assert!(hex::decode(tx_blob).is_ok());
        assert!(!tx_blob.is_empty());
        assert_eq!(signed.tx_hash.as_ref().unwrap().len(), 64);
        assert_eq!(signed.tx_json["TransactionType"], "NFTokenBurn");
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

        assert!(wallet
            .sign_xrpl_transaction_for_intent(&payment_intent(&destination, "1000000", None), &tx)
            .is_err());
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

        assert!(wallet
            .sign_xrpl_transaction_for_intent(
                &create_offer_intent(
                    "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                    &destination,
                ),
                &tx,
            )
            .is_err());
    }

    #[test]
    fn rejects_mismatched_account_for_nftoken_accept_offer_signing() {
        let wallet = deterministic_wallet();
        let tx = build_nftoken_accept_offer_tx(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
        );
        let tx = add_xrpl_signing_fields(tx, "12", 1, 100);

        assert!(wallet
            .sign_xrpl_transaction_for_intent(
                &accept_offer_intent(
                    "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                ),
                &tx,
            )
            .is_err());
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

            assert!(wallet
                .sign_xrpl_transaction_for_intent(
                    &create_offer_intent(
                        "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                        &destination,
                    ),
                    &tx,
                )
                .is_err());
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

        assert!(wallet
            .sign_xrpl_transaction_for_intent(
                &accept_offer_intent(
                    "ABCD1234DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC",
                ),
                &tx,
            )
            .is_err());
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(&mint_intent("ipfs://manifest"), &tx)
            .unwrap();
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
        let signed = wallet
            .sign_xrpl_transaction_for_intent(&mint_intent(&metadata_uri), &tx)
            .unwrap();
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
        let metadata_uri = "u".repeat(111);
        let signed = wallet
            .sign_xrpl_transaction_for_intent(&mint_intent(&metadata_uri), &tx)
            .unwrap();
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
        let metadata_uri = "u".repeat(111);
        let signed = wallet
            .sign_xrpl_transaction_for_intent(&mint_intent(&metadata_uri), &tx)
            .unwrap();
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
        assert!(wallet
            .sign_xrpl_transaction_for_intent(&mint_intent("ipfs://manifest"), &tx)
            .is_err());
    }

    #[test]
    fn policy_rejects_send_xrp_partial_payment_flag() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = other_wallet_address();
        let mut tx = add_xrpl_signing_fields(
            build_xrp_payment_tx(&account, &destination, "1000000", None),
            "12",
            1,
            100,
        );
        tx["Flags"] = serde_json::json!(0x0002_0000_u32);

        assert!(validate_xrpl_transaction_for_intent(
            &payment_intent(&destination, "1000000", None),
            &tx,
            &account,
        )
        .is_err());
    }

    #[test]
    fn policy_rejects_send_xrp_paths_and_sendmax() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = other_wallet_address();
        for field in ["Paths", "SendMax"] {
            let mut tx = add_xrpl_signing_fields(
                build_xrp_payment_tx(&account, &destination, "1000000", None),
                "12",
                1,
                100,
            );
            tx[field] = serde_json::json!("unexpected");
            assert!(
                validate_xrpl_transaction_for_intent(
                    &payment_intent(&destination, "1000000", None),
                    &tx,
                    &account,
                )
                .is_err(),
                "{field} must be rejected"
            );
        }
    }

    #[test]
    fn policy_rejects_send_xrp_destination_or_amount_substitution() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = other_wallet_address();
        let attacker = VaultedXrplWallet::from_bip39_seed(&[9u8; 64])
            .unwrap()
            .classic_address()
            .unwrap();
        let wrong_destination = add_xrpl_signing_fields(
            build_xrp_payment_tx(&account, &attacker, "1000000", None),
            "12",
            1,
            100,
        );
        let wrong_amount = add_xrpl_signing_fields(
            build_xrp_payment_tx(&account, &destination, "2000000", None),
            "12",
            1,
            100,
        );
        let intent = payment_intent(&destination, "1000000", None);

        assert!(
            validate_xrpl_transaction_for_intent(&intent, &wrong_destination, &account).is_err()
        );
        assert!(validate_xrpl_transaction_for_intent(&intent, &wrong_amount, &account).is_err());
    }

    #[test]
    fn policy_rejects_nftoken_mint_unexpected_field() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let mut tx = add_xrpl_signing_fields(
            build_nftoken_mint_tx(&account, "ipfs://manifest", 0, None, None),
            "12",
            1,
            100,
        );
        tx["Memos"] = serde_json::json!([]);

        assert!(validate_xrpl_transaction_for_intent(
            &mint_intent("ipfs://manifest"),
            &tx,
            &account
        )
        .is_err());
    }

    #[test]
    fn policy_accepts_valid_nftoken_create_offer_and_rejects_unsafe_variants() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let destination = other_wallet_address();
        let nftoken_id = "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC";
        let intent = create_offer_intent(nftoken_id, &destination);
        let valid = add_xrpl_signing_fields(
            build_nftoken_create_offer_tx(&account, nftoken_id, &destination, "0"),
            "12",
            1,
            100,
        );
        assert!(validate_xrpl_transaction_for_intent(&intent, &valid, &account).is_ok());

        let mut without_destination = valid.clone();
        without_destination
            .as_object_mut()
            .unwrap()
            .remove("Destination");
        assert!(
            validate_xrpl_transaction_for_intent(&intent, &without_destination, &account).is_err()
        );

        let wrong_nft = add_xrpl_signing_fields(
            build_nftoken_create_offer_tx(&account, "00080000OTHER", &destination, "0"),
            "12",
            1,
            100,
        );
        assert!(validate_xrpl_transaction_for_intent(&intent, &wrong_nft, &account).is_err());

        let paid = add_xrpl_signing_fields(
            build_nftoken_create_offer_tx(&account, nftoken_id, &destination, "1"),
            "12",
            1,
            100,
        );
        assert!(validate_xrpl_transaction_for_intent(&intent, &paid, &account).is_err());
    }

    #[test]
    fn policy_rejects_wrong_accept_offer_index() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = add_xrpl_signing_fields(
            build_nftoken_accept_offer_tx(&account, "WRONGOFFER"),
            "12",
            1,
            100,
        );

        assert!(validate_xrpl_transaction_for_intent(
            &accept_offer_intent("EXPECTEDOFFER"),
            &tx,
            &account,
        )
        .is_err());
    }

    #[test]
    fn policy_accepts_valid_burn_and_rejects_wrong_nftoken_id() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let nftoken_id = "00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC";
        let intent = burn_intent(nftoken_id);
        let valid =
            add_xrpl_signing_fields(build_nftoken_burn_tx(&account, nftoken_id), "12", 1, 100);
        assert!(validate_xrpl_transaction_for_intent(&intent, &valid, &account).is_ok());

        let wrong = add_xrpl_signing_fields(
            build_nftoken_burn_tx(&account, "00080000OTHER"),
            "12",
            1,
            100,
        );
        assert!(validate_xrpl_transaction_for_intent(&intent, &wrong, &account).is_err());
    }

    #[test]
    fn policy_rejects_unrelated_transaction_types() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        for tx_type in ["AccountSet", "TrustSet", "OfferCreate", "AMMCreate"] {
            let tx = serde_json::json!({
                "TransactionType": tx_type,
                "Account": account,
                "Fee": "12",
                "Sequence": 1,
                "LastLedgerSequence": 100
            });
            assert!(
                validate_xrpl_transaction_for_intent(
                    &mint_intent("ipfs://manifest"),
                    &tx,
                    &account,
                )
                .is_err(),
                "{tx_type} must be rejected"
            );
        }
    }

    #[test]
    fn policy_rejects_memo_and_unknown_top_level_field() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        for field in ["Memos", "UnexpectedField"] {
            let mut tx = add_xrpl_signing_fields(
                build_nftoken_mint_tx(&account, "ipfs://manifest", 0, None, None),
                "12",
                1,
                100,
            );
            tx[field] = serde_json::json!("hidden");
            assert!(
                validate_xrpl_transaction_for_intent(
                    &mint_intent("ipfs://manifest"),
                    &tx,
                    &account,
                )
                .is_err(),
                "{field} must be rejected"
            );
        }
    }

    #[test]
    fn generic_xrpl_blob_signing_requires_intent() {
        let wallet = deterministic_wallet();
        let account = wallet.classic_address().unwrap();
        let tx = add_xrpl_signing_fields(
            build_xrp_payment_tx(&account, &other_wallet_address(), "1000000", None),
            "12",
            1,
            100,
        );

        assert!(wallet.sign_xrpl_transaction_json(&tx).is_err());
    }

    fn deterministic_wallet() -> VaultedXrplWallet {
        VaultedXrplWallet::from_bip39_seed(&[7u8; 64]).unwrap()
    }

    fn other_wallet_address() -> String {
        VaultedXrplWallet::from_bip39_seed(&[8u8; 64])
            .unwrap()
            .classic_address()
            .unwrap()
    }

    fn mint_intent(metadata_uri: &str) -> XrplSigningIntent {
        XrplSigningIntent::MintVaultNft {
            metadata_uri: metadata_uri.to_string(),
            nftoken_taxon: 0,
            flags: TF_TRANSFERABLE,
            transfer_fee: None,
        }
    }

    fn payment_intent(
        destination: &str,
        amount_drops: &str,
        destination_tag: Option<u32>,
    ) -> XrplSigningIntent {
        XrplSigningIntent::SendXrp {
            destination: destination.to_string(),
            amount_drops: amount_drops.to_string(),
            destination_tag,
        }
    }

    fn create_offer_intent(nftoken_id: &str, destination: &str) -> XrplSigningIntent {
        XrplSigningIntent::CreateNftTransferOffer {
            nftoken_id: nftoken_id.to_string(),
            destination: destination.to_string(),
        }
    }

    fn accept_offer_intent(offer_index: &str) -> XrplSigningIntent {
        XrplSigningIntent::AcceptNftTransferOffer {
            offer_index: offer_index.to_string(),
        }
    }

    fn burn_intent(nftoken_id: &str) -> XrplSigningIntent {
        XrplSigningIntent::BurnVaultNft {
            nftoken_id: nftoken_id.to_string(),
        }
    }
}
