//! XRPL Vault Crypto Core
//!
//! Cryptographic primitives for the XRPL NFT-based encrypted file vault.

#![warn(missing_docs)]

pub mod aes;
pub mod commitment;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod identity;
pub mod key_derivation;
pub mod manifest;
pub mod nft_image;
pub mod pre;
pub mod qr_payload;
pub mod secure_note;
pub mod seed;
pub mod transfer;
pub mod types;
pub mod xrpl_wallet;

// Constants
/// AES-256 key size in bytes
pub const AES_KEY_SIZE: usize = 32;
/// Nonce size for AES-GCM
pub const AES_NONCE_SIZE: usize = 12;
/// Current cryptographic scheme version
pub const CRYPTO_VERSION: u8 = 1;

pub use aes::{AesKey, AesStreamEncryptor};
pub use commitment::KeyCommitment;
pub use envelope::{
    open_key_envelope, seal_key_for_recipient, seal_key_for_recipient_hex, KeyEnvelope,
};
pub use error::{CryptoError, Result};
pub use identity::{
    encryption_public_key_fingerprint_hex, format_fingerprint_groups, VaultedIdentityKeys,
};
pub use key_derivation::{DerivedKeys, KeyDerivation};
pub use manifest::{
    ManifestFragment, ManifestNftRef, ManifestSignature, VaultedManifest, VaultedNftMetadata,
    VaultedNftProperties,
};
pub use nft_image::{
    generate_nft_svg, generate_vaulted_nft_metadata_preview, get_nft_color,
    VaultedNftMetadataInput, VaultedNftMetadataPreview,
};
pub use pre::{
    EncryptedPreData, PreKeyPair, PrePublicKey, ProxyReEncryption, ReEncryptedData, ReEncryptionKey,
};
pub use qr_payload::{
    VaultedQrIntent, VaultedQrPayloadBody, VaultedSignedQrPayload, VAULTED_QR_PROTOCOL,
};
pub use seed::{SeedManager, DEFAULT_MNEMONIC_WORDS, MIN_MNEMONIC_WORDS};
pub use transfer::{TransferProof, TransferService, TransferVerification};
pub use types::*;
pub use xrpl_wallet::{
    add_xrpl_signing_fields, build_nftoken_accept_offer_tx, build_nftoken_burn_tx,
    build_nftoken_create_offer_tx, build_nftoken_mint_tx, build_xrp_payment_tx,
    is_valid_xrpl_classic_address, VaultedQrSigningRequest, VaultedSignedXrplTransaction,
    VaultedXrplWallet, VaultedXrplWalletPublic,
};
