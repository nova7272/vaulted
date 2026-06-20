//! Tauri Commands
//!
//! Bridge between the JavaScript UI and Rust backend.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use xrpl_vault_crypto_core::{
    add_xrpl_signing_fields, build_nftoken_accept_offer_tx, build_nftoken_burn_tx,
    build_nftoken_create_offer_tx, build_nftoken_mint_tx, build_xrp_payment_tx,
    encryption_public_key_fingerprint_hex, format_fingerprint_groups,
    generate_vaulted_nft_metadata_preview as build_vaulted_nft_metadata_preview,
    is_valid_xrpl_classic_address, open_key_envelope, seal_key_for_recipient_hex, KeyEnvelope,
    SeedManager, VaultedNftMetadataInput, VaultedNftMetadataPreview, VaultedQrSigningRequest,
    VaultedSignedXrplTransaction, DEFAULT_MNEMONIC_WORDS,
};

use crate::auth::{Session, VaultedSigningRequest};
use crate::crypto::FileEncryptor;
use crate::error::{ClientError, Result};
use crate::oracle::api::{
    ConfirmTransferOfferSignedRequest, CreateVaultRequest, FinalizeVaultMintRequest, GrantResponse,
    IdentityDeviceResponse, IdentityTokenRequest, OracleClient, OracleConfig,
    PublishVaultMetadataRequest, PublishVaultMetadataResponse, QrFileGrantConfirmRequest,
    QrFileGrantStartRequest, QrXrplSigningConfirmRequest, QrXrplSigningStartRequest,
    RecipientKeyTrustResponse, RegisterVaultObjectRequest, RevokeRecipientKeyTrustRequest,
    TrustRecipientKeyRequest, VaultFragment, VaultManifest, VaultObjectResponse,
};
use crate::state::AppState;
use crate::xrpl::client::is_xrpl_tx_blob_hex;
use crate::xrpl::XrplClient;

// ==================== Vaulted Identity Commands ====================

/// Response returned when creating/restoring the seed-based Vaulted wallet.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedIdentityResponse {
    /// Vaulted identity id.
    pub vaulted_identity_id: String,
    /// BIP-39 mnemonic. Returned only during creation so the UI can show backup ceremony.
    pub mnemonic: Option<String>,
    /// Ed25519 signing public key, hex.
    pub signing_public_key: String,
    /// X25519 encryption public key, hex.
    pub encryption_public_key: String,
    /// Device public key, hex.
    pub device_public_key: String,
    /// Protocol version.
    pub protocol_version: String,
}

/// Create a new seed-based Vaulted wallet. Defaults to 12 words.
#[tauri::command(rename_all = "camelCase")]
pub async fn create_vaulted_wallet(
    state: State<'_, Arc<AppState>>,
    word_count: Option<usize>,
    passphrase: Option<String>,
) -> Result<VaultedIdentityResponse> {
    let mnemonic = generate_create_wallet_mnemonic(word_count)?;
    let identity = state
        .init_vaulted_identity_from_mnemonic(&mnemonic, passphrase.as_deref())
        .await?;

    let response = VaultedIdentityResponse {
        vaulted_identity_id: identity.identity_id_hex(),
        mnemonic: Some(mnemonic),
        signing_public_key: identity.signing_public_key_hex(),
        encryption_public_key: identity.encryption_public_key_hex(),
        device_public_key: identity.device_public_key_hex(),
        protocol_version: "vaulted-v1".to_string(),
    };
    set_vaulted_session(state.inner()).await?;
    register_vaulted_identity_public(state.inner(), &response).await;
    Ok(response)
}

/// Restore/unlock a seed-based Vaulted wallet from a BIP-39 mnemonic.
#[tauri::command(rename_all = "camelCase")]
pub async fn restore_vaulted_wallet(
    state: State<'_, Arc<AppState>>,
    mut mnemonic: String,
    passphrase: Option<String>,
) -> Result<VaultedIdentityResponse> {
    use zeroize::Zeroize;

    if let Err(err) = SeedManager::validate_mnemonic(&mnemonic) {
        mnemonic.zeroize();
        return Err(err.into());
    }
    let identity_result = state
        .init_vaulted_identity_from_mnemonic(&mnemonic, passphrase.as_deref())
        .await;
    mnemonic.zeroize();
    let identity = identity_result?;

    let response = VaultedIdentityResponse {
        vaulted_identity_id: identity.identity_id_hex(),
        mnemonic: None,
        signing_public_key: identity.signing_public_key_hex(),
        encryption_public_key: identity.encryption_public_key_hex(),
        device_public_key: identity.device_public_key_hex(),
        protocol_version: "vaulted-v1".to_string(),
    };
    set_vaulted_session(state.inner()).await?;
    register_vaulted_identity_public(state.inner(), &response).await;
    Ok(response)
}

/// Validate a recovery phrase without unlocking it.
#[tauri::command(rename_all = "camelCase")]
pub async fn validate_vaulted_seed(mnemonic: String) -> Result<bool> {
    Ok(SeedManager::validate_mnemonic(&mnemonic).is_ok())
}

fn validate_create_wallet_word_count(word_count: Option<usize>) -> Result<usize> {
    match word_count {
        None | Some(DEFAULT_MNEMONIC_WORDS) => Ok(DEFAULT_MNEMONIC_WORDS),
        Some(_) => Err(ClientError::Validation(
            "Vaulted recovery phrase must be exactly 12 words".to_string(),
        )),
    }
}

fn generate_create_wallet_mnemonic(word_count: Option<usize>) -> Result<String> {
    SeedManager::generate_mnemonic(validate_create_wallet_word_count(word_count)?)
        .map_err(ClientError::from)
}

/// Returns whether the seed-based Vaulted wallet is currently unlocked.
#[tauri::command]
pub async fn has_vaulted_wallet(state: State<'_, Arc<AppState>>) -> Result<bool> {
    Ok(state.has_vaulted_identity().await)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthLifecycleStatus {
    pub auth_state: String,
    pub wallet_exists: bool,
    pub identity_exists: bool,
    pub session_exists: bool,
    pub locked: bool,
}

#[tauri::command]
pub async fn get_auth_lifecycle_status(
    state: State<'_, Arc<AppState>>,
) -> Result<AuthLifecycleStatus> {
    build_auth_lifecycle_status(state.inner()).await
}

async fn build_auth_lifecycle_status(state: &Arc<AppState>) -> Result<AuthLifecycleStatus> {
    let session_exists = state.has_active_session().await;
    let identity_exists = state.has_vaulted_identity().await;
    let wallet_exists = state.has_xrpl_wallet().await;
    let unlocked = session_exists && identity_exists && wallet_exists;

    Ok(AuthLifecycleStatus {
        auth_state: if unlocked { "unlocked" } else { "locked" }.to_string(),
        wallet_exists,
        identity_exists,
        session_exists,
        locked: !unlocked,
    })
}

async fn set_vaulted_session(state: &Arc<AppState>) -> Result<()> {
    let identity = state.get_vaulted_identity().await?;
    let wallet = state.get_xrpl_wallet().await?;
    let mut session = Session::new(
        wallet.classic_address()?,
        wallet.public_key_hex()?,
        format!("vaulted-seed:{}", identity.identity_id_hex()),
        24,
    );
    session.set_device_fingerprint(state.device_fingerprint().to_string());
    state.set_session(session).await;
    Ok(())
}

async fn register_vaulted_identity_public(
    state: &Arc<AppState>,
    identity: &VaultedIdentityResponse,
) {
    let oracle = match OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    }) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(
                "Could not create Oracle client for identity registration: {}",
                e
            );
            return;
        },
    };

    let request = crate::oracle::api::RegisterVaultedIdentityRequest {
        vaulted_identity_id: identity.vaulted_identity_id.clone(),
        encryption_public_key: identity.encryption_public_key.clone(),
        signing_public_key: identity.signing_public_key.clone(),
        device_public_key: identity.device_public_key.clone(),
        linked_wallets: vec![],
        protocol_version: identity.protocol_version.clone(),
    };

    match oracle.register_vaulted_identity(&request).await {
        Ok(r) => tracing::info!(
            "Vaulted identity registered in Oracle: id={}, created={}",
            r.id,
            r.created
        ),
        Err(e) => {
            tracing::warn!("Vaulted identity Oracle registration failed: {}", e);
            return;
        },
    }

    let challenge = match oracle
        .get_identity_challenge(&identity.vaulted_identity_id)
        .await
    {
        Ok(challenge) => challenge,
        Err(e) => {
            tracing::warn!("Vaulted identity challenge request failed: {}", e);
            return;
        },
    };

    let vaulted_identity = match state.get_vaulted_identity().await {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!("Vaulted identity is unavailable for Oracle login: {}", e);
            return;
        },
    };

    let wallet_address = match state.wallet_address().await {
        Ok(wallet_address) => wallet_address,
        Err(e) => {
            tracing::warn!(
                "Current wallet address is unavailable for Oracle identity login: {}",
                e
            );
            return;
        },
    };
    let pre_public_key = match state.get_public_key_hex().await {
        Ok(public_key) => public_key,
        Err(e) => {
            tracing::warn!(
                "Current recipient PRE public key is unavailable for Oracle identity login: {}",
                e
            );
            return;
        },
    };

    let signed_challenge = format!(
        "{}\nwallet_address:{}\npre_public_key:{}",
        challenge.challenge, wallet_address, pre_public_key
    );
    use ed25519_dalek::Signer as _;
    let signature = vaulted_identity
        .signing_key()
        .sign(signed_challenge.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    match oracle
        .get_identity_token(&IdentityTokenRequest {
            identity_id: identity.vaulted_identity_id.clone(),
            wallet_address,
            pre_public_key: Some(pre_public_key),
            challenge: signed_challenge,
            signature: signature_hex,
            device_public_key: Some(identity.device_public_key.clone()),
        })
        .await
    {
        Ok(token_response) => {
            let expires_in = token_response.expires_in;
            if let Err(e) = state
                .save_oracle_tokens(
                    token_response.access_token,
                    expires_in,
                    token_response.refresh_token,
                    token_response.role,
                )
                .await
            {
                tracing::warn!("Could not save Vaulted identity Oracle token: {}", e);
                return;
            }

            tracing::info!(
                "Vaulted identity Oracle login successful: identity_id={}, expires_in={}s",
                token_response.identity_id,
                expires_in
            );
        },
        Err(e) => tracing::warn!("Vaulted identity Oracle token request failed: {}", e),
    }
}

/// Public XRPL wallet details derived from the Vaulted seed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedWalletResponse {
    pub classic_address: String,
    pub public_key: String,
    pub protocol: String,
}

/// QR-login start response returned by Oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrLoginStartResponse {
    pub login_request_id: String,
    pub challenge: String,
    pub oracle_url: String,
    pub expires_at: String,
    pub qr_payload: serde_json::Value,
}

/// Returns the Vaulted-owned XRPL wallet public details.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_vaulted_xrpl_wallet(
    state: State<'_, Arc<AppState>>,
) -> Result<VaultedWalletResponse> {
    let wallet = state.get_xrpl_wallet().await?;
    Ok(VaultedWalletResponse {
        classic_address: wallet.classic_address()?,
        public_key: wallet.public_key_hex()?,
        protocol: "vaulted-xrpl-wallet-v1".to_string(),
    })
}

/// Builds a Vaulted QR payload for offline/mobile NFTokenMint signing.
#[tauri::command(rename_all = "camelCase")]
pub async fn create_vaulted_nft_mint_qr_request(
    state: State<'_, Arc<AppState>>,
    metadata_uri: String,
    nftoken_taxon: Option<u32>,
    flags: Option<u32>,
    transfer_fee: Option<u16>,
) -> Result<VaultedQrSigningRequest> {
    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;
    let tx_json = build_nftoken_mint_tx(
        &account,
        &metadata_uri,
        nftoken_taxon.unwrap_or(0),
        flags,
        transfer_fee,
    );
    let request_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
    Ok(VaultedQrSigningRequest {
        r#type: "vaulted-xrpl-signing-request-v1".to_string(),
        request_id,
        tx_json,
        oracle_url: state.config.oracle_url.clone(),
        expires_at,
        human_summary: Some(format!("Mint Vaulted NFT metadata at {}", metadata_uri)),
    })
}

/// Signs a Vaulted QR XRPL transaction request with the local Vaulted wallet.
#[tauri::command(rename_all = "camelCase")]
pub async fn sign_vaulted_xrpl_qr_request(
    state: State<'_, Arc<AppState>>,
    request: VaultedQrSigningRequest,
) -> Result<VaultedSignedXrplTransaction> {
    if request.r#type != "vaulted-xrpl-signing-request-v1" {
        return Err(ClientError::Auth(
            "Unsupported Vaulted QR signing request".to_string(),
        ));
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|e| ClientError::Config(format!("Invalid QR request expiration: {}", e)))?
        .with_timezone(&chrono::Utc);
    if expires_at < chrono::Utc::now() {
        return Err(ClientError::Auth("QR signing request expired".to_string()));
    }
    let wallet = state.get_xrpl_wallet().await?;
    wallet
        .sign_transaction_json(&request.tx_json)
        .map_err(Into::into)
}

/// Generate a deterministic Vaulted NFT image and metadata preview locally.
///
/// The generated visual is derived from opaque hashes/ids only and is safe to
/// show before XRPL minting. It does not require Oracle mint authority.
#[tauri::command(rename_all = "camelCase")]
pub async fn generate_vaulted_nft_metadata_preview(
    state: State<'_, Arc<AppState>>,
    manifest_hash: String,
    encrypted_hash: Option<String>,
    vault_object_id: Option<String>,
    metadata_uri: Option<String>,
) -> Result<VaultedNftMetadataPreview> {
    let owner_identity_id = state
        .get_vaulted_identity()
        .await
        .ok()
        .map(|identity| identity.identity_id_hex());
    let input = VaultedNftMetadataInput {
        manifest_hash,
        encrypted_hash,
        vault_object_id,
        owner_identity_id,
        metadata_uri,
    };
    Ok(build_vaulted_nft_metadata_preview(&input))
}

/// Publishes the client-generated public NFT metadata JSON to Oracle before local mint.
///
/// The resulting `metadata_uri` is the URI embedded in NFTokenMint. Oracle verifies
/// the JSON hash and stores the exact metadata as an immutable public artifact.
#[tauri::command(rename_all = "camelCase")]
pub async fn publish_vaulted_nft_metadata(
    state: State<'_, Arc<AppState>>,
    vault_object_id: String,
    manifest_hash: String,
    metadata_uri: String,
    metadata_json: String,
    metadata_hash: String,
) -> Result<PublishVaultMetadataResponse> {
    let oracle = state.get_oracle_client_with_timeout(30).await?;
    oracle
        .publish_vault_metadata(&PublishVaultMetadataRequest {
            vault_id: vault_object_id,
            manifest_hash,
            metadata_uri,
            metadata_json,
            metadata_hash,
        })
        .await
}

/// Parameters for building and locally signing an NFTokenMint transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedNftMintSigningRequest {
    pub metadata_uri: String,
    pub nftoken_taxon: Option<u32>,
    pub flags: Option<u32>,
    pub transfer_fee: Option<u16>,
    pub fee_drops: Option<String>,
    pub sequence: Option<u32>,
    pub last_ledger_sequence: Option<u32>,
}

/// Local signed NFTokenMint response. `tx_blob` can be submitted directly to XRPL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedSignedMintResponse {
    pub signed: VaultedSignedXrplTransaction,
    pub submitted: Option<VaultedSubmitResponse>,
}

/// XRPL submit response for a locally signed Vaulted transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedSubmitResponse {
    pub engine_result: String,
    pub engine_result_message: String,
    pub tx_hash: String,
    pub accepted: bool,
    pub nft_token_id: Option<String>,
}

/// Builds an NFTokenMint transaction, fills network fields, signs locally, and returns tx_blob.
#[tauri::command(rename_all = "camelCase")]
pub async fn sign_vaulted_nft_mint_transaction(
    state: State<'_, Arc<AppState>>,
    request: VaultedNftMintSigningRequest,
) -> Result<VaultedSignedXrplTransaction> {
    sign_vaulted_nft_mint_transaction_inner(state.inner(), request).await
}

async fn sign_vaulted_nft_mint_transaction_inner(
    state: &Arc<AppState>,
    request: VaultedNftMintSigningRequest,
) -> Result<VaultedSignedXrplTransaction> {
    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;

    let tx = build_nftoken_mint_tx(
        &account,
        &request.metadata_uri,
        request.nftoken_taxon.unwrap_or(0),
        request.flags,
        request.transfer_fee,
    );

    let (fee_drops, sequence, last_ledger_sequence) = match (
        request.fee_drops,
        request.sequence,
        request.last_ledger_sequence,
    ) {
        (Some(fee), Some(sequence), Some(last_ledger)) => (fee, sequence, last_ledger),
        (fee, sequence, last_ledger) => {
            let network = fetch_xrpl_signing_fields(
                &state.config.xrpl_node_url,
                &account,
                fee,
                sequence,
                last_ledger,
            )
            .await?;
            (
                network.fee_drops,
                network.sequence,
                network.last_ledger_sequence,
            )
        },
    };

    let tx = add_xrpl_signing_fields(tx, fee_drops, sequence, last_ledger_sequence);
    tracing::info!(
        transaction_type = "NFTokenMint",
        metadata_uri_len = request.metadata_uri.len(),
        account = %account,
        sequence,
        fee = %tx.get("Fee").and_then(|value| value.as_str()).unwrap_or(""),
        last_ledger_sequence,
        "Prepared Vaulted NFTokenMint signing fields"
    );
    wallet.sign_xrpl_transaction_json(&tx).map_err(Into::into)
}

/// Builds, locally signs, and optionally submits an NFTokenMint transaction to XRPL.
#[tauri::command(rename_all = "camelCase")]
pub async fn mint_vaulted_nft_locally(
    state: State<'_, Arc<AppState>>,
    request: VaultedNftMintSigningRequest,
    submit: Option<bool>,
) -> Result<VaultedSignedMintResponse> {
    let metadata_uri_len = request.metadata_uri.len();
    let mint_account = state.inner().get_xrpl_wallet().await?.classic_address()?;
    let signed = sign_vaulted_nft_mint_transaction_inner(state.inner(), request).await?;

    let submitted = if submit.unwrap_or(false) {
        let tx_blob = signed.tx_blob.clone().ok_or_else(|| {
            ClientError::Xrpl(
                "Local signing did not produce a signed XRPL transaction payload".to_string(),
            )
        })?;
        tracing::info!(
            transaction_type = "NFTokenMint",
            metadata_uri_len,
            account = %mint_account,
            tx_blob_len = tx_blob.len(),
            tx_blob_is_hex = is_xrpl_tx_blob_hex(&tx_blob),
            "Prepared locally signed Vaulted NFTokenMint submit payload"
        );
        Some(
            submit_vaulted_xrpl_tx_blob_inner(
                state.inner(),
                tx_blob,
                Some(MintSubmitDiagnostics {
                    classic_address: mint_account,
                    metadata_uri_len,
                }),
            )
            .await?,
        )
    } else {
        None
    };

    Ok(VaultedSignedMintResponse { signed, submitted })
}

/// Submits a locally signed XRPL tx_blob and returns engine result / tx hash.
#[tauri::command(rename_all = "camelCase")]
pub async fn submit_vaulted_xrpl_tx_blob(
    state: State<'_, Arc<AppState>>,
    tx_blob: String,
) -> Result<VaultedSubmitResponse> {
    submit_vaulted_xrpl_tx_blob_inner(state.inner(), tx_blob, None).await
}

struct MintSubmitDiagnostics {
    classic_address: String,
    metadata_uri_len: usize,
}

async fn submit_vaulted_xrpl_tx_blob_inner(
    state: &Arc<AppState>,
    tx_blob: String,
    diagnostics: Option<MintSubmitDiagnostics>,
) -> Result<VaultedSubmitResponse> {
    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    tracing::info!(
        method = "submit",
        phase = "prepared",
        tx_blob_len = tx_blob.len(),
        tx_blob_is_hex = is_xrpl_tx_blob_hex(&tx_blob),
        "Submitting locally signed Vaulted NFTokenMint transaction"
    );
    let result = client.submit(&tx_blob).await?;
    let accepted = result.engine_result.starts_with("tes");
    let tx_hash = result.tx_hash.clone();

    if let Some(ctx) = diagnostics.as_ref() {
        tracing::info!(
            accepted,
            engine_result = %result.engine_result,
            engine_result_message = %result.engine_result_message,
            tx_hash = %tx_hash,
            classic_address = %ctx.classic_address,
            metadata_uri_len = ctx.metadata_uri_len,
            "Vaulted NFTokenMint submit result"
        );
    } else {
        tracing::info!(
            accepted,
            engine_result = %result.engine_result,
            engine_result_message = %result.engine_result_message,
            tx_hash = %tx_hash,
            "Vaulted XRPL submit result"
        );
    }

    let nft_token_id = if accepted && !tx_hash.is_empty() {
        match client.extract_minted_nftoken_id(&tx_hash).await {
            Ok(token_id) => token_id,
            Err(_) => {
                tracing::warn!(
                    tx_hash = %tx_hash,
                    accepted,
                    "Failed to extract minted NFTokenID after accepted submit"
                );
                None
            },
        }
    } else {
        None
    };

    Ok(VaultedSubmitResponse {
        accepted,
        engine_result: result.engine_result,
        engine_result_message: result.engine_result_message,
        tx_hash,
        nft_token_id,
    })
}

/// Registers a locally minted Vaulted vault object in the Oracle manifest index.
///
/// This is used after local XRPL signing/submission succeeds so Oracle stores only
/// the manifest pointer and chain token id, not wallet-signing authority.
#[tauri::command(rename_all = "camelCase")]
pub async fn register_minted_vault_object(
    state: State<'_, Arc<AppState>>,
    vault_object_id: String,
    manifest_uri: String,
    manifest_hash: String,
    nft_token_id: String,
    tx_hash: String,
) -> Result<VaultObjectResponse> {
    register_minted_vault_object_inner(
        state.inner(),
        vault_object_id,
        manifest_uri,
        manifest_hash,
        nft_token_id,
        tx_hash,
    )
    .await
}

/// Finalizes a successful mint after the original submit path could not extract NFTokenID yet.
///
/// This does not submit or mint. It reads the validated XRPL transaction by hash,
/// extracts the minted NFTokenID, then reuses the normal Oracle finalize/register path.
#[tauri::command(rename_all = "camelCase")]
pub async fn finalize_pending_vault_mint(
    state: State<'_, Arc<AppState>>,
    vault_object_id: String,
    manifest_uri: String,
    manifest_hash: String,
    tx_hash: String,
) -> Result<VaultObjectResponse> {
    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    let nft_token_id = client
        .extract_minted_nftoken_id(&tx_hash)
        .await?
        .ok_or_else(|| {
            ClientError::Xrpl(format!(
                "Missing NFTokenID after successful XRPL mint. tx_hash={tx_hash}"
            ))
        })?;

    tracing::info!(
        nft_token_id = %nft_token_id,
        tx_hash = %tx_hash,
        metadata_hash = %manifest_hash,
        metadata_uri_len = manifest_uri.len(),
        request_phase = "finalize_pending_mint",
        status = "nftoken_id_extracted",
        "Recovered NFTokenID for pending Vaulted mint finalization"
    );

    register_minted_vault_object_inner(
        state.inner(),
        vault_object_id,
        manifest_uri,
        manifest_hash,
        nft_token_id,
        tx_hash,
    )
    .await
}

/// Recovers Oracle finalization for a mint that succeeded before the desktop restarted.
///
/// This does not mint, sign, or submit. Oracle supplies the published metadata
/// pointer for the vault id, XRPL supplies the validated NFTokenID by tx hash,
/// and the existing finalization/register flow performs the idempotent link.
#[tauri::command(rename_all = "camelCase")]
pub async fn recover_pending_vault_mint(
    state: State<'_, Arc<AppState>>,
    vault_id: String,
    tx_hash: String,
) -> Result<VaultObjectResponse> {
    let oracle = state.get_oracle_client_with_timeout(30).await?;
    let recovery = oracle.get_vault_mint_recovery(&vault_id).await?;
    ensure_recoverable_mint_status(&recovery.status)?;

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    let nft_token_id = client
        .extract_minted_nftoken_id(&tx_hash)
        .await?
        .ok_or_else(|| {
            ClientError::Xrpl(format!(
                "Missing NFTokenID after successful XRPL mint. tx_hash={tx_hash}"
            ))
        })?;

    tracing::info!(
        nft_token_id = %nft_token_id,
        tx_hash = %tx_hash,
        metadata_hash = %recovery.metadata_hash,
        metadata_uri_len = recovery.metadata_uri.len(),
        vault_id = %recovery.vault_id,
        owner_identity_id = recovery.owner_identity_id.as_deref().unwrap_or(""),
        status = %recovery.status,
        request_phase = "recover_pending_mint",
        "Recovering Vaulted mint finalization after restart"
    );

    if recovery.vault_object_nft_token_id.as_deref() == Some(nft_token_id.as_str()) {
        tracing::info!(
            nft_token_id = %nft_token_id,
            tx_hash = %tx_hash,
            metadata_hash = %recovery.metadata_hash,
            metadata_uri_len = recovery.metadata_uri.len(),
            vault_id = %recovery.vault_id,
            owner_identity_id = recovery.owner_identity_id.as_deref().unwrap_or(""),
            status = "already_linked",
            request_phase = "recover_pending_mint",
            "Vaulted mint recovery found an existing matching vault object link"
        );
    }

    register_minted_vault_object_inner(
        state.inner(),
        recovery.vault_id,
        recovery.metadata_uri,
        recovery.metadata_hash,
        nft_token_id,
        tx_hash,
    )
    .await
}

fn ensure_recoverable_mint_status(status: &str) -> Result<()> {
    if status == "pending_claim" || status == "active" {
        return Ok(());
    }

    Err(ClientError::Validation(format!(
        "Vault mint recovery is not available for status {status}"
    )))
}

async fn register_minted_vault_object_inner(
    state: &Arc<AppState>,
    vault_object_id: String,
    manifest_uri: String,
    manifest_hash: String,
    nft_token_id: String,
    tx_hash: String,
) -> Result<VaultObjectResponse> {
    let identity = state.get_vaulted_identity().await?;
    let oracle = state.get_oracle_client_with_timeout(30).await?;

    tracing::info!(
        nft_token_id = %nft_token_id,
        tx_hash = %tx_hash,
        metadata_hash = %manifest_hash,
        metadata_uri_len = manifest_uri.len(),
        lookup_key_type = "nft_token_id",
        status = "finalizing",
        "Registering locally minted vault object"
    );

    oracle
        .finalize_vault_mint(&FinalizeVaultMintRequest {
            vault_id: vault_object_id.clone(),
            nft_token_id: nft_token_id.clone(),
            tx_hash,
            manifest_uri: manifest_uri.clone(),
            manifest_hash: manifest_hash.clone(),
            owner_identity_id: identity.identity_id_hex(),
        })
        .await?;

    tracing::info!(
        nft_token_id = %nft_token_id,
        metadata_hash = %manifest_hash,
        metadata_uri_len = manifest_uri.len(),
        lookup_key_type = "nft_token_id",
        status = "finalized",
        "Oracle mint finalization completed"
    );

    let request = RegisterVaultObjectRequest {
        id: vault_object_id,
        owner_identity_id: identity.identity_id_hex(),
        manifest_uri,
        manifest_hash,
        nft_chain: Some("xrpl:testnet".to_string()),
        nft_token_id: Some(nft_token_id),
        manifest: None,
    };

    let response = oracle.register_vault_object(&request).await?;
    tracing::info!(
        nft_token_id = response.nft_token_id.as_deref().unwrap_or(""),
        lookup_key_type = "nft_token_id",
        status = %response.status,
        "Vault object manifest link registered"
    );

    Ok(response)
}

#[derive(Debug, Clone)]
struct XrplSigningFields {
    fee_drops: String,
    sequence: u32,
    last_ledger_sequence: u32,
}

async fn fetch_xrpl_signing_fields(
    xrpl_node_url: &str,
    account: &str,
    fee_drops: Option<String>,
    sequence: Option<u32>,
    last_ledger_sequence: Option<u32>,
) -> Result<XrplSigningFields> {
    let mut client = XrplClient::new(xrpl_node_url);
    client.connect().await?;

    let resolved_sequence = match sequence {
        Some(sequence) => sequence,
        None => client.account_info(account).await?.sequence,
    };

    let resolved_fee = match fee_drops {
        Some(fee) => fee,
        None => client.fee_drops().await?,
    };

    let resolved_last_ledger = match last_ledger_sequence {
        Some(last_ledger) => last_ledger,
        None => client.ledger_current_index().await?.saturating_add(20),
    };

    Ok(XrplSigningFields {
        fee_drops: resolved_fee,
        sequence: resolved_sequence,
        last_ledger_sequence: resolved_last_ledger,
    })
}

/// Starts QR login. Desktop shows the returned qr_payload for scanning by mobile.
#[tauri::command(rename_all = "camelCase")]
pub async fn start_vaulted_qr_login(
    state: State<'_, Arc<AppState>>,
) -> Result<QrLoginStartResponse> {
    tracing::info!(
        command = "start_vaulted_qr_login",
        phase = "begin",
        "qr_login_command_boundary"
    );
    let oracle = match OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    }) {
        Ok(client) => client,
        Err(e) => {
            log_qr_login_error("start_vaulted_qr_login", "client_init_error", &e);
            return Err(e);
        },
    };
    tracing::info!(
        command = "start_vaulted_qr_login",
        phase = "oracle_request",
        "qr_login_command_boundary"
    );
    let response = match oracle
        .start_qr_login(&crate::oracle::api::QrLoginStartRequest {
            desktop_device_name: hostname::get()
                .ok()
                .map(|h| h.to_string_lossy().to_string()),
            desktop_device_public_key: Some(state.device_fingerprint().to_string()),
        })
        .await
    {
        Ok(response) => response,
        Err(e) => {
            log_qr_login_error("start_vaulted_qr_login", "oracle_request_error", &e);
            return Err(e);
        },
    };
    tracing::info!(
        command = "start_vaulted_qr_login",
        phase = "success",
        qr_request_id = %response.login_request_id,
        "qr_login_command_boundary"
    );
    Ok(QrLoginStartResponse {
        login_request_id: response.login_request_id,
        challenge: response.challenge,
        oracle_url: response.oracle_url,
        expires_at: response.expires_at,
        qr_payload: response.qr_payload,
    })
}

/// Polls QR login status and stores Oracle session when approved.
#[tauri::command(rename_all = "camelCase")]
pub async fn poll_vaulted_qr_login(
    state: State<'_, Arc<AppState>>,
    login_request_id: String,
) -> Result<serde_json::Value> {
    tracing::info!(
        command = "poll_vaulted_qr_login",
        phase = "begin",
        qr_request_id = %login_request_id,
        "qr_login_command_boundary"
    );
    let oracle = match OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    }) {
        Ok(client) => client,
        Err(e) => {
            log_qr_login_error("poll_vaulted_qr_login", "client_init_error", &e);
            return Err(e);
        },
    };
    let status = match oracle.qr_login_status(&login_request_id).await {
        Ok(status) => status,
        Err(e) => {
            log_qr_login_error("poll_vaulted_qr_login", "status_request_error", &e);
            return Err(e);
        },
    };
    tracing::info!(
        command = "poll_vaulted_qr_login",
        phase = "status_result",
        qr_request_id = %login_request_id,
        status = %status.status,
        "qr_login_command_boundary"
    );
    let local_identity_id = state
        .get_vaulted_identity()
        .await
        .ok()
        .map(|identity| identity.identity_id_hex());
    let has_local_identity = local_identity_id.is_some();
    let local_identity_matches_approved = local_identity_matches_approved(
        local_identity_id.as_deref(),
        status.identity_id.as_deref(),
    );
    if status.status == "approved" || status.status == "consumed" {
        if let (Some(token), Some(identity_id)) =
            (status.access_token.clone(), status.identity_id.clone())
        {
            if local_identity_matches_approved {
                let mut session = match state.get_session().await {
                    Ok(session) => session,
                    Err(_) => {
                        let wallet = state.get_xrpl_wallet().await?;
                        Session::new(
                            wallet.classic_address()?,
                            wallet.public_key_hex()?,
                            format!("vaulted-seed:{}", identity_id),
                            24,
                        )
                    },
                };
                if let Some(expires_in) = status.expires_in {
                    session.set_oracle_token_with_expiry(token, expires_in);
                } else {
                    session.set_oracle_token(token);
                }
                if let Some(refresh) = status.refresh_token.clone() {
                    session.set_refresh_token(refresh);
                }
                session.set_device_fingerprint(state.device_fingerprint().to_string());
                state.set_session(session).await;
            } else if !has_local_identity {
                let mut session = Session::with_oracle_token(
                    identity_id,
                    String::new(),
                    format!("vaulted-qr:{}", login_request_id),
                    24,
                    token,
                );
                if let Some(refresh) = status.refresh_token.clone() {
                    session.set_refresh_token(refresh);
                }
                if let Some(expires_in) = status.expires_in {
                    session.set_oracle_token_with_expiry(
                        session.oracle_token.clone().unwrap_or_default(),
                        expires_in,
                    );
                }
                session.set_device_fingerprint(state.device_fingerprint().to_string());
                state.set_session(session).await;
            }
        }
    }
    Ok(serde_json::json!({
        "status": status.status,
        "identityId": status.identity_id,
        "approved": status.access_token.is_some(),
        "oracleSession": status.access_token.is_some(),
        "localVaultedWallet": has_local_identity,
        "localIdentityMatchesApproved": local_identity_matches_approved,
        "localDecryptAvailable": local_identity_matches_approved,
    }))
}

fn local_identity_matches_approved(
    local_identity_id: Option<&str>,
    approved_identity_id: Option<&str>,
) -> bool {
    match (local_identity_id, approved_identity_id) {
        (Some(local), Some(approved)) => {
            let local = local.trim();
            !local.is_empty() && local.eq_ignore_ascii_case(approved.trim())
        },
        _ => false,
    }
}

/// Confirms QR login from a device that has the Vaulted seed unlocked.
#[tauri::command(rename_all = "camelCase")]
pub async fn confirm_vaulted_qr_login(
    state: State<'_, Arc<AppState>>,
    login_request_id: String,
    challenge: String,
) -> Result<bool> {
    let qr_request_id = login_request_id.clone();
    tracing::info!(
        command = "confirm_vaulted_qr_login",
        phase = "begin",
        qr_request_id = %qr_request_id,
        "qr_login_command_boundary"
    );
    let identity = match state.get_vaulted_identity().await {
        Ok(identity) => identity,
        Err(e) => {
            log_qr_login_error("confirm_vaulted_qr_login", "identity_error", &e);
            return Err(e);
        },
    };
    let message = format!(
        "Vaulted QR Login v1\nlogin_request_id:{}\nchallenge:{}\noracle_url:{}\ndevice_id:{}",
        login_request_id,
        challenge,
        state.config.oracle_url,
        state.device_fingerprint()
    );
    use ed25519_dalek::Signer;
    let signature = identity.signing_key().sign(message.as_bytes());

    let oracle = match OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    }) {
        Ok(client) => client,
        Err(e) => {
            log_qr_login_error("confirm_vaulted_qr_login", "client_init_error", &e);
            return Err(e);
        },
    };
    let result = match oracle
        .confirm_qr_login(&crate::oracle::api::QrLoginConfirmRequest {
            login_request_id,
            identity_id: identity.identity_id_hex(),
            device_id: state.device_fingerprint().to_string(),
            signing_public_key: identity.signing_public_key_hex(),
            signature: hex::encode(signature.to_bytes()),
        })
        .await
    {
        Ok(result) => result,
        Err(e) => {
            log_qr_login_error("confirm_vaulted_qr_login", "confirm_request_error", &e);
            return Err(e);
        },
    };
    tracing::info!(
        command = "confirm_vaulted_qr_login",
        phase = "result",
        qr_request_id = %qr_request_id,
        approved = result.approved,
        status = %result.status,
        "qr_login_command_boundary"
    );
    Ok(result.approved)
}

fn log_qr_login_error(command: &'static str, phase: &'static str, error: &ClientError) {
    let (error_class, endpoint_status) = qr_login_error_diagnostics(error);
    tracing::warn!(
        command,
        phase,
        error_class,
        endpoint_status,
        "qr_login_command_boundary_error"
    );
}

fn qr_login_error_diagnostics(error: &ClientError) -> (&'static str, u16) {
    match error {
        ClientError::Http(e) => (
            "http_error",
            e.status().map(|status| status.as_u16()).unwrap_or(0),
        ),
        ClientError::Oracle(_) => ("oracle_api_error", 0),
        ClientError::Config(_) => ("config_error", 0),
        ClientError::Auth(_) => ("auth_error", 0),
        ClientError::Validation(_) => ("validation_error", 0),
        ClientError::NoSession => ("no_session", 0),
        ClientError::SessionExpired => ("session_expired", 0),
        _ => ("client_error", 0),
    }
}

/// Starts Scan-to-Pair-Device. The returned QR payload is scanned by a trusted device.
#[tauri::command(rename_all = "camelCase")]
pub async fn start_vaulted_device_pairing(
    state: State<'_, Arc<AppState>>,
    identity_id: Option<String>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let resolved_identity_id = match identity_id {
        Some(id) if !id.trim().is_empty() => id,
        _ => identity.identity_id_hex(),
    };
    let device_name = hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|| "Vaulted desktop".to_string());
    let device_public_key = identity.device_public_key_hex();
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let response = oracle
        .start_qr_device_pairing(&crate::oracle::api::QrPairDeviceStartRequest {
            identity_id: resolved_identity_id,
            desktop_device_name: Some(device_name.clone()),
            desktop_device_public_key: device_public_key.clone(),
        })
        .await?;
    Ok(serde_json::json!({
        "pairingRequestId": response.pairing_request_id,
        "challenge": response.challenge,
        "oracleUrl": response.oracle_url,
        "expiresAt": response.expires_at,
        "deviceName": device_name,
        "devicePublicKey": device_public_key,
        "qrPayload": response.qr_payload,
    }))
}

/// Polls Scan-to-Pair-Device status.
#[tauri::command(rename_all = "camelCase")]
pub async fn poll_vaulted_device_pairing(
    state: State<'_, Arc<AppState>>,
    pairing_request_id: String,
) -> Result<serde_json::Value> {
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let status = oracle.qr_device_pairing_status(&pairing_request_id).await?;
    Ok(serde_json::json!({
        "status": status.status,
        "identityId": status.identity_id,
        "deviceId": status.device_id,
        "pairedAt": status.paired_at,
        "paired": status.device_id.is_some(),
    }))
}

/// Confirms Scan-to-Pair-Device from a trusted unlocked Vaulted identity.
#[tauri::command(rename_all = "camelCase")]
pub async fn confirm_vaulted_device_pairing(
    state: State<'_, Arc<AppState>>,
    pairing_request_id: String,
    challenge: String,
    desktop_device_public_key: String,
    desktop_device_name: Option<String>,
) -> Result<bool> {
    let identity = state.get_vaulted_identity().await?;
    let message = format!(
        "Vaulted QR Pair Device v1\npairing_request_id:{}\nchallenge:{}\noracle_url:{}\ndesktop_device_public_key:{}\ndesktop_device_name:{}\nauthorizing_device_id:{}",
        pairing_request_id,
        challenge,
        state.config.oracle_url,
        desktop_device_public_key,
        desktop_device_name.as_deref().unwrap_or(""),
        state.device_fingerprint()
    );
    use ed25519_dalek::Signer;
    let signature = identity.signing_key().sign(message.as_bytes());

    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let result = oracle
        .confirm_qr_device_pairing(&crate::oracle::api::QrPairDeviceConfirmRequest {
            pairing_request_id,
            identity_id: identity.identity_id_hex(),
            authorizing_device_id: state.device_fingerprint().to_string(),
            signing_public_key: identity.signing_public_key_hex(),
            signature: hex::encode(signature.to_bytes()),
        })
        .await?;
    Ok(result.approved)
}

/// Starts Scan-to-Sign-XRPL-Transaction. The returned QR payload can be approved by a trusted device.
#[tauri::command(rename_all = "camelCase")]
pub async fn start_vaulted_xrpl_signing_request(
    state: State<'_, Arc<AppState>>,
    xrpl_tx_json: serde_json::Value,
    expected_xrpl_account: Option<String>,
    human_summary: Option<String>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let wallet = state.get_xrpl_wallet().await?;
    let resolved_account = match expected_xrpl_account {
        Some(account) if !account.trim().is_empty() => account,
        _ => wallet.classic_address()?,
    };
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let response = oracle
        .start_qr_xrpl_signing(&QrXrplSigningStartRequest {
            identity_id: identity.identity_id_hex(),
            xrpl_tx_json,
            expected_xrpl_account: resolved_account,
            requester_device_id: Some(state.device_fingerprint().to_string()),
            requester_device_name: hostname::get()
                .ok()
                .map(|h| h.to_string_lossy().to_string()),
            human_summary,
        })
        .await?;

    Ok(serde_json::json!({
        "signingRequestId": response.signing_request_id,
        "challenge": response.challenge,
        "oracleUrl": response.oracle_url,
        "expiresAt": response.expires_at,
        "txJsonHash": response.tx_json_hash,
        "qrPayload": response.qr_payload,
    }))
}

/// Polls Scan-to-Sign-XRPL-Transaction status.
#[tauri::command(rename_all = "camelCase")]
pub async fn poll_vaulted_xrpl_signing_request(
    state: State<'_, Arc<AppState>>,
    signing_request_id: String,
) -> Result<serde_json::Value> {
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let status = oracle.qr_xrpl_signing_status(&signing_request_id).await?;
    Ok(serde_json::json!({
        "status": status.status,
        "identityId": status.identity_id,
        "txJsonHash": status.tx_json_hash,
        "expectedXrplAccount": status.expected_xrpl_account,
        "approvedByDeviceId": status.approved_by_device_id,
        "approvalSignature": status.approval_signature,
        "approvedAt": status.approved_at,
        "approved": status.approval_signature.is_some(),
    }))
}

/// Confirms Scan-to-Sign-XRPL-Transaction from a trusted unlocked Vaulted identity.
// Keep the command signature stable for the Tauri camelCase API surface.
#[allow(clippy::too_many_arguments)]
#[tauri::command(rename_all = "camelCase")]
pub async fn confirm_vaulted_xrpl_signing_request(
    state: State<'_, Arc<AppState>>,
    signing_request_id: String,
    challenge: String,
    oracle_url: Option<String>,
    tx_json_hash: String,
    expected_xrpl_account: String,
    requester_device_id: Option<String>,
    requester_device_name: Option<String>,
) -> Result<bool> {
    let identity = state.get_vaulted_identity().await?;
    let resolved_oracle_url = oracle_url.unwrap_or_else(|| state.config.oracle_url.clone());
    let authorizing_device_id = state.device_fingerprint().to_string();
    let message = format!(
        "Vaulted QR XRPL Sign v1\nsigning_request_id:{}\nchallenge:{}\noracle_url:{}\ntx_json_hash:{}\nexpected_xrpl_account:{}\nrequester_device_id:{}\nrequester_device_name:{}\nauthorizing_device_id:{}",
        signing_request_id,
        challenge,
        resolved_oracle_url,
        tx_json_hash,
        expected_xrpl_account,
        requester_device_id.as_deref().unwrap_or(""),
        requester_device_name.as_deref().unwrap_or(""),
        authorizing_device_id,
    );
    use ed25519_dalek::Signer;
    let signature = identity.signing_key().sign(message.as_bytes());

    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let result = oracle
        .confirm_qr_xrpl_signing(&QrXrplSigningConfirmRequest {
            signing_request_id,
            identity_id: identity.identity_id_hex(),
            authorizing_device_id,
            signing_public_key: identity.signing_public_key_hex(),
            signature: hex::encode(signature.to_bytes()),
        })
        .await?;
    Ok(result.approved)
}

/// Computes the Vaulted display fingerprint for a recipient encryption public key.
#[tauri::command(rename_all = "camelCase")]
pub async fn compute_recipient_encryption_key_fingerprint(
    recipient_encryption_public_key: String,
) -> Result<serde_json::Value> {
    let fingerprint = encryption_public_key_fingerprint_hex(&recipient_encryption_public_key)?;
    Ok(serde_json::json!({
        "fingerprint": fingerprint,
        "displayFingerprint": format_fingerprint_groups(&fingerprint),
    }))
}

/// Returns recipient identity public keys plus TOFU trust status for the current owner.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_vaulted_recipient_key_trust(
    state: State<'_, Arc<AppState>>,
    recipient_identity_id: String,
    recipient_encryption_public_key: Option<String>,
    owner_identity_id: Option<String>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let owner_identity_id = owner_identity_id.unwrap_or_else(|| identity.identity_id_hex());
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let recipient_public = oracle
        .get_vaulted_identity_public(&recipient_identity_id)
        .await?;
    let encryption_key = recipient_encryption_public_key
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| recipient_public.encryption_public_key.clone());
    let fingerprint = encryption_public_key_fingerprint_hex(&encryption_key)?;
    let trust = oracle
        .recipient_key_trust_status(
            &owner_identity_id,
            &recipient_identity_id,
            Some(&fingerprint),
        )
        .await
        .unwrap_or_else(|_| RecipientKeyTrustResponse {
            owner_identity_id: owner_identity_id.clone(),
            recipient_identity_id: recipient_identity_id.clone(),
            recipient_encryption_public_key: encryption_key.clone(),
            recipient_encryption_public_key_fingerprint: fingerprint.clone(),
            trusted: false,
            trust_level: "untrusted".into(),
            trust_source: "none".into(),
            trusted_at: None,
            revoked_at: None,
            active_recipient_encryption_public_key_fingerprint: Some(fingerprint.clone()),
            key_rotation_detected: Some(false),
            trusted_different_key_fingerprint: None,
            trusted_different_key_at: None,
        });

    Ok(serde_json::json!({
        "ownerIdentityId": owner_identity_id,
        "recipientIdentityId": recipient_identity_id,
        "recipientEncryptionPublicKey": encryption_key,
        "recipientEncryptionPublicKeyFingerprint": fingerprint,
        "displayFingerprint": format_fingerprint_groups(&fingerprint),
        "trusted": trust.trusted,
        "trustLevel": trust.trust_level,
        "trustSource": trust.trust_source,
        "trustedAt": trust.trusted_at,
        "revokedAt": trust.revoked_at,
        "activeRecipientEncryptionPublicKeyFingerprint": trust.active_recipient_encryption_public_key_fingerprint.unwrap_or_else(|| fingerprint.clone()),
        "keyRotationDetected": trust.key_rotation_detected.unwrap_or(false),
        "trustedDifferentKeyFingerprint": trust.trusted_different_key_fingerprint,
        "trustedDifferentKeyAt": trust.trusted_different_key_at,
    }))
}

/// Stores a TOFU/manual trust decision for a recipient encryption public key.
#[tauri::command(rename_all = "camelCase")]
pub async fn trust_vaulted_recipient_key(
    state: State<'_, Arc<AppState>>,
    recipient_identity_id: String,
    recipient_encryption_public_key: Option<String>,
    owner_identity_id: Option<String>,
    trust_source: Option<String>,
    trust_level: Option<String>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let owner_identity_id = owner_identity_id.unwrap_or_else(|| identity.identity_id_hex());
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let recipient_public = oracle
        .get_vaulted_identity_public(&recipient_identity_id)
        .await?;
    let encryption_key = recipient_encryption_public_key
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| recipient_public.encryption_public_key.clone());
    let fingerprint = encryption_public_key_fingerprint_hex(&encryption_key)?;
    let trust = oracle
        .trust_recipient_key(&TrustRecipientKeyRequest {
            owner_identity_id: owner_identity_id.clone(),
            recipient_identity_id: recipient_identity_id.clone(),
            recipient_encryption_public_key: encryption_key.clone(),
            recipient_encryption_public_key_fingerprint: fingerprint.clone(),
            trust_source: trust_source.or_else(|| Some("desktop-tofu".into())),
            trust_level: trust_level.or_else(|| Some("tofu".into())),
        })
        .await?;
    Ok(serde_json::json!({
        "ownerIdentityId": trust.owner_identity_id,
        "recipientIdentityId": trust.recipient_identity_id,
        "recipientEncryptionPublicKey": trust.recipient_encryption_public_key,
        "recipientEncryptionPublicKeyFingerprint": trust.recipient_encryption_public_key_fingerprint,
        "displayFingerprint": format_fingerprint_groups(&trust.recipient_encryption_public_key_fingerprint),
        "trusted": trust.trusted,
        "trustLevel": trust.trust_level,
        "trustSource": trust.trust_source,
        "trustedAt": trust.trusted_at,
        "revokedAt": trust.revoked_at,
        "activeRecipientEncryptionPublicKeyFingerprint": trust.active_recipient_encryption_public_key_fingerprint.unwrap_or_else(|| trust.recipient_encryption_public_key_fingerprint.clone()),
        "keyRotationDetected": trust.key_rotation_detected.unwrap_or(false),
        "trustedDifferentKeyFingerprint": trust.trusted_different_key_fingerprint,
        "trustedDifferentKeyAt": trust.trusted_different_key_at,
    }))
}

/// Revokes a TOFU/manual trust decision for a recipient encryption public key.
#[tauri::command(rename_all = "camelCase")]
pub async fn revoke_vaulted_recipient_key_trust(
    state: State<'_, Arc<AppState>>,
    recipient_identity_id: String,
    recipient_encryption_public_key_fingerprint: Option<String>,
    owner_identity_id: Option<String>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let owner_identity_id = owner_identity_id.unwrap_or_else(|| identity.identity_id_hex());
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let trust = oracle
        .revoke_recipient_key_trust(&RevokeRecipientKeyTrustRequest {
            owner_identity_id: owner_identity_id.clone(),
            recipient_identity_id: recipient_identity_id.clone(),
            recipient_encryption_public_key_fingerprint,
        })
        .await?;
    Ok(serde_json::json!({
        "ownerIdentityId": trust.owner_identity_id,
        "recipientIdentityId": trust.recipient_identity_id,
        "recipientEncryptionPublicKey": trust.recipient_encryption_public_key,
        "recipientEncryptionPublicKeyFingerprint": trust.recipient_encryption_public_key_fingerprint,
        "displayFingerprint": format_fingerprint_groups(&trust.recipient_encryption_public_key_fingerprint),
        "trusted": trust.trusted,
        "trustLevel": trust.trust_level,
        "trustSource": trust.trust_source,
        "trustedAt": trust.trusted_at,
        "revokedAt": trust.revoked_at,
        "activeRecipientEncryptionPublicKeyFingerprint": trust.active_recipient_encryption_public_key_fingerprint.unwrap_or_else(|| trust.recipient_encryption_public_key_fingerprint.clone()),
        "keyRotationDetected": trust.key_rotation_detected.unwrap_or(false),
        "trustedDifferentKeyFingerprint": trust.trusted_different_key_fingerprint,
        "trustedDifferentKeyAt": trust.trusted_different_key_at,
    }))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultedDeviceInfo {
    pub device_id: String,
    pub identity_id: String,
    pub device_public_key: String,
    pub device_public_key_fingerprint: String,
    pub device_name: Option<String>,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub is_current_device: bool,
}

impl VaultedDeviceInfo {
    fn from_response(device: IdentityDeviceResponse, current_device_public_key: &str) -> Self {
        Self {
            is_current_device: device.device_public_key == current_device_public_key,
            device_id: device.id,
            identity_id: device.identity_id,
            device_public_key: device.device_public_key,
            device_public_key_fingerprint: device.device_public_key_fingerprint,
            device_name: device.device_name,
            status: device.status,
            created_at: device.created_at,
            revoked_at: device.revoked_at,
        }
    }
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_vaulted_identity_devices(
    state: State<'_, Arc<AppState>>,
    include_revoked: Option<bool>,
) -> Result<Vec<VaultedDeviceInfo>> {
    let identity = state.get_vaulted_identity().await?;
    let identity_id = identity.identity_id_hex();
    let current_device_public_key = identity.device_public_key_hex();
    let oracle = state.get_oracle_client_with_timeout(30).await?;
    let devices = oracle
        .list_identity_devices(&identity_id, include_revoked.unwrap_or(true))
        .await?;

    Ok(devices
        .into_iter()
        .map(|device| VaultedDeviceInfo::from_response(device, &current_device_public_key))
        .collect())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn revoke_vaulted_identity_device(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> Result<VaultedDeviceInfo> {
    let identity = state.get_vaulted_identity().await?;
    let identity_id = identity.identity_id_hex();
    let current_device_public_key = identity.device_public_key_hex();
    let oracle = state.get_oracle_client_with_timeout(30).await?;
    let device = oracle
        .revoke_identity_device(&device_id, &identity_id)
        .await?;
    Ok(VaultedDeviceInfo::from_response(
        device,
        &current_device_public_key,
    ))
}

async fn build_recipient_key_envelope(
    oracle: &OracleClient,
    vault_object_id: &str,
    recipient_identity_id: &str,
    compatibility_encrypted_file_key: &str,
    file_key_base64: Option<String>,
    recipient_encryption_public_key: Option<String>,
) -> Result<serde_json::Value> {
    if let Some(file_key_base64) = file_key_base64.filter(|v| !v.trim().is_empty()) {
        let recipient_public_key =
            match recipient_encryption_public_key.filter(|v| !v.trim().is_empty()) {
                Some(pk) => pk,
                None => {
                    oracle
                        .get_vaulted_identity_public(recipient_identity_id)
                        .await?
                        .encryption_public_key
                },
            };
        let file_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            file_key_base64.trim(),
        )
        .map_err(|e| ClientError::InvalidData(format!("Invalid file_key_base64: {e}")))?;
        if file_key.is_empty() {
            return Err(ClientError::InvalidData(
                "file_key_base64 decoded to an empty key".into(),
            ));
        }
        let recipient_key_id = recipient_public_key_id(&recipient_public_key);
        let aad = grant_envelope_aad(vault_object_id, recipient_identity_id);
        let envelope = seal_key_for_recipient_hex(
            &file_key,
            &recipient_public_key,
            recipient_identity_id.to_string(),
            recipient_key_id,
            "grant-recipient",
            aad.as_bytes(),
        )?;
        return serde_json::to_value(envelope).map_err(ClientError::from);
    }

    Ok(serde_json::json!({
        "protocol": "vaulted-key-envelope-v1",
        "alg": "legacy-pre-aes-key",
        "recipient_type": "grant-recipient",
        "recipient_identity_id": recipient_identity_id,
        "encrypted_file_key": compatibility_encrypted_file_key,
    }))
}

fn grant_envelope_aad(vault_object_id: &str, recipient_identity_id: &str) -> String {
    format!("vaulted-grant-envelope-v1:{vault_object_id}:{recipient_identity_id}")
}

fn recipient_public_key_id(recipient_public_key_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Vaulted v1 recipient encryption public key id");
    hasher.update(recipient_public_key_hex.as_bytes());
    hex::encode(hasher.finalize())
}

/// Starts Scan-to-Approve-File-Grant. The returned QR payload can be approved by a trusted device.
// Keep the command signature stable for the Tauri camelCase API surface.
#[allow(clippy::too_many_arguments)]
#[tauri::command(rename_all = "camelCase")]
pub async fn start_vaulted_file_grant_approval(
    state: State<'_, Arc<AppState>>,
    vault_object_id: String,
    recipient_identity_id: String,
    encrypted_file_key: String,
    permissions: Vec<String>,
    grant_expires_at: Option<String>,
    human_summary: Option<String>,
    // Optional raw file/content key as base64. When present, Vaulted builds a real X25519 key envelope.
    file_key_base64: Option<String>,
    // Optional recipient X25519 encryption public key hex. If omitted, Oracle identity lookup is used.
    recipient_encryption_public_key: Option<String>,
    // When true and file_key_base64 is present, the recipient encryption key must be TOFU/manual trusted.
    require_trusted_recipient: Option<bool>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let parsed_expires_at = match grant_expires_at {
        Some(ts) if !ts.trim().is_empty() => Some(
            chrono::DateTime::parse_from_rfc3339(&ts)
                .map_err(|e| ClientError::Config(format!("Invalid grant expiration: {}", e)))?
                .with_timezone(&chrono::Utc),
        ),
        _ => None,
    };
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    if require_trusted_recipient.unwrap_or(false)
        && file_key_base64
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    {
        let recipient_public_key = match recipient_encryption_public_key
            .as_ref()
            .filter(|v| !v.trim().is_empty())
        {
            Some(pk) => pk.clone(),
            None => {
                oracle
                    .get_vaulted_identity_public(&recipient_identity_id)
                    .await?
                    .encryption_public_key
            },
        };
        let fingerprint = encryption_public_key_fingerprint_hex(&recipient_public_key)?;
        let trust = oracle
            .recipient_key_trust_status(
                &identity.identity_id_hex(),
                &recipient_identity_id,
                Some(&fingerprint),
            )
            .await?;
        if !trust.trusted {
            return Err(ClientError::InvalidData(format!(
                "Recipient encryption key is not trusted. Verify fingerprint {} before granting access.",
                format_fingerprint_groups(&fingerprint)
            )));
        }
    }

    let key_envelope = build_recipient_key_envelope(
        &oracle,
        &vault_object_id,
        &recipient_identity_id,
        &encrypted_file_key,
        file_key_base64,
        recipient_encryption_public_key,
    )
    .await?;
    let response = oracle
        .start_qr_file_grant_approval(&QrFileGrantStartRequest {
            identity_id: identity.identity_id_hex(),
            vault_object_id,
            recipient_identity_id: recipient_identity_id.clone(),
            key_envelope,
            encrypted_file_key: None,
            permissions,
            grant_expires_at: parsed_expires_at,
            requester_device_id: Some(state.device_fingerprint().to_string()),
            requester_device_name: hostname::get()
                .ok()
                .map(|h| h.to_string_lossy().to_string()),
            human_summary,
        })
        .await?;

    Ok(serde_json::json!({
        "grantRequestId": response.grant_request_id,
        "grantId": response.grant_id,
        "challenge": response.challenge,
        "oracleUrl": response.oracle_url,
        "expiresAt": response.expires_at,
        "grantContextHash": response.grant_context_hash,
        "qrPayload": response.qr_payload,
    }))
}

/// Polls Scan-to-Approve-File-Grant status.
#[tauri::command(rename_all = "camelCase")]
pub async fn poll_vaulted_file_grant_approval(
    state: State<'_, Arc<AppState>>,
    grant_request_id: String,
) -> Result<serde_json::Value> {
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let status = oracle
        .qr_file_grant_approval_status(&grant_request_id)
        .await?;
    Ok(serde_json::json!({
        "status": status.status,
        "identityId": status.identity_id,
        "vaultObjectId": status.vault_object_id,
        "grantId": status.grant_id,
        "recipientIdentityId": status.recipient_identity_id,
        "grantContextHash": status.grant_context_hash,
        "approvedByDeviceId": status.approved_by_device_id,
        "approvalSignature": status.approval_signature,
        "createdGrantId": status.created_grant_id,
        "approvedAt": status.approved_at,
        "approved": status.created_grant_id.is_some(),
    }))
}

/// Confirms Scan-to-Approve-File-Grant from a trusted unlocked Vaulted identity.
// Keep the command signature stable for the Tauri camelCase API surface.
#[allow(clippy::too_many_arguments)]
#[tauri::command(rename_all = "camelCase")]
pub async fn confirm_vaulted_file_grant_approval(
    state: State<'_, Arc<AppState>>,
    grant_request_id: String,
    challenge: String,
    oracle_url: Option<String>,
    vault_object_id: String,
    grant_id: String,
    recipient_identity_id: String,
    grant_context_hash: String,
    requester_device_id: Option<String>,
    requester_device_name: Option<String>,
) -> Result<bool> {
    let identity = state.get_vaulted_identity().await?;
    let resolved_oracle_url = oracle_url.unwrap_or_else(|| state.config.oracle_url.clone());
    let authorizing_device_id = state.device_fingerprint().to_string();
    let message = format!(
        "Vaulted QR File Grant v1\ngrant_request_id:{}\nchallenge:{}\noracle_url:{}\nvault_object_id:{}\ngrant_id:{}\nrecipient_identity_id:{}\ngrant_context_hash:{}\nrequester_device_id:{}\nrequester_device_name:{}\nauthorizing_device_id:{}",
        grant_request_id,
        challenge,
        resolved_oracle_url,
        vault_object_id,
        grant_id,
        recipient_identity_id,
        grant_context_hash,
        requester_device_id.as_deref().unwrap_or(""),
        requester_device_name.as_deref().unwrap_or(""),
        authorizing_device_id,
    );
    use ed25519_dalek::Signer;
    let signature = identity.signing_key().sign(message.as_bytes());

    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;
    let result = oracle
        .confirm_qr_file_grant_approval(&QrFileGrantConfirmRequest {
            grant_request_id,
            identity_id: identity.identity_id_hex(),
            authorizing_device_id,
            signing_public_key: identity.signing_public_key_hex(),
            signature: hex::encode(signature.to_bytes()),
        })
        .await?;
    Ok(result.approved)
}

// ==================== Progress Events ====================

/// Progress event for upload/download
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    /// Operation identifier (nft_token_id or file_path)
    pub operation_id: String,
    /// Operation type: "upload" or "download"
    pub operation_type: String,
    /// Current phase: "encrypting", "uploading", "minting", "downloading", "decrypting"
    pub stage: String,
    /// Current phase progress (0-100)
    pub progress: u32,
    /// Overall operation progress (0-100)
    pub total_progress: u32,
    /// Current action description
    pub message: String,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Total bytes
    pub bytes_total: u64,
}

impl ProgressEvent {
    fn new(operation_id: &str, operation_type: &str) -> Self {
        Self {
            operation_id: operation_id.to_string(),
            operation_type: operation_type.to_string(),
            stage: "starting".to_string(),
            progress: 0,
            total_progress: 0,
            message: "Starting...".to_string(),
            bytes_processed: 0,
            bytes_total: 0,
        }
    }

    fn emit(&self, app: &AppHandle) {
        let _ = app.emit("file-progress", self.clone());
    }
}

// ==================== Auth Commands ====================

/// Step 3: DEPRECATED - PRE keys are now derived automatically during Vaulted unlock
/// Kept for UI compatibility
#[tauri::command]
pub async fn start_key_derivation(
    state: State<'_, Arc<AppState>>,
) -> Result<VaultedSigningRequest> {
    // PRE keys are already derived during Vaulted unlock
    // Return an empty payload - the UI will check has_pre_keys and see that keys exist
    let session = state.get_session().await?;

    if state.has_keypair().await {
        tracing::info!(
            "PRE keys already derived from Vaulted unlock for {}",
            session.wallet_address
        );
    }

    // Return a dummy payload - the UI must not use it
    Ok(VaultedSigningRequest {
        uuid: "keys-already-derived".to_string(),
        qr_png: String::new(),
        qr_uri: String::new(),
        websocket_url: String::new(),
        expires_at: None,
        challenge: None,
    })
}

/// Step 4: DEPRECATED - PRE keys are now derived automatically during Vaulted unlock
/// Kept for UI compatibility
#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_key_derivation(
    state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
) -> Result<KeyDerivationResponse> {
    let session = state.get_session().await?;

    // PRE keys are already derived during Vaulted unlock
    let public_key_hex = state.get_public_key_hex().await?;

    tracing::info!(
        "PRE keys already derived for {} from Vaulted unlock, public_key: {}...",
        session.wallet_address,
        &public_key_hex[..16]
    );

    Ok(KeyDerivationResponse {
        public_key: public_key_hex,
        wallet_address: session.wallet_address,
    })
}

/// Checks whether PRE keys exist for the current user (in memory)
#[tauri::command]
pub async fn has_pre_keys(state: State<'_, Arc<AppState>>) -> Result<bool> {
    let _session = state.get_session().await?;
    Ok(state.has_keypair().await)
}

/// Logs out
#[tauri::command]
pub async fn logout(state: State<'_, Arc<AppState>>) -> Result<()> {
    state.clear_session().await;
    Ok(())
}

/// Checks authorization status
#[tauri::command]
pub async fn is_authenticated(state: State<'_, Arc<AppState>>) -> Result<bool> {
    Ok(state.is_authenticated().await)
}

/// Returns the Oracle base URL for frontend image loading
#[tauri::command]
pub async fn get_oracle_url(state: State<'_, Arc<AppState>>) -> Result<String> {
    Ok(state.config.oracle_url.clone())
}

/// Gets the current session
#[tauri::command]
pub async fn get_current_session(state: State<'_, Arc<AppState>>) -> Result<Option<Session>> {
    match state.get_session().await {
        Ok(session) => Ok(Some(session)),
        Err(_) => Ok(None),
    }
}

/// User information
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub wallet_address: String,
    pub public_key: String,
    pub has_pre_keys: bool,
    pub has_vaulted_wallet: bool,
    pub vaulted_identity_id: Option<String>,
    pub encryption_public_key: Option<String>,
    pub signing_public_key: Option<String>,
    pub expires_at: String,
}

/// Gets current user information
#[tauri::command]
pub async fn get_current_user(state: State<'_, Arc<AppState>>) -> Result<UserInfo> {
    let session = state.get_session().await?;
    let has_pre_keys = state.has_keypair().await;
    let has_vaulted_wallet = state.has_vaulted_identity().await;
    let identity = if has_vaulted_wallet {
        state.get_vaulted_identity().await.ok()
    } else {
        None
    };
    let public_key = if let Some(identity) = identity.as_ref() {
        identity.encryption_public_key_hex()
    } else if has_pre_keys {
        state.get_public_key_hex().await.unwrap_or_default()
    } else {
        String::new()
    };

    Ok(UserInfo {
        wallet_address: session.wallet_address,
        public_key,
        has_pre_keys,
        has_vaulted_wallet,
        vaulted_identity_id: identity.as_ref().map(|i| i.identity_id_hex()),
        encryption_public_key: identity.as_ref().map(|i| i.encryption_public_key_hex()),
        signing_public_key: identity.as_ref().map(|i| i.signing_public_key_hex()),
        expires_at: session.expires_at.to_rfc3339(),
    })
}

/// Key derivation response
#[derive(Serialize)]
pub struct KeyDerivationResponse {
    pub public_key: String,
    pub wallet_address: String,
}

// ==================== File Upload Commands ====================

/// File upload result
#[derive(Debug, Serialize)]
pub struct UploadResult {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub signing_request_uri: String,
    pub nft_uri: String,
    pub manifest_hash: String,
    pub filename: String,
    pub file_size: u64,
    pub fragments_count: u32,
}

/// Upload progress
#[derive(Debug, Clone, Serialize)]
pub struct UploadProgress {
    pub stage: String,
    pub progress: u32,
    pub message: String,
}

/// Minimal file metadata returned for user-selected upload paths.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedFileMetadata {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_file: bool,
    pub is_dir: bool,
}

/// Returns metadata for selected upload paths without exposing the Tauri fs plugin to the WebView.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_selected_file_metadata(
    state: State<'_, Arc<AppState>>,
    file_paths: Vec<String>,
) -> Result<Vec<SelectedFileMetadata>> {
    state.get_session().await?;

    if file_paths.len() > 100 {
        return Err(ClientError::Validation(
            "Too many file paths selected".to_string(),
        ));
    }

    let mut entries = Vec::with_capacity(file_paths.len());
    for file_path in file_paths {
        let path = Path::new(&file_path);
        let metadata = tokio::fs::metadata(path).await?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        entries.push(SelectedFileMetadata {
            path: file_path,
            name,
            size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
        });
    }

    Ok(entries)
}

/// Uploads a file: encrypts it, sends it to storage, and mints an NFT
#[tauri::command]
pub async fn upload_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    file_path: String,
) -> Result<UploadResult> {
    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    // Check that the keypair is in memory
    if !state.has_keypair().await {
        return Err(ClientError::Auth(
            "Vaulted wallet is locked. Create or restore it from seed phrase first.".to_string(),
        ));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());

    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(ClientError::FileSystem(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", file_path),
        )));
    }

    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len();

    if file_size > state.config.max_file_size {
        return Err(ClientError::FileTooLarge {
            size: file_size,
            max: state.config.max_file_size,
        });
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Initialize progress
    let mut progress = ProgressEvent::new(&file_path, "upload");
    progress.bytes_total = file_size;
    progress.emit(&app);

    tracing::info!("Uploading encrypted file payload ({} bytes)", file_size);

    // Phase 1: Encryption (0-30%)
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting file...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_file(path, &public_key).await?;
    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.progress = 100;
    progress.message = "File encrypted".to_string();
    progress.emit(&app);

    tracing::info!("File encrypted: {} bytes", encrypted_bytes.len());

    // Phase 2: Vault creation and NFT minting (30-60%)
    progress.stage = "minting".to_string();
    progress.progress = 0;
    progress.message = "Preparing encrypted vault...".to_string();
    progress.total_progress = 35;
    progress.emit(&app);

    let metadata_hash = encrypted.manifest.compute_hash();

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    // Create a vault with empty storage info (filled after upload)
    let vault_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash: metadata_hash.clone(),
        manifest: VaultManifest {
            encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
            original_size: encrypted.manifest.original_size,
            mime_type: encrypted.manifest.mime_type.clone(),
            original_hash: encrypted.manifest.original_hash.clone(),
            fragments: vec![VaultFragment {
                index: 0,
                storage_node_id: String::new(), // Filled by Oracle
                storage_key: String::new(),     // Filled by Oracle
                encrypted_hash: encrypted.encrypted_hash.clone(),
                size: encrypted_bytes.len() as u64,
            }],
        },
    };

    progress.total_progress = 50;
    progress.message = "Preparing vault registry entry...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&vault_request).await?;

    progress.total_progress = 60;
    progress.message = "Vault prepared for local mint".to_string();
    progress.emit(&app);

    tracing::info!(
        "Vault prepared. Pending upload key: {}",
        vault_response.nft_token_id
    );

    // Phase 3: Upload through Oracle proxy (60-95%)
    progress.stage = "uploading".to_string();
    progress.progress = 0;
    progress.message = "Uploading encrypted data...".to_string();
    progress.total_progress = 65;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url, vault_response.nft_token_id
    );

    tracing::info!("Uploading encrypted payload through Oracle proxy");

    let response = state
        .create_authed_client()
        .await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes.clone())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload file: {} - {}",
            status, error_text
        )));
    }

    let _upload_result: serde_json::Value = response.json().await?;
    tracing::info!("Encrypted payload upload completed");

    progress.total_progress = 95;
    progress.progress = 100;
    progress.bytes_processed = encrypted_bytes.len() as u64;
    progress.message = "Upload complete".to_string();
    progress.emit(&app);

    // Final progress
    progress.stage = "complete".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.message = "Upload complete!".to_string();
    progress.emit(&app);

    Ok(UploadResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        signing_request_uri: vault_response.signing_request_uri,
        nft_uri: vault_response.nft_uri,
        manifest_hash: metadata_hash,
        filename,
        file_size,
        fragments_count: 1,
    })
}

/// Uploads multiple files (automatically archives them into ZIP)
#[tauri::command]
pub async fn upload_files(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    file_paths: Vec<String>,
    custom_name: Option<String>,
) -> Result<UploadResult> {
    use crate::archive::{create_zip_archive, generate_archive_name, needs_archiving};

    if file_paths.is_empty() {
        return Err(ClientError::Validation("No files selected".to_string()));
    }

    // If this is one file and not a directory, use regular upload
    if file_paths.len() == 1 && !needs_archiving(&file_paths) {
        // If custom_name exists, use upload_bytes
        if let Some(name) = custom_name {
            let path = Path::new(&file_paths[0]);
            let data = tokio::fs::read(path).await?;
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            return upload_bytes_internal(app, state, data, name, mime).await;
        }
        return upload_file(app, state, file_paths[0].clone()).await;
    }

    // Archiving is needed
    let archive_name = custom_name.unwrap_or_else(|| generate_archive_name(&file_paths));
    let archive_name = if !archive_name.ends_with(".zip") {
        format!("{}.zip", archive_name)
    } else {
        archive_name
    };

    tracing::info!(
        "Creating ZIP archive: {} from {} files",
        archive_name,
        file_paths.len()
    );

    // Create an archive
    let zip_data =
        create_zip_archive(&file_paths, &archive_name).map_err(ClientError::Validation)?;

    tracing::info!("ZIP archive created: {} bytes", zip_data.len());

    // Upload the archive
    upload_bytes_internal(
        app,
        state,
        zip_data,
        archive_name,
        "application/zip".to_string(),
    )
    .await
}

/// Internal function for uploading bytes
async fn upload_bytes_internal(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    data: Vec<u8>,
    filename: String,
    mime_type: String,
) -> Result<UploadResult> {
    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    if !state.has_keypair().await {
        return Err(ClientError::Auth(
            "Vaulted wallet is locked. Create or restore it from seed phrase first.".to_string(),
        ));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());
    let file_size = data.len() as u64;

    if file_size > state.config.max_file_size {
        return Err(ClientError::FileTooLarge {
            size: file_size,
            max: state.config.max_file_size,
        });
    }

    let mut progress = ProgressEvent::new(&filename, "upload");
    progress.bytes_total = file_size;
    progress.emit(&app);

    tracing::info!(
        "Uploading encrypted in-memory payload ({} bytes)",
        file_size
    );

    // Phase 1: Encryption (0-30%)
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting data...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(&data, &filename, &mime_type, &public_key)?;
    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.progress = 100;
    progress.message = "Data encrypted".to_string();
    progress.emit(&app);

    tracing::info!("Data encrypted: {} bytes", encrypted_bytes.len());

    // Phase 2: Vault creation and NFT minting (30-60%)
    progress.stage = "minting".to_string();
    progress.progress = 0;
    progress.message = "Preparing encrypted vault...".to_string();
    progress.total_progress = 35;
    progress.emit(&app);

    let encrypted_hash = format!("blake3:{}", &encrypted.encrypted_hash[..13]);
    let fragment = VaultFragment {
        index: 0,
        storage_node_id: String::new(), // Filled by Oracle
        storage_key: String::new(),     // Filled by Oracle
        encrypted_hash: encrypted_hash.clone(),
        size: encrypted_bytes.len() as u64,
    };

    let manifest = VaultManifest {
        encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type.clone(),
        original_hash: encrypted.manifest.original_hash.clone(),
        fragments: vec![fragment],
    };

    let metadata_hash = encrypted.manifest.compute_hash();

    let create_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash: metadata_hash.clone(),
        manifest,
    };

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    progress.total_progress = 50;
    progress.message = "Preparing vault registry entry...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&create_request).await?;

    progress.total_progress = 60;
    progress.message = "Vault prepared for local mint".to_string();
    progress.emit(&app);

    tracing::info!(
        "Vault prepared. Pending upload key: {}",
        vault_response.nft_token_id
    );

    // Phase 3: Upload through Oracle proxy (60-95%)
    progress.stage = "uploading".to_string();
    progress.progress = 0;
    progress.message = "Uploading encrypted data...".to_string();
    progress.total_progress = 65;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url, vault_response.nft_token_id
    );

    tracing::info!("Uploading encrypted payload through Oracle proxy");

    let response = state
        .create_authed_client()
        .await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes.clone())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload data: {} - {}",
            status, error_text
        )));
    }

    let _upload_result: serde_json::Value = response.json().await?;
    tracing::info!("Encrypted payload upload completed");

    progress.total_progress = 95;
    progress.progress = 100;
    progress.bytes_processed = encrypted_bytes.len() as u64;
    progress.message = "Upload complete".to_string();
    progress.emit(&app);

    // Final progress
    progress.stage = "complete".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.message = "Upload complete!".to_string();
    progress.emit(&app);

    Ok(UploadResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        signing_request_uri: vault_response.signing_request_uri,
        nft_uri: vault_response.nft_uri,
        manifest_hash: metadata_hash,
        filename,
        file_size,
        fragments_count: 1,
    })
}

/// Encrypts a file and returns encrypted data (without uploading)
#[tauri::command]
pub async fn encrypt_file(
    state: State<'_, Arc<AppState>>,
    file_path: String,
) -> Result<EncryptedFileInfo> {
    let _session = state.get_session().await?;

    if !state.has_keypair().await {
        return Err(ClientError::Auth(
            "PRE keys not initialized. Please sign in again.".to_string(),
        ));
    }

    let public_key = state.get_public_key().await?;

    let path = Path::new(&file_path);
    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_file(path, &public_key).await?;
    let metadata_hash = encrypted.manifest.compute_hash();

    Ok(EncryptedFileInfo {
        filename: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string(),
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type,
        original_hash: encrypted.manifest.original_hash,
        fragments_count: 1,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash,
    })
}

#[derive(Debug, Serialize)]
pub struct EncryptedFileInfo {
    pub filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub original_hash: String,
    pub fragments_count: u32,
    pub encrypted_aes_key: String,
    pub metadata_hash: String,
}

#[tauri::command]
pub async fn encrypt_bytes(
    state: State<'_, Arc<AppState>>,
    data: Vec<u8>,
    filename: String,
    mime_type: String,
) -> Result<EncryptedFileInfo> {
    let _session = state.get_session().await?;

    if !state.has_keypair().await {
        return Err(ClientError::Auth(
            "PRE keys not initialized. Please sign in again.".to_string(),
        ));
    }

    let public_key = state.get_public_key().await?;

    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(&data, &filename, &mime_type, &public_key)?;
    let metadata_hash = encrypted.manifest.compute_hash();

    Ok(EncryptedFileInfo {
        filename,
        original_size: encrypted.manifest.original_size,
        mime_type: encrypted.manifest.mime_type,
        original_hash: encrypted.manifest.original_hash,
        fragments_count: 1,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash,
    })
}

// ==================== NFT & Files Commands ====================

#[tauri::command]
pub async fn get_xrp_balance(state: State<'_, Arc<AppState>>) -> Result<String> {
    let overview = get_wallet_overview(state).await?;
    Ok(overview.balance_xrp.unwrap_or_else(|| "0".to_string()))
}

/// Decrypts the file name from encrypted_filename
async fn decrypt_filename(
    state: &State<'_, Arc<AppState>>,
    encrypted_aes_key: &str,
    encrypted_filename: &str,
    is_re_encrypted: bool,
) -> Result<String> {
    let keypair = state.get_keypair().await?;

    // Decrypt the AES key
    let aes_key_bytes = if is_re_encrypted {
        let re_encrypted_data =
            xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state
            .pre()
            .decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        let encrypted_pre_data =
            xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;

    // Decrypt the file name
    let decrypted_bytes = aes_key
        .decrypt_from_base64(encrypted_filename)
        .map_err(ClientError::Crypto)?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| ClientError::Config(format!("Invalid filename UTF-8: {}", e)))
}

#[tauri::command]
pub async fn list_my_nfts(state: State<'_, Arc<AppState>>) -> Result<Vec<NftInfo>> {
    let session = state.get_session().await?;

    let http_url = state
        .config
        .xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");

    let client = state.create_authed_client().await;
    let response = client
        .post(&http_url)
        .json(&serde_json::json!({
            "method": "account_nfts",
            "params": [{
                "account": session.wallet_address,
                "ledger_index": "validated"
            }]
        }))
        .send()
        .await?;

    let data: serde_json::Value = response.json().await?;

    let nfts = data
        .get("result")
        .and_then(|r| r.get("account_nfts"))
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();

    // Collect basic NFT information
    // Filter only NFTs from our project (URI: vaulted:// or .../nft/.../metadata.json)
    let mut nft_infos: Vec<NftInfo> = nfts
        .into_iter()
        .filter_map(|nft| {
            let nft_token_id = nft.get("NFTokenID")?.as_str()?.to_string();
            let uri_hex = nft.get("URI").and_then(|u| u.as_str()).unwrap_or("");
            let uri = if !uri_hex.is_empty() {
                hex::decode(uri_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| uri_hex.to_string())
            } else {
                String::new()
            };

            // Show only NFTs from our project
            let is_vault_nft = uri.starts_with("vaulted://")
                || (uri.contains("/nft/") && uri.contains("/metadata.json"));
            if !is_vault_nft {
                return None;
            }

            Some(NftInfo {
                nft_token_id,
                uri,
                filename: None,
                created_at: None,
                file_status: "unknown".to_string(),
            })
        })
        .collect();

    // Request and decrypt filename from Oracle for each NFT
    let oracle_url = &state.config.oracle_url;
    let has_keypair = state.has_keypair().await;

    // Parallel fetch: all /files/*/access requests at once instead of sequential
    let futures: Vec<_> = nft_infos
        .iter()
        .map(|nft| {
            let url = format!("{}/api/v1/files/{}/access", oracle_url, nft.nft_token_id);
            let client = client.clone();
            async move {
                match client.get(&url).send().await {
                    Ok(resp) => match file_access_status_from_http_status(resp.status()) {
                        Some("available") => resp
                            .json::<serde_json::Value>()
                            .await
                            .ok()
                            .map(|data| ("available".to_string(), data)),
                        Some(status_enum) => {
                            tracing::info!(
                                nft_token_id = %nft.nft_token_id,
                                uri_len = nft.uri.len(),
                                http_status = resp.status().as_u16(),
                                lookup_key_type = "nft_token_id",
                                status_enum,
                                "On-chain Vaulted NFT has no Oracle file access record yet"
                            );
                            Some((status_enum.to_string(), serde_json::Value::Null))
                        },
                        None => None,
                    },
                    _ => None,
                }
            }
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;

    for (nft, result) in nft_infos.iter_mut().zip(results) {
        match result {
            Some((status, data)) if status == "available" => {
                nft.file_status = "available".to_string();
                if let Some(created) = data["created_at"].as_str() {
                    nft.created_at = Some(created.to_string());
                }
                let encrypted_filename = data["manifest"]["encrypted_filename"]
                    .as_str()
                    .unwrap_or("");
                let encrypted_aes_key = data["encrypted_aes_key"].as_str().unwrap_or("");
                let is_re_encrypted = data["is_re_encrypted"].as_bool().unwrap_or(false);

                if has_keypair && !encrypted_filename.is_empty() && !encrypted_aes_key.is_empty() {
                    if let Ok(decrypted_name) = decrypt_filename(
                        &state,
                        encrypted_aes_key,
                        encrypted_filename,
                        is_re_encrypted,
                    )
                    .await
                    {
                        nft.filename = Some(decrypted_name);
                    } else {
                        nft.filename = Some(format!("Vault #{}", &nft.nft_token_id[..8]));
                    }
                } else {
                    nft.filename = Some(format!("Vault #{}", &nft.nft_token_id[..8]));
                }
            },
            Some((status, _)) if status == "unavailable" => {
                nft.file_status = "unavailable".to_string();
                nft.filename = Some(format!("Vault #{}", &nft.nft_token_id[..8]));
            },
            _ => {
                nft.file_status = "unknown".to_string();
            },
        }
    }

    tracing::info!(
        "Found {} NFTs for {}",
        nft_infos.len(),
        session.wallet_address
    );
    Ok(nft_infos)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NftInfo {
    pub nft_token_id: String,
    pub uri: String,
    pub filename: Option<String>,
    pub created_at: Option<String>,
    pub file_status: String, // "available" | "unavailable" | "deleted" | "unknown"
}

fn file_access_status_from_http_status(status: reqwest::StatusCode) -> Option<&'static str> {
    if status.is_success() {
        Some("available")
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Some("unavailable")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_auth_lifecycle_status, ensure_recoverable_mint_status,
        file_access_status_from_http_status, generate_create_wallet_mnemonic,
        local_identity_matches_approved, owner_download_error_for_status, parse_destination_tag,
        parse_wallet_transaction_history, parse_xrp_amount_to_drops,
        resolve_pre_submit_offer_lookup, set_vaulted_session, validate_create_wallet_word_count,
        validate_spendable_balance, PreSubmitOfferLookupOutcome,
    };
    use crate::error::{ClientError, Result};
    use crate::state::{AppConfig, AppState};
    use std::time::Duration;
    use xrpl_vault_crypto_core::{SeedManager, DEFAULT_MNEMONIC_WORDS};

    #[test]
    fn file_access_404_maps_to_unavailable_not_deleted() {
        assert_eq!(
            file_access_status_from_http_status(reqwest::StatusCode::NOT_FOUND),
            Some("unavailable")
        );
    }

    #[test]
    fn file_access_success_maps_to_available() {
        assert_eq!(
            file_access_status_from_http_status(reqwest::StatusCode::OK),
            Some("available")
        );
    }

    #[test]
    fn file_access_transient_failures_do_not_claim_deleted() {
        assert_eq!(
            file_access_status_from_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            None
        );
        assert_ne!(
            file_access_status_from_http_status(reqwest::StatusCode::NOT_FOUND),
            Some("deleted")
        );
    }

    #[test]
    fn qr_login_local_decrypt_available_when_identity_matches() {
        assert!(local_identity_matches_approved(
            Some("abc123"),
            Some("ABC123")
        ));
    }

    #[test]
    fn qr_login_local_decrypt_unavailable_when_identity_differs() {
        assert!(!local_identity_matches_approved(
            Some("local_identity"),
            Some("approved_identity")
        ));
    }

    #[test]
    fn qr_login_local_decrypt_unavailable_when_approved_identity_missing() {
        assert!(!local_identity_matches_approved(
            Some("local_identity"),
            None
        ));
        assert!(!local_identity_matches_approved(
            None,
            Some("approved_identity")
        ));
        assert!(!local_identity_matches_approved(None, None));
    }

    #[test]
    fn owner_download_status_errors_are_safe_and_actionable() {
        assert!(
            owner_download_error_for_status(reqwest::StatusCode::UNAUTHORIZED)
                .contains("Authorization")
        );
        assert!(
            owner_download_error_for_status(reqwest::StatusCode::FORBIDDEN)
                .contains("Authorization")
        );
        assert!(
            owner_download_error_for_status(reqwest::StatusCode::NOT_FOUND).contains("metadata")
        );
        assert!(
            owner_download_error_for_status(reqwest::StatusCode::SERVICE_UNAVAILABLE)
                .contains("storage")
        );
    }

    #[test]
    fn owner_download_status_errors_do_not_include_secret_terms() {
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let message = owner_download_error_for_status(status);
            assert!(!message.contains("token"));
            assert!(!message.contains("key"));
            assert!(!message.contains("url"));
        }
    }

    #[test]
    fn pending_mint_recovery_accepts_pending_or_active_status() {
        assert!(ensure_recoverable_mint_status("pending_claim").is_ok());
        assert!(ensure_recoverable_mint_status("active").is_ok());
    }

    #[test]
    fn pending_mint_recovery_rejects_nonrecoverable_status() {
        let err = ensure_recoverable_mint_status("burned").unwrap_err();
        assert!(err
            .to_string()
            .contains("Vault mint recovery is not available for status burned"));
    }

    #[test]
    fn create_wallet_mnemonic_generation_returns_12_words() {
        let mnemonic = generate_create_wallet_mnemonic(None).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), DEFAULT_MNEMONIC_WORDS);
        SeedManager::validate_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn create_wallet_word_count_rejects_non_12_word_requests() {
        assert_eq!(
            validate_create_wallet_word_count(Some(DEFAULT_MNEMONIC_WORDS)).unwrap(),
            DEFAULT_MNEMONIC_WORDS
        );
        assert!(validate_create_wallet_word_count(None).is_ok());
        assert!(validate_create_wallet_word_count(Some(24)).is_err());
    }

    #[tokio::test]
    async fn pre_submit_lookup_found_existing_offer() {
        let outcome = resolve_pre_submit_offer_lookup(
            async { Ok(Some("REUSE1234".to_string())) },
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(
            outcome,
            PreSubmitOfferLookupOutcome::Found("REUSE1234".to_string())
        );
    }

    #[tokio::test]
    async fn pre_submit_lookup_returns_none_and_flow_continues_to_create_offer() {
        let outcome =
            resolve_pre_submit_offer_lookup(async { Ok(None) }, Duration::from_secs(1)).await;

        assert_eq!(outcome, PreSubmitOfferLookupOutcome::None);
    }

    #[tokio::test]
    async fn pre_submit_lookup_errors_and_flow_continues_to_create_offer() {
        let outcome = resolve_pre_submit_offer_lookup(
            async { Err::<Option<String>, _>(ClientError::Xrpl("lookup failed".to_string())) },
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, PreSubmitOfferLookupOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn pre_submit_lookup_timeout_and_flow_continues_to_create_offer() {
        let outcome = resolve_pre_submit_offer_lookup(
            async { std::future::pending::<Result<Option<String>>>().await },
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(outcome, PreSubmitOfferLookupOutcome::Timeout);
    }

    #[test]
    fn parses_xrp_amount_to_drops() {
        assert_eq!(parse_xrp_amount_to_drops("1").unwrap(), 1_000_000);
        assert_eq!(parse_xrp_amount_to_drops("0.000001").unwrap(), 1);
        assert_eq!(parse_xrp_amount_to_drops("12.3456").unwrap(), 12_345_600);
    }

    #[test]
    fn xrp_amount_parser_rejects_invalid_values() {
        for value in [
            "",
            "0",
            "0.000000",
            "-1",
            "+1",
            "abc",
            "1.2.3",
            "NaN",
            "inf",
            "1.0000001",
            "18446744073709551616",
        ] {
            assert!(parse_xrp_amount_to_drops(value).is_err(), "{value}");
        }
    }

    #[test]
    fn spendable_balance_validation_accounts_for_reserve_and_fee() {
        assert!(validate_spendable_balance(20_000_012, 10_000_000, 12, 10_000_000).is_ok());
        assert!(validate_spendable_balance(20_000_011, 10_000_000, 12, 10_000_000).is_err());
        assert!(validate_spendable_balance(9_999_999, 10_000_000, 12, 1).is_err());
    }

    #[test]
    fn destination_tag_validation_rejects_invalid_values() {
        assert_eq!(parse_destination_tag(None).unwrap(), None);
        assert_eq!(parse_destination_tag(Some("")).unwrap(), None);
        assert_eq!(parse_destination_tag(Some("0")).unwrap(), Some(0));
        assert_eq!(
            parse_destination_tag(Some("4294967295")).unwrap(),
            Some(u32::MAX)
        );

        for value in ["-1", "+1", "1.5", "abc", "4294967296"] {
            assert!(parse_destination_tag(Some(value)).is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn auth_lifecycle_status_reports_locked_and_unlocked_without_secrets() {
        let state = AppState::new(AppConfig::default()).unwrap();

        let locked = build_auth_lifecycle_status(&state).await.unwrap();
        assert_eq!(locked.auth_state, "locked");
        assert!(locked.locked);
        assert!(!locked.session_exists);
        assert!(!locked.identity_exists);
        assert!(!locked.wallet_exists);

        let mnemonic = generate_create_wallet_mnemonic(None).unwrap();
        state
            .init_vaulted_identity_from_mnemonic(&mnemonic, None)
            .await
            .unwrap();
        set_vaulted_session(&state).await.unwrap();

        let unlocked = build_auth_lifecycle_status(&state).await.unwrap();
        assert_eq!(unlocked.auth_state, "unlocked");
        assert!(!unlocked.locked);
        assert!(unlocked.session_exists);
        assert!(unlocked.identity_exists);
        assert!(unlocked.wallet_exists);

        state.clear_session().await;
        let relocked = build_auth_lifecycle_status(&state).await.unwrap();
        assert_eq!(relocked.auth_state, "locked");
        assert!(relocked.locked);
        assert!(!relocked.session_exists);
        assert!(!relocked.identity_exists);
        assert!(!relocked.wallet_exists);
    }

    #[test]
    fn wallet_history_parses_compact_payment_rows() {
        let account = "rSender";
        let data = serde_json::json!({
            "result": {
                "transactions": [
                    {
                        "tx_json": {
                            "TransactionType": "Payment",
                            "Account": "rSender",
                            "Destination": "rReceiver",
                            "Amount": "1250000",
                            "hash": "ABC123",
                            "date": 783839401
                        },
                        "meta": { "TransactionResult": "tesSUCCESS" },
                        "ledger_index": 123
                    },
                    {
                        "tx": {
                            "TransactionType": "Payment",
                            "Account": "rOther",
                            "Destination": "rSender",
                            "Amount": "2000000"
                        },
                        "hash": "DEF456",
                        "metaData": { "TransactionResult": "tesSUCCESS" },
                        "close_time_iso": "2026-05-25T00:00:00Z",
                        "ledger_index": 124
                    }
                ]
            }
        });

        let rows = parse_wallet_transaction_history(account, &data);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].tx_hash, "ABC123");
        assert_eq!(rows[0].transaction_type, "Payment");
        assert_eq!(rows[0].direction.as_deref(), Some("sent"));
        assert_eq!(rows[0].amount_xrp.as_deref(), Some("1.25"));
        assert_eq!(rows[0].counterparty.as_deref(), Some("rReceiver"));
        assert_eq!(rows[0].ledger_index, Some(123));
        assert_eq!(rows[0].status, "tesSUCCESS");

        assert_eq!(rows[1].tx_hash, "DEF456");
        assert_eq!(rows[1].direction.as_deref(), Some("received"));
        assert_eq!(rows[1].amount_xrp.as_deref(), Some("2"));
        assert_eq!(rows[1].counterparty.as_deref(), Some("rOther"));
        assert_eq!(rows[1].date.as_deref(), Some("2026-05-25T00:00:00Z"));
    }

    #[test]
    fn wallet_history_omits_unparseable_or_hashless_entries() {
        let data = serde_json::json!({
            "result": {
                "transactions": [
                    { "tx_json": { "TransactionType": "Payment", "Account": "rA" } },
                    { "tx_json": { "TransactionType": "NFTokenMint", "hash": "NFT123" } }
                ]
            }
        });

        let rows = parse_wallet_transaction_history("rA", &data);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tx_hash, "NFT123");
        assert_eq!(rows[0].transaction_type, "NFTokenMint");
        assert!(rows[0].amount_xrp.is_none());
        assert!(rows[0].direction.is_none());
    }
}

#[tauri::command]
pub async fn get_my_nfts(state: State<'_, Arc<AppState>>) -> Result<Vec<NftInfo>> {
    list_my_nfts(state).await
}

#[tauri::command]
pub async fn get_my_files(state: State<'_, Arc<AppState>>) -> Result<Vec<FileInfo>> {
    let _session = state.get_session().await?;
    Ok(vec![])
}

#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub nft_token_id: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
    pub uploaded_at: String,
}

#[tauri::command]
pub async fn download_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    output_path: String,
) -> Result<String> {
    let _session = state.get_session().await?;
    tracing::info!(
        command = "download_file",
        phase = "begin",
        nft_token_id = %nft_token_id,
        "owner_download"
    );

    // Initialize progress
    let mut progress = ProgressEvent::new(&nft_token_id, "download");
    progress.emit(&app);

    let client = state.create_authed_client().await;

    // Get file metadata
    let oracle_url = format!(
        "{}/api/v1/files/{}/access",
        state.config.oracle_url, nft_token_id
    );

    progress.stage = "fetching".to_string();
    progress.message = "Fetching file metadata...".to_string();
    progress.total_progress = 5;
    progress.emit(&app);

    let access_response = client.get(&oracle_url).send().await?;
    if !access_response.status().is_success() {
        let status = access_response.status();
        tracing::warn!(
            command = "download_file",
            phase = "access_metadata_error",
            nft_token_id = %nft_token_id,
            endpoint_status = status.as_u16(),
            "owner_download"
        );
        return Err(ClientError::Oracle(
            owner_download_error_for_status(status).to_string(),
        ));
    }

    let file_info: serde_json::Value = access_response.json().await?;

    tracing::debug!(
        command = "download_file",
        phase = "access_metadata_ok",
        nft_token_id = %nft_token_id,
        "owner_download"
    );

    let encrypted_aes_key = file_info["encrypted_aes_key"]
        .as_str()
        .ok_or_else(|| ClientError::Oracle("Missing encrypted_aes_key".into()))?;

    // Check whether the key was re-encrypted (after transfer)
    let is_re_encrypted = file_info["is_re_encrypted"].as_bool().unwrap_or(false);

    let original_size = file_info["manifest"]["original_size"].as_u64().unwrap_or(0);

    progress.bytes_total = original_size;

    tracing::info!(
        command = "download_file",
        phase = "access_ready",
        nft_token_id = %nft_token_id,
        is_re_encrypted,
        bytes_total = original_size,
        "owner_download"
    );

    // Phase: Download through Oracle proxy (10-70%)
    progress.stage = "downloading".to_string();
    progress.message = "Downloading encrypted data...".to_string();
    progress.total_progress = 10;
    progress.emit(&app);

    // Use the new Oracle proxy endpoint
    let download_url = format!(
        "{}/api/v1/files/{}/download",
        state.config.oracle_url, nft_token_id
    );

    tracing::debug!(
        command = "download_file",
        phase = "proxy_request",
        nft_token_id = %nft_token_id,
        "owner_download"
    );

    let response = client.get(&download_url).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(
            command = "download_file",
            phase = "proxy_download_error",
            nft_token_id = %nft_token_id,
            endpoint_status = status.as_u16(),
            "owner_download"
        );
        return Err(ClientError::Oracle(
            owner_download_error_for_status(status).to_string(),
        ));
    }

    let encrypted_data = response.bytes().await?.to_vec();

    progress.bytes_processed = encrypted_data.len() as u64;
    progress.total_progress = 70;
    progress.message = "Download complete".to_string();
    progress.emit(&app);

    tracing::info!(
        command = "download_file",
        phase = "proxy_download_ok",
        nft_token_id = %nft_token_id,
        bytes_processed = encrypted_data.len(),
        "owner_download"
    );

    // Phase: Decryption (70-95%)
    progress.stage = "decrypting".to_string();
    progress.message = "Decrypting file...".to_string();
    progress.total_progress = 75;
    progress.progress = 0;
    progress.emit(&app);

    let keypair = state.get_keypair().await?;

    // Decrypt the AES key depending on the data type
    let aes_key_bytes = if is_re_encrypted {
        // After transfer - key is in ReEncryptedData format
        tracing::info!(
            command = "download_file",
            phase = "unwrap_transferred_key",
            nft_token_id = %nft_token_id,
            "owner_download"
        );
        progress.message = "Decrypting transferred key...".to_string();
        progress.emit(&app);

        let re_encrypted_data =
            xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state
            .pre()
            .decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        // Original owner - key is in EncryptedPreData format
        tracing::info!(
            command = "download_file",
            phase = "unwrap_owner_key",
            nft_token_id = %nft_token_id,
            "owner_download"
        );
        let encrypted_pre_data =
            xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;

    tracing::info!(
        command = "download_file",
        phase = "content_key_unwrapped",
        nft_token_id = %nft_token_id,
        "owner_download"
    );

    progress.message = "Decrypting file content...".to_string();
    progress.total_progress = 85;
    progress.emit(&app);

    let encrypted_fragment = xrpl_vault_crypto_core::EncryptedData::from_bytes(&encrypted_data)?;
    let decrypted_data = aes_key.decrypt(&encrypted_fragment)?;

    tracing::info!(
        command = "download_file",
        phase = "payload_decrypted",
        nft_token_id = %nft_token_id,
        bytes_processed = decrypted_data.len(),
        "owner_download"
    );

    // Phase: Saving (95-100%)
    progress.stage = "saving".to_string();
    progress.message = "Saving file...".to_string();
    progress.total_progress = 95;
    progress.emit(&app);

    std::fs::write(&output_path, &decrypted_data)
        .map_err(|e| ClientError::Config(format!("Failed to write file: {}", e)))?;

    // Final progress
    progress.stage = "complete".to_string();
    progress.message = "Download complete!".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.bytes_processed = decrypted_data.len() as u64;
    progress.emit(&app);

    tracing::info!(
        command = "download_file",
        phase = "complete",
        nft_token_id = %nft_token_id,
        bytes_processed = decrypted_data.len(),
        "owner_download"
    );

    Ok(output_path)
}

fn owner_download_error_for_status(status: reqwest::StatusCode) -> &'static str {
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            "Authorization or session problem while downloading this file. Sign in and verify ownership, then try again."
        },
        reqwest::StatusCode::NOT_FOUND => {
            "File or storage metadata is unavailable for this NFT. Confirm the vault object is active and try again."
        },
        reqwest::StatusCode::BAD_GATEWAY
        | reqwest::StatusCode::SERVICE_UNAVAILABLE
        | reqwest::StatusCode::GATEWAY_TIMEOUT
        | reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
            "Encrypted storage is temporarily unavailable. Try downloading again later."
        },
        _ => "File download failed. Check the vault status and try again.",
    }
}

#[tauri::command]
pub async fn request_file_access(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<FileAccessInfo> {
    let _session = state.get_session().await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let access = oracle.request_file_access(&nft_token_id).await?;

    // Decrypt the file name before move
    let filename = decrypt_filename(
        &state,
        &access.encrypted_aes_key,
        &access.manifest.encrypted_filename,
        access.is_re_encrypted,
    )
    .await
    .unwrap_or_else(|_| format!("Vault #{}", &nft_token_id[..8]));

    Ok(FileAccessInfo {
        nft_token_id: access.nft_token_id,
        encrypted_aes_key: access.encrypted_aes_key,
        is_re_encrypted: access.is_re_encrypted,
        filename,
        size: access.manifest.original_size,
        fragments_count: 1,
    })
}

#[derive(Debug, Serialize)]
pub struct FileAccessInfo {
    pub nft_token_id: String,
    pub encrypted_aes_key: String,
    pub is_re_encrypted: bool,
    pub filename: String,
    pub size: u64,
    pub fragments_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingGrantInfo {
    pub grant_id: String,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: serde_json::Value,
    pub expires_at: Option<String>,
    pub status: String,
    pub nft_token_id: Option<String>,
    pub manifest_hash: Option<String>,
    pub can_decrypt_key: bool,
    pub key_envelope_alg: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingGrantInfo {
    pub grant_id: String,
    pub vault_object_id: String,
    pub recipient_identity_id: String,
    pub permissions: serde_json::Value,
    pub expires_at: Option<String>,
    pub status: String,
    pub nft_token_id: Option<String>,
    pub manifest_hash: Option<String>,
}

fn open_grant_file_key(
    identity: &xrpl_vault_crypto_core::VaultedIdentityKeys,
    grant: &GrantResponse,
) -> Result<Vec<u8>> {
    if grant.recipient_identity_id != identity.identity_id_hex() {
        return Err(ClientError::Auth(
            "Grant is not addressed to this Vaulted identity".into(),
        ));
    }

    let envelope: KeyEnvelope = serde_json::from_value(grant.key_envelope.clone())
        .map_err(|e| ClientError::Config(format!("Invalid grant key envelope: {e}")))?;
    if envelope.recipient_identity_id != grant.recipient_identity_id {
        return Err(ClientError::Auth(
            "Grant key envelope recipient mismatch".into(),
        ));
    }

    let aad = grant_envelope_aad(&grant.vault_object_id, &grant.recipient_identity_id);
    open_key_envelope(
        &envelope,
        &identity.encryption_private_key(),
        aad.as_bytes(),
    )
    .map_err(Into::into)
}

fn decrypt_filename_with_file_key(file_key: &[u8], encrypted_filename: &str) -> Result<String> {
    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(file_key)?;
    let decrypted = aes_key
        .decrypt_from_base64(encrypted_filename)
        .map_err(ClientError::Crypto)?;
    String::from_utf8(decrypted)
        .map_err(|e| ClientError::Config(format!("Invalid filename UTF-8: {e}")))
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_outgoing_vaulted_grants(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<OutgoingGrantInfo>> {
    let identity = state.get_vaulted_identity().await?;
    let owner_identity_id = identity.identity_id_hex();
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let grants = oracle.outgoing_grants(&owner_identity_id).await?;

    let mut result = Vec::with_capacity(grants.len());
    for grant in grants {
        let vault = oracle.get_vault_object(&grant.vault_object_id).await.ok();
        result.push(OutgoingGrantInfo {
            grant_id: grant.id,
            vault_object_id: grant.vault_object_id,
            recipient_identity_id: grant.recipient_identity_id,
            permissions: grant.permissions,
            expires_at: grant.expires_at,
            status: grant.status,
            nft_token_id: vault.as_ref().and_then(|v| v.nft_token_id.clone()),
            manifest_hash: vault.map(|v| v.manifest_hash),
        });
    }
    Ok(result)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn revoke_vaulted_grant(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
) -> Result<OutgoingGrantInfo> {
    let identity = state.get_vaulted_identity().await?;
    let owner_identity_id = identity.identity_id_hex();
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let grant = oracle.revoke_grant(&grant_id, &owner_identity_id).await?;
    let vault = oracle.get_vault_object(&grant.vault_object_id).await.ok();
    Ok(OutgoingGrantInfo {
        grant_id: grant.id,
        vault_object_id: grant.vault_object_id,
        recipient_identity_id: grant.recipient_identity_id,
        permissions: grant.permissions,
        expires_at: grant.expires_at,
        status: grant.status,
        nft_token_id: vault.as_ref().and_then(|v| v.nft_token_id.clone()),
        manifest_hash: vault.map(|v| v.manifest_hash),
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_incoming_vaulted_grants(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<IncomingGrantInfo>> {
    let identity = state.get_vaulted_identity().await?;
    let identity_id = identity.identity_id_hex();
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let grants = oracle.incoming_grants(&identity_id).await?;

    let mut result = Vec::with_capacity(grants.len());
    for grant in grants {
        let can_decrypt_key = open_grant_file_key(&identity, &grant).is_ok();
        let key_envelope_alg = grant
            .key_envelope
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let vault = oracle.get_vault_object(&grant.vault_object_id).await.ok();
        result.push(IncomingGrantInfo {
            grant_id: grant.id,
            vault_object_id: grant.vault_object_id,
            recipient_identity_id: grant.recipient_identity_id,
            permissions: grant.permissions,
            expires_at: grant.expires_at,
            status: grant.status,
            nft_token_id: vault.as_ref().and_then(|v| v.nft_token_id.clone()),
            manifest_hash: vault.map(|v| v.manifest_hash),
            can_decrypt_key,
            key_envelope_alg,
        });
    }
    Ok(result)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn download_incoming_vaulted_grant(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    grant_id: String,
    output_path: String,
) -> Result<String> {
    let identity = state.get_vaulted_identity().await?;
    let identity_id = identity.identity_id_hex();
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let grants = oracle.incoming_grants(&identity_id).await?;
    let grant = grants
        .into_iter()
        .find(|g| g.id == grant_id)
        .ok_or_else(|| ClientError::Oracle(format!("Incoming grant not found: {grant_id}")))?;
    let file_key = open_grant_file_key(&identity, &grant)?;
    let access = oracle.grant_file_access(&grant_id, &identity_id).await?;

    let mut progress = ProgressEvent::new(&grant_id, "grant-download");
    progress.stage = "downloading".to_string();
    progress.message = "Downloading encrypted grant data...".to_string();
    progress.total_progress = 10;
    progress.bytes_total = access.manifest.original_size;
    progress.emit(&app);

    let client = state.create_authed_client().await;
    let mut fragments = access.fragment_urls;
    fragments.sort_by_key(|f| f.index);
    if fragments.is_empty() {
        return Err(ClientError::Oracle(
            "Grant has no downloadable fragments".into(),
        ));
    }

    let mut encrypted_data = Vec::new();
    for fragment in fragments {
        let response = client.get(&fragment.url).send().await?;
        if !response.status().is_success() {
            return Err(ClientError::Oracle(format!(
                "Failed to download grant fragment {}: {}",
                fragment.index,
                response.status()
            )));
        }
        let bytes = response.bytes().await?;
        encrypted_data.extend_from_slice(&bytes);
        progress.bytes_processed = encrypted_data.len() as u64;
        progress.emit(&app);
    }

    progress.stage = "decrypting".to_string();
    progress.message = "Decrypting file key envelope and content...".to_string();
    progress.total_progress = 75;
    progress.emit(&app);

    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&file_key)?;
    let encrypted_fragment = xrpl_vault_crypto_core::EncryptedData::from_bytes(&encrypted_data)?;
    let decrypted_data = aes_key.decrypt(&encrypted_fragment)?;

    progress.stage = "saving".to_string();
    progress.message = "Saving decrypted grant file...".to_string();
    progress.total_progress = 95;
    progress.emit(&app);

    std::fs::write(&output_path, &decrypted_data)
        .map_err(|e| ClientError::Config(format!("Failed to write grant file: {e}")))?;

    progress.stage = "complete".to_string();
    progress.message = "Grant download complete".to_string();
    progress.progress = 100;
    progress.total_progress = 100;
    progress.bytes_processed = decrypted_data.len() as u64;
    progress.emit(&app);

    Ok(output_path)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn preview_incoming_vaulted_grant(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let identity_id = identity.identity_id_hex();
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let grants = oracle.incoming_grants(&identity_id).await?;
    let grant = grants
        .into_iter()
        .find(|g| g.id == grant_id)
        .ok_or_else(|| ClientError::Oracle(format!("Incoming grant not found: {grant_id}")))?;
    let file_key = open_grant_file_key(&identity, &grant)?;
    let access = oracle.grant_file_access(&grant_id, &identity_id).await?;
    let filename = decrypt_filename_with_file_key(&file_key, &access.manifest.encrypted_filename)
        .unwrap_or_else(|_| format!("Grant #{}", &grant_id[..8.min(grant_id.len())]));
    Ok(serde_json::json!({
        "grantId": grant_id,
        "vaultObjectId": grant.vault_object_id,
        "nftTokenId": access.nft_token_id,
        "filename": filename,
        "size": access.manifest.original_size,
        "mimeType": access.manifest.mime_type,
        "fragmentsCount": access.fragment_urls.len(),
    }))
}

/// Starts a recipient-bound file grant for an owned NFT.
///
/// This is the desktop UX helper for Priority 5 sharing: it resolves the
/// vault_object_id from the NFT token, decrypts the local file key in memory,
/// seals it to the recipient identity key, and requires TOFU/manual trust by
/// default before opening the QR approval request.
#[tauri::command(rename_all = "camelCase")]
pub async fn start_vaulted_file_grant_for_nft(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    recipient_identity_id: String,
    permissions: Option<Vec<String>>,
    grant_expires_at: Option<String>,
    human_summary: Option<String>,
    require_trusted_recipient: Option<bool>,
) -> Result<serde_json::Value> {
    let identity = state.get_vaulted_identity().await?;
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    let access = oracle.request_file_access(&nft_token_id).await?;
    let keypair = state.get_keypair().await?;
    let file_key_bytes = if access.is_re_encrypted {
        let re_encrypted_data =
            xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(&access.encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state
            .pre()
            .decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        let encrypted_pre_data =
            xrpl_vault_crypto_core::EncryptedPreData::from_base64(&access.encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };
    let file_key_base64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &file_key_bytes);

    let vault_object = oracle.get_vault_object_by_nft(&nft_token_id).await?;
    let resolved_permissions = permissions.unwrap_or_else(|| vec!["read".into()]);
    let parsed_expires_at = match grant_expires_at {
        Some(ts) if !ts.trim().is_empty() => Some(
            chrono::DateTime::parse_from_rfc3339(&ts)
                .map_err(|e| ClientError::Config(format!("Invalid grant expiration: {}", e)))?
                .with_timezone(&chrono::Utc),
        ),
        _ => None,
    };

    let recipient_public_key = oracle
        .get_vaulted_identity_public(&recipient_identity_id)
        .await?
        .encryption_public_key;
    if require_trusted_recipient.unwrap_or(true) {
        let fingerprint = encryption_public_key_fingerprint_hex(&recipient_public_key)?;
        let trust = oracle
            .recipient_key_trust_status(
                &identity.identity_id_hex(),
                &recipient_identity_id,
                Some(&fingerprint),
            )
            .await?;
        if !trust.trusted {
            return Err(ClientError::InvalidData(format!(
                "Recipient encryption key is not trusted. Verify fingerprint {} before granting access.",
                format_fingerprint_groups(&fingerprint)
            )));
        }
    }

    let key_envelope = build_recipient_key_envelope(
        &oracle,
        &vault_object.id,
        &recipient_identity_id,
        &access.encrypted_aes_key,
        Some(file_key_base64),
        Some(recipient_public_key),
    )
    .await?;

    let response = oracle
        .start_qr_file_grant_approval(&QrFileGrantStartRequest {
            identity_id: identity.identity_id_hex(),
            vault_object_id: vault_object.id.clone(),
            recipient_identity_id: recipient_identity_id.clone(),
            key_envelope,
            encrypted_file_key: None,
            permissions: resolved_permissions,
            grant_expires_at: parsed_expires_at,
            requester_device_id: Some(state.device_fingerprint().to_string()),
            requester_device_name: hostname::get()
                .ok()
                .map(|h| h.to_string_lossy().to_string()),
            human_summary,
        })
        .await?;

    Ok(serde_json::json!({
        "grantRequestId": response.grant_request_id,
        "grantId": response.grant_id,
        "challenge": response.challenge,
        "oracleUrl": response.oracle_url,
        "expiresAt": response.expires_at,
        "grantContextHash": response.grant_context_hash,
        "vaultObjectId": vault_object.id,
        "recipientIdentityId": recipient_identity_id,
        "qrPayload": response.qr_payload,
    }))
}

// ==================== Transfer Commands ====================

#[tauri::command]
pub async fn create_mint_transaction(_state: State<'_, Arc<AppState>>) -> Result<String> {
    Err(ClientError::Config("Use upload_file instead".to_string()))
}

#[tauri::command]
pub async fn verify_nft_ownership(
    state: State<'_, Arc<AppState>>,
    _nft_token_id: String,
) -> Result<bool> {
    let _session = state.get_session().await?;
    Ok(false)
}

#[tauri::command]
pub async fn generate_transfer_key(
    state: State<'_, Arc<AppState>>,
    recipient_address: String,
) -> Result<TransferKeyInfo> {
    let session = state.get_session().await?;

    let sender_keypair = state.get_keypair().await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let recipient_info = oracle.get_user_public_key(&recipient_address).await?;
    let recipient_public_key =
        xrpl_vault_crypto_core::pre::PrePublicKey::from_hex(&recipient_info.pre_public_key)?;

    let re_key = state
        .pre()
        .generate_re_key(&sender_keypair, &recipient_public_key)?;
    let re_key_base64 = re_key.to_base64_verified(&sender_keypair);

    Ok(TransferKeyInfo {
        re_encryption_key: re_key_base64,
        from_address: session.wallet_address,
        to_address: recipient_address,
    })
}

#[derive(Debug, Serialize)]
pub struct TransferKeyInfo {
    pub re_encryption_key: String,
    pub from_address: String,
    pub to_address: String,
}

#[tauri::command]
pub async fn get_user_public_key(
    state: State<'_, Arc<AppState>>,
    wallet_address: String,
) -> Result<String> {
    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let user_info = oracle.get_user_public_key(&wallet_address).await?;
    Ok(user_info.pre_public_key)
}

#[tauri::command]
pub async fn initiate_transfer(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    to_address: String,
) -> Result<InitiateTransferResult> {
    let session = state.get_session().await?;

    tracing::info!(
        command = "initiate_transfer",
        phase = "begin",
        nft_token_id = %nft_token_id,
        to_address = %to_address,
        "Starting local XRPL NFT transfer flow"
    );

    let transfer_key = generate_transfer_key(state.clone(), to_address.clone()).await?;

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let response = oracle
        .initiate_transfer(
            &nft_token_id,
            &session.wallet_address,
            &to_address,
            &transfer_key.re_encryption_key,
        )
        .await?;

    let offer = create_transfer_offer_inner(
        state.inner(),
        response.transfer_id.clone(),
        nft_token_id.clone(),
        to_address.clone(),
    )
    .await?;

    Ok(InitiateTransferResult {
        transfer_id: response.transfer_id,
        status: offer.status,
        signing_request: None,
        offer_index: Some(offer.offer_index),
        tx_hash: Some(offer.tx_hash),
        engine_result: Some(offer.engine_result),
        engine_result_message: Some(offer.engine_result_message),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateTransferResult {
    pub transfer_id: String,
    pub status: String,
    pub signing_request: Option<crate::auth::VaultedSigningRequest>,
    pub offer_index: Option<String>,
    pub tx_hash: Option<String>,
    pub engine_result: Option<String>,
    pub engine_result_message: Option<String>,
}

#[tauri::command(rename_all = "camelCase")]
pub async fn create_transfer_offer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
    nft_token_id: String,
    to_address: String,
) -> Result<TransferOfferResult> {
    create_transfer_offer_inner(state.inner(), transfer_id, nft_token_id, to_address).await
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_transfer_offer(
    _state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
    _transfer_id: String,
    _nft_token_id: String,
) -> Result<TransferOfferResult> {
    Err(ClientError::Auth("Legacy external-wallet signing is disabled in Vaulted wallet mode; use Vaulted XRPL wallet QR signing/submission flows".to_string()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferOfferResult {
    pub transfer_id: String,
    pub offer_index: String,
    pub tx_hash: String,
    pub engine_result: String,
    pub engine_result_message: String,
    pub status: String,
}

async fn create_transfer_offer_inner(
    state: &Arc<AppState>,
    transfer_id: String,
    nft_token_id: String,
    to_address: String,
) -> Result<TransferOfferResult> {
    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;
    if !is_valid_xrpl_classic_address(&to_address) {
        return Err(ClientError::Validation(
            "Recipient wallet address is not a valid XRPL classic address".to_string(),
        ));
    }

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;

    tracing::info!(
        command = "create_transfer_offer",
        phase = "pre_submit_offer_lookup_started",
        nft_token_id = %nft_token_id,
        transfer_id = %transfer_id,
        "Checking for an existing matching NFTokenOffer before creating a new one"
    );
    match resolve_pre_submit_offer_lookup(
        client.find_matching_nftoken_offer(&account, &nft_token_id, &to_address, "0"),
        Duration::from_secs(6),
    )
    .await
    {
        PreSubmitOfferLookupOutcome::Found(offer_index) => {
            tracing::info!(
                command = "create_transfer_offer",
                phase = "pre_submit_offer_lookup_found",
                nft_token_id = %nft_token_id,
                transfer_id = %transfer_id,
                offer_index = %offer_index,
                "Reusing existing matching NFTokenOffer"
            );
            let status = confirm_transfer_offer_with_oracle(
                state,
                &transfer_id,
                &nft_token_id,
                &offer_index,
            )
            .await?;
            return Ok(TransferOfferResult {
                transfer_id,
                offer_index,
                tx_hash: String::new(),
                engine_result: "tesSUCCESS".to_string(),
                engine_result_message: "Existing matching NFTokenOffer reused".to_string(),
                status,
            });
        },
        PreSubmitOfferLookupOutcome::None => {
            tracing::info!(
                command = "create_transfer_offer",
                phase = "pre_submit_offer_lookup_none",
                nft_token_id = %nft_token_id,
                transfer_id = %transfer_id,
                "No existing matching NFTokenOffer found; creating a new offer"
            );
        },
        PreSubmitOfferLookupOutcome::Failed(error) => {
            tracing::warn!(
                command = "create_transfer_offer",
                phase = "pre_submit_offer_lookup_failed",
                nft_token_id = %nft_token_id,
                transfer_id = %transfer_id,
                error = %error,
                "Existing-offer lookup failed; continuing with new NFTokenCreateOffer"
            );
        },
        PreSubmitOfferLookupOutcome::Timeout => {
            tracing::warn!(
                command = "create_transfer_offer",
                phase = "pre_submit_offer_lookup_timeout",
                nft_token_id = %nft_token_id,
                transfer_id = %transfer_id,
                timeout_ms = 6000_u64,
                "Existing-offer lookup timed out; continuing with new NFTokenCreateOffer"
            );
        },
    }

    let account_info = client.account_info(&account).await?;
    let fee_drops = client.fee_drops().await?;
    let last_ledger_sequence = client.ledger_current_index().await?.saturating_add(20);
    let tx = build_nftoken_create_offer_tx(&account, &nft_token_id, &to_address, "0");
    let tx = add_xrpl_signing_fields(
        tx,
        fee_drops.clone(),
        account_info.sequence,
        last_ledger_sequence,
    );
    let signed = wallet.sign_xrpl_transaction_json(&tx)?;
    let tx_blob = signed.tx_blob.ok_or_else(|| {
        ClientError::Xrpl(
            "Local signing did not produce a signed XRPL transaction payload".to_string(),
        )
    })?;

    tracing::info!(
        command = "create_transfer_offer",
        phase = "submit_started",
        nft_token_id = %nft_token_id,
        transfer_id = %transfer_id,
        fee_drops = %fee_drops,
        "Submitting locally signed NFTokenCreateOffer"
    );
    let submit = client.submit(&tx_blob).await?;
    let accepted = submit.engine_result.starts_with("tes");
    tracing::info!(
        command = "create_transfer_offer",
        phase = "submit_completed",
        nft_token_id = %nft_token_id,
        transfer_id = %transfer_id,
        accepted,
        engine_result = %submit.engine_result,
        engine_result_message = %submit.engine_result_message,
        tx_hash = %submit.tx_hash,
        "NFTokenCreateOffer submit completed"
    );
    if !accepted {
        return Err(ClientError::Xrpl(format!(
            "{}: {}",
            submit.engine_result, submit.engine_result_message
        )));
    }

    let offer_index = client
        .resolve_nftoken_offer_index(&submit.tx_hash, &account, &nft_token_id, &to_address, "0")
        .await?
        .ok_or_else(|| {
            ClientError::Xrpl(
                "Offer was submitted to XRPL, but Vaulted could not resolve the offer index yet. Please refresh or retry confirmation.".to_string(),
            )
        })?;

    let status =
        confirm_transfer_offer_with_oracle(state, &transfer_id, &nft_token_id, &offer_index)
            .await?;

    Ok(TransferOfferResult {
        transfer_id,
        offer_index,
        tx_hash: submit.tx_hash,
        engine_result: submit.engine_result,
        engine_result_message: submit.engine_result_message,
        status,
    })
}

async fn confirm_transfer_offer_with_oracle(
    state: &Arc<AppState>,
    transfer_id: &str,
    nft_token_id: &str,
    offer_index: &str,
) -> Result<String> {
    tracing::info!(
        command = "create_transfer_offer",
        phase = "oracle_confirm_started",
        nft_token_id = %nft_token_id,
        transfer_id = %transfer_id,
        offer_index = %offer_index,
        "Confirming locally submitted NFT transfer offer with Oracle"
    );

    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let confirmation = oracle
        .confirm_transfer_offer_signed(&ConfirmTransferOfferSignedRequest {
            transfer_id: transfer_id.to_string(),
            offer_index: offer_index.to_string(),
        })
        .await?;
    if !confirmation.success {
        return Err(ClientError::Oracle(
            "Oracle did not confirm the NFT transfer offer".to_string(),
        ));
    }

    tracing::info!(
        command = "create_transfer_offer",
        phase = "oracle_confirm_completed",
        nft_token_id = %nft_token_id,
        transfer_id = %transfer_id,
        offer_index = %offer_index,
        status = %confirmation.status,
        "Oracle confirmed locally submitted NFT transfer offer"
    );

    Ok(confirmation.status)
}

#[derive(Debug, PartialEq, Eq)]
enum PreSubmitOfferLookupOutcome {
    Found(String),
    None,
    Failed(String),
    Timeout,
}

async fn resolve_pre_submit_offer_lookup<Fut>(
    lookup: Fut,
    timeout: Duration,
) -> PreSubmitOfferLookupOutcome
where
    Fut: Future<Output = Result<Option<String>>>,
{
    match tokio::time::timeout(timeout, lookup).await {
        Ok(Ok(Some(offer_index))) => PreSubmitOfferLookupOutcome::Found(offer_index),
        Ok(Ok(None)) => PreSubmitOfferLookupOutcome::None,
        Ok(Err(e)) => PreSubmitOfferLookupOutcome::Failed(e.to_string()),
        Err(_) => PreSubmitOfferLookupOutcome::Timeout,
    }
}

#[tauri::command]
pub async fn complete_transfer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
    xrpl_tx_hash: String,
) -> Result<bool> {
    complete_transfer_inner(state.inner(), transfer_id, xrpl_tx_hash).await
}

async fn complete_transfer_inner(
    state: &Arc<AppState>,
    transfer_id: String,
    xrpl_tx_hash: String,
) -> Result<bool> {
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let request = crate::oracle::api::CompleteTransferRequest {
        transfer_id: transfer_id.clone(),
        xrpl_tx_hash,
    };

    let response = oracle.complete_transfer(&request).await?;
    tracing::info!("Transfer completed, new owner: {}", response.new_owner);

    Ok(response.success)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn claim_nft(
    state: State<'_, Arc<AppState>>,
    offer_index: String,
) -> Result<ClaimResult> {
    claim_nft_inner(state.inner(), offer_index).await
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    pub success: bool,
    pub tx_hash: String,
    pub nft_token_id: Option<String>,
    pub transfer_id: Option<String>,
    pub engine_result: String,
    pub engine_result_message: String,
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_claim(
    _state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
    _offer_index: Option<String>,
) -> Result<ClaimResult> {
    Err(ClientError::Auth("Legacy external-wallet signing is disabled in Vaulted wallet mode; use Vaulted XRPL wallet QR signing/submission flows".to_string()))
}

async fn claim_nft_inner(state: &Arc<AppState>, offer_index: String) -> Result<ClaimResult> {
    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;
    let oracle = state.get_oracle_client_with_timeout(120).await?;
    let transfer = oracle.get_transfer_by_offer(&offer_index).await?;

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    let account_info = client.account_info(&account).await?;
    let fee_drops = client.fee_drops().await?;
    let last_ledger_sequence = client.ledger_current_index().await?.saturating_add(20);
    let tx = build_nftoken_accept_offer_tx(&account, &offer_index);
    let tx = add_xrpl_signing_fields(
        tx,
        fee_drops.clone(),
        account_info.sequence,
        last_ledger_sequence,
    );
    let signed = wallet.sign_xrpl_transaction_json(&tx)?;
    let tx_blob = signed.tx_blob.ok_or_else(|| {
        ClientError::Xrpl(
            "Local signing did not produce a signed XRPL transaction payload".to_string(),
        )
    })?;

    tracing::info!(
        command = "claim_nft",
        phase = "submit_started",
        transfer_id = %transfer.transfer_id,
        offer_index = %offer_index,
        fee_drops = %fee_drops,
        "Submitting locally signed NFTokenAcceptOffer"
    );
    let submit = client.submit(&tx_blob).await?;
    let accepted = submit.engine_result.starts_with("tes");
    tracing::info!(
        command = "claim_nft",
        phase = "submit_completed",
        transfer_id = %transfer.transfer_id,
        offer_index = %offer_index,
        accepted,
        engine_result = %submit.engine_result,
        engine_result_message = %submit.engine_result_message,
        tx_hash = %submit.tx_hash,
        "NFTokenAcceptOffer submit completed"
    );
    if !accepted {
        return Err(ClientError::Xrpl(format!(
            "{}: {}",
            submit.engine_result, submit.engine_result_message
        )));
    }

    wait_for_xrpl_tx_validated(&client, &submit.tx_hash, "claim_nft").await?;
    let completed =
        complete_transfer_inner(state, transfer.transfer_id.clone(), submit.tx_hash.clone())
            .await?;

    tracing::info!(
        command = "claim_nft",
        phase = "oracle_completed",
        transfer_id = %transfer.transfer_id,
        offer_index = %offer_index,
        tx_hash = %submit.tx_hash,
        "Oracle completed locally accepted NFT transfer"
    );

    Ok(ClaimResult {
        success: completed,
        tx_hash: submit.tx_hash,
        nft_token_id: None,
        transfer_id: Some(transfer.transfer_id),
        engine_result: submit.engine_result,
        engine_result_message: submit.engine_result_message,
    })
}

async fn wait_for_xrpl_tx_validated(
    client: &XrplClient,
    tx_hash: &str,
    command: &'static str,
) -> Result<()> {
    const MAX_ATTEMPTS: usize = 12;
    const POLL_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

    for attempt in 1..=MAX_ATTEMPTS {
        match client.tx(tx_hash).await {
            Ok(_) => {
                tracing::info!(
                    command,
                    phase = "validated",
                    tx_hash = %tx_hash,
                    "XRPL transaction reached validated lookup"
                );
                return Ok(());
            },
            Err(e) if attempt == MAX_ATTEMPTS => return Err(e),
            Err(_) => tokio::time::sleep(POLL_DELAY).await,
        }
    }

    Err(ClientError::Xrpl(
        "XRPL transaction validation polling exhausted".to_string(),
    ))
}
// ==================== Incoming Offers ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingOffer {
    pub offer_index: String,
    pub nft_token_id: String,
    pub from_address: String,
    pub amount: String,
}

#[tauri::command]
pub async fn get_incoming_offers(state: State<'_, Arc<AppState>>) -> Result<Vec<IncomingOffer>> {
    let session = state.get_session().await?;

    let http_url = state
        .config
        .xrpl_node_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace(":51233", ":51234");

    let client = state.create_authed_client().await;

    // Request pending transfers from Oracle where we are the recipient
    let oracle_url = format!(
        "{}/api/v1/transfers/incoming/{}",
        state.config.oracle_url, session.wallet_address
    );

    let incoming: Vec<IncomingOffer> = match client.get(&oracle_url).send().await {
        Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
        _ => {
            tracing::warn!("Oracle incoming endpoint not available, using fallback");
            vec![]
        },
    };

    // Verify each offer still exists on XRPL — filter out already-claimed ones
    let mut valid_offers = Vec::new();
    for offer in &incoming {
        let check: serde_json::Value = match client
            .post(&http_url)
            .json(&serde_json::json!({
                "method": "ledger_entry",
                "params": [{
                    "index": offer.offer_index,
                    "ledger_index": "validated"
                }]
            }))
            .send()
            .await
        {
            Ok(resp) => resp.json().await.unwrap_or_default(),
            Err(_) => {
                // Can't verify — keep the offer to be safe
                valid_offers.push(offer.clone());
                continue;
            },
        };

        let exists = check.get("result").and_then(|r| r.get("node")).is_some();

        if exists {
            valid_offers.push(offer.clone());
        } else {
            // Offer no longer exists on XRPL — auto-finalize in Oracle
            tracing::info!(
                "Offer {} no longer exists on XRPL, auto-finalizing",
                offer.offer_index
            );
            let finalize_url = format!(
                "{}/api/v1/transfers/finalize-by-offer",
                state.config.oracle_url
            );
            let _ = client
                .post(&finalize_url)
                .json(&serde_json::json!({
                    "offerIndex": offer.offer_index,
                    "xrplTxHash": "auto-finalized-stale-offer"
                }))
                .send()
                .await;
        }
    }

    tracing::info!(
        "Found {} incoming offers for {} ({} verified on XRPL)",
        incoming.len(),
        session.wallet_address,
        valid_offers.len()
    );
    Ok(valid_offers)
}

// ==================== Outgoing Offers ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingOffer {
    pub offer_index: String,
    pub nft_token_id: String,
    pub to_address: String,
    pub filename: String,
    pub status: String,
    pub created_at: String,
}

#[tauri::command]
pub async fn get_outgoing_offers(state: State<'_, Arc<AppState>>) -> Result<Vec<OutgoingOffer>> {
    let session = state.get_session().await?;
    let client = state.create_authed_client().await;

    // Request transfer history from Oracle
    let oracle_url = format!(
        "{}/api/v1/transfers/history/{}",
        state.config.oracle_url, session.wallet_address
    );

    #[derive(Debug, Deserialize)]
    struct TransferHistory {
        sent: Vec<SentTransfer>,
        #[allow(dead_code)]
        received: Vec<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    struct SentTransfer {
        #[serde(default)]
        offer_index: Option<String>,
        nft_token_id: String,
        to_address: String,
        status: String,
        created_at: String,
        #[serde(default)]
        encrypted_filename: Option<String>,
    }

    let outgoing: Vec<OutgoingOffer> = match client.get(&oracle_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(history) = resp.json::<TransferHistory>().await {
                history
                    .sent
                    .into_iter()
                    .map(|t| OutgoingOffer {
                        offer_index: t.offer_index.unwrap_or_default(),
                        nft_token_id: t.nft_token_id,
                        to_address: t.to_address,
                        filename: t
                            .encrypted_filename
                            .unwrap_or_else(|| "Unknown".to_string()),
                        status: t.status,
                        created_at: t.created_at,
                    })
                    .collect()
            } else {
                vec![]
            }
        },
        _ => {
            tracing::warn!("Oracle history endpoint not available");
            vec![]
        },
    };

    tracing::info!(
        "Found {} outgoing offers for {}",
        outgoing.len(),
        session.wallet_address
    );
    Ok(outgoing)
}

// ==================== Transfer History ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistoryItem {
    pub transfer_id: String,
    pub nft_token_id: String,
    pub other_party: String,
    pub direction: String,
    pub status: String,
    pub created_at: String,
    pub filename: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistory {
    pub sent: Vec<TransferHistoryItem>,
    pub received: Vec<TransferHistoryItem>,
}

#[tauri::command]
pub async fn get_transfer_history(state: State<'_, Arc<AppState>>) -> Result<TransferHistory> {
    let session = state.get_session().await?;

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/transfers/history/{}",
        state.config.oracle_url, session.wallet_address
    );

    let history: TransferHistory = client
        .get(&oracle_url)
        .send()
        .await?
        .json()
        .await
        .unwrap_or(TransferHistory {
            sent: vec![],
            received: vec![],
        });

    tracing::info!(
        "Transfer history: {} sent, {} received",
        history.sent.len(),
        history.received.len()
    );

    Ok(history)
}

// ==================== Cancel Transfer ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelTransferResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
}

#[tauri::command]
pub async fn cancel_transfer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
) -> Result<CancelTransferResponse> {
    let session = state.get_session().await?;

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/transfers/{}/cancel",
        state.config.oracle_url, transfer_id
    );

    let response = client
        .post(&oracle_url)
        .json(&serde_json::json!({
            "wallet_address": session.wallet_address
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(crate::error::ClientError::Oracle(format!(
            "Failed to cancel transfer: {}",
            error_text
        )));
    }

    let result: CancelTransferResponse = response.json().await?;

    tracing::info!("Transfer {} cancelled: {}", transfer_id, result.message);

    Ok(result)
}

// ==================== Delete Vault ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteVaultResponse {
    pub success: bool,
    pub overall_status: String,
    pub nft_token_id: String,
    pub message: String,
    pub nft_burned: bool,
    pub burn_tx_hash: Option<String>,
    pub burn_engine_result: Option<String>,
    pub oracle_deleted: bool,
    pub storage_deleted: bool,
    pub deleted_fragments: usize,
    pub total_fragments: Option<usize>,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OracleDeleteVaultResponse {
    pub success: bool,
    pub message: String,
    pub deleted_fragments: usize,
    #[serde(default)]
    pub total_fragments: Option<usize>,
    #[serde(default)]
    pub storage_deleted: bool,
    #[serde(default)]
    pub oracle_deleted: bool,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[tauri::command]
pub async fn delete_vault(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<DeleteVaultResponse> {
    let session = state.get_session().await?;
    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;
    if !account.eq_ignore_ascii_case(&session.wallet_address) {
        return Err(ClientError::Auth(
            "Current session wallet does not match the local Vaulted XRPL wallet".to_string(),
        ));
    }

    let mut xrpl = XrplClient::new(&state.config.xrpl_node_url);
    xrpl.connect().await?;
    match xrpl.verify_nft_owner(&nft_token_id, &account).await {
        Ok(true) => {},
        Ok(false) => {
            return Err(ClientError::Auth(
                "Only the current XRPL NFT owner can delete this vault".to_string(),
            ));
        },
        Err(e) => {
            return Err(ClientError::Xrpl(format!(
                "Could not verify NFT ownership before delete: {}",
                e
            )));
        },
    }

    let account_info = xrpl.account_info(&account).await?;
    let fee_drops = xrpl.fee_drops().await?;
    let last_ledger_sequence = xrpl.ledger_current_index().await?.saturating_add(20);
    let burn_tx = add_xrpl_signing_fields(
        build_nftoken_burn_tx(&account, &nft_token_id),
        fee_drops,
        account_info.sequence,
        last_ledger_sequence,
    );
    let signed = wallet.sign_xrpl_transaction_json(&burn_tx)?;
    let tx_blob = signed.tx_blob.clone().ok_or_else(|| {
        ClientError::Xrpl("Signed NFTokenBurn transaction is missing tx_blob".to_string())
    })?;
    let burn_submit = xrpl.submit(&tx_blob).await?;
    let burn_accepted = burn_submit.engine_result.starts_with("tes");

    if !burn_accepted {
        return Ok(DeleteVaultResponse {
            success: false,
            overall_status: "failed".to_string(),
            nft_token_id,
            message: format!(
                "NFT burn was not accepted by XRPL: {}",
                burn_submit.engine_result_message
            ),
            nft_burned: false,
            burn_tx_hash: Some(burn_submit.tx_hash),
            burn_engine_result: Some(burn_submit.engine_result),
            oracle_deleted: false,
            storage_deleted: false,
            deleted_fragments: 0,
            total_fragments: None,
            failures: vec!["xrpl_burn_failed".to_string()],
        });
    }

    if let Err(e) =
        wait_for_validated_nftoken_burn(&xrpl, &burn_submit.tx_hash, &nft_token_id, &account).await
    {
        return Ok(DeleteVaultResponse {
            success: false,
            overall_status: "partial".to_string(),
            nft_token_id,
            message: format!(
                "NFT burn was submitted, but Vaulted could not confirm validation before Oracle cleanup: {}",
                e
            ),
            nft_burned: true,
            burn_tx_hash: Some(burn_submit.tx_hash),
            burn_engine_result: Some(burn_submit.engine_result),
            oracle_deleted: false,
            storage_deleted: false,
            deleted_fragments: 0,
            total_fragments: None,
            failures: vec!["xrpl_burn_validation_pending".to_string()],
        });
    }

    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/vault/{}/delete",
        state.config.oracle_url, nft_token_id
    );

    let response = client
        .post(&oracle_url)
        .json(&serde_json::json!({
            "wallet_address": session.wallet_address,
            "burn_tx_hash": burn_submit.tx_hash,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Ok(DeleteVaultResponse {
            success: false,
            overall_status: "partial".to_string(),
            nft_token_id,
            message: format!(
                "NFT burn succeeded, but Oracle/storage cleanup failed: HTTP {} {}",
                status, error_text
            ),
            nft_burned: true,
            burn_tx_hash: Some(burn_submit.tx_hash),
            burn_engine_result: Some(burn_submit.engine_result),
            oracle_deleted: false,
            storage_deleted: false,
            deleted_fragments: 0,
            total_fragments: None,
            failures: vec!["oracle_cleanup_failed".to_string()],
        });
    }

    let oracle_result: OracleDeleteVaultResponse = response.json().await?;
    let storage_deleted = oracle_result.storage_deleted
        || oracle_result
            .total_fragments
            .map(|total| oracle_result.deleted_fragments >= total)
            .unwrap_or(oracle_result.success);
    let oracle_deleted = oracle_result.oracle_deleted || oracle_result.success;
    let mut failures = oracle_result.failures;
    if !storage_deleted {
        failures.push("storage_delete_partial".to_string());
    }
    if !oracle_deleted {
        failures.push("oracle_tombstone_failed".to_string());
    }
    let success = burn_accepted && storage_deleted && oracle_deleted && failures.is_empty();
    let overall_status = if success { "deleted" } else { "partial" }.to_string();

    tracing::info!(
        "Vault {} delete result: burn accepted, {} fragments removed",
        nft_token_id,
        oracle_result.deleted_fragments
    );

    Ok(DeleteVaultResponse {
        success,
        overall_status,
        nft_token_id,
        message: oracle_result.message,
        nft_burned: true,
        burn_tx_hash: Some(burn_submit.tx_hash),
        burn_engine_result: Some(burn_submit.engine_result),
        oracle_deleted,
        storage_deleted,
        deleted_fragments: oracle_result.deleted_fragments,
        total_fragments: oracle_result.total_fragments,
        failures,
    })
}

async fn wait_for_validated_nftoken_burn(
    xrpl: &XrplClient,
    tx_hash: &str,
    nft_token_id: &str,
    account: &str,
) -> Result<()> {
    const MAX_ATTEMPTS: usize = 12;
    const POLL_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

    for attempt in 1..=MAX_ATTEMPTS {
        match xrpl.tx(tx_hash).await {
            Ok(response) => {
                let Some(result) = response.get("result") else {
                    return Err(ClientError::Xrpl(
                        "XRPL tx response missing result".to_string(),
                    ));
                };
                if result.get("validated").and_then(|value| value.as_bool()) == Some(true) {
                    let tx_result = result
                        .pointer("/meta/TransactionResult")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown");
                    if tx_result != "tesSUCCESS" {
                        return Err(ClientError::Xrpl(format!(
                            "NFTokenBurn transaction failed: {}",
                            tx_result
                        )));
                    }
                    let tx_type = result
                        .get("TransactionType")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default();
                    let tx_account = result
                        .get("Account")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default();
                    let tx_nftoken_id = result
                        .get("NFTokenID")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default();
                    if tx_type == "NFTokenBurn"
                        && tx_account.eq_ignore_ascii_case(account)
                        && tx_nftoken_id.eq_ignore_ascii_case(nft_token_id)
                    {
                        return Ok(());
                    }
                    return Err(ClientError::Xrpl(
                        "Validated XRPL transaction does not match requested NFT burn".to_string(),
                    ));
                }
            },
            Err(e) if attempt == MAX_ATTEMPTS => return Err(e),
            Err(_) => {},
        }

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(POLL_DELAY).await;
        }
    }

    Err(ClientError::Xrpl(
        "Timed out waiting for NFTokenBurn validation".to_string(),
    ))
}

// ==================== Burn NFT ====================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurnNftResult {
    pub success: bool,
    pub tx_hash: String,
    pub message: String,
}

#[tauri::command(rename_all = "camelCase")]
pub async fn burn_nft(
    _state: State<'_, Arc<AppState>>,
    _nft_token_id: String,
) -> Result<crate::auth::VaultedSigningRequest> {
    Err(ClientError::Auth("Legacy external-wallet signing is disabled in Vaulted wallet mode; use Vaulted XRPL wallet QR signing/submission flows".to_string()))
}

#[tauri::command(rename_all = "camelCase")]
pub async fn wait_for_burn(
    _state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
    _nft_token_id: String,
) -> Result<BurnNftResult> {
    Err(ClientError::Auth("Legacy external-wallet signing is disabled in Vaulted wallet mode; use Vaulted XRPL wallet QR signing/submission flows".to_string()))
}

// ==================== Secure Notes ====================

/// Secure Note - encrypted note
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    pub nft_token_id: String,
    pub title: String,
    pub note_type: String, // "password", "seed", "key", "note"
    pub size: u64,
    pub created_at: String,
}

/// Secure note creation result
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteResult {
    pub vault_id: String,
    pub nft_token_id: String,
    pub offer_index: String,
    pub signing_request_uri: String,
    pub title: String,
    pub size: u64,
}

/// Encrypts and uploads text data (passwords, keys, notes)
/// Data is stored ONLY in RAM and cleared after encryption
#[tauri::command]
pub async fn encrypt_secure_note(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    title: String,
    content: String,
    note_type: String,
) -> Result<SecureNoteResult> {
    use zeroize::Zeroize;

    let session = state.get_session().await?;
    let wallet_address = session.wallet_address.clone();

    if !state.has_keypair().await {
        return Err(ClientError::Auth("PRE keys not initialized".to_string()));
    }

    let public_key = state.get_public_key().await?;
    let public_key_hex = hex::encode(public_key.to_bytes());

    // Data size
    let content_size = content.len() as u64;

    tracing::info!(
        "Creating secure note '{}' ({} bytes, type: {})",
        title,
        content_size,
        note_type
    );

    // Progress
    let mut progress = ProgressEvent::new(&title, "upload");
    progress.bytes_total = content_size;
    progress.stage = "encrypting".to_string();
    progress.message = "Encrypting secure note...".to_string();
    progress.total_progress = 10;
    progress.emit(&app);

    // Convert to bytes for encryption
    let mut content_bytes = content.into_bytes();

    // MIME type for notes
    let mime_type = match note_type.as_str() {
        "password" => "application/x-password",
        "seed" => "application/x-seed-phrase",
        "key" => "application/x-api-key",
        _ => "text/plain",
    };

    // Encrypt
    let encryptor = FileEncryptor::new(state.config.fragment_size);
    let encrypted = encryptor.encrypt_bytes(
        &content_bytes,
        &format!("{}.secure", title),
        mime_type,
        &public_key,
    )?;

    // IMPORTANT: Clear plaintext from memory
    content_bytes.zeroize();

    let encrypted_bytes = encrypted.encrypted_data.to_bytes()?;

    progress.total_progress = 30;
    progress.message = "Note encrypted".to_string();
    progress.emit(&app);

    tracing::info!("Secure note encrypted: {} bytes", encrypted_bytes.len());

    // Create a vault (mint NFT)
    progress.stage = "minting".to_string();
    progress.message = "Creating secure vault...".to_string();
    progress.total_progress = 40;
    progress.emit(&app);

    let oracle = state.get_oracle_client_with_timeout(120).await?;

    let vault_request = CreateVaultRequest {
        wallet_address: wallet_address.clone(),
        pre_public_key: public_key_hex,
        encrypted_aes_key: encrypted.encrypted_aes_key.to_base64()?,
        metadata_hash: encrypted.manifest.compute_hash(),
        manifest: VaultManifest {
            encrypted_filename: encrypted.manifest.encrypted_filename.clone(),
            original_size: encrypted.manifest.original_size,
            mime_type: mime_type.to_string(),
            original_hash: encrypted.manifest.original_hash.clone(),
            fragments: vec![VaultFragment {
                index: 0,
                storage_node_id: String::new(),
                storage_key: String::new(),
                encrypted_hash: encrypted.encrypted_hash.clone(),
                size: encrypted_bytes.len() as u64,
            }],
        },
    };

    progress.total_progress = 50;
    progress.message = "Minting NFT...".to_string();
    progress.emit(&app);

    let vault_response = oracle.create_vault(&vault_request).await?;

    progress.total_progress = 70;
    progress.message = "NFT created!".to_string();
    progress.emit(&app);

    tracing::info!(
        "Secure note vault created: NFT {}",
        vault_response.nft_token_id
    );

    // Upload through Oracle proxy
    progress.stage = "uploading".to_string();
    progress.message = "Uploading encrypted note...".to_string();
    progress.total_progress = 75;
    progress.emit(&app);

    let upload_url = format!(
        "{}/api/v1/files/upload?nft_token_id={}",
        state.config.oracle_url, vault_response.nft_token_id
    );

    let response = state
        .create_authed_client()
        .await
        .post(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_bytes)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(ClientError::Oracle(format!(
            "Failed to upload note: {} - {}",
            status, error_text
        )));
    }

    progress.stage = "complete".to_string();
    progress.total_progress = 100;
    progress.message = "Secure note saved!".to_string();
    progress.emit(&app);

    tracing::info!("Secure note saved successfully");

    Ok(SecureNoteResult {
        vault_id: vault_response.vault_id,
        nft_token_id: vault_response.nft_token_id,
        offer_index: vault_response.offer_index,
        signing_request_uri: vault_response.signing_request_uri,
        title,
        size: content_size,
    })
}

/// Decrypts and returns secure note content
/// Data is returned to the UI and must be cleared there after use
#[tauri::command]
pub async fn decrypt_secure_note(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
) -> Result<SecureNoteContent> {
    let _session = state.get_session().await?;

    tracing::info!("Decrypting secure note payload");

    // Get metadata
    let client = state.create_authed_client().await;
    let oracle_url = format!(
        "{}/api/v1/files/{}/access",
        state.config.oracle_url, nft_token_id
    );

    let file_info: serde_json::Value = client.get(&oracle_url).send().await?.json().await?;

    let encrypted_aes_key = file_info["encrypted_aes_key"]
        .as_str()
        .ok_or_else(|| ClientError::Oracle("Missing encrypted_aes_key".into()))?;

    let is_re_encrypted = file_info["is_re_encrypted"].as_bool().unwrap_or(false);

    let mime_type = file_info["manifest"]["mime_type"]
        .as_str()
        .unwrap_or("text/plain")
        .to_string();

    // Download through Oracle proxy
    let download_url = format!(
        "{}/api/v1/files/{}/download",
        state.config.oracle_url, nft_token_id
    );

    let response = client.get(&download_url).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        tracing::error!(
            "Failed to download note {}: {} - {}",
            nft_token_id,
            status,
            error_body
        );
        return Err(ClientError::Oracle(format!(
            "Failed to download note ({}): {}",
            status,
            if error_body.contains("missing from all storage nodes") {
                "Encrypted data is missing from storage. The note may need to be re-created."
                    .to_string()
            } else {
                error_body
            }
        )));
    }

    let encrypted_data = response.bytes().await?.to_vec();

    // Decrypt the AES key
    let keypair = state.get_keypair().await?;

    let aes_key_bytes = if is_re_encrypted {
        tracing::info!("Unwrapping transferred secure-note content key");
        let re_encrypted_data =
            xrpl_vault_crypto_core::pre::ReEncryptedData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state
            .pre()
            .decrypt_reencrypted_data(&keypair, &re_encrypted_data)?
    } else {
        tracing::info!("Unwrapping owner content key");
        let encrypted_pre_data =
            xrpl_vault_crypto_core::EncryptedPreData::from_base64(encrypted_aes_key)
                .map_err(ClientError::Crypto)?;
        state.pre().decrypt(&keypair, &encrypted_pre_data)?
    };

    // Decrypt data
    let aes_key = xrpl_vault_crypto_core::AesKey::from_bytes(&aes_key_bytes)?;
    let encrypted_fragment = xrpl_vault_crypto_core::EncryptedData::from_bytes(&encrypted_data)?;
    let decrypted = aes_key.decrypt(&encrypted_fragment)?;

    // Convert to string
    let content = String::from_utf8(decrypted)
        .map_err(|_| ClientError::Config("Invalid UTF-8 in note".to_string()))?;

    // Determine type by MIME
    let note_type = match mime_type.as_str() {
        "application/x-password" => "password",
        "application/x-seed-phrase" => "seed",
        "application/x-api-key" => "key",
        _ => "note",
    }
    .to_string();

    tracing::info!("Secure note payload decrypted");

    Ok(SecureNoteContent {
        nft_token_id,
        content,
        note_type,
        mime_type,
    })
}

/// Decrypted note content
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteContent {
    pub nft_token_id: String,
    pub content: String,
    pub note_type: String,
    pub mime_type: String,
}

/// Get the user's secure notes list
#[tauri::command]
pub async fn list_secure_notes(state: State<'_, Arc<AppState>>) -> Result<Vec<SecureNote>> {
    let _session = state.get_session().await?;

    // Get all files and filter by MIME type
    let files = get_my_files(state.clone()).await?;

    let secure_notes: Vec<SecureNote> = files
        .into_iter()
        .filter(|f| f.mime_type.starts_with("application/x-") || f.mime_type == "text/plain")
        .filter(|f| f.filename.ends_with(".secure"))
        .map(|f| {
            let note_type = match f.mime_type.as_str() {
                "application/x-password" => "password",
                "application/x-seed-phrase" => "seed",
                "application/x-api-key" => "key",
                _ => "note",
            }
            .to_string();

            let title = f
                .filename
                .strip_suffix(".secure")
                .unwrap_or(&f.filename)
                .to_string();

            SecureNote {
                nft_token_id: f.nft_token_id,
                title,
                note_type,
                size: f.size,
                created_at: f.uploaded_at,
            }
        })
        .collect();

    tracing::info!("Found {} secure notes", secure_notes.len());

    Ok(secure_notes)
}

/// NFT claim status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimStatus {
    pub claimed: bool,
    pub expired: bool,
    pub owner_address: Option<String>,
}

/// NFT claim status check
/// Checks whether the NFT was received by the user (offer accepted)
#[tauri::command]
pub async fn check_claim_status(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    offer_index: String,
) -> Result<ClaimStatus> {
    tracing::info!(
        "Checking claim status for NFT: {}, offer: {}",
        nft_token_id,
        offer_index
    );

    let _session = state.get_session().await?;

    let url = format!(
        "{}/api/v1/vault/claim-status/{}/{}",
        state.config.oracle_url, nft_token_id, offer_index
    );

    let response = state.create_authed_client().await.get(&url).send().await?;

    if response.status().is_success() {
        let status: ClaimStatus = response
            .json()
            .await
            .map_err(|e| ClientError::Oracle(format!("Failed to parse claim status: {}", e)))?;

        tracing::info!(
            "Claim status: claimed={}, expired={}",
            status.claimed,
            status.expired
        );
        Ok(status)
    } else {
        tracing::warn!("Oracle claim-status endpoint error, assuming not claimed");
        Ok(ClaimStatus {
            claimed: false,
            expired: false,
            owner_address: None,
        })
    }
}

/// Offer cancellation and NFT burn
/// Called when the user cancels the operation or time expires
#[tauri::command]
pub async fn cancel_secure_note_offer(
    state: State<'_, Arc<AppState>>,
    nft_token_id: String,
    offer_index: String,
) -> Result<()> {
    tracing::info!(
        "Cancelling secure note offer: NFT={}, offer={}",
        nft_token_id,
        offer_index
    );

    let _session = state.get_session().await?;

    let url = format!("{}/api/v1/vault/cancel-offer", state.config.oracle_url);

    let response = state
        .create_authed_client()
        .await
        .post(&url)
        .json(&serde_json::json!({
            "nft_token_id": nft_token_id,
            "offer_index": offer_index,
        }))
        .send()
        .await?;

    if response.status().is_success() {
        tracing::info!("Offer cancelled and NFT burned successfully");
        Ok(())
    } else {
        let error_text = response.text().await.unwrap_or_default();
        tracing::error!("Failed to cancel offer: {}", error_text);
        Err(ClientError::Oracle(format!(
            "Failed to cancel offer: {}",
            error_text
        )))
    }
}

// ==================== Production UX Status Commands ====================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrplAccountStatus {
    pub status: String,
    pub address: String,
    pub exists: bool,
    pub balance_xrp: Option<String>,
    pub reserve_requirement_xrp: String,
    pub network: String,
    pub can_mint: bool,
    pub action_hint: String,
    pub action_label: Option<String>,
    pub action_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletOverview {
    pub classic_address: String,
    pub network: String,
    pub status: String,
    pub connected: bool,
    pub funded: bool,
    pub balance_xrp: Option<String>,
    pub reserve_requirement_xrp: String,
    pub action_hint: String,
    pub action_label: Option<String>,
    pub action_url: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionHistoryItem {
    pub tx_hash: String,
    pub transaction_type: String,
    pub direction: Option<String>,
    pub amount_xrp: Option<String>,
    pub counterparty: Option<String>,
    pub ledger_index: Option<u32>,
    pub date: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendXrpPaymentRequest {
    pub destination: String,
    pub amount_xrp: String,
    pub destination_tag: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendXrpPaymentResponse {
    pub engine_result: String,
    pub engine_result_message: String,
    pub tx_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub status: String,
    pub message: Option<String>,
    pub nodes: Option<u32>,
    pub network: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    pub oracle: ServiceStatus,
    pub storage: ServiceStatus,
    pub xrpl: ServiceStatus,
    pub wallet: ServiceStatus,
}

fn xrpl_network_label(node_url: &str) -> String {
    let lower = node_url.to_ascii_lowercase();
    if lower.contains("altnet") || lower.contains("testnet") {
        "testnet".to_string()
    } else if lower.contains("devnet") {
        "devnet".to_string()
    } else {
        std::env::var("XRPL_NETWORK").unwrap_or_else(|_| "mainnet".to_string())
    }
}

fn testnet_faucet_url(address: &str) -> String {
    format!(
        "https://xrpl.org/xrp-testnet-faucet.html?account={}",
        address
    )
}

fn drops_to_xrp_string(drops: &str) -> String {
    match drops.parse::<f64>() {
        Ok(v) => {
            let xrp = v / 1_000_000.0;
            if xrp.fract() == 0.0 {
                format!("{xrp:.0}")
            } else {
                format!("{xrp:.6}")
                    .trim_end_matches('0')
                    .trim_end_matches('.')
                    .to_string()
            }
        },
        Err(_) => "0".to_string(),
    }
}

fn parse_xrp_amount_to_drops(amount_xrp: &str) -> Result<u64> {
    let trimmed = amount_xrp.trim();
    if trimmed.is_empty() {
        return Err(ClientError::Validation("Amount is required".to_string()));
    }
    if trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(ClientError::Validation(
            "Amount must be a positive XRP value".to_string(),
        ));
    }
    if trimmed.eq_ignore_ascii_case("nan") || trimmed.to_ascii_lowercase().contains("inf") {
        return Err(ClientError::Validation(
            "Amount must be a finite XRP value".to_string(),
        ));
    }

    let mut parts = trimmed.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some() || whole.is_empty() {
        return Err(ClientError::Validation(
            "Amount must be a numeric XRP value".to_string(),
        ));
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::Validation(
            "Amount must be a numeric XRP value".to_string(),
        ));
    }

    let fractional = fractional.unwrap_or("");
    if !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::Validation(
            "Amount must be a numeric XRP value".to_string(),
        ));
    }
    if fractional.len() > 6 {
        return Err(ClientError::Validation(
            "Amount supports at most 6 decimal places".to_string(),
        ));
    }

    let whole_drops = whole
        .parse::<u64>()
        .map_err(|_| ClientError::Validation("Amount is too large".to_string()))?
        .checked_mul(1_000_000)
        .ok_or_else(|| ClientError::Validation("Amount is too large".to_string()))?;
    let fractional_drops = if fractional.is_empty() {
        0
    } else {
        let padded = format!("{fractional:0<6}");
        padded
            .parse::<u64>()
            .map_err(|_| ClientError::Validation("Amount is too large".to_string()))?
    };
    let drops = whole_drops
        .checked_add(fractional_drops)
        .ok_or_else(|| ClientError::Validation("Amount is too large".to_string()))?;
    if drops == 0 {
        return Err(ClientError::Validation(
            "Amount must be greater than 0 XRP".to_string(),
        ));
    }
    Ok(drops)
}

fn parse_destination_tag(tag: Option<&str>) -> Result<Option<u32>> {
    let Some(tag) = tag.map(str::trim).filter(|tag| !tag.is_empty()) else {
        return Ok(None);
    };
    if tag.starts_with('-')
        || tag.starts_with('+')
        || !tag.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ClientError::Validation(
            "Destination tag must be a non-negative integer".to_string(),
        ));
    }
    tag.parse::<u32>()
        .map(Some)
        .map_err(|_| ClientError::Validation("Destination tag is too large".to_string()))
}

fn validate_spendable_balance(
    balance_drops: u64,
    reserve_drops: u64,
    fee_drops: u64,
    amount_drops: u64,
) -> Result<()> {
    let spendable = balance_drops
        .checked_sub(reserve_drops)
        .and_then(|value| value.checked_sub(fee_drops))
        .ok_or_else(|| {
            ClientError::Validation("Wallet balance does not cover reserve and fee".to_string())
        })?;
    if spendable < amount_drops {
        return Err(ClientError::Validation(
            "Insufficient spendable balance after reserve and fee".to_string(),
        ));
    }
    Ok(())
}

fn xrpl_datetime_to_iso(seconds_since_2000: u64) -> Option<String> {
    let unix_seconds = seconds_since_2000.checked_add(946_684_800)?;
    chrono::DateTime::from_timestamp(unix_seconds as i64, 0).map(|dt| dt.to_rfc3339())
}

fn extract_tx_object(entry: &serde_json::Value) -> Option<&serde_json::Value> {
    entry
        .get("tx_json")
        .or_else(|| entry.get("tx"))
        .or_else(|| entry.get("transaction"))
}

fn extract_tx_hash(entry: &serde_json::Value, tx: &serde_json::Value) -> String {
    tx.get("hash")
        .or_else(|| entry.get("hash"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn parse_payment_amount_xrp(tx: &serde_json::Value) -> Option<String> {
    tx.get("Amount")
        .and_then(|amount| amount.as_str())
        .map(drops_to_xrp_string)
}

fn parse_wallet_history_item(
    account: &str,
    entry: &serde_json::Value,
) -> Option<WalletTransactionHistoryItem> {
    let tx = extract_tx_object(entry)?;
    let transaction_type = tx.get("TransactionType")?.as_str()?.to_string();
    let tx_hash = extract_tx_hash(entry, tx);
    if tx_hash.is_empty() {
        return None;
    }

    let account_field = tx.get("Account").and_then(|value| value.as_str());
    let destination = tx.get("Destination").and_then(|value| value.as_str());
    let is_payment = transaction_type == "Payment";
    let direction = if is_payment {
        if account_field == Some(account) {
            Some("sent".to_string())
        } else if destination == Some(account) {
            Some("received".to_string())
        } else {
            None
        }
    } else {
        None
    };
    let counterparty = match direction.as_deref() {
        Some("sent") => destination.map(str::to_string),
        Some("received") => account_field.map(str::to_string),
        _ => None,
    };

    let ledger_index = entry
        .get("ledger_index")
        .or_else(|| tx.get("ledger_index"))
        .and_then(|value| value.as_u64())
        .map(|value| value as u32);
    let date = entry
        .get("close_time_iso")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| {
            tx.get("date")
                .and_then(|value| value.as_u64())
                .and_then(xrpl_datetime_to_iso)
        });

    let status = entry
        .get("meta")
        .or_else(|| entry.get("metaData"))
        .and_then(|meta| meta.get("TransactionResult"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
        .to_string();

    Some(WalletTransactionHistoryItem {
        tx_hash,
        transaction_type,
        direction,
        amount_xrp: if is_payment {
            parse_payment_amount_xrp(tx)
        } else {
            None
        },
        counterparty,
        ledger_index,
        date,
        status,
    })
}

fn parse_wallet_transaction_history(
    account: &str,
    response: &serde_json::Value,
) -> Vec<WalletTransactionHistoryItem> {
    response
        .get("result")
        .and_then(|result| result.get("transactions"))
        .and_then(|transactions| transactions.as_array())
        .map(|transactions| {
            transactions
                .iter()
                .filter_map(|entry| parse_wallet_history_item(account, entry))
                .collect()
        })
        .unwrap_or_default()
}

#[tauri::command]
pub async fn get_wallet_overview(state: State<'_, Arc<AppState>>) -> Result<WalletOverview> {
    let address = state.wallet_address().await?;
    tracing::debug!(
        command = "get_wallet_overview",
        request_phase = "started",
        network = %xrpl_network_label(&state.config.xrpl_node_url),
        "Loading XRPL wallet overview"
    );
    let account = check_xrpl_account_status_inner(state.inner(), Some(address.clone())).await?;
    Ok(WalletOverview {
        classic_address: address,
        network: account.network,
        status: account.status.clone(),
        connected: true,
        funded: account.exists,
        balance_xrp: account.balance_xrp,
        reserve_requirement_xrp: account.reserve_requirement_xrp,
        action_hint: account.action_hint,
        action_label: account.action_label,
        action_url: account.action_url,
    })
}

#[tauri::command]
pub async fn get_xrpl_transaction_history(
    state: State<'_, Arc<AppState>>,
    limit: Option<u32>,
) -> Result<Vec<WalletTransactionHistoryItem>> {
    let address = state.wallet_address().await?;
    tracing::debug!(
        command = "get_xrpl_transaction_history",
        request_phase = "started",
        network = %xrpl_network_label(&state.config.xrpl_node_url),
        "Loading compact XRPL transaction history"
    );

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    let response = client.account_tx(&address, limit.unwrap_or(20)).await?;
    Ok(parse_wallet_transaction_history(&address, &response))
}

#[tauri::command(rename_all = "camelCase")]
pub async fn send_xrp_payment(
    state: State<'_, Arc<AppState>>,
    request: SendXrpPaymentRequest,
) -> Result<SendXrpPaymentResponse> {
    const RESERVE_DROPS: u64 = 10_000_000;
    const RESERVE_XRP: &str = "10";

    tracing::info!(
        command = "send_xrp_payment",
        request_phase = "validation_started",
        status = "started",
        "Validating XRP payment request"
    );

    let destination = request.destination.trim().to_string();
    if !is_valid_xrpl_classic_address(&destination) {
        tracing::warn!(
            command = "send_xrp_payment",
            request_phase = "validation",
            validation_status = "invalid_destination",
            status = "rejected",
            "XRP payment validation rejected destination"
        );
        return Err(ClientError::Validation(
            "Destination must be a valid XRPL classic address".to_string(),
        ));
    }

    let amount_drops = parse_xrp_amount_to_drops(&request.amount_xrp)?;
    let destination_tag = parse_destination_tag(request.destination_tag.as_deref())?;
    let amount_xrp = drops_to_xrp_string(&amount_drops.to_string());

    tracing::info!(
        command = "send_xrp_payment",
        request_phase = "validation",
        validation_status = "input_valid",
        amount_xrp = %amount_xrp,
        reserve_xrp = RESERVE_XRP,
        status = "ok",
        "XRP payment input validation passed"
    );

    let wallet = state.get_xrpl_wallet().await?;
    let account = wallet.classic_address()?;

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    let account_info = client.account_info(&account).await.map_err(|err| {
        let raw = err.to_string();
        if raw.contains("actNotFound") || raw.contains("Account not found") {
            ClientError::Validation("Wallet account is not funded".to_string())
        } else {
            err
        }
    })?;
    let balance_drops = account_info
        .balance
        .parse::<u64>()
        .map_err(|_| ClientError::Xrpl("XRPL returned an invalid account balance".to_string()))?;
    let fee_drops = client.fee_drops().await?;
    let fee_drops_u64 = fee_drops
        .parse::<u64>()
        .map_err(|_| ClientError::Xrpl("XRPL returned an invalid fee".to_string()))?;

    validate_spendable_balance(balance_drops, RESERVE_DROPS, fee_drops_u64, amount_drops)?;
    tracing::info!(
        command = "send_xrp_payment",
        request_phase = "validation",
        validation_status = "spendable_balance_valid",
        amount_xrp = %amount_xrp,
        fee_drops = %fee_drops,
        reserve_xrp = RESERVE_XRP,
        status = "ok",
        "XRP payment spendable balance validation passed"
    );

    let last_ledger_sequence = client.ledger_current_index().await?.saturating_add(20);
    let tx = build_xrp_payment_tx(
        &account,
        &destination,
        &amount_drops.to_string(),
        destination_tag,
    );
    let tx = add_xrpl_signing_fields(
        tx,
        fee_drops.clone(),
        account_info.sequence,
        last_ledger_sequence,
    );
    let signed = wallet.sign_xrpl_transaction_json(&tx)?;
    let tx_blob = signed.tx_blob.ok_or_else(|| {
        ClientError::Xrpl(
            "Local signing did not produce a signed XRPL transaction payload".to_string(),
        )
    })?;

    tracing::info!(
        command = "send_xrp_payment",
        request_phase = "submit_started",
        amount_xrp = %amount_xrp,
        fee_drops = %fee_drops,
        reserve_xrp = RESERVE_XRP,
        status = "submitting",
        "Submitting locally signed XRP payment"
    );
    let result = client.submit(&tx_blob).await?;
    tracing::info!(
        command = "send_xrp_payment",
        request_phase = "submit_completed",
        amount_xrp = %amount_xrp,
        fee_drops = %fee_drops,
        reserve_xrp = RESERVE_XRP,
        engine_result = %result.engine_result,
        tx_hash = %result.tx_hash,
        status = if result.engine_result.starts_with("tes") { "accepted" } else { "rejected" },
        "XRP payment submit completed"
    );

    Ok(SendXrpPaymentResponse {
        engine_result: result.engine_result,
        engine_result_message: result.engine_result_message,
        tx_hash: result.tx_hash,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn check_xrpl_account_status(
    state: State<'_, Arc<AppState>>,
    address: Option<String>,
) -> Result<XrplAccountStatus> {
    check_xrpl_account_status_inner(state.inner(), address).await
}

async fn check_xrpl_account_status_inner(
    state: &Arc<AppState>,
    address: Option<String>,
) -> Result<XrplAccountStatus> {
    let resolved_address = match address {
        Some(addr) if !addr.trim().is_empty() => addr.trim().to_string(),
        _ => state.wallet_address().await?,
    };
    let network = xrpl_network_label(&state.config.xrpl_node_url);
    let reserve_requirement_xrp = "10".to_string();

    let mut client = XrplClient::new(&state.config.xrpl_node_url);
    client.connect().await?;
    match client.account_info(&resolved_address).await {
        Ok(info) => Ok(XrplAccountStatus {
            status: "funded".to_string(),
            address: resolved_address,
            exists: true,
            balance_xrp: Some(drops_to_xrp_string(&info.balance)),
            reserve_requirement_xrp,
            network,
            can_mint: true,
            action_hint: "Wallet is active and ready to mint vault NFTs.".to_string(),
            action_label: None,
            action_url: None,
        }),
        Err(err) => {
            let raw = err.to_string();
            if raw.contains("actNotFound") || raw.contains("Account not found") {
                Ok(XrplAccountStatus {
                    status: "unfunded".to_string(),
                    address: resolved_address.clone(),
                    exists: false,
                    balance_xrp: Some("0".to_string()),
                    reserve_requirement_xrp,
                    network,
                    can_mint: false,
                    action_hint: "XRPL account is not funded yet. You can register and receive access, but cannot submit XRPL transactions until funded.".to_string(),
                    action_label: Some("Open XRPL Testnet Faucet".to_string()),
                    action_url: Some(testnet_faucet_url(&resolved_address)),
                })
            } else {
                Err(err)
            }
        },
    }
}

#[tauri::command]
pub async fn get_system_status(state: State<'_, Arc<AppState>>) -> Result<SystemStatus> {
    let wallet_address = state.wallet_address().await.ok();
    let oracle_connected = state.has_oracle_token().await;

    let storage_status = match state
        .http()
        .get(format!(
            "{}/health",
            state.config.storage_node_url.trim_end_matches('/')
        ))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => ServiceStatus {
            status: "connected".to_string(),
            message: Some("Storage node connected".to_string()),
            nodes: Some(1),
            network: None,
            address: None,
        },
        Ok(resp) => ServiceStatus {
            status: "offline".to_string(),
            message: Some(format!("Storage node returned HTTP {}", resp.status())),
            nodes: Some(0),
            network: None,
            address: None,
        },
        Err(_) => ServiceStatus {
            status: "offline".to_string(),
            message: Some("Storage node is not reachable".to_string()),
            nodes: Some(0),
            network: None,
            address: None,
        },
    };

    let xrpl_status = if let Some(address) = wallet_address.clone() {
        match check_xrpl_account_status_inner(state.inner(), Some(address.clone())).await {
            Ok(account) => ServiceStatus {
                status: if account.can_mint {
                    "connected".to_string()
                } else {
                    "wallet_not_funded".to_string()
                },
                message: Some(account.action_hint),
                nodes: None,
                network: Some(account.network),
                address: Some(address),
            },
            Err(e) => ServiceStatus {
                status: "offline".to_string(),
                message: Some(format!("XRPL check failed: {e}")),
                nodes: None,
                network: Some(xrpl_network_label(&state.config.xrpl_node_url)),
                address: Some(address),
            },
        }
    } else {
        ServiceStatus {
            status: "locked".to_string(),
            message: Some("Wallet is locked".to_string()),
            nodes: None,
            network: Some(xrpl_network_label(&state.config.xrpl_node_url)),
            address: None,
        }
    };

    Ok(SystemStatus {
        oracle: ServiceStatus {
            status: if oracle_connected {
                "connected".to_string()
            } else {
                "checking".to_string()
            },
            message: Some(if oracle_connected {
                "Oracle connected".to_string()
            } else {
                "Oracle is syncing".to_string()
            }),
            nodes: None,
            network: None,
            address: wallet_address.clone(),
        },
        storage: storage_status,
        xrpl: xrpl_status,
        wallet: ServiceStatus {
            status: if wallet_address.is_some() {
                "unlocked".to_string()
            } else {
                "locked".to_string()
            },
            message: Some(if wallet_address.is_some() {
                "Wallet unlocked".to_string()
            } else {
                "Wallet locked".to_string()
            }),
            nodes: None,
            network: None,
            address: wallet_address,
        },
    })
}

// ==================== Oracle Auth Commands ====================

/// Check if user is authenticated with Oracle
#[tauri::command]
pub async fn check_oracle_auth(state: State<'_, Arc<AppState>>) -> Result<bool> {
    Ok(state.has_oracle_token().await)
}

/// Get Oracle auth status with user info
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleAuthStatus {
    pub authenticated: bool,
    pub wallet_address: Option<String>,
    pub expires_at: Option<String>,
}

/// Track if Oracle was ever authenticated (for session expiry detection)
static WAS_EVER_ORACLE_AUTHED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reset the "was ever authenticated" flag (called on logout)
pub fn reset_oracle_auth_flag() {
    WAS_EVER_ORACLE_AUTHED.store(false, std::sync::atomic::Ordering::Relaxed);
}

#[tauri::command]
pub async fn get_oracle_auth_status(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<OracleAuthStatus> {
    let has_token = state.has_oracle_token().await;
    tracing::info!("[AUTH_CHECK] has_oracle_token={}", has_token);

    // Vaulted seed-wallet auth issues an Oracle JWT for the XRPL wallet.
    // It does not necessarily have a legacy users row, so get_me() is not
    // a reliable auth check for this flow.
    if has_token {
        tracing::info!("[AUTH_CHECK] → authenticated=true (valid Oracle token)");
        WAS_EVER_ORACLE_AUTHED.store(true, std::sync::atomic::Ordering::Relaxed);
        return Ok(OracleAuthStatus {
            authenticated: true,
            wallet_address: state.wallet_address().await.ok(),
            expires_at: None,
        });
    }

    // Token expired or invalid — try to refresh
    match state.try_refresh_oracle_token().await {
        Ok(true) => {
            tracing::info!("[AUTH_CHECK] Oracle token auto-refreshed during status check");
            WAS_EVER_ORACLE_AUTHED.store(true, std::sync::atomic::Ordering::Relaxed);
            // Re-check with refreshed token
            if let Ok(oracle) = state.get_oracle_client_with_timeout(10).await {
                if let Ok(user) = oracle.get_me().await {
                    tracing::info!("[AUTH_CHECK] → authenticated=true (after refresh)");
                    return Ok(OracleAuthStatus {
                        authenticated: true,
                        wallet_address: Some(user.wallet_address),
                        expires_at: None,
                    });
                }
            }
            Ok(OracleAuthStatus {
                authenticated: true,
                wallet_address: None,
                expires_at: None,
            })
        },
        _ => {
            tracing::warn!("[AUTH_CHECK] → authenticated=false (no token, refresh failed)");
            // If was ever authenticated → session expired → force logout
            if WAS_EVER_ORACLE_AUTHED.load(std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "[AUTH_CHECK] SESSION EXPIRED — forcing full logout and page reload"
                );
                WAS_EVER_ORACLE_AUTHED.store(false, std::sync::atomic::Ordering::Relaxed);

                // Clear ALL session state on Rust side
                state.clear_session().await;

                // Force frontend to reload — bypasses all React/Vite issues
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.eval("window.location.reload();");
                }
            }
            Ok(OracleAuthStatus {
                authenticated: false,
                wallet_address: None,
                expires_at: None,
            })
        },
    }
}

/// Start Oracle login through Vaulted QR login
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleLoginPayload {
    pub challenge: String,
    pub signing_request: crate::auth::VaultedSigningRequest,
}

#[tauri::command]
pub async fn oracle_login_start(_state: State<'_, Arc<AppState>>) -> Result<OracleLoginPayload> {
    Err(ClientError::Auth("Legacy external-wallet signing is disabled in Vaulted wallet mode; use Vaulted XRPL wallet QR signing/submission flows".to_string()))
}

/// Complete Oracle login - exchange signature for JWT
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleLoginComplete {
    pub challenge: String,
    pub public_key: String,
    pub signature: String,
}

#[tauri::command]
pub async fn oracle_login_complete(
    state: State<'_, Arc<AppState>>,
    login_data: OracleLoginComplete,
) -> Result<bool> {
    let session = state.get_session().await?;

    // Exchange signature for JWT
    let oracle = OracleClient::new(OracleConfig {
        base_url: state.config.oracle_url.clone(),
        timeout_secs: 30,
        ..Default::default()
    })?;

    let token_response = oracle
        .get_auth_token(&crate::oracle::api::AuthTokenRequest {
            wallet_address: session.wallet_address.clone(),
            public_key: login_data.public_key,
            signature: login_data.signature,
            challenge: login_data.challenge,
            device_fingerprint: Some(state.device_fingerprint().to_string()),
        })
        .await?;

    // Save all tokens
    let expires_in = token_response.expires_in;
    state
        .save_oracle_tokens(
            token_response.access_token,
            expires_in,
            token_response.refresh_token,
            token_response.role,
        )
        .await?;

    tracing::info!(
        "Oracle login successful for {} (expires in {}s)",
        session.wallet_address,
        expires_in
    );

    Ok(true)
}

/// Legacy external-wallet login wait is disabled
#[tauri::command]
pub async fn oracle_login_wait(
    _state: State<'_, Arc<AppState>>,
    _payload_uuid: String,
    _websocket_url: String,
    _qr_png: String,
    _challenge: String,
) -> Result<bool> {
    Err(ClientError::Auth(
        "Legacy external-wallet auth is disabled in Vaulted wallet mode; use Vaulted QR login or Vaulted XRPL wallet signing".to_string(),
    ))
}
#[tauri::command]
pub async fn oracle_logout(state: State<'_, Arc<AppState>>) -> Result<bool> {
    // Try to call logout endpoint
    if state.has_oracle_token().await {
        if let Ok(oracle) = state.get_oracle_client().await {
            let _ = oracle.logout().await; // Ignore errors
        }
    }

    // Clear token from state
    state.set_oracle_token(String::new()).await?;

    // Reset the "was ever authenticated" flag
    reset_oracle_auth_flag();

    tracing::info!("Oracle logout completed");

    Ok(true)
}

/// Refresh Oracle token using stored refresh token
#[tauri::command]
pub async fn oracle_refresh_token(state: State<'_, Arc<AppState>>) -> Result<bool> {
    state.try_refresh_oracle_token().await
}

/// Get device fingerprint (for debugging/display)
#[tauri::command]
pub async fn get_device_fingerprint(state: State<'_, Arc<AppState>>) -> Result<String> {
    Ok(state.device_fingerprint().to_string())
}

/// Get Oracle auth status with extended info
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleAuthStatusExtended {
    pub authenticated: bool,
    pub wallet_address: Option<String>,
    pub expires_at: Option<String>,
    pub has_refresh_token: bool,
    pub role: Option<String>,
    pub device_fingerprint: String,
    pub needs_refresh: bool,
}

#[tauri::command]
pub async fn get_oracle_auth_status_extended(
    state: State<'_, Arc<AppState>>,
) -> Result<OracleAuthStatusExtended> {
    let dfp = state.device_fingerprint().to_string();

    if let Ok(session) = state.get_session().await {
        let authenticated = session.oracle_token.is_some() && !session.oracle_token_is_expired();
        let needs_refresh = session.oracle_token_needs_refresh();
        let has_refresh = session.refresh_token.is_some();
        Ok(OracleAuthStatusExtended {
            authenticated,
            wallet_address: Some(session.wallet_address.clone()),
            expires_at: session.oracle_token_expires_at.map(|dt| dt.to_rfc3339()),
            has_refresh_token: has_refresh,
            role: session.role.clone(),
            device_fingerprint: dfp,
            needs_refresh,
        })
    } else {
        Ok(OracleAuthStatusExtended {
            authenticated: false,
            wallet_address: None,
            expires_at: None,
            has_refresh_token: false,
            role: None,
            device_fingerprint: dfp,
            needs_refresh: false,
        })
    }
}
