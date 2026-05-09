//! XRPL сервис для Oracle
//!
//! Минтинг NFT, создание offers, проверка балансов.

use crate::error::{ApiError, Result};
use serde::Serialize;
use tracing::{info, warn, debug};
use std::time::Duration;

use xrpl_mithril::client::JsonRpcClient;
use xrpl_mithril::models::transactions::{
    Transaction, TransactionCommon,
    nft::{NFTokenMint, NFTokenCreateOffer, NFTokenCancelOffer, NFTokenBurn},
    wrapper::UnsignedTransaction,
};
use xrpl_mithril::tx::autofill::autofill;
use xrpl_mithril::tx::sign_transaction;
use xrpl_mithril::types::{AccountId, Amount, Blob, XrpAmount, Hash256};
use xrpl_mithril::wallet::Wallet;

/// Конфигурация XRPL
#[derive(Debug, Clone)]
pub struct XrplConfig {
    /// Primary XRPL node URL (JSON-RPC)
    pub node_url: String,
    /// Additional XRPL node URLs for failover
    pub node_urls: Vec<String>,
    /// Wallet seed for signing transactions (optional — read-only mode without it)
    pub wallet_seed: Option<String>,
}

impl Default for XrplConfig {
    fn default() -> Self {
        Self {
            node_url: "https://s.altnet.rippletest.net:51234".to_string(),
            node_urls: vec![],
            wallet_seed: None,
        }
    }
}

/// Результат минта NFT
#[derive(Debug, Serialize)]
pub struct MintResult {
    pub nft_token_id: String,
    pub tx_hash: String,
}

/// Результат создания offer
#[derive(Debug, Serialize)]
pub struct OfferResult {
    pub offer_index: String,
    pub tx_hash: String,
}

/// XRPL сервис
pub struct XrplService {
    config: XrplConfig,
    http: reqwest::Client,
    wallet: Option<Wallet>,
}

impl XrplService {
    /// Создаёт сервис без кошелька (только чтение)
    pub fn new(node_url: &str) -> Self {
        Self {
            config: XrplConfig {
                node_url: node_url.to_string(),
                node_urls: vec![],
                wallet_seed: None,
            },
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            wallet: None,
        }
    }

    /// Создаёт сервис с кошельком
    pub fn with_wallet(config: XrplConfig) -> Result<Self> {
        let wallet = if let Some(ref seed) = config.wallet_seed {
            let w = if seed.starts_with("sEd") {
                Wallet::from_seed_encoded_with_algorithm(seed, xrpl_mithril::wallet::Algorithm::Ed25519)
            } else {
                Wallet::from_seed_encoded(seed)
            }.map_err(|e| ApiError::Xrpl(format!("Invalid seed: {}", e)))?;
            info!("XRPL Oracle wallet: {}", w.account_id());
            Some(w)
        } else {
            None
        };

        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            wallet,
        })
    }

    /// Адрес Oracle кошелька
    pub fn oracle_address(&self) -> Option<String> {
        self.wallet.as_ref().map(|w| w.account_id().to_string())
    }

    /// Создаёт JSON-RPC клиент
    #[allow(dead_code)]
    fn client(&self) -> Result<JsonRpcClient> {
        JsonRpcClient::new(&self.config.node_url)
            .map_err(|e| ApiError::Xrpl(format!("Client error: {}", e)))
    }

    /// JSON-RPC вызов с retry
    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let mut last_error = None;

        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                tracing::debug!("RPC retry attempt {} for {}", attempt + 1, method);
            }

            match self.rpc_once(method, params.clone()).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    tracing::warn!("RPC {} attempt {} failed: {}", method, attempt + 1, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ApiError::Xrpl("RPC failed after retries".into())))
    }

    /// Один RPC вызов без retry
    async fn rpc_once(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self.http.post(&self.config.node_url)
            .json(&serde_json::json!({
                "method": method,
                "params": [params]
            }))
            .send()
            .await
            .map_err(|e| ApiError::Xrpl(format!("HTTP error: {}", e)))?;

        let data: serde_json::Value = resp.json().await
            .map_err(|e| ApiError::Xrpl(format!("JSON error: {}", e)))?;

        if let Some(error) = data["result"]["error"].as_str() {
            return Err(ApiError::Xrpl(format!("XRPL error: {}", error)));
        }

        Ok(data)
    }

    /// Submit transaction via HTTP and poll for validation
    ///
    /// Handles network errors gracefully by checking if the transaction was already
    /// accepted before retrying. This prevents tefPAST_SEQ errors when HTTP fails
    /// but the transaction actually made it to the network.
    async fn submit_and_wait_validation(&self, tx_blob: &str, tx_hash: &str) -> Result<()> {
        // Try to submit - use rpc_once to avoid automatic retry with same sequence
        let submit_result = match self.rpc_once("submit", serde_json::json!({
            "tx_blob": tx_blob
        })).await {
            Ok(result) => result,
            Err(e) => {
                // HTTP error - the tx might have actually been submitted
                // Check if it's already in the ledger before giving up
                warn!("Submit HTTP error, checking if tx was accepted: {}", e);

                // Wait a bit for potential propagation
                tokio::time::sleep(Duration::from_secs(2)).await;

                // Check if tx exists in ledger
                if let Ok(tx_data) = self.rpc_once("tx", serde_json::json!({
                    "transaction": tx_hash,
                    "binary": false
                })).await {
                    // Transaction found - it was actually submitted!
                    if tx_data["result"]["validated"].as_bool() == Some(true) {
                        let final_result = tx_data["result"]["meta"]["TransactionResult"]
                            .as_str()
                            .unwrap_or("unknown");

                        if final_result == "tesSUCCESS" {
                            info!("Transaction was actually submitted despite HTTP error: {}", tx_hash);
                            return Ok(());
                        } else {
                            return Err(ApiError::Xrpl(format!("Transaction failed: {}", final_result)));
                        }
                    }
                    // Found but not validated yet - continue to polling below
                    info!("Transaction found in ledger (pending validation): {}", tx_hash);
                } else {
                    // Transaction not found - retry submit with backoff
                    debug!("Transaction not found, retrying submit...");

                    for retry in 1..=2 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        debug!("RPC retry attempt {} for submit", retry + 1);

                        match self.rpc_once("submit", serde_json::json!({
                            "tx_blob": tx_blob
                        })).await {
                            Ok(result) => {
                                let engine_result = result["result"]["engine_result"]
                                    .as_str()
                                    .unwrap_or("unknown");

                                // tefPAST_SEQ means the original submission actually worked!
                                if engine_result == "tefPAST_SEQ" {
                                    info!("Got tefPAST_SEQ - original tx was submitted, checking status...");
                                    break; // Exit retry loop, continue to validation polling
                                }

                                info!("Transaction submitted on retry: {} (hash: {})", engine_result, tx_hash);

                                if engine_result.starts_with("tem") {
                                    return Err(ApiError::Xrpl(format!("Transaction failed: {}", engine_result)));
                                }
                                break; // Successfully submitted
                            }
                            Err(retry_err) => {
                                warn!("RPC submit attempt {} failed: {}", retry + 1, retry_err);
                                if retry == 2 {
                                    // Last resort: check if tx made it despite errors
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                    if let Ok(tx_data) = self.rpc_once("tx", serde_json::json!({
                                        "transaction": tx_hash,
                                        "binary": false
                                    })).await {
                                        if tx_data["result"]["validated"].as_bool() == Some(true) {
                                            let final_result = tx_data["result"]["meta"]["TransactionResult"]
                                                .as_str()
                                                .unwrap_or("unknown");
                                            if final_result == "tesSUCCESS" {
                                                info!("Transaction validated despite submit errors: {}", tx_hash);
                                                return Ok(());
                                            }
                                        }
                                    }
                                    return Err(ApiError::Xrpl(format!("Submit failed after retries: {}", retry_err)));
                                }
                            }
                        }
                    }
                }

                // Continue to validation polling with a synthetic "submitted" result
                serde_json::json!({"result": {"engine_result": "tesSUCCESS"}})
            }
        };

        let engine_result = submit_result["result"]["engine_result"]
            .as_str()
            .unwrap_or("unknown");

        info!("Transaction submitted: {} (hash: {})", engine_result, tx_hash);

        // Check for immediate failures (except tefPAST_SEQ which we handle specially)
        if engine_result.starts_with("tem") {
            return Err(ApiError::Xrpl(format!("Transaction failed: {}", engine_result)));
        }

        // tefPAST_SEQ means original submission worked - the tx should be in ledger
        if engine_result == "tefPAST_SEQ" {
            debug!("tefPAST_SEQ received - checking if original tx was validated");
        } else if engine_result.starts_with("tef") && engine_result != "tefPAST_SEQ" {
            return Err(ApiError::Xrpl(format!("Transaction failed: {}", engine_result)));
        }

        // For tesSUCCESS, tec* codes, or tefPAST_SEQ - poll for validation (up to 30 seconds)
        for i in 0..30 {
            tokio::time::sleep(Duration::from_secs(1)).await;

            match self.rpc_once("tx", serde_json::json!({
                "transaction": tx_hash,
                "binary": false
            })).await {
                Ok(tx_data) => {
                    if tx_data["result"]["validated"].as_bool() == Some(true) {
                        let final_result = tx_data["result"]["meta"]["TransactionResult"]
                            .as_str()
                            .unwrap_or("unknown");

                        if final_result == "tesSUCCESS" {
                            debug!("Transaction validated after {}s: {}", i + 1, tx_hash);
                            return Ok(());
                        } else {
                            return Err(ApiError::Xrpl(format!("Transaction failed: {}", final_result)));
                        }
                    }
                }
                Err(e) => {
                    // txnNotFound is expected while waiting
                    let err_str = e.to_string();
                    if !err_str.contains("txnNotFound") && !err_str.contains("notFound") {
                        debug!("Poll {} error: {}", i, e);
                    }
                }
            }
        }

        Err(ApiError::Xrpl("Transaction validation timeout".into()))
    }

    /// Получает баланс аккаунта в XRP
    pub async fn get_balance(&self, address: &str) -> Result<f64> {
        let data = self.rpc("account_info", serde_json::json!({
            "account": address,
            "ledger_index": "validated"
        })).await?;

        let balance_str = data["result"]["account_data"]["Balance"]
            .as_str()
            .ok_or_else(|| ApiError::Xrpl("No balance".into()))?;

        let drops: u64 = balance_str.parse()
            .map_err(|_| ApiError::Xrpl("Invalid balance".into()))?;

        Ok(drops as f64 / 1_000_000.0)
    }

    /// Проверяет баланс Oracle
    pub async fn check_oracle_balance(&self) -> Result<f64> {
        let address = self.oracle_address()
            .ok_or_else(|| ApiError::Xrpl("No wallet".into()))?;

        let balance = self.get_balance(&address).await?;

        if balance < 15.0 {
            warn!("Oracle balance low: {} XRP", balance);
        }
        if balance < 12.0 {
            return Err(ApiError::Xrpl(format!(
                "Balance critically low: {} XRP", balance
            )));
        }

        Ok(balance)
    }

    /// Минтит NFT с указанным URI
    pub async fn mint_nft(&self, uri: &str, transfer_fee: u16) -> Result<MintResult> {
        let wallet = self.wallet.as_ref()
            .ok_or_else(|| ApiError::Xrpl("No wallet for minting".into()))?;

        self.check_oracle_balance().await?;

        let client = self.client()?;

        // URI в hex
        let uri_bytes = uri.as_bytes().to_vec();

        // Создаём NFTokenMint транзакцию
        let fields = NFTokenMint {
            nftoken_taxon: 0,
            issuer: None,
            transfer_fee: if transfer_fee > 0 { Some(transfer_fee) } else { None },
            uri: Some(Blob::new(uri_bytes)),
        };

        // Common fields
        let common = TransactionCommon {
            account: *wallet.account_id(),
            fee: Amount::Xrp(XrpAmount::from_drops(12).unwrap()),
            sequence: 0,
            flags: Some(8), // tfTransferable
            last_ledger_sequence: None,
            account_txn_id: None,
            memos: None,
            network_id: None,
            signers: None,
            source_tag: None,
            ticket_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        };

        let tx = Transaction::NFTokenMint { common, fields };
        let mut unsigned = UnsignedTransaction::new(tx);

        // Autofill sequence, fee, last_ledger_sequence
        autofill(&client, &mut unsigned).await
            .map_err(|e| ApiError::Xrpl(format!("Autofill error: {}", e)))?;

        // Sign
        let signed = sign_transaction(&unsigned, wallet)
            .map_err(|e| ApiError::Xrpl(format!("Sign error: {}", e)))?;

        let tx_hash = signed.hash().to_string();
        let tx_blob = signed.tx_blob().to_string();

        // Submit and wait for validation via HTTP polling
        self.submit_and_wait_validation(&tx_blob, &tx_hash).await?;

        // Получаем NFT ID из метаданных транзакции - retry несколько раз
        let mut nft_token_id = None;
        for _ in 0..5 {
            if let Ok(tx_meta) = self.rpc("tx", serde_json::json!({
                "transaction": tx_hash,
                "binary": false
            })).await {
                if let Some(id) = extract_nft_id_from_meta(&tx_meta["result"]) {
                    nft_token_id = Some(id);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let nft_token_id = nft_token_id
            .ok_or_else(|| ApiError::Xrpl("NFT ID not found in tx meta".into()))?;

        info!("Minted NFT: {} (tx: {})", nft_token_id, tx_hash);

        Ok(MintResult {
            nft_token_id,
            tx_hash,
        })
    }

    /// Создаёт sell offer для передачи NFT пользователю бесплатно
    pub async fn create_sell_offer(
        &self,
        nft_token_id: &str,
        destination: &str,
    ) -> Result<OfferResult> {
        let wallet = self.wallet.as_ref()
            .ok_or_else(|| ApiError::Xrpl("No wallet".into()))?;

        let client = self.client()?;

        let dest_account: AccountId = destination.parse()
            .map_err(|e| ApiError::Xrpl(format!("Invalid destination: {}", e)))?;

        let nft_id = Hash256::from_hex(nft_token_id)
            .map_err(|e| ApiError::Xrpl(format!("Invalid NFT ID: {}", e)))?;

        let fields = NFTokenCreateOffer {
            nftoken_id: nft_id,
            amount: Amount::Xrp(XrpAmount::from_drops(0).unwrap()),
            owner: None,
            destination: Some(dest_account),
            expiration: None,
        };

        let common = TransactionCommon {
            account: *wallet.account_id(),
            fee: Amount::Xrp(XrpAmount::from_drops(12).unwrap()),
            sequence: 0,
            flags: Some(1), // tfSellNFToken
            last_ledger_sequence: None,
            account_txn_id: None,
            memos: None,
            network_id: None,
            signers: None,
            source_tag: None,
            ticket_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        };

        let tx = Transaction::NFTokenCreateOffer { common, fields };
        let mut unsigned = UnsignedTransaction::new(tx);

        // Autofill
        autofill(&client, &mut unsigned).await
            .map_err(|e| ApiError::Xrpl(format!("Autofill error: {}", e)))?;

        // Sign
        let signed = sign_transaction(&unsigned, wallet)
            .map_err(|e| ApiError::Xrpl(format!("Sign error: {}", e)))?;

        let tx_hash = signed.hash().to_string();
        let tx_blob = signed.tx_blob().to_string();

        // Submit and wait for validation
        self.submit_and_wait_validation(&tx_blob, &tx_hash).await?;

        // Получаем offer index - retry несколько раз
        let mut offer_index = None;
        for _ in 0..5 {
            if let Ok(tx_meta) = self.rpc("tx", serde_json::json!({
                "transaction": tx_hash,
                "binary": false
            })).await {
                if let Some(id) = extract_offer_id_from_meta(&tx_meta["result"]) {
                    offer_index = Some(id);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let offer_index = offer_index
            .ok_or_else(|| ApiError::Xrpl("Offer ID not found".into()))?;

        info!("Created sell offer {} for NFT {} to {}", offer_index, nft_token_id, destination);

        Ok(OfferResult {
            offer_index,
            tx_hash,
        })
    }

    /// Верифицирует владение NFT
    pub async fn verify_nft_owner(
        &self,
        nft_token_id: &str,
        expected_owner: &str,
    ) -> Result<bool> {
        let data = self.rpc("account_nfts", serde_json::json!({
            "account": expected_owner,
            "ledger_index": "validated"
        })).await?;

        if let Some(nfts) = data["result"]["account_nfts"].as_array() {
            for nft in nfts {
                if nft["NFTokenID"].as_str() == Some(nft_token_id) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Отменяет NFT offer (только Oracle может отменить свои offers)
    pub async fn cancel_offer(&self, offer_index: &str) -> Result<String> {
        let wallet = self.wallet.as_ref()
            .ok_or_else(|| ApiError::Xrpl("No wallet".into()))?;

        let client = self.client()?;

        let offer_id = Hash256::from_hex(offer_index)
            .map_err(|e| ApiError::Xrpl(format!("Invalid offer index: {}", e)))?;

        let fields = NFTokenCancelOffer {
            nftoken_offers: vec![offer_id],
        };

        let common = TransactionCommon {
            account: *wallet.account_id(),
            fee: Amount::Xrp(XrpAmount::from_drops(12).unwrap()),
            sequence: 0,
            flags: None,
            last_ledger_sequence: None,
            account_txn_id: None,
            memos: None,
            network_id: None,
            signers: None,
            source_tag: None,
            ticket_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        };

        let tx = Transaction::NFTokenCancelOffer { common, fields };
        let mut unsigned = UnsignedTransaction::new(tx);

        autofill(&client, &mut unsigned).await
            .map_err(|e| ApiError::Xrpl(format!("Autofill error: {}", e)))?;

        let signed = sign_transaction(&unsigned, wallet)
            .map_err(|e| ApiError::Xrpl(format!("Sign error: {}", e)))?;

        let tx_hash = signed.hash().to_string();
        let tx_blob = signed.tx_blob().to_string();

        self.submit_and_wait_validation(&tx_blob, &tx_hash).await?;

        info!("Cancelled offer {} (tx: {})", offer_index, tx_hash);

        Ok(tx_hash)
    }

    /// Сжигает NFT (только владелец NFT может это сделать)
    /// Этот метод используется когда Oracle ещё владеет NFT (до accept offer)
    pub async fn burn_nft(&self, nft_token_id: &str) -> Result<String> {
        let wallet = self.wallet.as_ref()
            .ok_or_else(|| ApiError::Xrpl("No wallet".into()))?;

        let client = self.client()?;

        let nft_id = Hash256::from_hex(nft_token_id)
            .map_err(|e| ApiError::Xrpl(format!("Invalid NFT ID: {}", e)))?;

        let fields = NFTokenBurn {
            nftoken_id: nft_id,
            owner: None, // None когда мы сами владелец
        };

        let common = TransactionCommon {
            account: *wallet.account_id(),
            fee: Amount::Xrp(XrpAmount::from_drops(12).unwrap()),
            sequence: 0,
            flags: None,
            last_ledger_sequence: None,
            account_txn_id: None,
            memos: None,
            network_id: None,
            signers: None,
            source_tag: None,
            ticket_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        };

        let tx = Transaction::NFTokenBurn { common, fields };
        let mut unsigned = UnsignedTransaction::new(tx);

        autofill(&client, &mut unsigned).await
            .map_err(|e| ApiError::Xrpl(format!("Autofill error: {}", e)))?;

        let signed = sign_transaction(&unsigned, wallet)
            .map_err(|e| ApiError::Xrpl(format!("Sign error: {}", e)))?;

        let tx_hash = signed.hash().to_string();
        let tx_blob = signed.tx_blob().to_string();

        self.submit_and_wait_validation(&tx_blob, &tx_hash).await?;

        info!("Burned NFT {} (tx: {})", nft_token_id, tx_hash);

        Ok(tx_hash)
    }

    /// Получает текущего владельца NFT
    /// Проверяет есть ли NFT на Oracle кошельке
    pub async fn check_nft_on_oracle(&self, nft_token_id: &str) -> Result<bool> {
        let oracle_address = self.oracle_address()
            .ok_or_else(|| ApiError::Internal("Oracle wallet not configured".to_string()))?;

        // Получаем все NFT на Oracle кошельке
        let response = self.rpc("account_nfts", serde_json::json!({
            "account": oracle_address,
            "limit": 400
        })).await?;

        // Проверяем есть ли наш NFT в списке
        if let Some(nfts) = response["result"]["account_nfts"].as_array() {
            for nft in nfts {
                if nft["NFTokenID"].as_str() == Some(nft_token_id) {
                    return Ok(true); // NFT на Oracle
                }
            }
        }

        Ok(false) // NFT не на Oracle (claimed или burned)
    }

    /// Получает текущего владельца NFT (legacy метод для совместимости)
    pub async fn get_nft_owner(&self, nft_token_id: &str) -> Result<String> {
        let oracle_address = self.oracle_address()
            .ok_or_else(|| ApiError::Internal("Oracle wallet not configured".to_string()))?;

        // Проверяем есть ли NFT на Oracle
        if self.check_nft_on_oracle(nft_token_id).await? {
            return Ok(oracle_address);
        }

        // NFT не на Oracle - значит был передан или сожжён
        // Возвращаем пустую строку чтобы отличить от Oracle
        Err(ApiError::NftNotFound(nft_token_id.to_string()))
    }
}

/// Извлекает NFTokenID из метаданных транзакции
fn extract_nft_id_from_meta(meta: &serde_json::Value) -> Option<String> {
    // Прямой путь (новый формат)
    if let Some(id) = meta["meta"]["nftoken_id"].as_str() {
        return Some(id.to_string());
    }

    // Через AffectedNodes
    meta["meta"]["AffectedNodes"]
        .as_array()?
        .iter()
        .find_map(|node| {
            // Ищем ModifiedNode с NFTokenPage
            let modified = node.get("ModifiedNode")?;
            let final_fields = modified.get("FinalFields")?;
            let nftokens = final_fields.get("NFTokens")?.as_array()?;

            // Последний токен в списке - новый
            let prev_nftokens = modified.get("PreviousFields")
                .and_then(|pf| pf.get("NFTokens"))
                .and_then(|t| t.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            if nftokens.len() > prev_nftokens {
                nftokens.last()
                    .and_then(|t| t.get("NFToken"))
                    .and_then(|nft| nft.get("NFTokenID"))
                    .and_then(|id| id.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            // Ищем CreatedNode с NFTokenPage
            meta["meta"]["AffectedNodes"]
                .as_array()?
                .iter()
                .find_map(|node| {
                    let created = node.get("CreatedNode")?;
                    let new_fields = created.get("NewFields")?;
                    let nftokens = new_fields.get("NFTokens")?.as_array()?;

                    nftokens.last()
                        .and_then(|t| t.get("NFToken"))
                        .and_then(|nft| nft.get("NFTokenID"))
                        .and_then(|id| id.as_str())
                        .map(|s| s.to_string())
                })
        })
}

/// Извлекает Offer ID из метаданных транзакции
fn extract_offer_id_from_meta(meta: &serde_json::Value) -> Option<String> {
    // Ищем CreatedNode с LedgerEntryType = NFTokenOffer
    meta["meta"]["AffectedNodes"]
        .as_array()?
        .iter()
        .find_map(|node| {
            let created = node.get("CreatedNode")?;
            let entry_type = created.get("LedgerEntryType")?.as_str()?;

            if entry_type == "NFTokenOffer" {
                created.get("LedgerIndex")
                    .and_then(|id| id.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
}