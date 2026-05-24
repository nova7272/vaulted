//! WebSocket клиент для XRPL
//!
//! Подключение к XRPL ноде для отправки транзакций и получения данных.

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::error::{ClientError, Result};

/// XRPL WebSocket клиент
pub struct XrplClient {
    node_url: String,
    request_id: AtomicU64,
    pending_requests: Arc<RwLock<std::collections::HashMap<u64, oneshot::Sender<Value>>>>,
    sender: Option<mpsc::Sender<Message>>,
}

impl XrplClient {
    /// Создаёт новый клиент
    pub fn new(node_url: &str) -> Self {
        Self {
            node_url: node_url.to_string(),
            request_id: AtomicU64::new(1),
            pending_requests: Arc::new(RwLock::new(std::collections::HashMap::new())),
            sender: None,
        }
    }

    /// Подключается к XRPL ноде
    pub async fn connect(&mut self) -> Result<()> {
        let (ws_stream, _) = connect_async(&self.node_url)
            .await
            .map_err(|e| ClientError::WebSocket(e.to_string()))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, mut rx) = mpsc::channel::<Message>(32);

        self.sender = Some(tx);

        let pending = Arc::clone(&self.pending_requests);

        // Обработчик входящих сообщений
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(response) = serde_json::from_str::<Value>(&text) {
                            if let Some(id) = response.get("id").and_then(|v| v.as_u64()) {
                                let mut guard = pending.write().await;
                                if let Some(sender) = guard.remove(&id) {
                                    let _ = sender.send(response);
                                }
                            }
                        }
                    },
                    Ok(Message::Close(_)) => {
                        tracing::info!("XRPL WebSocket closed");
                        break;
                    },
                    Err(e) => {
                        tracing::error!("XRPL WebSocket error: {}", e);
                        break;
                    },
                    _ => {},
                }
            }
        });

        // Обработчик исходящих сообщений
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
        });

        tracing::info!("Connected to XRPL node: {}", self.node_url);
        Ok(())
    }

    /// Отправляет запрос и ждёт ответ
    async fn request(&self, command: &str, params: Value) -> Result<Value> {
        self.request_with_id(command, params)
            .await
            .map(|(_, response)| response)
    }

    async fn request_with_id(&self, command: &str, params: Value) -> Result<(u64, Value)> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let log_submit_transport = command == "submit";

        if log_submit_transport {
            tracing::info!(request_id = id, method = "submit", phase = "started");
        }

        let sender = self.sender.as_ref().ok_or_else(|| {
            let message = "Not connected";
            if log_submit_transport {
                tracing::warn!(
                    request_id = id,
                    method = "submit",
                    phase = "transport_failed",
                    transport_error_kind = "not_connected",
                    transport_error_message = message
                );
            }
            ClientError::Xrpl(message.to_string())
        })?;

        let request = json!({
            "id": id,
            "command": command,
            "api_version": 1,
        });

        // Merge params
        let mut request = request.as_object().unwrap().clone();
        if let Some(obj) = params.as_object() {
            for (k, v) in obj {
                request.insert(k.clone(), v.clone());
            }
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending_requests.write().await;
            guard.insert(id, tx);
        }

        sender
            .send(Message::Text(serde_json::to_string(&request)?))
            .await
            .map_err(|e| {
                let message = safe_transport_error_message(&e.to_string());
                if log_submit_transport {
                    tracing::warn!(
                        request_id = id,
                        method = "submit",
                        phase = "transport_failed",
                        transport_error_kind = classify_transport_error(&message),
                        transport_error_message = %message
                    );
                }
                ClientError::WebSocket(e.to_string())
            })?;

        // Ждём ответ с таймаутом
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                if log_submit_transport {
                    tracing::warn!(
                        request_id = id,
                        method = "submit",
                        phase = "transport_failed",
                        transport_error_kind = "timeout",
                        transport_error_message = "Request timeout",
                        timeout = true
                    );
                }
                ClientError::Xrpl("Request timeout".to_string())
            })?
            .map_err(|_| {
                let message = "Response channel closed";
                if log_submit_transport {
                    tracing::warn!(
                        request_id = id,
                        method = "submit",
                        phase = "transport_failed",
                        transport_error_kind = "websocket_closed",
                        transport_error_message = message
                    );
                }
                ClientError::Xrpl(message.to_string())
            })?;

        // Проверяем на ошибку
        if response.get("error").is_some() {
            if log_submit_transport {
                let fields = extract_xrpl_error_response_fields(&response);
                tracing::warn!(
                    request_id = id,
                    method = "submit",
                    phase = "transport_failed",
                    transport_error_kind = "xrpl_error_response",
                    error = %fields.error,
                    error_code = %fields.error_code,
                    error_message = %fields.error_message,
                    status = %fields.status,
                    transport_error_message = %fields.error_message
                );
            }
            let fields = extract_xrpl_error_response_fields(&response);
            return Err(ClientError::Xrpl(format!(
                "{}: {}",
                fields.error, fields.error_message
            )));
        }

        Ok((id, response))
    }

    /// Получает информацию об аккаунте
    pub async fn account_info(&self, account: &str) -> Result<AccountInfo> {
        let response = self
            .request(
                "account_info",
                json!({
                    "account": account,
                    "ledger_index": "validated"
                }),
            )
            .await?;

        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result in response".to_string()))?;

        let account_data = result
            .get("account_data")
            .ok_or_else(|| ClientError::Xrpl("No account_data".to_string()))?;

        Ok(AccountInfo {
            account: account_data["Account"].as_str().unwrap_or("").to_string(),
            balance: account_data["Balance"].as_str().unwrap_or("0").to_string(),
            sequence: account_data["Sequence"].as_u64().unwrap_or(0) as u32,
        })
    }

    /// Получает NFT токены аккаунта
    pub async fn account_nfts(&self, account: &str) -> Result<Vec<NftToken>> {
        let response = self
            .request(
                "account_nfts",
                json!({
                    "account": account,
                    "ledger_index": "validated"
                }),
            )
            .await?;

        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;

        let nfts = result
            .get("account_nfts")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|nft| {
                        Some(NftToken {
                            nft_token_id: nft.get("NFTokenID")?.as_str()?.to_string(),
                            issuer: nft.get("Issuer")?.as_str()?.to_string(),
                            uri: nft
                                .get("URI")
                                .and_then(|v| v.as_str())
                                .map(|s| hex_to_string(s)),
                            flags: nft.get("Flags")?.as_u64()? as u32,
                            transfer_fee: nft.get("TransferFee").and_then(|v| v.as_u64())
                                as Option<u64>,
                            nft_serial: nft.get("nft_serial")?.as_u64()? as u32,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(nfts)
    }

    /// Проверяет владельца NFT
    pub async fn verify_nft_owner(&self, nft_token_id: &str, expected_owner: &str) -> Result<bool> {
        // Получаем все NFT владельца
        let nfts = self.account_nfts(expected_owner).await?;

        Ok(nfts.iter().any(|nft| nft.nft_token_id == nft_token_id))
    }

    /// Получает sell offers для NFT
    pub async fn nft_sell_offers(&self, nft_id: &str) -> Result<Vec<NftOffer>> {
        let response = self
            .request("nft_sell_offers", json!({ "nft_id": nft_id }))
            .await?;
        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;
        let offers = result
            .get("offers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|o| {
                        Some(NftOffer {
                            offer_index: o.get("nft_offer_index")?.as_str()?.to_string(),
                            owner: o.get("owner")?.as_str()?.to_string(),
                            amount: o.get("amount")?.as_str().unwrap_or("0").to_string(),
                            destination: o
                                .get("destination")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(offers)
    }

    /// Получает информацию о транзакции
    pub async fn tx(&self, tx_hash: &str) -> Result<Value> {
        self.request(
            "tx",
            json!({
                "transaction": tx_hash,
                "binary": false
            }),
        )
        .await
    }

    /// Отправляет подписанную транзакцию
    pub async fn submit(&self, tx_blob: &str) -> Result<SubmitResult> {
        let (request_id, response) = self
            .request_with_id(
                "submit",
                json!({
                    "tx_blob": tx_blob
                }),
            )
            .await?;

        let result = response.get("result").ok_or_else(|| {
            tracing::warn!(
                request_id,
                method = "submit",
                phase = "missing_result",
                transport_error_kind = "missing_result",
                transport_error_message = "No result"
            );
            ClientError::Xrpl("No result".to_string())
        })?;

        let submit_result = parse_submit_result(result);
        let accepted = submit_result.engine_result.starts_with("tes");

        if accepted {
            tracing::info!(
                request_id,
                method = "submit",
                phase = "parsed",
                accepted,
                engine_result = %submit_result.engine_result,
                engine_result_message = %submit_result.engine_result_message,
                tx_hash = %submit_result.tx_hash,
                "XRPL submit accepted"
            );
        } else {
            tracing::warn!(
                request_id,
                method = "submit",
                phase = "parsed",
                accepted,
                engine_result = %submit_result.engine_result,
                engine_result_message = %submit_result.engine_result_message,
                tx_hash = %submit_result.tx_hash,
                "XRPL submit rejected"
            );
        }

        Ok(submit_result)
    }

    /// Returns current validated ledger index.
    pub async fn ledger_current_index(&self) -> Result<u32> {
        let response = self.request("ledger_current", json!({})).await?;
        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;
        let index = result
            .get("ledger_current_index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ClientError::Xrpl("No ledger_current_index".to_string()))?;
        Ok(index as u32)
    }

    /// Returns a conservative transaction fee in drops.
    pub async fn fee_drops(&self) -> Result<String> {
        let response = self.request("fee", json!({})).await?;
        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;
        let drops = result
            .get("drops")
            .and_then(|v| v.get("open_ledger_fee"))
            .or_else(|| result.get("drops").and_then(|v| v.get("minimum_fee")))
            .and_then(|v| v.as_str())
            .unwrap_or("12");
        Ok(drops.to_string())
    }

    /// Attempts to extract the minted NFTokenID from a validated transaction metadata response.
    pub async fn extract_minted_nftoken_id(&self, tx_hash: &str) -> Result<Option<String>> {
        let response = self.tx(tx_hash).await?;
        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;
        Ok(extract_minted_nftoken_id_from_tx_result(result))
    }

    /// Получает текущий fee
    pub async fn server_info(&self) -> Result<ServerInfo> {
        let response = self.request("server_info", json!({})).await?;

        let result = response
            .get("result")
            .ok_or_else(|| ClientError::Xrpl("No result".to_string()))?;

        let info = result
            .get("info")
            .ok_or_else(|| ClientError::Xrpl("No info".to_string()))?;

        let fee = info
            .get("validated_ledger")
            .and_then(|vl| vl.get("base_fee_xrp"))
            .and_then(|f| f.as_f64())
            .unwrap_or(0.00001);

        Ok(ServerInfo {
            build_version: info["build_version"].as_str().unwrap_or("").to_string(),
            network_id: info.get("network_id").and_then(|n| n.as_u64()) as Option<u64>,
            base_fee_xrp: fee,
        })
    }
}

/// Информация об аккаунте
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account: String,
    pub balance: String,
    pub sequence: u32,
}

/// NFT токен
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftToken {
    pub nft_token_id: String,
    pub issuer: String,
    pub uri: Option<String>,
    pub flags: u32,
    pub transfer_fee: Option<u64>,
    pub nft_serial: u32,
}
/// NFT offer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftOffer {
    pub offer_index: String,
    pub owner: String,
    pub amount: String,
    pub destination: Option<String>,
}

/// Результат отправки транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    pub engine_result: String,
    pub engine_result_message: String,
    pub tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XrplErrorResponseFields {
    error: String,
    error_code: String,
    error_message: String,
    status: String,
}

fn extract_xrpl_error_response_fields(response: &Value) -> XrplErrorResponseFields {
    XrplErrorResponseFields {
        error: top_level_safe_field(response, "error").unwrap_or_else(|| "unknown".to_string()),
        error_code: top_level_safe_field(response, "error_code").unwrap_or_default(),
        error_message: top_level_safe_field(response, "error_message")
            .unwrap_or_else(|| "Unknown".to_string()),
        status: top_level_safe_field(response, "status").unwrap_or_default(),
    }
}

fn top_level_safe_field(response: &Value, field: &str) -> Option<String> {
    let value = response.get(field)?;
    let text = if let Some(text) = value.as_str() {
        text.to_string()
    } else if let Some(number) = value.as_i64() {
        number.to_string()
    } else if let Some(number) = value.as_u64() {
        number.to_string()
    } else if let Some(boolean) = value.as_bool() {
        boolean.to_string()
    } else {
        return None;
    };

    Some(safe_transport_error_message(&text))
}

fn parse_submit_result(result: &Value) -> SubmitResult {
    let engine_result = result["engine_result"].as_str().unwrap_or("").to_string();
    let engine_result_message = result["engine_result_message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let tx_hash = result
        .get("tx_json")
        .and_then(|tx| tx.get("hash"))
        .or_else(|| result.get("hash"))
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();

    SubmitResult {
        engine_result,
        engine_result_message,
        tx_hash,
    }
}

fn classify_transport_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timeout") {
        "timeout"
    } else if lower.contains("closed") || lower.contains("close") {
        "websocket_closed"
    } else if lower.contains("websocket")
        || lower.contains("connection")
        || lower.contains("io error")
    {
        "websocket_error"
    } else if lower.contains("not connected") {
        "not_connected"
    } else {
        "transport_error"
    }
}

fn safe_transport_error_message(message: &str) -> String {
    const MAX_MESSAGE_LEN: usize = 240;
    let mut safe = message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();

    for forbidden in [
        "tx_blob",
        "txBlob",
        "tx_json",
        "txJson",
        "seed",
        "Seed",
        "private key",
        "private_key",
        "Private key",
        "jwt",
        "JWT",
        "aes key",
        "aes_key",
        "AES key",
        "plaintext",
        "plain text",
        "recovery phrase",
        "Recovery phrase",
        "mnemonic entropy",
    ] {
        safe = safe.replace(forbidden, "[redacted]");
    }

    if safe.len() > MAX_MESSAGE_LEN {
        safe.truncate(MAX_MESSAGE_LEN);
    }

    safe
}

/// Информация о сервере
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub build_version: String,
    pub network_id: Option<u64>,
    pub base_fee_xrp: f64,
}

fn extract_minted_nftoken_id_from_tx_result(result: &Value) -> Option<String> {
    let meta = result
        .get("meta")
        .or_else(|| result.get("metaData"))
        .or_else(|| result.get("metadata"))?;
    let affected_nodes = meta.get("AffectedNodes")?.as_array()?;

    for node in affected_nodes {
        let created = node.get("CreatedNode")?;
        let ledger_entry_type = created.get("LedgerEntryType")?.as_str()?;
        if ledger_entry_type != "NFTokenPage" {
            continue;
        }
        let fields = created.get("NewFields")?;
        let tokens = fields.get("NFTokens")?.as_array()?;
        for token in tokens {
            let id = token
                .get("NFToken")
                .and_then(|v| v.get("NFTokenID"))
                .and_then(|v| v.as_str())?;
            return Some(id.to_string());
        }
    }

    None
}

/// Конвертирует hex строку в обычную строку
fn hex_to_string(hex: &str) -> String {
    hex::decode(hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_string() {
        let hex = "48656C6C6F"; // "Hello"
        assert_eq!(hex_to_string(hex), "Hello");
    }

    #[test]
    fn test_hex_to_string_empty() {
        assert_eq!(hex_to_string(""), "");
    }

    #[test]
    fn test_extract_minted_nftoken_id() {
        let result = json!({
            "meta": {
                "AffectedNodes": [{
                    "CreatedNode": {
                        "LedgerEntryType": "NFTokenPage",
                        "NewFields": {
                            "NFTokens": [{
                                "NFToken": {"NFTokenID": "00080000ABC"}
                            }]
                        }
                    }
                }]
            }
        });
        assert_eq!(
            extract_minted_nftoken_id_from_tx_result(&result),
            Some("00080000ABC".to_string())
        );
    }

    #[test]
    fn test_parse_submit_result_accepted_with_tx_json_hash() {
        let result = json!({
            "engine_result": "tesSUCCESS",
            "engine_result_message": "The transaction was applied.",
            "tx_json": {
                "hash": "ABC123"
            }
        });

        let parsed = parse_submit_result(&result);

        assert_eq!(parsed.engine_result, "tesSUCCESS");
        assert_eq!(parsed.engine_result_message, "The transaction was applied.");
        assert_eq!(parsed.tx_hash, "ABC123");
    }

    #[test]
    fn test_parse_submit_result_rejected_with_top_level_hash() {
        let result = json!({
            "engine_result": "tecINSUFF_RESERVE",
            "engine_result_message": "Insufficient reserve to complete transaction.",
            "hash": "DEF456"
        });

        let parsed = parse_submit_result(&result);

        assert_eq!(parsed.engine_result, "tecINSUFF_RESERVE");
        assert_eq!(
            parsed.engine_result_message,
            "Insufficient reserve to complete transaction."
        );
        assert_eq!(parsed.tx_hash, "DEF456");
    }

    #[test]
    fn test_extract_xrpl_error_response_fields() {
        let response = json!({
            "id": 1,
            "status": "error",
            "error": "invalidParams",
            "error_code": 31,
            "error_message": "Malformed request"
        });

        let fields = extract_xrpl_error_response_fields(&response);

        assert_eq!(fields.error, "invalidParams");
        assert_eq!(fields.error_code, "31");
        assert_eq!(fields.error_message, "Malformed request");
        assert_eq!(fields.status, "error");
    }

    #[test]
    fn test_extract_xrpl_error_response_fields_handles_missing_fields() {
        let fields = extract_xrpl_error_response_fields(&json!({ "id": 1 }));

        assert_eq!(fields.error, "unknown");
        assert_eq!(fields.error_code, "");
        assert_eq!(fields.error_message, "Unknown");
        assert_eq!(fields.status, "");
    }

    #[test]
    fn test_extract_xrpl_error_response_fields_ignores_nested_forbidden_fields() {
        let response = json!({
            "id": 1,
            "status": "error",
            "error": "invalidParams",
            "error_code": "31",
            "error_message": "Malformed request",
            "request": {
                "tx_blob": "SECRET_TX_BLOB",
                "params": {
                    "tx_json": "SECRET_TX_JSON"
                }
            }
        });

        let fields = extract_xrpl_error_response_fields(&response);
        let combined = format!(
            "{} {} {} {}",
            fields.error, fields.error_code, fields.error_message, fields.status
        );

        assert_eq!(fields.error_code, "31");
        assert!(!combined.contains("SECRET_TX_BLOB"));
        assert!(!combined.contains("SECRET_TX_JSON"));
        assert!(!combined.contains("tx_blob"));
        assert!(!combined.contains("tx_json"));
    }

    #[test]
    fn test_classify_transport_error() {
        assert_eq!(classify_transport_error("Request timeout"), "timeout");
        assert_eq!(
            classify_transport_error("Response channel closed"),
            "websocket_closed"
        );
        assert_eq!(
            classify_transport_error("WebSocket protocol error"),
            "websocket_error"
        );
    }

    #[test]
    fn test_safe_transport_error_message_redacts_sensitive_payload_terms() {
        let safe = safe_transport_error_message(
            "server rejected tx_blob and tx_json with seed and private key fields",
        );

        assert!(!safe.contains("tx_blob"));
        assert!(!safe.contains("tx_json"));
        assert!(!safe.contains("seed"));
        assert!(!safe.contains("private key"));
        assert!(safe.contains("[redacted]"));
    }
}
