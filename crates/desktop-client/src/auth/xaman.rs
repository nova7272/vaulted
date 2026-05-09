//! Интеграция с Xaman (XUMM) API
//!
//! ## Auth Flow с деривацией PRE ключей
//!
//! 1. SignIn — пользователь подтверждает личность, получаем wallet_address
//! 2. Sign Challenge — пользователь подписывает challenge, получаем signature  
//! 3. Деривация PRE — из signature детерминистично генерируем PRE keypair
//!
//! ## Безопасность
//! - Приватный ключ НИКОГДА не покидает Xaman
//! - Одна и та же подпись = одни и те же PRE ключи на любом устройстве

use reqwest::Client;
use serde::{Deserialize, Serialize};

use xrpl_vault_crypto_core::KeyDerivation;

use crate::error::{ClientError, Result};
use super::Session;

/// Default local Oracle URL for the Xaman proxy.
const DEFAULT_ORACLE_URL: &str = "http://127.0.0.1:3000";

/// Клиент для работы с Xaman API
pub struct XamanAuth {
    http_client: Client,
    oracle_url: String,
}

impl XamanAuth {
    /// Создаёт новый клиент Xaman
    pub fn new(_api_key: String, _api_secret: String) -> Self {
        let oracle_url = std::env::var("ORACLE_URL")
            .unwrap_or_else(|_| DEFAULT_ORACLE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        Self {
            http_client: Client::new(),
            oracle_url,
        }
    }

    /// Шаг 1: Создаёт SignIn payload для QR-авторизации
    pub async fn create_sign_in_request(&self) -> Result<XamanPayload> {
        let request = XamanSignInRequest {
            txjson: SignInTransaction {
                transaction_type: "SignIn".to_string(),
            },
            options: PayloadOptions {
                submit: false,
                expire: 5,
                return_url: None,
            },
            custom_meta: CustomMeta {
                identifier: "xrpl-vault-auth".to_string(),
                instruction: "Sign in to XRPL Vault".to_string(),
            },
        };

        self.create_payload(request).await
    }

    /// Шаг 2: Создаёт запрос на подпись challenge для деривации PRE ключей
    pub async fn create_key_derivation_request(&self, wallet_address: &str) -> Result<XamanPayload> {
        let challenge = KeyDerivation::get_challenge_for_wallet(wallet_address);

        // Используем Payment с 0 XRP к самому себе + Memo с challenge
        // Это позволяет получить реальную подпись (SignIn не возвращает signature)
        let request = serde_json::json!({
            "txjson": {
                "TransactionType": "Payment",
                "Destination": wallet_address,
                "Amount": "0",
                "Memos": [{
                    "Memo": {
                        "MemoType": hex::encode("xrpl-vault/key-derivation"),
                        "MemoData": hex::encode(&challenge)
                    }
                }]
            },
            "options": {
                "submit": false,  // НЕ отправляем в блокчейн!
                "expire": 5
            },
            "custom_meta": {
                "identifier": "xrpl-vault-key-derivation",
                "instruction": "Sign to generate your encryption keys. This will NOT be submitted to the blockchain."
            }
        });

        let response = self
            .http_client
            .post(format!("{}/api/v1/xaman/payload", self.oracle_url))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ClientError::Xaman(format!(
                "Failed to create key derivation payload: {}",
                error_text
            )));
        }

        let payload: XamanPayloadResponse = response.json().await?;

        // Fetch QR PNG and convert to base64 data URL
        let qr_png_url = payload.refs.qr_png.clone();
        let qr_base64 = match self.http_client.get(&qr_png_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.bytes().await {
                    Ok(bytes) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        format!("data:image/png;base64,{}", b64)
                    }
                    Err(_) => qr_png_url.clone(),
                }
            }
            _ => qr_png_url.clone(),
        };

        Ok(XamanPayload {
            uuid: payload.uuid,
            qr_png: qr_base64,
            qr_uri: payload.refs.qr_uri_quality_opts
                .first()
                .cloned()
                .unwrap_or(qr_png_url),
            websocket_url: payload.refs.websocket_status,
            expires_at: payload.expires_at,
        })
    }

    /// Ожидает SignIn и возвращает Session + signature для деривации PRE ключей
    pub async fn wait_for_sign_in(
        &self,
        payload: &XamanPayload,
        session_duration_hours: i64,
    ) -> Result<SignInResult> {
        let result = self.wait_for_payload(payload).await?;

        // SignIn возвращает signature в поле hex
        let signature_hex = result.txn_signature.ok_or_else(|| {
            ClientError::Auth("No signature in SignIn response".to_string())
        })?;

        let session = Session::new(
            result.wallet_address,
            result.public_key.unwrap_or_default(),
            payload.uuid.clone(),
            session_duration_hours,
        );

        Ok(SignInResult {
            session,
            signature_hex,
        })
    }

    /// Ожидает подпись challenge и возвращает signature
    pub async fn wait_for_key_derivation(&self, payload: &XamanPayload) -> Result<KeyDerivationResult> {
        let result = self.wait_for_payload(payload).await?;

        let signature = result.txn_signature.ok_or_else(|| {
            ClientError::Auth("No signature in response".to_string())
        })?;

        Ok(KeyDerivationResult {
            wallet_address: result.wallet_address,
            signature,
        })
    }

    /// Ожидает подписания payload и возвращает результат
    pub async fn wait_for_signature(&self, payload: &XamanPayload, timeout_secs: u64) -> Result<PayloadResult> {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            self.wait_for_payload(payload),
        ).await {
            Ok(result) => result,
            Err(_) => Err(ClientError::Auth("Request timed out — QR code expired".to_string())),
        }
    }

    /// Внутренний метод: ожидает завершения любого payload
    async fn wait_for_payload(&self, payload: &XamanPayload) -> Result<PayloadResult> {
        use futures_util::StreamExt;
        use tokio_tungstenite::{connect_async, tungstenite::Message};

        let (ws_stream, _) = connect_async(&payload.websocket_url)
            .await
            .map_err(|e| ClientError::WebSocket(e.to_string()))?;

        let (_write, mut read) = ws_stream.split();

        tracing::info!("Connected to Xaman WebSocket, waiting...");

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    tracing::info!("Raw WS: {}", text);
                    let ws_msg: WebSocketMessage = serde_json::from_str(&text)?;

                    if ws_msg.signed == Some(true) {
                        return self.get_payload_result(&payload.uuid).await;
                    }
                    match ws_msg.message.as_deref().unwrap_or("") {
                        "signed" => {
                            return self.get_payload_result(&payload.uuid).await;
                        }
                        "rejected" | "expired" => {
                            return Err(ClientError::Auth(
                                "Request was rejected or expired".to_string(),
                            ));
                        }
                        _ => {
                            tracing::debug!("WebSocket message: {:?}", ws_msg.message);
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    return Err(ClientError::WebSocket("Connection closed".to_string()));
                }
                Err(e) => {
                    return Err(ClientError::WebSocket(e.to_string()));
                }
                _ => {}
            }
        }

        Err(ClientError::WebSocket("Connection ended unexpectedly".to_string()))
    }

    /// Получает результат payload через API
    async fn get_payload_result(&self, uuid: &str) -> Result<PayloadResult> {
        let response = self
            .http_client
            .get(format!("{}/api/v1/xaman/payload/{}", self.oracle_url, uuid))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ClientError::Xaman(format!(
                "Failed to get payload: {}",
                error_text
            )));
        }

        let text = response.text().await?;
        tracing::info!("Payload status response: {}", text);
        let status: PayloadStatusResponse = serde_json::from_str(&text)?;

        if !status.meta.signed {
            return Err(ClientError::Auth("Payload not signed".to_string()));
        }

        // A Xaman payload can be signed by the user but still fail on XRPL submit.
        // Example: tecOBJECT_NOT_FOUND when a TESTNET offer is submitted on MAINNET.
        if let Some(ref response) = status.response {
            if let Some(ref dispatched_result) = response.dispatched_result {
                if !dispatched_result.is_empty() && dispatched_result != "tesSUCCESS" {
                    return Err(ClientError::Xaman(format!(
                        "XRPL transaction failed: {} on {:?}/{:?}",
                        dispatched_result,
                        response.dispatched_nodetype,
                        response.environment_nodetype,
                    )));
                }
            }
        }

        let response_data = status.response.ok_or_else(|| {
            ClientError::Auth("No response data".to_string())
        })?;

        // Use hex as signature if txn_signature is not available
        let signature = response_data.txn_signature.or(response_data.hex.clone());

        // Extract real XRPL public key from signed transaction hex.
        // The hex contains serialized XRPL tx where "7321" prefix marks
        // the SigningPubKey field (0x73 = type, 0x21 = 33 bytes length),
        // followed by 66 hex chars = 33-byte compressed secp256k1 pubkey.
        // response_data.signer is just the r-address, NOT a crypto pubkey.
        let public_key = response_data.hex.as_deref()
            .and_then(|hex| {
                if let Some(pos) = hex.find("7321") {
                    let start = pos + 4; // skip "7321"
                    let end = start + 66; // 33 bytes = 66 hex chars
                    if hex.len() >= end {
                        let pk = hex[start..end].to_string();
                        tracing::info!("Extracted XRPL public key from hex: {}...{}", &pk[..8], &pk[pk.len()-8..]);
                        Some(pk)
                    } else {
                        tracing::warn!("Hex too short to extract pubkey: len={}", hex.len());
                        None
                    }
                } else {
                    tracing::warn!("No SigningPubKey (7321) found in hex response");
                    None
                }
            });

        Ok(PayloadResult {
            wallet_address: response_data.account,
            public_key,
            txn_signature: signature,
            txid: response_data.txid.unwrap_or_default(),
        })
    }

    /// Создаёт payload и возвращает XamanPayload
    pub async fn create_payload<T: Serialize>(&self, request: T) -> Result<XamanPayload> {
        let mut request_value = serde_json::to_value(&request)
            .map_err(|e| ClientError::Xaman(format!("Failed to serialize Xaman payload: {}", e)))?;

        // Force Xaman to use the same network as the local Oracle/XRPL config.
        // Without this, Xaman may submit AcceptOffer to MAINNET while Oracle created
        // the NFT offer on TESTNET, causing tecOBJECT_NOT_FOUND.
        if let Ok(force_network) = std::env::var("XAMAN_FORCE_NETWORK") {
            if !force_network.trim().is_empty() {
                if let Some(obj) = request_value.as_object_mut() {
                    let options = obj
                        .entry("options")
                        .or_insert_with(|| serde_json::json!({}));

                    if let Some(options_obj) = options.as_object_mut() {
                        options_obj.insert(
                            "force_network".to_string(),
                            serde_json::Value::String(force_network),
                        );
                    }
                }
            }
        }

        let response = self
            .http_client
            .post(format!("{}/api/v1/xaman/payload", self.oracle_url))
            .header("Content-Type", "application/json")
            .json(&request_value)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ClientError::Xaman(format!(
                "Failed to create payload: {}",
                error_text
            )));
        }

        let payload: XamanPayloadResponse = response.json().await?;

        // Fetch QR PNG and convert to base64 data URL
        // (Tauri webview may block external image loading)
        let qr_png_url = payload.refs.qr_png.clone();
        let qr_base64 = match self.http_client.get(&qr_png_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.bytes().await {
                    Ok(bytes) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        format!("data:image/png;base64,{}", b64)
                    }
                    Err(_) => qr_png_url.clone(),
                }
            }
            _ => qr_png_url.clone(),
        };

        Ok(XamanPayload {
            uuid: payload.uuid,
            qr_png: qr_base64,
            qr_uri: payload.refs.qr_uri_quality_opts
                .first()
                .cloned()
                .unwrap_or(qr_png_url),
            websocket_url: payload.refs.websocket_status,
            expires_at: payload.expires_at,
        })
    }
}

// ==================== Request Types ====================

#[derive(Debug, Serialize)]
struct XamanSignInRequest {
    txjson: SignInTransaction,
    options: PayloadOptions,
    custom_meta: CustomMeta,
}

#[derive(Debug, Serialize)]
struct SignInTransaction {
    #[serde(rename = "TransactionType")]
    transaction_type: String,
}

#[derive(Debug, Serialize)]
struct PayloadOptions {
    submit: bool,
    expire: u32,
    return_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct CustomMeta {
    identifier: String,
    instruction: String,
}

// ==================== Response Types ====================

#[derive(Debug, Deserialize)]
struct XamanPayloadResponse {
    uuid: String,
    refs: PayloadRefs,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PayloadRefs {
    qr_png: String,
    #[serde(default)]
    qr_uri_quality_opts: Vec<String>,
    websocket_status: String,
}

#[derive(Debug, Deserialize)]
struct PayloadStatusResponse {
    meta: PayloadMeta,
    response: Option<PayloadResponseData>,
}

#[derive(Debug, Deserialize)]
struct PayloadMeta {
    signed: bool,
    #[allow(dead_code)]
    cancelled: bool,
    #[allow(dead_code)]
    expired: bool,
}

#[derive(Debug, Deserialize)]
struct PayloadResponseData {
    account: String,
    signer: Option<String>,
    #[serde(rename = "txnSignature")]
    txn_signature: Option<String>,
    hex: Option<String>,
    txid: Option<String>,

    #[serde(default)]
    dispatched_result: Option<String>,
    #[serde(default)]
    dispatched_nodetype: Option<String>,
    #[serde(default)]
    environment_nodetype: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebSocketMessage {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    signed: Option<bool>,
    #[serde(default)]
    opened: Option<bool>,
}

// ==================== Public Types ====================

/// Payload для отображения пользователю
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XamanPayload {
    pub uuid: String,

    pub qr_png: String,

    pub qr_uri: String,

    pub websocket_url: String,

    pub expires_at: Option<String>,
}

/// Результат payload
#[derive(Debug, Clone)]
pub struct PayloadResult {
    pub wallet_address: String,
    pub public_key: Option<String>,
    pub txn_signature: Option<String>,
    pub txid: String,
}

/// Результат деривации ключей
#[derive(Debug)]
pub struct KeyDerivationResult {
    pub wallet_address: String,
    pub signature: String,
}

/// Результат SignIn с signature для деривации ключей
#[derive(Debug)]
pub struct SignInResult {
    pub session: Session,
    /// Signature (hex) из SignIn — используется для деривации PRE ключей
    pub signature_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation() {
        let challenge = KeyDerivation::get_challenge_for_wallet("rXXXXX");
        assert!(challenge.contains("xrpl-vault"));
        assert!(challenge.contains("rXXXXX"));
    }
}