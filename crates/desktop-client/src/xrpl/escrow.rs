//! Escrow операции на XRPL
//!
//! Используется для безопасной передачи NFT с гарантией оплаты.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use super::client::XrplClient;

/// Операции с Escrow
pub struct EscrowOperations<'a> {
    #[allow(dead_code)]
    client: &'a XrplClient,
}

impl<'a> EscrowOperations<'a> {
    /// Создаёт новый объект операций
    pub fn new(client: &'a XrplClient) -> Self {
        Self { client }
    }

    /// Создаёт данные для EscrowCreate транзакции
    pub fn create_escrow_transaction(
        &self,
        request: &CreateEscrowRequest,
    ) -> EscrowCreateTransaction {
        let cancel_after_ripple = unix_to_ripple_time(request.cancel_after_unix);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let finish_after_ripple = unix_to_ripple_time(now_unix + 60);

        EscrowCreateTransaction {
            transaction_type: "EscrowCreate".to_string(),
            account: request.sender.clone(),
            destination: request.destination.clone(),
            amount: request.amount_drops.clone(),
            finish_after: Some(finish_after_ripple),
            cancel_after: Some(cancel_after_ripple),
            condition: request.condition.clone(),
            destination_tag: request.destination_tag,
        }
    }

    /// Создаёт данные для EscrowFinish транзакции
    pub fn create_finish_transaction(
        &self,
        request: &FinishEscrowRequest,
    ) -> EscrowFinishTransaction {
        EscrowFinishTransaction {
            transaction_type: "EscrowFinish".to_string(),
            account: request.account.clone(),
            owner: request.escrow_owner.clone(),
            offer_sequence: request.escrow_sequence,
            condition: request.condition.clone(),
            fulfillment: request.fulfillment.clone(),
        }
    }

    /// Создаёт данные для EscrowCancel транзакции
    pub fn create_cancel_transaction(
        &self,
        request: &CancelEscrowRequest,
    ) -> EscrowCancelTransaction {
        EscrowCancelTransaction {
            transaction_type: "EscrowCancel".to_string(),
            account: request.account.clone(),
            owner: request.escrow_owner.clone(),
            offer_sequence: request.escrow_sequence,
        }
    }

    /// Получает информацию об Escrow по owner и sequence
    /// TODO: Реализовать после добавления публичного метода request в XrplClient
    pub async fn get_escrow_info(
        &self,
        _owner: &str,
        _sequence: u32,
    ) -> Result<Option<EscrowInfo>> {
        Ok(None)
    }

    /// Проверяет, можно ли завершить Escrow
    pub fn can_finish(&self, escrow: &EscrowInfo) -> bool {
        let now_ripple = current_ripple_time();
        match escrow.finish_after {
            Some(finish_after) => now_ripple >= finish_after,
            None => true,
        }
    }

    /// Проверяет, можно ли отменить Escrow
    pub fn can_cancel(&self, escrow: &EscrowInfo) -> bool {
        let now_ripple = current_ripple_time();
        match escrow.cancel_after {
            Some(cancel_after) => now_ripple >= cancel_after,
            None => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEscrowRequest {
    pub sender: String,
    pub destination: String,
    pub amount_drops: String,
    pub cancel_after_unix: u64,
    pub condition: Option<String>,
    pub destination_tag: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishEscrowRequest {
    pub account: String,
    pub escrow_owner: String,
    pub escrow_sequence: u32,
    pub condition: Option<String>,
    pub fulfillment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelEscrowRequest {
    pub account: String,
    pub escrow_owner: String,
    pub escrow_sequence: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowCreateTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "FinishAfter", skip_serializing_if = "Option::is_none")]
    pub finish_after: Option<u64>,
    #[serde(rename = "CancelAfter", skip_serializing_if = "Option::is_none")]
    pub cancel_after: Option<u64>,
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(rename = "DestinationTag", skip_serializing_if = "Option::is_none")]
    pub destination_tag: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowFinishTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Owner")]
    pub owner: String,
    #[serde(rename = "OfferSequence")]
    pub offer_sequence: u32,
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(rename = "Fulfillment", skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowCancelTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Owner")]
    pub owner: String,
    #[serde(rename = "OfferSequence")]
    pub offer_sequence: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowInfo {
    pub owner: String,
    pub sequence: u32,
    pub destination: String,
    pub amount_drops: String,
    pub condition: Option<String>,
    pub finish_after: Option<u64>,
    pub cancel_after: Option<u64>,
}

impl EscrowInfo {
    pub fn amount_xrp(&self) -> f64 {
        drops_to_xrp(&self.amount_drops)
    }

    pub fn is_expired(&self) -> bool {
        if let Some(cancel_after) = self.cancel_after {
            current_ripple_time() >= cancel_after
        } else {
            false
        }
    }
}

pub fn xrp_to_drops(xrp: f64) -> String {
    ((xrp * 1_000_000.0) as u64).to_string()
}

pub fn drops_to_xrp(drops: &str) -> f64 {
    drops.parse::<u64>().unwrap_or(0) as f64 / 1_000_000.0
}

pub fn unix_to_ripple_time(unix_timestamp: u64) -> u64 {
    const RIPPLE_EPOCH: u64 = 946684800;
    unix_timestamp.saturating_sub(RIPPLE_EPOCH)
}

pub fn ripple_to_unix_time(ripple_timestamp: u64) -> u64 {
    const RIPPLE_EPOCH: u64 = 946684800;
    ripple_timestamp + RIPPLE_EPOCH
}

pub fn current_ripple_time() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    unix_to_ripple_time(now)
}
