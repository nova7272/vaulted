//! NFT операции XLS-20
//!
//! Минтинг NFT с метаданными зашифрованных файлов.

use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};
use super::client::XrplClient;

/// Операции с NFT
pub struct NftOperations<'a> {
    client: &'a XrplClient,
}

impl<'a> NftOperations<'a> {
    /// Создаёт новый объект операций
    pub fn new(client: &'a XrplClient) -> Self {
        Self { client }
    }

    /// Проверяет владение NFT
    pub async fn verify_ownership(&self, nft_token_id: &str, wallet_address: &str) -> Result<bool> {
        self.client
            .verify_nft_owner(nft_token_id, wallet_address)
            .await
    }

    /// Получает информацию о NFT
    pub async fn get_nft_info(&self, nft_token_id: &str, owner: &str) -> Result<NftInfo> {
        let nfts = self.client.account_nfts(owner).await?;

        let nft = nfts
            .into_iter()
            .find(|n| n.nft_token_id == nft_token_id)
            .ok_or_else(|| ClientError::NftNotFound(nft_token_id.to_string()))?;

        Ok(NftInfo {
            token_id: nft.nft_token_id,
            owner: owner.to_string(),
            issuer: nft.issuer,
            uri: nft.uri,
            flags: nft.flags,
            transfer_fee: nft.transfer_fee,
            serial: nft.nft_serial,
            is_transferable: (nft.flags & NFT_FLAG_TRANSFERABLE) != 0,
            is_burnable: (nft.flags & NFT_FLAG_BURNABLE) != 0,
        })
    }

    /// Получает все NFT пользователя
    pub async fn list_user_nfts(&self, wallet_address: &str) -> Result<Vec<NftInfo>> {
        let nfts = self.client.account_nfts(wallet_address).await?;

        Ok(nfts
            .into_iter()
            .map(|nft| NftInfo {
                token_id: nft.nft_token_id,
                owner: wallet_address.to_string(),
                issuer: nft.issuer,
                uri: nft.uri,
                flags: nft.flags,
                transfer_fee: nft.transfer_fee,
                serial: nft.nft_serial,
                is_transferable: (nft.flags & NFT_FLAG_TRANSFERABLE) != 0,
                is_burnable: (nft.flags & NFT_FLAG_BURNABLE) != 0,
            })
            .collect())
    }

    /// Создаёт данные для транзакции NFTokenMint
    ///
    /// Транзакция должна быть подписана через Xaman
    pub fn create_mint_transaction(&self, request: &NftMintRequest) -> NftMintTransaction {
        let uri_hex = string_to_hex(&request.uri);

        NftMintTransaction {
            transaction_type: "NFTokenMint".to_string(),
            account: request.issuer.clone(),
            uri: uri_hex,
            flags: request.flags.unwrap_or(NFT_FLAG_TRANSFERABLE),
            transfer_fee: request.transfer_fee,
            nftoken_taxon: request.taxon,
        }
    }

    /// Создаёт данные для транзакции NFTokenCreateOffer (продажа/передача)
    pub fn create_sell_offer_transaction(
        &self,
        owner: &str,
        nft_token_id: &str,
        destination: &str,
        amount: &str, // "0" для бесплатной передачи
    ) -> NftCreateOfferTransaction {
        NftCreateOfferTransaction {
            transaction_type: "NFTokenCreateOffer".to_string(),
            account: owner.to_string(),
            nftoken_id: nft_token_id.to_string(),
            amount: amount.to_string(),
            flags: NFT_OFFER_FLAG_SELL,
            destination: Some(destination.to_string()),
        }
    }

    /// Создаёт данные для принятия offer
    pub fn create_accept_offer_transaction(
        &self,
        buyer: &str,
        sell_offer_id: &str,
    ) -> NftAcceptOfferTransaction {
        NftAcceptOfferTransaction {
            transaction_type: "NFTokenAcceptOffer".to_string(),
            account: buyer.to_string(),
            nftoken_sell_offer: sell_offer_id.to_string(),
        }
    }
}

// NFT Flags (XLS-20)
const NFT_FLAG_BURNABLE: u32 = 0x0001;
const NFT_FLAG_ONLY_XRP: u32 = 0x0002;
const NFT_FLAG_TRANSFERABLE: u32 = 0x0008;

// Offer Flags
const NFT_OFFER_FLAG_SELL: u32 = 0x0001;

/// Информация о NFT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftInfo {
    /// NFT Token ID
    pub token_id: String,
    /// Текущий владелец
    pub owner: String,
    /// Issuer (создатель)
    pub issuer: String,
    /// URI (обычно hash метаданных)
    pub uri: Option<String>,
    /// Flags
    pub flags: u32,
    /// Комиссия при передаче (basis points)
    pub transfer_fee: Option<u64>,
    /// Серийный номер
    pub serial: u32,
    /// Можно ли передавать
    pub is_transferable: bool,
    /// Можно ли сжечь
    pub is_burnable: bool,
}

/// Запрос на минт NFT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMintRequest {
    /// Адрес создателя (issuer)
    pub issuer: String,
    /// URI (hash метаданных: "sha256:...")
    pub uri: String,
    /// Taxon (категория NFT)
    pub taxon: u32,
    /// Flags (по умолчанию: transferable)
    pub flags: Option<u32>,
    /// Комиссия при передаче (0-50000, basis points)
    pub transfer_fee: Option<u32>,
}

impl NftMintRequest {
    /// Создаёт запрос для XRPL Vault NFT
    pub fn for_vault(issuer: &str, metadata_hash: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            uri: metadata_hash.to_string(),
            taxon: XRPL_VAULT_TAXON,
            flags: Some(NFT_FLAG_TRANSFERABLE),
            transfer_fee: None,
        }
    }
}

/// Taxon для XRPL Vault NFT
pub const XRPL_VAULT_TAXON: u32 = 0x5652_4C54; // "VRLT" in hex

/// Транзакция NFTokenMint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMintTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "URI")]
    pub uri: String,
    #[serde(rename = "Flags")]
    pub flags: u32,
    #[serde(rename = "TransferFee", skip_serializing_if = "Option::is_none")]
    pub transfer_fee: Option<u32>,
    #[serde(rename = "NFTokenTaxon")]
    pub nftoken_taxon: u32,
}

/// Транзакция NFTokenCreateOffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCreateOfferTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "NFTokenID")]
    pub nftoken_id: String,
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Flags")]
    pub flags: u32,
    #[serde(rename = "Destination", skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
}

/// Транзакция NFTokenAcceptOffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftAcceptOfferTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "NFTokenSellOffer")]
    pub nftoken_sell_offer: String,
}

/// Конвертирует строку в hex
fn string_to_hex(s: &str) -> String {
    hex::encode(s.as_bytes()).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_request_for_vault() {
        let request = NftMintRequest::for_vault("rXXXX", "sha256:abcd1234");

        assert_eq!(request.issuer, "rXXXX");
        assert_eq!(request.uri, "sha256:abcd1234");
        assert_eq!(request.taxon, XRPL_VAULT_TAXON);
        assert_eq!(request.flags, Some(NFT_FLAG_TRANSFERABLE));
    }

    #[test]
    fn test_string_to_hex() {
        assert_eq!(string_to_hex("Hello"), "48656C6C6F");
        assert_eq!(string_to_hex("sha256:abc"), "7368613235363A616263");
    }

    #[test]
    fn test_nft_flags() {
        let flags = NFT_FLAG_TRANSFERABLE | NFT_FLAG_BURNABLE;
        assert_eq!(flags & NFT_FLAG_TRANSFERABLE, NFT_FLAG_TRANSFERABLE);
        assert_eq!(flags & NFT_FLAG_BURNABLE, NFT_FLAG_BURNABLE);
    }
}
