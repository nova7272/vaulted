//! XRPL интеграция
//!
//! Работа с XLS-20 NFT через WebSocket подключение к XRPL ноде.

pub mod client;
pub mod escrow;
mod nft;

pub use client::XrplClient;
pub use escrow::{
    CreateEscrowRequest, EscrowInfo, EscrowOperations, 
    xrp_to_drops, drops_to_xrp, unix_to_ripple_time, ripple_to_unix_time,
};
pub use nft::{NftInfo, NftMintRequest, NftOperations};
