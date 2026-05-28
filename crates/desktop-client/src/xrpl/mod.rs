//! XRPL integration
//!
//! Works with XLS-20 NFTs through a WebSocket connection to an XRPL node.

pub mod client;
pub mod escrow;
mod nft;

pub use client::XrplClient;
pub use escrow::{
    drops_to_xrp, ripple_to_unix_time, unix_to_ripple_time, xrp_to_drops, CreateEscrowRequest,
    EscrowInfo, EscrowOperations,
};
pub use nft::{NftInfo, NftMintRequest, NftOperations};
