//! XRPL Sync Service
//!
//! Periodically synchronizes NFT owners between Oracle and XRPL.
//! Needed when NFTs are transferred outside the app (directly on XRPL).

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::error::Result;
use crate::xrpl::XrplService;

/// Synchronization configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Synchronization interval in seconds
    pub interval_secs: u64,
    /// Maximum number of NFTs per cycle
    pub batch_size: i64,
    /// Whether synchronization is enabled
    pub enabled: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            interval_secs: 300, // 5 minutes
            batch_size: 100,
            enabled: true,
        }
    }
}

/// Synchronization service
pub struct XrplSyncService {
    db: PgPool,
    xrpl: Arc<XrplService>,
    config: SyncConfig,
}

impl XrplSyncService {
    pub fn new(db: PgPool, xrpl: Arc<XrplService>, config: SyncConfig) -> Self {
        Self { db, xrpl, config }
    }

    /// Starts background synchronization
    pub async fn start_background_sync(self: Arc<Self>) {
        if !self.config.enabled {
            info!("XRPL sync disabled");
            return;
        }

        info!(
            "Starting XRPL sync service (interval: {}s, batch: {})",
            self.config.interval_secs, self.config.batch_size
        );

        let mut ticker = interval(Duration::from_secs(self.config.interval_secs));

        loop {
            ticker.tick().await;

            if let Err(e) = self.sync_cycle().await {
                error!("Sync cycle failed: {}", e);
            }
        }
    }

    /// Runs one synchronization cycle
    pub async fn sync_cycle(&self) -> Result<SyncStats> {
        let start = std::time::Instant::now();
        let mut stats = SyncStats::default();

        // Get the list of active NFTs from the database
        let nfts = sqlx::query_as::<_, (uuid::Uuid, String, uuid::Uuid)>(
            r#"
            SELECT nm.id, nm.nft_token_id, nm.owner_id
            FROM nft_metadata nm
            WHERE nm.status = 'active'
            ORDER BY nm.updated_at ASC
            LIMIT $1
            "#,
        )
        .bind(self.config.batch_size)
        .fetch_all(&self.db)
        .await?;

        stats.total = nfts.len();
        info!("Syncing {} NFTs with XRPL", stats.total);

        for (nft_id, nft_token_id, current_owner_id) in nfts {
            match self
                .sync_single_nft(&nft_id, &nft_token_id, &current_owner_id)
                .await
            {
                Ok(SyncAction::NoChange) => stats.unchanged += 1,
                Ok(SyncAction::OwnerUpdated { old, new }) => {
                    stats.updated += 1;
                    info!(
                        "NFT {} owner changed: {} -> {}",
                        &nft_token_id[..16],
                        old,
                        new
                    );
                },
                Ok(SyncAction::NotFoundOnXrpl) => {
                    stats.not_found += 1;
                    warn!("NFT {} not found on XRPL", &nft_token_id[..16]);
                },
                Ok(SyncAction::NewOwnerNotRegistered(addr)) => {
                    stats.unregistered_owners += 1;
                    warn!(
                        "NFT {} new owner {} not registered",
                        &nft_token_id[..16],
                        addr
                    );
                },
                Err(e) => {
                    stats.errors += 1;
                    warn!("Failed to sync NFT {}: {}", &nft_token_id[..16], e);
                },
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "Sync complete: {} total, {} updated, {} unchanged, {} errors ({}ms)",
            stats.total, stats.updated, stats.unchanged, stats.errors, stats.duration_ms
        );

        Ok(stats)
    }

    /// Synchronizes one NFT
    async fn sync_single_nft(
        &self,
        nft_id: &uuid::Uuid,
        nft_token_id: &str,
        current_owner_id: &uuid::Uuid,
    ) -> Result<SyncAction> {
        // Get the current owner wallet address from the Oracle database
        let current_owner_wallet: String =
            sqlx::query_scalar("SELECT wallet_address FROM users WHERE id = $1")
                .bind(current_owner_id)
                .fetch_one(&self.db)
                .await?;

        // Check whether the current owner owns this NFT on XRPL
        let still_owns = self
            .xrpl
            .verify_nft_owner(nft_token_id, &current_owner_wallet)
            .await?;

        if still_owns {
            // Update timestamp for round-robin
            sqlx::query("UPDATE nft_metadata SET updated_at = NOW() WHERE id = $1")
                .bind(nft_id)
                .execute(&self.db)
                .await?;
            return Ok(SyncAction::NoChange);
        }

        // Owner changed - look for the new owner
        // To do this, find who currently owns the NFT
        let new_owner_wallet = self.find_nft_owner_on_xrpl(nft_token_id).await?;

        match new_owner_wallet {
            Some(new_wallet) => {
                // Check whether the new owner is registered in Oracle
                let new_owner_id: Option<uuid::Uuid> =
                    sqlx::query_scalar("SELECT id FROM users WHERE wallet_address = $1")
                        .bind(&new_wallet)
                        .fetch_optional(&self.db)
                        .await?;

                match new_owner_id {
                    Some(new_id) => {
                        // Update the owner in the database
                        // IMPORTANT: do NOT update encrypted_aes_key - this must be done through PRE transfer
                        // Mark the key as stale (the new owner will not be able to decrypt)
                        sqlx::query(
                            r#"
                            UPDATE nft_metadata
                            SET owner_id = $1,
                                status = 'active',
                                updated_at = NOW()
                            WHERE id = $2
                            "#,
                        )
                        .bind(&new_id)
                        .bind(nft_id)
                        .execute(&self.db)
                        .await?;

                        // Log to audit
                        sqlx::query(
                            r#"
                            INSERT INTO audit_log (user_id, action, nft_token_id, details)
                            VALUES ($1, 'xrpl_sync_owner_change', $2, $3)
                            "#,
                        )
                        .bind(&new_id)
                        .bind(nft_token_id)
                        .bind(serde_json::json!({
                            "old_owner_id": current_owner_id.to_string(),
                            "new_owner_wallet": new_wallet,
                            "sync_type": "automatic"
                        }))
                        .execute(&self.db)
                        .await?;

                        Ok(SyncAction::OwnerUpdated {
                            old: current_owner_wallet,
                            new: new_wallet,
                        })
                    },
                    None => {
                        // New owner is not registered - do nothing
                        // They must register in the app first
                        Ok(SyncAction::NewOwnerNotRegistered(new_wallet))
                    },
                }
            },
            None => {
                // NFT not found for anyone - possibly burned or an error occurred
                Ok(SyncAction::NotFoundOnXrpl)
            },
        }
    }

    /// Looks for the current NFT owner on XRPL
    ///
    /// XRPL has no direct API for this, so:
    /// 1. Check all known users from Oracle
    /// 2. If not found, return None
    async fn find_nft_owner_on_xrpl(&self, nft_token_id: &str) -> Result<Option<String>> {
        // Get all wallet addresses from Oracle
        let wallets: Vec<String> = sqlx::query_scalar("SELECT wallet_address FROM users")
            .fetch_all(&self.db)
            .await?;

        for wallet in wallets {
            if self.xrpl.verify_nft_owner(nft_token_id, &wallet).await? {
                return Ok(Some(wallet));
            }
        }

        Ok(None)
    }

    /// Manual synchronization trigger (for API endpoint)
    pub async fn trigger_sync(&self) -> Result<SyncStats> {
        info!("Manual sync triggered");
        self.sync_cycle().await
    }

    /// Synchronizes a specific NFT (for API endpoint)
    pub async fn sync_nft(&self, nft_token_id: &str) -> Result<SyncAction> {
        let nft = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
            "SELECT id, owner_id FROM nft_metadata WHERE nft_token_id = $1",
        )
        .bind(nft_token_id)
        .fetch_optional(&self.db)
        .await?;

        match nft {
            Some((nft_id, owner_id)) => {
                self.sync_single_nft(&nft_id, nft_token_id, &owner_id).await
            },
            None => Ok(SyncAction::NotFoundOnXrpl),
        }
    }
}

/// Single-NFT synchronization result
#[derive(Debug)]
pub enum SyncAction {
    /// Owner did not change
    NoChange,
    /// Owner updated
    OwnerUpdated { old: String, new: String },
    /// NFT not found on XRPL
    NotFoundOnXrpl,
    /// New owner is not registered in Oracle
    NewOwnerNotRegistered(String),
}

/// Synchronization cycle statistics
#[derive(Debug, Default)]
pub struct SyncStats {
    pub total: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub not_found: usize,
    pub unregistered_owners: usize,
    pub errors: usize,
    pub duration_ms: u64,
}

impl SyncStats {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total": self.total,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "not_found": self.not_found,
            "unregistered_owners": self.unregistered_owners,
            "errors": self.errors,
            "duration_ms": self.duration_ms
        })
    }
}
