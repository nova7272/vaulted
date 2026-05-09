//! Replication Service
//!
//! Manages fragment replication across storage nodes.

use sqlx::PgPool;
use serde::{Deserialize, Serialize};

/// Replication settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSettings {
    pub replication_factor: i32,
    pub strategy: String,
    pub min_active_replicas: i32,
}

impl Default for ReplicationSettings {
    fn default() -> Self {
        Self {
            replication_factor: 2,
            strategy: "mixed".to_string(),
            min_active_replicas: 1,
        }
    }
}

/// Storage node info for selection
#[derive(Debug, Clone)]
pub struct NodeCandidate {
    pub id: String,
    pub endpoint_url: String,
    pub region: String,
    pub used_space_bytes: i64,
    pub total_space_bytes: i64,
}

impl NodeCandidate {
    pub fn usage_percent(&self) -> f64 {
        if self.total_space_bytes == 0 {
            return 100.0;
        }
        (self.used_space_bytes as f64 / self.total_space_bytes as f64) * 100.0
    }
}

/// Selected nodes for upload
#[derive(Debug, Clone, Serialize)]
pub struct UploadTarget {
    pub node_id: String,
    pub endpoint_url: String,
    pub region: String,
    pub storage_key: String,
    pub upload_url: String,
}

/// Replication service
pub struct ReplicationService {
    db: PgPool,
}

impl ReplicationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Get replication settings
    pub async fn get_settings(&self) -> Result<ReplicationSettings, sqlx::Error> {
        let row: Option<(i32, String, i32)> = sqlx::query_as(
            "SELECT replication_factor, strategy, min_active_replicas FROM replication_settings WHERE id = 'default'"
        )
            .fetch_optional(&self.db)
            .await?;

        Ok(row.map(|(rf, s, mar)| ReplicationSettings {
            replication_factor: rf,
            strategy: s,
            min_active_replicas: mar,
        }).unwrap_or_default())
    }

    /// Select storage nodes for a new fragment upload
    /// Returns nodes based on replication strategy
    pub async fn select_nodes_for_upload(
        &self,
        fragment_size: i64,
        exclude_regions: Option<Vec<String>>,
    ) -> Result<Vec<NodeCandidate>, sqlx::Error> {
        let settings = self.get_settings().await?;

        // Get all active nodes with enough space
        let mut nodes: Vec<NodeCandidate> = sqlx::query_as::<_, (String, String, String, i64, i64)>(
            r#"
            SELECT id, endpoint_url, region, used_space_bytes, total_space_bytes
            FROM storage_nodes
            WHERE status = 'active'
              AND (total_space_bytes - used_space_bytes) > $1
            ORDER BY region, used_space_bytes ASC
            "#
        )
            .bind(fragment_size)
            .fetch_all(&self.db)
            .await?
            .into_iter()
            .map(|(id, endpoint_url, region, used, total)| NodeCandidate {
                id,
                endpoint_url,
                region,
                used_space_bytes: used,
                total_space_bytes: total,
            })
            .collect();

        // Filter out excluded regions if specified
        if let Some(ref exclude) = exclude_regions {
            nodes.retain(|n| !exclude.contains(&n.region));
        }

        // Apply selection strategy
        let selected = match settings.strategy.as_str() {
            "region_diverse" => self.select_region_diverse(nodes, settings.replication_factor),
            "load_balanced" => self.select_load_balanced(nodes, settings.replication_factor),
            _ => self.select_mixed(nodes, settings.replication_factor), // "mixed" or default
        };

        Ok(selected)
    }

    /// Select nodes prioritizing different regions
    fn select_region_diverse(&self, nodes: Vec<NodeCandidate>, count: i32) -> Vec<NodeCandidate> {
        let mut selected = Vec::new();
        let mut used_regions = std::collections::HashSet::new();

        // First pass: one node per region
        for node in nodes.iter() {
            if selected.len() >= count as usize {
                break;
            }
            if !used_regions.contains(&node.region) {
                selected.push(node.clone());
                used_regions.insert(node.region.clone());
            }
        }

        // Second pass: fill remaining slots with least loaded nodes
        if selected.len() < count as usize {
            let mut remaining: Vec<_> = nodes
                .into_iter()
                .filter(|n| !selected.iter().any(|s| s.id == n.id))
                .collect();
            remaining.sort_by(|a, b| a.usage_percent().partial_cmp(&b.usage_percent()).unwrap());

            for node in remaining {
                if selected.len() >= count as usize {
                    break;
                }
                selected.push(node);
            }
        }

        selected
    }

    /// Select nodes by lowest load
    fn select_load_balanced(&self, mut nodes: Vec<NodeCandidate>, count: i32) -> Vec<NodeCandidate> {
        nodes.sort_by(|a, b| a.usage_percent().partial_cmp(&b.usage_percent()).unwrap());
        nodes.into_iter().take(count as usize).collect()
    }

    /// Mixed strategy: prefer different regions, then balance by load
    fn select_mixed(&self, nodes: Vec<NodeCandidate>, count: i32) -> Vec<NodeCandidate> {
        // Group by region and sort each group by load
        let mut by_region: std::collections::HashMap<String, Vec<NodeCandidate>> = std::collections::HashMap::new();
        for node in nodes {
            by_region.entry(node.region.clone()).or_default().push(node);
        }

        // Sort each region's nodes by load
        for nodes in by_region.values_mut() {
            nodes.sort_by(|a, b| a.usage_percent().partial_cmp(&b.usage_percent()).unwrap());
        }

        let mut selected = Vec::new();
        let mut region_iter: Vec<_> = by_region.into_iter().collect();
        region_iter.sort_by_key(|(_, nodes)| {
            nodes.first().map(|n| n.usage_percent() as i64).unwrap_or(i64::MAX)
        });

        // Round-robin across regions, picking least loaded from each
        let mut indices: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        while selected.len() < count as usize {
            let mut added = false;
            for (region, nodes) in &region_iter {
                if selected.len() >= count as usize {
                    break;
                }
                let idx = indices.entry(region.clone()).or_insert(0);
                if *idx < nodes.len() {
                    selected.push(nodes[*idx].clone());
                    *idx += 1;
                    added = true;
                }
            }
            if !added {
                break; // No more nodes available
            }
        }

        selected
    }

    /// Generate upload targets for a fragment
    pub async fn create_upload_targets(
        &self,
        file_id: &str,
        fragment_index: u32,
        fragment_size: i64,
    ) -> Result<Vec<UploadTarget>, sqlx::Error> {
        let nodes = self.select_nodes_for_upload(fragment_size, None).await?;

        let targets: Vec<UploadTarget> = nodes
            .into_iter()
            .enumerate()
            .map(|(replica_idx, node)| {
                let storage_key = format!(
                    "file_{}_frag_{}_r{}",
                    file_id, fragment_index, replica_idx
                );
                let upload_url = format!("{}/fragments/{}", node.endpoint_url, storage_key);

                UploadTarget {
                    node_id: node.id,
                    endpoint_url: node.endpoint_url,
                    region: node.region,
                    storage_key,
                    upload_url,
                }
            })
            .collect();

        Ok(targets)
    }

    /// Get active replicas for a fragment
    pub async fn get_active_replicas(
        &self,
        fragment_id: &uuid::Uuid,
    ) -> Result<Vec<(String, String, String)>, sqlx::Error> {
        // Returns (node_id, endpoint_url, storage_key)
        let replicas: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT fr.storage_node_id, sn.endpoint_url, fr.storage_key
            FROM fragment_replicas fr
            JOIN storage_nodes sn ON sn.id = fr.storage_node_id
            WHERE fr.fragment_id = $1 
              AND fr.status = 'active'
              AND sn.status = 'active'
            ORDER BY sn.used_space_bytes ASC
            "#
        )
            .bind(fragment_id)
            .fetch_all(&self.db)
            .await?;

        Ok(replicas)
    }

    /// Check replication status for all fragments of a file
    pub async fn check_file_replication(
        &self,
        nft_token_id: &str,
    ) -> Result<FileReplicationStatus, sqlx::Error> {
        let settings = self.get_settings().await?;

        let stats: Vec<(i64, i64)> = sqlx::query_as(
            r#"
            SELECT 
                ff.id,
                COUNT(fr.id) FILTER (WHERE fr.status = 'active') as active_replicas
            FROM file_fragments ff
            JOIN file_manifests fm ON fm.id = ff.manifest_id
            JOIN nft_metadata nm ON nm.id = fm.nft_metadata_id
            LEFT JOIN fragment_replicas fr ON fr.fragment_id = ff.id
            WHERE nm.nft_token_id = $1
            GROUP BY ff.id
            "#
        )
            .bind(nft_token_id)
            .fetch_all(&self.db)
            .await?;

        let total_fragments = stats.len();
        let fully_replicated = stats.iter().filter(|(_, c)| *c >= settings.replication_factor as i64).count();
        let under_replicated = stats.iter().filter(|(_, c)| *c > 0 && *c < settings.replication_factor as i64).count();
        let not_replicated = stats.iter().filter(|(_, c)| *c == 0).count();

        Ok(FileReplicationStatus {
            nft_token_id: nft_token_id.to_string(),
            total_fragments,
            fully_replicated,
            under_replicated,
            not_replicated,
            replication_factor: settings.replication_factor,
            healthy: not_replicated == 0 && under_replicated == 0,
        })
    }

    /// Create replica record
    pub async fn create_replica(
        &self,
        fragment_id: &uuid::Uuid,
        storage_node_id: &str,
        storage_key: &str,
        size_bytes: i64,
        status: &str,
    ) -> Result<uuid::Uuid, sqlx::Error> {
        let replica_id: (uuid::Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO fragment_replicas (fragment_id, storage_node_id, storage_key, size_bytes, status)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (fragment_id, storage_node_id) DO UPDATE SET
                storage_key = EXCLUDED.storage_key,
                size_bytes = EXCLUDED.size_bytes,
                status = EXCLUDED.status,
                updated_at = NOW()
            RETURNING id
            "#
        )
            .bind(fragment_id)
            .bind(storage_node_id)
            .bind(storage_key)
            .bind(size_bytes)
            .bind(status)
            .fetch_one(&self.db)
            .await?;

        Ok(replica_id.0)
    }

    /// Update replica status
    pub async fn update_replica_status(
        &self,
        fragment_id: &uuid::Uuid,
        storage_node_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE fragment_replicas SET status = $3, updated_at = NOW() WHERE fragment_id = $1 AND storage_node_id = $2"
        )
            .bind(fragment_id)
            .bind(storage_node_id)
            .bind(status)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    /// Delete replica (when node is removed or fragment deleted)
    pub async fn delete_replica(
        &self,
        fragment_id: &uuid::Uuid,
        storage_node_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM fragment_replicas WHERE fragment_id = $1 AND storage_node_id = $2"
        )
            .bind(fragment_id)
            .bind(storage_node_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }
}

/// File replication status
#[derive(Debug, Clone, Serialize)]
pub struct FileReplicationStatus {
    pub nft_token_id: String,
    pub total_fragments: usize,
    pub fully_replicated: usize,
    pub under_replicated: usize,
    pub not_replicated: usize,
    pub replication_factor: i32,
    pub healthy: bool,
}