//! Storage node coordination
//!
//! Manages fragment distribution across storage backends.

use sqlx::PgPool;

use crate::error::Result;
use crate::models::StorageNode;

/// Storage management service
pub struct StorageService {
    db: PgPool,
}

impl StorageService {
    /// Creates a new service
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Gets the list of active storage nodes
    pub async fn get_active_nodes(&self) -> Result<Vec<StorageNode>> {
        let nodes = sqlx::query_as::<_, StorageNode>(
            r#"
            SELECT id, endpoint_url, region, status, total_space_bytes, 
                   used_space_bytes, last_health_check, health_check_failures,
                   created_at, updated_at
            FROM storage_nodes
            WHERE status = 'active'
            ORDER BY (used_space_bytes::float / NULLIF(total_space_bytes, 0)) ASC
            "#,
        )
        .fetch_all(&self.db)
        .await?;

        Ok(nodes)
    }

    /// Selects the optimal node for upload
    pub async fn select_node_for_upload(
        &self,
        region_hint: Option<&str>,
    ) -> Result<Option<StorageNode>> {
        let query = if let Some(region) = region_hint {
            sqlx::query_as::<_, StorageNode>(
                r#"
                SELECT id, endpoint_url, region, status, total_space_bytes,
                       used_space_bytes, last_health_check, health_check_failures,
                       created_at, updated_at
                FROM storage_nodes
                WHERE status = 'active' AND region = $1
                ORDER BY (used_space_bytes::float / NULLIF(total_space_bytes, 0)) ASC
                LIMIT 1
                "#,
            )
            .bind(region)
        } else {
            sqlx::query_as::<_, StorageNode>(
                r#"
                SELECT id, endpoint_url, region, status, total_space_bytes,
                       used_space_bytes, last_health_check, health_check_failures,
                       created_at, updated_at
                FROM storage_nodes
                WHERE status = 'active'
                ORDER BY (used_space_bytes::float / NULLIF(total_space_bytes, 0)) ASC
                LIMIT 1
                "#,
            )
        };

        let node = query.fetch_optional(&self.db).await?;
        Ok(node)
    }

    /// Updates the health check status
    pub async fn update_health_status(&self, node_id: &str, healthy: bool) -> Result<()> {
        if healthy {
            sqlx::query(
                r#"
                UPDATE storage_nodes
                SET last_health_check = NOW(), health_check_failures = 0
                WHERE id = $1
                "#,
            )
            .bind(node_id)
            .execute(&self.db)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE storage_nodes
                SET last_health_check = NOW(), 
                    health_check_failures = health_check_failures + 1,
                    status = CASE WHEN health_check_failures >= 3 THEN 'offline' ELSE status END
                WHERE id = $1
                "#,
            )
            .bind(node_id)
            .execute(&self.db)
            .await?;
        }

        Ok(())
    }
}
