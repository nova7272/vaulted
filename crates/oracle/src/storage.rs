//! Координация storage nodes
//!
//! Управление распределением фрагментов по хранилищам.

use sqlx::PgPool;

use crate::error::Result;
use crate::models::StorageNode;

/// Сервис управления хранилищами
pub struct StorageService {
    db: PgPool,
}

impl StorageService {
    /// Создаёт новый сервис
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Получает список активных storage nodes
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

    /// Выбирает оптимальную ноду для загрузки
    pub async fn select_node_for_upload(&self, region_hint: Option<&str>) -> Result<Option<StorageNode>> {
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

    /// Обновляет health check статус
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
