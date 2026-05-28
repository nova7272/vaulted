//! PostgreSQL database connection

use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::error::{ApiError, Result};

/// Creates a database connection pool
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to connect to database: {}", e)))
}

/// Checks the database connection
pub async fn check_connection(pool: &PgPool) -> Result<()> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(|e| ApiError::Database(format!("Database health check failed: {}", e)))?;
    Ok(())
}
