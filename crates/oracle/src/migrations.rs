//! Database migrations
//!
//! Automatically runs SQL migrations when the server starts.

use sqlx::PgPool;
use std::path::Path;
use tracing::{info, warn};

/// Migration result
#[derive(Debug)]
pub struct MigrationResult {
    pub total: usize,
    pub applied: usize,
    pub skipped: usize,
}

/// Runs migrations from a directory
pub async fn run_migrations(
    pool: &PgPool,
    migrations_dir: &Path,
) -> anyhow::Result<MigrationResult> {
    // Create the migrations table if it does not exist
    ensure_migrations_table(pool).await?;

    // Get the list of applied migrations
    let applied: Vec<String> =
        sqlx::query_scalar("SELECT name FROM _migrations ORDER BY applied_at")
            .fetch_all(pool)
            .await?;

    info!("Found {} previously applied migrations", applied.len());

    // Read migration files
    let mut migration_files: Vec<_> = std::fs::read_dir(migrations_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .collect();

    // Sort by file name
    migration_files.sort_by_key(|entry| entry.file_name());

    let mut result = MigrationResult {
        total: migration_files.len(),
        applied: 0,
        skipped: 0,
    };

    for entry in migration_files {
        let filename = entry.file_name().to_string_lossy().to_string();

        // Skip Zone.Identifier files (Windows)
        if filename.contains("Zone.Identifier") {
            continue;
        }

        if applied.contains(&filename) {
            info!("Migration {} already applied, skipping", filename);
            result.skipped += 1;
            continue;
        }

        // Read and apply the migration
        let sql = std::fs::read_to_string(entry.path())?;

        info!("Applying migration: {}", filename);

        // Execute in a transaction
        let mut tx = pool.begin().await?;

        // Split into separate statements
        for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
            let trimmed = statement.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }

            if let Err(e) = sqlx::query(trimmed).execute(&mut *tx).await {
                warn!("Statement failed: {}", e);
                // Some errors are acceptable (IF NOT EXISTS, DROP IF EXISTS, etc.)
                if !is_ignorable_error(&e) {
                    tx.rollback().await?;
                    return Err(anyhow::anyhow!("Migration {} failed: {}", filename, e));
                }
            }
        }

        // Record that the migration was applied
        sqlx::query("INSERT INTO _migrations (name, applied_at) VALUES ($1, NOW())")
            .bind(&filename)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        info!("Migration {} applied successfully", filename);
        result.applied += 1;
    }

    Ok(result)
}

/// Creates the migrations table
async fn ensure_migrations_table(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS _migrations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL UNIQUE,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Checks whether an error can be ignored
fn is_ignorable_error(error: &sqlx::Error) -> bool {
    let error_str = error.to_string().to_lowercase();

    // Errors that can be ignored
    error_str.contains("already exists")
        || error_str.contains("does not exist")
        || error_str.contains("duplicate key")
        || error_str.contains("constraint") && error_str.contains("already exists")
}

/// Embedded migrations (if files are unavailable)
pub async fn run_embedded_migrations(pool: &PgPool) -> anyhow::Result<MigrationResult> {
    ensure_migrations_table(pool).await?;

    let migrations = vec![
        ("001_init.sql", include_str!("../../../migrations/init.sql")),
        (
            "002_escrow_transfers.sql",
            include_str!("../../../migrations/002_escrow_transfers.sql"),
        ),
        (
            "002_encrypted_filename.sql",
            include_str!("../../../migrations/002_encrypted_filename.sql"),
        ),
        (
            "003_vault_fields.sql",
            include_str!("../../../migrations/003_vault_fields.sql"),
        ),
        (
            "004_is_re_encrypted.sql",
            include_str!("../../../migrations/004_is_re_encrypted.sql"),
        ),
        (
            "005_replication.sql",
            include_str!("../../../migrations/005_replication.sql"),
        ),
        (
            "006_admin_roles.sql",
            include_str!("../../../migrations/006_admin_roles.sql"),
        ),
        (
            "007_audit_encryption.sql",
            include_str!("../../../migrations/007_audit_encryption.sql"),
        ),
        (
            "008_column_encryption.sql",
            include_str!("../../../migrations/008_column_encryption.sql"),
        ),
        (
            "009_token_blacklist.sql",
            include_str!("../../../migrations/009_token_blacklist.sql"),
        ),
        (
            "010_vaulted_identity_manifest_layer.sql",
            include_str!("../../../migrations/010_vaulted_identity_manifest_layer.sql"),
        ),
        (
            "011_qr_login_and_vaulted_wallet.sql",
            include_str!("../../../migrations/011_qr_login_and_vaulted_wallet.sql"),
        ),
        (
            "012_qr_device_pairing.sql",
            include_str!("../../../migrations/012_qr_device_pairing.sql"),
        ),
        (
            "013_qr_xrpl_signing.sql",
            include_str!("../../../migrations/013_qr_xrpl_signing.sql"),
        ),
        (
            "014_qr_file_grant_approval.sql",
            include_str!("../../../migrations/014_qr_file_grant_approval.sql"),
        ),
        (
            "015_key_envelope_grants.sql",
            include_str!("../../../migrations/015_key_envelope_grants.sql"),
        ),
        (
            "016_recipient_key_trust.sql",
            include_str!("../../../migrations/016_recipient_key_trust.sql"),
        ),
    ];

    let applied: Vec<String> =
        sqlx::query_scalar("SELECT name FROM _migrations ORDER BY applied_at")
            .fetch_all(pool)
            .await?;

    let mut result = MigrationResult {
        total: migrations.len(),
        applied: 0,
        skipped: 0,
    };

    for (name, sql) in migrations {
        if applied.contains(&name.to_string()) {
            info!("Migration {} already applied", name);
            result.skipped += 1;
            continue;
        }

        info!("Applying embedded migration: {}", name);

        let mut tx = pool.begin().await?;

        // Important: SQL cannot be split on ';' because PostgreSQL functions
        // use $$ ... $$ blocks with internal ';' characters.
        // Execute the migration file as a whole.
        if let Err(e) = sqlx::raw_sql(sql).execute(&mut *tx).await {
            tx.rollback().await?;
            return Err(anyhow::anyhow!("Migration {} failed: {}", name, e));
        }

        sqlx::query("INSERT INTO _migrations (name, applied_at) VALUES ($1, NOW())")
            .bind(name)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        result.applied += 1;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ignorable_errors() {
        // Test ignored-error detection
        assert!(is_ignorable_error(&sqlx::Error::Database(Box::new(
            TestDbError("relation already exists".to_string())
        ))));
    }

    struct TestDbError(String);

    impl std::fmt::Debug for TestDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::fmt::Display for TestDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestDbError {}

    impl sqlx::error::DatabaseError for TestDbError {
        fn message(&self) -> &str {
            &self.0
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }
}
