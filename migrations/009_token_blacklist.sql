-- HIGH-02: Persistent token blacklist (survives Oracle restarts without Redis)
-- Stores blacklisted JWT token IDs with automatic expiry cleanup

CREATE TABLE IF NOT EXISTS token_blacklist (
                                               jti TEXT PRIMARY KEY,
                                               expires_at TIMESTAMPTZ NOT NULL,
                                               created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

-- Index for efficient cleanup of expired entries
CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires
    ON token_blacklist (expires_at);