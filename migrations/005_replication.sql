-- Migration: 005_replication.sql
-- Adds support for file replication across multiple storage nodes

-- ============================================
-- File replicas table
-- ============================================
CREATE TABLE IF NOT EXISTS file_replicas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- NFT Token ID (file is linked to an NFT)
    nft_token_id VARCHAR(64) NOT NULL,
    
    -- Storage node
    storage_node_id VARCHAR(64) NOT NULL REFERENCES storage_nodes(id),
    storage_key VARCHAR(255) NOT NULL,
    
    -- File size
    size_bytes BIGINT NOT NULL DEFAULT 0,
    
    -- Replica status
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'uploading', 'active', 'failed', 'deleted')),
    
    -- Metadata
    verified_at TIMESTAMPTZ,  -- When integrity was last checked
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Uniqueness: one file - one storage node
    UNIQUE (nft_token_id, storage_node_id)
);

CREATE INDEX idx_file_replicas_nft ON file_replicas(nft_token_id);
CREATE INDEX idx_file_replicas_storage ON file_replicas(storage_node_id);
CREATE INDEX idx_file_replicas_status ON file_replicas(status);

-- ============================================
-- Replication settings (global)
-- ============================================
CREATE TABLE IF NOT EXISTS replication_settings (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'default',
    
    -- Number of copies of each file
    replication_factor INT NOT NULL DEFAULT 2,
    
    -- Node selection strategy
    -- 'region_diverse' - different regions
    -- 'load_balanced' - lowest load
    -- 'mixed' - combination (preferred)
    strategy VARCHAR(32) NOT NULL DEFAULT 'mixed',
    
    -- Minimum number of active replicas for file access
    min_active_replicas INT NOT NULL DEFAULT 1,
    
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default settings
INSERT INTO replication_settings (id, replication_factor, strategy, min_active_replicas)
VALUES ('default', 2, 'mixed', 1)
ON CONFLICT (id) DO NOTHING;

-- ============================================
-- updated_at update trigger
-- ============================================
CREATE OR REPLACE FUNCTION update_file_replicas_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_file_replicas_updated_at ON file_replicas;
CREATE TRIGGER update_file_replicas_updated_at
    BEFORE UPDATE ON file_replicas
    FOR EACH ROW
    EXECUTE FUNCTION update_file_replicas_updated_at();

-- ============================================
-- View for convenient replica access
-- ============================================
CREATE OR REPLACE VIEW file_replicas_view AS
SELECT 
    fr.id AS replica_id,
    fr.nft_token_id,
    fr.storage_node_id,
    sn.endpoint_url,
    sn.region,
    sn.status AS node_status,
    fr.storage_key,
    fr.status AS replica_status,
    fr.size_bytes,
    fr.verified_at,
    fr.created_at
FROM file_replicas fr
JOIN storage_nodes sn ON sn.id = fr.storage_node_id;

COMMENT ON TABLE file_replicas IS 'Реплики зашифрованных файлов на storage nodes';
COMMENT ON TABLE replication_settings IS 'Глобальные настройки репликации';
