-- Migration: 005_replication.sql
-- Добавляет поддержку репликации файлов на несколько storage nodes

-- ============================================
-- Таблица реплик файлов
-- ============================================
CREATE TABLE IF NOT EXISTS file_replicas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- NFT Token ID (файл привязан к NFT)
    nft_token_id VARCHAR(64) NOT NULL,
    
    -- Storage node
    storage_node_id VARCHAR(64) NOT NULL REFERENCES storage_nodes(id),
    storage_key VARCHAR(255) NOT NULL,
    
    -- Размер файла
    size_bytes BIGINT NOT NULL DEFAULT 0,
    
    -- Статус реплики
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'uploading', 'active', 'failed', 'deleted')),
    
    -- Метаданные
    verified_at TIMESTAMPTZ,  -- Когда последний раз проверяли целостность
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Уникальность: один файл - один storage node
    UNIQUE (nft_token_id, storage_node_id)
);

CREATE INDEX idx_file_replicas_nft ON file_replicas(nft_token_id);
CREATE INDEX idx_file_replicas_storage ON file_replicas(storage_node_id);
CREATE INDEX idx_file_replicas_status ON file_replicas(status);

-- ============================================
-- Настройки репликации (глобальные)
-- ============================================
CREATE TABLE IF NOT EXISTS replication_settings (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'default',
    
    -- Количество копий каждого файла
    replication_factor INT NOT NULL DEFAULT 2,
    
    -- Стратегия выбора nodes
    -- 'region_diverse' - разные регионы
    -- 'load_balanced' - наименьшая загрузка
    -- 'mixed' - комбинация (предпочтительно)
    strategy VARCHAR(32) NOT NULL DEFAULT 'mixed',
    
    -- Минимальное количество активных реплик для доступа к файлу
    min_active_replicas INT NOT NULL DEFAULT 1,
    
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Дефолтные настройки
INSERT INTO replication_settings (id, replication_factor, strategy, min_active_replicas)
VALUES ('default', 2, 'mixed', 1)
ON CONFLICT (id) DO NOTHING;

-- ============================================
-- Триггер обновления updated_at
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
-- View для удобного доступа к репликам
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
