-- ============================================
-- XRPL Vault Database Schema
-- Version: 1.0.0
-- ============================================

-- Расширения
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Пользователи (кошельки XRPL)
-- ============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- XRPL wallet address (rXXX...)
    wallet_address VARCHAR(35) NOT NULL UNIQUE,
    
    -- Публичный ключ PRE (hex-encoded, 64 bytes = 128 chars)
    pre_public_key VARCHAR(130) NOT NULL,
    
    -- Метаданные
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

CREATE INDEX idx_users_wallet_address ON users(wallet_address);

-- ============================================
-- NFT метаданные
-- ============================================
CREATE TABLE nft_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- XRPL NFT TokenID
    nft_token_id VARCHAR(64) NOT NULL UNIQUE,
    
    -- Текущий владелец
    owner_id UUID NOT NULL REFERENCES users(id),
    
    -- Зашифрованный AES-ключ (base64, PRE encrypted)
    encrypted_aes_key TEXT NOT NULL,
    
    -- Hash метаданных (для верификации, хранится в URI NFT)
    metadata_hash VARCHAR(71) NOT NULL, -- "sha256:" + 64 hex chars
    
    -- Версия криптографической схемы
    crypto_version SMALLINT NOT NULL DEFAULT 1,
    
    -- Статус
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'transferring', 'archived')),
    
    -- Временные метки
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nft_metadata_token_id ON nft_metadata(nft_token_id);
CREATE INDEX idx_nft_metadata_owner ON nft_metadata(owner_id);
CREATE INDEX idx_nft_metadata_status ON nft_metadata(status);

-- ============================================
-- Манифест файлов
-- ============================================
CREATE TABLE file_manifests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Связь с NFT
    nft_metadata_id UUID NOT NULL REFERENCES nft_metadata(id) ON DELETE CASCADE,
    
    -- Информация о файле
    encrypted_filename VARCHAR(512) NOT NULL,
    original_size BIGINT NOT NULL,
    mime_type VARCHAR(127) NOT NULL,
    
    -- Hash оригинального файла (для верификации после расшифровки)
    original_hash VARCHAR(71) NOT NULL,
    
    -- Количество фрагментов
    fragment_count INT NOT NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_file_manifests_nft ON file_manifests(nft_metadata_id);

-- ============================================
-- Фрагменты файлов
-- ============================================
CREATE TABLE file_fragments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Связь с манифестом
    manifest_id UUID NOT NULL REFERENCES file_manifests(id) ON DELETE CASCADE,
    
    -- Порядковый номер фрагмента
    fragment_index INT NOT NULL,
    
    -- Размер фрагмента
    fragment_size BIGINT NOT NULL,
    
    -- Hash зашифрованного фрагмента
    encrypted_hash VARCHAR(71) NOT NULL,
    
    -- Информация о хранении
    storage_node_id VARCHAR(64) NOT NULL,  -- ID ноды хранения
    storage_key VARCHAR(255) NOT NULL,      -- Ключ/путь в хранилище
    
    -- Статус репликации
    replication_count INT NOT NULL DEFAULT 1,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE (manifest_id, fragment_index)
);

CREATE INDEX idx_file_fragments_manifest ON file_fragments(manifest_id);
CREATE INDEX idx_file_fragments_storage ON file_fragments(storage_node_id);

-- ============================================
-- Storage Nodes (серверы хранения)
-- ============================================
CREATE TABLE storage_nodes (
    id VARCHAR(64) PRIMARY KEY,
    
    -- Endpoint
    endpoint_url VARCHAR(255) NOT NULL,
    region VARCHAR(50) NOT NULL,  -- 'eu-central', 'us-east', 'ap-northeast'
    
    -- Статус и метрики
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'maintenance', 'offline')),
    total_space_bytes BIGINT NOT NULL DEFAULT 0,
    used_space_bytes BIGINT NOT NULL DEFAULT 0,
    
    -- Health check
    last_health_check TIMESTAMPTZ,
    health_check_failures INT NOT NULL DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_storage_nodes_status ON storage_nodes(status);
CREATE INDEX idx_storage_nodes_region ON storage_nodes(region);

-- ============================================
-- Запросы на передачу NFT
-- ============================================
CREATE TABLE transfer_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- NFT
    nft_metadata_id UUID NOT NULL REFERENCES nft_metadata(id),
    
    -- Участники
    from_user_id UUID NOT NULL REFERENCES users(id),
    to_user_id UUID NOT NULL REFERENCES users(id),
    
    -- Re-encryption key (сериализованный, base64)
    re_encryption_key TEXT NOT NULL,
    
    -- Статус процесса
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    
    -- Результат перешифровки (новый encrypted_aes_key)
    re_encrypted_aes_key TEXT,
    
    -- Информация об ошибке (если failed)
    error_message TEXT,
    
    -- XRPL transaction hash (подтверждение передачи NFT)
    xrpl_tx_hash VARCHAR(64),
    
    -- Временные метки
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_transfer_requests_nft ON transfer_requests(nft_metadata_id);
CREATE INDEX idx_transfer_requests_status ON transfer_requests(status);
CREATE INDEX idx_transfer_requests_from ON transfer_requests(from_user_id);
CREATE INDEX idx_transfer_requests_to ON transfer_requests(to_user_id);

-- ============================================
-- Audit Log (журнал операций)
-- ============================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Кто выполнил действие
    user_id UUID REFERENCES users(id),
    
    -- Тип действия
    action VARCHAR(50) NOT NULL,
    -- 'file_upload', 'file_download', 'nft_mint', 'nft_transfer_init',
    -- 'nft_transfer_complete', 'pre_re_encrypt', 'user_register'
    
    -- Связанные сущности
    nft_token_id VARCHAR(64),
    
    -- Детали (JSON)
    details JSONB,
    
    -- IP и User-Agent
    ip_address INET,
    user_agent TEXT,
    
    -- Время
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_nft ON audit_log(nft_token_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);

-- ============================================
-- Функции и триггеры
-- ============================================

-- Автоматическое обновление updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_nft_metadata_updated_at
    BEFORE UPDATE ON nft_metadata
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_storage_nodes_updated_at
    BEFORE UPDATE ON storage_nodes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Начальные данные (dev)
-- ============================================

-- Тестовые storage nodes
INSERT INTO storage_nodes (id, endpoint_url, region, status, total_space_bytes) VALUES
    ('node-eu-1', 'http://localhost:9001', 'eu-central', 'active', 107374182400),   -- 100GB
    ('node-us-1', 'http://localhost:9002', 'us-east', 'active', 107374182400),
    ('node-ap-1', 'http://localhost:9003', 'ap-northeast', 'active', 107374182400);

-- ============================================
-- Комментарии к таблицам
-- ============================================
COMMENT ON TABLE users IS 'XRPL wallet users with PRE public keys';
COMMENT ON TABLE nft_metadata IS 'NFT metadata with encrypted AES keys';
COMMENT ON TABLE file_manifests IS 'File information linked to NFTs';
COMMENT ON TABLE file_fragments IS 'Encrypted file fragments distributed across storage nodes';
COMMENT ON TABLE storage_nodes IS 'Distributed storage nodes registry';
COMMENT ON TABLE transfer_requests IS 'NFT transfer requests with PRE re-encryption';
COMMENT ON TABLE audit_log IS 'Audit trail for all operations';
