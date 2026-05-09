-- ============================================
-- XRPL Vault: Escrow-based Transfers
-- Version: 1.1.0
-- ============================================

-- Расширяем transfer_requests для поддержки Escrow
ALTER TABLE transfer_requests 
    -- Escrow информация
    ADD COLUMN price_drops VARCHAR(20),                    -- Цена в drops (NULL = бесплатная передача)
    ADD COLUMN escrow_owner VARCHAR(35),                   -- Кто создал escrow (buyer)
    ADD COLUMN escrow_sequence INT,                        -- Sequence number escrow на XRPL
    ADD COLUMN escrow_tx_hash VARCHAR(64),                 -- Hash транзакции EscrowCreate
    ADD COLUMN escrow_condition VARCHAR(512),              -- Crypto-condition (опционально)
    ADD COLUMN escrow_fulfillment VARCHAR(512),            -- Fulfillment для condition
    
    -- Oracle approval
    ADD COLUMN approval_signature TEXT,                     -- Подпись Oracle для NFT offer
    ADD COLUMN approval_message TEXT,                       -- Сообщение которое подписано
    
    -- NFT offer информация  
    ADD COLUMN nft_offer_index VARCHAR(64),                -- Offer index на XRPL
    ADD COLUMN nft_offer_tx_hash VARCHAR(64),              -- Hash транзакции NFTokenCreateOffer
    ADD COLUMN nft_accept_tx_hash VARCHAR(64),             -- Hash транзакции NFTokenAcceptOffer
    
    -- Escrow завершение
    ADD COLUMN escrow_finish_tx_hash VARCHAR(64),          -- Hash транзакции EscrowFinish
    ADD COLUMN escrow_cancel_tx_hash VARCHAR(64),          -- Hash транзакции EscrowCancel
    
    -- Расширенные статусы
    ADD COLUMN expires_at TIMESTAMPTZ;                     -- Когда transfer истекает

-- Обновляем CHECK constraint для status
ALTER TABLE transfer_requests 
    DROP CONSTRAINT IF EXISTS transfer_requests_status_check;
    
ALTER TABLE transfer_requests
    ADD CONSTRAINT transfer_requests_status_check 
    CHECK (status IN (
        'pending_escrow',      -- Ожидает создания escrow покупателем
        'pending_re_key',      -- Escrow создан, ожидает re-key от продавца
        'pending_nft_offer',   -- Re-key получен, ожидает NFT offer
        'pending_nft_accept',  -- NFT offer создан, ожидает accept
        'pending_escrow_finish', -- NFT передан, ожидает escrow finish
        'completed',           -- Успешно завершено
        'cancelled_timeout',   -- Отменено по таймауту
        'cancelled_by_seller', -- Отменено продавцом
        'cancelled_by_buyer',  -- Отменено покупателем
        'failed',              -- Ошибка
        -- Legacy статусы для совместимости
        'pending',
        'processing'
    ));

-- Индексы для новых полей
CREATE INDEX IF NOT EXISTS idx_transfer_requests_expires 
    ON transfer_requests(expires_at) 
    WHERE status NOT IN ('completed', 'cancelled_timeout', 'cancelled_by_seller', 'cancelled_by_buyer', 'failed');

CREATE INDEX IF NOT EXISTS idx_transfer_requests_escrow 
    ON transfer_requests(escrow_owner, escrow_sequence) 
    WHERE escrow_sequence IS NOT NULL;

-- ============================================
-- Таблица для подписей Oracle (для верификации)
-- ============================================
CREATE TABLE IF NOT EXISTS oracle_signatures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Связь с transfer
    transfer_id UUID NOT NULL REFERENCES transfer_requests(id) ON DELETE CASCADE,
    
    -- Что подписано
    message_type VARCHAR(50) NOT NULL,  -- 'transfer_approval', 'escrow_release'
    message_hash VARCHAR(64) NOT NULL,  -- SHA256 сообщения
    
    -- Подпись
    signature TEXT NOT NULL,            -- Ed25519 подпись (hex)
    public_key VARCHAR(64) NOT NULL,    -- Публичный ключ Oracle (hex)
    
    -- Время
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(transfer_id, message_type)
);

CREATE INDEX idx_oracle_signatures_transfer ON oracle_signatures(transfer_id);

-- ============================================
-- Таблица конфигурации Oracle
-- ============================================
CREATE TABLE IF NOT EXISTS oracle_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Начальная конфигурация
INSERT INTO oracle_config (key, value, description) VALUES
    ('transfer_timeout_hours', '24', 'Время жизни transfer request в часах'),
    ('min_escrow_amount_drops', '1000000', 'Минимальная сумма escrow (1 XRP)'),
    ('oracle_fee_percent', '0', 'Комиссия Oracle в процентах'),
    ('oracle_signing_key', '', 'Публичный ключ Oracle для подписей (заполняется при старте)')
ON CONFLICT (key) DO NOTHING;

-- ============================================
-- View для активных transfers
-- ============================================
CREATE OR REPLACE VIEW active_transfers AS
SELECT 
    tr.*,
    seller.wallet_address as seller_address,
    seller.pre_public_key as seller_pre_key,
    buyer.wallet_address as buyer_address,
    buyer.pre_public_key as buyer_pre_key,
    nm.nft_token_id,
    nm.encrypted_aes_key as current_encrypted_key
FROM transfer_requests tr
JOIN users seller ON tr.from_user_id = seller.id
JOIN users buyer ON tr.to_user_id = buyer.id
JOIN nft_metadata nm ON tr.nft_metadata_id = nm.id
WHERE tr.status NOT IN ('completed', 'cancelled_timeout', 'cancelled_by_seller', 'cancelled_by_buyer', 'failed');

-- ============================================
-- Функция для очистки просроченных transfers
-- ============================================
CREATE OR REPLACE FUNCTION cleanup_expired_transfers()
RETURNS INTEGER AS $$
DECLARE
    affected_rows INTEGER;
BEGIN
    UPDATE transfer_requests
    SET 
        status = 'cancelled_timeout',
        completed_at = NOW()
    WHERE 
        status IN ('pending_escrow', 'pending_re_key', 'pending_nft_offer', 'pending_nft_accept')
        AND expires_at < NOW();
    
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_transfers IS 'Marks expired transfers as cancelled_timeout. Should be called periodically.';
