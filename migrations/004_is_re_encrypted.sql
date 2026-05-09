-- ============================================
-- Migration 004: Add is_re_encrypted flag
-- ============================================
-- После transfer ключ хранится в формате ReEncryptedData
-- Клиенту нужно знать какой метод расшифровки использовать

ALTER TABLE nft_metadata 
ADD COLUMN IF NOT EXISTS is_re_encrypted BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN nft_metadata.is_re_encrypted IS 
    'True if encrypted_aes_key contains ReEncryptedData (after transfer), false for original EncryptedPreData';
