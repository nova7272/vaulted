-- ============================================
-- Migration 004: Add is_re_encrypted flag
-- ============================================
-- After transfer, the key is stored in ReEncryptedData format
-- The client needs to know which decryption method to use

ALTER TABLE nft_metadata 
ADD COLUMN IF NOT EXISTS is_re_encrypted BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN nft_metadata.is_re_encrypted IS 
    'True if encrypted_aes_key contains ReEncryptedData (after transfer), false for original EncryptedPreData';
