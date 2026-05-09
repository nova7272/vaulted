-- ============================================
-- Migration 008: Column-level Encryption
-- ============================================
-- Encrypts sensitive fields using pgcrypto.
-- 
-- Strategy:
--   manifest (filenames, sizes)  → encrypted (most sensitive)
--   wallet_address               → kept plain (public on XRPL, needed for lookups)
--                                  + add wallet_hash for obfuscated indexing
--   pre_public_key               → kept plain (public key by definition)
--   nft_token_id                 → kept plain (public on XRPL)
--   owner_id link                → can't encrypt without breaking JOINs
--
-- The encryption key is passed at runtime via app, NOT stored in DB.
-- ============================================

-- Ensure pgcrypto is available
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add encrypted manifest column
ALTER TABLE nft_metadata ADD COLUMN IF NOT EXISTS encrypted_manifest BYTEA;

-- Add wallet hash for obfuscated analytics (optional)
ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_hash VARCHAR(64);

-- Function to encrypt a JSONB field
CREATE OR REPLACE FUNCTION vault_encrypt(
    data TEXT,
    enc_key TEXT
) RETURNS BYTEA AS $$
BEGIN
    IF data IS NULL OR enc_key IS NULL OR enc_key = '' THEN
        RETURN NULL;
    END IF;
    RETURN pgp_sym_encrypt(data, enc_key, 'compress-algo=1, cipher-algo=aes256');
END;
$$ LANGUAGE plpgsql STRICT;

-- Function to decrypt
CREATE OR REPLACE FUNCTION vault_decrypt(
    encrypted BYTEA,
    enc_key TEXT
) RETURNS TEXT AS $$
BEGIN
    IF encrypted IS NULL OR enc_key IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN pgp_sym_decrypt(encrypted, enc_key);
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Helper: compute wallet hash (SHA-256, for obfuscated references)
CREATE OR REPLACE FUNCTION wallet_hash(wallet TEXT) RETURNS VARCHAR(64) AS $$
BEGIN
    RETURN encode(digest(wallet || 'xrpl-vault-salt-v1', 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- Populate wallet_hash for existing users
UPDATE users SET wallet_hash = wallet_hash(wallet_address) WHERE wallet_hash IS NULL;

-- Create index on wallet_hash
CREATE INDEX IF NOT EXISTS idx_users_wallet_hash ON users(wallet_hash);

COMMENT ON COLUMN nft_metadata.encrypted_manifest IS 'PGP-encrypted manifest JSON (filenames, sizes, fragment info)';
COMMENT ON COLUMN users.wallet_hash IS 'SHA-256 hash of wallet_address for obfuscated analytics/logging';
