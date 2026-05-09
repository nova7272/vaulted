-- ============================================
-- Migration 007: Audit Log Encryption
-- ============================================

-- Add encrypted_details column for sensitive data
-- plain details will store non-sensitive action descriptions
-- encrypted_details stores pgcrypto-encrypted JSON with sensitive fields
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS encrypted_details BYTEA;

-- Function to encrypt audit details using pgcrypto
-- Key is stored in environment variable, passed at query time
CREATE OR REPLACE FUNCTION encrypt_audit_details(
    details_json JSONB,
    encryption_key TEXT
) RETURNS BYTEA AS $$
BEGIN
    IF details_json IS NULL OR encryption_key IS NULL OR encryption_key = '' THEN
        RETURN NULL;
    END IF;
    RETURN pgp_sym_encrypt(details_json::text, encryption_key);
END;
$$ LANGUAGE plpgsql;

-- Function to decrypt audit details
CREATE OR REPLACE FUNCTION decrypt_audit_details(
    encrypted BYTEA,
    encryption_key TEXT
) RETURNS JSONB AS $$
BEGIN
    IF encrypted IS NULL OR encryption_key IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN pgp_sym_decrypt(encrypted, encryption_key)::jsonb;
EXCEPTION
    WHEN OTHERS THEN
        RETURN '{"error": "decryption_failed"}'::jsonb;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN audit_log.encrypted_details IS 'PGP-encrypted sensitive audit details (wallet addresses, token IDs)';
COMMENT ON COLUMN audit_log.details IS 'Non-sensitive action metadata (kept for basic querying without decryption key)';
