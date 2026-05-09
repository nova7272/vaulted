-- Migration: Rename original_filename to encrypted_filename
-- Reason: Filename is now encrypted with AES before storing
-- Safe/idempotent version for fresh schema where encrypted_filename already exists.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'file_manifests'
          AND column_name = 'original_filename'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'file_manifests'
          AND column_name = 'encrypted_filename'
    )
    THEN
        ALTER TABLE file_manifests
            RENAME COLUMN original_filename TO encrypted_filename;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN file_manifests.encrypted_filename IS 'AES-256-GCM encrypted filename (base64)';
