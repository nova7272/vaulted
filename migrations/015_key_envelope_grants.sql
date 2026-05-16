-- Priority 5: canonical recipient key envelopes for grants.
-- Keep encrypted_file_key as compatibility/index field, but make key_envelope the canonical payload.

ALTER TABLE grants
    ADD COLUMN IF NOT EXISTS key_envelope JSONB,
    ADD COLUMN IF NOT EXISTS key_envelope_version TEXT NOT NULL DEFAULT 'vaulted-key-envelope-v1';

UPDATE grants
SET key_envelope = jsonb_build_object(
        'protocol', 'vaulted-key-envelope-v1',
        'alg', 'legacy-pre-aes-key',
        'recipient_type', 'grant-recipient',
        'recipient_identity_id', recipient_identity_id,
        'encrypted_file_key', encrypted_file_key
    )
WHERE key_envelope IS NULL;

ALTER TABLE qr_file_grant_requests
    ADD COLUMN IF NOT EXISTS key_envelope JSONB,
    ADD COLUMN IF NOT EXISTS key_envelope_version TEXT NOT NULL DEFAULT 'vaulted-key-envelope-v1';

UPDATE qr_file_grant_requests
SET key_envelope = jsonb_build_object(
        'protocol', 'vaulted-key-envelope-v1',
        'alg', 'legacy-pre-aes-key',
        'recipient_type', 'grant-recipient',
        'recipient_identity_id', recipient_identity_id,
        'encrypted_file_key', encrypted_file_key
    )
WHERE key_envelope IS NULL;
