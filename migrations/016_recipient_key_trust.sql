-- Priority 5: TOFU/manual trust decisions for recipient encryption public keys.
-- This allows clients to verify recipient key fingerprints before creating KeyEnvelopes.

CREATE TABLE IF NOT EXISTS identity_trusted_recipient_keys (
    id UUID PRIMARY KEY,
    owner_identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    recipient_identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    recipient_encryption_public_key TEXT NOT NULL,
    recipient_encryption_public_key_fingerprint TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'tofu',
    trust_source TEXT NOT NULL DEFAULT 'desktop',
    trusted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_identity_id, recipient_identity_id, recipient_encryption_public_key_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_identity_trusted_recipient_keys_owner
    ON identity_trusted_recipient_keys(owner_identity_id);
CREATE INDEX IF NOT EXISTS idx_identity_trusted_recipient_keys_recipient
    ON identity_trusted_recipient_keys(recipient_identity_id);
CREATE INDEX IF NOT EXISTS idx_identity_trusted_recipient_keys_fingerprint
    ON identity_trusted_recipient_keys(recipient_encryption_public_key_fingerprint);
