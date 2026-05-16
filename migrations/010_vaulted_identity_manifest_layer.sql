-- Vaulted v1 seed-based identity + manifest layer.
-- Oracle stores public keys and indexes signed manifests; it never stores mnemonic,
-- master seed, private keys, plaintext metadata or file keys.

CREATE TABLE IF NOT EXISTS vaulted_identities (
    id TEXT PRIMARY KEY,
    signing_public_key TEXT NOT NULL,
    encryption_public_key TEXT NOT NULL,
    protocol_version TEXT NOT NULL DEFAULT 'vaulted-v1',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_devices (
    id UUID PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    device_public_key TEXT NOT NULL,
    device_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(identity_id, device_public_key)
);

CREATE TABLE IF NOT EXISTS linked_wallets (
    id UUID PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    chain TEXT NOT NULL,
    address TEXT NOT NULL,
    proof_signature TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(identity_id, chain, address)
);

CREATE TABLE IF NOT EXISTS vault_objects (
    id TEXT PRIMARY KEY,
    owner_identity_id TEXT NOT NULL REFERENCES vaulted_identities(id),
    manifest_uri TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    nft_chain TEXT,
    nft_token_id TEXT,
    manifest_version BIGINT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grants (
    id UUID PRIMARY KEY,
    vault_object_id TEXT NOT NULL REFERENCES vault_objects(id) ON DELETE CASCADE,
    recipient_identity_id TEXT NOT NULL REFERENCES vaulted_identities(id),
    encrypted_file_key TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '["read"]'::jsonb,
    expires_at TIMESTAMPTZ,
    owner_signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    identity_id TEXT REFERENCES vaulted_identities(id),
    action TEXT NOT NULL,
    vault_object_id TEXT,
    request_id TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_objects_owner ON vault_objects(owner_identity_id);
CREATE INDEX IF NOT EXISTS idx_vault_objects_nft ON vault_objects(nft_chain, nft_token_id);
CREATE INDEX IF NOT EXISTS idx_grants_recipient ON grants(recipient_identity_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_events_identity_created ON audit_events(identity_id, created_at DESC);
