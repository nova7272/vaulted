-- QR Scan-to-Approve-File-Grant requests.
-- The QR payload carries only opaque grant context. The encrypted_file_key is
-- already recipient-encrypted and is stored server-side until approval.

CREATE TABLE IF NOT EXISTS qr_file_grant_requests (
    id UUID PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    vault_object_id TEXT NOT NULL REFERENCES vault_objects(id) ON DELETE CASCADE,
    grant_id UUID NOT NULL,
    recipient_identity_id TEXT NOT NULL REFERENCES vaulted_identities(id),
    encrypted_file_key TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '["read"]'::jsonb,
    grant_expires_at TIMESTAMPTZ,
    grant_context_hash TEXT NOT NULL,
    requester_device_id TEXT,
    requester_device_name TEXT,
    approved_by_device_id TEXT,
    approval_signing_public_key TEXT,
    approval_signature TEXT,
    created_grant_id UUID REFERENCES grants(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_qr_file_grant_requests_identity ON qr_file_grant_requests(identity_id, status);
CREATE INDEX IF NOT EXISTS idx_qr_file_grant_requests_grant ON qr_file_grant_requests(grant_id);
