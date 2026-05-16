-- Vaulted QR Scan-to-Sign-XRPL-Transaction request state.
-- Stores only public transaction JSON and approval signatures; never private keys or seeds.

CREATE TABLE IF NOT EXISTS qr_xrpl_signing_requests (
    id UUID PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    xrpl_tx_json JSONB NOT NULL,
    xrpl_tx_hash TEXT NOT NULL,
    expected_xrpl_account TEXT NOT NULL,
    requester_device_id TEXT NULL,
    requester_device_name TEXT NULL,
    approved_by_device_id TEXT NULL,
    approval_signing_public_key TEXT NULL,
    approval_signature TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ NULL,
    rejected_at TIMESTAMPTZ NULL,
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_qr_xrpl_signing_status_expires
    ON qr_xrpl_signing_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_qr_xrpl_signing_identity
    ON qr_xrpl_signing_requests(identity_id);
