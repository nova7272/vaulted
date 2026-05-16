-- Vaulted QR Scan-to-Pair-Device request state.
-- Stores only public device keys and opaque challenges; never seed/private/file keys.

CREATE TABLE IF NOT EXISTS qr_device_pairing_requests (
    id UUID PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES vaulted_identities(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    desktop_device_name TEXT NULL,
    desktop_device_public_key TEXT NOT NULL,
    approved_by_device_id TEXT NULL,
    paired_device_id UUID NULL REFERENCES identity_devices(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ NULL,
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_qr_device_pairing_status_expires
    ON qr_device_pairing_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_qr_device_pairing_identity
    ON qr_device_pairing_requests(identity_id);
