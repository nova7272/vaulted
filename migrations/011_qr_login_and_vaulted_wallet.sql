-- Vaulted wallet mode: QR login / device pairing request state.
-- QR rows never store seed phrases, private keys, file keys or encrypted keystores.

CREATE TABLE IF NOT EXISTS qr_login_requests (
    id UUID PRIMARY KEY,
    challenge TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    identity_id TEXT NULL,
    desktop_device_name TEXT NULL,
    desktop_device_public_key TEXT NULL,
    approved_by_device_id TEXT NULL,
    access_token TEXT NULL,
    refresh_token TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ NULL,
    consumed_at TIMESTAMPTZ NULL,
    ip_address INET NULL,
    user_agent TEXT NULL,
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'consumed'))
);

CREATE INDEX IF NOT EXISTS idx_qr_login_requests_status_expires
    ON qr_login_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_qr_login_requests_identity
    ON qr_login_requests(identity_id);

-- Store Vaulted-owned XRPL wallet public keys as first-class wallet records.
ALTER TABLE linked_wallets
    ADD COLUMN IF NOT EXISTS wallet_source TEXT NOT NULL DEFAULT 'vaulted-wallet';

ALTER TABLE linked_wallets
    ADD COLUMN IF NOT EXISTS public_key TEXT NULL;
