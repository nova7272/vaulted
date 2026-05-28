-- Add fields for the Vault API

-- New statuses
ALTER TABLE nft_metadata DROP CONSTRAINT nft_metadata_status_check;
ALTER TABLE nft_metadata ADD CONSTRAINT nft_metadata_status_check 
    CHECK (status IN ('active', 'transferring', 'archived', 'pending_claim', 'claimed'));

-- Additional fields
ALTER TABLE nft_metadata ADD COLUMN IF NOT EXISTS offer_index VARCHAR(64);
ALTER TABLE nft_metadata ADD COLUMN IF NOT EXISTS manifest JSONB;

-- Offer index
CREATE INDEX IF NOT EXISTS idx_nft_metadata_offer ON nft_metadata(offer_index) WHERE offer_index IS NOT NULL;
