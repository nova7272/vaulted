use crate::{
    error::{ApiError, Result},
    services::AppState,
};

pub const XRPL_OWNERSHIP_VERIFICATION_UNAVAILABLE_MESSAGE: &str =
    "XRPL ownership verification is temporarily unavailable. Please retry when ledger verification is available.";

pub async fn require_verified_nft_owner(
    state: &AppState,
    nft_token_id: &str,
    wallet_address: &str,
    forbidden_message: &str,
) -> Result<String> {
    let (db_owner_wallet, status) = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT u.wallet_address, nm.status
        FROM nft_metadata nm
        JOIN users u ON nm.owner_id = u.id
        WHERE nm.nft_token_id = $1 AND nm.status IN ('active', 'pending_claim')
        "#,
    )
    .bind(nft_token_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NftNotFound(nft_token_id.to_string()))?;

    if !db_owner_wallet.eq_ignore_ascii_case(wallet_address) {
        return Err(ApiError::Forbidden(forbidden_message.to_string()));
    }

    if !requires_xrpl_ownership_verification(&status) {
        tracing::debug!("Pending vault ownership verified from Oracle metadata");
        return Ok(db_owner_wallet);
    }

    let verification = state
        .xrpl
        .verify_nft_owner(nft_token_id, wallet_address)
        .await;

    require_owner_from_verification(nft_token_id, wallet_address, verification)?;

    Ok(db_owner_wallet)
}

fn requires_xrpl_ownership_verification(status: &str) -> bool {
    status != "pending_claim"
}

fn require_owner_from_verification(
    nft_token_id: &str,
    wallet_address: &str,
    verification: Result<bool>,
) -> Result<()> {
    match verification {
        Ok(true) => {
            tracing::debug!(
                "On-chain NFT ownership verified for sensitive access to {}",
                nft_token_id
            );
            Ok(())
        },
        Ok(false) => {
            tracing::warn!(
                "On-chain ownership mismatch for NFT {} and wallet {}",
                nft_token_id,
                wallet_address
            );
            Err(ApiError::Forbidden(
                "NFT ownership could not be verified on XRPL ledger".into(),
            ))
        },
        Err(error) => {
            tracing::warn!(
                "On-chain ownership verification unavailable for NFT {} and wallet {}: {}",
                nft_token_id,
                wallet_address,
                error
            );
            Err(ApiError::OwnershipVerificationUnavailable(
                XRPL_OWNERSHIP_VERIFICATION_UNAVAILABLE_MESSAGE.into(),
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};

    const NFT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OWNER: &str = "rOwnerWallet";

    #[test]
    fn verifier_success_allows_owner() {
        assert!(require_owner_from_verification(NFT, OWNER, Ok(true)).is_ok());
    }

    #[test]
    fn verifier_mismatch_denies_stale_db_owner() {
        let err = require_owner_from_verification(NFT, OWNER, Ok(false))
            .expect_err("ledger owner mismatch must deny access");

        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[test]
    fn verifier_error_fails_closed_with_503_mapping() {
        let err = require_owner_from_verification(
            NFT,
            OWNER,
            Err(ApiError::Xrpl("timeout while querying account_nfts".into())),
        )
        .expect_err("verifier errors must fail closed");

        match err {
            ApiError::OwnershipVerificationUnavailable(message) => {
                assert_eq!(message, XRPL_OWNERSHIP_VERIFICATION_UNAVAILABLE_MESSAGE);
            },
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verifier_unavailable_maps_to_clear_503_response() {
        let response = ApiError::OwnershipVerificationUnavailable(
            XRPL_OWNERSHIP_VERIFICATION_UNAVAILABLE_MESSAGE.into(),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn verifier_error_does_not_return_forbidden_or_xrpl_fallback() {
        let err = require_owner_from_verification(
            NFT,
            OWNER,
            Err(ApiError::Xrpl("ledger unavailable".into())),
        )
        .expect_err("verifier errors must not fall back to DB ownership");

        assert!(matches!(err, ApiError::OwnershipVerificationUnavailable(_)));
    }

    #[test]
    fn pending_claim_rows_use_oracle_owner_until_mint_finalizes() {
        assert!(!requires_xrpl_ownership_verification("pending_claim"));
    }

    #[test]
    fn active_rows_still_require_xrpl_owner_verification() {
        assert!(requires_xrpl_ownership_verification("active"));
    }
}
