//! User session management

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Authorized user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// XRPL wallet address (rXXX...)
    pub wallet_address: String,
    /// Wallet public key (hex)
    pub public_key: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// UUID of the signing/login request that created this session.
    #[serde(alias = "xaman_payload_uuid")]
    pub signing_request_uuid: String,
    /// Oracle JWT access token
    #[serde(default)]
    pub oracle_token: Option<String>,
    /// Oracle token expiration time
    #[serde(default)]
    pub oracle_token_expires_at: Option<DateTime<Utc>>,
    /// Oracle JWT refresh token (for automatic token renewal)
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Device fingerprint (SHA-256 hash, unique per device)
    #[serde(default)]
    pub device_fingerprint: Option<String>,
    /// User role from Oracle
    #[serde(default)]
    pub role: Option<String>,
}

impl Session {
    /// Creates a new session
    pub fn new(
        wallet_address: String,
        public_key: String,
        signing_request_uuid: String,
        duration_hours: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            wallet_address,
            public_key,
            created_at: now,
            expires_at: now + Duration::hours(duration_hours),
            signing_request_uuid,
            oracle_token: None,
            oracle_token_expires_at: None,
            refresh_token: None,
            device_fingerprint: None,
            role: None,
        }
    }

    /// Creates a session with an Oracle token
    pub fn with_oracle_token(
        wallet_address: String,
        public_key: String,
        signing_request_uuid: String,
        duration_hours: i64,
        oracle_token: String,
    ) -> Self {
        let mut session = Self::new(
            wallet_address,
            public_key,
            signing_request_uuid,
            duration_hours,
        );
        session.oracle_token = Some(oracle_token);
        session.oracle_token_expires_at = Some(Utc::now() + Duration::hours(1));
        session
    }

    /// Checks whether the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Returns the remaining session lifetime
    pub fn time_remaining(&self) -> Option<Duration> {
        let remaining = self.expires_at - Utc::now();
        if remaining > Duration::zero() {
            Some(remaining)
        } else {
            None
        }
    }

    /// Updates the expiration time
    pub fn refresh(&mut self, duration_hours: i64) {
        self.expires_at = Utc::now() + Duration::hours(duration_hours);
    }

    /// Sets Oracle JWT token with expiration
    pub fn set_oracle_token(&mut self, token: String) {
        self.oracle_token = Some(token);
        self.oracle_token_expires_at = Some(Utc::now() + Duration::hours(1));
    }

    /// Sets Oracle JWT token with custom expiration (in seconds)
    pub fn set_oracle_token_with_expiry(&mut self, token: String, expires_in_secs: i64) {
        self.oracle_token = Some(token);
        self.oracle_token_expires_at = Some(Utc::now() + Duration::seconds(expires_in_secs));
    }

    /// Sets refresh token
    pub fn set_refresh_token(&mut self, token: String) {
        self.refresh_token = Some(token);
    }

    /// Sets device fingerprint
    pub fn set_device_fingerprint(&mut self, fingerprint: String) {
        self.device_fingerprint = Some(fingerprint);
    }

    /// Sets user role
    pub fn set_role(&mut self, role: String) {
        self.role = Some(role);
    }

    /// Updates tokens from refresh response (access + refresh + role)
    pub fn update_tokens(
        &mut self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in_secs: i64,
        role: Option<String>,
    ) {
        self.set_oracle_token_with_expiry(access_token, expires_in_secs);
        if let Some(rt) = refresh_token {
            self.refresh_token = Some(rt);
        }
        if let Some(r) = role {
            self.role = Some(r);
        }
    }

    /// Gets Oracle token if available
    pub fn get_oracle_token(&self) -> Option<&str> {
        self.oracle_token.as_deref()
    }

    /// Gets refresh token if available
    pub fn get_refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Gets device fingerprint
    pub fn get_device_fingerprint(&self) -> Option<&str> {
        self.device_fingerprint.as_deref()
    }

    /// Checks if Oracle token needs refresh (expires in < 5 minutes)
    pub fn oracle_token_needs_refresh(&self) -> bool {
        match self.oracle_token_expires_at {
            Some(expires_at) => {
                let remaining = expires_at - Utc::now();
                remaining < Duration::minutes(5)
            },
            None => self.oracle_token.is_some(),
        }
    }

    /// Checks if Oracle token is expired
    pub fn oracle_token_is_expired(&self) -> bool {
        match self.oracle_token_expires_at {
            Some(expires_at) => Utc::now() > expires_at,
            None => false,
        }
    }

    /// Checks if we have a valid refresh token
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_not_expired() {
        let session = Session::new(
            "rXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            "AAAA".to_string(),
            "uuid-123".to_string(),
            24,
        );
        assert!(!session.is_expired());
        assert!(session.time_remaining().is_some());
    }

    #[test]
    fn test_session_expired() {
        let mut session = Session::new(
            "rXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            "AAAA".to_string(),
            "uuid-123".to_string(),
            24,
        );
        // Set the expiration time in the past
        session.expires_at = Utc::now() - Duration::hours(1);
        assert!(session.is_expired());
        assert!(session.time_remaining().is_none());
    }
}
