//! Middleware для Oracle API

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of IP -> (request count, window start)
    requests: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    /// Requests allowed per window
    limit: u32,
    /// Window duration
    window: Duration,
    /// HIGH-01: Trusted proxy IPs (only these may set X-Forwarded-For, X-Real-IP, etc.)
    /// If empty, proxy headers are NEVER trusted — ConnectInfo is always used.
    pub trusted_proxies: Vec<String>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            limit: requests_per_minute,
            window: Duration::from_secs(60),
            trusted_proxies: Vec::new(),
        }
    }

    /// Create rate limiter with trusted proxy list
    pub fn with_trusted_proxies(requests_per_minute: u32, trusted_proxies: Vec<String>) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            limit: requests_per_minute,
            window: Duration::from_secs(60),
            trusted_proxies,
        }
    }

    /// Check if request should be rate limited
    /// Returns (allowed, remaining, reset_after_secs)
    pub async fn check(&self, key: &str) -> (bool, u32, u64) {
        let now = Instant::now();
        let mut requests = self.requests.write().await;

        let (count, window_start) = requests
            .entry(key.to_string())
            .or_insert((0, now));

        // Reset window if expired
        if now.duration_since(*window_start) >= self.window {
            *count = 0;
            *window_start = now;
        }

        let remaining = self.limit.saturating_sub(*count);
        let reset_after = self.window
            .saturating_sub(now.duration_since(*window_start))
            .as_secs();

        if *count >= self.limit {
            return (false, 0, reset_after);
        }

        *count += 1;
        (true, remaining - 1, reset_after)
    }

    /// Clean up old entries (call periodically)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.requests.write().await;
        requests.retain(|_, (_, start)| now.duration_since(*start) < self.window * 2);
    }
}

/// Rate limit middleware
///
/// Usage:
/// ```ignore
/// let rate_limiter = RateLimiter::new(60); // 60 req/min
/// app.layer(axum::middleware::from_fn_with_state(
///     rate_limiter,
///     rate_limit_middleware
/// ))
/// ```
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // HIGH-01: Use ConnectInfo (real TCP peer) as primary source.
    // Only trust proxy headers if the direct connection comes from a trusted proxy.
    let peer_ip = connect_info.map(|ci| ci.0.ip().to_string());
    let client_ip = extract_client_ip_safe(&headers, peer_ip.as_deref(), &limiter.trusted_proxies);

    let (allowed, remaining, reset_after) = limiter.check(&client_ip).await;

    if !allowed {
        tracing::warn!("Rate limit exceeded for IP: {}", client_ip);

        let response = (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Limit", limiter.limit.to_string()),
                ("X-RateLimit-Remaining", "0".to_string()),
                ("X-RateLimit-Reset", reset_after.to_string()),
                ("Retry-After", reset_after.to_string()),
            ],
            Json(serde_json::json!({
                "error": "Too many requests",
                "retry_after_seconds": reset_after
            }))
        );

        return Err(response.into_response());
    }

    let mut response = next.run(request).await;

    // Add rate limit headers to response
    let headers = response.headers_mut();
    headers.insert("X-RateLimit-Limit", limiter.limit.to_string().parse().unwrap());
    headers.insert("X-RateLimit-Remaining", remaining.to_string().parse().unwrap());
    headers.insert("X-RateLimit-Reset", reset_after.to_string().parse().unwrap());

    Ok(response)
}

/// HIGH-01: Extract client IP safely.
///
/// Priority:
/// 1. If peer_ip is from a trusted proxy → read X-Real-IP / CF-Connecting-IP / X-Forwarded-For
/// 2. Otherwise → use peer_ip directly (prevents header spoofing)
/// 3. Fallback → "unknown"
fn extract_client_ip_safe(
    headers: &HeaderMap,
    peer_ip: Option<&str>,
    trusted_proxies: &[String],
) -> String {
    let peer = peer_ip.unwrap_or("unknown");

    // Only trust proxy headers if the direct TCP connection is from a known proxy
    let peer_is_trusted = !trusted_proxies.is_empty()
        && trusted_proxies.iter().any(|tp| tp == peer);

    if peer_is_trusted {
        // Trusted proxy — read forwarded IP from headers
        if let Some(ip) = extract_ip_from_headers(headers) {
            return ip;
        }
    }

    // Not behind a trusted proxy, or headers are missing/invalid — use TCP peer IP
    peer.to_string()
}

/// Parse IP from proxy headers (only called when proxy is trusted)
fn extract_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    // X-Real-IP (nginx)
    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            let ip = ip_str.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                return Some(ip);
            }
        }
    }

    // CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("CF-Connecting-IP") {
        if let Ok(ip_str) = cf_ip.to_str() {
            let ip = ip_str.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                return Some(ip);
            }
        }
    }

    // X-Forwarded-For: take first (client) IP
    if let Some(xff) = headers.get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                let ip = first_ip.trim().to_string();
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    return Some(ip);
                }
            }
        }
    }

    None
}

/// Auth-specific rate limiter middleware (stricter: 10 req/min per IP)
///
/// Applied only to /auth/* endpoints to prevent brute-force attacks.
pub async fn auth_rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let peer_ip = connect_info.map(|ci| ci.0.ip().to_string());
    let client_ip = extract_client_ip_safe(&headers, peer_ip.as_deref(), &limiter.trusted_proxies);

    // Use "auth:" prefix to separate auth rate limit bucket from general one
    let key = format!("auth:{}", client_ip);
    let (allowed, remaining, reset_after) = limiter.check(&key).await;

    if !allowed {
        tracing::warn!("Auth rate limit exceeded for IP: {}", client_ip);

        let response = (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Limit", limiter.limit.to_string()),
                ("X-RateLimit-Remaining", "0".to_string()),
                ("X-RateLimit-Reset", reset_after.to_string()),
                ("Retry-After", reset_after.to_string()),
            ],
            Json(serde_json::json!({
                "error": "Too many authentication attempts. Please try again later.",
                "retry_after_seconds": reset_after
            }))
        );

        return Err(response.into_response());
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-RateLimit-Limit", limiter.limit.to_string().parse().unwrap());
    headers.insert("X-RateLimit-Remaining", remaining.to_string().parse().unwrap());
    headers.insert("X-RateLimit-Reset", reset_after.to_string().parse().unwrap());

    Ok(response)
}

/// Middleware для логирования запросов с IP
pub async fn logging_middleware(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let peer_ip = connect_info.map(|ci| ci.0.ip().to_string());
    let client_ip = extract_client_ip_safe(&headers, peer_ip.as_deref(), &[]);

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();

    tracing::info!(
        "{} {} {} -> {} ({:?})",
        client_ip,
        method,
        uri,
        response.status(),
        duration
    );

    response
}

/// Security headers middleware
pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Prevent clickjacking
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());

    // Prevent MIME sniffing
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());

    // XSS protection
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());

    // Referrer policy
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());

    // HSTS - enforce HTTPS (LOW-02)
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap()
    );

    // Content Security Policy
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'".parse().unwrap()
    );

    // Permissions Policy
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap()
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(3); // 3 requests per minute

        // First 3 requests should pass
        for i in 0..3 {
            let (allowed, remaining, _) = limiter.check("test_ip").await;
            assert!(allowed, "Request {} should be allowed", i);
            assert_eq!(remaining, 2 - i as u32);
        }

        // 4th request should be blocked
        let (allowed, remaining, _) = limiter.check("test_ip").await;
        assert!(!allowed, "4th request should be blocked");
        assert_eq!(remaining, 0);

        // Different IP should still be allowed
        let (allowed, _, _) = limiter.check("other_ip").await;
        assert!(allowed, "Different IP should be allowed");
    }

    #[test]
    fn test_extract_ip_no_trusted_proxies() {
        // HIGH-01: Without trusted proxies, headers are IGNORED
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "1.2.3.4".parse().unwrap());
        headers.insert("X-Forwarded-For", "5.6.7.8".parse().unwrap());

        let ip = extract_client_ip_safe(&headers, Some("10.0.0.1"), &[]);
        assert_eq!(ip, "10.0.0.1", "Should use peer IP when no trusted proxies configured");
    }

    #[test]
    fn test_extract_ip_trusted_proxy() {
        // HIGH-01: With trusted proxy, read from headers
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "1.2.3.4".parse().unwrap());

        let trusted = vec!["10.0.0.1".to_string()];
        let ip = extract_client_ip_safe(&headers, Some("10.0.0.1"), &trusted);
        assert_eq!(ip, "1.2.3.4", "Should use X-Real-IP from trusted proxy");
    }

    #[test]
    fn test_extract_ip_untrusted_proxy_spoofing() {
        // HIGH-01: Untrusted peer spoofing X-Real-IP — MUST be ignored
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "1.2.3.4".parse().unwrap());

        let trusted = vec!["10.0.0.1".to_string()]; // trusted is 10.0.0.1
        let ip = extract_client_ip_safe(&headers, Some("99.99.99.99"), &trusted); // peer is NOT trusted
        assert_eq!(ip, "99.99.99.99", "Should use peer IP — attacker cannot spoof");
    }

    #[test]
    fn test_extract_ip_no_peer() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip_safe(&headers, None, &[]);
        assert_eq!(ip, "unknown");
    }
}