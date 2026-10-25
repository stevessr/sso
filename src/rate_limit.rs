//! Bounded, in-process abuse guard for authentication endpoints.
//!
//! We intentionally use the TCP peer address, not untrusted X-Forwarded-For.
//! Behind a reverse proxy, configure an additional edge-side per-client limiter;
//! this guard remains a conservative defense-in-depth layer, shared by proxy users.
use axum::{
    extract::{connect_info::ConnectInfo, Request},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const MAX_BUCKETS: usize = 16_384;

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
enum Kind {
    Start, Callback, Token, Introspection, Registration, Management, Account,
}

fn policy(path: &str) -> Option<(Kind, u32, Duration)> {
    let minute = 60;
    match path {
        "/oauth/authorize" => Some((Kind::Start, 30, Duration::from_secs(5 * minute))),
        "/oauth/token" => Some((Kind::Token, 60, Duration::from_secs(5 * minute))),
        "/oauth/introspect" => Some((Kind::Introspection, 120, Duration::from_secs(5 * minute))),
        "/oauth/revoke" => Some((Kind::Token, 60, Duration::from_secs(5 * minute))),
        "/connect/register" => Some((Kind::Registration, 10, Duration::from_secs(60 * minute))),
        "/oauth/consent/decision" | "/session/logout" =>
            Some((Kind::Account, 40, Duration::from_secs(5 * minute))),
        path if path.starts_with("/auth/callback/") =>
            Some((Kind::Callback, 30, Duration::from_secs(5 * minute))),
        path if path.starts_with("/login/") =>
            Some((Kind::Start, 30, Duration::from_secs(5 * minute))),
        path if path.starts_with("/admin/") =>
            Some((Kind::Management, 120, Duration::from_secs(5 * minute))),
        path if path.starts_with("/me/link/") || path.starts_with("/me/unlink/")
            || path.starts_with("/me/apps/") =>
            Some((Kind::Account, 40, Duration::from_secs(5 * minute))),
        _ => None,
    }
}

struct Bucket {
    count: u32,
    resets_at: Instant,
}

#[derive(Default)]
struct Limiter {
    buckets: Mutex<HashMap<(IpAddr, Kind), Bucket>>,
}

impl Limiter {
    /// Returns the whole seconds until the bucket resets if the request is blocked.
    fn check(&self, ip: IpAddr, kind: Kind, limit: u32, window: Duration, now: Instant)
        -> Result<(), u64>
    {
        // Never poison-fail open: a crashed holder must not disable abuse controls.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= MAX_BUCKETS {
            buckets.retain(|_, bucket| bucket.resets_at > now);
        }
        let key = (ip, kind);
        if !buckets.contains_key(&key) && buckets.len() >= MAX_BUCKETS {
            return Err(window.as_secs().max(1));
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            count: 0,
            resets_at: now + window,
        });
        if now >= bucket.resets_at {
            bucket.count = 0;
            bucket.resets_at = now + window;
        }
        if bucket.count >= limit {
            return Err(bucket.resets_at.saturating_duration_since(now).as_secs().max(1));
        }
        bucket.count += 1;
        Ok(())
    }
}

static LIMITER: OnceLock<Limiter> = OnceLock::new();

pub async fn guard(request: Request, next: Next) -> Response {
    if let Some((kind, cap, window)) = policy(request.uri().path()) {
        // Do not accept user-supplied forwarding headers as a source of identity.
        // SocketAddr comes only from Axum's connect-info service.
        let peer = request.extensions().get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        if let Err(retry) = LIMITER.get_or_init(Limiter::default)
            .check(peer, kind, cap, window, Instant::now())
        {
            let mut response = (StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"rate_limited","retry_after":retry}))).into_response();
            response.headers_mut().insert(header::RETRY_AFTER,
                HeaderValue::from_str(&retry.to_string()).unwrap_or_else(|_| HeaderValue::from_static("60")));
            return response;
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn buckets_are_scoped_to_peer_and_endpoint_group() {
        let limiter = Limiter::default();
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(limiter.check(a, Kind::Token, 2, window, now).is_ok());
        assert!(limiter.check(a, Kind::Token, 2, window, now).is_ok());
        assert!(limiter.check(a, Kind::Token, 2, window, now).is_err());
        assert!(limiter.check(a, Kind::Registration, 2, window, now).is_ok());
        assert!(limiter.check(b, Kind::Token, 2, window, now).is_ok());
        assert!(limiter.check(a, Kind::Token, 2, window, now + window).is_ok());
    }
    #[test]
    fn no_untrusted_header_bypass_or_health_limit() {
        assert!(policy("/healthz").is_none());
        assert!(policy("/assets/app.js").is_none());
        assert!(policy("/oauth/token").is_some());
        assert!(policy("/login/google").is_some());
        assert!(policy("/connect/register").is_some());
    }
}
