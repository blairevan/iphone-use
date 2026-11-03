//! Browser origin/Host protection and bounded pre-password admission. A request
//! header cannot appoint itself a trusted proxy or authenticated identity.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::AppState;

const LOGIN_WINDOW: Duration = Duration::from_secs(30);
const LOGIN_ATTEMPTS: u32 = 12;
const MAX_SOURCES: usize = 1024;

/// Check before password comparison. Post-verification failure throttling alone
/// would still let an attacker test unlimited guesses and recognize success.
#[derive(Default)]
pub struct LoginAdmission {
    sources: HashMap<IpAddr, (Instant, u32)>,
}

impl LoginAdmission {
    /// Keep a bounded source budget; never evict an active budget just because
    /// new sources arrive. This limits memory without a shared session lockout.
    pub fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        self.sources
            .retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_SOURCES {
            return false;
        }
        let (_, attempts) = self.sources.entry(source).or_insert((now, 0));
        if *attempts >= LOGIN_ATTEMPTS {
            return false;
        }
        *attempts += 1;
        true
    }
}

/// Ignore a base path used by older native clients, never the scheme or port.
fn origin(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// Parse IPv6 authorities correctly and reject Host userinfo/path injection.
fn host(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(&format!("http://{raw}/")).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    url.host_str()
        .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())
}

/// Native/CLI clients without Origin still authenticate normally. Public HTTPS
/// is allowed only for the configured origin, not a supplied Forwarded header.
pub fn browser_request_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let authority = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if let Some(authority) = authority {
        let Some(name) = host(authority) else {
            return false;
        };
        if !state.allowed_hosts.is_empty() && !state.allowed_hosts.iter().any(|h| h == &name) {
            return false;
        }
    }
    let Some(request_origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Some(request_origin) = request_origin.to_str().ok().and_then(origin) else {
        return false;
    };
    if state.public_url.as_deref().and_then(origin).as_deref() == Some(request_origin.as_str()) {
        return true;
    }
    let Some(authority) = authority else {
        return false;
    };
    origin(&format!("http://{authority}")).as_deref() == Some(request_origin.as_str())
}

/// Proxies explicitly named by the operator must OVERWRITE X-Real-IP. All
/// forwarded headers from any other transport peer are ignored.
fn client_ip(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if state.trusted_proxy_ips.contains(&peer)
        || headers.get("x-iphone-use-verified-relay").is_some()
    {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|ip| ip.parse().ok())
            .unwrap_or(peer)
    } else {
        peer
    }
}

/// Protect every browser route and WebSocket handshake, including base paths.
/// This layer never reads the body or logs credentials, goals or screen text.
pub async fn layer(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let response = boundary(state, request, next).await;
    security_headers(response)
}

/// Apply privacy headers to successes and early security failures alike.
fn security_headers(mut response: Response) -> Response {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
    ] {
        response
            .headers_mut()
            .insert(name, axum::http::HeaderValue::from_static(value));
    }
    response
}

/// Prove which transport delivered a request before letting headers influence
/// cookies, source attribution or origin decisions. These internal headers are
/// always stripped from caller input. A local proxy must overwrite forwarding
/// headers; an arbitrary remote peer is never trusted even if its IP is listed.
async fn boundary(state: Arc<AppState>, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip());
    if let Some(peer) = peer {
        if !peer.is_loopback() {
            return (
                StatusCode::FORBIDDEN,
                "direct remote HTTP is disabled; use the configured HTTPS entry point",
            )
                .into_response();
        }
    }
    request.headers_mut().remove("x-iphone-use-verified-https");
    request.headers_mut().remove("x-iphone-use-verified-relay");
    let relay = request
        .headers_mut()
        .remove("x-iphone-use-relay-ingress")
        .is_some_and(|value| {
            peer.is_some_and(|p| p.is_loopback())
                && core::auth::verify_password(
                    value.to_str().unwrap_or(""),
                    &core::auth::sign(&state.secret, "relay-ingress-v1"),
                )
        });
    let proxy = peer.is_some_and(|p| p.is_loopback() && state.trusted_proxy_ips.contains(&p));
    let public_origin = state.public_url.as_deref().and_then(origin);
    let authority = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    let matches_public = authority
        .and_then(|h| origin(&format!("https://{h}")))
        .is_some_and(|o| public_origin.as_deref() == Some(o.as_str()));
    let forwarded_https = request
        .headers()
        .get("x-forwarded-proto")
        .is_some_and(|v| v == "https");
    let secure = matches_public && (relay || (proxy && forwarded_https));
    if secure {
        request.headers_mut().insert(
            "x-iphone-use-verified-https",
            axum::http::HeaderValue::from_static("1"),
        );
        if relay {
            request.headers_mut().insert(
                "x-iphone-use-verified-relay",
                axum::http::HeaderValue::from_static("1"),
            );
        }
    } else if relay
        || matches_public
        || (state.public_url.is_none()
            && (request.headers().contains_key("x-forwarded-host")
                || request.headers().contains_key("x-forwarded-proto")))
    {
        return (
            StatusCode::FORBIDDEN,
            "remote HTTPS ingress is not configured or verified",
        )
            .into_response();
    }
    if !browser_request_allowed(&state, request.headers()) {
        return (StatusCode::FORBIDDEN, "untrusted browser origin or host").into_response();
    }
    let path = request.uri().path().trim_end_matches('/');
    let takeover = path.ends_with("/takeover") || path.ends_with("/security/credentials");
    let identity = crate::http::authenticated_record(&state, request.headers());
    if let Some(record) = &identity {
        if record.scope == crate::credentials::Scope::Read
            && !matches!(
                *request.method(),
                axum::http::Method::GET | axum::http::Method::HEAD
            )
        {
            return (StatusCode::FORBIDDEN, "credential has read-only permission").into_response();
        }
    }
    if request.method() == axum::http::Method::POST && (path.ends_with("/login") || takeover) {
        if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
            // A paired device is not an administrator: even a valid cookie
            // must not bypass password-guess admission at /login. Anonymous
            // requests cannot consume the separate administrator budget.
            if !takeover || crate::http::credentials_ok(&state, request.headers()) {
                let source = client_ip(&state, peer.ip(), request.headers());
                let budget = if takeover {
                    &state.admin_admission
                } else {
                    &state.login_admission
                };
                let allowed = budget
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .allow(source, Instant::now());
                if !allowed {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, "30")],
                        "password attempts temporarily limited for this source",
                    )
                        .into_response();
                }
            }
        }
    }
    let administrative_response = path.ends_with("/security/credentials");
    let response = next.run(request).await;
    if administrative_response {
        return response;
    }
    match identity {
        Some(record) => fence_response(response, state, record.id),
        None => response,
    }
}

/// Revocation also closes already-open video/event bodies, not just the next
/// HTTP request. No credential string is captured in the response stream.
fn fence_response(response: Response, state: Arc<AppState>, identity: String) -> Response {
    use futures_util::StreamExt;
    let changes = state
        .credentials
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .subscribe();
    let (parts, body) = response.into_parts();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), changes, state, identity),
        |(mut body, mut changes, state, identity)| async move {
            loop {
                if !state
                    .credentials
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .active(&identity)
                {
                    return None;
                }
                tokio::select! {
                    biased;
                    result = changes.changed() => { if result.is_err() { return None; } }
                    chunk = body.next() => return chunk.map(|chunk| (chunk, (body, changes, state, identity))),
                }
            }
        },
    );
    Response::from_parts(parts, axum::body::Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_admission_is_source_scoped_bounded_and_expires() {
        let mut limiter = LoginAdmission::default();
        let now = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..LOGIN_ATTEMPTS {
            assert!(limiter.allow(a, now));
        }
        assert!(!limiter.allow(a, now));
        assert!(limiter.allow(b, now));
        assert!(limiter.allow(a, now + LOGIN_WINDOW));
        for i in 0..MAX_SOURCES as u32 {
            limiter.allow(IpAddr::V4((0x0a000000 + i).into()), now + LOGIN_WINDOW);
        }
        assert!(limiter.sources.len() <= MAX_SOURCES);
        assert!(!limiter.allow("203.0.113.1".parse().unwrap(), now + LOGIN_WINDOW));
    }

    #[test]
    fn authority_and_origin_parsing_rejects_spoofing() {
        assert_eq!(host("[::1]:44321").as_deref(), Some("::1"));
        assert!(host("user@localhost").is_none());
        assert!(host("localhost/path").is_none());
        assert!(origin("null").is_none());
        assert_ne!(
            origin("https://control.example"),
            origin("http://control.example")
        );
        assert_ne!(
            origin("https://control.example:444"),
            origin("https://control.example")
        );
    }
}
