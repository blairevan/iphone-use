//! Security regression tests against the real router; no device or network.
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use server as srv;
use server::http::{self, AppState};
use tower::ServiceExt;

include!("fixtures/app_state.rs");

/// A nonce response copied from the real daemon cannot authorize a different
/// TLS origin. The approved base path is part of the proof, not a Host header.
#[test]
fn migration_proof_binds_the_approved_https_address() {
    block(async {
        let mut state = Arc::try_unwrap(state()).ok().unwrap();
        state.public_url = Some("https://control.example/one".into());
        let key = srv::pairing::lan_key(&srv::pairing::device_key(
            &state.secret,
            state.password.as_deref(),
        ));
        let app = http::router(Arc::new(state));
        let nonce = "0123456789abcdef01234567";
        for target in [
            "https://attacker.example/one",
            "https://control.example/two",
            "http://control.example/one",
        ] {
            let mut url = reqwest::Url::parse("http://127.0.0.1/pair/probe").unwrap();
            url.query_pairs_mut()
                .append_pair("n", nonce)
                .append_pair("u", target);
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("{}?{}", url.path(), url.query().unwrap()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let target = "https://control.example/one";
        let mut url = reqwest::Url::parse("http://127.0.0.1/pair/probe").unwrap();
        url.query_pairs_mut()
            .append_pair("n", nonce)
            .append_pair("u", target);
        let response = app
            .oneshot(
                Request::get(format!("{}?{}", url.path(), url.query().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["proof"],
            srv::core_crate::auth::sign(&key, &format!("iphone-use-route-v2\n{nonce}\n{target}"))
        );
        assert_ne!(body["proof"], srv::core_crate::auth::sign(&key, nonce));
    });
}

/// Run an isolated router without touching system services.
fn block<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// Authenticate with synthetic credentials configured only for this test.
fn state() -> Arc<AppState> {
    let mut state = Arc::try_unwrap(fixture_app_state(Some("fixture-password")))
        .ok()
        .unwrap();
    state.agent_token = Some("fixture-agent".into());
    Arc::new(state)
}

#[test]
fn anonymous_pairing_failures_cannot_revoke_login_bearer_or_renewal() {
    block(async {
        let state = state();
        let code = state.pairing.issue();
        let app = http::router(state.clone());
        for _ in 0..8 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/pair")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"code":"invalid"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
            ));
        }
        assert!(state.pair_limiter.lock().unwrap().is_locked());
        assert!(!state.login_limiter.lock().unwrap().is_locked());
        assert!(!state.auth_limiter.lock().unwrap().is_locked());
        let login = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=fixture-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let bearer = app
            .clone()
            .oneshot(
                Request::get("/agent/status")
                    .header(header::AUTHORIZATION, "Bearer fixture-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bearer.status(), StatusCode::OK);
        let paired = app
            .clone()
            .oneshot(
                Request::post("/pair")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({"code":code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paired.status(), StatusCode::OK);
        let bytes = paired.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for _ in 0..5 {
            state.pair_limiter.lock().unwrap().record_failure();
        }
        let renewed = app
            .clone()
            .oneshot(
                Request::post("/pair")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"device_token":payload["device_token"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(renewed.status(), StatusCode::OK);
        let replay = app
            .oneshot(
                Request::post("/pair")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({"code":code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            replay.status(),
            StatusCode::UNAUTHORIZED,
            "the code still redeems only once"
        );
    });
}

#[test]
fn valid_password_and_bearer_work_with_full_failure_buckets() {
    block(async {
        let state = state();
        for _ in 0..5 {
            state.login_limiter.lock().unwrap().record_failure();
            state.auth_limiter.lock().unwrap().record_failure();
        }
        let app = http::router(state);
        let login = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=fixture-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let bearer = app
            .oneshot(
                Request::get("/agent/status")
                    .header(header::AUTHORIZATION, "Bearer fixture-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bearer.status(), StatusCode::OK);
    });
}

#[test]
fn token_only_login_cannot_mint_anonymous_session() {
    block(async {
        let mut state = Arc::try_unwrap(state()).ok().unwrap();
        state.password = None;
        let app = http::router(Arc::new(state));
        let login = app
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=anything"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
        assert!(!login.headers().contains_key(header::SET_COOKIE));
    });
}

#[test]
fn trusted_https_pairing_works_with_loopback_backend_and_ignores_host_input() {
    block(async {
        let mut state = Arc::try_unwrap(state()).ok().unwrap();
        state.public_url = Some("https://control.example/phone-one".into());
        state.pairing = Arc::new(server::pairing::Pairing::new(false));
        let cookie = format!(
            "phone_session={}",
            srv::core_crate::auth::make_token(&state.secret, 3600, u64::MAX / 2)
        );
        let app = http::router(Arc::new(state));
        let response = app
            .clone()
            .oneshot(
                Request::post("/pair/new?host=attacker.example")
                    .header(header::HOST, "127.0.0.1:44321")
                    .header(header::COOKIE, cookie)
                    .header("x-phone-control", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(payload["url"]
            .as_str()
            .unwrap()
            .starts_with("https://control.example/phone-one/pair?c="));
        assert_eq!(payload["host"], "control.example");
        let code = payload["url"]
            .as_str()
            .unwrap()
            .split("?c=")
            .nth(1)
            .unwrap();
        let page = app
            .oneshot(
                Request::get(format!("/pair?c={code}"))
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = String::from_utf8(
            page.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("https%3A%2F%2Fcontrol.example%2Fphone-one"));
        assert!(!html.contains("attacker.example"));
    });
}

#[test]
fn browser_origin_and_dns_rebinding_cannot_reuse_a_valid_session() {
    block(async {
        let mut state = Arc::try_unwrap(state()).ok().unwrap();
        state.allowed_hosts = vec!["127.0.0.1".into(), "control.example".into()];
        state.public_url = Some("https://control.example".into());
        state.trusted_proxy_ips = vec!["127.0.0.1".parse().unwrap()];
        let token =
            srv::core_crate::auth::try_make_token(&state.secret, 3600, u64::MAX / 2).unwrap();
        let app = http::router(Arc::new(state));
        for (host, origin) in [
            ("evil.example", "http://evil.example"),
            ("127.0.0.1:44321", "https://evil.example"),
            ("127.0.0.1:44321", "null"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/pair/new")
                        .header(header::HOST, host)
                        .header(header::ORIGIN, origin)
                        .header(header::COOKIE, format!("phone_session={token}"))
                        .header("x-phone-control", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = app
            .oneshot(
                Request::get("/agent/status")
                    .extension(axum::extract::ConnectInfo(
                        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .header("x-forwarded-proto", "https")
                    .header(header::HOST, "control.example")
                    .header(header::ORIGIN, "https://control.example")
                    .header(header::COOKIE, format!("phone_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[test]
fn password_admission_does_not_lock_out_other_sources_or_valid_agents() {
    block(async {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;
        let app = http::router(state());
        let peer: SocketAddr = "127.0.0.2:12345".parse().unwrap();
        for _ in 0..12 {
            let _ = app
                .clone()
                .oneshot(
                    Request::post("/login")
                        .extension(ConnectInfo(peer))
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from("password=wrong"))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let blocked = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .extension(ConnectInfo(peer))
                    .header("x-real-ip", "198.51.100.1")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=fixture-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            blocked.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "an untrusted forwarded IP cannot reset the pre-password budget"
        );
        let other = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .extension(ConnectInfo(
                        "127.0.0.3:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=fixture-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::SEE_OTHER);
        let agent = app
            .oneshot(
                Request::get("/agent/status")
                    .extension(ConnectInfo(peer))
                    .header(header::AUTHORIZATION, "Bearer fixture-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(agent.status(), StatusCode::OK);
    });
}

#[test]
fn direct_remote_http_is_refused_and_cookie_security_cannot_be_forged() {
    block(async {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;
        let mut state = Arc::try_unwrap(state()).ok().unwrap();
        state.public_url = Some("https://control.example".into());
        state.allowed_hosts = vec!["control.example".into(), "127.0.0.1".into()];
        state.trusted_proxy_ips = vec!["127.0.0.1".parse().unwrap()];
        let app = http::router(Arc::new(state));
        let direct = app
            .clone()
            .oneshot(
                Request::get("/agent/status")
                    .extension(ConnectInfo(
                        "192.0.2.10:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(header::AUTHORIZATION, "Bearer fixture-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(direct.status(), StatusCode::FORBIDDEN);
        for (host, forwarded, secure) in [
            ("control.example", "https", true),
            ("127.0.0.1:44321", "https", false),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/login")
                        .extension(ConnectInfo(
                            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                        ))
                        .header(header::HOST, host)
                        .header("x-forwarded-proto", forwarded)
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from("password=fixture-password"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("; Secure"),
                secure
            );
        }
        let forged = app
            .oneshot(
                Request::post("/login")
                    .extension(ConnectInfo(
                        "127.0.0.2:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(header::HOST, "control.example")
                    .header("x-iphone-use-verified-https", "1")
                    .header("x-iphone-use-relay-ingress", "forged")
                    .header("x-forwarded-proto", "https")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=fixture-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);
        assert!(!forged.headers().contains_key(header::SET_COOKIE));
    });
}

#[test]
fn administrator_can_revoke_one_device_without_disabling_another_or_agent() {
    block(async {
        let state = state();
        let app = http::router(state.clone());
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let code = state.pairing.issue();
            let response = app
                .clone()
                .oneshot(
                    Request::post("/pair")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::json!({"code":code}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let identity = app
                .clone()
                .oneshot(
                    Request::get("/agent/security/session")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = identity.into_body().collect().await.unwrap().to_bytes();
            let identity: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            sessions.push((
                cookie,
                body["device_token"].clone(),
                identity["credential"]["id"].clone(),
            ));
        }
        let result = app.clone().oneshot(Request::post("/agent/security/credentials")
            .header(header::AUTHORIZATION,"Bearer fixture-agent")
            .header("x-phone-control","1").header(header::CONTENT_TYPE,"application/json")
            .body(Body::from(serde_json::json!({"action":"revoke","id":sessions[0].2,"admin_password":"fixture-password"}).to_string())).unwrap()).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.headers()[header::CACHE_CONTROL], "no-store");
        for (index, (cookie, token, _)) in sessions.iter().enumerate() {
            let session = app
                .clone()
                .oneshot(
                    Request::get("/agent/security/session")
                        .header(header::COOKIE, cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                session.status(),
                if index == 0 {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::OK
                }
            );
            let renewal = app
                .clone()
                .oneshot(
                    Request::post("/pair")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::json!({"device_token":token}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                renewal.status(),
                if index == 0 {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::OK
                }
            );
        }
        let agent = app
            .oneshot(
                Request::get("/agent/status")
                    .header(header::AUTHORIZATION, "Bearer fixture-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(agent.status(), StatusCode::OK);
    });
}

#[test]
fn issued_readonly_agent_cannot_mutate_or_self_promote() {
    block(async {
        let state = state();
        let (record, token) = state
            .credentials
            .lock()
            .unwrap()
            .issue_agent(
                &state.secret,
                "fixture reader",
                srv::credentials::Scope::Read,
                1,
            )
            .unwrap();
        let app = http::router(state.clone());
        let read = app
            .clone()
            .oneshot(
                Request::get("/agent/status")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        for path in ["/agent/input", "/agent/task", "/agent/security/credentials"] {
            let response = app.clone().oneshot(Request::post(path).header(header::AUTHORIZATION,format!("Bearer {token}"))
                .header("x-phone-control","1").header(header::CONTENT_TYPE,"application/json")
                .body(Body::from(r#"{"action":"create_agent","scope":"control","admin_password":"fixture-password"}"#)).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        state
            .credentials
            .lock()
            .unwrap()
            .revoke(&record.id)
            .unwrap();
        let denied = app
            .oneshot(
                Request::get("/agent/status")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    });
}
