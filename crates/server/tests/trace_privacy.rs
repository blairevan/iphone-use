//! Trace exports must honor privacy changes until their bodies are published.

use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use server as srv;
use server::http::{self, AppState};
use tower::ServiceExt;

include!("fixtures/app_state.rs");

/// Use the repository's runtime pattern without shadowing Rust's `core` crate.
fn block(future: impl std::future::Future<Output = Result<()>>) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

/// Queue a real router response without polling its body or touching a device.
async fn queued_trace(state: Arc<AppState>, format: &str) -> Result<Response> {
    let response = http::router(state)
        .oneshot(
            Request::get(format!(
                "/agent/trace?run_id=privacy-fixture&format={format}"
            ))
            .header("x-phone-owner", "trace-owner")
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(response)
}

/// Retain an empty diagnostic run whose export needs no runner or credentials.
fn trace_state() -> Result<Arc<AppState>> {
    let state = fixture_app_state(None);
    let started = state
        .action_traces
        .lock()
        .map_err(|_| anyhow::anyhow!("trace fixture lock poisoned"))?
        .start("trace-owner", "privacy-fixture");
    assert!(started);
    Ok(state)
}

/// Normal JSON and JSONL exports remain readable when privacy has not changed.
#[test]
fn trace_exports_remain_readable_in_the_original_privacy_scope() -> Result<()> {
    block(async {
        for format in ["json", "jsonl"] {
            let response = queued_trace(trace_state()?, format).await?;
            let bytes = to_bytes(response.into_body(), 64 * 1024).await?;
            assert!(std::str::from_utf8(&bytes)?.contains("privacy-fixture"));
        }
        Ok(())
    })
}

/// Even a completed private interval invalidates an already queued export.
#[test]
fn queued_trace_exports_stop_after_a_privacy_epoch_change() -> Result<()> {
    block(async {
        for format in ["json", "jsonl"] {
            let state = trace_state()?;
            let response = queued_trace(state.clone(), format).await?;
            state.privacy_epoch.fetch_add(1, Ordering::AcqRel);
            assert!(to_bytes(response.into_body(), 64 * 1024).await.is_err());
        }
        Ok(())
    })
}

/// A private hold that starts before publication withholds both export formats.
#[test]
fn queued_trace_exports_stop_when_a_private_hold_begins() -> Result<()> {
    block(async {
        for format in ["json", "jsonl"] {
            let state = trace_state()?;
            let response = queued_trace(state.clone(), format).await?;
            *state
                .private_until
                .lock()
                .map_err(|_| anyhow::anyhow!("privacy fixture lock poisoned"))? =
                Some(Instant::now() + Duration::from_secs(60));
            assert!(to_bytes(response.into_body(), 64 * 1024).await.is_err());
        }
        Ok(())
    })
}
