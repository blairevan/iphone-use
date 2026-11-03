//! Administrator UI/API. Authentication is fresh per action; no password is
//! accepted in query parameters or echoed into logs, argv or response bodies.

use crate::http::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use std::sync::Arc;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAction {
    action: String,
    admin_password: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default = "read_scope")]
    scope: crate::credentials::Scope,
}
fn read_scope() -> crate::credentials::Scope {
    crate::credentials::Scope::Read
}

/// Fail closed unless the transport boundary and normal auth already accepted
/// the request, then independently check a freshly supplied human password.
pub(crate) fn admin_ok(state: &AppState, headers: &HeaderMap, password: &str) -> bool {
    crate::http::credentials_ok(state, headers)
        && headers.get("x-phone-control").is_some_and(|v| v == "1")
        && !password.is_empty()
        && state
            .password
            .as_deref()
            .is_some_and(|expected| core::auth::verify_password(password, expected))
}

/// List, issue or revoke credentials; returns no persisted credential material.
pub async fn manage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(action): Json<AdminAction>,
) -> Response {
    if !admin_ok(&state, &headers, &action.admin_password) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"ok":false,"error":"administrator_reauthentication_required"})),
        )
            .into_response();
    }
    let actor = crate::http::authenticated_record(&state, &headers)
        .map(|r| r.id)
        .unwrap_or_default();
    let mut store = state.credentials.lock().unwrap_or_else(|p| p.into_inner());
    let result: anyhow::Result<serde_json::Value> = match action.action.as_str() {
        "list" => Ok(serde_json::json!({"credentials":store.list()})),
        "create_agent" => store.issue_agent(&state.secret, &action.name, action.scope, crate::update::unix_now())
            .map(|(record, token)| serde_json::json!({"credential":record,"token":token,"shown_once":true})),
        "revoke" => store.revoke(&action.id).map(|()| {
            iphone_use_mcp::task::cancel_principal(&action.id);
            serde_json::json!({"revoked":action.id})
        }),
        "revoke_all" => store.revoke_all().map(|()| {
            for record in store.list() { iphone_use_mcp::task::cancel_principal(&record.id); }
            serde_json::json!({"revoked_all":true})
        }),
        "revoke_devices" => store.revoke_devices().map(|ids| {
            for id in &ids { iphone_use_mcp::task::cancel_principal(id); }
            serde_json::json!({"revoked_devices":ids})
        }),
        _ => Err(anyhow::anyhow!("unknown management action")),
    };
    match result {
        Ok(mut value) => {
            value["ok"] = true.into();
            if action.action != "list" {
                tracing::warn!(
                    operation = action.action.as_str(),
                    principal = actor.as_str(),
                    "credential administration completed"
                );
            }
            Json(value).into_response()
        }
        // Do not propagate an arbitrary serializer/filesystem error body to
        // logs or the browser; it may include private data or paths.
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok":false,"error":"credential_change_failed"})),
        )
            .into_response(),
    }
}

/// Return the live identity so clients can display revocation/permissions
/// without guessing from a self-asserted owner field.
pub async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match crate::http::authenticated_record(&state, &headers) {
        Some(record) => {
            Json(serde_json::json!({"ok":true,"credential":record,"public_url":state.public_url}))
                .into_response()
        }
        None => (StatusCode::UNAUTHORIZED, "authenticated identity required").into_response(),
    }
}

/// A minimal same-origin administrator screen; dynamic values use textContent
/// or JSON text, never HTML insertion. Password is not stored after a request.
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !crate::http::is_authed(&state, &headers) {
        return axum::response::Redirect::to(&format!("{}/login", state.base_path)).into_response();
    }
    Html(include_str!("../../../web/security.html")).into_response()
}
