//! Opt-in Cloudflare Zero Trust Access inventory and tightly scoped management.
//! The Cloudflare API is fixed to api.cloudflare.com; callers cannot supply URLs.
//! No login callback triggers a Cloudflare mutation, and token revocation is
//! intentionally explicit, global to the linked Access app and disabled by default.
use crate::{AppError, AppResult, AppState, management};
use axum::{extract::{Path, Query, State}, http::HeaderMap, Json};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::env;

const PAGE_SIZE: u16 = 50;
const MAX_RESPONSE: usize = 1_048_576;
const REVOKE_CONFIRMATION: &str = "REVOKE_ALL_ACCESS_TOKENS";

struct CloudflareSettings {
    account_id: String,
    token: String,
    revoke_enabled: bool,
}

impl CloudflareSettings {
    fn load() -> AppResult<Option<Self>> {
        let account_id = env::var("SSO_CLOUDFLARE_ACCOUNT_ID").unwrap_or_default();
        let token = env::var("SSO_CLOUDFLARE_API_TOKEN").unwrap_or_default();
        if account_id.is_empty() && token.is_empty() { return Ok(None); }
        if !valid_hex_id(&account_id) || account_id.len() != 32 ||
           token.len() < 10 || token.len() > 2048 || token.chars().any(|c| c.is_control()) {
            return Err(AppError::bad("invalid Cloudflare account/token configuration"));
        }
        Ok(Some(Self {
            account_id,
            token,
            revoke_enabled: env::var("SSO_CLOUDFLARE_ENABLE_REVOKE").as_deref() == Ok("true"),
        }))
    }
}

fn valid_hex_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit())
}
fn valid_access_app_id(id: &str) -> bool {
    (id.len() == 32 && valid_hex_id(id)) ||
    (id.len() == 36 && id.chars().enumerate().all(|(i,c)| {
        if [8,13,18,23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() }
    }))
}
fn settings() -> AppResult<CloudflareSettings> {
    CloudflareSettings::load()?.ok_or_else(|| AppError::bad("Cloudflare Zero Trust is not configured"))
}

async fn request(state: &AppState, cf: &CloudflareSettings, method: Method, path: &str,
                 body: Option<Value>) -> AppResult<Value> {
    // Every path is assembled by this module from static API paths and validated IDs.
    let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/access/{}",
                      cf.account_id, path);
    let mut builder = state.http.request(method, url)
        .bearer_auth(&cf.token)
        .header("Accept", "application/json");
    if let Some(payload) = body { builder = builder.json(&payload); }
    let response = builder.send().await.map_err(|e| {
        tracing::warn!(kind = ?e.status(), "Cloudflare API request failed");
        AppError::cloudflare_failure()
    })?;
    if !response.status().is_success() {
        tracing::warn!(http_status = %response.status(), "Cloudflare API returned error");
        return Err(AppError::cloudflare_failure());
    }
    let bytes = response.bytes().await.map_err(|_| AppError::cloudflare_failure())?;
    if bytes.len() > MAX_RESPONSE { return Err(AppError::cloudflare_failure()); }
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|_| AppError::cloudflare_failure())?;
    if parsed.get("success") != Some(&Value::Bool(true)) {
        return Err(AppError::cloudflare_failure());
    }
    Ok(parsed)
}

#[derive(Deserialize)]
pub struct ListPage { page: Option<u16> }

pub async fn status(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    let cfg = CloudflareSettings::load()?;
    Ok(Json(json!({
        "configured": cfg.is_some(),
        "account_id": cfg.as_ref().map(|c| c.account_id.as_str()),
        "revoke_enabled": cfg.as_ref().is_some_and(|c| c.revoke_enabled),
        "revoke_scope": "linked_access_app_all_users",
    })))
}

async fn inventory(state: AppState, headers: HeaderMap, page: ListPage, kind: &str)
    -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    let cf = settings()?;
    let page = page.page.unwrap_or(1).clamp(1, 100);
    let path = format!("{kind}?page={page}&per_page={PAGE_SIZE}");
    let data = request(&state, &cf, Method::GET, &path, None).await?;
    let list = data.get("result").and_then(Value::as_array)
        .ok_or_else(AppError::cloudflare_failure)?;
    let records: Vec<Value> = list.iter().map(|v| match kind {
        "apps" => json!({"id":v.get("id"),"name":v.get("name"),"domain":v.get("domain"),
                         "type":v.get("type")}),
        "groups" => json!({"id":v.get("id"),"name":v.get("name")}),
        _ => json!({"id":v.get("id"),"name":v.get("name"),"decision":v.get("decision"),
                    "precedence":v.get("precedence")}),
    }).collect();
    let info = data.get("result_info").cloned().unwrap_or(Value::Null);
    Ok(Json(json!({"items":records,"page":page,"per_page":PAGE_SIZE,"result_info":info})))
}

pub async fn apps(State(state): State<AppState>, headers: HeaderMap, Query(page): Query<ListPage>)
    -> AppResult<Json<Value>> { inventory(state,headers,page,"apps").await }
pub async fn groups(State(state): State<AppState>, headers: HeaderMap, Query(page): Query<ListPage>)
    -> AppResult<Json<Value>> { inventory(state,headers,page,"groups").await }
pub async fn policies(State(state): State<AppState>, headers: HeaderMap, Query(page): Query<ListPage>)
    -> AppResult<Json<Value>> { inventory(state,headers,page,"policies").await }

pub async fn links(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    let rows = sqlx::query(
        "SELECT l.client_id, c.name, l.access_app_id, l.created FROM cloudflare_app_links l \
         JOIN clients c ON c.id=l.client_id ORDER BY c.name"
    ).fetch_all(&state.db.pool).await?;
    let mut items = Vec::new();
    for row in rows {
        items.push(json!({
            "client_id": row.try_get::<String,_>("client_id")?,
            "client_name": row.try_get::<String,_>("name")?,
            "access_app_id": row.try_get::<String,_>("access_app_id")?,
            "created": row.try_get::<i64,_>("created")?,
        }));
    }
    Ok(Json(json!(items)))
}

#[derive(Deserialize)]
pub struct LinkInput { access_app_id: String }

pub async fn put_link(State(state): State<AppState>, headers: HeaderMap,
                      Path(client): Path<String>, Json(input): Json<LinkInput>)
    -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    if !valid_access_app_id(&input.access_app_id) {
        return Err(AppError::bad("invalid Access application ID"));
    }
    let cf = settings()?;
    let app = request(&state, &cf, Method::GET,
                      &format!("apps/{}", input.access_app_id), None).await?;
    if app.pointer("/result/id").and_then(Value::as_str) != Some(&input.access_app_id) {
        return Err(AppError::bad("Access application does not exist"));
    }
    let mut tx = state.db.pool.begin().await?;
    let exists = sqlx::query(&state.db.q("SELECT id FROM clients WHERE id=?"))
        .bind(&client).fetch_optional(&mut *tx).await?.is_some();
    if !exists { return Err(AppError::bad("unknown SSO client")); }
    // Transaction preserves the old mapping if another client owns the app ID.
    sqlx::query(&state.db.q("DELETE FROM cloudflare_app_links WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q(
        "INSERT INTO cloudflare_app_links (client_id,access_app_id,created) VALUES (?,?,?)"
    )).bind(&client).bind(&input.access_app_id).bind(crate::crypto::now())
      .execute(&mut *tx).await?;
    crate::sessions::event_tx(&state, &mut tx, "admin", "cloudflare.link.save",
        json!({"client_id":&client,"access_app_id":&input.access_app_id})).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":client,"access_app_id":input.access_app_id})))
}

pub async fn delete_link(State(state): State<AppState>, headers: HeaderMap,
                         Path(client): Path<String>) -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    let affected = sqlx::query(&state.db.q("DELETE FROM cloudflare_app_links WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?.rows_affected();
    if affected > 0 {
        crate::sessions::event_tx(&state, &mut tx, "admin", "cloudflare.link.delete",
            json!({"client_id":&client})).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"deleted":affected > 0})))
}

#[derive(Deserialize)]
pub struct RevokeInput {
    confirm_app_id: String,
    confirmation: String,
}

pub async fn revoke_app_tokens(State(state): State<AppState>, headers: HeaderMap,
                               Path(app_id): Path<String>, Json(input): Json<RevokeInput>)
    -> AppResult<Json<Value>> {
    management::admin(&state, &headers)?;
    let cf = settings()?;
    if !cf.revoke_enabled { return Err(AppError::forbidden()); }
    if !valid_access_app_id(&app_id) ||
       input.confirm_app_id != app_id || input.confirmation != REVOKE_CONFIRMATION {
        return Err(AppError::bad("explicit application-wide revocation confirmation required"));
    }
    let row = sqlx::query(&state.db.q(
        "SELECT client_id FROM cloudflare_app_links WHERE access_app_id=?"
    )).bind(&app_id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::bad("Access app must be linked before revocation"))?;
    let client_id: String = row.try_get("client_id")?;
    // Journal intent *before* the remote irreversible operation so a process
    // failure never leaves a totally unaudited attempt.
    let operation_id = uuid::Uuid::new_v4().to_string();
    let mut tx = state.db.pool.begin().await?;
    crate::sessions::event_tx(&state,&mut tx,"admin","cloudflare.app.revoke.requested",
        json!({"operation_id":&operation_id,"access_app_id":&app_id,
               "client_id":&client_id})).await?;
    tx.commit().await?;
    request(&state,&cf,Method::POST,&format!("apps/{app_id}/revoke_tokens"),None).await?;
    let mut tx = state.db.pool.begin().await?;
    crate::sessions::event_tx(&state,&mut tx,"admin","cloudflare.app.revoke.completed",
        json!({"operation_id":&operation_id,"access_app_id":&app_id,
               "client_id":&client_id})).await?;
    tx.commit().await?;
    Ok(Json(json!({"revoked":true,"access_app_id":app_id,"operation_id":operation_id,
                    "scope":"all_users_of_access_application"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_cannot_escape_static_cloudflare_api_path() {
        assert!(valid_access_app_id("0123456789abcdef0123456789abcdef"));
        assert!(valid_access_app_id("01234567-89ab-cdef-0123-456789abcdef"));
        for value in ["", "../organizations", "a/b", "0123456789abcdef0123456789abcde/",
                      "01234567-89ab-cdef-0123-456789abcdeg"] {
            assert!(!valid_access_app_id(value));
        }
    }
    #[test]
    fn confirmation_is_exact_and_never_inferred_from_app_id() {
        let correct: RevokeInput = serde_json::from_value(json!({
            "confirm_app_id":"0123456789abcdef0123456789abcdef",
            "confirmation":"REVOKE_ALL_ACCESS_TOKENS"
        })).unwrap();
        assert_eq!(correct.confirmation, REVOKE_CONFIRMATION);
        assert_ne!("revoke", REVOKE_CONFIRMATION);
    }
}
