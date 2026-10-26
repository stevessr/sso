//! RFC 8628 OAuth2 Device Authorization Grant.
//! An untrusted device learns no browser credentials. Approval happens on a
//! separate, MFA-assured first-party browser session.
use crate::{auth, crypto, AppError, AppResult, AppState};
use axum::{extract::{Form, Query, State}, http::HeaderMap, response::Html, Json};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

const LIFETIME: i64 = 600;
const INTERVAL: i64 = 5;
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Deserialize)]
pub struct StartForm {
    client_id: Option<String>, client_secret: Option<String>, scope: Option<String>,
}
fn normalize_code(value: &str) -> Option<String> {
    let code: String = value.chars().filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_ascii_uppercase()).collect();
    (code.len() == 8 && code.bytes().all(|c| ALPHABET.contains(&c))).then_some(code)
}
fn user_code() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    // The alphabet has exactly 32 entries. Security derives from 40 random bits.
    bytes.iter().map(|b| ALPHABET[(b & 31) as usize] as char).collect()
}
fn scope_valid(scope: &str) -> bool {
    !scope.is_empty() && scope.len() <= 128 &&
        scope.split_whitespace().all(|s| matches!(s,"profile"|"email"|"offline_access")) &&
        !scope.split_whitespace().collect::<Vec<_>>().is_empty()
}
pub async fn authorize(State(state): State<AppState>, headers: HeaderMap, Form(form): Form<StartForm>)
    -> AppResult<Json<Value>>
{
    let client = auth::authenticate_client(&state, &headers,
        form.client_id.as_deref(), form.client_secret.as_deref()).await?;
    let scope = form.scope.unwrap_or_else(||"profile".into());
    if !scope_valid(&scope) { return Err(AppError::bad("invalid_scope")); }
    let device_code = crypto::random_token();
    let user_code = user_code();
    let now = crypto::now();
    sqlx::query(&state.db.q(
        "INSERT INTO device_grants (device_hash,user_code_hash,client_id,scope,user_id,state,expires,last_poll,poll_interval) \
         VALUES (?,?,?,?,NULL,'pending',?,0,?)"))
        .bind(crypto::digest(&device_code)).bind(crypto::digest(&user_code))
        .bind(&client).bind(&scope).bind(now + LIFETIME).bind(INTERVAL)
        .execute(&state.db.pool).await?;
    let verification_uri = format!("{}/device",state.config.public_url);
    let verification_uri_complete = format!("{}?user_code={}-{}",
        verification_uri,&user_code[..4],&user_code[4..]);
    Ok(Json(json!({
        "device_code": device_code, "user_code": format!("{}-{}",&user_code[..4],&user_code[4..]),
        "verification_uri":verification_uri,"verification_uri_complete":verification_uri_complete,
        "expires_in":LIFETIME,"interval":INTERVAL
    })))
}
pub async fn page() -> Html<&'static str> { Html(include_str!("../web/device.html")) }

#[derive(Deserialize)]
pub struct CodeQuery { user_code: String }
pub async fn request(State(state): State<AppState>, headers: HeaderMap, Query(q):Query<CodeQuery>)
    -> AppResult<Json<Value>>
{
    let _user = auth::session_user(&state,&headers).await?;
    let normalized = normalize_code(&q.user_code).ok_or_else(||AppError::bad("invalid_user_code"))?;
    let row = sqlx::query(&state.db.q(
        "SELECT c.name,d.client_id,d.scope,d.expires FROM device_grants d \
         JOIN clients c ON c.id=d.client_id AND c.enabled=1 \
         WHERE d.user_code_hash=? AND d.state='pending' AND d.expires>?"))
        .bind(crypto::digest(&normalized)).bind(crypto::now())
        .fetch_optional(&state.db.pool).await?
        .ok_or_else(||AppError::bad("invalid_or_expired_user_code"))?;
    Ok(Json(json!({"client_name":row.try_get::<String,_>("name")?,
        "client_id":row.try_get::<String,_>("client_id")?,
        "scope":row.try_get::<String,_>("scope")?,
        "expires":row.try_get::<i64,_>("expires")?})))
}
#[derive(Deserialize)]
pub struct DecisionInput { user_code:String, decision:String }
pub async fn decision(State(state): State<AppState>, headers:HeaderMap, Json(body):Json<DecisionInput>)
    -> AppResult<Json<Value>>
{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    if !matches!(body.decision.as_str(),"allow"|"deny") {
        return Err(AppError::bad("invalid_decision"));
    }
    let code=normalize_code(&body.user_code).ok_or_else(||AppError::bad("invalid_user_code"))?;
    let digest=crypto::digest(&code);
    let new_state=if body.decision=="allow" {"approved"} else {"denied"};
    // No already-approved, expired or disabled-client grant can be changed.
    let changed=sqlx::query(&state.db.q(
        "UPDATE device_grants SET state=?,user_id=? WHERE user_code_hash=? AND state='pending' AND expires>? \
         AND client_id IN (SELECT id FROM clients WHERE enabled=1)"))
        .bind(new_state).bind(&user).bind(digest).bind(crypto::now())
        .execute(&state.db.pool).await?;
    if changed.rows_affected()!=1 {return Err(AppError::bad("invalid_or_expired_user_code"))}
    Ok(Json(json!({"ok":true,"status":new_state})))
}

/// This function is invoked only after the normal token endpoint has checked
/// client authentication (including its secret for confidential clients).
pub async fn exchange(state:&AppState,client:&str,device_code:&str)->AppResult<Value>{
    if device_code.len()>512 || device_code.is_empty(){return Err(AppError::bad("invalid_grant"))}
    let digest=crypto::digest(device_code);
    let row=sqlx::query(&state.db.q(
        "SELECT client_id,scope,user_id,state,expires,last_poll,poll_interval \
         FROM device_grants WHERE device_hash=?"))
        .bind(&digest).fetch_optional(&state.db.pool).await?
        .ok_or_else(||AppError::bad("invalid_grant"))?;
    let actual:String=row.try_get("client_id")?;
    if actual!=client {return Err(AppError::bad("invalid_grant"))}
    let now=crypto::now();
    let expires:i64=row.try_get("expires")?;
    if expires<=now {return Err(AppError::bad("expired_token"))}
    let state_value:String=row.try_get("state")?;
    if state_value=="used" {return Err(AppError::bad("invalid_grant"))}
    if state_value=="denied" {return Err(AppError::bad("access_denied"))}
    let last_poll:i64=row.try_get("last_poll")?;
    let interval:i64=row.try_get("poll_interval")?;
    if last_poll!=0 && now<last_poll.saturating_add(interval) {
        // Repeated early polls increase the required wait (RFC 8628 §3.5).
        sqlx::query(&state.db.q(
            "UPDATE device_grants SET poll_interval=? WHERE device_hash=? AND last_poll=? AND poll_interval=?"))
            .bind((interval+5).min(30)).bind(&digest).bind(last_poll).bind(interval)
            .execute(&state.db.pool).await?;
        return Err(AppError::bad("slow_down"));
    }
    let updated=sqlx::query(&state.db.q(
        "UPDATE device_grants SET last_poll=? WHERE device_hash=? AND last_poll=? AND state=? AND expires>?"))
        .bind(now).bind(&digest).bind(last_poll).bind(&state_value).bind(now)
        .execute(&state.db.pool).await?;
    if updated.rows_affected()!=1 {return Err(AppError::bad("slow_down"))}
    if state_value=="pending" {return Err(AppError::bad("authorization_pending"))}
    if state_value!="approved" {return Err(AppError::bad("invalid_grant"))}
    let consumed=sqlx::query(&state.db.q(
        "UPDATE device_grants SET state='used' WHERE device_hash=? AND client_id=? \
         AND state='approved' AND last_poll=? AND expires>?"))
        .bind(&digest).bind(client).bind(now).bind(now)
        .execute(&state.db.pool).await?;
    if consumed.rows_affected()!=1 {return Err(AppError::bad("invalid_grant"))}
    let user:Option<String>=row.try_get("user_id")?;
    let user=user.ok_or_else(||AppError::bad("invalid_grant"))?;
    let scope:String=row.try_get("scope")?;
    auth::issue_tokens(state,client,&user,&scope).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr,sync::Arc};
    use axum::http::{header,HeaderMap};
    async fn fixture()->AppState {
        let db=Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        sqlx::query("INSERT INTO clients (id,name,secret_hash,redirects,created,enabled) VALUES ('cli','Example Device',NULL,'[]',0,1)")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO users (id,name,created) VALUES ('alice','Alice',0)")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,'alice',?)")
            .bind(crypto::digest("browser")).bind(crypto::now()+600)
            .execute(&db.pool).await.unwrap();
        AppState{config:Arc::new(crate::config::Config{
            public_url:"http://localhost:3000".into(),
            bind:"127.0.0.1:3000".parse::<SocketAddr>().unwrap(),auto_port:false,
            db_url:"sqlite::memory:".into(),admin_token_hash:crypto::digest("unused"),
            registration_token_hash:None,providers:vec![],
        }),db,http:reqwest::Client::new()}
    }
    fn browser()->HeaderMap {
        let mut h=HeaderMap::new();
        h.insert(header::COOKIE,"sso_session=browser".parse().unwrap());
        h.insert(header::ORIGIN,"http://localhost:3000".parse().unwrap());
        h
    }
    #[test] fn rejects_invalid_codes_and_scopes(){
        assert!(normalize_code("aBCD-2345").is_some());
        assert!(normalize_code("ABCDEFG!").is_none());
        assert!(normalize_code("AAAA-OOOO").is_none());
        assert!(scope_valid("profile offline_access"));
        assert!(!scope_valid("openid"));
        assert!(!scope_valid(""));
    }
    #[tokio::test] async fn pending_approval_replay_and_client_binding(){
        let s=fixture().await;
        let start=authorize(State(s.clone()),HeaderMap::new(),
            Form(StartForm{client_id:Some("cli".into()),client_secret:None,scope:Some("profile".into())}))
            .await.unwrap().0;
        let dev=start["device_code"].as_str().unwrap();
        let user=start["user_code"].as_str().unwrap();
        assert_eq!(exchange(&s,"other",dev).await.err().unwrap().message,"invalid_grant");
        assert_eq!(exchange(&s,"cli",dev).await.err().unwrap().message,"authorization_pending");
        let data=request(State(s.clone()),browser(),Query(CodeQuery{user_code:user.into()})).await.unwrap().0;
        assert_eq!(data["client_name"],"Example Device");
        decision(State(s.clone()),browser(),Json(DecisionInput{
            user_code:user.into(),decision:"allow".into()})).await.unwrap();
        // Simulate the device waiting for the announced interval.
        sqlx::query("UPDATE device_grants SET last_poll=0 WHERE device_hash=?")
            .bind(crypto::digest(dev)).execute(&s.db.pool).await.unwrap();
        let token=exchange(&s,"cli",dev).await.unwrap();
        assert!(token["access_token"].as_str().unwrap().len()>20);
        assert_eq!(exchange(&s,"cli",dev).await.err().unwrap().message,"invalid_grant");
    }
    #[tokio::test] async fn denial_and_cross_site_approval_are_blocked(){
        let s=fixture().await;
        let start=authorize(State(s.clone()),HeaderMap::new(),
            Form(StartForm{client_id:Some("cli".into()),client_secret:None,scope:None}))
            .await.unwrap().0;
        let dev=start["device_code"].as_str().unwrap();
        let code=start["user_code"].as_str().unwrap();
        assert!(decision(State(s.clone()),HeaderMap::new(),Json(DecisionInput{
            user_code:code.into(),decision:"allow".into()})).await.is_err());
        decision(State(s.clone()),browser(),Json(DecisionInput{
            user_code:code.into(),decision:"deny".into()})).await.unwrap();
        assert_eq!(exchange(&s,"cli",dev).await.err().unwrap().message,"access_denied");
    }
    #[tokio::test] async fn early_poll_is_throttled(){
        let s=fixture().await;
        let start=authorize(State(s.clone()),HeaderMap::new(),
            Form(StartForm{client_id:Some("cli".into()),client_secret:None,scope:None}))
            .await.unwrap().0;
        let dev=start["device_code"].as_str().unwrap();
        assert_eq!(exchange(&s,"cli",dev).await.err().unwrap().message,"authorization_pending");
        assert_eq!(exchange(&s,"cli",dev).await.err().unwrap().message,"slow_down");
    }
}
