//! First-party browser session management and scoped security-audit access.
//! Session identifiers are hashes and cannot be used as login bearer tokens.
use crate::{auth, crypto, mfa, AppError, AppResult, AppState};
use axum::{extract::{Path,Query,State},http::{header,HeaderMap},response::{IntoResponse,Response},Json};
use serde::Deserialize;
use serde_json::{json,Value};
use sqlx::Row;

pub async fn record(state:&AppState,hash:&str,headers:&HeaderMap,method:&str)->AppResult<()>{
    let agent=headers.get(header::USER_AGENT).and_then(|v|v.to_str().ok()).unwrap_or("Unknown")
        .chars().take(160).collect::<String>();
    sqlx::query(&state.db.q("INSERT INTO session_devices (token_hash,user_agent,method,created) VALUES (?,?,?,?)"))
        .bind(hash).bind(agent).bind(method.chars().take(64).collect::<String>())
        .bind(crypto::now()).execute(&state.db.pool).await?;
    Ok(())
}
/// Create an OAuth browser session with the same per-user lock used by
/// administrator disable/enable. Device metadata is committed with the session.
pub async fn create_browser_session(state: &AppState, user: &str, headers: &HeaderMap, method: &str) -> AppResult<String> {
    let session = crypto::random_token();
    let digest = crypto::digest(&session);
    let agent = headers.get(header::USER_AGENT).and_then(|v|v.to_str().ok()).unwrap_or("Unknown")
        .chars().take(160).collect::<String>();
    let mut tx = state.db.pool.begin().await?;
    crate::directory::lock_enabled(state, &mut tx, user).await?;
    sqlx::query(&state.db.q("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)"))
        .bind(&digest).bind(user).bind(crypto::now() + 7*86400)
        .execute(&mut *tx).await?;
    sqlx::query(&state.db.q("INSERT INTO session_devices (token_hash,user_agent,method,created) VALUES (?,?,?,?)"))
        .bind(&digest).bind(agent).bind(method.chars().take(64).collect::<String>())
        .bind(crypto::now()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(session)
}

pub async fn event(state:&AppState,actor:&str,name:&str,metadata:Value)->AppResult<()>{
    // Never pass bearer tokens, credentials, account secrets or device codes.
    sqlx::query(&state.db.q("INSERT INTO audit (id,event,actor,metadata,created) VALUES (?,?,?,?,?)"))
        .bind(uuid::Uuid::new_v4().to_string()).bind(name).bind(actor)
        .bind(metadata.to_string()).bind(crypto::now()).execute(&state.db.pool).await?;
    Ok(())
}
/// Add an audit event to the caller's transaction. Use this for security
/// settings and client mutations so a failed audit write aborts the mutation.
pub async fn event_tx(
    state:&AppState, tx:&mut sqlx::Transaction<'_,sqlx::Any>, actor:&str, name:&str, metadata:Value
)->AppResult<()> {
    sqlx::query(&state.db.q("INSERT INTO audit (id,event,actor,metadata,created) VALUES (?,?,?,?,?)"))
        .bind(uuid::Uuid::new_v4().to_string()).bind(name).bind(actor)
        .bind(metadata.to_string()).bind(crypto::now()).execute(&mut **tx).await?;
    Ok(())
}

pub async fn list(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>>{
    let user=auth::session_user(&state,&headers).await?;
    let current=mfa::cookie_digest(&headers)?;
    let rows=sqlx::query(&state.db.q(
        "SELECT s.token_hash,s.expires,d.user_agent,d.method,d.created,a.factor \
         FROM sessions s LEFT JOIN session_devices d ON d.token_hash=s.token_hash \
         LEFT JOIN session_assurance a ON a.token_hash=s.token_hash \
         WHERE s.user_id=? AND s.expires>? ORDER BY s.expires DESC LIMIT 100"))
        .bind(&user).bind(crypto::now()).fetch_all(&state.db.pool).await?;
    let mut out=Vec::with_capacity(rows.len());
    for row in rows {
        let id:String=row.try_get("token_hash")?;
        out.push(json!({"id":id,"current":id==current,
            "expires":row.try_get::<i64,_>("expires")?,
            "created":row.try_get::<Option<i64>,_>("created")?,
            "method":row.try_get::<Option<String>,_>("method")?,
            "user_agent":row.try_get::<Option<String>,_>("user_agent")?,
            "assurance":row.try_get::<Option<String>,_>("factor")?}));
    }
    Ok(Json(json!(out)))
}
fn valid_digest(s:&str)->bool{
    s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit())
}
pub async fn revoke(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<String>)
    ->AppResult<Response>
{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    mfa::require_recent_login(&state,&headers).await?;
    if !valid_digest(&id){return Err(AppError::bad("invalid_session_id"))}
    let current=mfa::cookie_digest(&headers)?;
    let mut tx=state.db.pool.begin().await?;
    let changed=sqlx::query(&state.db.q("DELETE FROM sessions WHERE token_hash=? AND user_id=?"))
        .bind(&id).bind(&user).execute(&mut *tx).await?;
    if changed.rows_affected()!=1{return Err(AppError::bad("unknown_session"))}
    // Metadata and verification artifacts cannot survive revoked sessions.
    sqlx::query(&state.db.q("DELETE FROM session_assurance WHERE token_hash=?"))
        .bind(&id).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM mfa_redirects WHERE token_hash=?"))
        .bind(&id).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM session_devices WHERE token_hash=?"))
        .bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    event(&state,&user,"session.revoke",json!({"current":id==current})).await?;
    let mut response=Json(json!({"ok":true,"current":id==current})).into_response();
    if id==current{
        response.headers_mut().insert(header::SET_COOKIE,
            "sso_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax".parse()
                .map_err(|_|AppError::bad("invalid_cookie"))?);
    }
    Ok(response)
}
pub async fn revoke_others(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>>{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    mfa::require_recent_login(&state,&headers).await?;
    let current=mfa::cookie_digest(&headers)?;
    let mut tx=state.db.pool.begin().await?;
    // Metadata cleanup precedes session deletion; consistent across SQLite,
    // PostgreSQL and MySQL without engine-specific cascading foreign keys.
    for table in ["session_assurance","mfa_redirects","session_devices"]{
        let q=state.db.q(&format!(
            "DELETE FROM {table} WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=? AND token_hash<>?)"));
        sqlx::query(&q).bind(&user).bind(&current).execute(&mut *tx).await?;
    }
    let count=sqlx::query(&state.db.q("DELETE FROM sessions WHERE user_id=? AND token_hash<>?"))
        .bind(&user).bind(&current).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    event(&state,&user,"session.revoke_others",json!({"count":count})).await?;
    Ok(Json(json!({"revoked":count})))
}
#[derive(Deserialize)]
pub struct AuditQuery{limit:Option<i64>}
pub async fn audit(State(state):State<AppState>,headers:HeaderMap,Query(q):Query<AuditQuery>)
    ->AppResult<Json<Value>>
{
    crate::management::admin(&state,&headers)?;
    let rows=sqlx::query(&state.db.q(
        "SELECT id,event,actor,metadata,created FROM audit ORDER BY created DESC LIMIT ?"))
        .bind(q.limit.unwrap_or(50).clamp(1,200))
        .fetch_all(&state.db.pool).await?;
    let mut events=Vec::with_capacity(rows.len());
    for row in rows{
        let metadata:String=row.try_get("metadata")?;
        events.push(json!({"id":row.try_get::<String,_>("id")?,
            "event":row.try_get::<String,_>("event")?,
            "actor":row.try_get::<String,_>("actor")?,
            "metadata":serde_json::from_str::<Value>(&metadata).unwrap_or(Value::Null),
            "created":row.try_get::<i64,_>("created")?}));
    }
    Ok(Json(json!(events)))
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::{net::SocketAddr,sync::Arc};
    async fn fixture()->AppState{
        let db=Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        sqlx::query("INSERT INTO users (id,name,created) VALUES ('alice','Alice',0)")
            .execute(&db.pool).await.unwrap();
        for token in ["current","other"]{
            sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,'alice',?)")
                .bind(crypto::digest(token)).bind(crypto::now()+1000)
                .execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES (?,'passkey',?)")
                .bind(crypto::digest(token)).bind(crypto::now())
                .execute(&db.pool).await.unwrap();
        }
        AppState{config:Arc::new(crate::config::Config{
            public_url:"http://localhost:3000".into(),
            bind:"127.0.0.1:3000".parse::<SocketAddr>().unwrap(),auto_port:false,
            db_url:"sqlite::memory:".into(),admin_token_hash:crypto::digest("a very long test secret"),
            registration_token_hash:None,providers:vec![],
        }),db,http:reqwest::Client::new()}
    }
    fn browser()->HeaderMap{
        let mut headers=HeaderMap::new();
        headers.insert(header::COOKIE,"sso_session=current".parse().unwrap());
        headers.insert(header::ORIGIN,"http://localhost:3000".parse().unwrap());
        headers
    }
    #[tokio::test] async fn revoke_others_keeps_current_and_cleans_assurance(){
        let state=fixture().await;
        let r=revoke_others(State(state.clone()),browser()).await.unwrap().0;
        assert_eq!(r["revoked"],1);
        let got=list(State(state.clone()),browser()).await.unwrap().0;
        assert_eq!(got.as_array().unwrap().len(),1);
        assert_eq!(got[0]["current"],true);
        let count:(i64,)=sqlx::query_as("SELECT COUNT(*) FROM session_assurance")
            .fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(count.0,1);
    }
    #[tokio::test] async fn revoke_requires_same_origin_and_is_one_time(){
        let state=fixture().await;
        let id=crypto::digest("other");
        assert!(revoke(State(state.clone()),HeaderMap::new(),Path(id.clone())).await.is_err());
        assert!(revoke(State(state.clone()),browser(),Path("wrong".into())).await.is_err());
        assert!(revoke(State(state.clone()),browser(),Path(id.clone())).await.is_ok());
        assert!(revoke(State(state.clone()),browser(),Path(id)).await.is_err());
    }
}
