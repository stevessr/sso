//! Keycloak-inspired user directory and account lifecycle operations.
//! This is a single-realm administrative API; no delegated admin roles yet.
use crate::{auth, crypto, management, sessions, AppError, AppResult, AppState};
use axum::{extract::{Path, Query, State}, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Any, Row, Transaction};

#[derive(Deserialize)]
pub struct Search {
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// A missing access row is an existing account's default (enabled) state.
/// Kept in a separate table for portable SQLite/PostgreSQL/MySQL migration.
pub async fn require_enabled(state: &AppState, user: &str) -> AppResult<()> {
    let row = sqlx::query(&state.db.q("SELECT disabled FROM user_access WHERE user_id=?"))
        .bind(user).fetch_optional(&state.db.pool).await?;
    if row.map(|r| r.try_get::<i64, _>("disabled").unwrap_or(1) != 0).unwrap_or(false) {
        return Err(AppError::forbidden());
    }
    Ok(())
}

pub async fn users(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<Search>)
    -> AppResult<Json<Value>>
{
    management::admin(&state, &headers)?;
    let term = query.q.unwrap_or_default();
    if term.len() > 100 { return Err(AppError::bad("search query too long")); }
    let pattern = format!("%{}%", term.trim().to_lowercase());
    let limit = query.limit.unwrap_or(30).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).clamp(0, 100_000);
    let rows = sqlx::query(&state.db.q(
        "SELECT u.id,u.name,u.email,u.created,COALESCE(a.disabled,0) AS disabled, \
         (SELECT COUNT(*) FROM identities i WHERE i.user_id=u.id) AS identity_count, \
         (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.expires>?) AS session_count \
         FROM users u LEFT JOIN user_access a ON a.user_id=u.id \
         WHERE LOWER(u.id) LIKE ? OR LOWER(u.name) LIKE ? OR LOWER(COALESCE(u.email,'')) LIKE ? \
         ORDER BY u.created DESC,u.id LIMIT ? OFFSET ?"))
        .bind(crypto::now()).bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(limit).bind(offset).fetch_all(&state.db.pool).await?;
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        output.push(json!({
            "id": row.try_get::<String, _>("id")?,
            "name": row.try_get::<String, _>("name")?,
            "email": row.try_get::<Option<String>, _>("email")?,
            "created": row.try_get::<i64, _>("created")?,
            "enabled": row.try_get::<i64, _>("disabled")? == 0,
            "identities": row.try_get::<i64, _>("identity_count")?,
            "sessions": row.try_get::<i64, _>("session_count")?
        }));
    }
    Ok(Json(json!({"users": output, "limit": limit, "offset": offset, "has_more": output.len() == limit as usize})))
}

pub async fn user(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>)
    -> AppResult<Json<Value>>
{
    management::admin(&state, &headers)?;
    let row = sqlx::query(&state.db.q(
        "SELECT u.id,u.name,u.email,u.avatar,u.created,COALESCE(a.disabled,0) AS disabled \
         FROM users u LEFT JOIN user_access a ON a.user_id=u.id WHERE u.id=?"))
        .bind(&id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::bad("unknown user"))?;
    let identities = sqlx::query(&state.db.q("SELECT provider,subject FROM identities WHERE user_id=? ORDER BY provider"))
        .bind(&id).fetch_all(&state.db.pool).await?;
    let linked = identities.into_iter().map(|identity| {
        Ok::<Value, sqlx::Error>(json!({
            "provider": identity.try_get::<String, _>("provider")?,
            "subject": identity.try_get::<String, _>("subject")?
        }))
    }).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({
        "id": row.try_get::<String, _>("id")?,
        "name": row.try_get::<String, _>("name")?,
        "email": row.try_get::<Option<String>, _>("email")?,
        "avatar": row.try_get::<Option<String>, _>("avatar")?,
        "created": row.try_get::<i64, _>("created")?,
        "enabled": row.try_get::<i64, _>("disabled")? == 0,
        "identities": linked
    })))
}

pub async fn user_sessions(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>)
    -> AppResult<Json<Value>>
{
    management::admin(&state, &headers)?;
    let rows = sqlx::query(&state.db.q(
        "SELECT s.token_hash,s.expires,d.user_agent,d.method,d.created \
         FROM sessions s LEFT JOIN session_devices d ON d.token_hash=s.token_hash \
         WHERE s.user_id=? AND s.expires>? ORDER BY s.expires DESC LIMIT 100"))
        .bind(&id).bind(crypto::now()).fetch_all(&state.db.pool).await?;
    let mut sessions = Vec::with_capacity(rows.len());
    for row in rows {
        sessions.push(json!({
            "id": row.try_get::<String, _>("token_hash")?,
            "expires": row.try_get::<i64, _>("expires")?,
            "created": row.try_get::<Option<i64>, _>("created")?,
            "user_agent": row.try_get::<Option<String>, _>("user_agent")?,
            "method": row.try_get::<Option<String>, _>("method")?
        }));
    }
    Ok(Json(json!(sessions)))
}

async fn remove_sessions(state: &AppState, tx: &mut Transaction<'_, Any>, id: &str) -> AppResult<u64> {
    for table in ["session_assurance", "mfa_redirects", "session_devices"] {
        let query = state.db.q(&format!(
            "DELETE FROM {table} WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=?)"));
        sqlx::query(&query).bind(id).execute(&mut **tx).await?;
    }
    let removed = sqlx::query(&state.db.q("DELETE FROM sessions WHERE user_id=?"))
        .bind(id).execute(&mut **tx).await?.rows_affected();
    Ok(removed)
}

pub async fn revoke_sessions(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>)
    -> AppResult<Json<Value>>
{
    management::admin(&state, &headers)?;
    auth::require_same_origin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    if sqlx::query(&state.db.q("SELECT id FROM users WHERE id=?"))
        .bind(&id).fetch_optional(&mut *tx).await?.is_none() {
        return Err(AppError::bad("unknown user"));
    }
    let removed = remove_sessions(&state, &mut tx, &id).await?;
    sessions::event_tx(&state, &mut tx, "admin", "user.sessions.revoke",
        json!({"user_id": id, "sessions": removed})).await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true, "revoked_sessions": removed})))
}

async fn change_status(state: AppState, headers: HeaderMap, id: String, disabled: bool)
    -> AppResult<Json<Value>>
{
    management::admin(&state, &headers)?;
    auth::require_same_origin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    if sqlx::query(&state.db.q("SELECT id FROM users WHERE id=?"))
        .bind(&id).fetch_optional(&mut *tx).await?.is_none() {
        return Err(AppError::bad("unknown user"));
    }
    let existing = sqlx::query(&state.db.q("SELECT disabled FROM user_access WHERE user_id=?"))
        .bind(&id).fetch_optional(&mut *tx).await?;
    if existing.is_some() {
        sqlx::query(&state.db.q("UPDATE user_access SET disabled=?,updated=? WHERE user_id=?"))
            .bind(i64::from(disabled)).bind(crypto::now()).bind(&id)
            .execute(&mut *tx).await?;
    } else {
        sqlx::query(&state.db.q("INSERT INTO user_access (user_id,disabled,updated) VALUES (?,?,?)"))
            .bind(&id).bind(i64::from(disabled)).bind(crypto::now())
            .execute(&mut *tx).await?;
    }
    let mut revoked_access = 0;
    let mut revoked_refresh = 0;
    let mut revoked_sessions = 0;
    if disabled {
        // Re-enabling must not resurrect any previous authorization grant.
        revoked_access = sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE user_id=? AND revoked=0"))
            .bind(&id).execute(&mut *tx).await?.rows_affected();
        revoked_refresh = sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE user_id=? AND revoked=0"))
            .bind(&id).execute(&mut *tx).await?.rows_affected();
        revoked_sessions = remove_sessions(&state, &mut tx, &id).await?;
        sqlx::query(&state.db.q("UPDATE codes SET used=1 WHERE user_id=? AND used=0"))
            .bind(&id).execute(&mut *tx).await?;
        sqlx::query(&state.db.q("UPDATE pending_consents SET used=1 WHERE user_id=? AND used=0"))
            .bind(&id).execute(&mut *tx).await?;
        sqlx::query(&state.db.q("UPDATE device_grants SET state='denied' WHERE user_id=? AND state='approved'"))
            .bind(&id).execute(&mut *tx).await?;
        sqlx::query(&state.db.q("UPDATE passkey_challenges SET used=1 WHERE user_id=? AND used=0"))
            .bind(&id).execute(&mut *tx).await?;
    }
    sessions::event_tx(&state, &mut tx, "admin",
        if disabled { "user.disable" } else { "user.enable" },
        json!({"user_id": id, "revoked_access": revoked_access,
            "revoked_refresh": revoked_refresh, "revoked_sessions": revoked_sessions})).await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true, "enabled": !disabled, "revoked_access": revoked_access,
        "revoked_refresh": revoked_refresh, "revoked_sessions": revoked_sessions})))
}

pub async fn disable(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>)
    -> AppResult<Json<Value>> { change_status(state, headers, id, true).await }

pub async fn enable(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>)
    -> AppResult<Json<Value>> { change_status(state, headers, id, false).await }

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use std::sync::Arc;

    async fn setup() -> (AppState, HeaderMap) {
        let db = Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        let config = crate::config::Config {
            public_url: "http://localhost:3000".into(),
            bind: "127.0.0.1:3000".parse().unwrap(), auto_port: false,
            db_url: "sqlite::memory:".into(),
            admin_token_hash: crypto::digest("test-admin"),
            registration_token_hash: None, providers: vec![],
        };
        let state = AppState { config: Arc::new(config), db, http: reqwest::Client::new() };
        sqlx::query("INSERT INTO users (id,name,email,avatar,created) VALUES ('u1','Alice','alice@example.test',NULL,1)")
            .execute(&state.db.pool).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-admin".parse().unwrap());
        (state, headers)
    }

    #[tokio::test]
    async fn admin_directory_is_private_and_searchable() {
        let (state, headers) = setup().await;
        assert!(users(State(state.clone()), HeaderMap::new(),
            Query(Search { q: None, limit: None, offset: None })).await.is_err());
        let result = users(State(state.clone()), headers.clone(),
            Query(Search { q: Some("alice".into()), limit: None, offset: None })).await.unwrap().0;
        assert_eq!(result["users"][0]["id"], "u1");
        let detail = user(State(state), headers, Path("u1".into())).await.unwrap().0;
        assert_eq!(detail["enabled"], true);
    }

    #[tokio::test]
    async fn disabling_revokes_every_grant_and_reenable_does_not_restore_them() {
        let (state, headers) = setup().await;
        let now = crypto::now();
        sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)")
            .bind(crypto::digest("session1")).bind("u1").bind(now+300)
            .execute(&state.db.pool).await.unwrap();
        sqlx::query("INSERT INTO tokens (token_hash,client_id,user_id,scope,expires,revoked,suspended_until) VALUES (?,?,?,?,?,0,0)")
            .bind(crypto::digest("token1")).bind("client1").bind("u1").bind("profile").bind(now+300)
            .execute(&state.db.pool).await.unwrap();
        sqlx::query("INSERT INTO refresh_tokens (token_hash,family_id,client_id,user_id,scope,expires,used,revoked) VALUES (?,?,?,?,?,?,0,0)")
            .bind(crypto::digest("refresh1")).bind("family1").bind("client1").bind("u1").bind("offline_access").bind(now+300)
            .execute(&state.db.pool).await.unwrap();
        let r = disable(State(state.clone()), headers.clone(), Path("u1".into())).await.unwrap().0;
        assert_eq!(r["revoked_access"], 1);
        assert_eq!(r["revoked_refresh"], 1);
        assert_eq!(r["revoked_sessions"], 1);
        assert!(require_enabled(&state, "u1").await.is_err());
        let row = sqlx::query("SELECT revoked FROM tokens WHERE user_id='u1'")
            .fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64, _>("revoked").unwrap(), 1);
        assert!(auth::session_user_raw(&state, &{
            let mut h=HeaderMap::new();
            h.insert(header::COOKIE, "sso_session=session1".parse().unwrap());
            h
        }).await.is_err());
        enable(State(state.clone()), headers, Path("u1".into())).await.unwrap();
        require_enabled(&state, "u1").await.unwrap();
        let row = sqlx::query("SELECT revoked FROM refresh_tokens WHERE user_id='u1'")
            .fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64, _>("revoked").unwrap(), 1);
    }

    #[tokio::test]
    async fn revoking_browser_sessions_keeps_oauth_tokens() {
        let (state, headers) = setup().await;
        sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)")
            .bind(crypto::digest("session")).bind("u1").bind(crypto::now()+300)
            .execute(&state.db.pool).await.unwrap();
        let r = revoke_sessions(State(state.clone()), headers, Path("u1".into())).await.unwrap().0;
        assert_eq!(r["revoked_sessions"], 1);
        let row = sqlx::query("SELECT COUNT(*) AS count FROM sessions")
            .fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64,_>("count").unwrap(), 0);
    }
}
