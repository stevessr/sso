//! Opaque, SHA-256-at-rest rotating OAuth2 refresh tokens.
//! A refresh token is single-use. Replaying a consumed token invalidates its
//! entire grant family, including every access token minted in that family.
use crate::{crypto, AppError, AppResult, AppState};
use serde_json::{json, Value};
use sqlx::{Any, Row, Transaction};

const REFRESH_TTL: i64 = 30 * 24 * 3600;
const ACCESS_TTL: i64 = 3600;

fn offline_access(scope: &str) -> bool {
    scope.split_whitespace().any(|s| s == "offline_access")
}

/// Called only after the authorization code was validated and consumed.
/// Insert a refresh family inside the caller's issuance transaction, so
/// disabling an account can never slip between access/refresh writes.
pub async fn issue_initial_in_tx(
    state: &AppState, tx: &mut Transaction<'_, Any>,
    client: &str, user: &str, scope: &str, access_token: &str,
) -> AppResult<Option<String>> {
    if !offline_access(scope) { return Ok(None); }
    let token = crypto::random_token();
    let family = uuid::Uuid::new_v4().to_string();
    sqlx::query(&state.db.q(
        "INSERT INTO refresh_tokens (token_hash,family_id,client_id,user_id,scope,expires,used,revoked) VALUES (?,?,?,?,?,?,0,0)"
    )).bind(crypto::digest(&token)).bind(&family).bind(client).bind(user)
        .bind(scope).bind(crypto::now() + REFRESH_TTL).execute(&mut **tx).await?;
    sqlx::query(&state.db.q("INSERT INTO refresh_access (token_hash,family_id) VALUES (?,?)"))
        .bind(crypto::digest(access_token)).bind(&family).execute(&mut **tx).await?;
    Ok(Some(token))
}

/// Standalone helper retained for tests and existing callers.
#[cfg(test)]
pub async fn issue_initial(
    state: &AppState, client: &str, user: &str, scope: &str, access_token: &str,
) -> AppResult<Option<String>> {
    let mut tx = state.db.pool.begin().await?;
    let issued = issue_initial_in_tx(state, &mut tx, client, user, scope, access_token).await?;
    tx.commit().await?;
    Ok(issued)
}

async fn revoke_family(
    state: &AppState, tx: &mut Transaction<'_, Any>, family: &str,
) -> AppResult<()> {
    sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE family_id=?"))
        .bind(family).execute(&mut **tx).await?;
    sqlx::query(&state.db.q(
        "UPDATE tokens SET revoked=1 WHERE token_hash IN (SELECT token_hash FROM refresh_access WHERE family_id=?)"
    )).bind(family).execute(&mut **tx).await?;
    Ok(())
}

/// Rotates only the token belonging to this authenticated OAuth client. The
/// absolute expiry is inherited, so perpetual refresh does not extend a grant.
pub async fn rotate(state: &AppState, client: &str, token: &str) -> AppResult<Value> {
    if token.len() < 32 || token.len() > 512 { return Err(AppError::bad("invalid_grant")); }
    let digest = crypto::digest(token);
    // Resolve immutable owner before opening the transaction, then lock its
    // user row BEFORE any transactional reads (MySQL REPEATABLE READ safety).
    let owner = sqlx::query(&state.db.q(
        "SELECT user_id FROM refresh_tokens WHERE token_hash=? AND client_id=?"
    )).bind(&digest).bind(client).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::bad("invalid_grant"))?
        .try_get::<String, _>("user_id")?;
    let mut tx = state.db.pool.begin().await?;
    crate::directory::lock_enabled(state, &mut tx, &owner).await
        .map_err(|_| AppError::bad("invalid_grant"))?;
    let row = sqlx::query(&state.db.q(
        "SELECT family_id,user_id,scope,expires,used,revoked FROM refresh_tokens WHERE token_hash=? AND client_id=?"
    )).bind(&digest).bind(client).fetch_optional(&mut *tx).await?
        .ok_or_else(|| AppError::bad("invalid_grant"))?;
    let family: String = row.try_get("family_id")?;
    let used: i64 = row.try_get("used")?;
    let revoked: i64 = row.try_get("revoked")?;
    let expires: i64 = row.try_get("expires")?;
    if used != 0 {
        // A stolen old token is indistinguishable from a legitimate retried
        // response: invalidate both parties rather than selecting a winner.
        revoke_family(state, &mut tx, &family).await?;
        tx.commit().await?;
        return Err(AppError::bad("invalid_grant"));
    }
    if revoked != 0 || expires <= crypto::now() {
        return Err(AppError::bad("invalid_grant"));
    }
    if row.try_get::<String, _>("user_id")? != owner {
        return Err(AppError::bad("invalid_grant"));
    }
    let changed = sqlx::query(&state.db.q(
        "UPDATE refresh_tokens SET used=1 WHERE token_hash=? AND client_id=? AND used=0 AND revoked=0 AND expires>?"
    )).bind(&digest).bind(client).bind(crypto::now()).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        revoke_family(state, &mut tx, &family).await?;
        tx.commit().await?;
        return Err(AppError::bad("invalid_grant"));
    }
    let user: String = row.try_get("user_id")?;
    let scope: String = row.try_get("scope")?;
    let fresh_refresh = crypto::random_token();
    let fresh_access = crypto::random_token();
    sqlx::query(&state.db.q(
        "INSERT INTO refresh_tokens (token_hash,family_id,client_id,user_id,scope,expires,used,revoked) VALUES (?,?,?,?,?,?,0,0)"
    )).bind(crypto::digest(&fresh_refresh)).bind(&family).bind(client).bind(&user)
        .bind(&scope).bind(expires).execute(&mut *tx).await?;
    sqlx::query(&state.db.q(
        "INSERT INTO tokens (token_hash,client_id,user_id,scope,expires,revoked,suspended_until) VALUES (?,?,?,?,?,0,0)"
    )).bind(crypto::digest(&fresh_access)).bind(client).bind(&user)
        .bind(&scope).bind(crypto::now() + ACCESS_TTL).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("INSERT INTO refresh_access (token_hash,family_id) VALUES (?,?)"))
        .bind(crypto::digest(&fresh_access)).bind(&family).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(json!({
        "access_token":fresh_access, "token_type":"Bearer",
        "expires_in":ACCESS_TTL, "refresh_token":fresh_refresh,
        "refresh_expires_in":(expires - crypto::now()).max(0), "scope":scope
    }))
}

/// RFC 7009: revoking any refresh token invalidates its grant family. Unknown
/// tokens are not disclosed to the caller.
pub async fn revoke_grant(state: &AppState, client: &str, token: &str) -> AppResult<bool> {
    let mut tx = state.db.pool.begin().await?;
    let family = sqlx::query(&state.db.q(
        "SELECT family_id FROM refresh_tokens WHERE token_hash=? AND client_id=?"
    )).bind(crypto::digest(token)).bind(client).fetch_optional(&mut *tx).await?;
    if let Some(row) = family {
        let id: String = row.try_get("family_id")?;
        revoke_family(state, &mut tx, &id).await?;
        tx.commit().await?;
        Ok(true)
    } else { Ok(false) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::Arc};

    async fn fixture() -> AppState {
        let db = Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        let config = crate::config::Config {
            public_url: "http://localhost:3000".into(),
            bind: "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
            auto_port: false, db_url: "sqlite::memory:".into(),
            admin_token_hash: crypto::digest("unused"),
            registration_token_hash: None, providers: vec![],
        };
        let state = AppState { config: Arc::new(config), db, http: reqwest::Client::new() };
        sqlx::query("INSERT INTO users (id,name,created) VALUES ('user','Test User',0)")
            .execute(&state.db.pool).await.unwrap();
        sqlx::query("INSERT INTO clients (id,name,secret_hash,redirects,created,enabled) VALUES ('app','Example',NULL,'[]',0,1)")
            .execute(&state.db.pool).await.unwrap();
        sqlx::query("INSERT INTO tokens (token_hash,client_id,user_id,scope,expires,revoked,suspended_until) VALUES (?,'app','user','profile offline_access',?,0,0)")
            .bind(crypto::digest("initial-access")).bind(crypto::now()+3600)
            .execute(&state.db.pool).await.unwrap();
        state
    }

    #[tokio::test]
    async fn refresh_rotation_replay_rejects_every_token_in_family() {
        let state = fixture().await;
        let first = issue_initial(&state, "app", "user", "profile offline_access", "initial-access")
            .await.unwrap().unwrap();
        let second = rotate(&state, "app", &first).await.unwrap();
        assert_eq!(second["token_type"], "Bearer");
        assert!(rotate(&state, "other", &second["refresh_token"].as_str().unwrap()).await.is_err());
        assert!(rotate(&state, "app", &first).await.is_err()); // replay
        assert!(rotate(&state, "app", second["refresh_token"].as_str().unwrap()).await.is_err());
        let row = sqlx::query("SELECT revoked FROM tokens WHERE token_hash=?")
            .bind(crypto::digest(second["access_token"].as_str().unwrap()))
            .fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64,_>("revoked").unwrap(), 1);
        let original = sqlx::query("SELECT revoked FROM tokens WHERE token_hash=?")
            .bind(crypto::digest("initial-access")).fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(original.try_get::<i64,_>("revoked").unwrap(), 1);
    }

    #[tokio::test]
    async fn grant_revocation_is_scoped_to_the_client_and_cascades() {
        let state = fixture().await;
        let refresh = issue_initial(&state, "app", "user", "profile offline_access", "initial-access")
            .await.unwrap().unwrap();
        assert!(!revoke_grant(&state, "unrelated", &refresh).await.unwrap());
        assert!(revoke_grant(&state, "app", &refresh).await.unwrap());
        assert!(rotate(&state, "app", &refresh).await.is_err());
        let row = sqlx::query("SELECT revoked FROM tokens WHERE token_hash=?")
            .bind(crypto::digest("initial-access")).fetch_one(&state.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64,_>("revoked").unwrap(), 1);
    }

    #[tokio::test]
    async fn no_refresh_without_explicit_offline_access() {
        let state = fixture().await;
        assert!(issue_initial(&state, "app", "user", "profile", "initial-access")
            .await.unwrap().is_none());
    }
}
