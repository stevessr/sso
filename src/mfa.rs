//! TOTP second factor, one-time recovery codes, and session assurance.
//! Secrets are AES-256-GCM sealed with an independent deployment key. A
//! same-origin authenticated session is required to enroll or disable factors.
use crate::{auth, crypto, AppError, AppResult, AppState};
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use axum::{extract::State, http::{HeaderMap, header}, response::Html, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use totp_rs::{Builder, Secret};
use std::convert::TryInto;

fn key() -> AppResult<[u8; 32]> {
    let supplied = std::env::var("SSO_MFA_ENCRYPTION_KEY")
        .map_err(|_| AppError::bad("SSO_MFA_ENCRYPTION_KEY is required for TOTP"))?;
    let raw = hex::decode(supplied).map_err(|_| AppError::bad("MFA encryption key must be 64 hex characters"))?;
    raw.try_into().map_err(|_| AppError::bad("MFA encryption key must be 32 bytes"))
}
fn seal_with(key: &[u8; 32], user: &str, secret: &[u8]) -> AppResult<String> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AppError::bad("invalid MFA cipher"))?;
    let mut output = nonce.to_vec();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce),
        Payload {msg:secret, aad:user.as_bytes()})
        .map_err(|_| AppError::bad("MFA secret encryption failed"))?;
    output.extend(ciphertext);
    Ok(format!("v1:{}",URL_SAFE_NO_PAD.encode(output)))
}
fn open_with(key: &[u8; 32], user: &str, sealed: &str) -> AppResult<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD.decode(sealed.strip_prefix("v1:")
        .ok_or_else(|| AppError::bad("unknown MFA secret format"))?)
        .map_err(|_| AppError::bad("corrupt MFA secret"))?;
    if raw.len() < 12+16 { return Err(AppError::bad("invalid MFA envelope")); }
    Aes256Gcm::new_from_slice(key).map_err(|_| AppError::bad("invalid MFA cipher"))?
        .decrypt(Nonce::from_slice(&raw[..12]),
            Payload {msg:&raw[12..],aad:user.as_bytes()})
        .map_err(|_| AppError::bad("unable to open MFA secret; check master key"))
}
fn totp(secret: &[u8]) -> AppResult<totp_rs::Totp> {
    Builder::new().with_secret(Secret::from(secret))
        .build().map_err(|_| AppError::bad("invalid TOTP secret"))
}
pub fn cookie_digest(headers: &HeaderMap) -> AppResult<String> {
    let raw = headers.get(header::COOKIE).and_then(|h| h.to_str().ok())
        .unwrap_or("").split(';').find_map(|part|part.trim().strip_prefix("sso_session="))
        .ok_or_else(AppError::unauthorized)?;
    if raw.is_empty() || raw.len() > 512 { return Err(AppError::unauthorized()); }
    Ok(crypto::digest(raw))
}
pub async fn enabled(state: &AppState, user: &str) -> AppResult<bool> {
    let row = sqlx::query(&state.db.q("SELECT enabled FROM totp_accounts WHERE user_id=?"))
        .bind(user).fetch_optional(&state.db.pool).await?;
    Ok(row.map(|r|r.try_get::<i64,_>("enabled").unwrap_or(0)==1).unwrap_or(false))
}
pub async fn enforce_session(state: &AppState, user: &str, digest: &str) -> AppResult<()> {
    if !enabled(state,user).await? { return Ok(()); }
    let row = sqlx::query(&state.db.q("SELECT factor FROM session_assurance WHERE token_hash=?"))
        .bind(digest).fetch_optional(&state.db.pool).await?;
    if row.is_none() { return Err(AppError::forbidden()); }
    Ok(())
}
fn valid_next(next:&str)->bool {
    next=="/" || next.strip_prefix("/consent?request=")
        .map(|id|!id.is_empty() && id.len()<=128 && id.bytes()
            .all(|b|b.is_ascii_alphanumeric() || b==b'_' || b==b'-'))
        .unwrap_or(false)
}
pub async fn new_session_target(
    state: &AppState, user: &str, digest: &str, next: &str, passkey_verified: bool,
) -> AppResult<String> {
    // Path is server-generated, never read from a browser redirect parameter.
    if !valid_next(next) { return Err(AppError::bad("invalid post-MFA redirect")); }
    if passkey_verified {
        sqlx::query(&state.db.q("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES (?,'passkey',?)"))
            .bind(digest).bind(crypto::now()).execute(&state.db.pool).await?;
        return Ok(next.into());
    }
    if enabled(state,user).await? {
        sqlx::query(&state.db.q("INSERT INTO mfa_redirects (token_hash,next_path,expires) VALUES (?,?,?)"))
            .bind(digest).bind(next).bind(crypto::now()+300).execute(&state.db.pool).await?;
        return Ok("/mfa".into());
    }
    Ok(next.into())
}
pub async fn page()->Html<&'static str>{
    Html(include_str!("../web/mfa.html"))
}
pub async fn status(State(state): State<AppState>,headers:HeaderMap)->AppResult<Json<Value>> {
    let user=auth::session_user_raw(&state,&headers).await?;
    let digest=cookie_digest(&headers)?;
    let factor=enabled(&state,&user).await?;
    let verified=if factor {enforce_session(&state,&user,&digest).await.is_ok()}else{true};
    let count: (i64,)=sqlx::query_as(&state.db.q("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used=0"))
        .bind(user).fetch_one(&state.db.pool).await?;
    Ok(Json(json!({"enabled":factor,"verified":verified,"recovery_remaining":count.0})))
}
pub async fn enroll_start(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>> {
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    if enabled(&state,&user).await? {return Err(AppError::bad("TOTP is already enabled"))}
    let mut secret=[0u8;20];OsRng.fill_bytes(&mut secret);
    let code=data_encoding::BASE32_NOPAD.encode(&secret);
    let sealed=seal_with(&key()?,&user,&secret)?;
    sqlx::query(&state.db.q("DELETE FROM totp_pending WHERE user_id=?"))
        .bind(&user).execute(&state.db.pool).await?;
    sqlx::query(&state.db.q("INSERT INTO totp_pending (user_id,sealed_secret,expires) VALUES (?,?,?)"))
        .bind(&user).bind(sealed).bind(crypto::now()+600).execute(&state.db.pool).await?;
    let issuer="SSO";
    let label=format!("{issuer}:{user}");
    let uri=format!("otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        url::form_urlencoded::byte_serialize(label.as_bytes()).collect::<String>(),code,issuer);
    Ok(Json(json!({"secret":code,"otpauth_uri":uri,"expires_in":600})))
}
#[derive(Deserialize)]
pub struct CodeInput {code:String}
pub async fn enroll_confirm(State(state):State<AppState>,headers:HeaderMap,Json(data):Json<CodeInput>)->AppResult<Json<Value>> {
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    let digest=cookie_digest(&headers)?;
    let mut tx=state.db.pool.begin().await?;
    let row=sqlx::query(&state.db.q("SELECT sealed_secret FROM totp_pending WHERE user_id=? AND expires>?"))
        .bind(&user).bind(crypto::now()).fetch_optional(&mut *tx).await?
        .ok_or_else(||AppError::bad("TOTP setup expired"))?;
    let sealed:String=row.try_get("sealed_secret")?;
    let secret=open_with(&key()?,&user,&sealed)?;
    let step=totp(&secret)?.check_current(&data.code).ok_or_else(AppError::unauthorized)?;
    // A second attempt cannot enable the same pending secret twice.
    let removed=sqlx::query(&state.db.q("DELETE FROM totp_pending WHERE user_id=? AND expires>?"))
        .bind(&user).bind(crypto::now()).execute(&mut *tx).await?;
    if removed.rows_affected()!=1 {return Err(AppError::bad("TOTP setup already consumed"))}
    sqlx::query(&state.db.q("INSERT INTO totp_accounts (user_id,sealed_secret,enabled,last_step) VALUES (?,?,1,?)"))
        .bind(&user).bind(sealed).bind(step as i64).execute(&mut *tx).await?;
    let mut recovery=Vec::new();
    for _ in 0..10 {
        let code=crypto::random_token();
        sqlx::query(&state.db.q("INSERT INTO recovery_codes (user_id,code_hash,used) VALUES (?,?,0)"))
            .bind(&user).bind(crypto::digest(&code)).execute(&mut *tx).await?;
        recovery.push(code);
    }
    sqlx::query(&state.db.q("DELETE FROM session_assurance WHERE token_hash=?"))
        .bind(&digest).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES (?,'totp',?)"))
        .bind(&digest).bind(crypto::now()).execute(&mut *tx).await?;
    // Enrollment immediately invalidates every OTHER pre-enrollment session.
    sqlx::query(&state.db.q("DELETE FROM sessions WHERE user_id=? AND token_hash<>?"))
        .bind(&user).bind(&digest).execute(&mut *tx).await?;
    // Enabling 2FA invalidates grants minted before the factor was required.
    sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE user_id=?"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE codes SET used=1 WHERE user_id=? AND used=0"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE pending_consents SET used=1 WHERE user_id=? AND used=0"))
        .bind(&user).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"enabled":true,"recovery_codes":recovery})))
}
async fn verify_factor(state:&AppState,user:&str,code:&str)->AppResult<&'static str>{
    if code.is_empty() || code.len()>128 {return Err(AppError::unauthorized())}
    let mut tx=state.db.pool.begin().await?;
    if code.len()==6 && code.as_bytes().iter().all(|b|b.is_ascii_digit()) {
        let row=sqlx::query(&state.db.q("SELECT sealed_secret,last_step FROM totp_accounts WHERE user_id=? AND enabled=1"))
            .bind(user).fetch_optional(&mut *tx).await?.ok_or_else(AppError::unauthorized)?;
        let sealed:String=row.try_get("sealed_secret")?;
        let secret=open_with(&key()?,user,&sealed)?;
        if let Some(step)=totp(&secret)?.check_current(code) {
            let changed=sqlx::query(&state.db.q("UPDATE totp_accounts SET last_step=? WHERE user_id=? AND enabled=1 AND last_step<?"))
                .bind(step as i64).bind(user).bind(step as i64).execute(&mut *tx).await?;
            if changed.rows_affected()==1 {
                tx.commit().await?;
                return Ok("totp");
            }
        }
    } else if code.len()>=32 {
        let consumed=sqlx::query(&state.db.q("UPDATE recovery_codes SET used=1 WHERE user_id=? AND code_hash=? AND used=0"))
            .bind(user).bind(crypto::digest(code)).execute(&mut *tx).await?;
        if consumed.rows_affected()==1 {
            tx.commit().await?;
            return Ok("recovery");
        }
    }
    Err(AppError::unauthorized())
}
pub async fn verify(State(state):State<AppState>,headers:HeaderMap,Json(data):Json<CodeInput>)->AppResult<Json<Value>> {
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user_raw(&state,&headers).await?;
    if !enabled(&state,&user).await?{return Err(AppError::bad("MFA not configured"))}
    let factor=verify_factor(&state,&user,&data.code).await?;
    let next=mark_factor(&state,&headers,factor).await?;
    Ok(Json(json!({"ok":true,"next":next})))
}

pub async fn mark_factor(state:&AppState,headers:&HeaderMap,factor:&str)->AppResult<String>{
    let user=auth::session_user_raw(state,headers).await?;
    if !enabled(state,&user).await? {return Err(AppError::bad("second factor not enabled"))}
    let digest=cookie_digest(headers)?;
    let mut tx=state.db.pool.begin().await?;
    sqlx::query(&state.db.q("DELETE FROM session_assurance WHERE token_hash=?"))
        .bind(&digest).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES (?,?,?)"))
        .bind(&digest).bind(factor).bind(crypto::now()).execute(&mut *tx).await?;
    let row=sqlx::query(&state.db.q("SELECT next_path FROM mfa_redirects WHERE token_hash=? AND expires>?"))
        .bind(&digest).bind(crypto::now()).fetch_optional(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM mfa_redirects WHERE token_hash=?"))
        .bind(&digest).execute(&mut *tx).await?;
    tx.commit().await?;
    let next=row.and_then(|r|r.try_get::<String,_>("next_path").ok()).unwrap_or_else(||"/".into());
    Ok(if valid_next(&next) {next} else {"/".into()})
}
pub async fn disable(State(state):State<AppState>,headers:HeaderMap,Json(data):Json<CodeInput>)->AppResult<Json<Value>> {
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    verify_factor(&state,&user,&data.code).await?;
    let mut tx=state.db.pool.begin().await?;
    sqlx::query(&state.db.q("DELETE FROM totp_accounts WHERE user_id=?"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM recovery_codes WHERE user_id=?"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM session_assurance WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=?)"))
        .bind(&user).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("DELETE FROM sessions WHERE user_id=?"))
        .bind(&user).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"disabled":true,"all_sessions_revoked":true})))
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn mfa_seal_rejects_wrong_user_and_tampering(){
        let key=[3u8;32];
        let sealed=seal_with(&key,"alice",b"01234567890123456789").unwrap();
        assert_eq!(open_with(&key,"alice",&sealed).unwrap(),b"01234567890123456789");
        assert!(open_with(&key,"bob",&sealed).is_err());
        let mut corrupted=sealed.clone();corrupted.push('X');
        assert!(open_with(&key,"alice",&corrupted).is_err());
    }
    #[tokio::test]
    async fn otp_enabled_sessions_require_explicit_assurance() {
        let db=std::sync::Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        let config=crate::config::Config {
            public_url:"http://localhost:3000".into(),
            bind:"127.0.0.1:3000".parse().unwrap(),auto_port:false,
            db_url:"sqlite::memory:".into(),admin_token_hash:crypto::digest("unused"),
            registration_token_hash:None,providers:vec![],
        };
        let state=AppState{config:std::sync::Arc::new(config),db,http:reqwest::Client::new()};
        sqlx::query("INSERT INTO totp_accounts (user_id,sealed_secret,enabled,last_step) VALUES ('user','encrypted',1,-1)")
            .execute(&state.db.pool).await.unwrap();
        assert!(enforce_session(&state,"user","session").await.is_err());
        sqlx::query("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES ('session','totp',1)")
            .execute(&state.db.pool).await.unwrap();
        assert!(enforce_session(&state,"user","session").await.is_ok());
        assert!(enforce_session(&state,"user","attacker-session").await.is_err());
    }
    #[test]
    fn post_mfa_next_must_be_a_server_generated_path() {
        for target in ["//evil.example","https://evil.example","\n/consent","",
            "/\\evil.example","/consent?request=../admin","/admin"] {
            assert!(!valid_next(target), "unexpected open redirect: {target}");
        }
        assert!(valid_next("/"));
        assert!(valid_next("/consent?request=valid_random-id_123"));
    }
    #[tokio::test]
    async fn recovery_code_is_single_use_and_bound_to_its_user(){
        let db=std::sync::Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        let config=crate::config::Config{
            public_url:"http://localhost:3000".into(),bind:"127.0.0.1:3000".parse().unwrap(),
            auto_port:false,db_url:"sqlite::memory:".into(),admin_token_hash:"unused".into(),
            registration_token_hash:None,providers:vec![],
        };
        let state=AppState{config:std::sync::Arc::new(config),db,http:reqwest::Client::new()};
        let secret="a".repeat(48);
        sqlx::query("INSERT INTO recovery_codes (user_id,code_hash,used) VALUES ('alice',?,0)")
            .bind(crypto::digest(&secret)).execute(&state.db.pool).await.unwrap();
        assert!(verify_factor(&state,"bob",&secret).await.is_err());
        assert_eq!(verify_factor(&state,"alice",&secret).await.unwrap(),"recovery");
        assert!(verify_factor(&state,"alice",&secret).await.is_err());
    }
    #[test]
    fn otp_has_six_digits(){
        let totp=totp(b"01234567890123456789").unwrap();
        let code=totp.generate_current().to_string();
        assert_eq!(code.len(),6);
        assert!(totp.check_current(&code).is_some());
    }
}
