//! WebAuthn/passkeys: signed assertion verification, server-side one-time
//! ceremonies, credential ownership and user-verification enforcement.
//! Passkey login currently uses the user's stable account ID (shown in /me).
use crate::{auth, crypto, mfa, AppError, AppResult, AppState};
use axum::{
    extract::{Path, State}, http::{header, HeaderMap},
    response::{IntoResponse, Response}, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::convert::TryFrom;
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::*;

fn engine(state: &AppState) -> AppResult<Webauthn> {
    let origin=Url::parse(&state.config.public_url).map_err(|_|AppError::bad("invalid WebAuthn origin"))?;
    let rp_id=origin.host_str().ok_or_else(||AppError::bad("WebAuthn origin has no host"))?;
    if origin.scheme()!="https" && rp_id!="localhost" && rp_id!="127.0.0.1" {
        return Err(AppError::bad("WebAuthn requires HTTPS"));
    }
    WebauthnBuilder::new(rp_id,&origin).map_err(|_|AppError::bad("invalid WebAuthn RP ID"))?
        .rp_name("SSO Identity").build().map_err(|_|AppError::bad("WebAuthn unavailable"))
}
fn id_of(passkey:&Passkey)->String {URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())}
async fn credentials(state:&AppState,user:&str)->AppResult<Vec<(String,Passkey)>> {
    let rows=sqlx::query(&state.db.q("SELECT credential_id,credential_json FROM passkeys WHERE user_id=?"))
        .bind(user).fetch_all(&state.db.pool).await?;
    rows.into_iter().map(|row| {
        let id:String=row.try_get("credential_id")?;
        let raw:String=row.try_get("credential_json")?;
        let key=serde_json::from_str(&raw).map_err(|_|AppError::bad("stored passkey invalid"))?;
        Ok((id,key))
    }).collect()
}
fn cookie_flow(headers:&HeaderMap,expected:&str)->bool {
    headers.get(header::COOKIE).and_then(|h|h.to_str().ok()).unwrap_or("")
        .split(';').filter_map(|x|x.trim().strip_prefix("sso_passkey_flow="))
        .any(|candidate|candidate.len()==expected.len() &&
            bool::from(candidate.as_bytes().ct_eq(expected.as_bytes())))
}
fn secure_cookie(state:&AppState,id:&str)->String{
    let secure=if state.config.public_url.starts_with("https://") {"; Secure"}else{""};
    format!("sso_passkey_flow={id}; HttpOnly; Path=/; Max-Age=300; SameSite=Strict{secure}")
}
fn cleared_cookie(state:&AppState)->String{
    let secure=if state.config.public_url.starts_with("https://") {"; Secure"}else{""};
    format!("sso_passkey_flow=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{secure}")
}
#[derive(Deserialize)]
pub struct RegistrationFinish {request_id:String,credential:Value,label:Option<String>}
pub async fn register_start(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>>{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    let uuid=Uuid::parse_str(&user).map_err(|_|AppError::bad("invalid local user ID"))?;
    let old=credentials(&state,&user).await?;
    if old.len()>=12 {return Err(AppError::bad("passkey quota reached"))}
    let row=sqlx::query(&state.db.q("SELECT name FROM users WHERE id=?"))
        .bind(&user).fetch_one(&state.db.pool).await?;
    let name:String=row.try_get("name")?;
    let exclude=old.iter().map(|(_,c)|c.cred_id().clone()).collect();
    let (options,ceremony)=engine(&state)?.start_passkey_registration(uuid,&user,&name,Some(exclude))
        .map_err(|_|AppError::bad("passkey registration could not start"))?;
    let request_id=crypto::random_token();
    sqlx::query(&state.db.q("INSERT INTO passkey_challenges (id,user_id,kind,state_json,session_hash,expires,used) VALUES (? ,?,'register',?,?,?,0)"))
        .bind(&request_id).bind(&user)
        .bind(serde_json::to_string(&ceremony).map_err(|_|AppError::bad("invalid ceremony state"))?)
        .bind(mfa::cookie_digest(&headers)?).bind(crypto::now()+300)
        .execute(&state.db.pool).await?;
    Ok(Json(json!({"request_id":request_id,"options":options})))
}
pub async fn register_finish(State(state):State<AppState>,headers:HeaderMap,
    Json(body):Json<RegistrationFinish>)->AppResult<Json<Value>>{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    let digest=mfa::cookie_digest(&headers)?;
    let row=sqlx::query(&state.db.q(
        "SELECT state_json FROM passkey_challenges WHERE id=? AND kind='register' AND user_id=? AND session_hash=? AND expires>? AND used=0"
    )).bind(&body.request_id).bind(&user).bind(digest).bind(crypto::now())
        .fetch_optional(&state.db.pool).await?.ok_or_else(||AppError::bad("passkey registration expired"))?;
    let raw:String=row.try_get("state_json")?;
    let ceremony:PasskeyRegistration=serde_json::from_str(&raw)
        .map_err(|_|AppError::bad("invalid passkey registration state"))?;
    let used=sqlx::query(&state.db.q("UPDATE passkey_challenges SET used=1 WHERE id=? AND kind='register' AND used=0 AND expires>?"))
        .bind(&body.request_id).bind(crypto::now()).execute(&state.db.pool).await?;
    if used.rows_affected()!=1 {return Err(AppError::bad("passkey ceremony replayed"))}
    let credential:RegisterPublicKeyCredential=serde_json::from_value(body.credential)
        .map_err(|_|AppError::bad("invalid WebAuthn credential"))?;
    let passkey=engine(&state)?.finish_passkey_registration(&credential,&ceremony)
        .map_err(|_|AppError::bad("WebAuthn attestation verification failed"))?;
    let id=id_of(&passkey);
    let label=body.label.unwrap_or_else(||"Passkey".into());
    let label=label.chars().take(60).collect::<String>();
    sqlx::query(&state.db.q("INSERT INTO passkeys (credential_id,user_id,credential_json,label,created) VALUES (?,?,?,?,?)"))
        .bind(&id).bind(&user).bind(serde_json::to_string(&passkey).map_err(|_|AppError::bad("passkey encoding failed"))?)
        .bind(&label).bind(crypto::now()).execute(&state.db.pool).await?;
    Ok(Json(json!({"ok":true,"id":id,"label":label})))
}
#[derive(Deserialize)]
pub struct LoginStart {user_id:String}
pub async fn login_start(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<LoginStart>)
    ->AppResult<Response>
{
    auth::require_same_origin(&state,&headers)?;
    if Uuid::try_from(body.user_id.as_str()).is_err() {return Err(AppError::bad("invalid account identifier"))}
    let saved=credentials(&state,&body.user_id).await?;
    if saved.is_empty(){return Err(AppError::bad("no passkeys registered for account"))}
    let creds:Vec<Passkey>=saved.into_iter().map(|(_,p)|p).collect();
    let (options,ceremony)=engine(&state)?.start_passkey_authentication(&creds)
        .map_err(|_|AppError::bad("passkey login could not start"))?;
    let request_id=crypto::random_token();
    sqlx::query(&state.db.q("INSERT INTO passkey_challenges (id,user_id,kind,state_json,session_hash,expires,used) VALUES (?,?,'authenticate',?,NULL,?,0)"))
        .bind(&request_id).bind(&body.user_id)
        .bind(serde_json::to_string(&ceremony).map_err(|_|AppError::bad("invalid ceremony state"))?)
        .bind(crypto::now()+300).execute(&state.db.pool).await?;
    let cookie=secure_cookie(&state,&request_id);
    Ok(([(header::SET_COOKIE,cookie)],Json(json!({"request_id":request_id,"options":options}))).into_response())
}
#[derive(Deserialize)]
pub struct LoginFinish {request_id:String,credential:Value}
pub async fn login_finish(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<LoginFinish>)
    ->AppResult<Response>
{
    auth::require_same_origin(&state,&headers)?;
    if !cookie_flow(&headers,&body.request_id){return Err(AppError::forbidden())}
    let row=sqlx::query(&state.db.q(
        "SELECT user_id,state_json FROM passkey_challenges WHERE id=? AND kind='authenticate' AND used=0 AND expires>?"
    )).bind(&body.request_id).bind(crypto::now()).fetch_optional(&state.db.pool).await?
        .ok_or_else(||AppError::bad("passkey login expired"))?;
    let user:String=row.try_get("user_id")?;
    let raw:String=row.try_get("state_json")?;
    let ceremony:PasskeyAuthentication=serde_json::from_str(&raw)
        .map_err(|_|AppError::bad("invalid authentication state"))?;
    let consumed=sqlx::query(&state.db.q(
        "UPDATE passkey_challenges SET used=1 WHERE id=? AND used=0 AND expires>?"
    )).bind(&body.request_id).bind(crypto::now()).execute(&state.db.pool).await?;
    if consumed.rows_affected()!=1 {return Err(AppError::bad("passkey login replayed"))}
    let credential:PublicKeyCredential=serde_json::from_value(body.credential)
        .map_err(|_|AppError::bad("invalid WebAuthn response"))?;
    let outcome=engine(&state)?.finish_passkey_authentication(&credential,&ceremony)
        .map_err(|_|AppError::unauthorized())?;
    let mut saved=credentials(&state,&user).await?;
    let mut updated=None;
    for (id,passkey) in &mut saved {
        let original=serde_json::to_string(passkey).map_err(|_|AppError::bad("passkey serialization failed"))?;
        if passkey.update_credential(&outcome).is_some() {
            updated=Some((id.clone(),original,serde_json::to_string(passkey)
                .map_err(|_|AppError::bad("passkey serialization failed"))?));
            break;
        }
    }
    let (id,original_key,updated_key)=updated.ok_or_else(AppError::unauthorized)?;
    let mut tx=state.db.pool.begin().await?;
    // Prevent concurrent assertions from silently overwriting authenticator
    // counters or backup-state updates made by another request.
    let updated=sqlx::query(&state.db.q("UPDATE passkeys SET credential_json=? WHERE credential_id=? AND user_id=? AND credential_json=?"))
        .bind(updated_key).bind(id).bind(&user).bind(original_key)
        .execute(&mut *tx).await?;
    if updated.rows_affected()!=1 {return Err(AppError::bad("passkey credential changed; retry"))}
    let session=crypto::random_token();
    let session_digest=crypto::digest(&session);
    sqlx::query(&state.db.q("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)"))
        .bind(&session_digest).bind(&user).bind(crypto::now()+7*86400)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let next=mfa::new_session_target(&state,&user,&session_digest,"/",true).await?;
    let secure=if state.config.public_url.starts_with("https://"){"; Secure"}else{""};
    let cookie=format!("sso_session={session}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax{secure}");
    let mut response=Json(json!({"ok":true,"next":next})).into_response();
    response.headers_mut().append(header::SET_COOKIE,cookie.parse()
        .map_err(|_|AppError::bad("session cookie failure"))?);
    response.headers_mut().append(header::SET_COOKIE,cleared_cookie(&state).parse()
        .map_err(|_|AppError::bad("flow cookie failure"))?);
    Ok(response)
}
/// Elevate an OAuth-originated first-factor session using an already enrolled
/// passkey, without replacing the session cookie. The challenge is bound to
/// the exact session hash and cannot be replayed across browsers.
pub async fn stepup_start(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>> {
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user_raw(&state,&headers).await?;
    if !mfa::enabled(&state,&user).await? {return Err(AppError::bad("MFA is not enabled"))}
    let saved=credentials(&state,&user).await?;
    if saved.is_empty(){return Err(AppError::bad("no passkeys registered"))}
    let creds:Vec<Passkey>=saved.into_iter().map(|(_,p)|p).collect();
    let (options,ceremony)=engine(&state)?.start_passkey_authentication(&creds)
        .map_err(|_|AppError::bad("passkey challenge unavailable"))?;
    let request_id=crypto::random_token();
    sqlx::query(&state.db.q("INSERT INTO passkey_challenges (id,user_id,kind,state_json,session_hash,expires,used) VALUES (?,?,'stepup',?,?,?,0)"))
        .bind(&request_id).bind(user)
        .bind(serde_json::to_string(&ceremony).map_err(|_|AppError::bad("invalid ceremony state"))?)
        .bind(mfa::cookie_digest(&headers)?).bind(crypto::now()+300)
        .execute(&state.db.pool).await?;
    Ok(Json(json!({"request_id":request_id,"options":options})))
}
pub async fn stepup_finish(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<LoginFinish>)
    ->AppResult<Json<Value>>
{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user_raw(&state,&headers).await?;
    let digest=mfa::cookie_digest(&headers)?;
    let row=sqlx::query(&state.db.q(
        "SELECT state_json FROM passkey_challenges WHERE id=? AND kind='stepup' AND user_id=? AND session_hash=? AND used=0 AND expires>?"
    )).bind(&body.request_id).bind(&user).bind(&digest).bind(crypto::now())
      .fetch_optional(&state.db.pool).await?.ok_or_else(||AppError::bad("passkey step-up expired"))?;
    let raw:String=row.try_get("state_json")?;
    let ceremony:PasskeyAuthentication=serde_json::from_str(&raw)
        .map_err(|_|AppError::bad("invalid passkey state"))?;
    let changed=sqlx::query(&state.db.q(
        "UPDATE passkey_challenges SET used=1 WHERE id=? AND kind='stepup' AND user_id=? AND session_hash=? AND used=0 AND expires>?"
    )).bind(&body.request_id).bind(&user).bind(&digest).bind(crypto::now())
      .execute(&state.db.pool).await?;
    if changed.rows_affected()!=1 {return Err(AppError::bad("passkey step-up replayed"))}
    let credential:PublicKeyCredential=serde_json::from_value(body.credential)
        .map_err(|_|AppError::bad("invalid WebAuthn credential"))?;
    let outcome=engine(&state)?.finish_passkey_authentication(&credential,&ceremony)
        .map_err(|_|AppError::unauthorized())?;
    let mut saved=credentials(&state,&user).await?;
    let mut update=None;
    for (id,passkey) in &mut saved {
        let original=serde_json::to_string(passkey).map_err(|_|AppError::bad("passkey serialization failed"))?;
        if passkey.update_credential(&outcome).is_some(){
            update=Some((id.clone(),original,serde_json::to_string(passkey)
                .map_err(|_|AppError::bad("passkey serialization failed"))?));break;
        }
    }
    let (id,old,new)=update.ok_or_else(AppError::unauthorized)?;
    let changed=sqlx::query(&state.db.q(
        "UPDATE passkeys SET credential_json=? WHERE credential_id=? AND user_id=? AND credential_json=?"
    )).bind(new).bind(id).bind(&user).bind(old).execute(&state.db.pool).await?;
    if changed.rows_affected()!=1 {return Err(AppError::bad("passkey changed concurrently"))}
    let next=mfa::mark_factor(&state,&headers,"passkey").await?;
    Ok(Json(json!({"ok":true,"next":next})))
}
pub async fn list(State(state):State<AppState>,headers:HeaderMap)->AppResult<Json<Value>> {
    let user=auth::session_user(&state,&headers).await?;
    let rows=sqlx::query(&state.db.q("SELECT credential_id,label,created FROM passkeys WHERE user_id=? ORDER BY created DESC"))
        .bind(user).fetch_all(&state.db.pool).await?;
    let out:Vec<Value>=rows.iter().map(|r|json!({
        "id":r.try_get::<String,_>("credential_id").unwrap_or_default(),
        "label":r.try_get::<String,_>("label").unwrap_or_default(),
        "created":r.try_get::<i64,_>("created").unwrap_or_default()
    })).collect();
    Ok(Json(json!(out)))
}
pub async fn remove(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<String>)
    ->AppResult<Json<Value>>
{
    auth::require_same_origin(&state,&headers)?;
    let user=auth::session_user(&state,&headers).await?;
    let changed=sqlx::query(&state.db.q("DELETE FROM passkeys WHERE credential_id=? AND user_id=?"))
        .bind(&id).bind(user).execute(&state.db.pool).await?;
    if changed.rows_affected()!=1 {return Err(AppError::forbidden())}
    Ok(Json(json!({"deleted":true})))
}
#[cfg(test)]
mod tests{
    use super::*;
    #[tokio::test]
    async fn ceremony_consumption_is_atomic_and_rejects_cross_session_use(){
        let db=crate::db::Db::open("sqlite::memory:").await.unwrap();
        sqlx::query("INSERT INTO passkey_challenges (id,user_id,kind,state_json,session_hash,expires,used) VALUES ('unique-ceremony','alice','stepup','{}','browser-a',9999999999,0)")
            .execute(&db.pool).await.unwrap();
        let wrong=sqlx::query("SELECT state_json FROM passkey_challenges WHERE id='unique-ceremony' AND session_hash='browser-b'")
            .fetch_optional(&db.pool).await.unwrap();
        assert!(wrong.is_none());
        let attempt=||sqlx::query("UPDATE passkey_challenges SET used=1 WHERE id='unique-ceremony' AND session_hash='browser-a' AND used=0 AND expires>0");
        assert_eq!(attempt().execute(&db.pool).await.unwrap().rows_affected(),1);
        assert_eq!(attempt().execute(&db.pool).await.unwrap().rows_affected(),0);
    }
    #[test]
    fn browser_flow_cookie_is_exact_and_constant_time_compared(){
        let mut headers=HeaderMap::new();
        headers.insert(header::COOKIE,"sso_passkey_flow=abc; other=x".parse().unwrap());
        assert!(cookie_flow(&headers,"abc"));
        assert!(!cookie_flow(&headers,"abcd"));
        assert!(!cookie_flow(&headers,"def"));
    }
}
