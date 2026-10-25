use crate::{AppError, AppResult, AppState, crypto, provider};
use axum::{extract::{Path, Query, State, Form}, http::{HeaderMap, header}, response::{IntoResponse, Redirect, Response}, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use subtle::ConstantTimeEq;
use url::Url;

#[derive(Serialize)]
pub struct ProviderSummary { id: String, label: String }
pub async fn providers(State(state): State<AppState>) -> Json<Vec<ProviderSummary>> {
    Json(state.config.providers.iter().map(|p| ProviderSummary { id:p.id.clone(), label:p.label.clone() }).collect())
}
#[derive(Deserialize)]
pub struct AuthorizeQuery {
    client_id: String, redirect_uri: String, response_type: String,
    code_challenge: String, code_challenge_method: String,
    state: String, scope: Option<String>, provider: Option<String>
}
#[derive(Serialize, Deserialize)]
struct Transaction {
    mode: String, provider: String, verifier: String, nonce: String,
    client_id: Option<String>, redirect_uri: Option<String>,
    downstream_state: Option<String>, challenge: Option<String>,
    scope: String, link_user: Option<String>
}
async fn begin(state: &AppState, provider_id: &str, mut tx: Transaction) -> AppResult<Redirect> {
    let p = state.config.provider(provider_id).ok_or_else(|| AppError::bad("unknown provider"))?;
    let upstream_state = crypto::random_token();
    tx.verifier = crypto::random_token();
    tx.nonce = crypto::random_token();
    tx.provider = p.id.clone();
    let payload = serde_json::to_string(&tx).map_err(|_| AppError::bad("invalid auth transaction"))?;
    sqlx::query(&state.db.q("INSERT INTO auth_tx (state,data,expires,used) VALUES (?,?,?,0)"))
        .bind(&upstream_state).bind(payload).bind(crypto::now()+300)
        .execute(&state.db.pool).await?;
    let mut url = Url::parse(&p.authorize_url).map_err(|_| AppError::bad("invalid provider URL"))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &p.client_id)
            .append_pair("redirect_uri", &format!("{}/auth/callback/{}",state.config.public_url,p.id))
            .append_pair("response_type","code").append_pair("scope",&p.scopes)
            .append_pair("state",&upstream_state)
            .append_pair("code_challenge",&crypto::pkce_challenge(&tx.verifier))
            .append_pair("code_challenge_method","S256");
        if matches!(p.kind, crate::config::ProviderKind::Oidc) { q.append_pair("nonce",&tx.nonce); }
    }
    Ok(Redirect::to(url.as_str()))
}
async fn check_client(state: &AppState, id: &str, redirect: &str) -> AppResult<()> {
    let row = sqlx::query(&state.db.q("SELECT redirects, enabled FROM clients WHERE id=?"))
        .bind(id).fetch_optional(&state.db.pool).await?.ok_or_else(|| AppError::bad("unknown client"))?;
    if row.try_get::<i64,_>("enabled")? != 1 { return Err(AppError::bad("client disabled")); }
    let redirect_uris: Vec<String> = serde_json::from_str(&row.try_get::<String,_>("redirects")?)
        .map_err(|_| AppError::bad("invalid stored client"))?;
    if !redirect_uris.iter().any(|v| v == redirect) { return Err(AppError::bad("unregistered redirect URI")); }
    Ok(())
}
pub async fn authorize(State(state): State<AppState>, Query(q): Query<AuthorizeQuery>) -> AppResult<Redirect> {
    if q.response_type != "code" || q.code_challenge_method != "S256"
        || !crypto::valid_pkce(&q.code_challenge) || q.state.len() < 16 || q.state.len() > 512 {
        return Err(AppError::bad("authorization_code, PKCE S256 and state required"));
    }
    check_client(&state, &q.client_id, &q.redirect_uri).await?;
    let provider = q.provider.or_else(|| state.config.providers.first().map(|p| p.id.clone()))
        .ok_or_else(|| AppError::bad("no login providers configured"))?;
    begin(&state, &provider, Transaction {
        mode:"client".into(),provider:String::new(),verifier:String::new(),nonce:String::new(),
        client_id:Some(q.client_id),redirect_uri:Some(q.redirect_uri),
        downstream_state:Some(q.state),challenge:Some(q.code_challenge),
        scope:q.scope.unwrap_or_else(|| "profile".into()),link_user:None
    }).await
}
pub async fn login(State(state): State<AppState>, Path(provider): Path<String>) -> AppResult<Redirect> {
    begin(&state, &provider, Transaction {
        mode:"login".into(),provider:String::new(),verifier:String::new(),nonce:String::new(),
        client_id:None,redirect_uri:None,downstream_state:None,challenge:None,
        scope:"profile".into(),link_user:None
    }).await
}
#[derive(Deserialize)]
pub struct Callback { code: Option<String>, state: Option<String>, error: Option<String> }
pub async fn callback(State(state): State<AppState>, Path(provider_id): Path<String>,
                      Query(q): Query<Callback>) -> AppResult<Response> {
    if q.error.is_some() { return Err(AppError::bad("login was denied by provider")); }
    let st = q.state.ok_or_else(|| AppError::bad("missing state"))?;
    let code = q.code.ok_or_else(|| AppError::bad("missing code"))?;
    let row = sqlx::query(&state.db.q("SELECT data FROM auth_tx WHERE state=? AND expires>? AND used=0"))
        .bind(&st).bind(crypto::now()).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::bad("state expired or already used"))?;
    let tx: Transaction = serde_json::from_str(&row.try_get::<String,_>("data")?)
        .map_err(|_| AppError::bad("invalid auth state"))?;
    if tx.provider != provider_id { return Err(AppError::bad("provider mismatch")); }
    let consumed = sqlx::query(&state.db.q("UPDATE auth_tx SET used=1 WHERE state=? AND used=0 AND expires>?"))
        .bind(&st).bind(crypto::now()).execute(&state.db.pool).await?;
    if consumed.rows_affected() != 1 { return Err(AppError::bad("replayed callback")); }
    let p = state.config.provider(&provider_id).ok_or_else(|| AppError::bad("unknown provider"))?;
    let raw = provider::exchange(&state,p,&code,&tx.verifier,&tx.nonce).await?;
    let profile = provider::normalize(&state,p,raw).await?;
    let idrow = sqlx::query(&state.db.q("SELECT user_id FROM identities WHERE provider=? AND subject=?"))
        .bind(&provider_id).bind(&profile.subject).fetch_optional(&state.db.pool).await?;
    let user_id = if let Some(idrow) = idrow {
        let id: String = idrow.try_get("user_id")?;
        if tx.mode == "link" && tx.link_user.as_deref() != Some(&id) {
            return Err(AppError::bad("this identity belongs to another account"));
        }
        id
    } else {
        let id = tx.link_user.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if tx.mode != "link" {
            sqlx::query(&state.db.q("INSERT INTO users (id,name,email,avatar,created) VALUES (?,?,?,?,?)"))
                .bind(&id).bind(&profile.name).bind(&profile.email).bind(&profile.avatar)
                .bind(crypto::now()).execute(&state.db.pool).await?;
        }
        // Unique(provider,subject) prevents the same external identity being bound twice.
        sqlx::query(&state.db.q("INSERT INTO identities (provider,subject,user_id) VALUES (?,?,?)"))
            .bind(&provider_id).bind(&profile.subject).bind(&id).execute(&state.db.pool).await?;
        id
    };
    match tx.mode.as_str() {
        "client" => {
            let client_id = tx.client_id.ok_or_else(|| AppError::bad("missing client"))?;
            let redirect_uri = tx.redirect_uri.ok_or_else(|| AppError::bad("missing redirect"))?;
            check_client(&state, &client_id, &redirect_uri).await?;
            let challenge = tx.challenge.ok_or_else(|| AppError::bad("missing challenge"))?;
            let authorization_code = crypto::random_token();
            sqlx::query(&state.db.q("INSERT INTO codes (code_hash,client_id,user_id,redirect_uri,challenge,scope,expires,used) VALUES (?,?,?,?,?,?,?,0)"))
                .bind(crypto::digest(&authorization_code)).bind(&client_id).bind(&user_id)
                .bind(&redirect_uri).bind(challenge).bind(tx.scope)
                .bind(crypto::now()+120).execute(&state.db.pool).await?;
            let mut url = Url::parse(&redirect_uri).map_err(|_| AppError::bad("invalid redirect"))?;
            url.query_pairs_mut().append_pair("code",&authorization_code)
                .append_pair("state",&tx.downstream_state.unwrap_or_default());
            Ok(Redirect::to(url.as_str()).into_response())
        },
        "login" | "link" => {
            let session = crypto::random_token();
            sqlx::query(&state.db.q("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)"))
                .bind(crypto::digest(&session)).bind(&user_id).bind(crypto::now()+7*86400)
                .execute(&state.db.pool).await?;
            let secure = if state.config.public_url.starts_with("https://") { "; Secure" } else { "" };
            let cookie = format!("sso_session={session}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax{secure}");
            Ok(([(header::SET_COOKIE,cookie)],Redirect::to("/")).into_response())
        }
        _ => Err(AppError::bad("unknown auth transaction"))
    }
}

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String, code: String, redirect_uri: String, code_verifier: String,
    client_id: Option<String>, client_secret: Option<String>
}
async fn authenticate_client(state: &AppState, headers: &HeaderMap, supplied_id: Option<&str>, supplied_secret: Option<&str>) -> AppResult<String> {
    let mut id = supplied_id.unwrap_or_default().to_owned();
    let mut secret = supplied_secret.map(str::to_owned);
    if let Some(h) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = h.strip_prefix("Basic ") {
            let decoded = STANDARD.decode(encoded).map_err(|_| AppError::unauthorized())?;
            let credentials = String::from_utf8(decoded).map_err(|_| AppError::unauthorized())?;
            let (key,value) = credentials.split_once(':').ok_or_else(AppError::unauthorized)?;
            id = key.into(); secret = Some(value.into());
        }
    }
    let row = sqlx::query(&state.db.q("SELECT secret_hash,enabled FROM clients WHERE id=?"))
        .bind(&id).fetch_optional(&state.db.pool).await?.ok_or_else(AppError::unauthorized)?;
    if row.try_get::<i64,_>("enabled")? != 1 { return Err(AppError::unauthorized()); }
    let stored: Option<String> = row.try_get("secret_hash")?;
    if let Some(expected) = stored {
        let provided = secret.ok_or_else(AppError::unauthorized)?;
        if !crypto::secure_eq_hex(&expected,&crypto::digest(&provided)) { return Err(AppError::unauthorized()); }
    }
    Ok(id)
}
pub async fn token(State(state): State<AppState>, headers: HeaderMap, Form(f): Form<TokenForm>) -> AppResult<Json<Value>> {
    if f.grant_type != "authorization_code" || !crypto::valid_pkce(&f.code_verifier) {
        return Err(AppError::bad("unsupported grant or invalid PKCE verifier"));
    }
    let client_id = authenticate_client(&state,&headers,f.client_id.as_deref(),f.client_secret.as_deref()).await?;
    let row = sqlx::query(&state.db.q("SELECT client_id,user_id,redirect_uri,challenge,scope FROM codes WHERE code_hash=? AND used=0 AND expires>?"))
        .bind(crypto::digest(&f.code)).bind(crypto::now())
        .fetch_optional(&state.db.pool).await?.ok_or_else(|| AppError::bad("invalid_grant"))?;
    let stored_client: String = row.try_get("client_id")?;
    let redirect: String = row.try_get("redirect_uri")?;
    let challenge: String = row.try_get("challenge")?;
    let calculated = crypto::pkce_challenge(&f.code_verifier);
    if stored_client != client_id || redirect != f.redirect_uri
        || !bool::from(calculated.as_bytes().ct_eq(challenge.as_bytes())) { return Err(AppError::bad("invalid_grant")); }
    let used = sqlx::query(&state.db.q("UPDATE codes SET used=1 WHERE code_hash=? AND used=0 AND expires>?"))
        .bind(crypto::digest(&f.code)).bind(crypto::now()).execute(&state.db.pool).await?;
    if used.rows_affected() != 1 { return Err(AppError::bad("invalid_grant")); }
    let user_id: String = row.try_get("user_id")?;
    let scope: String = row.try_get("scope")?;
    let access_token = crypto::random_token();
    sqlx::query(&state.db.q("INSERT INTO tokens (token_hash,client_id,user_id,scope,expires,revoked,suspended_until) VALUES (?,?,?,?,?,0,0)"))
        .bind(crypto::digest(&access_token)).bind(&client_id).bind(&user_id).bind(&scope)
        .bind(crypto::now()+3600).execute(&state.db.pool).await?;
    apply_policies(&state,&client_id,&user_id).await?;
    Ok(Json(json!({"access_token":access_token,"token_type":"Bearer","expires_in":3600,"scope":scope})))
}
async fn apply_policies(state: &AppState, source: &str, user: &str) -> AppResult<()> {
    let rows = sqlx::query(&state.db.q("SELECT target_client,action,duration_seconds FROM policies WHERE source_client=?"))
        .bind(source).fetch_all(&state.db.pool).await?;
    for row in rows {
        let target: String = row.try_get("target_client")?;
        let action: String = row.try_get("action")?;
        let duration: i64 = row.try_get("duration_seconds")?;
        match action.as_str() {
            "revoke" => { sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE client_id=? AND user_id=?"))
                .bind(&target).bind(user).execute(&state.db.pool).await?; }
            "suspend" => { sqlx::query(&state.db.q("UPDATE tokens SET suspended_until=? WHERE client_id=? AND user_id=? AND revoked=0"))
                .bind(crypto::now().saturating_add(duration)).bind(&target).bind(user).execute(&state.db.pool).await?; }
            "resume" => { sqlx::query(&state.db.q("UPDATE tokens SET suspended_until=0 WHERE client_id=? AND user_id=? AND revoked=0"))
                .bind(&target).bind(user).execute(&state.db.pool).await?; }
            _ => {}
        }
    }
    Ok(())
}
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let bearer = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ")).ok_or_else(AppError::unauthorized)?;
    let row = sqlx::query(&state.db.q("SELECT u.id,u.name,u.email,u.avatar FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.expires>? AND t.revoked=0 AND t.suspended_until<=?"))
        .bind(crypto::digest(bearer)).bind(crypto::now()).bind(crypto::now())
        .fetch_optional(&state.db.pool).await?.ok_or_else(AppError::unauthorized)?;
    Ok(Json(json!({"sub":row.try_get::<String,_>("id")?,"name":row.try_get::<String,_>("name")?,
        "email":row.try_get::<Option<String>,_>("email")?,"picture":row.try_get::<Option<String>,_>("avatar")?})))
}
#[derive(Deserialize)]
pub struct RevokeForm { token: String, client_id: Option<String>, client_secret: Option<String> }
pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, Form(form): Form<RevokeForm>) -> AppResult<Json<Value>> {
    let id = authenticate_client(&state,&headers,form.client_id.as_deref(),form.client_secret.as_deref()).await?;
    sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE token_hash=? AND client_id=?"))
        .bind(crypto::digest(&form.token)).bind(id).execute(&state.db.pool).await?;
    Ok(Json(json!({})))
}
pub async fn metadata(State(state): State<AppState>) -> Json<Value> {
    let origin=&state.config.public_url;
    Json(json!({"issuer":origin,"authorization_endpoint":format!("{origin}/oauth/authorize"),
        "token_endpoint":format!("{origin}/oauth/token"),
        "userinfo_endpoint":format!("{origin}/oauth/userinfo"),
        "revocation_endpoint":format!("{origin}/oauth/revoke"),
        "registration_endpoint":format!("{origin}/connect/register"),
        "response_types_supported":["code"],"grant_types_supported":["authorization_code"],
        "code_challenge_methods_supported":["S256"],
        "token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic","none"]}))
}
pub(crate) async fn session_user(state: &AppState, headers: &HeaderMap) -> AppResult<String> {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let token = cookie.split(';').filter_map(|part| part.trim().strip_prefix("sso_session="))
        .next().ok_or_else(AppError::unauthorized)?;
    let row = sqlx::query(&state.db.q("SELECT user_id FROM sessions WHERE token_hash=? AND expires>?"))
        .bind(crypto::digest(token)).bind(crypto::now()).fetch_optional(&state.db.pool).await?
        .ok_or_else(AppError::unauthorized)?;
    Ok(row.try_get("user_id")?)
}
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let id=session_user(&state,&headers).await?;
    let row=sqlx::query(&state.db.q("SELECT name,email,avatar FROM users WHERE id=?"))
        .bind(&id).fetch_one(&state.db.pool).await?;
    Ok(Json(json!({"id":id,"name":row.try_get::<String,_>("name")?,
        "email":row.try_get::<Option<String>,_>("email")?,"avatar":row.try_get::<Option<String>,_>("avatar")?})))
}
pub async fn links(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let id=session_user(&state,&headers).await?;
    let rows=sqlx::query(&state.db.q("SELECT provider,subject FROM identities WHERE user_id=?"))
        .bind(id).fetch_all(&state.db.pool).await?;
    let linked: Vec<Value> = rows.into_iter().filter_map(|r| Some(json!({
        "provider":r.try_get::<String,_>("provider").ok()?,
        "subject":r.try_get::<String,_>("subject").ok()?
    }))).collect();
    Ok(Json(json!(linked)))
}
pub async fn link(State(state): State<AppState>, headers: HeaderMap, Path(provider): Path<String>) -> AppResult<Redirect> {
    let id=session_user(&state,&headers).await?;
    begin(&state,&provider,Transaction {
        mode:"link".into(),provider:String::new(),verifier:String::new(),nonce:String::new(),
        client_id:None,redirect_uri:None,downstream_state:None,challenge:None,
        scope:"profile".into(),link_user:Some(id)
    }).await
}
pub(crate) fn require_same_origin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let actual = headers.get(header::ORIGIN).and_then(|v|v.to_str().ok()).ok_or_else(AppError::forbidden)?;
    if actual == state.config.public_url { Ok(()) } else { Err(AppError::forbidden()) }
}
pub async fn unlink(State(state): State<AppState>, headers: HeaderMap, Path(provider): Path<String>) -> AppResult<Json<Value>> {
    require_same_origin(&state,&headers)?;
    let id=session_user(&state,&headers).await?;
    let count: i64 = sqlx::query(&state.db.q("SELECT COUNT(*) AS n FROM identities WHERE user_id=?"))
        .bind(&id).fetch_one(&state.db.pool).await?.try_get("n")?;
    if count < 2 { return Err(AppError::bad("cannot remove final login method")); }
    sqlx::query(&state.db.q("DELETE FROM identities WHERE user_id=? AND provider=?"))
        .bind(id).bind(provider).execute(&state.db.pool).await?;
    Ok(Json(json!({"ok":true})))
}
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_same_origin(&state,&headers)?;
    if let Ok(user_id)=session_user(&state,&headers).await {
        let cookie=headers.get(header::COOKIE).and_then(|v|v.to_str().ok()).unwrap_or("");
        if let Some(token)=cookie.split(';').filter_map(|part|part.trim().strip_prefix("sso_session=")).next() {
            sqlx::query(&state.db.q("DELETE FROM sessions WHERE token_hash=? AND user_id=?"))
                .bind(crypto::digest(token)).bind(user_id).execute(&state.db.pool).await?;
        }
    }
    Ok(([(header::SET_COOKIE,"sso_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax")],Json(json!({"ok":true}))).into_response())
}
