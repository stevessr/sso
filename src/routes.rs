use crate::{config::Provider, error::ApiError, fields::{self, FieldRule}, security, upstream, AppState};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, OriginalUri, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post}, Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;

type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(web_index))
        .route("/login", get(web_index))
        .route("/account", get(web_index))
        .route("/admin", get(web_index))
        .route("/assets/app.js", get(web_js))
        .route("/assets/style.css", get(web_css))
        .route_service("/assets/monet.bundle.js", ServeFile::new("web/monet.bundle.js"))
        .nest_service("/assets/crypto", ServeDir::new("crypto-wasm/pkg"))
        .route("/branding/background", get(background))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .route("/.well-known/sso-configuration", get(sso_config))
        .route("/oauth/jwks", get(jwks))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(userinfo))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/revoke", post(revoke))
        .route("/connect/register", post(register))
        .route("/auth/{provider}/start", get(start_upstream))
        .route("/auth/{provider}/callback", get(callback))
        .route("/api/meta", get(meta))
        .route("/api/me", get(me))
        .route("/api/me/identities", get(identities))
        .route("/api/me/apps", get(my_apps))
        .route("/api/me/apps/{client}/revoke", post(my_revoke_app))
        .route("/api/me/apps/{client}/block", post(my_block_app))
        .route("/api/me/identities/{identity}", axum::routing::delete(unlink))
        .route("/api/me/logout", post(logout))
        .route("/admin/api/clients", get(admin_clients))
        .route("/admin/api/rules", get(admin_rules).post(admin_add_rule))
        .route("/admin/api/rules/{id}", axum::routing::delete(admin_delete_rule))
        .route("/admin/api/policies", post(admin_policy))
        .route("/admin/api/mappings", get(admin_mappings).post(admin_save_mapping))
        .route("/admin/api/mappings/preview", post(admin_mapping_preview))
        .route("/admin/api/branding", post(upload_background))
        .layer(DefaultBodyLimit::max(6 * 1024 * 1024))
        .with_state(state)
}

async fn web_index() -> Html<&'static str> { Html(include_str!("../web/index.html")) }
async fn web_js() -> impl IntoResponse { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("../web/app.js")) }
async fn web_css() -> impl IntoResponse { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../web/style.css")) }
fn admin(headers: &HeaderMap, state: &AppState) -> ApiResult<()> {
    let auth = security::bearer(headers).ok_or(ApiError::unauthorized())?;
    if !security::secret_eq(auth, &state.config.admin_token) { return Err(ApiError::unauthorized()); }
    Ok(())
}
fn registrant(headers: &HeaderMap, state: &AppState) -> ApiResult<()> {
    let auth = security::bearer(headers).ok_or(ApiError::unauthorized())?;
    if !security::secret_eq(auth, &state.config.registration_token) && !security::secret_eq(auth, &state.config.admin_token) {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}
fn provider<'a>(state: &'a AppState, id: &str) -> ApiResult<&'a Provider> {
    state.config.providers.iter().find(|p| p.id == id).ok_or(ApiError::not_found())
}
fn absolute(state: &AppState, path: &str) -> String { format!("{}{path}", state.config.public_url) }
fn secure(state: &AppState) -> bool { state.config.public_url.starts_with("https://") }

async fn audit(state: &AppState, kind: &str, actor: Option<&str>, detail: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO audit_log(id,kind,actor,detail,created_at) VALUES($1,$2,$3,$4,$5)")
        .bind(security::random()).bind(kind).bind(actor).bind(detail).bind(security::now())
        .execute(&state.db).await?;
    Ok(())
}

#[derive(Serialize)]
struct ProviderView<'a> { id: &'a str, label: &'a str, kind: &'a crate::config::ProviderKind }
async fn meta(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"issuer":state.config.public_url,"providers":state.config.providers.iter().map(|p| ProviderView{id:&p.id,label:&p.label,kind:&p.kind}).collect::<Vec<_>>()}))
}
async fn sso_config(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"issuer":state.config.public_url,"registration_endpoint":absolute(&state,"/connect/register"),"protocols":["oidc","oauth2"],"version":"0.1.0"}))
}
async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
    let origin = &state.config.public_url;
    Json(json!({
        "issuer":origin,"authorization_endpoint":absolute(&state,"/oauth/authorize"),
        "token_endpoint":absolute(&state,"/oauth/token"),"userinfo_endpoint":absolute(&state,"/oauth/userinfo"),
        "jwks_uri":absolute(&state,"/oauth/jwks"),"introspection_endpoint":absolute(&state,"/oauth/introspect"),
        "revocation_endpoint":absolute(&state,"/oauth/revoke"),"registration_endpoint":absolute(&state,"/connect/register"),
        "response_types_supported":["code"],"grant_types_supported":["authorization_code"],
        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],
        "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],
        "code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"]
    }))
}
async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> { Json(security::jwks(&state.signing)) }

#[derive(Deserialize)]
struct ClientRegistration { client_name: String, redirect_uris: Vec<String>, #[serde(default = "default_auth_method")] token_endpoint_auth_method: String }
fn default_auth_method() -> String { "client_secret_basic".into() }
fn checked_redirect(uri: &str) -> bool {
    if let Ok(u) = Url::parse(uri) {
        if u.fragment().is_some() || u.username() != "" || u.password().is_some() || u.host_str().is_none() { return false; }
        return u.scheme() == "https" || (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "::1")));
    }
    false
}
async fn register(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<ClientRegistration>) -> ApiResult<(StatusCode, Json<Value>)> {
    registrant(&headers, &state)?;
    if input.client_name.trim().is_empty() || input.client_name.len() > 128 || input.redirect_uris.is_empty() || input.redirect_uris.len() > 10 || input.redirect_uris.iter().any(|u| !checked_redirect(u)) {
        return Err(ApiError::bad("invalid_client_metadata"));
    }
    if !matches!(input.token_endpoint_auth_method.as_str(), "client_secret_basic" | "client_secret_post" | "none") {
        return Err(ApiError::bad("unsupported_client_auth_method"));
    }
    let client_id = security::random();
    let secret = if input.token_endpoint_auth_method == "none" { None } else { Some(security::random()) };
    sqlx::query("INSERT INTO oauth_clients(id,name,secret_hash,auth_method,redirects_json,created_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(&client_id).bind(&input.client_name).bind(secret.as_deref().map(security::sha256))
        .bind(&input.token_endpoint_auth_method).bind(serde_json::to_string(&input.redirect_uris).map_err(|_| ApiError::internal())?)
        .bind(security::now()).execute(&state.db).await?;
    audit(&state,"client.register",Some(&client_id),"dynamic client registration").await?;
    Ok((StatusCode::CREATED, Json(json!({"client_id":client_id,"client_secret":secret,"client_name":input.client_name,
        "redirect_uris":input.redirect_uris,"token_endpoint_auth_method":input.token_endpoint_auth_method,
        "grant_types":["authorization_code"],"response_types":["code"],"client_id_issued_at":security::now()}))))
}

#[derive(Deserialize)]
struct Authorization {
    client_id: String, redirect_uri: String, response_type: String,
    code_challenge: String, code_challenge_method: String,
    state: Option<String>, scope: Option<String>, nonce: Option<String>,
}
async fn authorized_user(headers: &HeaderMap, state: &AppState) -> ApiResult<Option<String>> {
    let Some(session) = security::cookie(headers) else { return Ok(None); };
    let row = sqlx::query("SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at>$2")
        .bind(security::sha256(session)).bind(security::now()).fetch_optional(&state.db).await?;
    Ok(row.map(|r| r.get::<String,_>("user_id")))
}
async fn get_client(state: &AppState, id: &str) -> ApiResult<sqlx::any::AnyRow> {
    sqlx::query("SELECT id,name,secret_hash,auth_method,redirects_json FROM oauth_clients WHERE id=$1")
        .bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::bad("invalid_client"))
}
fn redirects_allow(row: &sqlx::any::AnyRow, redirect_uri: &str) -> bool {
    serde_json::from_str::<Vec<String>>(&row.get::<String,_>("redirects_json"))
        .unwrap_or_default().iter().any(|u| u == redirect_uri)
}
async fn allowed(state: &AppState, user: &str, client: &str) -> ApiResult<bool> {
    let user_block = sqlx::query("SELECT blocked FROM app_user_blocks WHERE user_id=$1 AND client_id=$2")
        .bind(user).bind(client).fetch_optional(&state.db).await?;
    if user_block.is_some_and(|r|r.get::<i64,_>("blocked") != 0) { return Ok(false); }
    let row = sqlx::query("SELECT mode FROM app_overrides WHERE user_id=$1 AND client_id=$2 AND (expires_at IS NULL OR expires_at>$3)")
        .bind(user).bind(client).bind(security::now()).fetch_optional(&state.db).await?;
    if let Some(r) = row { return Ok(r.get::<String,_>("mode") == "allow"); }
    let base = sqlx::query("SELECT enabled FROM app_base_access WHERE user_id=$1 AND client_id=$2")
        .bind(user).bind(client).fetch_optional(&state.db).await?;
    Ok(base.map(|r| r.get::<i64,_>("enabled") != 0).unwrap_or(true))
}
async fn authorize(State(state): State<Arc<AppState>>, headers: HeaderMap, original: OriginalUri, Query(q): Query<Authorization>) -> ApiResult<Response> {
    if q.response_type != "code" || q.code_challenge_method != "S256" || q.code_challenge.len() != 43 || !q.code_challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(ApiError::bad("invalid_authorization_request"));
    }
    let client = get_client(&state, &q.client_id).await?;
    if !redirects_allow(&client, &q.redirect_uri) { return Err(ApiError::bad("invalid_redirect_uri")); }
    let scope = q.scope.as_deref().unwrap_or("openid profile");
    if scope.split_whitespace().any(|s| !matches!(s, "openid" | "profile" | "email")) { return Err(ApiError::bad("unsupported_scope")); }
    let Some(user_id) = authorized_user(&headers,&state).await? else {
        let path = original.path_and_query().map(|p|p.as_str()).unwrap_or("/oauth/authorize");
        let login = format!("/login?return_to={}", url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>());
        return Ok(Redirect::to(&login).into_response());
    };
    if !allowed(&state, &user_id, &q.client_id).await? { return Err(ApiError::forbidden()); }
    let code = security::random();
    sqlx::query("INSERT INTO auth_codes(code_hash,client_id,user_id,redirect_uri,scope,nonce,challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(security::sha256(&code)).bind(&q.client_id).bind(user_id).bind(&q.redirect_uri)
        .bind(scope).bind(q.nonce.as_deref()).bind(&q.code_challenge).bind(security::now()+120).execute(&state.db).await?;
    let mut uri = Url::parse(&q.redirect_uri).map_err(|_| ApiError::bad("invalid_redirect_uri"))?;
    uri.query_pairs_mut().append_pair("code",&code);
    if let Some(s) = q.state { uri.query_pairs_mut().append_pair("state",&s); }
    Ok(Redirect::to(uri.as_str()).into_response())
}

#[derive(Deserialize)]
struct OAuthTokenRequest {
    grant_type: String, code: String, redirect_uri: String,
    client_id: Option<String>, client_secret: Option<String>, code_verifier: String,
}
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let encoded = headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (id, secret) = pair.split_once(':')?;
    Some((id.to_owned(), secret.to_owned()))
}
async fn client_auth(state: &AppState, headers: &HeaderMap, form_id: Option<&str>, form_secret: Option<&str>) -> ApiResult<String> {
    let from_basic = basic_credentials(headers);
    let client_id = from_basic.as_ref().map(|(id,_)| id.as_str()).or(form_id).ok_or(ApiError::unauthorized())?;
    let row = get_client(state, client_id).await.map_err(|_| ApiError::unauthorized())?;
    let method: String = row.get("auth_method");
    let expected: Option<String> = row.try_get("secret_hash").unwrap_or(None);
    let valid = match method.as_str() {
        "none" => from_basic.is_none() && form_secret.is_none() && form_id == Some(client_id),
        "client_secret_basic" => from_basic.as_ref().map(|(_,secret)| secret.as_str()).zip(expected.as_deref())
            .is_some_and(|(value,hash)| security::secret_eq(&security::sha256(value), hash)),
        "client_secret_post" => from_basic.is_none() && form_secret.zip(expected.as_deref())
            .is_some_and(|(value,hash)| security::secret_eq(&security::sha256(value), hash)),
        _ => false,
    };
    if !valid || (form_id.is_some() && form_id != Some(client_id)) { return Err(ApiError::unauthorized()); }
    Ok(client_id.to_owned())
}

async fn claims_for(state: &AppState, user_id: &str, client_id: &str, scope: &str) -> ApiResult<Value> {
    let user = sqlx::query("SELECT name,email FROM users WHERE id=$1").bind(user_id)
        .fetch_optional(&state.db).await?.ok_or(ApiError::not_found())?;
    let mut result = json!({"sub":user_id});
    if scope.split_whitespace().any(|s| s == "profile") { result["name"] = json!(user.get::<String,_>("name")); }
    if scope.split_whitespace().any(|s| s == "email") {
        if let Ok(Some(email)) = user.try_get::<Option<String>,_>("email") { result["email"] = json!(email); }
    }
    let identity = sqlx::query("SELECT provider,claims_json FROM identities WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1")
        .bind(user_id).fetch_optional(&state.db).await?;
    if let Some(id) = identity {
        let provider: String = id.get("provider");
        let mapping = sqlx::query("SELECT rules_json,script FROM field_mappings WHERE provider=$1 AND client_id=$2")
            .bind(&provider).bind(client_id).fetch_optional(&state.db).await?;
        if let Some(map) = mapping {
            let source: Value = serde_json::from_str(&id.get::<String,_>("claims_json")).map_err(|_| ApiError::internal())?;
            let rules: Vec<FieldRule> = serde_json::from_str(&map.get::<String,_>("rules_json")).map_err(|_| ApiError::internal())?;
            let script: String = map.get("script");
            let transformed = tokio::task::spawn_blocking(move || fields::transform(&source, &rules, &script))
                .await.map_err(|_| ApiError::internal())?.map_err(|err| { tracing::warn!(?err, "claim mapping failed"); ApiError::bad("mapping_error") })?;
            for key in ["name", "preferred_username", "picture", "email", "email_verified"] {
                let in_scope = if key == "email" || key == "email_verified" { scope.split_whitespace().any(|s| s == "email") }
                    else { scope.split_whitespace().any(|s| s == "profile") };
                if in_scope { if let Some(value) = transformed.get(key) { result[key] = value.clone(); } }
            }
        }
    }
    Ok(result)
}

async fn on_client_login(state: &AppState, user: &str, trigger: &str) -> ApiResult<()> {
    let rows = sqlx::query("SELECT target_client,action,duration_seconds FROM link_rules WHERE trigger_client=$1")
        .bind(trigger).fetch_all(&state.db).await?;
    for row in rows {
        let target: String = row.get("target_client");
        let action: String = row.get("action");
        let duration: Option<i64> = row.try_get("duration_seconds").unwrap_or(None);
        match action.as_str() {
            "revoke" => {
                sqlx::query("UPDATE access_tokens SET revoked_at=$1 WHERE user_id=$2 AND client_id=$3 AND revoked_at IS NULL")
                    .bind(security::now()).bind(user).bind(&target).execute(&state.db).await?;
            }
            "suspend" | "restore_for" => {
                let mode = if action == "suspend" { "deny" } else { "allow" };
                sqlx::query("INSERT INTO app_overrides(user_id,client_id,mode,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,client_id) DO UPDATE SET mode=excluded.mode,expires_at=excluded.expires_at")
                    .bind(user).bind(&target).bind(mode).bind(duration.map(|d|security::now()+d))
                    .execute(&state.db).await?;
            }
            _ => return Err(ApiError::internal()),
        }
        audit(state,"app.link_rule",Some(user),&format!("{trigger} -> {target}: {action}")).await?;
    }
    Ok(())
}

async fn token(State(state): State<Arc<AppState>>, headers: HeaderMap, Form(q): Form<OAuthTokenRequest>) -> ApiResult<Json<Value>> {
    if q.grant_type != "authorization_code" || !(43..=128).contains(&q.code_verifier.len()) ||
        !q.code_verifier.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')) {
        return Err(ApiError::bad("unsupported_grant_type_or_pkce"));
    }
    let client = client_auth(&state,&headers,q.client_id.as_deref(),q.client_secret.as_deref()).await?;
    let code_row = sqlx::query("DELETE FROM auth_codes WHERE code_hash=$1 AND expires_at>$2 RETURNING client_id,user_id,redirect_uri,scope,nonce,challenge")
        .bind(security::sha256(&q.code)).bind(security::now()).fetch_optional(&state.db).await?
        .ok_or(ApiError::bad("invalid_grant"))?;
    let actual_client: String = code_row.get("client_id");
    let user: String = code_row.get("user_id");
    let redirect: String = code_row.get("redirect_uri");
    let challenge: String = code_row.get("challenge");
    if client != actual_client || q.redirect_uri != redirect || !security::secret_eq(&challenge, &security::pkce(&q.code_verifier)) {
        return Err(ApiError::bad("invalid_grant"));
    }
    if !allowed(&state, &user, &client).await? { return Err(ApiError::forbidden()); }
    let scope: String = code_row.get("scope");
    let nonce: Option<String> = code_row.try_get("nonce").unwrap_or(None);
    let claims = claims_for(&state, &user, &client, &scope).await?;
    let access = security::random();
    sqlx::query("INSERT INTO access_tokens(token_hash,client_id,user_id,scope,expires_at,revoked_at) VALUES($1,$2,$3,$4,$5,NULL)")
        .bind(security::sha256(&access)).bind(&client).bind(&user).bind(&scope).bind(security::now()+3600)
        .execute(&state.db).await?;
    on_client_login(&state,&user,&client).await?;
    audit(&state,"app.login",Some(&user),&client).await?;
    let mut response = json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"scope":scope});
    if scope.split_whitespace().any(|s| s == "openid") {
        response["id_token"] = json!(security::id_token(&state.signing,&state.config.public_url,&client,&user,nonce.as_deref(),claims));
    }
    Ok(Json(response))
}

async fn access_identity(state: &AppState, headers: &HeaderMap) -> ApiResult<(String,String,String)> {
    let bearer = security::bearer(headers).ok_or(ApiError::unauthorized())?;
    let row = sqlx::query("SELECT user_id,client_id,scope FROM access_tokens WHERE token_hash=$1 AND expires_at>$2 AND revoked_at IS NULL")
        .bind(security::sha256(bearer)).bind(security::now()).fetch_optional(&state.db).await?
        .ok_or(ApiError::unauthorized())?;
    let user: String = row.get("user_id");
    let client: String = row.get("client_id");
    if !allowed(state,&user,&client).await? { return Err(ApiError::forbidden()); }
    Ok((user,client,row.get("scope")))
}
async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let (user,client,scope) = access_identity(&state,&headers).await?;
    if !scope.split_whitespace().any(|s|s == "openid") { return Err(ApiError::forbidden()); }
    Ok(Json(claims_for(&state,&user,&client,&scope).await?))
}

#[derive(Deserialize)]
struct TokenInput { token: String, client_id: Option<String>, client_secret: Option<String> }
async fn introspect(State(state): State<Arc<AppState>>, headers: HeaderMap, Form(input): Form<TokenInput>) -> ApiResult<Json<Value>> {
    let requesting_client = client_auth(&state,&headers,input.client_id.as_deref(),input.client_secret.as_deref()).await?;
    let row = sqlx::query("SELECT client_id,user_id,scope,expires_at FROM access_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>$2")
        .bind(security::sha256(&input.token)).bind(security::now()).fetch_optional(&state.db).await?;
    if let Some(row) = row {
        let owner: String = row.get("client_id");
        let user: String = row.get("user_id");
        if owner == requesting_client && allowed(&state,&user,&owner).await? {
            return Ok(Json(json!({"active":true,"client_id":owner,"sub":user,"scope":row.get::<String,_>("scope"),
                "exp":row.get::<i64,_>("expires_at"),"iss":state.config.public_url,"token_type":"Bearer"})));
        }
    }
    Ok(Json(json!({"active":false})))
}
async fn revoke(State(state): State<Arc<AppState>>, headers: HeaderMap, Form(input): Form<TokenInput>) -> ApiResult<StatusCode> {
    let client = client_auth(&state,&headers,input.client_id.as_deref(),input.client_secret.as_deref()).await?;
    sqlx::query("UPDATE access_tokens SET revoked_at=$1 WHERE token_hash=$2 AND client_id=$3")
        .bind(security::now()).bind(security::sha256(&input.token)).bind(client).execute(&state.db).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct StartQuery { return_to: Option<String>, link: Option<bool> }
fn safe_return(s: &str) -> bool {
    s == "/account" || (s.starts_with("/oauth/authorize?") && s.len() < 4096 && !s.contains('\n') && !s.contains('\r'))
}
async fn start_upstream(State(state): State<Arc<AppState>>, Path(provider_id): Path<String>, headers: HeaderMap, Query(q): Query<StartQuery>) -> ApiResult<Response> {
    let provider = provider(&state,&provider_id)?;
    let link_user = if q.link.unwrap_or(false) { Some(authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?) } else { None };
    let return_to = q.return_to.unwrap_or_else(||"/account".into());
    if !safe_return(&return_to) { return Err(ApiError::bad("invalid_return_path")); }
    let state_token = security::random();
    let verifier = security::random();
    let nonce = security::random();
    sqlx::query("INSERT INTO login_attempts(state_hash,provider,verifier,nonce,return_to,link_user_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(security::sha256(&state_token)).bind(&provider_id).bind(&verifier).bind(&nonce)
        .bind(&return_to).bind(link_user).bind(security::now()+600).execute(&state.db).await?;
    let callback_url = absolute(&state,&format!("/auth/{provider_id}/callback"));
    let mut destination = Url::parse(&provider.authorization_url).map_err(|_| ApiError::internal())?;
    destination.query_pairs_mut()
        .append_pair("client_id",&provider.client_id).append_pair("response_type","code")
        .append_pair("redirect_uri",&callback_url).append_pair("scope",&provider.scopes)
        .append_pair("state",&state_token).append_pair("code_challenge",&security::pkce(&verifier))
        .append_pair("code_challenge_method","S256");
    if matches!(provider.kind, crate::config::ProviderKind::Oidc) { destination.query_pairs_mut().append_pair("nonce",&nonce); }
    let mut response = Redirect::to(destination.as_str()).into_response();
    let flow_cookie = format!("sso_flow={state_token}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=600{}", if secure(&state) { "; Secure" } else { "" });
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&flow_cookie).map_err(|_|ApiError::internal())?);
    Ok(response)
}

#[derive(Deserialize)]
struct CallbackQuery { code: Option<String>, state: Option<String>, error: Option<String> }
async fn callback(State(state): State<Arc<AppState>>, Path(provider_id): Path<String>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> ApiResult<Response> {
    if q.error.is_some() { return Err(ApiError::bad("upstream_authorization_rejected")); }
    let provided_state = q.state.as_deref().ok_or(ApiError::bad("missing_state"))?;
    let flow_cookie = headers.get(header::COOKIE).and_then(|v|v.to_str().ok())
        .and_then(|v|v.split(';').find_map(|s|s.trim().strip_prefix("sso_flow=")))
        .ok_or(ApiError::bad("missing_browser_flow"))?;
    if !security::secret_eq(flow_cookie,provided_state) { return Err(ApiError::bad("browser_flow_mismatch")); }
    let code = q.code.as_deref().ok_or(ApiError::bad("missing_code"))?;
    let attempt = sqlx::query("DELETE FROM login_attempts WHERE state_hash=$1 AND provider=$2 AND expires_at>$3 RETURNING verifier,nonce,return_to,link_user_id")
        .bind(security::sha256(provided_state)).bind(&provider_id).bind(security::now())
        .fetch_optional(&state.db).await?.ok_or(ApiError::bad("invalid_or_expired_state"))?;
    let verifier: String = attempt.get("verifier");
    let nonce: String = attempt.get("nonce");
    let return_to: String = attempt.get("return_to");
    let link_user: Option<String> = attempt.try_get("link_user_id").unwrap_or(None);
    if let Some(link_id) = &link_user {
        if authorized_user(&headers,&state).await?.as_deref() != Some(link_id) { return Err(ApiError::unauthorized()); }
    }
    let p = provider(&state,&provider_id)?;
    let profile = upstream::exchange_profile(&state.http,p,code,&verifier,&nonce,
        &absolute(&state,&format!("/auth/{provider_id}/callback"))).await?;
    let subject = profile.get("sub").and_then(Value::as_str).ok_or(ApiError::bad("no_subject"))?;
    let existing = sqlx::query("SELECT user_id FROM identities WHERE provider=$1 AND subject=$2")
        .bind(&provider_id).bind(subject).fetch_optional(&state.db).await?;
    let existing_user = existing.map(|r|r.get::<String,_>("user_id"));
    if link_user.is_some() && existing_user.is_some() && link_user != existing_user { return Err(ApiError::bad("identity_already_bound_to_another_user")); }
    let user_id = link_user.or(existing_user.clone()).unwrap_or_else(security::random);
    let name = profile.get("name").and_then(Value::as_str)
        .or_else(||profile.get("preferred_username").and_then(Value::as_str)).unwrap_or("User");
    let email = if profile.get("email_verified").and_then(Value::as_bool) == Some(true) {
        profile.get("email").and_then(Value::as_str)
    } else { None };
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO users(id,name,email,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING")
        .bind(&user_id).bind(name).bind(email).bind(security::now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO identities(id,user_id,provider,subject,claims_json,created_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(provider,subject) DO UPDATE SET claims_json=excluded.claims_json")
        .bind(security::random()).bind(&user_id).bind(&provider_id).bind(subject).bind(profile.to_string())
        .bind(security::now()).execute(&mut *tx).await?;
    // Re-read ownership after the upsert; never auto-merge two accounts by email.
    let owner = sqlx::query("SELECT user_id FROM identities WHERE provider=$1 AND subject=$2")
        .bind(&provider_id).bind(subject).fetch_one(&mut *tx).await?.get::<String,_>("user_id");
    if owner != user_id { return Err(ApiError::bad("identity_ownership_conflict")); }
    let session = security::random();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES($1,$2,$3,$4)")
        .bind(security::sha256(&session)).bind(&user_id).bind(security::now()).bind(security::now()+14*86400)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    audit(&state,if existing_user.is_some(){"account.login"}else{"account.created"},Some(&user_id),&provider_id).await?;
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&security::session_cookie(&session,secure(&state))).map_err(|_|ApiError::internal())?);
    response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&format!("sso_flow=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0{}",if secure(&state){"; Secure"}else{""})).map_err(|_|ApiError::internal())?);
    Ok(response)
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user_id = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    let row = sqlx::query("SELECT name,email,created_at FROM users WHERE id=$1").bind(&user_id)
        .fetch_optional(&state.db).await?.ok_or(ApiError::unauthorized())?;
    Ok(Json(json!({"id":user_id,"name":row.get::<String,_>("name"),
        "email":row.try_get::<Option<String>,_>("email").unwrap_or(None),"created_at":row.get::<i64,_>("created_at")})))
}
async fn identities(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    let rows = sqlx::query("SELECT id,provider,subject,created_at FROM identities WHERE user_id=$1 ORDER BY created_at DESC")
        .bind(user).fetch_all(&state.db).await?;
    Ok(Json(json!({"identities": rows.iter().map(|r|json!({"id":r.get::<String,_>("id"),
        "provider":r.get::<String,_>("provider"),"subject":r.get::<String,_>("subject"),
        "created_at":r.get::<i64,_>("created_at")})).collect::<Vec<_>>()})))
}
async fn unlink(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(identity): Path<String>) -> ApiResult<StatusCode> {
    same_origin(&headers,&state)?;
    let user = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    let mut tx = state.db.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE user_id=$1")
        .bind(&user).fetch_one(&mut *tx).await?;
    if count <= 1 { return Err(ApiError::bad("cannot_unlink_last_login_method")); }
    let result = sqlx::query("DELETE FROM identities WHERE id=$1 AND user_id=$2")
        .bind(&identity).bind(&user).execute(&mut *tx).await?;
    if result.rows_affected() == 0 { return Err(ApiError::not_found()); }
    tx.commit().await?;
    audit(&state,"account.unlink",Some(&user),&identity).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    same_origin(&headers,&state)?;
    if let Some(token) = security::cookie(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash=$1").bind(security::sha256(token)).execute(&state.db).await?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&security::clear_cookie(secure(&state))).map_err(|_| ApiError::internal())?);
    Ok(response)
}

fn same_origin(headers: &HeaderMap, state: &AppState) -> ApiResult<()> {
    if let Some(origin) = headers.get(header::ORIGIN) {
        if origin.to_str().ok() != Some(state.config.public_url.as_str()) { return Err(ApiError::forbidden()); }
    }
    Ok(())
}

async fn my_apps(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    let rows = sqlx::query("SELECT DISTINCT c.id,c.name FROM oauth_clients c JOIN access_tokens t ON c.id=t.client_id WHERE t.user_id=$1 ORDER BY c.name LIMIT 300")
        .bind(&user).fetch_all(&state.db).await?;
    let mut result = Vec::new();
    for row in rows {
        let client: String = row.get("id");
        let access = allowed(&state,&user,&client).await?;
        result.push(json!({"id":client,"name":row.get::<String,_>("name"),"allowed":access}));
    }
    Ok(Json(json!({"apps":result})))
}
async fn my_revoke_app(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(client): Path<String>) -> ApiResult<StatusCode> {
    same_origin(&headers,&state)?;
    let user = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    sqlx::query("UPDATE access_tokens SET revoked_at=$1 WHERE user_id=$2 AND client_id=$3 AND revoked_at IS NULL")
        .bind(security::now()).bind(&user).bind(&client).execute(&state.db).await?;
    audit(&state,"account.revoke_app",Some(&user),&client).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
struct UserBlockInput { blocked: bool }
async fn my_block_app(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(client): Path<String>, Json(input): Json<UserBlockInput>) -> ApiResult<StatusCode> {
    same_origin(&headers,&state)?;
    let user = authorized_user(&headers,&state).await?.ok_or(ApiError::unauthorized())?;
    get_client(&state,&client).await?;
    sqlx::query("INSERT INTO app_user_blocks(user_id,client_id,blocked) VALUES($1,$2,$3) ON CONFLICT(user_id,client_id) DO UPDATE SET blocked=excluded.blocked")
        .bind(&user).bind(&client).bind(if input.blocked{1i64}else{0i64}).execute(&state.db).await?;
    if input.blocked {
        sqlx::query("UPDATE access_tokens SET revoked_at=$1 WHERE user_id=$2 AND client_id=$3 AND revoked_at IS NULL")
            .bind(security::now()).bind(&user).bind(&client).execute(&state.db).await?;
    }
    audit(&state,"account.block_app",Some(&user),&format!("{}={}",client,input.blocked)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_clients(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    let rows = sqlx::query("SELECT id,name,auth_method,redirects_json,created_at FROM oauth_clients ORDER BY created_at DESC LIMIT 500")
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"clients":rows.iter().map(|r|json!({
        "id":r.get::<String,_>("id"),"name":r.get::<String,_>("name"),
        "auth_method":r.get::<String,_>("auth_method"),
        "redirect_uris":serde_json::from_str::<Value>(&r.get::<String,_>("redirects_json")).unwrap_or(json!([])),
        "created_at":r.get::<i64,_>("created_at")
    })).collect::<Vec<_>>()})))
}
async fn admin_rules(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    let rows = sqlx::query("SELECT id,trigger_client,target_client,action,duration_seconds FROM link_rules ORDER BY created_at DESC")
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"rules":rows.iter().map(|r|json!({
        "id":r.get::<String,_>("id"),"trigger_client":r.get::<String,_>("trigger_client"),
        "target_client":r.get::<String,_>("target_client"),"action":r.get::<String,_>("action"),
        "duration_seconds":r.try_get::<Option<i64>,_>("duration_seconds").unwrap_or(None)
    })).collect::<Vec<_>>()})))
}
#[derive(Deserialize)]
struct LinkRuleInput { trigger_client: String, target_client: String, action: String, duration_seconds: Option<i64> }
async fn admin_add_rule(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(rule): Json<LinkRuleInput>) -> ApiResult<(StatusCode, Json<Value>)> {
    admin(&headers,&state)?;
    if rule.trigger_client == rule.target_client || !matches!(rule.action.as_str(), "revoke" | "suspend" | "restore_for") ||
        rule.duration_seconds.is_some_and(|v| v < 1 || v > 31_536_000) || (rule.action == "restore_for" && rule.duration_seconds.is_none()) {
        return Err(ApiError::bad("invalid_link_rule"));
    }
    get_client(&state,&rule.trigger_client).await?;
    get_client(&state,&rule.target_client).await?;
    let id = security::random();
    sqlx::query("INSERT INTO link_rules(id,trigger_client,target_client,action,duration_seconds,created_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(&id).bind(&rule.trigger_client).bind(&rule.target_client).bind(&rule.action)
        .bind(rule.duration_seconds).bind(security::now()).execute(&state.db).await?;
    audit(&state,"admin.link_rule",None,&format!("{} -> {} ({})",rule.trigger_client,rule.target_client,rule.action)).await?;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
async fn admin_delete_rule(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult<StatusCode> {
    admin(&headers,&state)?;
    let result = sqlx::query("DELETE FROM link_rules WHERE id=$1").bind(&id).execute(&state.db).await?;
    if result.rows_affected()==0 { return Err(ApiError::not_found()); }
    audit(&state,"admin.delete_rule",None,&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AccessPolicyInput { user_id: String, client_id: String, enabled: bool }
async fn admin_policy(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(policy): Json<AccessPolicyInput>) -> ApiResult<StatusCode> {
    admin(&headers,&state)?;
    get_client(&state,&policy.client_id).await?;
    let user = sqlx::query("SELECT id FROM users WHERE id=$1").bind(&policy.user_id).fetch_optional(&state.db).await?;
    if user.is_none() { return Err(ApiError::not_found()); }
    sqlx::query("INSERT INTO app_base_access(user_id,client_id,enabled) VALUES($1,$2,$3) ON CONFLICT(user_id,client_id) DO UPDATE SET enabled=excluded.enabled")
        .bind(&policy.user_id).bind(&policy.client_id).bind(if policy.enabled {1i64} else {0i64})
        .execute(&state.db).await?;
    // Existing signed ID tokens remain valid until expiry at relying parties that never introspect.
    if !policy.enabled {
        sqlx::query("UPDATE access_tokens SET revoked_at=$1 WHERE user_id=$2 AND client_id=$3 AND revoked_at IS NULL")
            .bind(security::now()).bind(&policy.user_id).bind(&policy.client_id).execute(&state.db).await?;
    }
    audit(&state,"admin.policy",Some(&policy.user_id),&format!("{}={}",policy.client_id,policy.enabled)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct MappingInput { provider: String, client_id: String, rules: Vec<FieldRule>, script: String }
async fn admin_mappings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    let rows = sqlx::query("SELECT id,provider,client_id,rules_json,script FROM field_mappings ORDER BY created_at DESC")
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"mappings":rows.iter().map(|r|json!({
        "id":r.get::<String,_>("id"),"provider":r.get::<String,_>("provider"),
        "client_id":r.get::<String,_>("client_id"),
        "rules":serde_json::from_str::<Value>(&r.get::<String,_>("rules_json")).unwrap_or(json!([])),
        "script":r.get::<String,_>("script")
    })).collect::<Vec<_>>()})))
}
async fn admin_save_mapping(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<MappingInput>) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    provider(&state,&input.provider)?;
    get_client(&state,&input.client_id).await?;
    // Prevalidate rules and JavaScript against a fixed example before accepting them.
    fields::transform(&json!({"sub":"demo","name":"Example","email":"example@example.org"}),&input.rules,&input.script)
        .map_err(|_| ApiError::bad("invalid_field_mapping"))?;
    let id=security::random();
    sqlx::query("INSERT INTO field_mappings(id,provider,client_id,rules_json,script,created_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(provider,client_id) DO UPDATE SET rules_json=excluded.rules_json,script=excluded.script")
        .bind(&id).bind(&input.provider).bind(&input.client_id)
        .bind(serde_json::to_string(&input.rules).map_err(|_|ApiError::internal())?)
        .bind(&input.script).bind(security::now()).execute(&state.db).await?;
    audit(&state,"admin.field_mapping",None,&format!("{} -> {}",input.provider,input.client_id)).await?;
    Ok(Json(json!({"saved":true})))
}
#[derive(Deserialize)]
struct PreviewInput { source: Value, rules: Vec<FieldRule>, script: String }
async fn admin_mapping_preview(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<PreviewInput>) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    let result=tokio::task::spawn_blocking(move ||fields::transform(&input.source,&input.rules,&input.script))
        .await.map_err(|_|ApiError::internal())?.map_err(|_|ApiError::bad("mapping_preview_failed"))?;
    Ok(Json(json!({"output":result})))
}

async fn upload_background(State(state): State<Arc<AppState>>, headers: HeaderMap, mut multipart: Multipart) -> ApiResult<Json<Value>> {
    admin(&headers,&state)?;
    let field = multipart.next_field().await.map_err(|_|ApiError::bad("invalid_multipart"))?
        .ok_or(ApiError::bad("missing_image"))?;
    let data = field.bytes().await.map_err(|_|ApiError::bad("invalid_image"))?;
    if data.len() > 5*1024*1024 || data.len() < 16 { return Err(ApiError::bad("image_size_invalid")); }
    let mime = if data.starts_with(&[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]) { "image/png" }
        else if data.starts_with(&[0xff,0xd8,0xff]) { "image/jpeg" }
        else if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") { "image/webp" }
        else { return Err(ApiError::bad("unsupported_image_format")); };
    // Stored outside the source tree; never use an untrusted filename.
    tokio::fs::write(state.config.data_dir.join("branding-background"),&data).await.map_err(|_|ApiError::internal())?;
    sqlx::query("INSERT INTO settings(key,value) VALUES('background_mime',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(mime).execute(&state.db).await?;
    audit(&state,"admin.background",None,mime).await?;
    Ok(Json(json!({"url":"/branding/background","mime":mime})))
}
async fn background(State(state): State<Arc<AppState>>) -> ApiResult<Response> {
    let mime = sqlx::query("SELECT value FROM settings WHERE key='background_mime'")
        .fetch_optional(&state.db).await?.map(|r|r.get::<String,_>("value")).ok_or(ApiError::not_found())?;
    let bytes = tokio::fs::read(state.config.data_dir.join("branding-background")).await.map_err(|_|ApiError::not_found())?;
    Ok(([(header::CONTENT_TYPE,mime),(header::CACHE_CONTROL,"no-store".into())],Bytes::from(bytes)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn redirect_checks() {
        assert!(checked_redirect("https://example.org/callback"));
        assert!(checked_redirect("http://127.0.0.1:12345/cb"));
        assert!(!checked_redirect("http://example.org/cb"));
        assert!(!checked_redirect("javascript:alert(1)"));
        assert!(!checked_redirect("https://example.org/cb#fragment"));
    }
    #[test] fn only_internal_return_paths() {
        assert!(safe_return("/account"));
        assert!(safe_return("/oauth/authorize?client_id=test"));
        assert!(!safe_return("//attacker.example"));
        assert!(!safe_return("https://attacker.example"));
    }
}
