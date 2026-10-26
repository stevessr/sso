use crate::{AppError, AppResult, AppState, auth, crypto, provider};
use axum::{body::Bytes, extract::{Path, State}, http::{HeaderMap, header, StatusCode}, response::{Html, IntoResponse, Response}, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{collections::HashMap, io::Cursor};

pub async fn index() -> Html<&'static str> { Html(include_str!("../web/index.html")) }
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|s| s.strip_prefix("Bearer "))
}
pub(crate) fn admin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let provided=bearer(headers).ok_or_else(AppError::unauthorized)?;
    if crypto::secure_eq_hex(&crypto::digest(provided), &state.config.admin_token_hash) { Ok(()) }
    else { Err(AppError::unauthorized()) }
}
fn registration_allowed(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    if admin(state,headers).is_ok() { return Ok(()); }
    let expected=state.config.registration_token_hash.as_ref().ok_or_else(AppError::forbidden)?;
    let provided=bearer(headers).ok_or_else(AppError::unauthorized)?;
    if crypto::secure_eq_hex(&crypto::digest(provided),expected) { Ok(()) }
    else { Err(AppError::unauthorized()) }
}
fn validate_redirects(redirects: &[String]) -> AppResult<()> {
    if redirects.is_empty() || redirects.len() > 10 { return Err(AppError::bad("1-10 redirect URIs required")); }
    for raw in redirects {
        if raw.len() > 2048 || raw.contains('#') { return Err(AppError::bad("invalid redirect URI")); }
        let uri=url::Url::parse(raw).map_err(|_| AppError::bad("invalid redirect URI"))?;
        if uri.username() != "" || uri.password().is_some() || uri.fragment().is_some() {
            return Err(AppError::bad("redirect URI cannot contain credentials or fragment"));
        }
        let local=matches!(uri.host_str(),Some("localhost"|"127.0.0.1"|"::1"));
        if uri.scheme() != "https" && !(uri.scheme() == "http" && local) {
            return Err(AppError::bad("redirect URI must use HTTPS except localhost"));
        }
    }
    Ok(())
}
#[derive(Deserialize)]
pub struct ClientInput {
    client_name: String,
    redirect_uris: Vec<String>,
    #[serde(default)] public_client: bool,
}
async fn new_client(state: &AppState, input: ClientInput, owner: Option<&str>, actor:&str) -> AppResult<Value> {
    if input.client_name.trim().is_empty() || input.client_name.len() > 120 { return Err(AppError::bad("invalid client name")); }
    validate_redirects(&input.redirect_uris)?;
    let client_id=format!("sso_{}", uuid::Uuid::new_v4().simple());
    let secret=if input.public_client { None } else { Some(crypto::random_token()) };
    let secret_hash=secret.as_ref().map(|s|crypto::digest(s));
    let mut tx = state.db.pool.begin().await?;
    if let Some(user) = owner {
        let count = sqlx::query(&state.db.q("SELECT COUNT(*) AS n FROM client_owners WHERE user_id=?"))
            .bind(user).fetch_one(&mut *tx).await?.try_get::<i64,_>("n")?;
        if count >= 10 { return Err(AppError::bad("user client quota reached (10)")); }
    }
    sqlx::query(&state.db.q("INSERT INTO clients (id,name,secret_hash,redirects,created,enabled) VALUES (?,?,?,?,?,1)"))
        .bind(&client_id).bind(&input.client_name).bind(secret_hash)
        .bind(serde_json::to_string(&input.redirect_uris).map_err(|_| AppError::bad("invalid URIs"))?)
        .bind(crypto::now()).execute(&mut *tx).await?;
    if let Some(user) = owner {
        sqlx::query(&state.db.q("INSERT INTO client_owners (client_id,user_id) VALUES (?,?)"))
            .bind(&client_id).bind(user).execute(&mut *tx).await?;
    }
    crate::sessions::event_tx(state,&mut tx,actor,"client.create",
        json!({"client_id":&client_id,"public_client":input.public_client,
               "personal":owner.is_some()})).await?;
    tx.commit().await?;
    Ok(json!({"client_id":client_id,"client_secret":secret,"client_name":input.client_name,
        "redirect_uris":input.redirect_uris,"grant_types":["authorization_code"],
        "response_types":["code"],"token_endpoint_auth_method":if input.public_client{"none"}else{"client_secret_post"}}))
}
pub async fn register(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ClientInput>) -> AppResult<(StatusCode,Json<Value>)> {
    registration_allowed(&state,&headers)?;
    Ok((StatusCode::CREATED,Json(new_client(&state,input,None,"registration").await?)))
}
pub async fn create_client(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ClientInput>) -> AppResult<(StatusCode,Json<Value>)> {
    admin(&state,&headers)?;
    Ok((StatusCode::CREATED,Json(new_client(&state,input,None,"admin").await?)))
}
/// A signed-in user may register a bounded number of clients without sharing
/// the global machine registration token or receiving administrative privileges.
pub async fn personal_create(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ClientInput>)
    -> AppResult<(StatusCode,Json<Value>)>
{
    auth::require_same_origin(&state,&headers)?;
    let user = auth::session_user(&state,&headers).await?;
    Ok((StatusCode::CREATED,Json(new_client(&state,input,Some(&user),&user).await?)))
}

pub async fn personal_list(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session_user(&state,&headers).await?;
    let rows = sqlx::query(&state.db.q(
        "SELECT c.id,c.name,c.redirects,c.enabled,c.secret_hash FROM clients c JOIN client_owners o ON o.client_id=c.id WHERE o.user_id=? ORDER BY c.created DESC LIMIT 10"
    )).bind(user).fetch_all(&state.db.pool).await?;
    let result: Vec<Value> = rows.into_iter().filter_map(|row| Some(json!({
        "id":row.try_get::<String,_>("id").ok()?,
        "name":row.try_get::<String,_>("name").ok()?,
        "redirect_uris":serde_json::from_str::<Value>(&row.try_get::<String,_>("redirects").ok()?).ok()?,
        "enabled":row.try_get::<i64,_>("enabled").ok()? == 1,
        "public_client":row.try_get::<Option<String>,_>("secret_hash").ok()?.is_none()
    }))).collect();
    Ok(Json(json!(result)))
}

async fn personal_enabled(state: AppState, headers: HeaderMap, client: String, enabled: bool)
    -> AppResult<Json<Value>>
{
    auth::require_same_origin(&state,&headers)?;
    let user = auth::session_user(&state,&headers).await?;
    let mut tx = state.db.pool.begin().await?;
    let changed = sqlx::query(&state.db.q(
        "UPDATE clients SET enabled=? WHERE id=? AND EXISTS (SELECT 1 FROM client_owners WHERE client_id=? AND user_id=?)"
    )).bind(if enabled {1i64} else {0i64}).bind(&client).bind(&client).bind(&user)
        .execute(&mut *tx).await?;
    if changed.rows_affected() == 0 { return Err(AppError::forbidden()); }
    if !enabled {
        sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE client_id=?"))
            .bind(&client).execute(&mut *tx).await?;
        sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE client_id=?"))
            .bind(&client).execute(&mut *tx).await?;
    }
    crate::sessions::event_tx(&state,&mut tx,&user,
        if enabled {"client.enable"} else {"client.disable"},
        json!({"client_id":&client,"personal":true})).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":client,"enabled":enabled,"old_tokens_restored":false})))
}

pub async fn personal_disable(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>)
    -> AppResult<Json<Value>>
{ personal_enabled(state,headers,client,false).await }

pub async fn personal_enable(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>)
    -> AppResult<Json<Value>>
{ personal_enabled(state,headers,client,true).await }

pub async fn personal_rotate(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>)
    -> AppResult<Json<Value>>
{
    auth::require_same_origin(&state,&headers)?;
    let user = auth::session_user(&state,&headers).await?;
    let mut tx = state.db.pool.begin().await?;
    let row = sqlx::query(&state.db.q(
        "SELECT c.secret_hash FROM clients c JOIN client_owners o ON o.client_id=c.id WHERE c.id=? AND o.user_id=?"
    )).bind(&client).bind(&user).fetch_optional(&mut *tx).await?
        .ok_or_else(AppError::forbidden)?;
    if row.try_get::<Option<String>,_>("secret_hash")?.is_none() {
        return Err(AppError::bad("public PKCE clients do not have client secrets"));
    }
    let secret = crypto::random_token();
    sqlx::query(&state.db.q("UPDATE clients SET secret_hash=? WHERE id=?"))
        .bind(crypto::digest(&secret)).bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    crate::sessions::event_tx(&state,&mut tx,&user,"client.rotate_secret",
        json!({"client_id":&client,"personal":true})).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":client,"client_secret":secret,"existing_tokens_revoked":true})))
}

pub async fn clients(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    let rows=sqlx::query("SELECT id,name,redirects,enabled FROM clients").fetch_all(&state.db.pool).await?;
    let out: Vec<Value>=rows.into_iter().filter_map(|r| Some(json!({
        "id":r.try_get::<String,_>("id").ok()?,
        "name":r.try_get::<String,_>("name").ok()?,
        "redirect_uris":serde_json::from_str::<Value>(&r.try_get::<String,_>("redirects").ok()?).ok()?,
        "enabled":r.try_get::<i64,_>("enabled").ok()? == 1
    }))).collect();
    Ok(Json(json!(out)))
}

pub async fn disable_client(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>) -> AppResult<Json<Value>> {
    admin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    let changed = sqlx::query(&state.db.q("UPDATE clients SET enabled=0 WHERE id=?"))
        .bind(&client).execute(&mut *tx).await?;
    if changed.rows_affected() == 0 { return Err(AppError::bad("unknown client")); }
    // Disabling must invalidate existing grants, not just temporarily hide their validity.
    sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    crate::sessions::event_tx(&state,&mut tx,"admin","client.disable",
        json!({"client_id":&client,"personal":false})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":client,"enabled":false,"existing_tokens_revoked":true})))
}
pub async fn enable_client(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>) -> AppResult<Json<Value>> {
    admin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    let result = sqlx::query(&state.db.q("UPDATE clients SET enabled=1 WHERE id=?"))
        .bind(&client).execute(&mut *tx).await?;
    if result.rows_affected() == 0 { return Err(AppError::bad("unknown client")); }
    crate::sessions::event_tx(&state,&mut tx,"admin","client.enable",
        json!({"client_id":&client,"personal":false})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":client,"enabled":true,"old_tokens_restored":false})))
}
pub async fn rotate_client_secret(State(state): State<AppState>, headers: HeaderMap, Path(client): Path<String>) -> AppResult<Json<Value>> {
    admin(&state, &headers)?;
    let row = sqlx::query(&state.db.q("SELECT secret_hash FROM clients WHERE id=?"))
        .bind(&client).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::bad("unknown client"))?;
    let old: Option<String> = row.try_get("secret_hash")?;
    if old.is_none() { return Err(AppError::bad("public PKCE clients have no secret to rotate")); }
    let secret = crypto::random_token();
    let mut tx = state.db.pool.begin().await?;
    sqlx::query(&state.db.q("UPDATE clients SET secret_hash=? WHERE id=?"))
        .bind(crypto::digest(&secret)).bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    sqlx::query(&state.db.q("UPDATE refresh_tokens SET revoked=1 WHERE client_id=?"))
        .bind(&client).execute(&mut *tx).await?;
    crate::sessions::event_tx(&state,&mut tx,"admin","client.rotate_secret",
        json!({"client_id":&client,"personal":false})).await?;
    tx.commit().await?;
    // This plaintext is deliberately returned only once. Do not log the response.
    Ok(Json(json!({"client_id":client,"client_secret":secret,"existing_tokens_revoked":true})))
}

#[derive(Deserialize)]
pub struct PolicyInput {
    source_client: String, target_client: String, action: String,
    #[serde(default)] duration_seconds: i64,
}
pub async fn create_policy(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<PolicyInput>) -> AppResult<(StatusCode,Json<Value>)> {
    admin(&state,&headers)?;
    if input.source_client == input.target_client { return Err(AppError::bad("source and target must differ")); }
    if !["revoke","suspend","resume"].contains(&input.action.as_str()) { return Err(AppError::bad("invalid policy action")); }
    if input.action == "suspend" && !(1..=604800).contains(&input.duration_seconds) {
        return Err(AppError::bad("suspension must last 1 second to 7 days"));
    }
    for id in [&input.source_client,&input.target_client] {
        let exists=sqlx::query(&state.db.q("SELECT id FROM clients WHERE id=?"))
            .bind(id).fetch_optional(&state.db.pool).await?.is_some();
        if !exists { return Err(AppError::bad("policy client not found")); }
    }
    let id=uuid::Uuid::new_v4().to_string();
    let mut tx = state.db.pool.begin().await?;
    sqlx::query(&state.db.q("INSERT INTO policies (id,source_client,target_client,action,duration_seconds) VALUES (?,?,?,?,?)"))
        .bind(&id).bind(&input.source_client).bind(&input.target_client).bind(&input.action)
        .bind(input.duration_seconds).execute(&mut *tx).await?;
    crate::sessions::event_tx(&state,&mut tx,"admin","policy.create",
        json!({"policy_id":&id,"source_client":&input.source_client,
               "target_client":&input.target_client,"action":&input.action,
               "duration_seconds":input.duration_seconds})).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED,Json(json!({"id":id}))))
}
pub async fn policies(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    let rows=sqlx::query("SELECT id,source_client,target_client,action,duration_seconds FROM policies")
        .fetch_all(&state.db.pool).await?;
    let out: Vec<Value>=rows.into_iter().filter_map(|r|Some(json!({
        "id":r.try_get::<String,_>("id").ok()?,
        "source_client":r.try_get::<String,_>("source_client").ok()?,
        "target_client":r.try_get::<String,_>("target_client").ok()?,
        "action":r.try_get::<String,_>("action").ok()?,
        "duration_seconds":r.try_get::<i64,_>("duration_seconds").ok()?
    }))).collect();
    Ok(Json(json!(out)))
}

pub async fn delete_policy(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> AppResult<Json<Value>> {
    admin(&state, &headers)?;
    let mut tx = state.db.pool.begin().await?;
    let result = sqlx::query(&state.db.q("DELETE FROM policies WHERE id=?"))
        .bind(&id).execute(&mut *tx).await?;
    if result.rows_affected() > 0 {
        crate::sessions::event_tx(&state,&mut tx,"admin","policy.delete",
            json!({"policy_id":&id})).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"deleted":result.rows_affected() > 0})))
}

#[derive(Deserialize, Serialize)]
pub struct MappingInput { #[serde(default)] fields: HashMap<String,String>, #[serde(default)] script: String }
fn validate_mapping(m: &MappingInput) -> AppResult<()> {
    if m.script.len() > 8192 || m.fields.len() > 3 || m.fields.iter().any(|(k,v)|
        !["name","email","avatar"].contains(&k.as_str()) || v.is_empty() || v.len()>128) {
        return Err(AppError::bad("mapping outside permitted fields/size"));
    }
    Ok(())
}
pub async fn get_mapping(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    let row=sqlx::query(&state.db.q("SELECT fields,script FROM mappings WHERE provider=?"))
        .bind(&id).fetch_optional(&state.db.pool).await?;
    if let Some(row)=row {
        let fields: String=row.try_get("fields")?;
        let script: String=row.try_get("script")?;
        Ok(Json(json!({"provider":id,"fields":serde_json::from_str::<Value>(&fields).unwrap_or(json!({})),"script":script})))
    } else { Ok(Json(json!({"provider":id,"fields":{},"script":""}))) }
}
pub async fn set_mapping(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(m): Json<MappingInput>) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    if state.config.provider(&id).is_none() { return Err(AppError::bad("unknown provider")); }
    validate_mapping(&m)?;
    let fields=serde_json::to_string(&m.fields).map_err(|_|AppError::bad("invalid mapping"))?;
    let mut tx=state.db.pool.begin().await?;
    // MySQL returns zero affected rows for an unchanged UPDATE. Checking row
    // existence avoids a duplicate INSERT when a mapping is saved unchanged.
    let exists=sqlx::query(&state.db.q("SELECT provider FROM mappings WHERE provider=?"))
        .bind(&id).fetch_optional(&mut *tx).await?.is_some();
    if exists {
        sqlx::query(&state.db.q("UPDATE mappings SET fields=?,script=? WHERE provider=?"))
            .bind(&fields).bind(&m.script).bind(&id).execute(&mut *tx).await?;
    } else {
        sqlx::query(&state.db.q("INSERT INTO mappings (provider,fields,script) VALUES (?,?,?)"))
            .bind(&id).bind(&fields).bind(&m.script).execute(&mut *tx).await?;
    }
    crate::sessions::event_tx(&state,&mut tx,"admin","mapping.update",
        json!({"provider":&id,"field_count":m.fields.len(),"has_script":!m.script.is_empty()})).await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
pub struct MappingPreview { raw: Value, #[serde(flatten)] mapping: MappingInput }
pub async fn mapping_preview(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(data): Json<MappingPreview>) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    validate_mapping(&data.mapping)?;
    Ok(Json(provider::preview(&state,&id,data.raw,data.mapping.fields,data.mapping.script).await?))
}
pub async fn background_upload(State(state): State<AppState>, headers: HeaderMap, bytes: Bytes) -> AppResult<Json<Value>> {
    admin(&state,&headers)?;
    if bytes.len() > 8*1024*1024 { return Err(AppError::bad("image exceeds 8 MiB")); }
    let mime=if bytes.starts_with(b"\x89PNG\r\n\x1a\n") { "image/png" }
        else if bytes.starts_with(b"\xff\xd8\xff") { "image/jpeg" }
        else if bytes.starts_with(b"RIFF") && bytes.get(8..12)==Some(b"WEBP") { "image/webp" }
        else { return Err(AppError::bad("PNG, JPEG or WebP required")); };
    let dims=image::ImageReader::new(Cursor::new(&bytes)).with_guessed_format()
        .map_err(|_| AppError::bad("invalid image"))?
        .into_dimensions().map_err(|_| AppError::bad("invalid image dimensions"))?;
    if (dims.0 as u64)*(dims.1 as u64)>16_000_000 { return Err(AppError::bad("image exceeds 16 megapixels")); }
    let decoded=image::load_from_memory(&bytes).map_err(|_|AppError::bad("cannot decode image"))?;
    // Material Color Utilities: quantization + ranking + HCT tonal schemes.
    let material_theme = material_color_utils::theme_from_image(&decoded.thumbnail(160,160))
        .call().map_err(|_| AppError::bad("unable to extract Material theme from image"))?;
    let palette = serde_json::to_value(&material_theme)
        .map_err(|_| AppError::bad("unable to serialize Material theme"))?;
    let small=decoded.thumbnail(32,32).to_rgb8();
    let (mut r,mut g,mut b)=(0u64,0u64,0u64);
    for p in small.pixels() { r+=p[0] as u64;g+=p[1] as u64;b+=p[2] as u64; }
    let count=small.width() as u64*small.height() as u64;
    let seed=format!("#{:02x}{:02x}{:02x}",r/count,g/count,b/count);
    tokio::fs::create_dir_all("data").await.map_err(|_|AppError::bad("cannot create data directory"))?;
    tokio::fs::write("data/background.upload",&bytes).await.map_err(|_|AppError::bad("could not store image"))?;
    tokio::fs::rename("data/background.upload","data/background.bin").await.map_err(|_|AppError::bad("cannot publish image"))?;
    tokio::fs::write("data/background.mime",mime).await.map_err(|_|AppError::bad("cannot store image metadata"))?;
    tokio::fs::write("data/theme.seed",&seed).await.map_err(|_|AppError::bad("cannot store theme seed"))?;
    tokio::fs::write("data/theme.json",palette.to_string()).await.map_err(|_|AppError::bad("cannot store Monet palette"))?;
    crate::sessions::event(&state,"admin","theme.background_upload",
        json!({"mime":mime,"width":dims.0,"height":dims.1})).await?;
    Ok(Json(json!({"ok":true,"seed":seed,"palette":palette,"width":dims.0,"height":dims.1})))
}
pub async fn background() -> AppResult<Response> {
    let data=tokio::fs::read("data/background.bin").await.map_err(|_|AppError::bad("no background uploaded"))?;
    let mime=tokio::fs::read_to_string("data/background.mime").await.unwrap_or_else(|_|"image/png".into());
    let seed=tokio::fs::read_to_string("data/theme.seed").await.unwrap_or_else(|_|"#6750a4".into());
    let mut response=data.into_response();
    response.headers_mut().insert(header::CONTENT_TYPE,mime.parse().map_err(|_|AppError::bad("bad content type"))?);
    response.headers_mut().insert("x-theme-seed",seed.parse().map_err(|_|AppError::bad("bad seed"))?);
    Ok(response)
}

pub async fn theme() -> AppResult<Json<Value>> {
    let json=tokio::fs::read_to_string("data/theme.json").await
        .map_err(|_| AppError::bad("no Material theme uploaded"))?;
    let data=serde_json::from_str(&json).map_err(|_|AppError::bad("invalid Material theme"))?;
    Ok(Json(data))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::Arc};
    async fn fixture() -> (AppState, HeaderMap) {
        let db = Arc::new(crate::db::Db::open("sqlite::memory:").await.unwrap());
        let cfg = crate::config::Config {
            public_url:"http://localhost:3000".into(),
            bind:"127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
            auto_port:false,db_url:"sqlite::memory:".into(),
            admin_token_hash:crypto::digest("ci-local-admin-secret"),
            registration_token_hash:None,providers:vec![],
        };
        let mut headers=HeaderMap::new();
        headers.insert(header::AUTHORIZATION,"Bearer ci-local-admin-secret".parse().unwrap());
        (AppState{config:Arc::new(cfg),db,http:reqwest::Client::new()},headers)
    }
    #[tokio::test]
    async fn self_service_registration_is_private_and_enforces_quota() {
        let (s, _) = fixture().await;
        for (token,user) in [("owner-session","owner"), ("other-session","other")] {
            sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)")
                .bind(crypto::digest(token)).bind(user).bind(crypto::now()+300)
                .execute(&s.db.pool).await.unwrap();
        }
        let headers = |token: &str| {
            let mut h=HeaderMap::new();
            h.insert(header::ORIGIN,"http://localhost:3000".parse().unwrap());
            h.insert(header::COOKIE,format!("sso_session={token}").parse().unwrap());
            h
        };
        let input = || ClientInput {
            client_name:"My owned app".into(),
            redirect_uris:vec!["https://owned.example.test/cb".into()],
            public_client:false,
        };
        let (_,created)=personal_create(State(s.clone()),headers("owner-session"),Json(input())).await.unwrap();
        let id=created.0["client_id"].as_str().unwrap().to_owned();
        assert!(created.0["client_secret"].as_str().is_some());
        let owner_list=personal_list(State(s.clone()),headers("owner-session")).await.unwrap().0;
        let other_list=personal_list(State(s.clone()),headers("other-session")).await.unwrap().0;
        assert_eq!(owner_list.as_array().unwrap().len(),1);
        assert_eq!(other_list.as_array().unwrap().len(),0);
        assert!(personal_disable(State(s.clone()),headers("other-session"),Path(id.clone())).await.is_err());
        personal_disable(State(s.clone()),headers("owner-session"),Path(id.clone())).await.unwrap();
        let rotated=personal_rotate(State(s.clone()),headers("owner-session"),Path(id.clone())).await.unwrap();
        assert_ne!(rotated.0["client_secret"],created.0["client_secret"]);
        personal_enable(State(s.clone()),headers("owner-session"),Path(id.clone())).await.unwrap();
        for _ in 0..9 { new_client(&s,input(),Some("owner"),"owner").await.unwrap(); }
        assert!(personal_create(State(s),headers("owner-session"),Json(input())).await.is_err());
    }

    #[test]
    fn strict_redirect_validation() {
        assert!(validate_redirects(&["https://app.example.test/callback".into()]).is_ok());
        assert!(validate_redirects(&["http://127.0.0.1:8080/callback".into()]).is_ok());
        assert!(validate_redirects(&["http://app.example.test/callback".into()]).is_err());
        assert!(validate_redirects(&["https://alice@app.example.test/callback".into()]).is_err());
        assert!(validate_redirects(&["https://app.example.test/callback#fragment".into()]).is_err());
        assert!(validate_redirects(&[]).is_err());
    }
    #[tokio::test]
    async fn disabling_and_reenabling_never_revives_old_access_tokens() {
        let (s,admin_headers)=fixture().await;
        let c = new_client(&s,ClientInput{
            client_name:"CI confidential".into(),redirect_uris:vec!["https://client.example.test/cb".into()],
            public_client:false,
        },None,"admin").await.unwrap();
        let id=c["client_id"].as_str().unwrap().to_owned();
        sqlx::query(&s.db.q("INSERT INTO tokens (token_hash,client_id,user_id,scope,expires,revoked,suspended_until) VALUES (?,?,?,?,?,0,0)"))
            .bind(crypto::digest("first")).bind(&id).bind("user").bind("profile")
            .bind(crypto::now()+300).execute(&s.db.pool).await.unwrap();
        disable_client(State(s.clone()),admin_headers.clone(),Path(id.clone())).await.unwrap();
        enable_client(State(s.clone()),admin_headers.clone(),Path(id.clone())).await.unwrap();
        let row=sqlx::query(&s.db.q("SELECT revoked FROM tokens WHERE token_hash=?"))
            .bind(crypto::digest("first")).fetch_one(&s.db.pool).await.unwrap();
        assert_eq!(row.try_get::<i64,_>("revoked").unwrap(),1);
        let previous=c["client_secret"].as_str().unwrap();
        let rotated=rotate_client_secret(State(s.clone()),admin_headers.clone(),Path(id.clone())).await.unwrap();
        let replacement=rotated.0["client_secret"].as_str().unwrap();
        assert_ne!(replacement,previous);
        let row=sqlx::query(&s.db.q("SELECT secret_hash FROM clients WHERE id=?"))
            .bind(&id).fetch_one(&s.db.pool).await.unwrap();
        assert!(crypto::secure_eq_hex(&row.try_get::<String,_>("secret_hash").unwrap(),&crypto::digest(replacement)));
        assert!(rotate_client_secret(State(s),admin_headers,Path("unknown".into())).await.is_err());
    }
}
