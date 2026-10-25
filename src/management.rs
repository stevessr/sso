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
fn admin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
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
async fn new_client(state: &AppState, input: ClientInput) -> AppResult<Value> {
    if input.client_name.trim().is_empty() || input.client_name.len() > 120 { return Err(AppError::bad("invalid client name")); }
    validate_redirects(&input.redirect_uris)?;
    let client_id=format!("sso_{}", uuid::Uuid::new_v4().simple());
    let secret=if input.public_client { None } else { Some(crypto::random_token()) };
    let secret_hash=secret.as_ref().map(|s|crypto::digest(s));
    sqlx::query(&state.db.q("INSERT INTO clients (id,name,secret_hash,redirects,created,enabled) VALUES (?,?,?,?,?,1)"))
        .bind(&client_id).bind(&input.client_name).bind(secret_hash)
        .bind(serde_json::to_string(&input.redirect_uris).map_err(|_| AppError::bad("invalid URIs"))?)
        .bind(crypto::now()).execute(&state.db.pool).await?;
    Ok(json!({"client_id":client_id,"client_secret":secret,"client_name":input.client_name,
        "redirect_uris":input.redirect_uris,"grant_types":["authorization_code"],
        "response_types":["code"],"token_endpoint_auth_method":if input.public_client{"none"}else{"client_secret_post"}}))
}
pub async fn register(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ClientInput>) -> AppResult<(StatusCode,Json<Value>)> {
    registration_allowed(&state,&headers)?;
    Ok((StatusCode::CREATED,Json(new_client(&state,input).await?)))
}
pub async fn create_client(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ClientInput>) -> AppResult<(StatusCode,Json<Value>)> {
    admin(&state,&headers)?;
    Ok((StatusCode::CREATED,Json(new_client(&state,input).await?)))
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
    sqlx::query(&state.db.q("INSERT INTO policies (id,source_client,target_client,action,duration_seconds) VALUES (?,?,?,?,?)"))
        .bind(&id).bind(&input.source_client).bind(&input.target_client).bind(&input.action)
        .bind(input.duration_seconds).execute(&state.db.pool).await?;
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
    let result=sqlx::query(&state.db.q("UPDATE mappings SET fields=?,script=? WHERE provider=?"))
        .bind(&fields).bind(&m.script).bind(&id).execute(&state.db.pool).await?;
    if result.rows_affected()==0 {
        sqlx::query(&state.db.q("INSERT INTO mappings (provider,fields,script) VALUES (?,?,?)"))
            .bind(&id).bind(&fields).bind(&m.script).execute(&state.db.pool).await?;
    }
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
    Ok(Json(json!({"ok":true,"seed":seed,"width":dims.0,"height":dims.1})))
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
