use crate::{config::{Provider, ProviderKind}, AppError, AppResult, AppState};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{collections::HashMap, time::{Duration, Instant}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub provider: String,
    pub subject: String,
    pub name: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
}

pub async fn exchange(state: &AppState, provider: &Provider, code: &str, verifier: &str, nonce: &str) -> AppResult<Value> {
    let callback = format!("{}/auth/callback/{}", state.config.public_url, provider.id);
    let form = [
        ("grant_type", "authorization_code"), ("code", code),
        ("redirect_uri", callback.as_str()), ("client_id", provider.client_id.as_str()),
        ("code_verifier", verifier)
    ];
    let request = if provider.token_auth_basic {
        state.http.post(&provider.token_url)
            .basic_auth(&provider.client_id, Some(&provider.client_secret))
            .form(&form).header(reqwest::header::ACCEPT, "application/json")
    } else {
        let full_form = [
            ("grant_type", "authorization_code"), ("code", code),
            ("redirect_uri", callback.as_str()), ("client_id", provider.client_id.as_str()),
            ("code_verifier", verifier), ("client_secret", provider.client_secret.as_str()),
        ];
        state.http.post(&provider.token_url).form(&full_form).header(reqwest::header::ACCEPT, "application/json")
    };
    let response = request.send().await.map_err(|_| AppError::upstream())?;
    if !response.status().is_success() { return Err(AppError::upstream()); }
    let tokens: Value = response.json().await.map_err(|_| AppError::upstream())?;
    match provider.kind {
        ProviderKind::Oidc => {
            let jwt = tokens["id_token"].as_str().ok_or_else(AppError::upstream)?;
            verify_oidc(state, provider, jwt, nonce).await
        }
        ProviderKind::OAuthUserinfo => {
            let token = tokens["access_token"].as_str().ok_or_else(AppError::upstream)?;
            let endpoint = provider.userinfo_url.as_ref().ok_or_else(AppError::upstream)?;
            let resp = state.http.get(endpoint).bearer_auth(token).send().await.map_err(|_| AppError::upstream())?;
            if !resp.status().is_success() { return Err(AppError::upstream()); }
            let value: Value = resp.json().await.map_err(|_| AppError::upstream())?;
            Ok(if provider.id == "x" { value["data"].clone() } else { value })
        }
    }
}

async fn verify_oidc(state: &AppState, provider: &Provider, jwt: &str, nonce: &str) -> AppResult<Value> {
    let header = decode_header(jwt).map_err(|_| AppError::upstream())?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA) {
        return Err(AppError::upstream());
    }
    let jwks: JwkSet = state.http.get(provider.jwks_url.as_ref().ok_or_else(AppError::upstream)?)
        .send().await.map_err(|_| AppError::upstream())?
        .error_for_status().map_err(|_| AppError::upstream())?
        .json().await.map_err(|_| AppError::upstream())?;
    let jwk = header.kid.as_deref().and_then(|kid| jwks.find(kid)).ok_or_else(AppError::upstream)?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| AppError::upstream())?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[provider.client_id.as_str()]);
    validation.set_issuer(&[provider.issuer.as_deref().ok_or_else(AppError::upstream)?]);
    validation.validate_nbf = true;
    let claims = decode::<Value>(jwt, &decoding_key, &validation).map_err(|_| AppError::upstream())?.claims;
    if claims["nonce"].as_str() != Some(nonce) || claims["sub"].as_str().filter(|x| !x.is_empty()).is_none() {
        return Err(AppError::upstream());
    }
    Ok(claims)
}

fn field<'a>(obj: &'a Value, path: &str) -> Option<&'a Value> {
    if path.len() > 128 || path.is_empty() { return None; }
    path.split('.').try_fold(obj, |node, key| node.get(key))
}

// JavaScript runs only on the server: no filesystem, no network, restricted heap and CPU.
fn run_script(script: &str, input: &Value) -> AppResult<Value> {
    if script.len() > 8192 || input.to_string().len() > 65536 {
        return Err(AppError::bad("mapping size limit exceeded"));
    }
    let rt = rquickjs::Runtime::new().map_err(|_| AppError::bad("JS runtime unavailable"))?;
    rt.set_memory_limit(4 * 1024 * 1024);
    rt.set_max_stack_size(256 * 1024);
    let deadline = Instant::now() + Duration::from_millis(50);
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
    let ctx = rquickjs::Context::full(&rt).map_err(|_| AppError::bad("JS context unavailable"))?;
    ctx.with(|ctx| {
        let v = ctx.json_parse(input.to_string()).map_err(|_| AppError::bad("invalid mapping input"))?;
        ctx.globals().set("input", v).map_err(|_| AppError::bad("invalid JS global"))?;
        let source = format!("(function(input){{ {} }})(input)", script);
        let v: rquickjs::Value = ctx.eval(source).map_err(|_| AppError::bad("JS mapping failed or exceeded limit"))?;
        let serialized = ctx.json_stringify(v).map_err(|_| AppError::bad("mapping result invalid"))?
            .ok_or_else(|| AppError::bad("mapping must return JSON"))?
            .to_string().map_err(|_| AppError::bad("mapping result invalid"))?;
        serde_json::from_str(&serialized).map_err(|_| AppError::bad("mapping must return JSON"))
    })
}

pub async fn normalize(state: &AppState, provider: &Provider, raw: Value) -> AppResult<Profile> {
    let sub = raw["sub"].as_str().or_else(|| raw["id"].as_str())
        .map(str::to_owned)
        .or_else(|| raw["id"].as_u64().map(|n|n.to_string()))
        .ok_or_else(AppError::upstream)?;
    if sub.len() > 191 { return Err(AppError::upstream()); }
    let name = raw["name"].as_str().or_else(|| raw["first_name"].as_str())
        .or_else(|| raw["username"].as_str()).or_else(||raw["login"].as_str()).unwrap_or(&sub).to_owned();
    let email = raw["email"].as_str()
        .filter(|_|raw["email_verified"] == true || (provider.id=="discord" && raw["verified"]==true))
        .map(str::to_owned);
    let avatar = raw["picture"].as_str().or_else(|| raw["profile_image_url"].as_str()).or_else(||raw["avatar_url"].as_str()).map(str::to_owned);
    let verified_email = email.clone();
    let row = sqlx::query(&state.db.q("SELECT fields, script FROM mappings WHERE provider=?"))
        .bind(&provider.id).fetch_optional(&state.db.pool).await?;
    let mut out = json!({"name":name, "email":email, "avatar":avatar});
    if let Some(row) = row {
        let fields: HashMap<String, String> = serde_json::from_str(&row.try_get::<String,_>("fields")?)
            .map_err(|_| AppError::bad("invalid stored mapping"))?;
        for target in ["name", "email", "avatar"] {
            if let Some(path) = fields.get(target) {
                if let Some(value) = field(&raw, path) { out[target] = value.clone(); }
            }
        }
        let script: String = row.try_get("script")?;
        if !script.trim().is_empty() {
            let input = json!({"profile":out, "upstream":raw});
            let result = tokio::task::spawn_blocking(move || run_script(&script, &input))
                .await.map_err(|_| AppError::bad("mapping thread unavailable"))??;
            out = result;
        }
    }
    // Provider and cryptographically proven subject are NEVER overridable by mapping/JS.
    Ok(Profile {
        provider: provider.id.clone(), subject: sub,
        name: out["name"].as_str().unwrap_or("User").chars().take(150).collect(),
        email: out["email"].as_str().filter(|s| verified_email.as_deref() == Some(*s)).map(|s| s.chars().take(254).collect()),
        avatar: out["avatar"].as_str().filter(|s| s.starts_with("https://")).map(|s| s.chars().take(2048).collect())
    })
}

pub async fn preview(state: &AppState, provider_id: &str, raw: Value, fields: HashMap<String, String>, script: String) -> AppResult<Value> {
    let provider = state.config.provider(provider_id).ok_or_else(|| AppError::bad("unknown provider"))?;
    let mut out = json!({});
    for target in ["name", "email", "avatar"] {
        if let Some(path) = fields.get(target) { if let Some(v) = field(&raw, path) { out[target] = v.clone(); } }
    }
    if !script.trim().is_empty() {
        out = tokio::task::spawn_blocking(move || run_script(&script, &json!({"profile":out, "upstream":raw})))
            .await.map_err(|_| AppError::bad("mapping thread unavailable"))??;
    }
    Ok(json!({"provider":provider.id, "mapped_fields":out, "subject_mutable":false}))
}
