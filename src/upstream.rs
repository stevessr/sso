use crate::{config::{Provider, ProviderKind}, error::ApiError, security};
use axum::http::StatusCode;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct UpstreamToken {
    access_token: String,
    id_token: Option<String>,
}

pub async fn exchange_profile(http: &Client, provider: &Provider, code: &str, verifier: &str, nonce: &str, callback_url: &str) -> Result<Value, ApiError> {
    let mut fields = vec![
        ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", callback_url),
        ("client_id", provider.client_id.as_str()), ("code_verifier", verifier),
    ];
    if !provider.client_secret_basic { fields.push(("client_secret", provider.client_secret.as_str())); }
    let request = http.post(&provider.token_url).form(&fields);
    let request = if provider.client_secret_basic { request.basic_auth(&provider.client_id, Some(&provider.client_secret)) } else { request };
    let response = request.send().await?.error_for_status()?;
    let tokens: UpstreamToken = response.json().await?;
    let mut claims = match provider.kind {
        ProviderKind::Oidc => {
            let raw = tokens.id_token.as_deref().ok_or(ApiError(StatusCode::BAD_GATEWAY, "missing_id_token"))?;
            verify_id_token(http, provider, raw, nonce).await?
        }
        ProviderKind::Oauth2 => {
            let url = provider.userinfo_url.as_ref().ok_or(ApiError(StatusCode::BAD_GATEWAY, "missing_userinfo_endpoint"))?;
            let response = http.get(url).bearer_auth(&tokens.access_token).send().await?.error_for_status()?;
            let result: Value = response.json().await?;
            if let Some(path) = provider.profile_path.as_deref() {
                let mut current = &result;
                for part in path.split('.') { current = current.get(part).ok_or(ApiError(StatusCode::BAD_GATEWAY, "missing_upstream_profile"))?; }
                current.clone()
            } else { result }
        }
    };
    let subject = claims.get("sub").or_else(|| claims.get("id"))
        .and_then(|v| v.as_str().map(str::to_owned).or_else(|| v.as_i64().map(|i| i.to_string())))
        .ok_or(ApiError(StatusCode::BAD_GATEWAY, "missing_subject"))?;
    if !claims.is_object() { return Err(ApiError(StatusCode::BAD_GATEWAY, "invalid_profile")); }
    claims["sub"] = json!(subject);
    if claims.get("name").is_none() {
        if let Some(name) = claims.get("username").or_else(|| claims.get("preferred_username")).cloned() { claims["name"] = name; }
    }
    if claims.get("preferred_username").is_none() {
        if let Some(name) = claims.get("username").cloned() { claims["preferred_username"] = name; }
    }
    if claims.get("picture").is_none() {
        if let Some(image) = claims.get("profile_image_url").cloned() { claims["picture"] = image; }
    }
    Ok(claims)
}

async fn verify_id_token(http: &Client, provider: &Provider, token: &str, nonce: &str) -> Result<Value, ApiError> {
    let header = decode_header(token).map_err(|_| ApiError::bad("bad_id_token"))?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA) {
        return Err(ApiError::bad("unsupported_id_token_algorithm"));
    }
    let url = provider.jwks_url.as_ref().ok_or(ApiError::internal())?;
    let keys: JwkSet = http.get(url).send().await?.error_for_status()?.json().await?;
    let jwk = match &header.kid {
        Some(kid) => keys.find(kid),
        None if keys.keys.len() == 1 => keys.keys.first(),
        _ => None,
    }.ok_or(ApiError::bad("unknown_signing_key"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| ApiError::bad("bad_signing_key"))?;
    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.set_audience(&[provider.client_id.as_str()]);
    validation.set_issuer(&[provider.issuer.as_deref().ok_or(ApiError::internal())?]);
    let result = decode::<Value>(token, &key, &validation).map_err(|_| ApiError::bad("id_token_validation_failed"))?;
    // The upstream nonce is only mandatory if supplied by that provider; reject an absent claim too.
    let received = result.claims.get("nonce").and_then(Value::as_str)
        .ok_or(ApiError::bad("missing_oidc_nonce"))?;
    if !security::secret_eq(received, nonce) { return Err(ApiError::bad("nonce_mismatch")); }
    Ok(result.claims)
}
