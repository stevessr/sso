use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf};
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Oidc,
    Oauth2,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub kind: ProviderKind,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: String,
    #[serde(default)]
    pub client_secret_basic: bool,
    #[serde(default)]
    pub profile_path: Option<String>,
}

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub database_url: String,
    pub data_dir: PathBuf,
    pub signing_seed: [u8; 32],
    pub admin_token: String,
    pub registration_token: String,
    pub providers: Vec<Provider>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        let public_url = env::var("SSO_PUBLIC_URL").context("SSO_PUBLIC_URL is required")?;
        let url = Url::parse(&public_url)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            bail!("SSO_PUBLIC_URL must be an origin, without path/query/fragment");
        }
        if url.scheme() != "https" && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1")) {
            bail!("public HTTP issuer is allowed only for loopback development");
        }
        let public_url = public_url.trim_end_matches('/').to_owned();
        let seed = hex::decode(env::var("SSO_SIGNING_KEY_HEX").context("SSO_SIGNING_KEY_HEX is required")?)?;
        let signing_seed: [u8; 32] = seed.try_into().map_err(|_| anyhow::anyhow!("SSO_SIGNING_KEY_HEX must be exactly 32 bytes"))?;
        let admin_token = env::var("SSO_ADMIN_TOKEN").context("SSO_ADMIN_TOKEN is required")?;
        let registration_token = env::var("SSO_REGISTRATION_TOKEN").context("SSO_REGISTRATION_TOKEN is required")?;
        if admin_token.len() < 32 || registration_token.len() < 32 || admin_token == registration_token {
            bail!("admin and registration tokens must be distinct and at least 32 characters");
        }
        let mut providers = vec![];
        let mut add = |id: &str, label: &str, kind: ProviderKind, authorization: &str, token: &str, userinfo: Option<&str>, issuer: Option<&str>, jwks: Option<&str>, scopes: &str, basic: bool, profile_path: Option<&str>| {
            if let (Ok(client_id), Ok(client_secret)) = (env::var(format!("{}_CLIENT_ID", id.to_uppercase())), env::var(format!("{}_CLIENT_SECRET", id.to_uppercase()))) {
                if !client_id.is_empty() && !client_secret.is_empty() {
                    providers.push(Provider {
                        id: id.to_owned(), label: label.to_owned(), kind,
                        client_id, client_secret, authorization_url: authorization.to_owned(), token_url: token.to_owned(),
                        userinfo_url: userinfo.map(str::to_owned), issuer: issuer.map(str::to_owned), jwks_url: jwks.map(str::to_owned),
                        scopes: scopes.to_owned(), client_secret_basic: basic, profile_path: profile_path.map(str::to_owned),
                    });
                }
            }
        };
        add("google", "Google", ProviderKind::Oidc,
            "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
            Some("https://openidconnect.googleapis.com/v1/userinfo"), Some("https://accounts.google.com"),
            Some("https://www.googleapis.com/oauth2/v3/certs"), "openid profile email", false, None);
        add("telegram", "Telegram", ProviderKind::Oidc,
            "https://oauth.telegram.org/auth", "https://oauth.telegram.org/token", None,
            Some("https://oauth.telegram.org"), Some("https://oauth.telegram.org/.well-known/jwks.json"),
            "openid profile", true, None);
        add("x", "X", ProviderKind::Oauth2,
            "https://x.com/i/oauth2/authorize", "https://api.x.com/2/oauth2/token",
            Some("https://api.x.com/2/users/me?user.fields=profile_image_url,name,username"), None, None,
            "users.read tweet.read", true, Some("data"));
        let extra: Vec<Provider> = serde_json::from_str(&env::var("SSO_PROVIDERS_JSON").unwrap_or_else(|_| "[]".into()))?;
        providers.extend(extra);
        for p in &providers {
            if p.id.is_empty() || !p.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || p.client_id.is_empty() || p.client_secret.is_empty() {
                bail!("invalid provider identifier or credentials");
            }
            if providers.iter().filter(|candidate| candidate.id == p.id).count() != 1 { bail!("duplicate provider id {}", p.id); }
            for endpoint in [&p.authorization_url, &p.token_url].into_iter().chain(p.userinfo_url.iter()).chain(p.jwks_url.iter()) {
                if Url::parse(endpoint)?.scheme() != "https" { bail!("provider URLs must be HTTPS"); }
            }
            if matches!(p.kind, ProviderKind::Oidc) && (p.issuer.is_none() || p.jwks_url.is_none()) {
                bail!("OIDC provider {} needs issuer and JWKS", p.id);
            }
        }
        Ok(Self {
            bind: env::var("SSO_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()),
            public_url,
            database_url: env::var("SSO_DATABASE_URL").unwrap_or_else(|_| "sqlite://sso.db?mode=rwc".into()),
            data_dir: env::var("SSO_DATA_DIR").unwrap_or_else(|_| "./data".into()).into(),
            signing_seed, admin_token, registration_token, providers,
        })
    }
}
