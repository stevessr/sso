use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};

#[derive(Clone)]
pub struct Config {
    pub public_url: String,
    pub bind: SocketAddr,
    pub auto_port: bool,
    pub db_url: String,
    pub admin_token_hash: String,
    pub registration_token_hash: Option<String>,
    pub providers: Vec<Provider>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind { Oidc, OAuthUserinfo }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub kind: ProviderKind,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    #[serde(default)] pub issuer: Option<String>,
    #[serde(default)] pub jwks_url: Option<String>,
    #[serde(default)] pub userinfo_url: Option<String>,
    pub scopes: String,
    #[serde(default)] pub token_auth_basic: bool,
}
impl Config {
    pub fn load() -> Result<Self, String> {
        let admin = env::var("SSO_ADMIN_TOKEN").map_err(|_| "SSO_ADMIN_TOKEN must be set")?;
        if admin.len() < 32 { return Err("SSO_ADMIN_TOKEN must contain at least 32 characters".into()); }
        let public_url = env::var("SSO_PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into());
        let parsed = url::Url::parse(&public_url).map_err(|e| e.to_string())?;
        if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") && parsed.host_str() != Some("127.0.0.1") {
            return Err("SSO_PUBLIC_URL must use HTTPS outside localhost".into());
        }
        if parsed.query().is_some() || parsed.fragment().is_some() || parsed.path() != "/" {
            return Err("SSO_PUBLIC_URL must be an origin without path/query/fragment".into());
        }
        let bind = env::var("SSO_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into()).parse().map_err(|e| format!("invalid SSO_BIND: {e}"))?;
        let mut providers = Vec::new();
        let mut add = |id: &str, label: &str, kind: ProviderKind, authorize_url: &str, token_url: &str,
                       issuer: Option<&str>, jwks_url: Option<&str>, userinfo_url: Option<&str>, scopes: &str, basic: bool| {
            let client_id = env::var(format!("{}_CLIENT_ID", id.to_uppercase())).unwrap_or_default();
            let client_secret = env::var(format!("{}_CLIENT_SECRET", id.to_uppercase())).unwrap_or_default();
            if !client_id.is_empty() && !client_secret.is_empty() {
                providers.push(Provider { id: id.into(), label: label.into(), kind, client_id, client_secret,
                    authorize_url: authorize_url.into(), token_url: token_url.into(),
                    issuer: issuer.map(str::to_owned), jwks_url: jwks_url.map(str::to_owned),
                    userinfo_url: userinfo_url.map(str::to_owned), scopes: scopes.into(), token_auth_basic: basic });
            }
        };
        add("google", "Google", ProviderKind::Oidc, "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token", Some("https://accounts.google.com"),
            Some("https://www.googleapis.com/oauth2/v3/certs"), None, "openid profile email", false);
        add("telegram", "Telegram", ProviderKind::Oidc, "https://oauth.telegram.org/auth",
            "https://oauth.telegram.org/token", Some("https://oauth.telegram.org"),
            Some("https://oauth.telegram.org/.well-known/jwks.json"), None, "openid profile", true);
        add("x", "X", ProviderKind::OAuthUserinfo, "https://twitter.com/i/oauth2/authorize",
            "https://api.x.com/2/oauth2/token", None, None,
            Some("https://api.x.com/2/users/me?user.fields=name,username,profile_image_url"),
            "users.read tweet.read", true);
        let custom: Vec<Provider> = serde_json::from_str(&env::var("SSO_PROVIDERS_JSON").unwrap_or_else(|_| "[]".into()))
            .map_err(|e| format!("invalid SSO_PROVIDERS_JSON: {e}"))?;
        for p in custom {
            if providers.iter().any(|e| e.id == p.id) { return Err(format!("duplicate provider {}", p.id)); }
            if p.id.is_empty() || !p.id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err("provider IDs must be lower-case slugs".into());
            }
            for ep in [&p.authorize_url, &p.token_url].into_iter().chain(p.jwks_url.iter()).chain(p.userinfo_url.iter()) {
                if url::Url::parse(ep).map_err(|e| e.to_string())?.scheme() != "https" {
                    return Err(format!("provider {} endpoints must use HTTPS", p.id));
                }
            }
            if matches!(p.kind, ProviderKind::Oidc) && (p.issuer.is_none() || p.jwks_url.is_none()) {
                return Err(format!("provider {} requires OIDC issuer and JWKS", p.id));
            }
            if matches!(p.kind, ProviderKind::OAuthUserinfo) && p.userinfo_url.is_none() {
                return Err(format!("provider {} requires userinfo URL", p.id));
            }
            providers.push(p);
        }
        let registration_token_hash = env::var("SSO_REGISTRATION_TOKEN").ok()
            .filter(|s| s.len() >= 32).map(|s| crate::crypto::digest(&s));
        Ok(Self { public_url: public_url.trim_end_matches('/').into(), bind,
            auto_port: env::var("SSO_AUTO_PORT").as_deref() == Ok("true"),
            db_url: env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://sso.db".into()),
            admin_token_hash: crate::crypto::digest(&admin), registration_token_hash, providers })
    }
    pub fn provider(&self, id: &str) -> Option<&Provider> { self.providers.iter().find(|p| p.id == id) }
}
