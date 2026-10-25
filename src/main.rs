mod config;
mod db;
mod error;
mod fields;
mod routes;
mod security;
mod upstream;

use anyhow::Result;
use axum::http::{header, HeaderValue};
use config::Config;
use ed25519_dalek::SigningKey;
use sqlx::{any::AnyPoolOptions, AnyPool};
use std::{sync::Arc, time::Duration};
use tower_http::{limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: AnyPool,
    pub http: reqwest::Client,
    pub signing: Arc<SigningKey>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "sso=info,tower_http=info".into())).init();
    let mut config = Config::from_env()?;
    tokio::fs::create_dir_all(&config.data_dir).await?;
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    let listening = listener.local_addr()?;
    if listening.port() != config.bind.rsplit(':').next().unwrap_or("").parse::<u16>().unwrap_or(u16::MAX) {
        // Port 0 is intended for local testing and OS-assigned port discovery.
        if !config.public_url.starts_with("http://127.0.0.1") && !config.public_url.starts_with("http://localhost") {
            anyhow::bail!("automatic port allocation requires a loopback issuer");
        }
        let hostname = if config.public_url.contains("localhost") { "localhost" } else { "127.0.0.1" };
        config.public_url = format!("http://{hostname}:{}", listening.port());
    }
    sqlx::any::install_default_drivers();
    let db = AnyPoolOptions::new().max_connections(8).connect(&config.database_url).await?;
    db::migrate(&db).await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let signing = SigningKey::from_bytes(&config.signing_seed);
    let state = Arc::new(AppState { config: Arc::new(config), db, http, signing: Arc::new(signing) });
    let app = routes::router(state.clone())
        .layer(RequestBodyLimitLayer::new(6 * 1024 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::if_not_present(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")))
        .layer(TraceLayer::new_for_http());
    tracing::info!(issuer=%state.config.public_url, listen=%listening, "SSO ready; OIDC discovery at /.well-known/openid-configuration");
    axum::serve(listener, app).await?;
    Ok(())
}
