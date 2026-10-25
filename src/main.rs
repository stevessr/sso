mod config;
mod crypto;
mod db;
mod provider;
mod auth;
mod management;

use axum::{
    extract::DefaultBodyLimit, http::StatusCode, response::{IntoResponse, Response},
    routing::{get, post}, Json, Router
};
use serde_json::json;
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use tower_http::{services::ServeDir, trace::TraceLayer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub db: Arc<db::Db>,
    pub http: reqwest::Client,
}
#[derive(Debug)]
pub struct AppError { status: StatusCode, message: String }
pub type AppResult<T> = Result<T, AppError>;
impl AppError {
    pub fn bad(msg: &str) -> Self { Self { status: StatusCode::BAD_REQUEST, message: msg.into() } }
    pub fn unauthorized() -> Self { Self { status: StatusCode::UNAUTHORIZED, message: "unauthorized".into() } }
    pub fn forbidden() -> Self { Self { status: StatusCode::FORBIDDEN, message: "forbidden".into() } }
    pub fn upstream() -> Self { Self { status: StatusCode::BAD_GATEWAY, message: "upstream authentication failed".into() } }
}
impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database failure");
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: "database failure".into() }
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response { (self.status, Json(json!({"error":self.message}))).into_response() }
}
async fn healthz() -> Json<serde_json::Value> { Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")})) }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "sso=info,tower_http=info".into())).init();
    let mut config = config::Config::load().map_err(std::io::Error::other)?;
    let db = Arc::new(db::Db::open(&config.db_url).await?);
    let mut listener = tokio::net::TcpListener::bind(config.bind).await;
    if listener.is_err() && config.auto_port && config.bind.ip().is_loopback() {
        for port in config.bind.port().saturating_add(1)..=config.bind.port().saturating_add(20) {
            if let Ok(l) = tokio::net::TcpListener::bind(SocketAddr::new(config.bind.ip(), port)).await {
                let parsed = url::Url::parse(&config.public_url)?;
                if parsed.host_str() != Some("localhost") && parsed.host_str() != Some("127.0.0.1") {
                    return Err("auto-port requires a loopback public URL".into());
                }
                let mut changed = parsed;
                changed.set_port(Some(port)).map_err(|_| "could not update callback port")?;
                config.public_url = changed.as_str().trim_end_matches('/').to_owned();
                listener = Ok(l);
                break;
            }
        }
    }
    let listener = listener?;
    let bind_addr = listener.local_addr()?;
    let state = AppState {
        config: Arc::new(config),
        db,
        http: reqwest::Client::builder().timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::none()).build()?,
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/auth/providers", get(auth::providers))
        .route("/oauth/authorize", get(auth::authorize))
        .route("/auth/callback/{provider}", get(auth::callback))
        .route("/login/{provider}", get(auth::login))
        .route("/oauth/token", post(auth::token))
        .route("/oauth/userinfo", get(auth::userinfo))
        .route("/oauth/revoke", post(auth::revoke))
        .route("/.well-known/oauth-authorization-server", get(auth::metadata))
        .route("/me", get(auth::me))
        .route("/me/links", get(auth::links))
        .route("/me/link/{provider}", get(auth::link))
        .route("/me/unlink/{provider}", post(auth::unlink))
        .route("/session/logout", post(auth::logout))
        .route("/connect/register", post(management::register))
        .route("/admin/clients", get(management::clients).post(management::create_client))
        .route("/admin/policies", get(management::policies).post(management::create_policy))
        .route("/admin/mappings/{provider}", get(management::get_mapping).put(management::set_mapping))
        .route("/admin/mappings/{provider}/preview", post(management::mapping_preview))
        .route("/admin/background", post(management::background_upload).get(management::background))
        .route("/theme", get(management::theme))
        .route("/", get(management::index))
        .nest_service("/wasm", ServeDir::new("web/wasm"))
        .layer(DefaultBodyLimit::max(9 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    tracing::info!(%bind_addr, "SSO gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}
