mod config;
mod crypto;
mod db;
mod provider;
mod auth;
mod management;
mod rate_limit;
mod refresh;
mod mfa;
mod passkey;
mod device;
mod sessions;
mod maintenance;

use axum::{
    extract::DefaultBodyLimit, http::{StatusCode, header, HeaderName, HeaderValue}, response::{IntoResponse, Response},
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

/// Liveness remains independent of storage; readiness probes the database so
/// orchestration does not route authentication requests to an unavailable node.
async fn readyz(axum::extract::State(state):axum::extract::State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db.pool).await {
        Ok(_) => (StatusCode::OK,Json(json!({"status":"ready"}))).into_response(),
        Err(error) => {
            tracing::warn!(%error,"SSO database is not ready");
            (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"status":"not_ready"}))).into_response()
        }
    }
}

async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer"));
    headers.insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    headers.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));
    headers.insert(HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'"));
    response
}


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
        http: reqwest::Client::builder().user_agent("SSO-Identity-Gateway/0.1").timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::none()).build()?,
    };
    tokio::spawn(maintenance::background(Arc::clone(&state.db)));
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/auth/providers", get(auth::providers))
        .route("/mfa", get(mfa::page))
        .route("/mfa/status", get(mfa::status))
        .route("/mfa/enroll/start", post(mfa::enroll_start))
        .route("/mfa/enroll/confirm", post(mfa::enroll_confirm))
        .route("/mfa/verify", post(mfa::verify))
        .route("/mfa/disable", post(mfa::disable))
        .route("/passkeys/register/start", post(passkey::register_start))
        .route("/passkeys/register/finish", post(passkey::register_finish))
        .route("/passkeys/login/start", post(passkey::login_start))
        .route("/passkeys/login/finish", post(passkey::login_finish))
        .route("/passkeys/stepup/start", post(passkey::stepup_start))
        .route("/passkeys/stepup/finish", post(passkey::stepup_finish))
        .route("/me/passkeys", get(passkey::list))
        .route("/me/passkeys/{id}", axum::routing::delete(passkey::remove))
        .route("/oauth/authorize", get(auth::authorize))
        .route("/consent", get(auth::consent_page))
        .route("/oauth/consent/request", get(auth::consent_details))
        .route("/oauth/consent/decision", post(auth::consent_decision))
        .route("/auth/callback/{provider}", get(auth::callback))
        .route("/login/{provider}", get(auth::login))
        .route("/oauth/token", post(auth::token))
        .route("/oauth/device_authorization", post(device::authorize))
        .route("/device", get(device::page))
        .route("/oauth/device/request", get(device::request))
        .route("/oauth/device/decision", post(device::decision))
        .route("/oauth/userinfo", get(auth::userinfo))
        .route("/oauth/revoke", post(auth::revoke))
        .route("/oauth/introspect", post(auth::introspect))
        .route("/.well-known/oauth-authorization-server", get(auth::metadata))
        .route("/me", get(auth::me))
        .route("/me/links", get(auth::links))
        .route("/me/sessions", get(sessions::list))
        .route("/me/sessions/others/revoke", post(sessions::revoke_others))
        .route("/me/sessions/{id}", axum::routing::delete(sessions::revoke))
        .route("/me/apps", get(auth::apps))
        .route("/me/clients", get(management::personal_list).post(management::personal_create))
        .route("/me/clients/{client}/disable", post(management::personal_disable))
        .route("/me/clients/{client}/enable", post(management::personal_enable))
        .route("/me/clients/{client}/rotate", post(management::personal_rotate))
        .route("/me/apps/{client}/revoke", post(auth::revoke_app))
        .route("/me/link/{provider}", post(auth::link))
        .route("/me/unlink/{provider}", post(auth::unlink))
        .route("/session/logout", post(auth::logout))
        .route("/connect/register", post(management::register))
        .route("/admin/clients", get(management::clients).post(management::create_client))
        .route("/admin/audit", get(sessions::audit))
        .route("/admin/clients/{client}/disable", post(management::disable_client))
        .route("/admin/clients/{client}/enable", post(management::enable_client))
        .route("/admin/clients/{client}/rotate", post(management::rotate_client_secret))
        .route("/admin/policies", get(management::policies).post(management::create_policy))
        .route("/admin/policies/{id}", axum::routing::delete(management::delete_policy))
        .route("/admin/mappings/{provider}", get(management::get_mapping).put(management::set_mapping))
        .route("/admin/mappings/{provider}/preview", post(management::mapping_preview))
        .route("/admin/background", post(management::background_upload).get(management::background))
        .route("/theme", get(management::theme))
        .route("/", get(management::index))
        .nest_service("/assets", ServeDir::new("web/assets"))
        .nest_service("/wasm", ServeDir::new("web/wasm"))
        .layer(DefaultBodyLimit::max(9 * 1024 * 1024))
        .layer(axum::middleware::from_fn(rate_limit::guard))
        .layer(axum::middleware::map_response(security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    tracing::info!(%bind_addr, "SSO gateway listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
