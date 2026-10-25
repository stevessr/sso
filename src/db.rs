use anyhow::Result;
use sqlx::AnyPool;

pub async fn migrate(pool: &AnyPool) -> Result<()> {
    // SQL is deliberately limited to constructs shared by SQLite and PostgreSQL.
    let statements = [
        "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, subject TEXT NOT NULL, claims_json TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(provider, subject))",
        "CREATE INDEX IF NOT EXISTS idx_identities_user ON identities(user_id)",
        "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
        "CREATE TABLE IF NOT EXISTS login_attempts (state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL, verifier TEXT NOT NULL, nonce TEXT NOT NULL, return_to TEXT NOT NULL, link_user_id TEXT, expires_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT, auth_method TEXT NOT NULL, redirects_json TEXT NOT NULL, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS auth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, nonce TEXT, challenge TEXT NOT NULL, expires_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS access_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at BIGINT NOT NULL, revoked_at BIGINT)",
        "CREATE INDEX IF NOT EXISTS idx_token_client_user ON access_tokens(client_id, user_id)",
        "CREATE TABLE IF NOT EXISTS app_user_blocks (user_id TEXT NOT NULL, client_id TEXT NOT NULL, blocked BIGINT NOT NULL, PRIMARY KEY(user_id, client_id))",
        "CREATE TABLE IF NOT EXISTS app_base_access (user_id TEXT NOT NULL, client_id TEXT NOT NULL, enabled BIGINT NOT NULL, PRIMARY KEY(user_id, client_id))",
        "CREATE TABLE IF NOT EXISTS app_overrides (user_id TEXT NOT NULL, client_id TEXT NOT NULL, mode TEXT NOT NULL, expires_at BIGINT, PRIMARY KEY(user_id, client_id))",
        "CREATE TABLE IF NOT EXISTS link_rules (id TEXT PRIMARY KEY, trigger_client TEXT NOT NULL, target_client TEXT NOT NULL, action TEXT NOT NULL, duration_seconds BIGINT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS field_mappings (id TEXT PRIMARY KEY, provider TEXT NOT NULL, client_id TEXT NOT NULL, rules_json TEXT NOT NULL, script TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(provider, client_id))",
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor TEXT, detail TEXT NOT NULL, created_at BIGINT NOT NULL)",
    ];
    let mut tx = pool.begin().await?;
    for statement in statements { sqlx::query(statement).execute(&mut *tx).await?; }
    tx.commit().await?;
    Ok(())
}
