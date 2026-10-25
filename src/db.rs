use sqlx::{any::AnyPoolOptions, AnyPool};
pub struct Db { pub pool: AnyPool, postgres: bool }
impl Db {
    pub async fn open(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        sqlx::any::install_default_drivers();
        if url.starts_with("sqlite://") {
            let path = url.trim_start_matches("sqlite://").split('?').next().unwrap_or("sso.db");
            if path != ":memory:" && !path.is_empty() {
                if let Some(parent) = std::path::Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()) { std::fs::create_dir_all(parent)?; }
                std::fs::OpenOptions::new().write(true).create(true).open(path)?;
            }
        }
        let pool = AnyPoolOptions::new().max_connections(if url.starts_with("sqlite:") { 1 } else { 10 }).connect(url).await?;
        let db = Self { pool, postgres: url.starts_with("postgres:") || url.starts_with("postgresql:") };
        db.migrate().await?;
        Ok(db)
    }
    // Query templates reserve '?' exclusively for SQL bind placeholders.
    pub fn q(&self, template: &str) -> String {
        if !self.postgres { return template.into(); }
        let mut n = 0;
        template.chars().map(|c| if c == '?' { n += 1; format!("${}", n) } else { c.to_string() }).collect()
    }

    /// Remember suspensions independently of individual tokens, so logging in again
    /// cannot bypass a temporary linked-application lockout.
    pub async fn set_app_suspension(&self, user: &str, client: &str, until: i64) -> Result<(), sqlx::Error> {
        let updated = sqlx::query(&self.q("UPDATE app_access SET suspended_until=? WHERE user_id=? AND client_id=?"))
            .bind(until).bind(user).bind(client).execute(&self.pool).await?;
        if updated.rows_affected() != 0 { return Ok(()); }
        let inserted = sqlx::query(&self.q("INSERT INTO app_access (user_id,client_id,suspended_until) VALUES (?,?,?)"))
            .bind(user).bind(client).bind(until).execute(&self.pool).await;
        if inserted.is_err() {
            // Another request may have won the unique-key race.
            sqlx::query(&self.q("UPDATE app_access SET suspended_until=? WHERE user_id=? AND client_id=?"))
                .bind(until).bind(user).bind(client).execute(&self.pool).await?;
        }
        Ok(())
    }
    async fn migrate(&self) -> Result<(), sqlx::Error> {
        let statements = [
            "CREATE TABLE IF NOT EXISTS users (id VARCHAR(191) PRIMARY KEY, name TEXT NOT NULL, email TEXT, avatar TEXT, created BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS identities (provider VARCHAR(191) NOT NULL, subject VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, PRIMARY KEY(provider,subject))",
            "CREATE TABLE IF NOT EXISTS clients (id VARCHAR(191) PRIMARY KEY, name TEXT NOT NULL, secret_hash VARCHAR(191), redirects TEXT NOT NULL, created BIGINT NOT NULL, enabled BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS auth_tx (state VARCHAR(191) PRIMARY KEY, data TEXT NOT NULL, expires BIGINT NOT NULL, used BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS codes (code_hash VARCHAR(191) PRIMARY KEY, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, scope TEXT NOT NULL, expires BIGINT NOT NULL, used BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS pending_consents (id VARCHAR(191) PRIMARY KEY, user_id VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, scope TEXT NOT NULL, downstream_state TEXT NOT NULL, expires BIGINT NOT NULL, used BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS tokens (token_hash VARCHAR(191) PRIMARY KEY, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, scope TEXT NOT NULL, expires BIGINT NOT NULL, revoked BIGINT NOT NULL, suspended_until BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS app_access (user_id VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, suspended_until BIGINT NOT NULL DEFAULT 0, PRIMARY KEY(user_id,client_id))",
            "CREATE TABLE IF NOT EXISTS refresh_tokens (token_hash VARCHAR(191) PRIMARY KEY, family_id VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, scope TEXT NOT NULL, expires BIGINT NOT NULL, used BIGINT NOT NULL DEFAULT 0, revoked BIGINT NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS refresh_access (token_hash VARCHAR(191) PRIMARY KEY, family_id VARCHAR(191) NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sessions (token_hash VARCHAR(191) PRIMARY KEY, user_id VARCHAR(191) NOT NULL, expires BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS policies (id VARCHAR(191) PRIMARY KEY, source_client VARCHAR(191) NOT NULL, target_client VARCHAR(191) NOT NULL, action VARCHAR(32) NOT NULL, duration_seconds BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS mappings (provider VARCHAR(191) PRIMARY KEY, fields TEXT NOT NULL, script TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS audit (id VARCHAR(191) PRIMARY KEY, event VARCHAR(191) NOT NULL, actor TEXT NOT NULL, metadata TEXT NOT NULL, created BIGINT NOT NULL)"
        ];
        for statement in statements { sqlx::query(statement).execute(&self.pool).await?; }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn sqlite_schema_is_ready() {
        let db = Db::open("sqlite::memory:").await.expect("create in-memory database");
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients").fetch_one(&db.pool).await.expect("clients table");
        assert_eq!(row.0, 0);
    }
    #[tokio::test]
    async fn postgresql_placeholders_numbered() {
        let db = Db { pool: AnyPool::connect_lazy("sqlite::memory:").unwrap(), postgres: true };
        assert_eq!(db.q("SELECT a FROM t WHERE a=? AND b=?"), "SELECT a FROM t WHERE a=$1 AND b=$2");
    }
}
