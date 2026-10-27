//! Bounded, idempotent cleanup of expired authentication artifacts.
//!
//! Expired refresh-token rows remain until their absolute expiry, including
//! consumed tokens: they are replay evidence and must not be deleted early.
//! Audit history is retained indefinitely unless the operator opts into a
//! retention window via SSO_AUDIT_RETENTION_DAYS.
use crate::{crypto, db::Db};
use std::{sync::Arc, time::Duration};
use tokio::time::{interval, MissedTickBehavior};

/// Runs as a single transaction so a partial database failure cannot leave
/// stale session metadata or partially pruned refresh-token family mappings.
pub async fn prune(db: &Db, now: i64, audit_retention_days: Option<i64>)
    -> Result<u64, sqlx::Error>
{
    let mut tx = db.pool.begin().await?;
    let mut removed = 0u64;
    // Identifiers are compile-time constants, not caller-controlled SQL.
    for table in [
        "auth_tx", "device_grants", "codes", "pending_consents",
        "passkey_challenges", "totp_pending", "mfa_redirects",
        "sessions", "tokens", "refresh_tokens",
    ] {
        let query = db.q(&format!("DELETE FROM {table} WHERE expires<=?"));
        removed += sqlx::query(&query).bind(now).execute(&mut *tx).await?.rows_affected();
    }
    // Clean data left after explicit session revocation, not only expiry.
    for table in ["session_devices", "session_assurance", "mfa_redirects"] {
        let query = format!(
            "DELETE FROM {table} WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash={table}.token_hash)"
        );
        removed += sqlx::query(&query).execute(&mut *tx).await?.rows_affected();
    }
    // Keep access-to-refresh-family links while any family member is still
    // within its absolute lifetime. Deleting used but unexpired refresh tokens
    // would silently defeat refresh-token reuse detection.
    removed += sqlx::query(
        "DELETE FROM refresh_access WHERE NOT EXISTS          (SELECT 1 FROM refresh_tokens r WHERE r.family_id=refresh_access.family_id)"
    ).execute(&mut *tx).await?.rows_affected();

    // Audit deletion is opt-in, never an implicit default. Reject unsafe
    // retention values rather than silently truncating recent audit records.
    if let Some(days) = audit_retention_days.filter(|d| (7..=3650).contains(d)) {
        let cutoff = now.saturating_sub(days.saturating_mul(86_400));
        removed += sqlx::query(&db.q("DELETE FROM audit WHERE created<?"))
            .bind(cutoff).execute(&mut *tx).await?.rows_affected();
    }
    tx.commit().await?;
    Ok(removed)
}

fn configured_retention() -> Option<i64> {
    match std::env::var("SSO_AUDIT_RETENTION_DAYS") {
        Err(std::env::VarError::NotPresent) => None,
        Ok(value) if value == "0" => None,
        Ok(value) => match value.parse::<i64>() {
            Ok(days) if (7..=3650).contains(&days) => Some(days),
            _ => {
                tracing::warn!("invalid SSO_AUDIT_RETENTION_DAYS; audit cleanup disabled");
                None
            }
        },
        Err(_) => {
            tracing::warn!("invalid SSO_AUDIT_RETENTION_DAYS; audit cleanup disabled");
            None
        }
    }
}

/// Initial cleanup at startup, then hourly. In a multi-replica deployment
/// these deletes are idempotent; this job is not a distributed rate limiter.
pub async fn background(db: Arc<Db>) {
    let retention = configured_retention();
    let mut timer = interval(Duration::from_secs(3600));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        match prune(&db, crypto::now(), retention).await {
            Ok(removed) if removed > 0 => tracing::info!(removed, "expired SSO artifacts pruned"),
            Ok(_) => (),
            Err(error) => tracing::warn!(%error, "SSO artifact cleanup failed; will retry"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    async fn count(db: &Db, table: &str) -> i64 {
        let statement = format!("SELECT COUNT(*) AS n FROM {table}");
        let row = sqlx::query(&statement).fetch_one(&db.pool).await.unwrap();
        row.try_get("n").unwrap()
    }

    #[tokio::test]
    async fn preserves_live_grants_and_refresh_replay_history() {
        let db = Db::open("sqlite::memory:").await.unwrap();
        let now = 10_000_000i64;
        for (name, expiry) in [("expired", now - 1), ("live", now + 500)] {
            sqlx::query("INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,'alice',?)")
                .bind(name).bind(expiry).execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO session_devices (token_hash,user_agent,method,created) VALUES (?,'test','oauth',0)")
                .bind(name).execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO session_assurance (token_hash,factor,verified_at) VALUES (?,'totp',0)")
                .bind(name).execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO codes (code_hash,client_id,user_id,redirect_uri,challenge,scope,expires,used) VALUES (?,'app','alice','https://localhost/cb','challenge','profile',?,0)")
                .bind(name).bind(expiry).execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO refresh_tokens (token_hash,family_id,client_id,user_id,scope,expires,used,revoked) VALUES (?,?,'app','alice','offline_access',?,1,0)")
                .bind(name).bind(name).bind(expiry).execute(&db.pool).await.unwrap();
            sqlx::query("INSERT INTO refresh_access (token_hash,family_id) VALUES (?,?)")
                .bind(name).bind(name).execute(&db.pool).await.unwrap();
        }
        assert!(prune(&db, now, None).await.unwrap() >= 6);
        for table in ["sessions","session_devices","session_assurance","codes","refresh_tokens","refresh_access"] {
            assert_eq!(count(&db, table).await, 1, "{table}: only live row remains");
        }
        // Repeating cleanup is safe, and consumed but unexpired refresh tokens
        // are NOT discarded: retaining them is essential for replay detection.
        assert_eq!(prune(&db, now, None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn audit_retention_is_explicit_and_has_a_seven_day_floor() {
        let db = Db::open("sqlite::memory:").await.unwrap();
        let now = 10_000_000i64;
        for (id, created) in [("old", now - 100 * 86400), ("new", now - 86400)] {
            sqlx::query("INSERT INTO audit (id,event,actor,metadata,created) VALUES (?,'test','admin','{}',?)")
                .bind(id).bind(created).execute(&db.pool).await.unwrap();
        }
        prune(&db, now, None).await.unwrap();
        prune(&db, now, Some(1)).await.unwrap(); // unsafe setting is ignored
        assert_eq!(count(&db, "audit").await, 2);
        prune(&db, now, Some(90)).await.unwrap();
        assert_eq!(count(&db, "audit").await, 1);
    }
}
