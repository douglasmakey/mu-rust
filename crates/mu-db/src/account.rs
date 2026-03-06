use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mu_game::{
    errors::InfrastructureError,
    iam::{AccountId, BanStatus, Username, account::Account, ports::AccountRepository},
};
use sqlx::PgPool;

#[derive(Debug)]
struct AccountRow {
    id: i64,
    username: String,
    password_hash: String,
    is_banned: bool,
    banned_until: Option<DateTime<Utc>>,
    last_login_at: Option<DateTime<Utc>>,
}

impl From<AccountRow> for Account {
    fn from(row: AccountRow) -> Self {
        let ban_status = if row.is_banned {
            match row.banned_until {
                Some(until) if until > Utc::now() => BanStatus::TempBanned { until },
                _ => BanStatus::Banned,
            }
        } else {
            BanStatus::Active
        };

        Account::new(
            AccountId(row.id),
            Username::new(&row.username)
                .expect("DB VARCHAR(10) constraint guarantees a valid login name"),
            row.password_hash,
            ban_status,
            row.last_login_at,
        )
    }
}

pub struct PostgresAccountRepo {
    pool: PgPool,
}

impl PostgresAccountRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccountRepository for PostgresAccountRepo {
    async fn find_by_username(
        &self,
        username: &Username,
    ) -> Result<Option<Account>, InfrastructureError> {
        let row = sqlx::query_as!(
            AccountRow,
            "SELECT id, username, password_hash, is_banned, banned_until, last_login_at FROM accounts where username = $1",
            username.as_str()
        ).fetch_optional(&self.pool)
        .await
        .map_err(|e| InfrastructureError::DbQueryFailed(e.to_string()))?;

        Ok(row.map(Account::from))
    }
}
