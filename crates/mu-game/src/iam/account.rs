use super::value_objects::{AccountId, BanStatus, Username};
use chrono::{DateTime, Utc};

pub struct Account {
    pub id: AccountId,
    pub username: Username,
    password_hash: String,
    pub ban_status: BanStatus,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl Account {
    pub fn new(
        id: AccountId,
        username: Username,
        password_hash: String,
        ban_status: BanStatus,
        last_login_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id,
            username,
            password_hash,
            ban_status,
            last_login_at,
        }
    }

    pub fn can_authenticate(&self) -> Result<(), AccountError> {
        match self.ban_status {
            BanStatus::Active => Ok(()),
            BanStatus::Banned => Err(AccountError::PermanentlyBanned),
            BanStatus::TempBanned { until } => {
                if until > Utc::now() {
                    Err(AccountError::TemporarilyBanned { until })
                } else {
                    // Ban has expired
                    // TODO: clear ban status from the database later
                    Ok(())
                }
            }
        }
    }

    /// Returns the stored bcrypt hash — only for use by the `PasswordVerifier` port.
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("Account is permanently banned")]
    PermanentlyBanned,
    #[error("Account is temporarily banned until {until}")]
    TemporarilyBanned { until: DateTime<Utc> },
    #[error("invalid login name")]
    InvalidLoginName,
}
