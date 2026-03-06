use crate::iam::account::AccountError;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId(pub i64);

/// A validated account login name — max 10 bytes, matches the wire field size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Username(String);

impl Username {
    pub const MAX_LEN: usize = 10;

    pub fn new(raw: &str) -> Result<Self, AccountError> {
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(AccountError::InvalidLoginName);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Account lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanStatus {
    Active,
    Banned,
    TempBanned { until: DateTime<Utc> },
}
