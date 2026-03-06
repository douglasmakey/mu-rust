use crate::{
    errors::InfrastructureError,
    iam::{
        account::Account,
        value_objects::{AccountId, Username},
    },
};
use async_trait::async_trait;

/// Port: in-memory (local/remote) session deduplication — prevents duplicate logins.
#[async_trait]
pub trait AccountSessionRegistry: Send + Sync {
    async fn register(&self, account_id: AccountId) -> Result<bool, InfrastructureError>;
    async fn unregister(&self, account_id: AccountId) -> Result<(), InfrastructureError>;
}

/// Port: persistent storage for Account
#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn find_by_username(
        &self,
        username: &Username,
    ) -> Result<Option<Account>, InfrastructureError>;
}
