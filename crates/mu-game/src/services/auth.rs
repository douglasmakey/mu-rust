use std::sync::Arc;

use crate::{
    errors::InfrastructureError,
    iam::{
        AccountId, Username,
        account::AccountError,
        ports::{AccountRepository, AccountSessionRegistry},
    },
};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum AuthServiceError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("password verification failed")]
    PasswordVerificationFailed,
    #[error("account already has an active session")]
    DuplicateSession,
    #[error("Account domain violation: {0}")]
    Domain(#[from] AccountError),
    #[error("infrastructure error: {0}")]
    Infrastructure(#[from] InfrastructureError),
}

pub struct AuthService<R, S> {
    account_repo: Arc<R>,
    session_registry: Arc<S>,
}

impl<R, S> AuthService<R, S>
where
    R: AccountRepository,
    S: AccountSessionRegistry,
{
    pub fn new(account_repo: Arc<R>, session_registry: Arc<S>) -> Self {
        Self {
            account_repo,
            session_registry,
        }
    }

    pub async fn login(
        &self,
        username: &Username,
        password: &str,
    ) -> Result<AccountId, AuthServiceError> {
        let account = self
            .account_repo
            .find_by_username(username)
            .await?
            .ok_or(AuthServiceError::InvalidCredentials)?;

        // Verify account is not banned
        account.can_authenticate()?;

        // Verify password - extract the verifier later
        let matches = bcrypt::verify(password, account.password_hash())
            .map_err(|_| AuthServiceError::PasswordVerificationFailed)?;

        if !matches {
            return Err(AuthServiceError::InvalidCredentials);
        }

        let registered = self
            .session_registry
            .register(account.id)
            .await
            .map_err(|e| InfrastructureError::CacheOperationFailed(e.to_string()))?;

        if !registered {
            return Err(AuthServiceError::DuplicateSession);
        }

        Ok(account.id)
    }

    pub async fn logout(&self, account_id: AccountId) {
        if let Err(e) = self.session_registry.unregister(account_id).await {
            warn!(
                account_id = %account_id.0,
                error = %e,
                "failed to unregister session on logout"
            );
        }
    }
}
