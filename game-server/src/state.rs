use async_trait::async_trait;
use mu_db::{account::PostgresAccountRepo, character::PostgresCharacterRepo};
use mu_game::{
    errors::InfrastructureError,
    iam::{AccountId, ports::AccountSessionRegistry},
    services::{auth::AuthService, character::CharacterService},
};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::Mutex;

pub struct InMemorySessionRegistry {
    active: Mutex<HashSet<AccountId>>,
}

impl InMemorySessionRegistry {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for InMemorySessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AccountSessionRegistry for InMemorySessionRegistry {
    async fn register(&self, account_id: AccountId) -> Result<bool, InfrastructureError> {
        let mut active = self.active.lock().await;
        Ok(active.insert(account_id))
    }

    async fn unregister(&self, account_id: AccountId) -> Result<(), InfrastructureError> {
        let mut active = self.active.lock().await;
        active.remove(&account_id);
        Ok(())
    }
}

/// Shared application state, cloned (via Arc) into every client handler.
pub struct GameState {
    pub auth_service: AuthService<PostgresAccountRepo, InMemorySessionRegistry>,
    pub character_service: CharacterService<PostgresCharacterRepo>,
}

impl GameState {
    pub fn new(
        account_repo: PostgresAccountRepo,
        sessions: InMemorySessionRegistry,
        character_repo: PostgresCharacterRepo,
    ) -> Self {
        Self {
            auth_service: AuthService::new(Arc::new(account_repo), Arc::new(sessions)),
            character_service: CharacterService::new(Arc::new(character_repo)),
        }
    }
}
