use crate::{
    character::{
        character::{Character, CharacterError},
        ports::CharacterRepository,
        value_objects::CharacterName,
    },
    errors::InfrastructureError,
    iam::AccountId,
};
use std::sync::Arc;

pub struct CharacterService<R> {
    character_repo: Arc<R>,
}

impl<R> CharacterService<R>
where
    R: CharacterRepository,
{
    pub fn new(character_repo: Arc<R>) -> Self {
        Self { character_repo }
    }

    pub async fn find_all_by_account_id(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<Character>, CharacterServiceError> {
        let result = self
            .character_repo
            .find_all_by_account_id(account_id)
            .await?;

        Ok(result)
    }

    pub async fn select_character(
        &self,
        account_id: AccountId,
        name: &CharacterName,
    ) -> Result<Character, CharacterServiceError> {
        self.character_repo
            .find_by_name_and_account(account_id, name)
            .await?
            .ok_or(CharacterServiceError::NotFound)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CharacterServiceError {
    #[error("character not found")]
    NotFound,
    #[error("Character domain violation: {0}")]
    Domain(#[from] CharacterError),
    #[error("infrastructure error: {0}")]
    Infrastructure(#[from] InfrastructureError),
}
