use crate::{
    character::{Character, value_objects::CharacterName},
    errors::InfrastructureError,
    iam::value_objects::AccountId,
};
use async_trait::async_trait;

#[async_trait]
pub trait CharacterRepository: Send + Sync {
    async fn find_all_by_account_id(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<Character>, InfrastructureError>;

    async fn find_by_name_and_account(
        &self,
        account_id: AccountId,
        name: &CharacterName,
    ) -> Result<Option<Character>, InfrastructureError>;
}
