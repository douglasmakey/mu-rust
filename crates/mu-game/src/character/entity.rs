use crate::{
    character::{
        CharacterClass, CharacterLevel, CharacterSlot, HeroState, SpawnPoint,
        value_objects::{CharacterId, CharacterName},
    },
    iam::value_objects::AccountId,
};

#[derive(Debug)]
pub struct Character {
    pub id: CharacterId,
    pub account_id: AccountId,
    pub slot: CharacterSlot,
    pub name: CharacterName,
    pub class: CharacterClass,
    pub level: CharacterLevel,
    pub experience: u64,
    pub spawn: SpawnPoint,
    pub hero_state: HeroState,
}

impl Character {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: CharacterId,
        account_id: AccountId,
        slot: CharacterSlot,
        name: CharacterName,
        class: CharacterClass,
        level: CharacterLevel,
        experience: u64,
        hero_state: HeroState,
        spawn: SpawnPoint,
    ) -> Self {
        Self {
            id,
            account_id,
            slot,
            name,
            class,
            level,
            experience,
            hero_state,
            spawn,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CharacterError {
    #[error("invalid character name")]
    InvalidName,
    #[error("max slots reached")]
    MaxSlotsReached,
    #[error("level out of range")]
    LevelOutOfRange { min: i64, max: i64, actual: i64 },
}
