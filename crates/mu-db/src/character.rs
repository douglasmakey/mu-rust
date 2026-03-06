use async_trait::async_trait;
use mu_game::{
    character::{
        Character, CharacterClass, CharacterId, CharacterLevel, CharacterName, CharacterSlot,
        HeroState, MapId, Position, SpawnPoint, ports::CharacterRepository,
    },
    errors::InfrastructureError,
    iam::AccountId,
};
use sqlx::PgPool;
use tracing::warn;

struct CharacterRow {
    id: i64,
    account_id: i64,
    slot: i16,
    name: String,
    class: i16,
    level: i16,
    map_id: i16,
    pos_x: i16,
    pos_y: i16,
    experience: i64,
    hero_state: i16,
}

impl From<CharacterRow> for Character {
    fn from(row: CharacterRow) -> Self {
        let class = CharacterClass::try_from(row.class).unwrap_or_else(|_| {
            warn!(
                id = row.id,
                class = row.class,
                "unknown character class in DB, defaulting to BladeKnight"
            );
            CharacterClass::BladeKnight
        });

        let hero_state = HeroState::try_from(row.hero_state).unwrap_or_else(|_| {
            warn!(
                id = row.id,
                hero_state = row.hero_state,
                "unknown hero_state in DB, defaulting to Normal"
            );
            HeroState::Normal
        });

        let spawn = SpawnPoint {
            map_id: MapId::from_db(row.map_id),
            position: Position {
                x: row.pos_x.clamp(0, 255) as u8,
                y: row.pos_y.clamp(0, 255) as u8,
            },
        };

        Character::new(
            CharacterId(row.id),
            AccountId(row.account_id),
            CharacterSlot::from_db(row.slot),
            CharacterName::from_trusted(row.name),
            class,
            CharacterLevel::from_db(row.level),
            row.experience as u64,
            hero_state,
            spawn,
        )
    }
}

pub struct PostgresCharacterRepo {
    pool: PgPool,
}

impl PostgresCharacterRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CharacterRepository for PostgresCharacterRepo {
    async fn find_all_by_account_id(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<Character>, InfrastructureError> {
        let rows = sqlx::query_as!(
            CharacterRow,
            "SELECT id, account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state FROM characters WHERE account_id = $1 ORDER BY slot ASC",
            account_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| InfrastructureError::DbQueryFailed(e.to_string()))?;

        Ok(rows.into_iter().map(Character::from).collect())
    }

    async fn find_by_name_and_account(
        &self,
        account_id: AccountId,
        name: &CharacterName,
    ) -> Result<Option<Character>, InfrastructureError> {
        let row = sqlx::query_as!(
            CharacterRow,
            "SELECT id, account_id, slot, name, class, level, map_id, pos_x, pos_y, \
             experience, hero_state \
             FROM characters \
             WHERE account_id = $1 AND name = $2",
            account_id.0,
            name.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| InfrastructureError::DbQueryFailed(e.to_string()))?;

        Ok(row.map(Character::from))
    }
}
