pub mod account;
pub mod character;

mod error;

pub use error::DBError;
use sqlx::PgPool;

use crate::account::PostgresAccountRepo;
use crate::character::PostgresCharacterRepo;

pub struct Postgres {
    pool: PgPool,
}

impl Postgres {
    pub async fn new(url: &str) -> Result<Postgres, DBError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<(), DBError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub fn account_repo(&self) -> PostgresAccountRepo {
        PostgresAccountRepo::new(self.pool.clone())
    }

    pub fn character_repo(&self) -> PostgresCharacterRepo {
        PostgresCharacterRepo::new(self.pool.clone())
    }
}
