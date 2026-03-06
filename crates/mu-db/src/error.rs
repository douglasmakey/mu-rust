#[derive(Debug, thiserror::Error)]
pub enum DBError {
    #[error("migration error: {0}")]
    MigrateError(#[from] sqlx::migrate::MigrateError),

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}
