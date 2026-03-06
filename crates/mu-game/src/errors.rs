use thiserror::Error;

#[derive(Debug, Error)]
pub enum InfrastructureError {
    // Database concerns
    #[error("database query failed: {0}")]
    DbQueryFailed(String),

    // Session/Cache concerns
    #[error("cache operation failed: {0}")]
    CacheOperationFailed(String),

    // A good catch-all for unexpected system issues
    #[error("internal infrastructure fault: {0}")]
    Internal(String),
}
