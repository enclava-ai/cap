use thiserror::Error;

#[derive(Debug, Error)]
pub enum InitError {
    #[error("config error: {0}")]
    Config(String),

    #[error("argon2 derivation failed: {0}")]
    Argon2(String),

    #[error("hkdf derivation failed: {0}")]
    Hkdf(String),

    #[error("rate limit: too many unlock attempts")]
    RateLimited,

    #[error("invalid password")]
    InvalidPassword,

    #[error("luks operation failed: {0}")]
    Luks(String),

    #[error("kbs fetch failed: {0}")]
    Kbs(String),

    #[error("trustee policy verification failed: {0}")]
    TrusteePolicy(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, InitError>;
