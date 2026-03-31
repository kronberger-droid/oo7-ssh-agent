use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("keyring error: {0}")]
    Keyring(#[from] oo7::Error),

    #[error("no SSH key found for fingerprint: {0}")]
    KeyNotFound(String),

    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("signing error: {0}")]
    Signature(#[from] signature::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
