use thiserror::Error;

#[derive(Error, Debug)]
pub enum NcmError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::utils::crypto::CryptoError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API error: {code} - {msg}")]
    Api { code: i32, msg: String },

    #[error("Unknown error: {0}")]
    Unknown(String),
}
