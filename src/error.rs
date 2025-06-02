use thiserror::Error;

pub type Result<T> = std::result::Result<T, PqGpgError>;

#[derive(Error, Debug)]
pub enum PqGpgError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Invalid packet format: {0}")]
    InvalidPacket(String),
    
    #[error("Key error: {0}")]
    KeyError(String),
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Decryption failed")]
    DecryptionFailed,
    
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}
