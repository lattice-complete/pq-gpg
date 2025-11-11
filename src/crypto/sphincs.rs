//! SLH-DSA (SPHINCS+) digital signature implementation
//!
//! NOTE: SPHINCS+ implementation is currently disabled as the sphincsplus
//! crate is not available on crates.io. This is a stub implementation
//! that returns "not implemented" errors.

use super::DigitalSignature;
use crate::error::{PqGpgError, Result};

pub struct SphincsPlus128s;
pub struct SphincsPlus256s;

impl SphincsPlus128s {
    pub fn new() -> Self {
        Self
    }
}

impl DigitalSignature for SphincsPlus128s {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }

    fn sign(_sk: &Self::SecretKey, _message: &[u8]) -> Result<Self::Signature> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }

    fn verify(_pk: &Self::PublicKey, _message: &[u8], _signature: &Self::Signature) -> Result<bool> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }
}

impl SphincsPlus256s {
    pub fn new() -> Self { Self }
}

impl DigitalSignature for SphincsPlus256s {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }

    fn sign(_sk: &Self::SecretKey, _message: &[u8]) -> Result<Self::Signature> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }

    fn verify(_pk: &Self::PublicKey, _message: &[u8], _signature: &Self::Signature) -> Result<bool> {
        Err(PqGpgError::UnsupportedAlgorithm(
            "SPHINCS+ is not yet implemented (library not available)".to_string()
        ))
    }
}
