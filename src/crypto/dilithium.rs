//! ML-DSA (Dilithium) digital signature implementation

use super::DigitalSignature;
use crate::error::{PqGpgError, Result};
use pqc_dilithium::*;
use rand::rngs::OsRng;

pub struct Dilithium2;
pub struct Dilithium3;
pub struct Dilithium5;

impl Dilithium2 {
    pub fn new() -> Self {
        Self
    }
}

impl DigitalSignature for Dilithium2 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;
    
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = Keypair::generate(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium2 keygen failed: {:?}", e)))?;
        Ok((keys.public.as_bytes().to_vec(), keys.secret.as_bytes().to_vec()))
    }
    
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature> {
        let secret_key = SecretKey::from_bytes(sk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;
        
        let signature = secret_key.sign(message, &mut OsRng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium2 signing failed: {:?}", e)))?;
        
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool> {
        let public_key = PublicKey::from_bytes(pk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;
        let sig = SignedMessage::from_bytes(signature)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid signature: {:?}", e)))?;
        
        match public_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Dilithium3 {
    pub fn new() -> Self { Self }
}

impl DigitalSignature for Dilithium3 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = Keypair::generate(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium3 keygen failed: {:?}", e)))?;
        Ok((keys.public.as_bytes().to_vec(), keys.secret.as_bytes().to_vec()))
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature> {
        let secret_key = SecretKey::from_bytes(sk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;

        let signature = secret_key.sign(message, &mut OsRng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium3 signing failed: {:?}", e)))?;

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool> {
        let public_key = PublicKey::from_bytes(pk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;
        let sig = SignedMessage::from_bytes(signature)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid signature: {:?}", e)))?;

        match public_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Dilithium5 {
    pub fn new() -> Self { Self }
}

impl DigitalSignature for Dilithium5 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = Keypair::generate(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium5 keygen failed: {:?}", e)))?;
        Ok((keys.public.as_bytes().to_vec(), keys.secret.as_bytes().to_vec()))
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature> {
        let secret_key = SecretKey::from_bytes(sk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;

        let signature = secret_key.sign(message, &mut OsRng)
            .map_err(|e| PqGpgError::CryptoError(format!("Dilithium5 signing failed: {:?}", e)))?;

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool> {
        let public_key = PublicKey::from_bytes(pk)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;
        let sig = SignedMessage::from_bytes(signature)
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid signature: {:?}", e)))?;

        match public_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
