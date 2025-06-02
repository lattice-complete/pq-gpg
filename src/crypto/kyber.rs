//! ML-KEM (Kyber) key encapsulation mechanism implementation

use super::Kem;
use crate::error::{PqGpgError, Result};
use pqc_kyber::*;
use rand::rngs::OsRng;

pub struct Kyber512;
pub struct Kyber768;  
pub struct Kyber1024;

impl Kyber512 {
    pub fn new() -> Self {
        Self
    }
}

impl Kem for Kyber512 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Ciphertext = Vec<u8>;
    type SharedSecret = Vec<u8>;
    
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = keypair(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber512 keygen failed: {:?}", e)))?;
        Ok((keys.public.to_vec(), keys.secret.to_vec()))
    }
    
    fn encaps(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut rng = OsRng;
        let public_key = PublicKey::try_from(pk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;
        
        let (ciphertext, shared_secret) = encapsulate(&public_key, &mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber512 encaps failed: {:?}", e)))?;
        
        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }
    
    fn decaps(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        let secret_key = SecretKey::try_from(sk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;
        let ciphertext = Ciphertext::try_from(ct.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid ciphertext: {:?}", e)))?;
        
        let shared_secret = decapsulate(&ciphertext, &secret_key)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber512 decaps failed: {:?}", e)))?;
        
        Ok(shared_secret.to_vec())
    }
}

// Similar implementations for Kyber768 and Kyber1024...
impl Kyber768 {
    pub fn new() -> Self { Self }
}

impl Kyber1024 {
    pub fn new() -> Self { Self }
}

// TODO: Implement Kem trait for Kyber768 and Kyber1024 with appropriate parameter sets
