//! ML-KEM (Kyber) key encapsulation mechanism implementation

use super::Kem;
use crate::error::{PqGpgError, Result};
use pqc_kyber::*;
use rand::rngs::OsRng;
use std::convert::TryInto;

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

        if pk.len() != KYBER_PUBLICKEYBYTES {
            return Err(PqGpgError::CryptoError("Invalid public key length".to_string()));
        }

        let pk_array: [u8; KYBER_PUBLICKEYBYTES] = pk.as_slice()
            .try_into()
            .map_err(|_| PqGpgError::CryptoError("Failed to convert public key".to_string()))?;

        let (ct, ss) = encapsulate(&pk_array, &mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber512 encaps failed: {:?}", e)))?;

        Ok((ct.to_vec(), ss.to_vec()))
    }

    fn decaps(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        if sk.len() != KYBER_SECRETKEYBYTES || ct.len() != KYBER_CIPHERTEXTBYTES {
            return Err(PqGpgError::CryptoError("Invalid key or ciphertext length".to_string()));
        }

        let sk_array: [u8; KYBER_SECRETKEYBYTES] = sk.as_slice()
            .try_into()
            .map_err(|_| PqGpgError::CryptoError("Failed to convert secret key".to_string()))?;
        let ct_array: [u8; KYBER_CIPHERTEXTBYTES] = ct.as_slice()
            .try_into()
            .map_err(|_| PqGpgError::CryptoError("Failed to convert ciphertext".to_string()))?;

        let ss = decapsulate(&ct_array, &sk_array)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber512 decaps failed: {:?}", e)))?;

        Ok(ss.to_vec())
    }
}

impl Kyber768 {
    pub fn new() -> Self { Self }
}

impl Kem for Kyber768 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Ciphertext = Vec<u8>;
    type SharedSecret = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = keypair(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber768 keygen failed: {:?}", e)))?;
        Ok((keys.public.to_vec(), keys.secret.to_vec()))
    }

    fn encaps(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut rng = OsRng;
        let public_key = PublicKey::try_from(pk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;

        let (ciphertext, shared_secret) = encapsulate(&public_key, &mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber768 encaps failed: {:?}", e)))?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    fn decaps(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        let secret_key = SecretKey::try_from(sk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;
        let ciphertext = Ciphertext::try_from(ct.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid ciphertext: {:?}", e)))?;

        let shared_secret = decapsulate(&ciphertext, &secret_key)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber768 decaps failed: {:?}", e)))?;

        Ok(shared_secret.to_vec())
    }
}

impl Kyber1024 {
    pub fn new() -> Self { Self }
}

impl Kem for Kyber1024 {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Ciphertext = Vec<u8>;
    type SharedSecret = Vec<u8>;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = OsRng;
        let keys = keypair(&mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber1024 keygen failed: {:?}", e)))?;
        Ok((keys.public.to_vec(), keys.secret.to_vec()))
    }

    fn encaps(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut rng = OsRng;
        let public_key = PublicKey::try_from(pk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid public key: {:?}", e)))?;

        let (ciphertext, shared_secret) = encapsulate(&public_key, &mut rng)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber1024 encaps failed: {:?}", e)))?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    fn decaps(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        let secret_key = SecretKey::try_from(sk.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid secret key: {:?}", e)))?;
        let ciphertext = Ciphertext::try_from(ct.as_slice())
            .map_err(|e| PqGpgError::CryptoError(format!("Invalid ciphertext: {:?}", e)))?;

        let shared_secret = decapsulate(&ciphertext, &secret_key)
            .map_err(|e| PqGpgError::CryptoError(format!("Kyber1024 decaps failed: {:?}", e)))?;

        Ok(shared_secret.to_vec())
    }
}
