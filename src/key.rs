//! Key management for post-quantum GPG

use crate::constants::PqAlgorithm;
use crate::error::{PqGpgError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: PqAlgorithm,
    pub key_data: Vec<u8>,
    pub creation_time: DateTime<Utc>,
    pub fingerprint: Vec<u8>,
    pub key_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub public_key: PublicKey,
    pub secret_data: Vec<u8>,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl PublicKey {
    pub fn new(algorithm: PqAlgorithm, key_data: Vec<u8>) -> Result<Self> {
        let creation_time = Utc::now();
        let fingerprint = Self::compute_fingerprint(&key_data, &creation_time)?;
        let key_id = fingerprint[fingerprint.len()-8..].to_vec();
        
        Ok(Self {
            algorithm,
            key_data,
            creation_time,
            fingerprint,
            key_id,
        })
    }
    
    fn compute_fingerprint(key_data: &[u8], creation_time: &DateTime<Utc>) -> Result<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(key_data);
        hasher.update(creation_time.timestamp().to_be_bytes());
        
        Ok(hasher.finalize().to_vec())
    }
    
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(&self.fingerprint)
    }
    
    pub fn key_id_hex(&self) -> String {
        hex::encode(&self.key_id)
    }
}

impl KeyPair {
    pub fn generate(algorithm: PqAlgorithm) -> Result<Self> {
        match algorithm {
            PqAlgorithm::MlKem512 | PqAlgorithm::MlKem768 | PqAlgorithm::MlKem1024 => {
                let kem = crate::crypto::create_kem(algorithm)?;
                let (pk_data, sk_data) = kem.keygen()?;
                
                let public = PublicKey::new(algorithm, pk_data)?;
                let private = PrivateKey {
                    public_key: public.clone(),
                    secret_data: sk_data,
                    encrypted: false,
                };
                
                Ok(KeyPair { public, private })
            },
            PqAlgorithm::MlDsa44 | PqAlgorithm::MlDsa65 | PqAlgorithm::MlDsa87 |
            PqAlgorithm::SlhDsaSha2_128s | PqAlgorithm::SlhDsaSha2_256s => {
                let sig_scheme = crate::crypto::create_signature_scheme(algorithm)?;
                let (pk_data, sk_data) = sig_scheme.keygen()?;
                
                let public = PublicKey::new(algorithm, pk_data)?;
                let private = PrivateKey {
                    public_key: public.clone(),
                    secret_data: sk_data,
                    encrypted: false,
                };
                
                Ok(KeyPair { public, private })
            },
            _ => Err(PqGpgError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
        }
    }
}
