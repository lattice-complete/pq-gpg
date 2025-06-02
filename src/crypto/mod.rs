//! Post-quantum cryptographic primitives

pub mod kyber;
pub mod dilithium;
pub mod sphincs;
pub mod hybrid;

use crate::constants::PqAlgorithm;
use crate::error::{PqGpgError, Result};

/// Trait for post-quantum key encapsulation mechanisms
pub trait Kem {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type Ciphertext: Clone;
    type SharedSecret: Clone;
    
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn encaps(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)>;
    fn decaps(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret>;
}

/// Trait for post-quantum digital signature schemes
pub trait DigitalSignature {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type Signature: Clone;
    
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature>;
    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool>;
}

/// Factory for creating crypto instances based on algorithm
pub fn create_kem(algorithm: PqAlgorithm) -> Result<Box<dyn Kem<PublicKey=Vec<u8>, SecretKey=Vec<u8>, Ciphertext=Vec<u8>, SharedSecret=Vec<u8>>>> {
    match algorithm {
        PqAlgorithm::MlKem512 => Ok(Box::new(kyber::Kyber512::new())),
        PqAlgorithm::MlKem768 => Ok(Box::new(kyber::Kyber768::new())),
        PqAlgorithm::MlKem1024 => Ok(Box::new(kyber::Kyber1024::new())),
        _ => Err(PqGpgError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
    }
}

pub fn create_signature_scheme(algorithm: PqAlgorithm) -> Result<Box<dyn DigitalSignature<PublicKey=Vec<u8>, SecretKey=Vec<u8>, Signature=Vec<u8>>>> {
    match algorithm {
        PqAlgorithm::MlDsa44 => Ok(Box::new(dilithium::Dilithium2::new())),
        PqAlgorithm::MlDsa65 => Ok(Box::new(dilithium::Dilithium3::new())),
        PqAlgorithm::MlDsa87 => Ok(Box::new(dilithium::Dilithium5::new())),
        PqAlgorithm::SlhDsaSha2_128s => Ok(Box::new(sphincs::SphincsPlus128s::new())),
        PqAlgorithm::SlhDsaSha2_256s => Ok(Box::new(sphincs::SphincsPlus256s::new())),
        _ => Err(PqGpgError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
    }
}
