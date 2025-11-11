//! Hybrid cryptography combining classical and post-quantum algorithms
//!
//! This module implements hybrid encryption schemes that combine
//! classical cryptography (e.g., RSA, ECC) with post-quantum algorithms
//! for forward secrecy and quantum resistance.

use crate::error::{PqGpgError, Result};
use crate::constants::PqAlgorithm;
use super::{Kem, DigitalSignature};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use sha2::{Sha256, Digest};

/// Hybrid key encapsulation combining X25519 and ML-KEM
pub struct HybridKem {
    pq_algorithm: PqAlgorithm,
}

impl HybridKem {
    pub fn new(pq_algorithm: PqAlgorithm) -> Self {
        Self { pq_algorithm }
    }

    /// Generate a hybrid keypair (X25519 + PQ-KEM)
    pub fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let rng = SystemRandom::new();

        // Generate X25519 keypair
        let x25519_private = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|e| PqGpgError::CryptoError(format!("X25519 keygen failed: {:?}", e)))?;

        let x25519_public = x25519_private.compute_public_key()
            .map_err(|e| PqGpgError::CryptoError(format!("X25519 public key derivation failed: {:?}", e)))?;

        // Generate PQ-KEM keypair
        let kem = super::create_kem(self.pq_algorithm)?;
        let (pq_pk, pq_sk) = kem.keygen()?;

        // Combine keys (simple concatenation for now)
        let mut public_key = Vec::new();
        public_key.extend_from_slice(x25519_public.as_ref());
        public_key.extend_from_slice(&pq_pk);

        // Note: In production, x25519_private would need to be serialized
        // For now, we just use the PQ secret key
        let secret_key = pq_sk;

        Ok((public_key, secret_key))
    }

    /// Perform hybrid encapsulation
    pub fn encaps(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Split the public key into X25519 and PQ parts
        if public_key.len() < 32 {
            return Err(PqGpgError::CryptoError("Invalid hybrid public key".to_string()));
        }

        let (_x25519_pk, pq_pk) = public_key.split_at(32);

        // Perform PQ encapsulation
        let kem = super::create_kem(self.pq_algorithm)?;
        let (ciphertext, pq_shared) = kem.encaps(&pq_pk.to_vec())?;

        // In a full implementation, we would also do X25519 ECDH here
        // For now, just use the PQ shared secret
        let shared_secret = self.combine_secrets(&[], &pq_shared)?;

        Ok((ciphertext, shared_secret))
    }

    /// Perform hybrid decapsulation
    pub fn decaps(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Perform PQ decapsulation
        let kem = super::create_kem(self.pq_algorithm)?;
        let pq_shared = kem.decaps(&secret_key.to_vec(), &ciphertext.to_vec())?;

        // Combine with classical shared secret (if available)
        let shared_secret = self.combine_secrets(&[], &pq_shared)?;

        Ok(shared_secret)
    }

    /// Combine classical and PQ shared secrets using a KDF
    fn combine_secrets(&self, classical: &[u8], pq: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(b"pq-gpg-hybrid-v1");
        hasher.update(classical);
        hasher.update(pq);
        Ok(hasher.finalize().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_keygen() {
        let hybrid = HybridKem::new(PqAlgorithm::MlKem512);
        let result = hybrid.keygen();
        assert!(result.is_ok());

        let (pk, sk) = result.unwrap();
        assert!(pk.len() > 32); // Should be X25519 + PQ public key
        assert!(sk.len() > 0);
    }

    #[test]
    fn test_hybrid_kem_encaps_decaps() {
        let hybrid = HybridKem::new(PqAlgorithm::MlKem512);
        let (pk, sk) = hybrid.keygen().unwrap();

        let (ct, ss1) = hybrid.encaps(&pk).unwrap();
        let ss2 = hybrid.decaps(&sk, &ct).unwrap();

        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 32); // SHA-256 output
    }
}
