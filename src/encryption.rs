//! Message encryption and decryption using post-quantum cryptography
//!
//! This module implements hybrid encryption combining post-quantum KEMs
//! with symmetric encryption (AES-GCM) for efficient message encryption.

use crate::constants::PqAlgorithm;
use crate::crypto::{create_kem, Kem};
use crate::error::{PqGpgError, Result};
use crate::key::{PublicKey, PrivateKey};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Encrypted message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Algorithm used for key encapsulation
    pub algorithm: PqAlgorithm,
    /// Encapsulated key (ciphertext from KEM)
    pub encapsulated_key: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
}

/// Encrypt a message for a recipient's public key
pub fn encrypt_message(plaintext: &[u8], recipient_pk: &PublicKey) -> Result<EncryptedMessage> {
    // Get the KEM for the recipient's algorithm
    let kem = create_kem(recipient_pk.algorithm)?;

    // Encapsulate to generate shared secret
    let (encapsulated_key, shared_secret) = kem.encaps(&recipient_pk.key_material)?;

    // Derive AES key from shared secret (use first 32 bytes or hash if needed)
    let aes_key = derive_symmetric_key(&shared_secret)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| PqGpgError::CryptoError(format!("AES key init failed: {}", e)))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PqGpgError::CryptoError(format!("Encryption failed: {}", e)))?;

    Ok(EncryptedMessage {
        algorithm: recipient_pk.algorithm,
        encapsulated_key,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a message using a private key
pub fn decrypt_message(encrypted: &EncryptedMessage, private_key: &PrivateKey) -> Result<Vec<u8>> {
    // Verify algorithm matches
    if encrypted.algorithm != private_key.public_key.algorithm {
        return Err(PqGpgError::DecryptionFailed(
            "Algorithm mismatch".to_string(),
        ));
    }

    // Get the KEM
    let kem = create_kem(encrypted.algorithm)?;

    // Decapsulate to recover shared secret
    let shared_secret = kem.decaps(
        &private_key.secret_material,
        &encrypted.encapsulated_key,
    )?;

    // Derive AES key
    let aes_key = derive_symmetric_key(&shared_secret)?;

    // Decrypt with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| PqGpgError::CryptoError(format!("AES key init failed: {}", e)))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| PqGpgError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Derive a 256-bit symmetric key from shared secret
fn derive_symmetric_key(shared_secret: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"pq-gpg-encryption-v1");
    hasher.update(shared_secret);
    Ok(hasher.finalize().to_vec())
}

/// Encrypt a file
pub fn encrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    recipient_pk: &PublicKey,
) -> Result<()> {
    use std::fs;

    let plaintext = fs::read(input_path)
        .map_err(|e| PqGpgError::IoError(e))?;

    let encrypted = encrypt_message(&plaintext, recipient_pk)?;

    let serialized = bincode::serialize(&encrypted)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    fs::write(output_path, serialized)
        .map_err(|e| PqGpgError::IoError(e))?;

    Ok(())
}

/// Decrypt a file
pub fn decrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    private_key: &PrivateKey,
) -> Result<()> {
    use std::fs;

    let encrypted_data = fs::read(input_path)
        .map_err(|e| PqGpgError::IoError(e))?;

    let encrypted: EncryptedMessage = bincode::deserialize(&encrypted_data)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    let plaintext = decrypt_message(&encrypted, private_key)?;

    fs::write(output_path, plaintext)
        .map_err(|e| PqGpgError::IoError(e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    #[test]
    fn test_encrypt_decrypt_message() {
        let keypair = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let plaintext = b"Hello, PQ-GPG World!";

        let encrypted = encrypt_message(plaintext, &keypair.public_key).unwrap();
        let decrypted = decrypt_message(&encrypted, &keypair.private_key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let keypair = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();
        let plaintext = vec![42u8; 10000];

        let encrypted = encrypt_message(&plaintext, &keypair.public_key).unwrap();
        let decrypted = decrypt_message(&encrypted, &keypair.private_key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let keypair2 = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let plaintext = b"Secret message";

        let encrypted = encrypt_message(plaintext, &keypair1.public_key).unwrap();
        let result = decrypt_message(&encrypted, &keypair2.private_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_serialization() {
        let keypair = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let plaintext = b"Test data";

        let encrypted = encrypt_message(plaintext, &keypair.public_key).unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&encrypted).unwrap();
        let deserialized: EncryptedMessage = bincode::deserialize(&serialized).unwrap();

        let decrypted = decrypt_message(&deserialized, &keypair.private_key).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
