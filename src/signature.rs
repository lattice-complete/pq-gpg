//! Digital signature creation and verification using post-quantum algorithms
//!
//! This module implements digital signatures using ML-DSA (Dilithium) and
//! SLH-DSA (SPHINCS+) for quantum-resistant authentication.

use crate::constants::PqAlgorithm;
use crate::crypto::{create_signature_scheme, DigitalSignature};
use crate::error::{PqGpgError, Result};
use crate::key::{PrivateKey, PublicKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Algorithm used for signing
    pub algorithm: PqAlgorithm,
    /// The actual signature bytes
    pub signature_data: Vec<u8>,
    /// Timestamp when signature was created
    pub created_at: DateTime<Utc>,
    /// Hash of the signed data (for verification reference)
    pub data_hash: Vec<u8>,
    /// Key ID of the signer
    pub key_id: Vec<u8>,
}

/// Sign data with a private key
pub fn sign_data(data: &[u8], private_key: &PrivateKey) -> Result<Signature> {
    // Hash the data first
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_hash = hasher.finalize().to_vec();

    // Get the signature scheme
    let scheme = create_signature_scheme(private_key.public_key.algorithm)?;

    // Sign the data
    let signature_data = scheme.sign(&private_key.secret_material, data)?;

    Ok(Signature {
        algorithm: private_key.public_key.algorithm,
        signature_data,
        created_at: Utc::now(),
        data_hash,
        key_id: private_key.public_key.key_id(),
    })
}

/// Verify a signature against data and public key
pub fn verify_signature(data: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool> {
    // Verify algorithm matches
    if signature.algorithm != public_key.algorithm {
        return Err(PqGpgError::SignatureVerificationFailed(
            "Algorithm mismatch".to_string(),
        ));
    }

    // Verify key ID matches
    if signature.key_id != public_key.key_id() {
        return Err(PqGpgError::SignatureVerificationFailed(
            "Key ID mismatch".to_string(),
        ));
    }

    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_hash = hasher.finalize().to_vec();

    // Verify data hash matches
    if signature.data_hash != data_hash {
        return Err(PqGpgError::SignatureVerificationFailed(
            "Data hash mismatch".to_string(),
        ));
    }

    // Get the signature scheme
    let scheme = create_signature_scheme(public_key.algorithm)?;

    // Verify the signature
    scheme.verify(
        &public_key.key_material,
        data,
        &signature.signature_data,
    )
}

/// Sign a file
pub fn sign_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    private_key: &PrivateKey,
    detached: bool,
) -> Result<()> {
    use std::fs;

    let data = fs::read(input_path)
        .map_err(|e| PqGpgError::IoError(e))?;

    let signature = sign_data(&data, private_key)?;

    let serialized = bincode::serialize(&signature)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    if detached {
        // Write only signature to output file
        fs::write(output_path, serialized)
            .map_err(|e| PqGpgError::IoError(e))?;
    } else {
        // Write data + signature to output file
        let mut output = Vec::new();
        output.extend_from_slice(&(data.len() as u64).to_le_bytes());
        output.extend_from_slice(&data);
        output.extend_from_slice(&serialized);

        fs::write(output_path, output)
            .map_err(|e| PqGpgError::IoError(e))?;
    }

    Ok(())
}

/// Verify a file signature
pub fn verify_file(
    data_path: &std::path::Path,
    signature_path: Option<&std::path::Path>,
    public_key: &PublicKey,
) -> Result<bool> {
    use std::fs;

    let data = fs::read(data_path)
        .map_err(|e| PqGpgError::IoError(e))?;

    let signature = if let Some(sig_path) = signature_path {
        // Detached signature
        let sig_data = fs::read(sig_path)
            .map_err(|e| PqGpgError::IoError(e))?;

        bincode::deserialize(&sig_data)
            .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?
    } else {
        // Signature embedded in file
        if data.len() < 8 {
            return Err(PqGpgError::InvalidPacket(
                "File too small to contain signature".to_string(),
            ));
        }

        let data_len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;

        if data.len() < 8 + data_len {
            return Err(PqGpgError::InvalidPacket(
                "Invalid embedded signature format".to_string(),
            ));
        }

        let sig_data = &data[8 + data_len..];

        bincode::deserialize(sig_data)
            .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?
    };

    verify_signature(&data, &signature, public_key)
}

/// Create a detached signature (returns signature bytes)
pub fn create_detached_signature(data: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>> {
    let signature = sign_data(data, private_key)?;

    bincode::serialize(&signature)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))
}

/// Verify a detached signature (from bytes)
pub fn verify_detached_signature(
    data: &[u8],
    signature_bytes: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let signature: Signature = bincode::deserialize(signature_bytes)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    verify_signature(data, &signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    #[test]
    fn test_sign_verify_data() {
        let keypair = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let data = b"Test message for signing";

        let signature = sign_data(data, &keypair.private_key).unwrap();
        let is_valid = verify_signature(data, &signature, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_sign_verify_large_data() {
        let keypair = KeyPair::generate(PqAlgorithm::MlDsa65).unwrap();
        let data = vec![42u8; 100000];

        let signature = sign_data(&data, &keypair.private_key).unwrap();
        let is_valid = verify_signature(&data, &signature, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let keypair2 = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let data = b"Test message";

        let signature = sign_data(data, &keypair1.private_key).unwrap();
        let result = verify_signature(data, &signature, &keypair2.public_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let keypair = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let data = b"Original message";
        let tampered = b"Tampered message";

        let signature = sign_data(data, &keypair.private_key).unwrap();
        let result = verify_signature(tampered, &signature, &keypair.public_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_detached_signature() {
        let keypair = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let data = b"Message to sign";

        let sig_bytes = create_detached_signature(data, &keypair.private_key).unwrap();
        let is_valid = verify_detached_signature(data, &sig_bytes, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
        let data = b"Test";

        let signature = sign_data(data, &keypair.private_key).unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&signature).unwrap();
        let deserialized: Signature = bincode::deserialize(&serialized).unwrap();

        let is_valid = verify_signature(data, &deserialized, &keypair.public_key).unwrap();
        assert!(is_valid);
    }
}
