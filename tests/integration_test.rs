//! Integration tests for pq-gpg
//!
//! These tests verify end-to-end workflows including key generation,
//! encryption, decryption, signing, and verification.

use pq_gpg::constants::PqAlgorithm;
use pq_gpg::{armor, encryption, signature};
use pq_gpg::key::KeyPair;
use pq_gpg::prelude::*;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_key_generation_all_algorithms() {
    let algorithms = vec![
        PqAlgorithm::MlKem512,
        PqAlgorithm::MlKem768,
        PqAlgorithm::MlKem1024,
        PqAlgorithm::MlDsa44,
        PqAlgorithm::MlDsa65,
        PqAlgorithm::MlDsa87,
        PqAlgorithm::SlhDsaSha2_128s,
        PqAlgorithm::SlhDsaSha2_256s,
    ];

    for algo in algorithms {
        let result = KeyPair::generate(algo);
        assert!(result.is_ok(), "Failed to generate keypair for {:?}", algo);

        let keypair = result.unwrap();
        assert_eq!(keypair.public_key.algorithm, algo);
        assert!(!keypair.public_key.key_material.is_empty());
        assert!(!keypair.private_key.secret_material.is_empty());

        // Verify key ID and fingerprint are generated
        assert!(keypair.public_key.key_id().len() > 0);
        assert!(keypair.public_key.fingerprint().len() > 0);
    }
}

#[test]
fn test_encryption_decryption_workflow() {
    let algorithms = vec![
        PqAlgorithm::MlKem512,
        PqAlgorithm::MlKem768,
        PqAlgorithm::MlKem1024,
    ];

    for algo in algorithms {
        let keypair = KeyPair::generate(algo).unwrap();
        let plaintext = b"Test message for encryption";

        // Encrypt
        let encrypted = encryption::encrypt_message(plaintext, &keypair.public_key).unwrap();
        assert_eq!(encrypted.algorithm, algo);
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.encapsulated_key.is_empty());

        // Decrypt
        let decrypted = encryption::decrypt_message(&encrypted, &keypair.private_key).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}

#[test]
fn test_signature_workflow() {
    let algorithms = vec![
        PqAlgorithm::MlDsa44,
        PqAlgorithm::MlDsa65,
        PqAlgorithm::MlDsa87,
    ];

    for algo in algorithms {
        let keypair = KeyPair::generate(algo).unwrap();
        let data = b"Test data for signing";

        // Sign
        let sig = signature::sign_data(data, &keypair.private_key).unwrap();
        assert_eq!(sig.algorithm, algo);
        assert!(!sig.signature_data.is_empty());

        // Verify
        let is_valid = signature::verify_signature(data, &sig, &keypair.public_key).unwrap();
        assert!(is_valid);

        // Verify with tampered data fails
        let tampered = b"Tampered data";
        let result = signature::verify_signature(tampered, &sig, &keypair.public_key);
        assert!(result.is_err());
    }
}

#[test]
fn test_armor_encoding_decoding() {
    let test_data = b"Test data for armor encoding";

    let armor_types = vec![
        armor::ArmorType::Message,
        armor::ArmorType::PublicKey,
        armor::ArmorType::PrivateKey,
        armor::ArmorType::Signature,
    ];

    for armor_type in armor_types {
        // Encode
        let armored = armor::encode(test_data, armor_type).unwrap();
        assert!(armored.contains("-----BEGIN"));
        assert!(armored.contains("-----END"));

        // Decode
        let (decoded, decoded_type) = armor::decode(&armored).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
        assert_eq!(armor_type, decoded_type);
    }
}

#[test]
fn test_large_message_encryption() {
    let keypair = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();
    let large_plaintext = vec![42u8; 1_000_000]; // 1 MB

    let encrypted = encryption::encrypt_message(&large_plaintext, &keypair.public_key).unwrap();
    let decrypted = encryption::decrypt_message(&encrypted, &keypair.private_key).unwrap();

    assert_eq!(large_plaintext, decrypted);
}

#[test]
fn test_file_encryption_decryption() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("plaintext.txt");
    let encrypted_path = temp_dir.path().join("encrypted.pgp");
    let output_path = temp_dir.path().join("decrypted.txt");

    let plaintext = b"Secret file content";
    fs::write(&input_path, plaintext).unwrap();

    let keypair = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();

    // Encrypt file
    encryption::encrypt_file(&input_path, &encrypted_path, &keypair.public_key).unwrap();
    assert!(encrypted_path.exists());

    // Decrypt file
    encryption::decrypt_file(&encrypted_path, &output_path, &keypair.private_key).unwrap();
    assert!(output_path.exists());

    // Verify content
    let decrypted = fs::read(&output_path).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_file_signing_verification() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("document.txt");
    let signature_path = temp_dir.path().join("document.sig");

    let data = b"Document to be signed";
    fs::write(&input_path, data).unwrap();

    let keypair = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();

    // Sign file
    signature::sign_file(&input_path, &signature_path, &keypair.private_key, true).unwrap();
    assert!(signature_path.exists());

    // Verify file
    let is_valid = signature::verify_file(
        &input_path,
        Some(&signature_path),
        &keypair.public_key
    ).unwrap();
    assert!(is_valid);
}

#[test]
fn test_wrong_key_decryption_fails() {
    let keypair1 = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
    let keypair2 = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();

    let plaintext = b"Secret message";
    let encrypted = encryption::encrypt_message(plaintext, &keypair1.public_key).unwrap();

    // Trying to decrypt with wrong key should fail
    let result = encryption::decrypt_message(&encrypted, &keypair2.private_key);
    assert!(result.is_err());
}

#[test]
fn test_wrong_key_verification_fails() {
    let keypair1 = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();
    let keypair2 = KeyPair::generate(PqAlgorithm::MlDsa44).unwrap();

    let data = b"Test data";
    let sig = signature::sign_data(data, &keypair1.private_key).unwrap();

    // Trying to verify with wrong key should fail
    let result = signature::verify_signature(data, &sig, &keypair2.public_key);
    assert!(result.is_err());
}

#[test]
fn test_serialization_roundtrip() {
    let keypair = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();

    // Serialize public key
    let pub_serialized = bincode::serialize(&keypair.public_key).unwrap();
    let pub_deserialized: pq_gpg::key::PublicKey = bincode::deserialize(&pub_serialized).unwrap();
    assert_eq!(keypair.public_key.key_id(), pub_deserialized.key_id());

    // Serialize private key
    let priv_serialized = bincode::serialize(&keypair.private_key).unwrap();
    let priv_deserialized: pq_gpg::key::PrivateKey = bincode::deserialize(&priv_serialized).unwrap();
    assert_eq!(
        keypair.private_key.public_key.key_id(),
        priv_deserialized.public_key.key_id()
    );
}

#[test]
fn test_hybrid_kem() {
    use pq_gpg::crypto::hybrid::HybridKem;

    let hybrid = HybridKem::new(PqAlgorithm::MlKem768);
    let (pk, sk) = hybrid.keygen().unwrap();

    let (ct, ss1) = hybrid.encaps(&pk).unwrap();
    let ss2 = hybrid.decaps(&sk, &ct).unwrap();

    assert_eq!(ss1, ss2);
}

#[test]
fn test_detached_signature_workflow() {
    let keypair = KeyPair::generate(PqAlgorithm::MlDsa65).unwrap();
    let data = b"Important document content";

    // Create detached signature
    let sig_bytes = signature::create_detached_signature(data, &keypair.private_key).unwrap();

    // Verify detached signature
    let is_valid = signature::verify_detached_signature(data, &sig_bytes, &keypair.public_key).unwrap();
    assert!(is_valid);
}

#[test]
fn test_armor_with_encryption() {
    let keypair = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
    let plaintext = b"Message to encrypt and armor";

    // Encrypt
    let encrypted = encryption::encrypt_message(plaintext, &keypair.public_key).unwrap();
    let serialized = bincode::serialize(&encrypted).unwrap();

    // Armor
    let armored = armor::encode(&serialized, armor::ArmorType::Message).unwrap();
    assert!(armored.contains("BEGIN PGP MESSAGE"));

    // Dearmor
    let (decoded, _) = armor::decode(&armored).unwrap();

    // Decrypt
    let deserialized: encryption::EncryptedMessage = bincode::deserialize(&decoded).unwrap();
    let decrypted = encryption::decrypt_message(&deserialized, &keypair.private_key).unwrap();

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_key_fingerprint_uniqueness() {
    let keypair1 = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();
    let keypair2 = KeyPair::generate(PqAlgorithm::MlKem768).unwrap();

    assert_ne!(keypair1.public_key.fingerprint(), keypair2.public_key.fingerprint());
    assert_ne!(keypair1.public_key.key_id(), keypair2.public_key.key_id());
}
