//! Constants defined in draft-ietf-openpgp-pqc-10

/// Post-Quantum Public Key Algorithm IDs
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAlgorithm {
    // ML-KEM (Kyber) variants
    MlKem512 = 105,
    MlKem768 = 106,
    MlKem1024 = 107,
    
    // ML-DSA (Dilithium) variants
    MlDsa44 = 108,
    MlDsa65 = 109,
    MlDsa87 = 110,
    
    // SLH-DSA (SPHINCS+) variants
    SlhDsaSha2_128s = 111,
    SlhDsaSha2_128f = 112,
    SlhDsaSha2_192s = 113,
    SlhDsaSha2_192f = 114,
    SlhDsaSha2_256s = 115,
    SlhDsaSha2_256f = 116,
}

/// Symmetric encryption algorithms
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    Aes128 = 7,
    Aes192 = 8,
    Aes256 = 9,
}

/// Hash algorithms
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
    Sha3_256 = 12,
    Sha3_512 = 14,
}

/// Packet types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    PublicKeyEncryptedSessionKey = 1,
    Signature = 2,
    SymmetricKeyEncryptedSessionKey = 3,
    OnePassSignature = 4,
    SecretKey = 5,
    PublicKey = 6,
    SecretSubkey = 7,
    CompressedData = 8,
    SymmetricallyEncryptedData = 9,
    Marker = 10,
    LiteralData = 11,
    Trust = 12,
    UserId = 13,
    PublicSubkey = 14,
    UserAttribute = 17,
    SymmetricallyEncryptedIntegrityProtectedData = 18,
    ModificationDetectionCode = 19,
}
