//! OpenPGP packet handling with post-quantum extensions

use crate::constants::{PacketType, PqAlgorithm};
use crate::error::{PqGpgError, Result};
use crate::key::{PublicKey, PrivateKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Packet {
    PublicKey(PublicKeyPacket),
    SecretKey(SecretKeyPacket),
    Signature(SignaturePacket),
    PublicKeyEncryptedSessionKey(PkeskPacket),
    LiteralData(LiteralDataPacket),
    SymmetricallyEncryptedIntegrityProtectedData(SeipdPacket),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyPacket {
    pub version: u8,
    pub creation_time: u32,
    pub algorithm: PqAlgorithm,
    pub public_key_material: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyPacket {
    pub public_key: PublicKeyPacket,
    pub secret_key_material: Vec<u8>,
    pub encrypted: bool,
    pub checksum: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePacket {
    pub version: u8,
    pub signature_type: u8,
    pub public_key_algorithm: PqAlgorithm,
    pub hash_algorithm: u8,
    pub hashed_subpackets: Vec<u8>,
    pub unhashed_subpackets: Vec<u8>,
    pub signature_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkeskPacket {
    pub version: u8,
    pub key_id: Vec<u8>,
    pub public_key_algorithm: PqAlgorithm,
    pub encrypted_session_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteralDataPacket {
    pub format: u8,
    pub filename: String,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeipdPacket {
    pub version: u8,
    pub encrypted_data: Vec<u8>,
}

impl Packet {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| PqGpgError::SerializationError(e))
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| PqGpgError::SerializationError(e))
    }
    
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::PublicKey(_) => PacketType::PublicKey,
            Packet::SecretKey(_) => PacketType::SecretKey,
            Packet::Signature(_) => PacketType::Signature,
            Packet::PublicKeyEncryptedSessionKey(_) => PacketType::PublicKeyEncryptedSessionKey,
            Packet::LiteralData(_) => PacketType::LiteralData,
            Packet::SymmetricallyEncryptedIntegrityProtectedData(_) => PacketType::SymmetricallyEncryptedIntegrityProtectedData,
        }
    }
}

impl From<&PublicKey> for PublicKeyPacket {
    fn from(key: &PublicKey) -> Self {
        Self {
            version: 6, // OpenPGP v6 for post-quantum
            creation_time: key.creation_time.timestamp() as u32,
            algorithm: key.algorithm,
            public_key_material: key.key_data.clone(),
        }
    }
}

impl From<&PrivateKey> for SecretKeyPacket {
    fn from(key: &PrivateKey) -> Self {
        Self {
            public_key: (&key.public_key).into(),
            secret_key_material: key.secret_data.clone(),
            encrypted: key.encrypted,
            checksum: None, // TODO: Implement checksum calculation
        }
    }
}
