//! ASCII Armor encoding and decoding for OpenPGP messages
//!
//! Implements RFC 4880 ASCII Armor format for encoding binary
//! OpenPGP data as printable ASCII characters.

use crate::error::{PqGpgError, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};

/// Type of armored data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorType {
    Message,
    PublicKey,
    PrivateKey,
    Signature,
}

impl ArmorType {
    /// Get the header string for this armor type
    pub fn header(&self) -> &'static str {
        match self {
            ArmorType::Message => "-----BEGIN PGP MESSAGE-----",
            ArmorType::PublicKey => "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            ArmorType::PrivateKey => "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            ArmorType::Signature => "-----BEGIN PGP SIGNATURE-----",
        }
    }

    /// Get the footer string for this armor type
    pub fn footer(&self) -> &'static str {
        match self {
            ArmorType::Message => "-----END PGP MESSAGE-----",
            ArmorType::PublicKey => "-----END PGP PUBLIC KEY BLOCK-----",
            ArmorType::PrivateKey => "-----END PGP PRIVATE KEY BLOCK-----",
            ArmorType::Signature => "-----END PGP SIGNATURE-----",
        }
    }

    /// Parse armor type from header string
    pub fn from_header(header: &str) -> Option<Self> {
        if header.contains("MESSAGE") {
            Some(ArmorType::Message)
        } else if header.contains("PUBLIC KEY") {
            Some(ArmorType::PublicKey)
        } else if header.contains("PRIVATE KEY") {
            Some(ArmorType::PrivateKey)
        } else if header.contains("SIGNATURE") {
            Some(ArmorType::Signature)
        } else {
            None
        }
    }
}

/// Encode binary data with ASCII armor
pub fn encode(data: &[u8], armor_type: ArmorType) -> Result<String> {
    let mut result = String::new();

    // Add header
    result.push_str(armor_type.header());
    result.push_str("\n\n");

    // Encode data as base64
    let encoded = BASE64.encode(data);

    // Split into 64-character lines
    for chunk in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk)
            .map_err(|e| PqGpgError::SerializationError(format!("UTF-8 error: {}", e)))?);
        result.push('\n');
    }

    // Add CRC24 checksum
    let checksum = calculate_crc24(data);
    result.push('=');
    result.push_str(&BASE64.encode(&checksum.to_be_bytes()[1..])); // Use only 3 bytes
    result.push('\n');

    // Add footer
    result.push_str(armor_type.footer());
    result.push('\n');

    Ok(result)
}

/// Decode ASCII armored data
pub fn decode(armored: &str) -> Result<(Vec<u8>, ArmorType)> {
    let lines: Vec<&str> = armored.lines().collect();

    if lines.is_empty() {
        return Err(PqGpgError::InvalidPacket("Empty armored data".to_string()));
    }

    // Find header
    let header_line = lines.iter()
        .find(|l| l.starts_with("-----BEGIN"))
        .ok_or_else(|| PqGpgError::InvalidPacket("No armor header found".to_string()))?;

    let armor_type = ArmorType::from_header(header_line)
        .ok_or_else(|| PqGpgError::InvalidPacket("Unknown armor type".to_string()))?;

    // Find footer
    let footer_line = lines.iter()
        .find(|l| l.starts_with("-----END"))
        .ok_or_else(|| PqGpgError::InvalidPacket("No armor footer found".to_string()))?;

    // Extract base64 data between header and footer
    let start_idx = lines.iter().position(|l| l.starts_with("-----BEGIN")).unwrap() + 1;
    let end_idx = lines.iter().position(|l| l.starts_with("-----END")).unwrap();

    let mut base64_data = String::new();
    let mut checksum_line = None;

    for line in &lines[start_idx..end_idx] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('=') {
            checksum_line = Some(trimmed);
            break;
        }
        base64_data.push_str(trimmed);
    }

    // Decode base64
    let decoded = BASE64.decode(base64_data.as_bytes())
        .map_err(|e| PqGpgError::SerializationError(format!("Base64 decode error: {}", e)))?;

    // Verify checksum if present
    if let Some(checksum) = checksum_line {
        let checksum_bytes = BASE64.decode(&checksum[1..])
            .map_err(|e| PqGpgError::SerializationError(format!("Checksum decode error: {}", e)))?;

        if checksum_bytes.len() == 3 {
            let expected_crc = calculate_crc24(&decoded);
            let actual_crc = u32::from_be_bytes([0, checksum_bytes[0], checksum_bytes[1], checksum_bytes[2]]);

            if expected_crc != actual_crc {
                return Err(PqGpgError::InvalidPacket("CRC24 checksum mismatch".to_string()));
            }
        }
    }

    Ok((decoded, armor_type))
}

/// Calculate CRC-24 checksum as specified in RFC 4880
fn calculate_crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0xB704CE;
    const CRC24_POLY: u32 = 0x1864CFB;

    let mut crc = CRC24_INIT;

    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0xFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_encode_decode() {
        let data = b"Hello, PQ-GPG!";
        let armored = encode(data, ArmorType::Message).unwrap();

        assert!(armored.contains("BEGIN PGP MESSAGE"));
        assert!(armored.contains("END PGP MESSAGE"));

        let (decoded, armor_type) = decode(&armored).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(armor_type, ArmorType::Message);
    }

    #[test]
    fn test_crc24() {
        let data = b"test data";
        let crc = calculate_crc24(data);
        assert!(crc <= 0xFFFFFF);
    }

    #[test]
    fn test_armor_types() {
        assert_eq!(ArmorType::from_header("-----BEGIN PGP MESSAGE-----"), Some(ArmorType::Message));
        assert_eq!(ArmorType::from_header("-----BEGIN PGP PUBLIC KEY BLOCK-----"), Some(ArmorType::PublicKey));
        assert_eq!(ArmorType::from_header("-----BEGIN PGP PRIVATE KEY BLOCK-----"), Some(ArmorType::PrivateKey));
        assert_eq!(ArmorType::from_header("-----BEGIN PGP SIGNATURE-----"), Some(ArmorType::Signature));
    }

    #[test]
    fn test_long_data() {
        let data = vec![0u8; 1000];
        let armored = encode(&data, ArmorType::Message).unwrap();
        let (decoded, _) = decode(&armored).unwrap();
        assert_eq!(decoded, data);
    }
}
