//! Keyring management for storing and retrieving keys
//!
//! This module provides simple file-based keyring storage for
//! public and private keys.

use crate::error::{PqGpgError, Result};
use crate::key::{KeyPair, PrivateKey, PublicKey};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Keyring for managing public and private keys
pub struct Keyring {
    pub_keys: HashMap<String, PublicKey>,
    priv_keys: HashMap<String, PrivateKey>,
    keyring_dir: PathBuf,
}

impl Keyring {
    /// Create a new keyring at the specified directory
    pub fn new<P: AsRef<Path>>(keyring_dir: P) -> Result<Self> {
        let keyring_dir = keyring_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !keyring_dir.exists() {
            fs::create_dir_all(&keyring_dir)
                .map_err(|e| PqGpgError::IoError(e))?;
        }

        let mut keyring = Keyring {
            pub_keys: HashMap::new(),
            priv_keys: HashMap::new(),
            keyring_dir,
        };

        // Load existing keys
        keyring.load_keys()?;

        Ok(keyring)
    }

    /// Get the default keyring directory
    pub fn default_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| PqGpgError::KeyError("Cannot determine home directory".to_string()))?;

        Ok(home.join(".pq-gpg"))
    }

    /// Create or open the default keyring
    pub fn default() -> Result<Self> {
        let dir = Self::default_dir()?;
        Self::new(dir)
    }

    /// Add a keypair to the keyring
    pub fn add_keypair(&mut self, keypair: &KeyPair) -> Result<()> {
        let key_id = keypair.public.key_id_hex();

        // Save public key
        let pub_path = self.keyring_dir.join(format!("{}.pub", key_id));
        let pub_data = bincode::serialize(&keypair.public)
            .map_err(|e| PqGpgError::SerializationError(e.to_string()))?;
        fs::write(&pub_path, pub_data)
            .map_err(|e| PqGpgError::IoError(e))?;

        // Save private key
        let priv_path = self.keyring_dir.join(format!("{}.key", key_id));
        let priv_data = bincode::serialize(&keypair.private)
            .map_err(|e| PqGpgError::SerializationError(e.to_string()))?;
        fs::write(&priv_path, priv_data)
            .map_err(|e| PqGpgError::IoError(e))?;

        // Add to memory
        self.pub_keys.insert(key_id.clone(), keypair.public.clone());
        self.priv_keys.insert(key_id, keypair.private.clone());

        Ok(())
    }

    /// Add a public key to the keyring
    pub fn add_public_key(&mut self, key: &PublicKey) -> Result<()> {
        let key_id = key.key_id_hex();

        let pub_path = self.keyring_dir.join(format!("{}.pub", key_id));
        let pub_data = bincode::serialize(key)
            .map_err(|e| PqGpgError::SerializationError(e.to_string()))?;
        fs::write(&pub_path, pub_data)
            .map_err(|e| PqGpgError::IoError(e))?;

        self.pub_keys.insert(key_id, key.clone());

        Ok(())
    }

    /// Get a public key by key ID (hex string)
    pub fn get_public_key(&self, key_id: &str) -> Option<&PublicKey> {
        self.pub_keys.get(key_id)
    }

    /// Get a private key by key ID (hex string)
    pub fn get_private_key(&self, key_id: &str) -> Option<&PrivateKey> {
        self.priv_keys.get(key_id)
    }

    /// List all public key IDs
    pub fn list_public_keys(&self) -> Vec<String> {
        self.pub_keys.keys().cloned().collect()
    }

    /// List all private key IDs
    pub fn list_private_keys(&self) -> Vec<String> {
        self.priv_keys.keys().cloned().collect()
    }

    /// Load all keys from the keyring directory
    fn load_keys(&mut self) -> Result<()> {
        if !self.keyring_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.keyring_dir)
            .map_err(|e| PqGpgError::IoError(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| PqGpgError::IoError(e))?;
            let path = entry.path();

            if let Some(ext) = path.extension() {
                if ext == "pub" {
                    // Load public key
                    if let Ok(data) = fs::read(&path) {
                        if let Ok(key) = bincode::deserialize::<PublicKey>(&data) {
                            self.pub_keys.insert(key.key_id_hex(), key);
                        }
                    }
                } else if ext == "key" {
                    // Load private key
                    if let Ok(data) = fs::read(&path) {
                        if let Ok(key) = bincode::deserialize::<PrivateKey>(&data) {
                            self.priv_keys.insert(key.public_key.key_id_hex(), key);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Export a public key to a file
    pub fn export_public_key(&self, key_id: &str, output: &Path) -> Result<()> {
        let key = self.get_public_key(key_id)
            .ok_or_else(|| PqGpgError::KeyError(format!("Key not found: {}", key_id)))?;

        let data = bincode::serialize(key)
            .map_err(|e| PqGpgError::SerializationError(e.to_string()))?;

        fs::write(output, data)
            .map_err(|e| PqGpgError::IoError(e))?;

        Ok(())
    }

    /// Import a public key from a file
    pub fn import_public_key(&mut self, input: &Path) -> Result<String> {
        let data = fs::read(input)
            .map_err(|e| PqGpgError::IoError(e))?;

        let key: PublicKey = bincode::deserialize(&data)
            .map_err(|e| PqGpgError::SerializationError(e.to_string()))?;

        let key_id = key.key_id_hex();
        self.add_public_key(&key)?;

        Ok(key_id)
    }
}

// Add dirs crate for home directory detection
// This will need to be added to Cargo.toml

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PqAlgorithm;
    use tempfile::TempDir;

    #[test]
    fn test_keyring_creation() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = Keyring::new(temp_dir.path()).unwrap();
        assert_eq!(keyring.list_public_keys().len(), 0);
    }

    #[test]
    fn test_add_and_retrieve_keypair() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::new(temp_dir.path()).unwrap();

        let keypair = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let key_id = keypair.public_key.key_id_hex();

        keyring.add_keypair(&keypair).unwrap();

        assert!(keyring.get_public_key(&key_id).is_some());
        assert!(keyring.get_private_key(&key_id).is_some());
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();

        let keypair = KeyPair::generate(PqAlgorithm::MlKem512).unwrap();
        let key_id = keypair.public_key.key_id_hex();

        // Create keyring and add key
        {
            let mut keyring = Keyring::new(temp_dir.path()).unwrap();
            keyring.add_keypair(&keypair).unwrap();
        }

        // Create new keyring and verify key is loaded
        {
            let keyring = Keyring::new(temp_dir.path()).unwrap();
            assert!(keyring.get_public_key(&key_id).is_some());
        }
    }
}
