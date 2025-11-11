//! Post-Quantum GPG Implementation
//! 
//! A modern implementation of OpenPGP with post-quantum cryptographic algorithms
//! as specified in draft-ietf-openpgp-pqc-10.

pub mod crypto;
pub mod packet;
pub mod key;
pub mod armor;
pub mod signature;
pub mod encryption;
pub mod keyring;
pub mod error;
pub mod constants;

pub use error::{PqGpgError, Result};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::crypto::*;
    pub use crate::key::{KeyPair, PublicKey, PrivateKey};
    pub use crate::packet::Packet;
    pub use crate::signature::Signature;
    pub use crate::encryption::{encrypt_message, decrypt_message};
    pub use crate::error::{PqGpgError, Result};
}
