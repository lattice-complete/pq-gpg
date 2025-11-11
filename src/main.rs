//! Post-Quantum GPG CLI

use clap::{Args, Parser, Subcommand};
use pq_gpg::constants::PqAlgorithm;
use pq_gpg::prelude::*;
use pq_gpg::{armor, encryption, keyring::Keyring, signature};
use std::path::PathBuf;
use std::fs;

#[derive(Parser)]
#[command(name = "pq-gpg")]
#[command(about = "A post-quantum implementation of GPG")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    GenKey(GenKeyArgs),
    /// List keys in keyring
    ListKeys(ListKeysArgs),
    /// Export public key
    Export(ExportArgs),
    /// Import key
    Import(ImportArgs),
    /// Encrypt data
    Encrypt(EncryptArgs),
    /// Decrypt data
    Decrypt(DecryptArgs),
    /// Sign data
    Sign(SignArgs),
    /// Verify signature
    Verify(VerifyArgs),
}

#[derive(Args)]
struct GenKeyArgs {
    /// Key algorithm (ml-kem-512, ml-kem-768, ml-kem-1024, ml-dsa-44, ml-dsa-65, ml-dsa-87)
    #[arg(long, default_value = "ml-kem-768")]
    algorithm: String,
    
    /// User ID
    #[arg(long)]
    user_id: String,
    
    /// Output file for the key
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct ListKeysArgs {
    /// Show secret keys instead of public keys
    #[arg(long)]
    secret: bool,
}

#[derive(Args)]
struct ExportArgs {
    /// Key ID or user ID to export
    key_id: String,
    
    /// Output file
    #[arg(long)]
    output: Option<PathBuf>,
    
    /// Export in ASCII armor format
    #[arg(long)]
    armor: bool,
}

#[derive(Args)]
struct ImportArgs {
    /// File to import
    file: PathBuf,
}

#[derive(Args)]
struct EncryptArgs {
    /// Recipient key ID
    #[arg(long)]
    recipient: String,
    
    /// Input file
    input: PathBuf,
    
    /// Output file
    #[arg(long)]
    output: Option<PathBuf>,
    
    /// Use ASCII armor format
    #[arg(long)]
    armor: bool,
}

#[derive(Args)]
struct DecryptArgs {
    /// Input file
    input: PathBuf,
    
    /// Output file
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct SignArgs {
    /// Input file to sign
    input: PathBuf,
    
    /// Output file for signature
    #[arg(long)]
    output: Option<PathBuf>,
    
    /// Create detached signature
    #[arg(long)]
    detach: bool,
    
    /// Use ASCII armor format
    #[arg(long)]
    armor: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Signature file
    signature: PathBuf,
    
    /// File that was signed (for detached signatures)
    file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::GenKey(args) => handle_gen_key(args).await,
        Commands::ListKeys(args) => handle_list_keys(args).await,
        Commands::Export(args) => handle_export(args).await,
        Commands::Import(args) => handle_import(args).await,
        Commands::Encrypt(args) => handle_encrypt(args).await,
        Commands::Decrypt(args) => handle_decrypt(args).await,
        Commands::Sign(args) => handle_sign(args).await,
        Commands::Verify(args) => handle_verify(args).await,
    }
}

async fn handle_gen_key(args: GenKeyArgs) -> Result<()> {
    let algorithm = parse_algorithm(&args.algorithm)?;

    println!("Generating {} key pair for user '{}'...", args.algorithm, args.user_id);
    let keypair = KeyPair::generate(algorithm)?;

    println!("\nKey generated successfully!");
    println!("User ID: {}", args.user_id);
    println!("Key ID: {}", keypair.public_key.key_id_hex());
    println!("Fingerprint: {}", keypair.public_key.fingerprint_hex());

    // Save to keyring
    let mut keyring = Keyring::default()?;
    keyring.add_keypair(&keypair)?;
    println!("\nKey added to keyring at: {}", Keyring::default_dir()?.display());

    // Optionally save to specific file
    if let Some(output) = args.output {
        let serialized = bincode::serialize(&keypair)
            .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;
        fs::write(&output, serialized)
            .map_err(|e| PqGpgError::IoError(e))?;
        println!("Key also saved to: {}", output.display());
    }

    Ok(())
}

async fn handle_list_keys(args: ListKeysArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    if args.secret {
        println!("Secret keys in keyring:");
        let keys = keyring.list_private_keys();
        if keys.is_empty() {
            println!("  (no secret keys found)");
        } else {
            for key_id in keys {
                if let Some(key) = keyring.get_private_key(&key_id) {
                    println!("  Key ID: {}", key_id);
                    println!("  Algorithm: {:?}", key.public_key.algorithm);
                    println!("  Fingerprint: {}", key.public_key.fingerprint_hex());
                    println!();
                }
            }
        }
    } else {
        println!("Public keys in keyring:");
        let keys = keyring.list_public_keys();
        if keys.is_empty() {
            println!("  (no public keys found)");
        } else {
            for key_id in keys {
                if let Some(key) = keyring.get_public_key(&key_id) {
                    println!("  Key ID: {}", key_id);
                    println!("  Algorithm: {:?}", key.algorithm);
                    println!("  Fingerprint: {}", key.fingerprint_hex());
                    println!();
                }
            }
        }
    }

    Ok(())
}

async fn handle_export(args: ExportArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    let output = args.output.unwrap_or_else(|| {
        PathBuf::from(format!("{}.pub", args.key_id))
    });

    keyring.export_public_key(&args.key_id, &output)?;

    if args.armor {
        // Re-encode as ASCII armor
        let data = fs::read(&output)?;
        let armored = armor::encode(&data, armor::ArmorType::PublicKey)?;
        fs::write(&output, armored)?;
    }

    println!("Key {} exported to: {}", args.key_id, output.display());

    Ok(())
}

async fn handle_import(args: ImportArgs) -> Result<()> {
    let mut keyring = Keyring::default()?;

    // Check if file is ASCII armored
    let data = fs::read(&args.file)?;
    let key_data = if let Ok(contents) = std::str::from_utf8(&data) {
        if contents.contains("-----BEGIN PGP") {
            // Decode armor
            let (decoded, _) = armor::decode(contents)?;
            decoded
        } else {
            data
        }
    } else {
        data
    };

    // Import the key
    let key: PublicKey = bincode::deserialize(&key_data)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    let key_id = key.key_id_hex();
    keyring.add_public_key(&key)?;

    println!("Key {} imported successfully!", key_id);
    println!("Fingerprint: {}", key.fingerprint_hex());

    Ok(())
}

async fn handle_encrypt(args: EncryptArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    // Get recipient's public key
    let recipient_key = keyring.get_public_key(&args.recipient)
        .ok_or_else(|| PqGpgError::KeyError(format!("Recipient key not found: {}", args.recipient)))?;

    println!("Encrypting for recipient: {}", args.recipient);

    let output = args.output.unwrap_or_else(|| {
        let mut path = args.input.clone();
        path.set_extension("pgp");
        path
    });

    // Read input file
    let plaintext = fs::read(&args.input)?;

    // Encrypt
    let encrypted = encryption::encrypt_message(&plaintext, recipient_key)?;

    // Serialize
    let mut data = bincode::serialize(&encrypted)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    // Apply armor if requested
    if args.armor {
        let armored = armor::encode(&data, armor::ArmorType::Message)?;
        data = armored.into_bytes();
    }

    fs::write(&output, data)?;

    println!("File encrypted successfully!");
    println!("Output: {}", output.display());

    Ok(())
}

async fn handle_decrypt(args: DecryptArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    let output = args.output.unwrap_or_else(|| {
        let mut path = args.input.clone();
        path.set_extension("dec");
        path
    });

    // Read encrypted file
    let mut data = fs::read(&args.input)?;

    // Check if armored
    if let Ok(contents) = std::str::from_utf8(&data) {
        if contents.contains("-----BEGIN PGP") {
            let (decoded, _) = armor::decode(contents)?;
            data = decoded;
        }
    }

    // Deserialize
    let encrypted: encryption::EncryptedMessage = bincode::deserialize(&data)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    // Find the private key
    let key_ids = keyring.list_private_keys();
    let mut decrypted = None;

    for key_id in key_ids {
        if let Some(private_key) = keyring.get_private_key(&key_id) {
            if let Ok(plaintext) = encryption::decrypt_message(&encrypted, private_key) {
                decrypted = Some(plaintext);
                println!("Decrypted with key: {}", key_id);
                break;
            }
        }
    }

    let plaintext = decrypted
        .ok_or_else(|| PqGpgError::DecryptionFailed("No suitable key found".to_string()))?;

    fs::write(&output, plaintext)?;

    println!("File decrypted successfully!");
    println!("Output: {}", output.display());

    Ok(())
}

async fn handle_sign(args: SignArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    // Get the first available private key for signing
    let key_ids = keyring.list_private_keys();
    if key_ids.is_empty() {
        return Err(PqGpgError::KeyError("No private keys found in keyring".to_string()));
    }

    let private_key = keyring.get_private_key(&key_ids[0])
        .ok_or_else(|| PqGpgError::KeyError("Failed to load private key".to_string()))?;

    println!("Signing with key: {}", key_ids[0]);

    let output = args.output.unwrap_or_else(|| {
        let mut path = args.input.clone();
        if args.detach {
            path.set_extension("sig");
        } else {
            path.set_extension("signed");
        }
        path
    });

    // Read input file
    let data = fs::read(&args.input)?;

    // Sign
    let sig = signature::sign_data(&data, private_key)?;

    // Serialize signature
    let sig_data = bincode::serialize(&sig)
        .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

    let mut output_data = if args.detach {
        // Detached signature
        sig_data
    } else {
        // Embedded signature
        let mut result = Vec::new();
        result.extend_from_slice(&(data.len() as u64).to_le_bytes());
        result.extend_from_slice(&data);
        result.extend_from_slice(&sig_data);
        result
    };

    // Apply armor if requested
    if args.armor {
        let armored = armor::encode(&output_data, armor::ArmorType::Signature)?;
        output_data = armored.into_bytes();
    }

    fs::write(&output, output_data)?;

    println!("File signed successfully!");
    println!("Output: {}", output.display());

    Ok(())
}

async fn handle_verify(args: VerifyArgs) -> Result<()> {
    let keyring = Keyring::default()?;

    // Read signature file
    let mut sig_data = fs::read(&args.signature)?;

    // Check if armored
    if let Ok(contents) = std::str::from_utf8(&sig_data) {
        if contents.contains("-----BEGIN PGP") {
            let (decoded, _) = armor::decode(contents)?;
            sig_data = decoded;
        }
    }

    // Determine if detached or embedded signature
    let (data, sig) = if let Some(data_file) = args.file {
        // Detached signature
        let data = fs::read(&data_file)?;
        let sig: signature::Signature = bincode::deserialize(&sig_data)
            .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;
        (data, sig)
    } else {
        // Embedded signature
        if sig_data.len() < 8 {
            return Err(PqGpgError::InvalidPacket("Invalid signature format".to_string()));
        }

        let data_len = u64::from_le_bytes(sig_data[..8].try_into().unwrap()) as usize;
        if sig_data.len() < 8 + data_len {
            return Err(PqGpgError::InvalidPacket("Invalid signature format".to_string()));
        }

        let data = sig_data[8..8 + data_len].to_vec();
        let sig: signature::Signature = bincode::deserialize(&sig_data[8 + data_len..])
            .map_err(|e| PqGpgError::SerializationError(format!("{}", e)))?;

        (data, sig)
    };

    // Find the public key
    let public_key = keyring.get_public_key(&hex::encode(&sig.key_id))
        .ok_or_else(|| PqGpgError::KeyError(format!("Public key not found for signature")))?;

    // Verify
    let is_valid = signature::verify_signature(&data, &sig, public_key)?;

    if is_valid {
        println!("✓ Signature is VALID");
        println!("Signed by: {}", hex::encode(&sig.key_id));
        println!("Signed at: {}", sig.created_at);
    } else {
        println!("✗ Signature is INVALID");
        return Err(PqGpgError::SignatureVerificationFailed("Invalid signature".to_string()));
    }

    Ok(())
}

fn parse_algorithm(algorithm: &str) -> Result<PqAlgorithm> {
    match algorithm.to_lowercase().as_str() {
        "ml-kem-512" => Ok(PqAlgorithm::MlKem512),
        "ml-kem-768" => Ok(PqAlgorithm::MlKem768),
        "ml-kem-1024" => Ok(PqAlgorithm::MlKem1024),
        "ml-dsa-44" => Ok(PqAlgorithm::MlDsa44),
        "ml-dsa-65" => Ok(PqAlgorithm::MlDsa65),
        "ml-dsa-87" => Ok(PqAlgorithm::MlDsa87),
        "slh-dsa-sha2-128s" => Ok(PqAlgorithm::SlhDsaSha2_128s),
        "slh-dsa-sha2-256s" => Ok(PqAlgorithm::SlhDsaSha2_256s),
        _ => Err(PqGpgError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}
