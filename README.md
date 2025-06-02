<h1 align="center">Post-Quantum GPG (pq-gpg)</h1>
<p align="center">
    <a href="https://github.com/lattice-complete/Lazarus?tab=Apache-2.0-1-ov-file"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
</p>
<p align="center">A modern implementation of OpenPGP with post-quantum cryptographic algorithms, built in Rust. This project implements the specifications from <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html">draft-ietf-openpgp-pqc-10</a> and provides a GPG-compatible command-line interface.</p>

<p align="center">
  <img src="./assets/pq-gpg.png" alt="pq-gpg" width="200">
</p>

## Features

- **Post-Quantum Algorithms**:
  - ML-KEM (Kyber) for key encapsulation: 512, 768, 1024-bit variants
  - ML-DSA (Dilithium) for digital signatures: 44, 65, 87-bit security levels
  - SLH-DSA (SPHINCS+) for stateless signatures: SHA2-128s, SHA2-256s variants

- **OpenPGP Compatibility**: 
  - Implements OpenPGP v6 packet format with post-quantum extensions
  - GPG-compatible command-line interface
  - ASCII armor support for text-based key/message exchange

- **Security Features**:
  - Hybrid encryption combining classical and post-quantum algorithms
  - Integrity protection for encrypted messages
  - Digital signatures with post-quantum resistance

## Installation

### Prerequisites

- Rust 1.70+ 
- Cargo package manager

### Build from Source

```bash
git clone https://github.com/your-username/pq-gpg.git
cd pq-gpg
cargo build --release
```

The binary will be available at `target/release/pq-gpg`.

### Install via Cargo

```bash
cargo install --path .
```

## Quick Start

### Generate a Key Pair

```bash
# Generate ML-KEM-768 key pair
pq-gpg gen-key --algorithm ml-kem-768 --user-id "Alice <alice@example.com>"

# Generate ML-DSA-65 signing key
pq-gpg gen-key --algorithm ml-dsa-65 --user-id "Bob <bob@example.com>"
```

### List Keys

```bash
# List public keys
pq-gpg list-keys

# List secret keys
pq-gpg list-keys --secret
```

### Encrypt and Decrypt

```bash
# Encrypt a file
pq-gpg encrypt --recipient alice@example.com --armor message.txt

# Decrypt a file
pq-gpg decrypt message.txt.asc
```

### Sign and Verify

```bash
# Create a detached signature
pq-gpg sign --detach --armor document.pdf

# Verify a signature
pq-gpg verify document.pdf.asc document.pdf
```

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)

| Algorithm | Security Level | Key Size (bytes) | Ciphertext Size (bytes) |
|-----------|----------------|------------------|-------------------------|
| ML-KEM-512 | 128-bit | 800 / 1632 | 768 |
| ML-KEM-768 | 192-bit | 1184 / 2400 | 1088 |
| ML-KEM-1024 | 256-bit | 1568 / 3168 | 1568 |

### Digital Signature Schemes

| Algorithm | Security Level | Public Key (bytes) | Signature Size (bytes) |
|-----------|----------------|-------------------|------------------------|
| ML-DSA-44 | 128-bit | 1312 | 2420 |
| ML-DSA-65 | 192-bit | 1952 | 3309 |
| ML-DSA-87 | 256-bit | 2592 | 4627 |
| SLH-DSA-SHA2-128s | 128-bit | 32 | 7856 |
| SLH-DSA-SHA2-256s | 256-bit | 64 | 29792 |

## Architecture

```
pq-gpg/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── main.rs             # CLI application
│   ├── crypto/             # Cryptographic primitives
│   │   ├── mod.rs          # Crypto module interface
│   │   ├── kyber.rs        # ML-KEM implementation
│   │   ├── dilithium.rs    # ML-DSA implementation
│   │   ├── sphincs.rs      # SLH-DSA implementation
│   │   └── hybrid.rs       # Hybrid crypto schemes
│   ├── packet.rs           # OpenPGP packet handling
│   ├── key.rs              # Key management
│   ├── signature.rs        # Digital signatures
│   ├── encryption.rs       # Encryption/decryption
│   ├── armor.rs            # ASCII armor encoding
│   ├── constants.rs        # Algorithm constants
│   └── error.rs            # Error types
└── tests/                  # Integration tests
```

## Standards Compliance

This implementation follows:

- [RFC 4880](https://tools.ietf.org/rfc/rfc4880.txt): OpenPGP Message Format
- [draft-ietf-openpgp-pqc-10](https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html): Post-Quantum Cryptography in OpenPGP
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography): ML-KEM, ML-DSA, SLH-DSA

## Security Considerations

- **Hybrid Security**: Uses both classical and post-quantum algorithms for defense-in-depth
- **Forward Secrecy**: Session keys use ephemeral key exchange
- **Side-Channel Resistance**: Constant-time implementations where possible
- **Memory Safety**: Built in Rust for memory-safe cryptographic operations

## Compatibility

### GPG Interoperability

While this implementation uses post-quantum algorithms not yet supported by standard GPG, it maintains compatibility at the protocol level:

- Same command-line interface patterns
- Compatible ASCII armor format
- Standard OpenPGP packet structure (with PQ extensions)

### Migration Path

1. **Hybrid Mode**: Use both classical and PQ algorithms during transition
2. **Key Rollover**: Gradual migration from RSA/ECC to PQ algorithms  
3. **Backward Compatibility**: Support for reading legacy GPG files

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# Benchmark tests
cargo bench
```

### Code Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] Complete SPHINCS+ implementation
- [ ] Keyring management and storage
- [ ] Web of trust support
- [ ] Hardware security module (HSM) integration
- [ ] GUI application
- [ ] Network keyserver support
- [ ] Smart card integration

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [IETF OpenPGP Working Group](https://datatracker.ietf.org/wg/openpgp/about/)
- [GnuPG Project](https://gnupg.org/) for the original GPG implementation
- [GPG Tools](https://gpgtools.org/) for user interface inspiration

## Disclaimer

⚠️ **This is experimental software.** While based on NIST-standardized algorithms, this implementation has not undergone security audit. Use at your own risk for production systems.