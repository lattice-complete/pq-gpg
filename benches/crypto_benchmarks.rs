//! Benchmarks for post-quantum cryptographic operations
//!
//! This benchmark suite measures the performance of key generation,
//! encryption, decryption, signing, and verification operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use pq_gpg::constants::PqAlgorithm;
use pq_gpg::{encryption, signature};
use pq_gpg::key::KeyPair;

fn benchmark_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");

    let kem_algorithms = vec![
        ("ML-KEM-512", PqAlgorithm::MlKem512),
        ("ML-KEM-768", PqAlgorithm::MlKem768),
        ("ML-KEM-1024", PqAlgorithm::MlKem1024),
    ];

    for (name, algo) in kem_algorithms {
        group.bench_with_input(BenchmarkId::new("KEM", name), &algo, |b, &algo| {
            b.iter(|| {
                KeyPair::generate(black_box(algo)).unwrap()
            });
        });
    }

    let sig_algorithms = vec![
        ("ML-DSA-44", PqAlgorithm::MlDsa44),
        ("ML-DSA-65", PqAlgorithm::MlDsa65),
        ("ML-DSA-87", PqAlgorithm::MlDsa87),
        ("SLH-DSA-SHA2-128s", PqAlgorithm::SlhDsaSha2_128s),
        ("SLH-DSA-SHA2-256s", PqAlgorithm::SlhDsaSha2_256s),
    ];

    for (name, algo) in sig_algorithms {
        group.bench_with_input(BenchmarkId::new("Signature", name), &algo, |b, &algo| {
            b.iter(|| {
                KeyPair::generate(black_box(algo)).unwrap()
            });
        });
    }

    group.finish();
}

fn benchmark_encryption_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encryption/Decryption");

    let message_sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];

    let algorithms = vec![
        ("ML-KEM-512", PqAlgorithm::MlKem512),
        ("ML-KEM-768", PqAlgorithm::MlKem768),
        ("ML-KEM-1024", PqAlgorithm::MlKem1024),
    ];

    for (algo_name, algo) in algorithms {
        let keypair = KeyPair::generate(algo).unwrap();

        for (size_name, size) in &message_sizes {
            let plaintext = vec![42u8; *size];

            // Benchmark encryption
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("Encrypt-{}", algo_name), size_name),
                &plaintext,
                |b, plaintext| {
                    b.iter(|| {
                        encryption::encrypt_message(black_box(plaintext), black_box(&keypair.public_key)).unwrap()
                    });
                },
            );

            // Benchmark decryption
            let encrypted = encryption::encrypt_message(&plaintext, &keypair.public_key).unwrap();
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("Decrypt-{}", algo_name), size_name),
                &encrypted,
                |b, encrypted| {
                    b.iter(|| {
                        encryption::decrypt_message(black_box(encrypted), black_box(&keypair.private_key)).unwrap()
                    });
                },
            );
        }
    }

    group.finish();
}

fn benchmark_signing_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signing/Verification");

    let message_sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];

    let algorithms = vec![
        ("ML-DSA-44", PqAlgorithm::MlDsa44),
        ("ML-DSA-65", PqAlgorithm::MlDsa65),
        ("ML-DSA-87", PqAlgorithm::MlDsa87),
    ];

    for (algo_name, algo) in algorithms {
        let keypair = KeyPair::generate(algo).unwrap();

        for (size_name, size) in &message_sizes {
            let data = vec![42u8; *size];

            // Benchmark signing
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("Sign-{}", algo_name), size_name),
                &data,
                |b, data| {
                    b.iter(|| {
                        signature::sign_data(black_box(data), black_box(&keypair.private_key)).unwrap()
                    });
                },
            );

            // Benchmark verification
            let sig = signature::sign_data(&data, &keypair.private_key).unwrap();
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("Verify-{}", algo_name), size_name),
                &(&data, &sig),
                |b, (data, sig)| {
                    b.iter(|| {
                        signature::verify_signature(black_box(data), black_box(sig), black_box(&keypair.public_key)).unwrap()
                    });
                },
            );
        }
    }

    group.finish();
}

fn benchmark_sphincs_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+ Signing");
    group.sample_size(10); // SPHINCS+ is slow, use fewer samples

    let algorithms = vec![
        ("SLH-DSA-SHA2-128s", PqAlgorithm::SlhDsaSha2_128s),
        ("SLH-DSA-SHA2-256s", PqAlgorithm::SlhDsaSha2_256s),
    ];

    let data = vec![42u8; 1024];

    for (algo_name, algo) in algorithms {
        let keypair = KeyPair::generate(algo).unwrap();

        group.bench_with_input(
            BenchmarkId::new("Sign", algo_name),
            &data,
            |b, data| {
                b.iter(|| {
                    signature::sign_data(black_box(data), black_box(&keypair.private_key)).unwrap()
                });
            },
        );

        let sig = signature::sign_data(&data, &keypair.private_key).unwrap();
        group.bench_with_input(
            BenchmarkId::new("Verify", algo_name),
            &(&data, &sig),
            |b, (data, sig)| {
                b.iter(|| {
                    signature::verify_signature(black_box(data), black_box(sig), black_box(&keypair.public_key)).unwrap()
                });
            },
        );
    }

    group.finish();
}

fn benchmark_armor(c: &mut Criterion) {
    let mut group = c.benchmark_group("ASCII Armor");

    let data_sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
    ];

    for (size_name, size) in data_sizes {
        let data = vec![42u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("Encode", size_name),
            &data,
            |b, data| {
                b.iter(|| {
                    pq_gpg::armor::encode(black_box(data), pq_gpg::armor::ArmorType::Message).unwrap()
                });
            },
        );

        let armored = pq_gpg::armor::encode(&data, pq_gpg::armor::ArmorType::Message).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("Decode", size_name),
            &armored,
            |b, armored| {
                b.iter(|| {
                    pq_gpg::armor::decode(black_box(armored)).unwrap()
                });
            },
        );
    }

    group.finish();
}

fn benchmark_hybrid_kem(c: &mut Criterion) {
    use pq_gpg::crypto::hybrid::HybridKem;

    let mut group = c.benchmark_group("Hybrid KEM");

    let hybrid = HybridKem::new(PqAlgorithm::MlKem768);

    group.bench_function("Hybrid-Keygen", |b| {
        b.iter(|| {
            black_box(hybrid.keygen().unwrap())
        });
    });

    let (pk, sk) = hybrid.keygen().unwrap();

    group.bench_function("Hybrid-Encaps", |b| {
        b.iter(|| {
            black_box(hybrid.encaps(&pk).unwrap())
        });
    });

    let (ct, _ss) = hybrid.encaps(&pk).unwrap();

    group.bench_function("Hybrid-Decaps", |b| {
        b.iter(|| {
            black_box(hybrid.decaps(&sk, &ct).unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_encryption_decryption,
    benchmark_signing_verification,
    benchmark_sphincs_signing,
    benchmark_armor,
    benchmark_hybrid_kem,
);
criterion_main!(benches);
