//! Benchmarks for libmu-crypto
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use libmu_crypto::*;

fn bench_cipher(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let cipher = cipher::MuSpiralCipher::new(&key).unwrap();
    let plaintext = [0u8; 16];

    let mut group = c.benchmark_group("cipher");
    group.throughput(Throughput::Bytes(16));

    group.bench_function("encrypt_block", |b| {
        b.iter(|| cipher.encrypt_block(black_box(&plaintext)))
    });

    let ciphertext = cipher.encrypt_block(&plaintext).unwrap();
    group.bench_function("decrypt_block", |b| {
        b.iter(|| cipher.decrypt_block(black_box(&ciphertext)))
    });

    group.finish();
}

fn bench_cipher_ctr(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let cipher = cipher::MuSpiralCtr::new(&key, &nonce).unwrap();

    let mut group = c.benchmark_group("cipher_ctr");

    for size in [64, 256, 1024, 4096, 16384] {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encrypt_{}_bytes", size), |b| {
            b.iter(|| cipher.encrypt(black_box(&plaintext)))
        });
    }

    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aead = cipher::MuSpiralAead::new(&key, &nonce).unwrap();

    let plaintext = vec![0u8; 1024];
    let aad = b"associated data";

    let mut group = c.benchmark_group("aead");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("encrypt_1kb", |b| {
        b.iter(|| aead.encrypt(black_box(&plaintext), black_box(aad)))
    });

    let ciphertext = aead.encrypt(&plaintext, aad).unwrap();
    group.bench_function("decrypt_1kb", |b| {
        b.iter(|| aead.decrypt(black_box(&ciphertext), black_box(aad)))
    });

    group.finish();
}

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");

    for size in [32, 64, 256, 1024, 4096, 16384] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("hash_{}_bytes", size), |b| {
            b.iter(|| hash::MuHash::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_hmac(c: &mut Criterion) {
    let key = b"benchmark key";
    let hmac = hash::MuHmac::new(key);
    let data = vec![0u8; 1024];

    let mut group = c.benchmark_group("hmac");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("compute_1kb", |b| {
        b.iter(|| hmac.compute(black_box(&data)))
    });

    group.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    group.bench_function("hkdf_extract", |b| {
        b.iter(|| kdf::MuKdf::extract(black_box(b"salt"), black_box(b"ikm")))
    });

    let kdf = kdf::MuKdf::extract(b"salt", b"ikm");
    group.bench_function("hkdf_expand_32", |b| {
        b.iter(|| kdf.expand(black_box(b"info"), black_box(32)))
    });

    group.bench_function("hkdf_derive_32", |b| {
        b.iter(|| kdf::MuKdf::derive(black_box(b"salt"), black_box(b"ikm"), black_box(b"info"), 32))
    });

    group.finish();
}

fn bench_pbkdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("pbkdf");

    // Fast parameters for benchmarking
    let pbkdf = kdf::MuPbkdf::new()
        .time_cost(1)
        .memory_cost(64); // 64KB

    group.bench_function("pbkdf_fast", |b| {
        b.iter(|| pbkdf.derive(black_box(b"password"), black_box(b"salt1234salt1234"), 32))
    });

    group.finish();
}

fn bench_signature(c: &mut Criterion) {
    let keypair = signature::MuKeyPair::from_seed(b"benchmark seed");
    let message = b"message to sign";

    let mut group = c.benchmark_group("signature");

    group.bench_function("sign", |b| {
        b.iter(|| keypair.sign(black_box(message)))
    });

    let sig = keypair.sign(message);
    group.bench_function("verify", |b| {
        b.iter(|| keypair.verify(black_box(message), black_box(&sig)))
    });

    group.bench_function("keygen", |b| {
        b.iter(|| signature::MuKeyPair::from_seed(black_box(b"seed")))
    });

    group.finish();
}

fn bench_random(c: &mut Criterion) {
    let mut rng = random::MuRng::from_seed(b"benchmark seed");

    let mut group = c.benchmark_group("random");

    group.bench_function("next_u64", |b| {
        b.iter(|| rng.next_u64())
    });

    let mut buf = [0u8; 32];
    group.bench_function("fill_32_bytes", |b| {
        b.iter(|| {
            use rand_core::RngCore;
            rng.fill_bytes(black_box(&mut buf))
        })
    });

    let mut buf1k = [0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("fill_1kb", |b| {
        b.iter(|| {
            use rand_core::RngCore;
            rng.fill_bytes(black_box(&mut buf1k))
        })
    });

    group.finish();
}

fn bench_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives");

    group.bench_function("mu_pow", |b| {
        b.iter(|| primitives::MuComplex::mu_pow(black_box(5)))
    });

    group.bench_function("spiral_ray_new", |b| {
        b.iter(|| primitives::SpiralRay::new(black_box(42)))
    });

    let mut golden = primitives::GoldenSequence::new();
    group.bench_function("golden_next", |b| {
        b.iter(|| golden.next())
    });

    group.bench_function("sbox_generate", |b| {
        b.iter(|| primitives::MuSBox::generate(black_box(0)))
    });

    let sbox = primitives::MuSBox::generate(0);
    group.bench_function("sbox_substitute", |b| {
        b.iter(|| sbox.substitute(black_box(0x42)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cipher,
    bench_cipher_ctr,
    bench_aead,
    bench_hash,
    bench_hmac,
    bench_kdf,
    bench_pbkdf,
    bench_signature,
    bench_random,
    bench_primitives,
);

criterion_main!(benches);
