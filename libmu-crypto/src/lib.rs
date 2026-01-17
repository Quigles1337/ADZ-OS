//! # libmu-crypto
//!
//! A novel cryptographic library based on balance primitive geometry for the μOS project.
//!
//! ## Overview
//!
//! This library implements a complete cryptographic suite using mathematical principles
//! derived from the balance primitive μ = e^(i·3π/4), the fine-structure constant α ≈ 1/137,
//! and golden ratio φ for quasirandom sequences.
//!
//! ## Core Components
//!
//! - **[`primitives`]** - Core μ-arithmetic and mathematical constants
//! - **[`cipher`]** - μ-Spiral block cipher (256-bit key, 128-bit block)
//! - **[`hash`]** - μ-Hash sponge construction (256-bit output)
//! - **[`kdf`]** - Key derivation functions (HKDF-like and password-based)
//! - **[`signature`]** - Digital signatures using V_Z spiral geometry
//! - **[`random`]** - Cryptographically secure random number generator
//!
//! ## Mathematical Foundation
//!
//! ```text
//! μ = e^(i·3π/4) = (-1 + i)/√2    # Balance primitive (8th root of unity)
//! α ≈ 1/137.036                    # Fine-structure coupling
//! V_Z = Z · α · μ                  # Quantized spiral rays
//! φ = (1 + √5)/2                   # Golden ratio
//! ```
//!
//! The key insight is that μ^8 = 1 (closure property) and |Re(μ)| = |Im(μ)| (balance property),
//! which provide natural structures for cryptographic transformations.
//!
//! ## Quick Start
//!
//! ### Encryption
//!
//! ```rust
//! use libmu_crypto::cipher::{MuSpiralCipher, MuSpiralAead};
//!
//! // Generate a random key
//! let key = libmu_crypto::random::random_bytes::<32>().unwrap();
//! let nonce = libmu_crypto::random::random_bytes::<12>().unwrap();
//!
//! // Encrypt with AEAD
//! let aead = MuSpiralAead::new(&key, &nonce).unwrap();
//! let ciphertext = aead.encrypt(b"secret message", b"associated data").unwrap();
//! let plaintext = aead.decrypt(&ciphertext, b"associated data").unwrap();
//! ```
//!
//! ### Hashing
//!
//! ```rust
//! use libmu_crypto::hash::MuHash;
//!
//! let hash = MuHash::hash(b"data to hash");
//! ```
//!
//! ### Signatures
//!
//! ```rust
//! use libmu_crypto::signature::MuKeyPair;
//!
//! let keypair = MuKeyPair::from_seed(b"seed");
//! let signature = keypair.sign(b"message");
//! assert!(keypair.verify(b"message", &signature).is_ok());
//! ```
//!
//! ## Security Considerations
//!
//! **WARNING**: This is experimental cryptography for the μOS project.
//! It has NOT been audited and should NOT be used for production security.
//!
//! The cryptographic primitives are designed with:
//! - Constant-time operations where possible (using `subtle` crate)
//! - Secure memory handling (using `zeroize` crate)
//! - Forward secrecy in the CSPRNG
//! - Deterministic nonce generation for signatures
//!
//! ## Feature Flags
//!
//! - `std` (default): Enable standard library features
//! - `kernel`: Enable no_std mode for kernel integration
//! - `experimental`: Enable experimental features
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![cfg_attr(feature = "kernel", no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

// Re-export commonly used items at crate root
pub use primitives::{
    MuComplex, MuSBox, SpiralRay, GoldenSequence,
    MU, ALPHA, PHI, ALCHEMY_K,
    MU_BLOCK_SIZE, MU_KEY_SIZE, MU_HASH_SIZE, MU_ROUNDS,
};
pub use cipher::{MuSpiralCipher, MuSpiralCtr, MuSpiralAead, CipherError};
pub use hash::{MuHash, MuHmac};
pub use kdf::{MuKdf, MuPbkdf, GoldenKdf, KdfError};
pub use signature::{
    MuPrivateKey, MuPublicKey, MuSignature, MuKeyPair,
    MU_SIGNATURE_SIZE, SignatureError,
};
pub use random::{MuRng, RandomError};

/// Core mathematical primitives for μ-cryptography
pub mod primitives;

/// μ-Spiral block cipher
pub mod cipher;

/// μ-Hash cryptographic hash function
pub mod hash;

/// Key derivation functions
pub mod kdf;

/// Digital signature scheme
pub mod signature;

/// Cryptographically secure random number generation
pub mod random;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "libmu-crypto";

/// Prelude module for convenient imports
pub mod prelude {
    //! Convenient imports for common use cases
    //!
    //! ```rust
    //! use libmu_crypto::prelude::*;
    //! ```

    pub use crate::cipher::{MuSpiralCipher, MuSpiralCtr, MuSpiralAead};
    pub use crate::hash::{MuHash, MuHmac};
    pub use crate::kdf::{MuKdf, MuPbkdf};
    pub use crate::signature::{MuKeyPair, MuSignature};
    pub use crate::random::MuRng;
    pub use crate::primitives::{MU, ALPHA, PHI};
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_encryption_workflow() {
        // Generate key and nonce
        let mut rng = MuRng::from_seed(b"integration test seed");
        let key: [u8; 32] = rng.random_bytes();
        let nonce: [u8; 12] = rng.random_bytes();

        // Encrypt
        let aead = MuSpiralAead::new(&key, &nonce).unwrap();
        let plaintext = b"This is a secret message for integration testing";
        let aad = b"context data";

        let ciphertext = aead.encrypt(plaintext, aad).unwrap();

        // Decrypt
        let decrypted = aead.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_key_derivation_to_encryption() {
        // Derive key from password
        let pbkdf = MuPbkdf::new()
            .time_cost(1)
            .memory_cost(64);

        let key = pbkdf.derive_key(b"password", b"salt1234salt1234").unwrap();
        let hash = MuHash::hash(b"nonce derivation");
        let nonce: [u8; 12] = hash[..12].try_into().unwrap();

        // Use derived key for encryption
        let aead = MuSpiralAead::new(&key, &nonce).unwrap();
        let ciphertext = aead.encrypt(b"data", b"").unwrap();
        let decrypted = aead.decrypt(&ciphertext, b"").unwrap();

        assert_eq!(b"data".to_vec(), decrypted);
    }

    #[test]
    fn test_signature_with_derived_key() {
        // Derive signing key
        let master_secret = b"master secret for signing";
        let derived = MuKdf::derive(b"", master_secret, b"signing key", 32).unwrap();

        // Create keypair
        let keypair = MuKeyPair::from_bytes(&derived.try_into().unwrap()).unwrap();

        // Sign message
        let message = b"Document to sign";
        let signature = keypair.sign(message);

        // Verify
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_hash_then_sign() {
        // Hash large document
        let document = vec![0x42u8; 10000];
        let hash = MuHash::hash(&document);

        // Sign the hash
        let keypair = MuKeyPair::from_seed(b"document signing");
        let signature = keypair.sign(&hash);

        // Verify
        assert!(keypair.verify(&hash, &signature).is_ok());
    }

    #[test]
    fn test_constants() {
        // Verify mathematical constants
        assert!((MU.re + std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-10);
        assert!((MU.im - std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-10);
        assert!((ALPHA - 1.0 / 137.035999084).abs() < 1e-15);
        assert!((PHI - 1.618033988749895).abs() < 1e-15);
    }

    #[test]
    fn test_golden_sequence_properties() {
        let mut seq = GoldenSequence::new();

        // Golden ratio sequence should be equidistributed
        let mut bins = [0u32; 10];
        for _ in 0..10000 {
            let val = seq.next();
            let bin = (val * 10.0) as usize;
            if bin < 10 {
                bins[bin] += 1;
            }
        }

        // Each bin should have roughly 1000 values
        for bin in &bins {
            assert!(*bin > 800 && *bin < 1200);
        }
    }
}
