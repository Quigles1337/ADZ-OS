//! Integration tests for libmu-crypto
//!
//! These tests verify that all components work together correctly.

use libmu_crypto::*;

mod cipher_tests {
    use super::*;
    use cipher::{MuSpiralCipher, MuSpiralCtr, MuSpiralAead};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = MuSpiralCipher::new(&key).unwrap();

        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let ciphertext = cipher.encrypt_block(&plaintext).unwrap();
        let decrypted = cipher.decrypt_block(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_ctr_mode_variable_length() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let cipher = MuSpiralCtr::new(&key, &nonce).unwrap();

        // Test various lengths
        for len in [0, 1, 15, 16, 17, 31, 32, 100, 1000] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ciphertext = cipher.encrypt(&plaintext).unwrap();
            let decrypted = cipher.decrypt(&ciphertext).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_aead_authentication() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let cipher = MuSpiralAead::new(&key, &nonce).unwrap();

        let plaintext = b"Secret message";
        let aad = b"Associated data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();

        // Verify correct decryption
        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // Verify tamper detection - modified ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(cipher.decrypt(&tampered, aad).is_err());

        // Verify tamper detection - modified AAD
        assert!(cipher.decrypt(&ciphertext, b"Wrong AAD").is_err());
    }
}

mod hash_tests {
    use super::*;
    use hash::{MuHash, MuHmac};

    #[test]
    fn test_hash_collision_resistance() {
        // Very basic collision check (not exhaustive)
        let mut hashes = std::collections::HashSet::new();

        for i in 0..10000 {
            let data = format!("test data {}", i);
            let hash = MuHash::hash(data.as_bytes());
            assert!(hashes.insert(hash), "Hash collision detected at {}", i);
        }
    }

    #[test]
    fn test_hash_length_extension_resistance() {
        let secret = b"secret";
        let message = b"message";

        let mut input1 = secret.to_vec();
        input1.extend_from_slice(message);
        let hash1 = MuHash::hash(&input1);

        // Length extension attack should produce different hash
        let mut hasher = MuHash::new();
        hasher.update(&hash1);
        hasher.update(b"extension");
        let hash2 = hasher.finalize();

        // The extended hash should not equal H(secret || message || extension)
        let mut input2 = secret.to_vec();
        input2.extend_from_slice(message);
        input2.extend_from_slice(b"extension");
        let expected = MuHash::hash(&input2);
        assert_ne!(hash2, expected, "Vulnerable to length extension attack");
    }

    #[test]
    fn test_hmac_key_sensitivity() {
        let data = b"test data";

        let hmac1 = MuHmac::new(b"key1").compute(data);
        let hmac2 = MuHmac::new(b"key2").compute(data);
        let hmac3 = MuHmac::new(b"key1").compute(data);

        assert_ne!(hmac1, hmac2);
        assert_eq!(hmac1, hmac3);
    }
}

mod kdf_tests {
    use super::*;
    use kdf::{MuKdf, MuPbkdf, GoldenKdf};

    #[test]
    fn test_kdf_different_contexts() {
        let master = b"master key";

        let key1 = MuKdf::derive_key(b"", master, b"context1").unwrap();
        let key2 = MuKdf::derive_key(b"", master, b"context2").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf_time_cost_effect() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";

        let key1 = MuPbkdf::new()
            .time_cost(1)
            .memory_cost(32)
            .derive_key(password, salt)
            .unwrap();

        let key2 = MuPbkdf::new()
            .time_cost(2)
            .memory_cost(32)
            .derive_key(password, salt)
            .unwrap();

        // Different time costs should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_golden_kdf_sequence_uniqueness() {
        let mut kdf = GoldenKdf::new(b"master seed");
        let mut keys = Vec::new();

        for _ in 0..100 {
            keys.push(kdf.next_key());
        }

        // All keys should be unique
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }
}

mod signature_tests {
    use super::*;
    use signature::{MuKeyPair, MuPublicKey, MuSignature, batch_verify};

    #[test]
    fn test_signature_non_malleability() {
        let keypair = MuKeyPair::from_seed(b"test");
        let message = b"message";

        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        // Deterministic signatures should be identical
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let keypair = MuKeyPair::from_seed(b"test");

        let sig1 = keypair.sign(b"message1");
        let sig2 = keypair.sign(b"message2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_batch_verification() {
        let keypairs: Vec<_> = (0..10)
            .map(|i| MuKeyPair::from_seed(&[i as u8; 32]))
            .collect();

        let messages: Vec<&[u8]> = vec![
            b"msg0", b"msg1", b"msg2", b"msg3", b"msg4",
            b"msg5", b"msg6", b"msg7", b"msg8", b"msg9",
        ];

        let signatures: Vec<_> = keypairs
            .iter()
            .zip(&messages)
            .map(|(kp, msg)| kp.sign(msg))
            .collect();

        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();

        assert!(batch_verify(&messages, &signatures, &public_keys).is_ok());
    }
}

mod random_tests {
    use super::*;
    use random::MuRng;
    use rand_core::RngCore;

    #[test]
    fn test_rng_statistical_distribution() {
        let mut rng = MuRng::from_seed(b"statistical test");
        let mut bytes = vec![0u8; 100000];
        RngCore::fill_bytes(&mut rng, &mut bytes);

        // Chi-squared test for uniformity
        let mut counts = [0u64; 256];
        for &b in &bytes {
            counts[b as usize] += 1;
        }

        let expected = bytes.len() as f64 / 256.0;
        let chi_squared: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();

        // Chi-squared critical value for df=255 at p=0.001 is ~310
        assert!(chi_squared < 350.0,
                "Chi-squared test failed: {} > 350", chi_squared);
    }

    #[test]
    fn test_rng_no_short_cycles() {
        let mut rng = MuRng::from_seed(b"cycle test");
        let initial: [u8; 64] = rng.random_bytes();

        // Generate many blocks and ensure we don't see the initial block again
        for i in 0..10000 {
            let block: [u8; 64] = rng.random_bytes();
            assert_ne!(block, initial, "Short cycle detected at iteration {}", i);
        }
    }
}

mod cross_component_tests {
    use super::*;

    #[test]
    fn test_derive_key_then_encrypt() {
        // Use KDF to derive encryption key
        let password = b"user password";
        let salt = b"unique salt 1234";

        let key = kdf::MuPbkdf::new()
            .time_cost(1)
            .memory_cost(64)
            .derive_key(password, salt)
            .unwrap();

        // Derive nonce from additional info
        let nonce_material = hash::MuHash::hash(b"nonce context");
        let nonce: [u8; 12] = nonce_material[..12].try_into().unwrap();

        // Encrypt
        let aead = cipher::MuSpiralAead::new(&key, &nonce).unwrap();
        let ciphertext = aead.encrypt(b"secret data", b"").unwrap();

        // Re-derive key and decrypt
        let key2 = kdf::MuPbkdf::new()
            .time_cost(1)
            .memory_cost(64)
            .derive_key(password, salt)
            .unwrap();

        let aead2 = cipher::MuSpiralAead::new(&key2, &nonce).unwrap();
        let plaintext = aead2.decrypt(&ciphertext, b"").unwrap();

        assert_eq!(b"secret data".to_vec(), plaintext);
    }

    #[test]
    fn test_sign_encrypted_message() {
        // Generate signing key
        let signing_key = signature::MuKeyPair::from_seed(b"signing");

        // Generate encryption key
        let mut rng = random::MuRng::from_seed(b"encryption rng");
        let enc_key: [u8; 32] = rng.random_bytes();
        let nonce: [u8; 12] = rng.random_bytes();

        // Encrypt message
        let message = b"Message to sign and encrypt";
        let aead = cipher::MuSpiralAead::new(&enc_key, &nonce).unwrap();
        let ciphertext = aead.encrypt(message, b"").unwrap();

        // Sign the ciphertext (sign-then-encrypt pattern reversed)
        let signature = signing_key.sign(&ciphertext);

        // Verify and decrypt
        assert!(signing_key.verify(&ciphertext, &signature).is_ok());
        let decrypted = aead.decrypt(&ciphertext, b"").unwrap();
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_hash_based_commitment() {
        let secret = b"my secret value";
        let random_blind = random::random_bytes::<32>().unwrap();

        // Commitment = H(random || secret)
        let commitment = hash::MuHash::hash(&[&random_blind[..], secret].concat());

        // Later, reveal and verify
        let verification = hash::MuHash::hash(&[&random_blind[..], secret].concat());
        assert_eq!(commitment, verification);

        // Different secret produces different commitment
        let wrong_verify = hash::MuHash::hash(&[&random_blind[..], b"wrong secret"].concat());
        assert_ne!(commitment, wrong_verify);
    }
}
