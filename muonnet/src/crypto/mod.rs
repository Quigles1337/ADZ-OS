//! MuonNet Cryptographic Layer
//!
//! Provides onion encryption/decryption using μ-cryptography.
//!
//! # Key Exchange
//!
//! MuonNet uses a hybrid key exchange:
//! 1. μ-Signatures for relay identity verification
//! 2. Ephemeral μ-KDF for forward secrecy
//! 3. μ-Spiral AEAD for bulk encryption
//!
//! # Onion Layers
//!
//! Each hop adds a layer of encryption:
//! ```text
//! Client -> R1 -> R2 -> R3 -> Destination
//!   |       |     |     |
//!   +-- K1 -+     |     |     (outermost layer)
//!   +------ K2 ---+     |     (middle layer)
//!   +----------- K3 ----+     (innermost layer)
//! ```

pub mod onion;
pub mod handshake;
pub mod keys;

pub use onion::{OnionLayer, OnionPacket};
pub use handshake::{Handshake, HandshakeState};
pub use keys::{CircuitKeys, HopKeys, KeyMaterial};

use crate::{MuonResult, MuonError};
use libmu_crypto::{MuSpiralAead, MuHash, MuKdf, signature::MuKeyPair};

/// Cryptographic context for a MuonNet node
pub struct CryptoContext {
    /// Long-term identity keypair
    identity: MuKeyPair,
    /// Identity fingerprint (μ-hash of public key)
    fingerprint: [u8; 32],
}

impl CryptoContext {
    /// Create new crypto context with random identity
    pub fn new() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Create crypto context from seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let identity = MuKeyPair::from_seed(seed);
        let fingerprint = MuHash::hash(&identity.public_key().to_bytes());
        Self { identity, fingerprint }
    }

    /// Get identity keypair
    pub fn identity(&self) -> &MuKeyPair {
        &self.identity
    }

    /// Get identity fingerprint
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Sign data with identity key
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.identity.sign(data);
        sig.to_bytes()
    }

    /// Verify signature with public key
    pub fn verify(public_key: &[u8; 64], data: &[u8], signature: &[u8; 64]) -> MuonResult<()> {
        use libmu_crypto::signature::{MuPublicKey, MuSignature};

        let pk = MuPublicKey::from_bytes(public_key)
            .map_err(|_| MuonError::InvalidKey("Invalid public key".into()))?;
        let sig = MuSignature::from_bytes(signature)
            .map_err(|_| MuonError::InvalidKey("Invalid signature".into()))?;

        pk.verify(data, &sig)
            .map_err(|_| MuonError::SignatureVerificationFailed)
    }
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CryptoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoContext")
            .field("fingerprint", &hex::encode(&self.fingerprint))
            .finish()
    }
}

/// Derive shared secret for key exchange
pub fn derive_shared_secret(
    our_private: &[u8; 32],
    their_public: &[u8; 64],
    context: &[u8],
) -> MuonResult<[u8; 32]> {
    // Use μ-KDF to derive shared secret
    // In a real implementation, this would use a proper ECDH-like scheme
    // For now, we simulate with hash-based derivation

    let mut hasher = MuHash::new();
    hasher.update(our_private);
    hasher.update(&their_public[..32]); // Use first half of public key
    hasher.update(context);
    hasher.update(b"muonnet-key-exchange-v1");

    Ok(hasher.finalize())
}

/// Derive symmetric shared secret from two ephemeral public keys
/// This simulates ECDH by hashing both public keys in sorted order
pub fn derive_symmetric_secret(
    ephemeral_a: &[u8; 64],
    ephemeral_b: &[u8; 64],
    context: &[u8],
) -> MuonResult<[u8; 32]> {
    let mut hasher = MuHash::new();
    hasher.update(b"muonnet-symmetric-exchange-v1");

    // Sort public keys to ensure both sides compute the same hash
    if ephemeral_a < ephemeral_b {
        hasher.update(ephemeral_a);
        hasher.update(ephemeral_b);
    } else {
        hasher.update(ephemeral_b);
        hasher.update(ephemeral_a);
    }

    hasher.update(context);
    Ok(hasher.finalize())
}

/// Derive key material from shared secret
pub fn derive_key_material(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> MuonResult<Vec<u8>> {
    // Use μ-KDF for key expansion
    let kdf = MuKdf::extract(salt, shared_secret);
    kdf.expand(info, output_len)
        .map_err(|e| MuonError::KeyExchangeFailed(format!("KDF failed: {:?}", e)))
}

/// Create AEAD cipher for cell encryption
pub fn create_cell_cipher(key: &[u8; 32], nonce: &[u8; 12]) -> MuonResult<MuSpiralAead> {
    MuSpiralAead::new(key, nonce)
        .map_err(|e| MuonError::EncryptionFailed(format!("Failed to create cipher: {:?}", e)))
}

/// Encrypt cell payload
pub fn encrypt_cell(
    cipher: &MuSpiralAead,
    plaintext: &[u8],
    associated_data: &[u8],
) -> MuonResult<Vec<u8>> {
    cipher.encrypt(plaintext, associated_data)
        .map_err(|e| MuonError::EncryptionFailed(format!("{:?}", e)))
}

/// Decrypt cell payload
pub fn decrypt_cell(
    cipher: &MuSpiralAead,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> MuonResult<Vec<u8>> {
    cipher.decrypt(ciphertext, associated_data)
        .map_err(|e| MuonError::DecryptionFailed(format!("{:?}", e)))
}

/// Generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Compute fingerprint of data
pub fn fingerprint(data: &[u8]) -> [u8; 32] {
    MuHash::hash(data)
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_context_creation() {
        let ctx = CryptoContext::new();
        assert!(!ctx.fingerprint().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_crypto_context_deterministic() {
        let seed = b"test seed for muonnet crypto";
        let ctx1 = CryptoContext::from_seed(seed);
        let ctx2 = CryptoContext::from_seed(seed);
        assert_eq!(ctx1.fingerprint(), ctx2.fingerprint());
    }

    #[test]
    fn test_sign_verify() {
        let ctx = CryptoContext::new();
        let message = b"test message";
        let signature = ctx.sign(message);

        let pk = ctx.identity().public_key().to_bytes();
        assert!(CryptoContext::verify(&pk, message, &signature).is_ok());
    }

    #[test]
    fn test_sign_verify_tampered() {
        let ctx = CryptoContext::new();
        let message = b"test message";
        let signature = ctx.sign(message);

        let pk = ctx.identity().public_key().to_bytes();
        assert!(CryptoContext::verify(&pk, b"tampered", &signature).is_err());
    }

    #[test]
    fn test_shared_secret_derivation() {
        let private = random_bytes::<32>();
        let public = [0u8; 64]; // Dummy public key

        let secret = derive_shared_secret(&private, &public, b"test context").unwrap();
        assert!(!secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_key_material_derivation() {
        let secret = random_bytes::<32>();
        let salt = b"test salt";
        let info = b"test info";

        let material = derive_key_material(&secret, salt, info, 64).unwrap();
        assert_eq!(material.len(), 64);
    }

    #[test]
    fn test_cell_encryption() {
        let key = random_bytes::<32>();
        let nonce = random_bytes::<12>();
        let cipher = create_cell_cipher(&key, &nonce).unwrap();

        let plaintext = b"hello muonnet";
        let aad = b"circuit_id";

        let ciphertext = encrypt_cell(&cipher, plaintext, aad).unwrap();

        // Create new cipher for decryption (same key/nonce)
        let cipher2 = create_cell_cipher(&key, &nonce).unwrap();
        let decrypted = decrypt_cell(&cipher2, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }
}
