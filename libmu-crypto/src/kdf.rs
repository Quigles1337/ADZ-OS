//! # μ-Key Derivation Functions
//!
//! Key derivation using golden ratio quasirandom sequences: {Z · φ}
//!
//! ## Functions
//! - `MuKdf`: HKDF-like construction using μ-Hash
//! - `MuPbkdf`: Password-based KDF with memory hardening
//! - `GoldenKdf`: Key expansion using golden ratio sequence

use crate::hash::{MuHash, MuHmac};
use crate::primitives::{GoldenSequence, MU_KEY_SIZE, MU_HASH_SIZE};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error types for KDF operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// Output length too large
    OutputTooLong,
    /// Invalid salt length
    InvalidSaltLength,
    /// Invalid iteration count
    InvalidIterations,
    /// Memory allocation failed
    MemoryError,
}

impl std::fmt::Display for KdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdfError::OutputTooLong => write!(f, "Requested output length too large"),
            KdfError::InvalidSaltLength => write!(f, "Invalid salt length"),
            KdfError::InvalidIterations => write!(f, "Invalid iteration count"),
            KdfError::MemoryError => write!(f, "Memory allocation failed"),
        }
    }
}

impl std::error::Error for KdfError {}

/// HKDF-like key derivation using μ-Hash
///
/// Based on RFC 5869 structure but using μ-cryptography primitives.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MuKdf {
    /// Pseudo-random key from extract phase
    prk: [u8; MU_HASH_SIZE],
}

impl MuKdf {
    /// Maximum output length (255 * hash_len)
    pub const MAX_OUTPUT_LEN: usize = 255 * MU_HASH_SIZE;

    /// Extract phase: derive PRK from input keying material
    ///
    /// # Arguments
    /// * `salt` - Optional salt (use empty for no salt)
    /// * `ikm` - Input keying material
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        // If salt is empty, use zeros
        let salt = if salt.is_empty() {
            &[0u8; MU_HASH_SIZE]
        } else {
            salt
        };

        let hmac = MuHmac::new(salt);
        let prk = hmac.compute(ikm);

        Self { prk }
    }

    /// Expand phase: generate output keying material
    ///
    /// # Arguments
    /// * `info` - Context/application-specific info
    /// * `length` - Desired output length
    pub fn expand(&self, info: &[u8], length: usize) -> Result<Vec<u8>, KdfError> {
        if length > Self::MAX_OUTPUT_LEN {
            return Err(KdfError::OutputTooLong);
        }

        let hmac = MuHmac::new(&self.prk);
        let mut output = Vec::with_capacity(length);
        let mut t = Vec::new();
        let mut counter = 1u8;

        while output.len() < length {
            // T(n) = HMAC(PRK, T(n-1) || info || counter)
            let mut input = t.clone();
            input.extend_from_slice(info);
            input.push(counter);

            t = hmac.compute(&input).to_vec();

            let to_copy = (length - output.len()).min(MU_HASH_SIZE);
            output.extend_from_slice(&t[..to_copy]);

            counter = counter.wrapping_add(1);
        }

        Ok(output)
    }

    /// Combined extract-and-expand
    pub fn derive(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, KdfError> {
        let kdf = Self::extract(salt, ikm);
        kdf.expand(info, length)
    }

    /// Derive a fixed-size key (256-bit)
    pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; MU_KEY_SIZE], KdfError> {
        let output = Self::derive(salt, ikm, info, MU_KEY_SIZE)?;
        let mut key = [0u8; MU_KEY_SIZE];
        key.copy_from_slice(&output);
        Ok(key)
    }
}

/// Password-based key derivation with memory hardening
///
/// Inspired by Argon2 but using μ-cryptography primitives.
#[derive(Clone)]
pub struct MuPbkdf {
    /// Time cost (iterations)
    time_cost: u32,
    /// Memory cost in KB
    memory_cost: u32,
    /// Parallelism degree
    parallelism: u32,
}

impl MuPbkdf {
    /// Default time cost
    pub const DEFAULT_TIME_COST: u32 = 3;
    /// Default memory cost (64 MB)
    pub const DEFAULT_MEMORY_COST: u32 = 65536;
    /// Default parallelism
    pub const DEFAULT_PARALLELISM: u32 = 4;
    /// Minimum memory cost (8 KB)
    pub const MIN_MEMORY_COST: u32 = 8;

    /// Create a new PBKDF instance with default parameters
    pub fn new() -> Self {
        Self {
            time_cost: Self::DEFAULT_TIME_COST,
            memory_cost: Self::DEFAULT_MEMORY_COST,
            parallelism: Self::DEFAULT_PARALLELISM,
        }
    }

    /// Set time cost (iterations)
    pub fn time_cost(mut self, t: u32) -> Self {
        self.time_cost = t.max(1);
        self
    }

    /// Set memory cost in KB
    pub fn memory_cost(mut self, m: u32) -> Self {
        self.memory_cost = m.max(Self::MIN_MEMORY_COST);
        self
    }

    /// Set parallelism degree
    pub fn parallelism(mut self, p: u32) -> Self {
        self.parallelism = p.max(1);
        self
    }

    /// Derive key from password
    ///
    /// # Arguments
    /// * `password` - User password
    /// * `salt` - Unique salt (at least 16 bytes recommended)
    /// * `output_len` - Desired output length
    pub fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, KdfError> {
        if salt.len() < 8 {
            return Err(KdfError::InvalidSaltLength);
        }

        // Initialize memory blocks
        let block_count = (self.memory_cost as usize * 1024) / 64;
        let mut memory: Vec<[u8; 64]> = vec![[0u8; 64]; block_count];

        // Initial hash: H(password || salt || params)
        let mut initial_input = Vec::new();
        initial_input.extend_from_slice(password);
        initial_input.extend_from_slice(salt);
        initial_input.extend_from_slice(&self.time_cost.to_le_bytes());
        initial_input.extend_from_slice(&self.memory_cost.to_le_bytes());
        initial_input.extend_from_slice(&self.parallelism.to_le_bytes());
        initial_input.extend_from_slice(&(output_len as u32).to_le_bytes());

        let h0 = MuHash::hash(&initial_input);

        // Fill first blocks
        for i in 0..block_count.min(2) {
            let mut block_input = h0.to_vec();
            block_input.extend_from_slice(&(i as u32).to_le_bytes());
            let hash = MuHash::hash(&block_input);
            memory[i][..32].copy_from_slice(&hash);

            // Second half from extended hash
            block_input.push(0x01);
            let hash2 = MuHash::hash(&block_input);
            memory[i][32..].copy_from_slice(&hash2);
        }

        // Fill remaining blocks using golden ratio indexing
        let mut golden = GoldenSequence::with_seed(u64::from_le_bytes(h0[0..8].try_into().unwrap()));

        for i in 2..block_count {
            // Reference block from golden ratio sequence
            let ref_idx = ((golden.next() * (i as f64)) as usize) % i;

            // Mix with previous block
            let prev_idx = i - 1;

            // Combine blocks
            let mut combined = [0u8; 64];
            for j in 0..64 {
                combined[j] = memory[prev_idx][j] ^ memory[ref_idx][j];
            }

            // Hash the combination
            let hash = MuHash::hash(&combined);
            memory[i][..32].copy_from_slice(&hash);

            // Extended hash for second half
            let hash2 = MuHash::hash(&[&combined[..], &[0x01]].concat());
            memory[i][32..].copy_from_slice(&hash2);
        }

        // Time iterations
        for _ in 0..self.time_cost {
            for i in 0..block_count {
                let ref_idx = ((golden.next() * (block_count as f64)) as usize) % block_count;
                let prev_idx = if i == 0 { block_count - 1 } else { i - 1 };

                let mut combined = [0u8; 64];
                for j in 0..64 {
                    combined[j] = memory[prev_idx][j] ^ memory[ref_idx][j] ^ memory[i][j];
                }

                let hash = MuHash::hash(&combined);
                memory[i][..32].copy_from_slice(&hash);

                let hash2 = MuHash::hash(&[&combined[..], &[0x01]].concat());
                memory[i][32..].copy_from_slice(&hash2);
            }
        }

        // Final: XOR last blocks and hash
        let mut final_block = [0u8; 64];
        let lanes = self.parallelism as usize;
        let lane_len = block_count / lanes.max(1);

        for lane in 0..lanes.min(block_count) {
            let last_idx = ((lane + 1) * lane_len).min(block_count) - 1;
            for j in 0..64 {
                final_block[j] ^= memory[last_idx][j];
            }
        }

        // Derive output using KDF
        let kdf = MuKdf::extract(salt, &final_block);
        let output = kdf.expand(b"mu-pbkdf", output_len)?;

        // Zeroize memory
        for block in memory.iter_mut() {
            block.zeroize();
        }

        Ok(output)
    }

    /// Derive a fixed-size key (256-bit)
    pub fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> Result<[u8; MU_KEY_SIZE], KdfError> {
        let output = self.derive(password, salt, MU_KEY_SIZE)?;
        let mut key = [0u8; MU_KEY_SIZE];
        key.copy_from_slice(&output);
        Ok(key)
    }
}

impl Default for MuPbkdf {
    fn default() -> Self {
        Self::new()
    }
}

/// Golden ratio key expansion
///
/// Expands a seed into a sequence of keys using the golden ratio.
pub struct GoldenKdf {
    sequence: GoldenSequence,
    seed_hash: [u8; MU_HASH_SIZE],
}

impl GoldenKdf {
    /// Create a new golden KDF from seed
    pub fn new(seed: &[u8]) -> Self {
        let seed_hash = MuHash::hash(seed);
        let seed_u64 = u64::from_le_bytes(seed_hash[0..8].try_into().unwrap());

        Self {
            sequence: GoldenSequence::with_seed(seed_u64),
            seed_hash,
        }
    }

    /// Generate the next key in the sequence
    pub fn next_key(&mut self) -> [u8; MU_KEY_SIZE] {
        let golden_val = self.sequence.next();

        // Combine golden value with seed hash
        let mut input = self.seed_hash.to_vec();
        input.extend_from_slice(&golden_val.to_le_bytes());

        let hash = MuHash::hash(&input);

        // Update seed hash for forward secrecy
        self.seed_hash = MuHash::hash(&[&self.seed_hash[..], &hash[..]].concat());

        hash
    }

    /// Generate multiple keys
    pub fn generate_keys(&mut self, count: usize) -> Vec<[u8; MU_KEY_SIZE]> {
        (0..count).map(|_| self.next_key()).collect()
    }

    /// Generate key at specific index (resets state)
    pub fn key_at(&mut self, index: u64) -> [u8; MU_KEY_SIZE] {
        // Use golden ratio property for direct indexing
        let golden_val = GoldenSequence::nth(index);

        let mut input = self.seed_hash.to_vec();
        input.extend_from_slice(&golden_val.to_le_bytes());
        input.extend_from_slice(&index.to_le_bytes());

        MuHash::hash(&input)
    }
}

/// Derive multiple keys from a master key using KDF
pub fn derive_subkeys<const N: usize>(
    master_key: &[u8],
    context: &[u8],
) -> Result<[[u8; MU_KEY_SIZE]; N], KdfError> {
    let kdf = MuKdf::extract(&[], master_key);
    let mut keys = [[0u8; MU_KEY_SIZE]; N];

    for i in 0..N {
        let mut info = context.to_vec();
        info.extend_from_slice(&(i as u32).to_le_bytes());

        let derived = kdf.expand(&info, MU_KEY_SIZE)?;
        keys[i].copy_from_slice(&derived);
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_deterministic() {
        let salt = b"test salt";
        let ikm = b"input keying material";
        let info = b"context info";

        let key1 = MuKdf::derive(salt, ikm, info, 32).unwrap();
        let key2 = MuKdf::derive(salt, ikm, info, 32).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_kdf_different_info() {
        let salt = b"salt";
        let ikm = b"ikm";

        let key1 = MuKdf::derive(salt, ikm, b"info1", 32).unwrap();
        let key2 = MuKdf::derive(salt, ikm, b"info2", 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_kdf_variable_length() {
        let kdf = MuKdf::extract(b"salt", b"ikm");

        let key16 = kdf.expand(b"info", 16).unwrap();
        let key64 = kdf.expand(b"info", 64).unwrap();

        assert_eq!(key16.len(), 16);
        assert_eq!(key64.len(), 64);
        // First 16 bytes should match
        assert_eq!(&key16[..], &key64[..16]);
    }

    #[test]
    fn test_pbkdf_basic() {
        let pbkdf = MuPbkdf::new()
            .time_cost(1)
            .memory_cost(64); // 64KB for fast testing

        let password = b"password123";
        let salt = b"unique_salt_here";

        let key = pbkdf.derive(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Should be deterministic
        let key2 = pbkdf.derive(password, salt, 32).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf_different_passwords() {
        let pbkdf = MuPbkdf::new()
            .time_cost(1)
            .memory_cost(64);

        let salt = b"salt_value_16byt";

        let key1 = pbkdf.derive(b"password1", salt, 32).unwrap();
        let key2 = pbkdf.derive(b"password2", salt, 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_golden_kdf_sequence() {
        let mut kdf = GoldenKdf::new(b"master seed");

        let key1 = kdf.next_key();
        let key2 = kdf.next_key();
        let key3 = kdf.next_key();

        // All keys should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_subkeys() {
        let master = b"master key for subkey derivation";
        let context = b"encryption keys";

        let keys: [[u8; 32]; 4] = derive_subkeys(master, context).unwrap();

        // All subkeys should be different
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[test]
    fn test_kdf_max_output() {
        let kdf = MuKdf::extract(b"salt", b"ikm");

        // Should succeed at max length
        assert!(kdf.expand(b"info", MuKdf::MAX_OUTPUT_LEN).is_ok());

        // Should fail above max length
        assert!(matches!(
            kdf.expand(b"info", MuKdf::MAX_OUTPUT_LEN + 1),
            Err(KdfError::OutputTooLong)
        ));
    }
}
