//! # μ-Hash
//!
//! A cryptographic hash function exploiting the μ^8 = 1 closure property.
//!
//! ## Design
//! - Sponge construction with μ-spiral permutation
//! - 256-bit output (configurable)
//! - Rate: 128 bits, Capacity: 256 bits for 128-bit security
//!
//! ## Properties
//! - Preimage resistance
//! - Second preimage resistance
//! - Collision resistance
//! - Avalanche effect via μ-mixing

use crate::primitives::{
    mu_mix, rotl64, MuSBox, SpiralRay, MU_HASH_SIZE,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Internal state size (384 bits = rate 128 + capacity 256)
const STATE_SIZE: usize = 48;
/// Rate in bytes (128 bits)
const RATE: usize = 16;
/// Number of permutation rounds
const PERMUTATION_ROUNDS: usize = 24;

/// Round constants derived from μ-spiral geometry
const ROUND_CONSTANTS: [u64; PERMUTATION_ROUNDS] = {
    let mut constants = [0u64; PERMUTATION_ROUNDS];
    let mut i = 0;
    while i < PERMUTATION_ROUNDS {
        // Constants based on golden ratio and spiral ray properties
        // Computed at compile time using const evaluation
        let z = (i + 1) as u64;
        // Simulating: spiral_const = (z * ALPHA * PHI * 1e16) as u64
        // Using fixed-point approximation since const fn can't use f64
        let alpha_scaled = 7297353u64; // ALPHA * 1e9
        let phi_scaled = 1618033989u64; // PHI * 1e9
        constants[i] = z.wrapping_mul(alpha_scaled).wrapping_mul(phi_scaled >> 16);
        i += 1;
    }
    constants
};

/// μ-Hash state for incremental hashing
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MuHash {
    /// Internal state (6 × 64-bit words)
    state: [u64; 6],
    /// Buffer for incomplete blocks
    buffer: [u8; RATE],
    /// Current position in buffer
    buffer_pos: usize,
    /// Total bytes absorbed
    total_len: u64,
    /// S-Box for nonlinear layer
    sbox: MuSBox,
}

impl MuHash {
    /// Create a new μ-Hash instance
    pub fn new() -> Self {
        // Initialize state with IV derived from μ constants
        let iv = Self::generate_iv();

        Self {
            state: iv,
            buffer: [0u8; RATE],
            buffer_pos: 0,
            total_len: 0,
            sbox: MuSBox::generate(0x4D75_4861_7368), // "MuHash" in hex-ish
        }
    }

    /// Generate initialization vector from μ-spiral properties
    fn generate_iv() -> [u64; 6] {
        let mut iv = [0u64; 6];

        // IV derived from spiral ray values at Z = 1, 2, ..., 6
        for i in 0..6 {
            let ray = SpiralRay::new((i + 1) as u64);
            // Convert complex value to u64
            let re_bits = (ray.value.re.abs() * 1e16) as u64;
            let im_bits = (ray.value.im.abs() * 1e16) as u64;
            iv[i] = re_bits ^ rotl64(im_bits, 32);
        }

        iv
    }

    /// Absorb data into the hash state
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If buffer has data, try to fill it
        if self.buffer_pos > 0 {
            let space = RATE - self.buffer_pos;
            let to_copy = data.len().min(space);

            self.buffer[self.buffer_pos..self.buffer_pos + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_pos += to_copy;
            offset = to_copy;

            // If buffer is full, absorb it
            if self.buffer_pos == RATE {
                self.absorb_block(&self.buffer.clone());
                self.buffer_pos = 0;
            }
        }

        // Process full blocks
        while offset + RATE <= data.len() {
            let block: [u8; RATE] = data[offset..offset + RATE].try_into().unwrap();
            self.absorb_block(&block);
            offset += RATE;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_pos = remaining;
        }
    }

    /// Absorb a single rate-sized block
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        // XOR block into rate portion of state
        let block_words = [
            u64::from_le_bytes(block[0..8].try_into().unwrap()),
            u64::from_le_bytes(block[8..16].try_into().unwrap()),
        ];

        self.state[0] ^= block_words[0];
        self.state[1] ^= block_words[1];

        // Apply permutation
        self.permute();
    }

    /// The μ-spiral permutation function
    fn permute(&mut self) {
        for round in 0..PERMUTATION_ROUNDS {
            // 1. Add round constant
            self.state[0] ^= ROUND_CONSTANTS[round];

            // 2. θ (theta) - Column mixing via μ-mix
            let (a, b) = mu_mix(self.state[0], self.state[1], round);
            let (c, d) = mu_mix(self.state[2], self.state[3], round);
            let (e, f) = mu_mix(self.state[4], self.state[5], round);

            // 3. ρ (rho) - Rotations based on μ^n angles
            // Rotation amounts: 24, 48, 12, 36, 6, 42 (derived from 135° spiral)
            self.state[0] = rotl64(a, 24);
            self.state[1] = rotl64(b, 48 % 64);
            self.state[2] = rotl64(c, 12);
            self.state[3] = rotl64(d, 36);
            self.state[4] = rotl64(e, 6);
            self.state[5] = rotl64(f, 42);

            // 4. π (pi) - Position permutation (rotate state array)
            let temp = self.state[5];
            self.state[5] = self.state[4];
            self.state[4] = self.state[3];
            self.state[3] = self.state[2];
            self.state[2] = self.state[1];
            self.state[1] = self.state[0];
            self.state[0] = temp;

            // 5. χ (chi) - Nonlinear mixing
            let mut new_state = [0u64; 6];
            for i in 0..6 {
                new_state[i] = self.state[i]
                    ^ ((!self.state[(i + 1) % 6]) & self.state[(i + 2) % 6]);
            }
            self.state = new_state;

            // 6. S-box layer on lower bytes
            for i in 0..6 {
                let bytes = self.state[i].to_le_bytes();
                let subst_low = self.sbox.substitute(bytes[0]);
                let subst_high = self.sbox.substitute(bytes[7]);
                self.state[i] = (self.state[i] & 0x00FF_FFFF_FFFF_FF00)
                    | (subst_low as u64)
                    | ((subst_high as u64) << 56);
            }
        }
    }

    /// Finalize and produce the hash output
    pub fn finalize(mut self) -> [u8; MU_HASH_SIZE] {
        // Padding: append 0x80, zeros, and length in bits
        self.buffer[self.buffer_pos] = 0x80;
        self.buffer_pos += 1;

        // If not enough space for length, absorb current buffer and start fresh
        if self.buffer_pos > RATE - 8 {
            // Fill rest with zeros
            for i in self.buffer_pos..RATE {
                self.buffer[i] = 0;
            }
            self.absorb_block(&self.buffer.clone());
            self.buffer = [0u8; RATE];
            self.buffer_pos = 0;
        }

        // Pad with zeros up to length field
        for i in self.buffer_pos..RATE - 8 {
            self.buffer[i] = 0;
        }

        // Append length in bits (big-endian)
        let bit_len = self.total_len * 8;
        self.buffer[RATE - 8..RATE].copy_from_slice(&bit_len.to_be_bytes());

        // Final absorption
        self.absorb_block(&self.buffer.clone());

        // Squeeze phase - extract hash output
        let mut output = [0u8; MU_HASH_SIZE];

        // Extract from state (32 bytes = 4 words)
        output[0..8].copy_from_slice(&self.state[0].to_le_bytes());
        output[8..16].copy_from_slice(&self.state[1].to_le_bytes());

        // Permute and squeeze more
        self.permute();
        output[16..24].copy_from_slice(&self.state[0].to_le_bytes());
        output[24..32].copy_from_slice(&self.state[1].to_le_bytes());

        output
    }

    /// Hash data in one shot
    pub fn hash(data: &[u8]) -> [u8; MU_HASH_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash data with a key (HMAC-like construction)
    pub fn keyed_hash(key: &[u8], data: &[u8]) -> [u8; MU_HASH_SIZE] {
        // Simple prefix-MAC: H(key || data)
        // For production, use proper HMAC construction
        let mut hasher = Self::new();

        // Pad or hash key to block size
        if key.len() <= RATE {
            let mut key_block = [0u8; RATE];
            key_block[..key.len()].copy_from_slice(key);
            hasher.update(&key_block);
        } else {
            let key_hash = Self::hash(key);
            hasher.update(&key_hash);
        }

        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

/// HMAC using μ-Hash
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MuHmac {
    inner_key: [u8; RATE],
    outer_key: [u8; RATE],
}

impl MuHmac {
    /// HMAC block size
    const BLOCK_SIZE: usize = RATE;
    /// Inner padding byte
    const IPAD: u8 = 0x36;
    /// Outer padding byte
    const OPAD: u8 = 0x5c;

    /// Create new HMAC instance with given key
    pub fn new(key: &[u8]) -> Self {
        let mut processed_key = [0u8; Self::BLOCK_SIZE];

        // If key is longer than block size, hash it
        if key.len() > Self::BLOCK_SIZE {
            let hashed = MuHash::hash(key);
            processed_key[..hashed.len().min(Self::BLOCK_SIZE)]
                .copy_from_slice(&hashed[..hashed.len().min(Self::BLOCK_SIZE)]);
        } else {
            processed_key[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0u8; Self::BLOCK_SIZE];
        let mut outer_key = [0u8; Self::BLOCK_SIZE];

        for i in 0..Self::BLOCK_SIZE {
            inner_key[i] = processed_key[i] ^ Self::IPAD;
            outer_key[i] = processed_key[i] ^ Self::OPAD;
        }

        Self {
            inner_key,
            outer_key,
        }
    }

    /// Compute HMAC of data
    pub fn compute(&self, data: &[u8]) -> [u8; MU_HASH_SIZE] {
        // Inner hash: H(K ^ ipad || data)
        let mut inner_hasher = MuHash::new();
        inner_hasher.update(&self.inner_key);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.finalize();

        // Outer hash: H(K ^ opad || inner_hash)
        let mut outer_hasher = MuHash::new();
        outer_hasher.update(&self.outer_key);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize()
    }

    /// Verify HMAC
    pub fn verify(&self, data: &[u8], expected_tag: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let computed = self.compute(data);
        computed.ct_eq(expected_tag).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"Hello, mu-Hash!";
        let hash1 = MuHash::hash(data);
        let hash2 = MuHash::hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_avalanche() {
        let data1 = b"Hello, mu-Hash!";
        let mut data2 = *data1;
        data2[0] ^= 1; // Flip one bit

        let hash1 = MuHash::hash(data1);
        let hash2 = MuHash::hash(&data2);

        // Count differing bits (should be ~50%)
        let mut diff_bits = 0;
        for i in 0..MU_HASH_SIZE {
            diff_bits += (hash1[i] ^ hash2[i]).count_ones();
        }

        // Expect roughly 50% of bits to differ (128 out of 256)
        // Allow range [90, 166] for statistical variance
        assert!(diff_bits >= 90 && diff_bits <= 166,
                "Avalanche effect too weak or too strong: {} bits differ", diff_bits);
    }

    #[test]
    fn test_incremental_hash() {
        let data = b"Hello, mu-Hash! This is a longer message for testing.";

        // One-shot hash
        let hash1 = MuHash::hash(data);

        // Incremental hash
        let mut hasher = MuHash::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..30]);
        hasher.update(&data[30..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_empty_hash() {
        let hash = MuHash::hash(b"");
        // Should produce a valid (non-zero) hash for empty input
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hmac_verify() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let hmac = MuHmac::new(key);
        let tag = hmac.compute(data);

        assert!(hmac.verify(data, &tag));
        assert!(!hmac.verify(b"wrong message", &tag));
    }

    #[test]
    fn test_hmac_different_keys() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"same data";

        let tag1 = MuHmac::new(key1).compute(data);
        let tag2 = MuHmac::new(key2).compute(data);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_large_data() {
        // Test with data larger than buffer
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let hash = MuHash::hash(&data);

        // Should produce valid hash
        assert!(hash.iter().any(|&b| b != 0));

        // Should be deterministic
        let hash2 = MuHash::hash(&data);
        assert_eq!(hash, hash2);
    }
}
