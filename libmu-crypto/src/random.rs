//! # μ-CSPRNG
//!
//! Cryptographically secure pseudo-random number generator seeded from
//! quantum-inspired μ-sampling.
//!
//! ## Design
//! - ChaCha20-like structure with μ-spiral mixing
//! - Forward secrecy through continuous reseeding
//! - Backtracking resistance via state destruction
//!
//! ## Seeding
//! - System entropy from OS
//! - Golden ratio sequence for additional mixing
//! - μ-spiral transformation for state expansion

use crate::hash::MuHash;
use crate::primitives::{mu_mix, rotl64, GoldenSequence, SpiralRay};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State size in 64-bit words (512 bits)
const STATE_WORDS: usize = 8;
/// Output buffer size in bytes
const OUTPUT_BUFFER_SIZE: usize = 64;
/// Reseed interval (number of output blocks before automatic reseed)
const RESEED_INTERVAL: u64 = 1 << 20; // ~1 million blocks

/// Error types for random operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomError {
    /// System entropy source unavailable
    EntropyUnavailable,
    /// State exhausted, needs reseed
    NeedsReseed,
    /// Internal error
    InternalError,
}

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandomError::EntropyUnavailable => write!(f, "System entropy source unavailable"),
            RandomError::NeedsReseed => write!(f, "CSPRNG needs reseeding"),
            RandomError::InternalError => write!(f, "Internal CSPRNG error"),
        }
    }
}

impl std::error::Error for RandomError {}

/// μ-CSPRNG: Cryptographically secure random number generator
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MuRng {
    /// Internal state (8 × 64-bit words)
    state: [u64; STATE_WORDS],
    /// Output buffer
    buffer: [u8; OUTPUT_BUFFER_SIZE],
    /// Current position in buffer
    buffer_pos: usize,
    /// Block counter for reseeding
    block_counter: u64,
    /// Golden sequence for mixing
    #[zeroize(skip)]
    golden: GoldenSequence,
}

impl MuRng {
    /// Create a new μ-CSPRNG seeded from system entropy
    pub fn new() -> Result<Self, RandomError> {
        let mut seed = [0u8; 64];

        // Get entropy from OS
        getrandom::getrandom(&mut seed)
            .map_err(|_| RandomError::EntropyUnavailable)?;

        Ok(Self::from_seed(&seed))
    }

    /// Create μ-CSPRNG from a seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut state = [0u64; STATE_WORDS];

        // Initialize state from seed using μ-Hash
        let seed_hash = MuHash::hash(seed);

        // First 4 words from seed hash
        for i in 0..4 {
            state[i] = u64::from_le_bytes(seed_hash[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Remaining 4 words from spiral ray constants
        for i in 0..4 {
            let ray = SpiralRay::new((i + 1) as u64);
            let re_bits = (ray.value.re.abs() * 1e18) as u64;
            let im_bits = (ray.value.im.abs() * 1e18) as u64;
            state[i + 4] = re_bits ^ rotl64(im_bits, 32) ^ state[i];
        }

        // Create golden sequence seeded from state
        let golden_seed = state[0] ^ state[1] ^ state[2] ^ state[3];

        let mut rng = Self {
            state,
            buffer: [0u8; OUTPUT_BUFFER_SIZE],
            buffer_pos: OUTPUT_BUFFER_SIZE, // Force initial generation
            block_counter: 0,
            golden: GoldenSequence::with_seed(golden_seed),
        };

        // Mix initial state
        rng.mix_state();

        rng
    }

    /// Reseed the CSPRNG with additional entropy
    pub fn reseed(&mut self, additional_seed: &[u8]) -> Result<(), RandomError> {
        let mut new_entropy = [0u8; 64];

        // Mix in system entropy
        getrandom::getrandom(&mut new_entropy)
            .map_err(|_| RandomError::EntropyUnavailable)?;

        // Hash: current state || system entropy || additional seed
        let mut hasher = MuHash::new();
        for word in &self.state {
            hasher.update(&word.to_le_bytes());
        }
        hasher.update(&new_entropy);
        hasher.update(additional_seed);
        let new_seed = hasher.finalize();

        // Update state
        for i in 0..4 {
            self.state[i] ^= u64::from_le_bytes(
                new_seed[i * 8..(i + 1) * 8].try_into().unwrap()
            );
        }

        // Reset counter and buffer
        self.block_counter = 0;
        self.buffer_pos = OUTPUT_BUFFER_SIZE;

        // Mix state
        self.mix_state();

        // Zeroize temporary entropy
        new_entropy.zeroize();

        Ok(())
    }

    /// Generate random bytes
    pub fn fill_bytes_result(&mut self, dest: &mut [u8]) -> Result<(), RandomError> {
        let mut offset = 0;

        while offset < dest.len() {
            // Check if we need to refill buffer
            if self.buffer_pos >= OUTPUT_BUFFER_SIZE {
                // Check if we need to reseed
                if self.block_counter >= RESEED_INTERVAL {
                    self.reseed(&[])?;
                }

                self.generate_block();
                self.buffer_pos = 0;
                self.block_counter += 1;
            }

            let available = OUTPUT_BUFFER_SIZE - self.buffer_pos;
            let to_copy = (dest.len() - offset).min(available);

            dest[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);

            self.buffer_pos += to_copy;
            offset += to_copy;
        }

        Ok(())
    }

    /// Generate a single block of random output
    fn generate_block(&mut self) {
        // Copy state for output generation
        let mut working_state = self.state;

        // Apply 20 rounds of mixing (similar to ChaCha20)
        for _ in 0..10 {
            // Column rounds
            self.quarter_round(&mut working_state, 0, 2, 4, 6);
            self.quarter_round(&mut working_state, 1, 3, 5, 7);

            // Diagonal rounds
            self.quarter_round(&mut working_state, 0, 3, 4, 7);
            self.quarter_round(&mut working_state, 1, 2, 5, 6);
        }

        // Add original state (makes the function not invertible)
        for i in 0..STATE_WORDS {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }

        // Convert to bytes
        for i in 0..STATE_WORDS {
            self.buffer[i * 8..(i + 1) * 8].copy_from_slice(&working_state[i].to_le_bytes());
        }

        // Update internal state for forward secrecy
        self.advance_state();

        // Zeroize working state
        working_state.zeroize();
    }

    /// Quarter round function using μ-mix
    fn quarter_round(&self, state: &mut [u64; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
        // μ-inspired mixing
        let (ab, ba) = mu_mix(state[a], state[b], a);
        let (cd, dc) = mu_mix(state[c], state[d], c);

        state[a] = ab ^ rotl64(cd, 16);
        state[b] = ba ^ rotl64(dc, 32);
        state[c] = cd ^ rotl64(ab, 24);
        state[d] = dc ^ rotl64(ba, 48);
    }

    /// Advance internal state (forward secrecy)
    fn advance_state(&mut self) {
        // Use golden ratio sequence for state advancement
        let golden_val = (self.golden.next() * (u64::MAX as f64)) as u64;

        // Mix state forward
        for i in 0..STATE_WORDS {
            self.state[i] = rotl64(
                self.state[i] ^ golden_val,
                ((i + 1) * 7) as u32 % 64
            );
        }

        // Additional mixing via mu_mix
        for i in 0..STATE_WORDS / 2 {
            let (a, b) = mu_mix(self.state[i * 2], self.state[i * 2 + 1], i);
            self.state[i * 2] = a;
            self.state[i * 2 + 1] = b;
        }
    }

    /// Mix the internal state (used during init and reseed)
    fn mix_state(&mut self) {
        // Apply multiple rounds of mixing
        for round in 0..4 {
            for i in 0..STATE_WORDS / 2 {
                let (a, b) = mu_mix(self.state[i], self.state[STATE_WORDS - 1 - i], round);
                self.state[i] = a;
                self.state[STATE_WORDS - 1 - i] = b;
            }

            // Rotate state array
            let temp = self.state[0];
            for i in 0..STATE_WORDS - 1 {
                self.state[i] = self.state[i + 1];
            }
            self.state[STATE_WORDS - 1] = temp;
        }
    }

    /// Generate a random u64
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Generate a random u32
    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Generate random bytes into a fixed-size array
    pub fn random_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random value in range [0, bound)
    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }

        // Rejection sampling for uniform distribution
        let threshold = (u64::MAX - bound + 1) % bound;

        loop {
            let val = self.next_u64();
            if val >= threshold {
                return val % bound;
            }
        }
    }
}

impl Default for MuRng {
    fn default() -> Self {
        Self::new().expect("Failed to initialize CSPRNG from system entropy")
    }
}

// Implement RngCore for compatibility with rand ecosystem
impl RngCore for MuRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Panic on error for RngCore compatibility
        self.fill_bytes_result(dest)
            .expect("CSPRNG entropy exhausted")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes_result(dest)
            .map_err(|_| {
                // Create error from a NonZeroU32 code
                rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap())
            })
    }
}

// Mark as cryptographically secure
impl CryptoRng for MuRng {}

/// Generate a random byte array using system entropy
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| RandomError::EntropyUnavailable)?;
    Ok(bytes)
}

/// Generate random bytes into a mutable slice
pub fn fill_random(dest: &mut [u8]) -> Result<(), RandomError> {
    getrandom::getrandom(dest)
        .map_err(|_| RandomError::EntropyUnavailable)
}

// Thread-local CSPRNG for convenience
#[cfg(feature = "std")]
thread_local! {
    static THREAD_RNG: std::cell::RefCell<MuRng> = std::cell::RefCell::new(
        MuRng::new().expect("Failed to initialize thread-local CSPRNG")
    );
}

/// Get random bytes using thread-local CSPRNG
#[cfg(feature = "std")]
pub fn thread_random_bytes<const N: usize>() -> [u8; N] {
    THREAD_RNG.with(|rng| rng.borrow_mut().random_bytes::<N>())
}

/// Fill slice with random bytes using thread-local CSPRNG
#[cfg(feature = "std")]
pub fn thread_fill_random(dest: &mut [u8]) {
    THREAD_RNG.with(|rng| rng.borrow_mut().fill_bytes(dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_deterministic_from_seed() {
        let seed = b"test seed for deterministic output";

        let mut rng1 = MuRng::from_seed(seed);
        let mut rng2 = MuRng::from_seed(seed);

        let output1: [u8; 64] = rng1.random_bytes();
        let output2: [u8; 64] = rng2.random_bytes();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_rng_different_seeds() {
        let mut rng1 = MuRng::from_seed(b"seed 1");
        let mut rng2 = MuRng::from_seed(b"seed 2");

        let output1: [u8; 32] = rng1.random_bytes();
        let output2: [u8; 32] = rng2.random_bytes();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_rng_sequential_different() {
        let mut rng = MuRng::from_seed(b"test seed");

        let output1: [u8; 32] = rng.random_bytes();
        let output2: [u8; 32] = rng.random_bytes();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_rng_large_output() {
        let mut rng = MuRng::from_seed(b"large output test");

        let mut output = vec![0u8; 10000];
        rng.fill_bytes(&mut output);

        // Check that output is not all zeros
        assert!(output.iter().any(|&b| b != 0));

        // Check distribution (very basic)
        let zeros = output.iter().filter(|&&b| b == 0).count();
        let expected_zeros = 10000 / 256;
        // Allow some variance
        assert!(zeros < expected_zeros * 2);
    }

    #[test]
    fn test_rng_bounded() {
        let mut rng = MuRng::from_seed(b"bounded test");

        for _ in 0..1000 {
            let val = rng.next_bounded(100);
            assert!(val < 100);
        }
    }

    #[test]
    fn test_rng_reseed() {
        let mut rng = MuRng::from_seed(b"initial seed");

        let output1: [u8; 32] = rng.random_bytes();

        rng.reseed(b"additional entropy").unwrap();

        let output2: [u8; 32] = rng.random_bytes();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_rng_core_trait() {
        let mut rng = MuRng::from_seed(b"trait test");

        // Test RngCore trait methods
        let _val32 = RngCore::next_u32(&mut rng);
        let _val64 = RngCore::next_u64(&mut rng);

        let mut buf = [0u8; 16];
        RngCore::fill_bytes(&mut rng, &mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_function() {
        let bytes1: [u8; 32] = random_bytes().unwrap();
        let bytes2: [u8; 32] = random_bytes().unwrap();

        // Extremely unlikely to be equal
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_zeroize_on_drop() {
        let seed = b"zeroize test";
        let rng = MuRng::from_seed(seed);

        // Get a copy of internal state before drop
        let state_before = rng.state;

        // Drop the RNG
        drop(rng);

        // Note: We can't actually verify zeroization after drop
        // This test just ensures the zeroize derive compiles correctly
        assert!(state_before.iter().any(|&v| v != 0));
    }
}
