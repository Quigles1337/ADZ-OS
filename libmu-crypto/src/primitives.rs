//! # μ-Cryptography Core Primitives
//!
//! Mathematical foundation for the μ-cryptography system based on balance primitive geometry.
//!
//! ## Core Constants
//! - **μ** = e^(i·3π/4) = (-1 + i)/√2 — The balance primitive (8th root of unity)
//! - **α** ≈ 1/137.036 — Fine-structure coupling constant
//! - **φ** = (1 + √5)/2 — Golden ratio for quasirandom sequences
//!
//! ## Key Concepts
//! - **V_Z**: Quantized spiral rays V_Z = Z · α · μ
//! - **μ^8 = 1**: Closure property enabling cyclic transformations
//! - **Balance Property**: |Re(V_Z)| = |Im(V_Z)| at the 135° angle

use num_complex::Complex64;
use zeroize::Zeroize;
use std::f64::consts::{PI, FRAC_1_SQRT_2};

/// The balance primitive μ = e^(i·3π/4) = (-1 + i)/√2
/// This is the 8th root of unity at angle 135° (3π/4 radians)
pub const MU: Complex64 = Complex64::new(-FRAC_1_SQRT_2, FRAC_1_SQRT_2);

/// Fine-structure constant α ≈ 1/137.036
/// Fundamental physical constant used for coupling in V_Z rays
pub const ALPHA: f64 = 1.0 / 137.035999084;

/// Golden ratio φ = (1 + √5)/2
/// Used for quasirandom key derivation sequences
pub const PHI: f64 = 1.618033988749895;

/// Alchemy constant K = e/μ^8 = e (since μ^8 = 1)
pub const ALCHEMY_K: f64 = std::f64::consts::E;

/// Block size in bytes for the μ-Spiral cipher
pub const MU_BLOCK_SIZE: usize = 16;

/// Number of rounds in the μ-Spiral cipher (based on 8 μ-rotations × 2)
pub const MU_ROUNDS: usize = 16;

/// Key size in bytes (256-bit security)
pub const MU_KEY_SIZE: usize = 32;

/// Hash output size in bytes
pub const MU_HASH_SIZE: usize = 32;

/// A complex number in the μ-field with secure memory handling
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct MuComplex {
    pub re: f64,
    pub im: f64,
}

impl MuComplex {
    /// Create a new MuComplex from real and imaginary parts
    #[inline]
    pub const fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    /// Create from a Complex64
    #[inline]
    pub fn from_complex(c: Complex64) -> Self {
        Self { re: c.re, im: c.im }
    }

    /// Convert to Complex64
    #[inline]
    pub fn to_complex(self) -> Complex64 {
        Complex64::new(self.re, self.im)
    }

    /// The balance primitive μ = (-1 + i)/√2
    #[inline]
    pub fn mu() -> Self {
        Self::from_complex(MU)
    }

    /// Compute μ^n using De Moivre's theorem
    /// μ^n = e^(i·n·3π/4) = cos(n·3π/4) + i·sin(n·3π/4)
    #[inline]
    pub fn mu_pow(n: i32) -> Self {
        let angle = (n as f64) * 3.0 * PI / 4.0;
        Self::new(angle.cos(), angle.sin())
    }

    /// Magnitude squared |z|^2 = re^2 + im^2
    #[inline]
    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    /// Magnitude |z| = √(re^2 + im^2)
    #[inline]
    pub fn norm(&self) -> f64 {
        self.norm_sqr().sqrt()
    }

    /// Complex conjugate z* = re - i·im
    #[inline]
    pub fn conj(&self) -> Self {
        Self::new(self.re, -self.im)
    }

    /// Complex multiplication
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        Self::new(
            self.re * other.re - self.im * other.im,
            self.re * other.im + self.im * other.re,
        )
    }

    /// Complex addition
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        Self::new(self.re + other.re, self.im + other.im)
    }

    /// Complex subtraction
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(self.re - other.re, self.im - other.im)
    }

    /// Scalar multiplication
    #[inline]
    pub fn scale(&self, s: f64) -> Self {
        Self::new(self.re * s, self.im * s)
    }

    /// Check if this complex number satisfies the balance property
    /// |Re| ≈ |Im| (within tolerance)
    #[inline]
    pub fn is_balanced(&self, tolerance: f64) -> bool {
        (self.re.abs() - self.im.abs()).abs() < tolerance
    }

    /// Rotate by μ (multiply by the balance primitive)
    #[inline]
    pub fn rotate_mu(&self) -> Self {
        self.mul(&Self::mu())
    }

    /// Rotate by μ^n
    #[inline]
    pub fn rotate_mu_n(&self, n: i32) -> Self {
        self.mul(&Self::mu_pow(n))
    }
}

/// V_Z: Quantized spiral ray computation
/// V_Z = Z · α · μ where Z is the quantization level
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct SpiralRay {
    /// Quantization level Z (integer)
    pub z: u64,
    /// The computed V_Z value
    pub value: MuComplex,
}

impl SpiralRay {
    /// Create a new spiral ray for quantization level Z
    /// V_Z = Z · α · μ
    pub fn new(z: u64) -> Self {
        let scale = (z as f64) * ALPHA;
        let value = MuComplex::mu().scale(scale);
        Self { z, value }
    }

    /// Create spiral ray with custom coupling constant
    pub fn with_coupling(z: u64, coupling: f64) -> Self {
        let scale = (z as f64) * coupling;
        let value = MuComplex::mu().scale(scale);
        Self { z, value }
    }

    /// Compute the n-th rotation of this spiral ray
    /// V_Z^(n) = V_Z · μ^n
    pub fn rotate(&self, n: i32) -> MuComplex {
        self.value.rotate_mu_n(n)
    }

    /// Get the discrete sample point on the continuous symmetry
    /// Used for S-box generation
    pub fn sample_point(&self, phase: u8) -> MuComplex {
        // Each phase represents 1/8 of the full rotation (μ^8 = 1)
        let n = (phase % 8) as i32;
        self.rotate(n)
    }

    /// Check if this ray satisfies the balance property
    pub fn is_balanced(&self) -> bool {
        // At 135°, |Re| = |Im| exactly
        self.value.is_balanced(1e-10)
    }
}

/// Golden ratio quasirandom sequence generator
/// Produces low-discrepancy sequence: {n · φ} mod 1
#[derive(Clone, Debug, Zeroize)]
pub struct GoldenSequence {
    current: u64,
    offset: f64,
}

impl GoldenSequence {
    /// Create a new golden sequence starting at n=0
    pub fn new() -> Self {
        Self {
            current: 0,
            offset: 0.0,
        }
    }

    /// Create with a seed offset
    pub fn with_seed(seed: u64) -> Self {
        Self {
            current: seed,
            offset: (seed as f64 * PHI).fract(),
        }
    }

    /// Get the next value in the sequence: {n · φ} mod 1
    pub fn next(&mut self) -> f64 {
        self.current = self.current.wrapping_add(1);
        self.offset = (self.offset + PHI).fract();
        self.offset
    }

    /// Get the n-th value directly (without advancing state)
    pub fn nth(n: u64) -> f64 {
        ((n as f64) * PHI).fract()
    }

    /// Generate n values as a vector
    pub fn generate(&mut self, n: usize) -> Vec<f64> {
        (0..n).map(|_| self.next()).collect()
    }
}

impl Default for GoldenSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// S-Box generated from V_Z discrete sampling
/// 256-byte substitution box derived from spiral geometry
#[derive(Clone, Zeroize)]
pub struct MuSBox {
    forward: [u8; 256],
    inverse: [u8; 256],
}

impl MuSBox {
    /// Generate S-Box from quantization levels and spiral sampling
    pub fn generate(seed: u64) -> Self {
        let mut forward = [0u8; 256];
        let mut inverse = [0u8; 256];
        let mut used = [false; 256];

        // Use golden ratio sequence for quasirandom selection
        let mut golden = GoldenSequence::with_seed(seed);

        for i in 0..256 {
            // Compute spiral ray for this index
            let ray = SpiralRay::new(i as u64 + 1);

            // Sample at golden-ratio-determined phase
            let phase = ((golden.next() * 8.0) as u8) % 8;
            let sample = ray.sample_point(phase);

            // Convert complex sample to byte value
            // Use both real and imaginary parts for mixing
            let re_contrib = ((sample.re.abs() * 1000.0) as u64) % 256;
            let im_contrib = ((sample.im.abs() * 1000.0) as u64) % 256;
            let mut val = ((re_contrib ^ im_contrib ^ (seed % 256)) as u8).wrapping_add(i as u8);

            // Ensure bijection by finding next unused value
            while used[val as usize] {
                val = val.wrapping_add(1);
            }

            forward[i] = val;
            inverse[val as usize] = i as u8;
            used[val as usize] = true;
        }

        Self { forward, inverse }
    }

    /// Apply forward substitution
    #[inline]
    pub fn substitute(&self, byte: u8) -> u8 {
        self.forward[byte as usize]
    }

    /// Apply inverse substitution
    #[inline]
    pub fn inverse_substitute(&self, byte: u8) -> u8 {
        self.inverse[byte as usize]
    }

    /// Get the forward table (for analysis/testing)
    pub fn forward_table(&self) -> &[u8; 256] {
        &self.forward
    }

    /// Get the inverse table (for analysis/testing)
    pub fn inverse_table(&self) -> &[u8; 256] {
        &self.inverse
    }
}

/// Convert bytes to a MuComplex for cryptographic operations
/// Maps 16 bytes to a complex number in a reversible way
pub fn bytes_to_mu_complex(bytes: &[u8; 16]) -> [MuComplex; 4] {
    let mut result = [MuComplex::new(0.0, 0.0); 4];

    for i in 0..4 {
        let offset = i * 4;
        // Interpret 4 bytes as two 16-bit values for real and imaginary
        let re_bits = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let im_bits = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);

        // Normalize to [-1, 1] range while preserving all bits
        result[i] = MuComplex::new(
            (re_bits as f64) / 32768.0 - 1.0,
            (im_bits as f64) / 32768.0 - 1.0,
        );
    }

    result
}

/// Convert MuComplex array back to bytes
pub fn mu_complex_to_bytes(complex: &[MuComplex; 4]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..4 {
        let offset = i * 4;
        // Denormalize from [-1, 1] back to u16
        let re_bits = ((complex[i].re + 1.0) * 32768.0) as u16;
        let im_bits = ((complex[i].im + 1.0) * 32768.0) as u16;

        let re_bytes = re_bits.to_le_bytes();
        let im_bytes = im_bits.to_le_bytes();

        result[offset] = re_bytes[0];
        result[offset + 1] = re_bytes[1];
        result[offset + 2] = im_bytes[0];
        result[offset + 3] = im_bytes[1];
    }

    result
}

/// XOR two byte blocks
#[inline]
pub fn xor_blocks(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Rotate left for 64-bit value
#[inline]
pub const fn rotl64(x: u64, n: u32) -> u64 {
    (x << n) | (x >> (64 - n))
}

/// Rotate right for 64-bit value
#[inline]
pub const fn rotr64(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// Mix function based on μ-spiral geometry
/// Provides diffusion using the balance property
#[inline]
pub fn mu_mix(a: u64, b: u64, round: usize) -> (u64, u64) {
    // Rotation amounts derived from μ^n angles
    // 3π/4 ≈ 135° → rotation by 135/360 * 64 ≈ 24 bits
    const MU_ROTATIONS: [u32; 8] = [24, 48, 12, 36, 6, 42, 18, 54];

    let rot = MU_ROTATIONS[round % 8];
    let mixed_a = rotl64(a, rot) ^ b;
    let mixed_b = rotr64(b, rot) ^ a;

    (mixed_a, mixed_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mu_eighth_root_of_unity() {
        // μ^8 should equal 1
        let mut result = MuComplex::mu();
        for _ in 0..7 {
            result = result.mul(&MuComplex::mu());
        }
        assert!((result.re - 1.0).abs() < 1e-10);
        assert!(result.im.abs() < 1e-10);
    }

    #[test]
    fn test_mu_balance_property() {
        // μ has |Re| = |Im| = 1/√2
        let mu = MuComplex::mu();
        assert!((mu.re.abs() - mu.im.abs()).abs() < 1e-10);
        assert!((mu.re.abs() - FRAC_1_SQRT_2).abs() < 1e-10);
    }

    #[test]
    fn test_spiral_ray_balance() {
        // V_Z = Z · α · μ should be balanced for any Z
        for z in 1..100 {
            let ray = SpiralRay::new(z);
            assert!(ray.is_balanced());
        }
    }

    #[test]
    fn test_golden_sequence_distribution() {
        // Golden ratio sequence should produce values in [0, 1)
        let mut seq = GoldenSequence::new();
        for _ in 0..1000 {
            let val = seq.next();
            assert!(val >= 0.0 && val < 1.0);
        }
    }

    #[test]
    fn test_sbox_bijection() {
        let sbox = MuSBox::generate(0);

        // Check that forward and inverse are true inverses
        for i in 0..=255u8 {
            let substituted = sbox.substitute(i);
            let recovered = sbox.inverse_substitute(substituted);
            assert_eq!(i, recovered);
        }
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let complex = bytes_to_mu_complex(&original);
        let recovered = mu_complex_to_bytes(&complex);

        // Should be approximately equal (some precision loss is expected)
        for i in 0..16 {
            assert!((original[i] as i16 - recovered[i] as i16).abs() <= 1);
        }
    }

    #[test]
    fn test_mu_pow_cycle() {
        // Test that μ^n cycles with period 8
        for n in 0..8 {
            let a = MuComplex::mu_pow(n);
            let b = MuComplex::mu_pow(n + 8);
            assert!((a.re - b.re).abs() < 1e-10);
            assert!((a.im - b.im).abs() < 1e-10);
        }
    }
}
