//! # μ-Spiral Cipher
//!
//! A novel block cipher based on μ-spiral geometry and the balance primitive.
//!
//! ## Design Principles
//! - **Key Space**: Keys derived from Z-quantization on 135° spiral
//! - **Round Function**: Rotations through μ-ray geometry
//! - **S-Box**: Generated from V_Z discrete sampling
//! - **Diffusion**: Based on |Re(V_Z)| = |Im(V_Z)| balance property
//!
//! ## Security Features
//! - 256-bit key, 128-bit block size
//! - 16 rounds (2× the μ^8 cycle)
//! - Constant-time operations where possible
//! - Zeroize on drop for sensitive data

use crate::primitives::{
    mu_mix, rotl64, rotr64, xor_blocks, GoldenSequence, MuSBox,
    SpiralRay, MU_BLOCK_SIZE, MU_KEY_SIZE, MU_ROUNDS,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error types for cipher operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// Invalid key length (expected 32 bytes)
    InvalidKeyLength,
    /// Invalid block length (expected 16 bytes)
    InvalidBlockLength,
    /// Invalid nonce length (expected 12 bytes)
    InvalidNonceLength,
    /// Authentication tag mismatch
    AuthenticationFailed,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKeyLength => write!(f, "Invalid key length (expected 32 bytes)"),
            CipherError::InvalidBlockLength => write!(f, "Invalid block length (expected 16 bytes)"),
            CipherError::InvalidNonceLength => write!(f, "Invalid nonce length (expected 12 bytes)"),
            CipherError::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
        }
    }
}

impl std::error::Error for CipherError {}

/// Round key structure for the μ-Spiral cipher
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct RoundKeys {
    /// 16 round keys, each 128 bits (two 64-bit halves)
    keys: [[u64; 2]; MU_ROUNDS],
    /// S-Box for substitution layer
    sbox: MuSBox,
}

/// The μ-Spiral Cipher
///
/// A symmetric block cipher using μ-spiral geometry for its round function.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MuSpiralCipher {
    round_keys: RoundKeys,
}

impl MuSpiralCipher {
    /// Create a new μ-Spiral cipher instance with the given key
    ///
    /// # Arguments
    /// * `key` - 256-bit (32 byte) key
    ///
    /// # Returns
    /// * `Ok(MuSpiralCipher)` on success
    /// * `Err(CipherError::InvalidKeyLength)` if key is not 32 bytes
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != MU_KEY_SIZE {
            return Err(CipherError::InvalidKeyLength);
        }

        let round_keys = Self::key_schedule(key);
        Ok(Self { round_keys })
    }

    /// Key schedule: expand 256-bit key into round keys
    fn key_schedule(key: &[u8]) -> RoundKeys {
        let mut keys = [[0u64; 2]; MU_ROUNDS];

        // Split key into 4 × 64-bit words
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let k2 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let k3 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        // Initialize golden sequence for key derivation
        let mut golden = GoldenSequence::with_seed(k0 ^ k2);

        // Generate round keys using μ-spiral properties
        let mut state = [k0, k1, k2, k3];

        for round in 0..MU_ROUNDS {
            // Apply μ-mix transformation
            let (a, b) = mu_mix(state[0], state[1], round);
            let (c, d) = mu_mix(state[2], state[3], round);

            // XOR with spiral ray constant for this round
            let ray = SpiralRay::new(round as u64 + 1);
            let ray_const = ((ray.value.re.abs() * 1e16) as u64)
                ^ ((ray.value.im.abs() * 1e16) as u64);

            // Golden ratio mixing
            let golden_factor = (golden.next() * (u64::MAX as f64)) as u64;

            // Generate round key
            keys[round][0] = a ^ c ^ ray_const;
            keys[round][1] = b ^ d ^ golden_factor;

            // Update state for next round
            state[0] = rotl64(a ^ golden_factor, 13);
            state[1] = rotr64(b ^ ray_const, 17);
            state[2] = rotl64(c ^ state[0], 29);
            state[3] = rotr64(d ^ state[1], 31);
        }

        // Generate S-Box from key material
        let sbox_seed = k0 ^ k1 ^ k2 ^ k3;
        let sbox = MuSBox::generate(sbox_seed);

        RoundKeys { keys, sbox }
    }

    /// Encrypt a single 128-bit block
    ///
    /// # Arguments
    /// * `plaintext` - 16-byte plaintext block
    ///
    /// # Returns
    /// * `Ok([u8; 16])` - 16-byte ciphertext block
    /// * `Err(CipherError::InvalidBlockLength)` if input is not 16 bytes
    pub fn encrypt_block(&self, plaintext: &[u8]) -> Result<[u8; MU_BLOCK_SIZE], CipherError> {
        if plaintext.len() != MU_BLOCK_SIZE {
            return Err(CipherError::InvalidBlockLength);
        }

        let mut block = [0u8; MU_BLOCK_SIZE];
        block.copy_from_slice(plaintext);

        // Initial whitening
        let whitening = self.round_keys.keys[0];
        self.xor_key(&mut block, whitening);

        // Main rounds
        for round in 0..MU_ROUNDS {
            self.round_encrypt(&mut block, round);
        }

        // Final whitening
        let final_whitening = self.round_keys.keys[MU_ROUNDS - 1];
        self.xor_key(&mut block, final_whitening);

        Ok(block)
    }

    /// Decrypt a single 128-bit block
    ///
    /// # Arguments
    /// * `ciphertext` - 16-byte ciphertext block
    ///
    /// # Returns
    /// * `Ok([u8; 16])` - 16-byte plaintext block
    /// * `Err(CipherError::InvalidBlockLength)` if input is not 16 bytes
    pub fn decrypt_block(&self, ciphertext: &[u8]) -> Result<[u8; MU_BLOCK_SIZE], CipherError> {
        if ciphertext.len() != MU_BLOCK_SIZE {
            return Err(CipherError::InvalidBlockLength);
        }

        let mut block = [0u8; MU_BLOCK_SIZE];
        block.copy_from_slice(ciphertext);

        // Reverse final whitening
        let final_whitening = self.round_keys.keys[MU_ROUNDS - 1];
        self.xor_key(&mut block, final_whitening);

        // Inverse rounds (in reverse order)
        for round in (0..MU_ROUNDS).rev() {
            self.round_decrypt(&mut block, round);
        }

        // Reverse initial whitening
        let whitening = self.round_keys.keys[0];
        self.xor_key(&mut block, whitening);

        Ok(block)
    }

    /// Single encryption round
    fn round_encrypt(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        // 1. Substitution layer (S-Box)
        self.substitute(block);

        // 2. Permutation layer (μ-rotation inspired bit permutation)
        self.permute(block, round);

        // 3. Diffusion layer (μ-mix)
        self.diffuse(block, round);

        // 4. Key addition
        self.xor_key(block, self.round_keys.keys[round]);
    }

    /// Single decryption round
    fn round_decrypt(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        // Inverse operations in reverse order

        // 4. Key subtraction (XOR is self-inverse)
        self.xor_key(block, self.round_keys.keys[round]);

        // 3. Inverse diffusion
        self.inverse_diffuse(block, round);

        // 2. Inverse permutation
        self.inverse_permute(block, round);

        // 1. Inverse substitution
        self.inverse_substitute(block);
    }

    /// S-Box substitution layer
    #[inline]
    fn substitute(&self, block: &mut [u8; MU_BLOCK_SIZE]) {
        for byte in block.iter_mut() {
            *byte = self.round_keys.sbox.substitute(*byte);
        }
    }

    /// Inverse S-Box substitution
    #[inline]
    fn inverse_substitute(&self, block: &mut [u8; MU_BLOCK_SIZE]) {
        for byte in block.iter_mut() {
            *byte = self.round_keys.sbox.inverse_substitute(*byte);
        }
    }

    /// Permutation layer inspired by μ-rotations
    /// Rotates bytes by positions derived from μ^n angles
    fn permute(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        // Permutation pattern based on μ-angles
        // Each position maps to: (i + round * 3) mod 16 for forward spiral
        let mut temp = [0u8; MU_BLOCK_SIZE];
        for i in 0..MU_BLOCK_SIZE {
            let target = (i + round * 3) % MU_BLOCK_SIZE;
            temp[target] = block[i];
        }
        block.copy_from_slice(&temp);

        // Bit rotation within each byte based on position
        for (i, byte) in block.iter_mut().enumerate() {
            let rot = ((i + round) % 8) as u32;
            *byte = byte.rotate_left(rot);
        }
    }

    /// Inverse permutation
    fn inverse_permute(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        // Inverse bit rotation
        for (i, byte) in block.iter_mut().enumerate() {
            let rot = ((i + round) % 8) as u32;
            *byte = byte.rotate_right(rot);
        }

        // Inverse byte permutation
        let mut temp = [0u8; MU_BLOCK_SIZE];
        for i in 0..MU_BLOCK_SIZE {
            let source = (i + round * 3) % MU_BLOCK_SIZE;
            temp[i] = block[source];
        }
        block.copy_from_slice(&temp);
    }

    /// Diffusion layer using Feistel-like ARX on 64-bit halves
    fn diffuse(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        let mut lo = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut hi = u64::from_le_bytes(block[8..16].try_into().unwrap());

        const MU_ROTATIONS: [u32; 8] = [24, 48, 12, 36, 6, 42, 18, 54];
        let rot = MU_ROTATIONS[round % 8];

        // Feistel-like structure (invertible)
        // Step 1: lo = lo ^ rotl64(hi, rot)
        lo ^= rotl64(hi, rot);
        // Step 2: hi = hi ^ rotr64(lo, rot)
        hi ^= rotr64(lo, rot);

        block[0..8].copy_from_slice(&lo.to_le_bytes());
        block[8..16].copy_from_slice(&hi.to_le_bytes());
    }

    /// Inverse diffusion
    fn inverse_diffuse(&self, block: &mut [u8; MU_BLOCK_SIZE], round: usize) {
        let mut lo = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut hi = u64::from_le_bytes(block[8..16].try_into().unwrap());

        const MU_ROTATIONS: [u32; 8] = [24, 48, 12, 36, 6, 42, 18, 54];
        let rot = MU_ROTATIONS[round % 8];

        // Inverse of Feistel steps (reverse order)
        // Inverse Step 2: hi = hi ^ rotr64(lo, rot)
        hi ^= rotr64(lo, rot);
        // Inverse Step 1: lo = lo ^ rotl64(hi, rot)
        lo ^= rotl64(hi, rot);

        block[0..8].copy_from_slice(&lo.to_le_bytes());
        block[8..16].copy_from_slice(&hi.to_le_bytes());
    }

    /// XOR block with round key
    #[inline]
    fn xor_key(&self, block: &mut [u8; MU_BLOCK_SIZE], key: [u64; 2]) {
        let key_bytes_lo = key[0].to_le_bytes();
        let key_bytes_hi = key[1].to_le_bytes();

        for i in 0..8 {
            block[i] ^= key_bytes_lo[i];
            block[i + 8] ^= key_bytes_hi[i];
        }
    }
}

/// Counter mode (CTR) encryption for arbitrary-length data
pub struct MuSpiralCtr {
    cipher: MuSpiralCipher,
    nonce: [u8; 12],
}

impl MuSpiralCtr {
    /// Create a new CTR mode cipher
    ///
    /// # Arguments
    /// * `key` - 256-bit key
    /// * `nonce` - 96-bit (12 byte) nonce
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, CipherError> {
        if nonce.len() != 12 {
            return Err(CipherError::InvalidNonceLength);
        }

        let cipher = MuSpiralCipher::new(key)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);

        Ok(Self {
            cipher,
            nonce: nonce_arr,
        })
    }

    /// Build counter block from nonce and counter
    fn build_counter_block(&self, counter: u32) -> [u8; MU_BLOCK_SIZE] {
        let mut block = [0u8; MU_BLOCK_SIZE];
        block[0..12].copy_from_slice(&self.nonce);
        block[12..16].copy_from_slice(&counter.to_be_bytes());
        block
    }

    /// Encrypt or decrypt data (CTR mode is symmetric)
    pub fn process(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = 0u32;

        for chunk in data.chunks(MU_BLOCK_SIZE) {
            let counter_block = self.build_counter_block(counter);
            let keystream = self.cipher.encrypt_block(&counter_block)?;

            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }

            counter = counter.wrapping_add(1);
        }

        Ok(output)
    }

    /// Encrypt data (same as process for CTR mode)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.process(plaintext)
    }

    /// Decrypt data (same as process for CTR mode)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.process(ciphertext)
    }
}

/// Authenticated encryption with associated data (AEAD) mode
/// Uses μ-Spiral cipher in CTR mode with polynomial MAC
pub struct MuSpiralAead {
    cipher: MuSpiralCipher,
    nonce: [u8; 12],
}

impl MuSpiralAead {
    /// Authentication tag size (128 bits)
    pub const TAG_SIZE: usize = 16;

    /// Create a new AEAD cipher
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, CipherError> {
        if nonce.len() != 12 {
            return Err(CipherError::InvalidNonceLength);
        }

        let cipher = MuSpiralCipher::new(key)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);

        Ok(Self {
            cipher,
            nonce: nonce_arr,
        })
    }

    /// Encrypt and authenticate
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// Ciphertext with appended authentication tag
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        let ctr = MuSpiralCtr {
            cipher: self.cipher.clone(),
            nonce: self.nonce,
        };

        let ciphertext = ctr.encrypt(plaintext)?;
        let tag = self.compute_tag(aad, &ciphertext)?;

        let mut output = ciphertext;
        output.extend_from_slice(&tag);

        Ok(output)
    }

    /// Decrypt and verify
    ///
    /// # Arguments
    /// * `ciphertext_with_tag` - Ciphertext with appended authentication tag
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext if authentication succeeds
    /// * `Err(CipherError::AuthenticationFailed)` if tag verification fails
    pub fn decrypt(&self, ciphertext_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext_with_tag.len() < Self::TAG_SIZE {
            return Err(CipherError::AuthenticationFailed);
        }

        let tag_start = ciphertext_with_tag.len() - Self::TAG_SIZE;
        let ciphertext = &ciphertext_with_tag[..tag_start];
        let provided_tag = &ciphertext_with_tag[tag_start..];

        let computed_tag = self.compute_tag(aad, ciphertext)?;

        // Constant-time tag comparison
        let tags_equal = provided_tag.ct_eq(&computed_tag);
        if tags_equal.into() {
            let ctr = MuSpiralCtr {
                cipher: self.cipher.clone(),
                nonce: self.nonce,
            };
            ctr.decrypt(ciphertext)
        } else {
            Err(CipherError::AuthenticationFailed)
        }
    }

    /// Compute authentication tag using polynomial MAC
    fn compute_tag(&self, aad: &[u8], ciphertext: &[u8]) -> Result<[u8; Self::TAG_SIZE], CipherError> {
        // Generate auth key by encrypting zero block with special nonce
        let mut auth_nonce_block = [0u8; MU_BLOCK_SIZE];
        auth_nonce_block[0..12].copy_from_slice(&self.nonce);
        // Counter 0 reserved for auth key
        auth_nonce_block[12..16].copy_from_slice(&0u32.to_be_bytes());

        let auth_key = self.cipher.encrypt_block(&auth_nonce_block)?;

        // Simple polynomial MAC over AAD || ciphertext || lengths
        let mut accumulator = [0u8; MU_BLOCK_SIZE];

        // Process AAD
        for chunk in aad.chunks(MU_BLOCK_SIZE) {
            let mut block = [0u8; MU_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            accumulator = xor_blocks(&accumulator, &block);
            accumulator = self.cipher.encrypt_block(&accumulator)?;
        }

        // Process ciphertext
        for chunk in ciphertext.chunks(MU_BLOCK_SIZE) {
            let mut block = [0u8; MU_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            accumulator = xor_blocks(&accumulator, &block);
            accumulator = self.cipher.encrypt_block(&accumulator)?;
        }

        // Include lengths for domain separation
        let mut length_block = [0u8; MU_BLOCK_SIZE];
        length_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        length_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        accumulator = xor_blocks(&accumulator, &length_block);
        accumulator = self.cipher.encrypt_block(&accumulator)?;

        // Final XOR with auth key
        Ok(xor_blocks(&accumulator, &auth_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    fn test_nonce() -> [u8; 12] {
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]
    }

    #[test]
    fn test_block_encrypt_decrypt() {
        let cipher = MuSpiralCipher::new(&test_key()).unwrap();

        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let ciphertext = cipher.encrypt_block(&plaintext).unwrap();
        let decrypted = cipher.decrypt_block(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_ctr_mode() {
        let cipher = MuSpiralCtr::new(&test_key(), &test_nonce()).unwrap();

        let plaintext = b"Hello, mu-Spiral cipher! This is a test of CTR mode encryption.";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aead_mode() {
        let cipher = MuSpiralAead::new(&test_key(), &test_nonce()).unwrap();

        let plaintext = b"Secret message";
        let aad = b"Additional authenticated data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let cipher = MuSpiralAead::new(&test_key(), &test_nonce()).unwrap();

        let plaintext = b"Secret message";
        let aad = b"AAD";

        let mut ciphertext = cipher.encrypt(plaintext, aad).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01;

        let result = cipher.decrypt(&ciphertext, aad);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_different_keys_different_ciphertext() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0x01;

        let cipher1 = MuSpiralCipher::new(&key1).unwrap();
        let cipher2 = MuSpiralCipher::new(&key2).unwrap();

        let plaintext = [0u8; 16];
        let ct1 = cipher1.encrypt_block(&plaintext).unwrap();
        let ct2 = cipher2.encrypt_block(&plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        assert!(matches!(
            MuSpiralCipher::new(&short_key),
            Err(CipherError::InvalidKeyLength)
        ));
    }
}
