//! Onion Encryption
//!
//! Implements layered encryption for onion routing.
//!
//! # Design
//!
//! Each layer uses μ-Spiral AEAD with:
//! - 256-bit key derived from circuit handshake
//! - 96-bit nonce (counter + random)
//! - Associated data: circuit_id || hop_index
//!
//! # Layer Structure
//!
//! ```text
//! +------------------+
//! | Layer 1 (Exit)   |  <- Decrypted by exit relay
//! +------------------+
//! | Layer 2 (Middle) |  <- Decrypted by middle relay
//! +------------------+
//! | Layer 3 (Guard)  |  <- Decrypted by guard relay
//! +------------------+
//! ```

use super::{create_cell_cipher, encrypt_cell, decrypt_cell, random_bytes};
use crate::{MuonResult, MuonError, CELL_PAYLOAD_SIZE};
use libmu_crypto::MuHash;

/// A single onion layer
#[derive(Debug, Clone)]
pub struct OnionLayer {
    /// Layer index (0 = innermost/exit, increasing = outer)
    pub index: u8,
    /// Encryption key for this layer
    pub key: [u8; 32],
    /// Forward nonce counter
    pub forward_counter: u64,
    /// Backward nonce counter
    pub backward_counter: u64,
    /// Random nonce prefix
    pub nonce_prefix: [u8; 4],
}

impl OnionLayer {
    /// Create a new onion layer
    pub fn new(index: u8, key: [u8; 32]) -> Self {
        // Derive nonce prefix from key for deterministic nonce generation
        // This ensures both sender and receiver use the same nonce
        let mut nonce_prefix = [0u8; 4];
        let mut hasher = MuHash::new();
        hasher.update(&key);
        hasher.update(&[index]);
        hasher.update(b"mu-onion-nonce-prefix-v1");
        let prefix_hash = hasher.finalize();
        nonce_prefix.copy_from_slice(&prefix_hash[..4]);

        Self {
            index,
            key,
            forward_counter: 0,
            backward_counter: 0,
            nonce_prefix,
        }
    }

    /// Get nonce for forward direction (client -> exit)
    fn forward_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..12].copy_from_slice(&self.forward_counter.to_le_bytes());
        self.forward_counter += 1;
        nonce
    }

    /// Get nonce for backward direction (exit -> client)
    fn backward_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        // Use high bit to distinguish direction
        let counter = self.backward_counter | (1u64 << 63);
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        self.backward_counter += 1;
        nonce
    }

    /// Encrypt data with this layer (forward direction)
    pub fn encrypt_forward(&mut self, circuit_id: u32, data: &[u8]) -> MuonResult<Vec<u8>> {
        let nonce = self.forward_nonce();
        let cipher = create_cell_cipher(&self.key, &nonce)?;

        // Associated data: circuit_id || layer_index || direction
        let mut aad = [0u8; 6];
        aad[..4].copy_from_slice(&circuit_id.to_be_bytes());
        aad[4] = self.index;
        aad[5] = 0; // Forward

        encrypt_cell(&cipher, data, &aad)
    }

    /// Decrypt data with this layer (forward direction - relay decrypts)
    pub fn decrypt_forward(&mut self, circuit_id: u32, data: &[u8]) -> MuonResult<Vec<u8>> {
        let nonce = self.forward_nonce();
        let cipher = create_cell_cipher(&self.key, &nonce)?;

        let mut aad = [0u8; 6];
        aad[..4].copy_from_slice(&circuit_id.to_be_bytes());
        aad[4] = self.index;
        aad[5] = 0;

        decrypt_cell(&cipher, data, &aad)
    }

    /// Encrypt data with this layer (backward direction - relay encrypts)
    pub fn encrypt_backward(&mut self, circuit_id: u32, data: &[u8]) -> MuonResult<Vec<u8>> {
        let nonce = self.backward_nonce();
        let cipher = create_cell_cipher(&self.key, &nonce)?;

        let mut aad = [0u8; 6];
        aad[..4].copy_from_slice(&circuit_id.to_be_bytes());
        aad[4] = self.index;
        aad[5] = 1; // Backward

        encrypt_cell(&cipher, data, &aad)
    }

    /// Decrypt data with this layer (backward direction - client decrypts)
    pub fn decrypt_backward(&mut self, circuit_id: u32, data: &[u8]) -> MuonResult<Vec<u8>> {
        let nonce = self.backward_nonce();
        let cipher = create_cell_cipher(&self.key, &nonce)?;

        let mut aad = [0u8; 6];
        aad[..4].copy_from_slice(&circuit_id.to_be_bytes());
        aad[4] = self.index;
        aad[5] = 1;

        decrypt_cell(&cipher, data, &aad)
    }
}

/// Complete onion packet with all layers
#[derive(Debug)]
pub struct OnionPacket {
    /// Circuit ID
    pub circuit_id: u32,
    /// Layers from innermost (exit) to outermost (guard)
    layers: Vec<OnionLayer>,
}

impl OnionPacket {
    /// Create a new onion packet builder
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            layers: Vec::new(),
        }
    }

    /// Add a layer (call in order from exit to guard)
    pub fn add_layer(&mut self, key: [u8; 32]) {
        let index = self.layers.len() as u8;
        self.layers.push(OnionLayer::new(index, key));
    }

    /// Get number of layers
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Wrap payload in all onion layers (client side)
    /// Encrypts from innermost (exit) to outermost (guard)
    pub fn wrap(&mut self, payload: &[u8]) -> MuonResult<Vec<u8>> {
        if payload.len() > CELL_PAYLOAD_SIZE {
            return Err(MuonError::CellTooLarge(payload.len(), CELL_PAYLOAD_SIZE));
        }

        let mut data = payload.to_vec();

        // Encrypt from innermost to outermost
        for layer in &mut self.layers {
            data = layer.encrypt_forward(self.circuit_id, &data)?;
        }

        Ok(data)
    }

    /// Peel one layer (relay side)
    /// Returns (decrypted_data, is_final_hop)
    pub fn peel(&mut self, hop_index: usize, data: &[u8]) -> MuonResult<(Vec<u8>, bool)> {
        if hop_index >= self.layers.len() {
            return Err(MuonError::InvalidCircuitState(
                format!("Invalid hop index: {}", hop_index)
            ));
        }

        // Relays decrypt in reverse order (guard first, then middle, then exit)
        let layer_index = self.layers.len() - 1 - hop_index;
        let layer = &mut self.layers[layer_index];

        let decrypted = layer.decrypt_forward(self.circuit_id, data)?;
        let is_final = layer_index == 0;

        Ok((decrypted, is_final))
    }

    /// Unwrap all layers (client side, for return traffic)
    /// Decrypts from outermost (guard) to innermost (exit)
    pub fn unwrap(&mut self, data: &[u8]) -> MuonResult<Vec<u8>> {
        let mut result = data.to_vec();

        // Decrypt from outermost to innermost (reverse order)
        for layer in self.layers.iter_mut().rev() {
            result = layer.decrypt_backward(self.circuit_id, &result)?;
        }

        Ok(result)
    }

    /// Add a layer of encryption for return traffic (relay side)
    pub fn wrap_backward(&mut self, hop_index: usize, data: &[u8]) -> MuonResult<Vec<u8>> {
        if hop_index >= self.layers.len() {
            return Err(MuonError::InvalidCircuitState(
                format!("Invalid hop index: {}", hop_index)
            ));
        }

        let layer_index = self.layers.len() - 1 - hop_index;
        let layer = &mut self.layers[layer_index];

        layer.encrypt_backward(self.circuit_id, data)
    }
}

/// Builder for creating onion packets
pub struct OnionBuilder {
    circuit_id: u32,
    keys: Vec<[u8; 32]>,
}

impl OnionBuilder {
    /// Create new onion builder
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            keys: Vec::new(),
        }
    }

    /// Add a hop with its key
    pub fn add_hop(mut self, key: [u8; 32]) -> Self {
        self.keys.push(key);
        self
    }

    /// Build the onion packet
    pub fn build(self) -> OnionPacket {
        let mut packet = OnionPacket::new(self.circuit_id);
        for key in self.keys {
            packet.add_layer(key);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_onion_layer_creation() {
        let key = random_bytes::<32>();
        let layer = OnionLayer::new(0, key);
        assert_eq!(layer.index, 0);
        assert_eq!(layer.forward_counter, 0);
    }

    #[test]
    fn test_single_layer_roundtrip() {
        let key = random_bytes::<32>();
        let mut layer = OnionLayer::new(0, key);
        let circuit_id = 12345u32;

        let plaintext = b"hello onion";
        let encrypted = layer.encrypt_forward(circuit_id, plaintext).unwrap();

        // Reset counter for decryption test
        layer.forward_counter = 0;
        let decrypted = layer.decrypt_forward(circuit_id, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_onion_packet_three_hops() {
        let circuit_id = 42u32;

        // Create keys for 3 hops (guard, middle, exit)
        let guard_key = random_bytes::<32>();
        let middle_key = random_bytes::<32>();
        let exit_key = random_bytes::<32>();

        // Build client-side onion packet for wrapping (exit -> middle -> guard order)
        let mut client_packet = OnionBuilder::new(circuit_id)
            .add_hop(exit_key)
            .add_hop(middle_key)
            .add_hop(guard_key)
            .build();

        assert_eq!(client_packet.layer_count(), 3);

        // Wrap payload (client encrypts from exit to guard layer)
        let payload = b"secret message to destination";
        let wrapped = client_packet.wrap(payload).unwrap();

        // Create separate relay layers for peeling (each relay has its own layer)
        // Guard relay has outermost layer
        let mut guard_layer = OnionLayer::new(2, guard_key);
        // Middle relay
        let mut middle_layer = OnionLayer::new(1, middle_key);
        // Exit relay has innermost layer
        let mut exit_layer = OnionLayer::new(0, exit_key);

        // Guard peels first
        let after_guard = guard_layer.decrypt_forward(circuit_id, &wrapped).unwrap();

        // Middle peels second
        let after_middle = middle_layer.decrypt_forward(circuit_id, &after_guard).unwrap();

        // Exit peels third
        let after_exit = exit_layer.decrypt_forward(circuit_id, &after_middle).unwrap();

        // Should recover original payload
        assert_eq!(&after_exit, payload);
    }

    #[test]
    fn test_backward_encryption() {
        let key = random_bytes::<32>();
        let mut layer = OnionLayer::new(0, key);
        let circuit_id = 100u32;

        let plaintext = b"response from server";

        // Relay encrypts backward
        let encrypted = layer.encrypt_backward(circuit_id, plaintext).unwrap();

        // Reset counter
        layer.backward_counter = 0;

        // Client decrypts backward
        let decrypted = layer.decrypt_backward(circuit_id, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = random_bytes::<32>();
        let mut layer = OnionLayer::new(0, key);

        let nonce1 = layer.forward_nonce();
        let nonce2 = layer.forward_nonce();
        let nonce3 = layer.forward_nonce();

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }
}
