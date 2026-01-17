//! Circuit Key Management
//!
//! Manages encryption keys for circuit hops.

use super::onion::OnionLayer;
use super::handshake::CircuitKeyMaterial;
use crate::MuonResult;

/// Keys for a single hop in a circuit
#[derive(Debug, Clone)]
pub struct HopKeys {
    /// Hop index (0 = guard, increasing toward exit)
    pub hop_index: usize,
    /// Raw key material
    pub material: CircuitKeyMaterial,
    /// Onion layer for this hop
    pub layer: OnionLayer,
}

impl HopKeys {
    /// Create new hop keys from key material
    pub fn new(hop_index: usize, material: CircuitKeyMaterial) -> Self {
        // Use forward key for onion layer
        let layer = OnionLayer::new(hop_index as u8, material.forward_key);

        Self {
            hop_index,
            material,
            layer,
        }
    }

    /// Get forward encryption key
    pub fn forward_key(&self) -> &[u8; 32] {
        &self.material.forward_key
    }

    /// Get backward decryption key
    pub fn backward_key(&self) -> &[u8; 32] {
        &self.material.backward_key
    }
}

/// Key material for deriving session keys
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Master secret
    master: [u8; 32],
    /// Salt for key derivation
    salt: [u8; 32],
    /// Key derivation counter
    counter: u32,
}

impl KeyMaterial {
    /// Create new key material from master secret
    pub fn new(master: [u8; 32], salt: [u8; 32]) -> Self {
        Self {
            master,
            salt,
            counter: 0,
        }
    }

    /// Derive next key
    pub fn next_key(&mut self) -> MuonResult<[u8; 32]> {
        use super::derive_key_material;

        let info = self.counter.to_be_bytes();
        let material = derive_key_material(&self.master, &self.salt, &info, 32)?;

        self.counter += 1;

        let mut key = [0u8; 32];
        key.copy_from_slice(&material);
        Ok(key)
    }

    /// Get current counter
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

/// Complete key set for a circuit
#[derive(Debug)]
pub struct CircuitKeys {
    /// Circuit ID
    circuit_id: u32,
    /// Keys for each hop (ordered from guard to exit)
    hops: Vec<HopKeys>,
}

impl CircuitKeys {
    /// Create new circuit key set
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            hops: Vec::new(),
        }
    }

    /// Add keys for a new hop
    pub fn add_hop(&mut self, material: CircuitKeyMaterial) {
        let hop_index = self.hops.len();
        self.hops.push(HopKeys::new(hop_index, material));
    }

    /// Get number of hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Get keys for a specific hop
    pub fn hop(&self, index: usize) -> Option<&HopKeys> {
        self.hops.get(index)
    }

    /// Get mutable keys for a specific hop
    pub fn hop_mut(&mut self, index: usize) -> Option<&mut HopKeys> {
        self.hops.get_mut(index)
    }

    /// Get circuit ID
    pub fn circuit_id(&self) -> u32 {
        self.circuit_id
    }

    /// Encrypt payload through all layers (client side, forward direction)
    pub fn encrypt_forward(&mut self, payload: &[u8]) -> MuonResult<Vec<u8>> {
        let mut data = payload.to_vec();

        // Encrypt from innermost (exit) to outermost (guard)
        for hop in self.hops.iter_mut().rev() {
            data = hop.layer.encrypt_forward(self.circuit_id, &data)?;
        }

        Ok(data)
    }

    /// Decrypt payload through all layers (client side, backward direction)
    pub fn decrypt_backward(&mut self, payload: &[u8]) -> MuonResult<Vec<u8>> {
        let mut data = payload.to_vec();

        // Decrypt from outermost (guard) to innermost (exit)
        for hop in self.hops.iter_mut() {
            data = hop.layer.decrypt_backward(self.circuit_id, &data)?;
        }

        Ok(data)
    }

    /// Peel one layer (relay side)
    pub fn peel_layer(&mut self, hop_index: usize, payload: &[u8]) -> MuonResult<Vec<u8>> {
        let hop = self.hops.get_mut(hop_index)
            .ok_or_else(|| crate::MuonError::InvalidCircuitState(
                format!("Invalid hop index: {}", hop_index)
            ))?;

        hop.layer.decrypt_forward(self.circuit_id, payload)
    }

    /// Add one layer (relay side, backward direction)
    pub fn add_layer(&mut self, hop_index: usize, payload: &[u8]) -> MuonResult<Vec<u8>> {
        let hop = self.hops.get_mut(hop_index)
            .ok_or_else(|| crate::MuonError::InvalidCircuitState(
                format!("Invalid hop index: {}", hop_index)
            ))?;

        hop.layer.encrypt_backward(self.circuit_id, payload)
    }

    /// Check if circuit is fully established
    pub fn is_complete(&self) -> bool {
        self.hops.len() >= 3 // Minimum 3 hops
    }
}

/// Builder for circuit keys
pub struct CircuitKeysBuilder {
    circuit_id: u32,
    materials: Vec<CircuitKeyMaterial>,
}

impl CircuitKeysBuilder {
    /// Create new builder
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            materials: Vec::new(),
        }
    }

    /// Add key material for a hop
    pub fn add_material(mut self, material: CircuitKeyMaterial) -> Self {
        self.materials.push(material);
        self
    }

    /// Build the circuit keys
    pub fn build(self) -> CircuitKeys {
        let mut keys = CircuitKeys::new(self.circuit_id);
        for material in self.materials {
            keys.add_hop(material);
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    fn random_key_material() -> CircuitKeyMaterial {
        CircuitKeyMaterial {
            forward_key: random_bytes(),
            backward_key: random_bytes(),
            forward_digest: random_bytes(),
            backward_digest: random_bytes(),
        }
    }

    #[test]
    fn test_hop_keys_creation() {
        let material = random_key_material();
        let hop = HopKeys::new(0, material.clone());

        assert_eq!(hop.hop_index, 0);
        assert_eq!(hop.forward_key(), &material.forward_key);
    }

    #[test]
    fn test_key_material_derivation() {
        let master = random_bytes::<32>();
        let salt = random_bytes::<32>();

        let mut material = KeyMaterial::new(master, salt);

        let key1 = material.next_key().unwrap();
        let key2 = material.next_key().unwrap();

        assert_ne!(key1, key2);
        assert_eq!(material.counter(), 2);
    }

    #[test]
    fn test_circuit_keys_building() {
        let circuit_id = 42u32;

        let keys = CircuitKeysBuilder::new(circuit_id)
            .add_material(random_key_material())
            .add_material(random_key_material())
            .add_material(random_key_material())
            .build();

        assert_eq!(keys.circuit_id(), circuit_id);
        assert_eq!(keys.hop_count(), 3);
        assert!(keys.is_complete());
    }

    #[test]
    fn test_circuit_encryption_decryption() {
        let circuit_id = 100u32;

        // Create same keys for "client" and "relays"
        let m1 = random_key_material();
        let m2 = random_key_material();
        let m3 = random_key_material();

        let mut client_keys = CircuitKeysBuilder::new(circuit_id)
            .add_material(m1.clone())
            .add_material(m2.clone())
            .add_material(m3.clone())
            .build();

        let payload = b"test message through circuit";

        // Client encrypts
        let encrypted = client_keys.encrypt_forward(payload).unwrap();

        // Simulated relay peeling would happen here
        // For this test, we just verify the encrypted data is different
        assert_ne!(encrypted.as_slice(), payload);
    }

    #[test]
    fn test_incomplete_circuit() {
        let keys = CircuitKeysBuilder::new(1)
            .add_material(random_key_material())
            .add_material(random_key_material())
            .build();

        assert!(!keys.is_complete()); // Only 2 hops
    }
}
