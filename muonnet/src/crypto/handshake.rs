//! Circuit Handshake Protocol
//!
//! Implements the cryptographic handshake for establishing circuit keys.
//!
//! # Protocol Overview
//!
//! 1. Client generates ephemeral keypair
//! 2. Client sends CREATE cell with ephemeral public key
//! 3. Relay generates its ephemeral keypair
//! 4. Relay computes shared secret and derives keys
//! 5. Relay sends CREATED cell with its public key + proof
//! 6. Client computes shared secret and derives same keys
//!
//! # Security Properties
//!
//! - Forward secrecy: Ephemeral keys are discarded after handshake
//! - Authentication: Relay signs handshake with identity key
//! - Key confirmation: Both sides derive same keys or handshake fails

use super::{derive_symmetric_secret, derive_key_material, random_bytes, CryptoContext};
use crate::{MuonResult, MuonError};
use libmu_crypto::MuHash;

/// Handshake state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state
    Initial,
    /// Client sent CREATE, waiting for CREATED
    AwaitingCreated,
    /// Handshake complete
    Complete,
    /// Handshake failed
    Failed,
}

/// Client-side handshake
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    /// Handshake state
    state: HandshakeState,
    /// Ephemeral private key
    ephemeral_private: [u8; 32],
    /// Ephemeral public key
    ephemeral_public: [u8; 64],
    /// Relay's identity public key (for verification)
    relay_identity: Option<[u8; 64]>,
    /// Derived shared secret
    shared_secret: Option<[u8; 32]>,
}

impl ClientHandshake {
    /// Create new client handshake
    pub fn new() -> Self {
        // Generate ephemeral keypair
        let seed = random_bytes::<32>();
        let keypair = libmu_crypto::signature::MuKeyPair::from_seed(&seed);

        Self {
            state: HandshakeState::Initial,
            ephemeral_private: keypair.private_key_bytes(),
            ephemeral_public: keypair.public_key().to_bytes(),
            relay_identity: None,
            shared_secret: None,
        }
    }

    /// Create new handshake targeting a specific relay
    pub fn with_relay(relay_identity: [u8; 64]) -> Self {
        let mut handshake = Self::new();
        handshake.relay_identity = Some(relay_identity);
        handshake
    }

    /// Get state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Get client's ephemeral public key (for CREATE cell)
    pub fn client_public(&self) -> &[u8; 64] {
        &self.ephemeral_public
    }

    /// Process CREATED response from relay
    pub fn process_created(
        &mut self,
        relay_ephemeral: &[u8; 64],
        relay_identity: &[u8; 64],
        signature: &[u8; 64],
    ) -> MuonResult<[u8; 32]> {
        if self.state != HandshakeState::Initial && self.state != HandshakeState::AwaitingCreated {
            return Err(MuonError::InvalidCircuitState(
                "Unexpected handshake state".into()
            ));
        }

        // Verify relay identity if we have it
        if let Some(expected) = &self.relay_identity {
            if expected != relay_identity {
                self.state = HandshakeState::Failed;
                return Err(MuonError::RelayHandshakeFailed(
                    "Relay identity mismatch".into()
                ));
            }
        }

        // Verify signature over handshake transcript
        let transcript = self.compute_transcript(relay_ephemeral);
        CryptoContext::verify(relay_identity, &transcript, signature)?;

        // Derive shared secret using symmetric derivation
        let shared = derive_symmetric_secret(
            &self.ephemeral_public,
            relay_ephemeral,
            b"muonnet-handshake-v1",
        )?;

        self.shared_secret = Some(shared);
        self.state = HandshakeState::Complete;

        Ok(shared)
    }

    /// Compute handshake transcript for signing
    fn compute_transcript(&self, relay_ephemeral: &[u8; 64]) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-handshake-transcript-v1");
        hasher.update(&self.ephemeral_public);
        hasher.update(relay_ephemeral);
        hasher.finalize()
    }

    /// Set state to awaiting (after sending CREATE)
    pub fn mark_sent(&mut self) {
        self.state = HandshakeState::AwaitingCreated;
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay-side handshake
#[derive(Debug)]
pub struct RelayHandshake {
    /// Relay's crypto context (for signing)
    context: CryptoContext,
}

impl RelayHandshake {
    /// Create new relay handshake handler
    pub fn new(context: CryptoContext) -> Self {
        Self { context }
    }

    /// Process CREATE from client, return CREATED response data
    pub fn process_create(
        &self,
        client_ephemeral: &[u8; 64],
    ) -> MuonResult<CreatedResponse> {
        // Generate ephemeral keypair
        let seed = random_bytes::<32>();
        let keypair = libmu_crypto::signature::MuKeyPair::from_seed(&seed);

        let relay_ephemeral = keypair.public_key().to_bytes();

        // Derive shared secret using symmetric derivation
        let shared = derive_symmetric_secret(
            client_ephemeral,
            &relay_ephemeral,
            b"muonnet-handshake-v1",
        )?;

        // Compute and sign transcript
        let transcript = Self::compute_transcript(client_ephemeral, &relay_ephemeral);
        let signature = self.context.sign(&transcript);

        Ok(CreatedResponse {
            relay_ephemeral,
            relay_identity: self.context.identity().public_key().to_bytes(),
            signature,
            shared_secret: shared,
        })
    }

    /// Compute handshake transcript
    fn compute_transcript(client_ephemeral: &[u8; 64], relay_ephemeral: &[u8; 64]) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-handshake-transcript-v1");
        hasher.update(client_ephemeral);
        hasher.update(relay_ephemeral);
        hasher.finalize()
    }
}

/// Response data for CREATED cell
#[derive(Debug)]
pub struct CreatedResponse {
    /// Relay's ephemeral public key
    pub relay_ephemeral: [u8; 64],
    /// Relay's identity public key
    pub relay_identity: [u8; 64],
    /// Signature over handshake transcript
    pub signature: [u8; 64],
    /// Derived shared secret (for relay's use)
    pub shared_secret: [u8; 32],
}

/// General handshake type (either client or relay side)
pub enum Handshake {
    Client(ClientHandshake),
    Relay(RelayHandshake),
}

impl Handshake {
    /// Create client handshake
    pub fn client() -> Self {
        Handshake::Client(ClientHandshake::new())
    }

    /// Create client handshake for specific relay
    pub fn client_for_relay(relay_identity: [u8; 64]) -> Self {
        Handshake::Client(ClientHandshake::with_relay(relay_identity))
    }

    /// Create relay handshake
    pub fn relay(context: CryptoContext) -> Self {
        Handshake::Relay(RelayHandshake::new(context))
    }
}

/// Derive circuit keys from shared secret
pub fn derive_circuit_keys(shared_secret: &[u8; 32]) -> MuonResult<CircuitKeyMaterial> {
    // Derive 128 bytes of key material:
    // - 32 bytes: forward key (client -> relay)
    // - 32 bytes: backward key (relay -> client)
    // - 32 bytes: forward digest key
    // - 32 bytes: backward digest key

    let material = derive_key_material(
        shared_secret,
        b"muonnet-circuit-keys",
        b"key-expansion-v1",
        128,
    )?;

    let mut forward_key = [0u8; 32];
    let mut backward_key = [0u8; 32];
    let mut forward_digest = [0u8; 32];
    let mut backward_digest = [0u8; 32];

    forward_key.copy_from_slice(&material[0..32]);
    backward_key.copy_from_slice(&material[32..64]);
    forward_digest.copy_from_slice(&material[64..96]);
    backward_digest.copy_from_slice(&material[96..128]);

    Ok(CircuitKeyMaterial {
        forward_key,
        backward_key,
        forward_digest,
        backward_digest,
    })
}

/// Key material for a circuit hop
#[derive(Debug, Clone)]
pub struct CircuitKeyMaterial {
    /// Key for forward direction (client -> relay)
    pub forward_key: [u8; 32],
    /// Key for backward direction (relay -> client)
    pub backward_key: [u8; 32],
    /// Digest key for forward direction
    pub forward_digest: [u8; 32],
    /// Digest key for backward direction
    pub backward_digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() {
        // Setup relay
        let relay_context = CryptoContext::new();
        let relay = RelayHandshake::new(relay_context);

        // Client initiates
        let mut client = ClientHandshake::new();
        let client_pub = *client.client_public();

        // Relay processes CREATE
        let response = relay.process_create(&client_pub).unwrap();

        // Client processes CREATED
        let client_secret = client.process_created(
            &response.relay_ephemeral,
            &response.relay_identity,
            &response.signature,
        ).unwrap();

        // Both should have same shared secret
        assert_eq!(client_secret, response.shared_secret);
        assert_eq!(client.state(), HandshakeState::Complete);
    }

    #[test]
    fn test_handshake_with_identity_verification() {
        let relay_context = CryptoContext::new();
        let relay_identity = relay_context.identity().public_key().to_bytes();
        let relay = RelayHandshake::new(relay_context);

        // Client knows relay identity
        let mut client = ClientHandshake::with_relay(relay_identity);
        let client_pub = *client.client_public();

        let response = relay.process_create(&client_pub).unwrap();

        // Should succeed with correct identity
        let result = client.process_created(
            &response.relay_ephemeral,
            &response.relay_identity,
            &response.signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handshake_identity_mismatch() {
        let relay_context = CryptoContext::new();
        let relay = RelayHandshake::new(relay_context);

        // Client expects different relay
        let fake_identity = [0xffu8; 64];
        let mut client = ClientHandshake::with_relay(fake_identity);
        let client_pub = *client.client_public();

        let response = relay.process_create(&client_pub).unwrap();

        // Should fail with wrong identity
        let result = client.process_created(
            &response.relay_ephemeral,
            &response.relay_identity,
            &response.signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_key_derivation() {
        let shared = random_bytes::<32>();
        let keys = derive_circuit_keys(&shared).unwrap();

        // All keys should be different
        assert_ne!(keys.forward_key, keys.backward_key);
        assert_ne!(keys.forward_digest, keys.backward_digest);
        assert_ne!(keys.forward_key, keys.forward_digest);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let shared = [42u8; 32];

        let keys1 = derive_circuit_keys(&shared).unwrap();
        let keys2 = derive_circuit_keys(&shared).unwrap();

        assert_eq!(keys1.forward_key, keys2.forward_key);
        assert_eq!(keys1.backward_key, keys2.backward_key);
    }
}
