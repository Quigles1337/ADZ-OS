//! Circuit Construction and Management
//!
//! Circuits are encrypted tunnels through the MuonNet network.
//!
//! # Circuit Lifecycle
//!
//! 1. **Creation**: Client selects path (guard → middle → exit)
//! 2. **Building**: Telescoping handshake extends circuit hop-by-hop
//! 3. **Ready**: Circuit ready for streams
//! 4. **Destruction**: Clean teardown or timeout
//!
//! # Security Properties
//!
//! - Forward secrecy per hop (ephemeral keys)
//! - Onion encryption (each hop only sees next/prev)
//! - Traffic analysis resistance (fixed-size cells)

use crate::{MuonResult, MuonError, CELL_SIZE};
use crate::cell::{Cell, CellType, RelayCell, RelayCommand, DestroyReason};
use crate::relay::{RelayDescriptor, RelayId, RelayRole};
use crate::crypto::keys::{CircuitKeys, CircuitKeysBuilder};
use crate::crypto::handshake::{ClientHandshake, derive_circuit_keys, HandshakeState};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU16, Ordering};
use std::time::{Duration, Instant};
use bytes::Bytes;

/// Unique circuit identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(u32);

impl CircuitId {
    /// Create from raw value
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get raw value
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for CircuitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit({})", self.0)
    }
}

/// Global circuit ID counter
static CIRCUIT_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Generate next circuit ID
pub fn next_circuit_id() -> CircuitId {
    CircuitId(CIRCUIT_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Circuit state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit being built
    Building,
    /// Extending to next hop
    Extending,
    /// Circuit ready for use
    Ready,
    /// Circuit being destroyed
    Destroying,
    /// Circuit destroyed
    Destroyed,
    /// Circuit failed
    Failed,
}

impl CircuitState {
    /// Check if circuit is usable for streams
    pub fn is_ready(&self) -> bool {
        matches!(self, CircuitState::Ready)
    }

    /// Check if circuit is terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, CircuitState::Destroyed | CircuitState::Failed)
    }
}

/// A hop in the circuit path
#[derive(Debug, Clone)]
pub struct CircuitHop {
    /// Relay descriptor
    pub relay: RelayDescriptor,
    /// Role in circuit
    pub role: RelayRole,
    /// Handshake state
    pub handshake: Option<ClientHandshake>,
    /// Whether handshake is complete
    pub established: bool,
}

impl CircuitHop {
    /// Create a new hop
    pub fn new(relay: RelayDescriptor, role: RelayRole) -> Self {
        Self {
            relay,
            role,
            handshake: None,
            established: false,
        }
    }

    /// Start handshake for this hop
    pub fn start_handshake(&mut self) {
        let handshake = ClientHandshake::with_relay(self.relay.onion_key);
        self.handshake = Some(handshake);
    }

    /// Get client's ephemeral public key for CREATE/EXTEND
    pub fn client_public(&self) -> Option<&[u8; 64]> {
        self.handshake.as_ref().map(|h| h.client_public())
    }

    /// Process CREATED/EXTENDED response
    pub fn process_created(
        &mut self,
        relay_ephemeral: &[u8; 64],
        signature: &[u8; 64],
    ) -> MuonResult<[u8; 32]> {
        let handshake = self.handshake.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No handshake in progress".into()))?;

        let shared = handshake.process_created(
            relay_ephemeral,
            &self.relay.identity_key,
            signature,
        )?;

        self.established = true;
        Ok(shared)
    }
}

/// Circuit path (ordered list of hops)
#[derive(Debug, Clone)]
pub struct CircuitPath {
    /// Hops in order (guard, middle(s), exit)
    hops: Vec<CircuitHop>,
}

impl CircuitPath {
    /// Create empty path
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    /// Add a hop to the path
    pub fn add_hop(&mut self, relay: RelayDescriptor, role: RelayRole) {
        self.hops.push(CircuitHop::new(relay, role));
    }

    /// Get number of hops
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Check if path is empty
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Get hop by index
    pub fn hop(&self, index: usize) -> Option<&CircuitHop> {
        self.hops.get(index)
    }

    /// Get mutable hop by index
    pub fn hop_mut(&mut self, index: usize) -> Option<&mut CircuitHop> {
        self.hops.get_mut(index)
    }

    /// Get guard (first hop)
    pub fn guard(&self) -> Option<&CircuitHop> {
        self.hops.first()
    }

    /// Get exit (last hop)
    pub fn exit(&self) -> Option<&CircuitHop> {
        self.hops.last()
    }

    /// Get all relay IDs in path
    pub fn relay_ids(&self) -> Vec<RelayId> {
        self.hops.iter().map(|h| h.relay.id).collect()
    }

    /// Check if path contains a relay
    pub fn contains(&self, relay_id: &RelayId) -> bool {
        self.hops.iter().any(|h| &h.relay.id == relay_id)
    }

    /// Iterate over hops
    pub fn iter(&self) -> impl Iterator<Item = &CircuitHop> {
        self.hops.iter()
    }
}

impl Default for CircuitPath {
    fn default() -> Self {
        Self::new()
    }
}

/// A MuonNet circuit
#[derive(Debug)]
pub struct Circuit {
    /// Circuit ID (local)
    pub id: CircuitId,
    /// Circuit state
    state: CircuitState,
    /// Circuit path
    path: CircuitPath,
    /// Encryption keys for each hop
    keys: Option<CircuitKeys>,
    /// Current hop being built (0-indexed)
    current_hop: usize,
    /// Active streams on this circuit
    streams: HashMap<u16, StreamInfo>,
    /// Next stream ID
    next_stream_id: AtomicU16,
    /// Creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Destruction reason (if destroyed)
    destroy_reason: Option<DestroyReason>,
}

/// Stream info for tracking
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID
    pub id: u16,
    /// Target address
    pub target: String,
    /// Stream state
    pub state: StreamState,
    /// Creation time
    pub created_at: Instant,
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Closing
    Closing,
    /// Closed
    Closed,
}

impl Circuit {
    /// Create a new circuit with the given path
    pub fn new(path: CircuitPath) -> Self {
        let id = next_circuit_id();

        Self {
            id,
            state: CircuitState::Building,
            path,
            keys: None,
            current_hop: 0,
            streams: HashMap::new(),
            next_stream_id: AtomicU16::new(1),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            destroy_reason: None,
        }
    }

    /// Get circuit ID
    pub fn circuit_id(&self) -> CircuitId {
        self.id
    }

    /// Get circuit state
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Get circuit path
    pub fn path(&self) -> &CircuitPath {
        &self.path
    }

    /// Check if circuit is ready
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// Get current hop being built
    pub fn current_hop(&self) -> usize {
        self.current_hop
    }

    /// Get number of established hops
    pub fn established_hops(&self) -> usize {
        self.path.iter().filter(|h| h.established).count()
    }

    /// Start building the circuit (first hop)
    pub fn start_build(&mut self) -> MuonResult<Cell> {
        if self.state != CircuitState::Building {
            return Err(MuonError::InvalidCircuitState(
                format!("Cannot start build in state {:?}", self.state)
            ));
        }

        let hop = self.path.hop_mut(0)
            .ok_or_else(|| MuonError::InvalidCircuitState("Empty path".into()))?;

        hop.start_handshake();

        let client_pub = hop.client_public()
            .ok_or_else(|| MuonError::InvalidCircuitState("No handshake".into()))?;

        // Create CREATE cell
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(client_pub);

        Cell::new(self.id.value(), CellType::Create, payload)
    }

    /// Process CREATED response for first hop
    pub fn process_created(&mut self, payload: &[u8]) -> MuonResult<()> {
        if self.state != CircuitState::Building {
            return Err(MuonError::InvalidCircuitState(
                format!("Unexpected CREATED in state {:?}", self.state)
            ));
        }

        if payload.len() < 128 {
            return Err(MuonError::RelayHandshakeFailed(
                "CREATED payload too small".into()
            ));
        }

        let mut relay_ephemeral = [0u8; 64];
        let mut signature = [0u8; 64];
        relay_ephemeral.copy_from_slice(&payload[0..64]);
        signature.copy_from_slice(&payload[64..128]);

        let hop = self.path.hop_mut(0)
            .ok_or_else(|| MuonError::InvalidCircuitState("No first hop".into()))?;

        let shared_secret = hop.process_created(&relay_ephemeral, &signature)?;

        // Derive circuit keys
        let key_material = derive_circuit_keys(&shared_secret)?;

        let mut keys = CircuitKeys::new(self.id.value());
        keys.add_hop(key_material);
        self.keys = Some(keys);

        self.current_hop = 1;

        // Check if circuit is complete
        if self.current_hop >= self.path.len() {
            self.state = CircuitState::Ready;
        } else {
            self.state = CircuitState::Extending;
        }

        self.last_activity = Instant::now();
        Ok(())
    }

    /// Create EXTEND cell for next hop
    pub fn create_extend(&mut self) -> MuonResult<Cell> {
        if self.state != CircuitState::Extending {
            return Err(MuonError::InvalidCircuitState(
                format!("Cannot extend in state {:?}", self.state)
            ));
        }

        let hop_idx = self.current_hop;
        let hop = self.path.hop_mut(hop_idx)
            .ok_or_else(|| MuonError::InvalidCircuitState(
                format!("No hop at index {}", hop_idx)
            ))?;

        hop.start_handshake();

        let client_pub = hop.client_public()
            .ok_or_else(|| MuonError::InvalidCircuitState("No handshake".into()))?;

        // Build EXTEND2 relay cell
        // Link specifiers: address of next relay
        let next_relay = &hop.relay;
        let mut link_specs = Vec::new();

        // Link specifier type 0: IPv4 address
        link_specs.push(0u8); // Type
        link_specs.push(6u8); // Length
        match next_relay.or_address {
            std::net::SocketAddr::V4(addr) => {
                link_specs.extend_from_slice(&addr.ip().octets());
                link_specs.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(addr) => {
                // Type 1: IPv6
                link_specs.clear();
                link_specs.push(1u8);
                link_specs.push(18u8);
                link_specs.extend_from_slice(&addr.ip().octets());
                link_specs.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        // Link specifier type 2: Identity key hash
        link_specs.push(2u8);
        link_specs.push(32u8);
        link_specs.extend_from_slice(next_relay.id.as_bytes());

        // Number of link specifiers
        let num_specs = 2u8;

        // Build EXTEND2 payload
        let mut extend_payload = Vec::new();
        extend_payload.push(num_specs);
        extend_payload.extend_from_slice(&link_specs);
        // Handshake type (0 = our type)
        extend_payload.extend_from_slice(&0u16.to_be_bytes());
        // Handshake data length
        extend_payload.extend_from_slice(&(64u16).to_be_bytes());
        // Client ephemeral public key
        extend_payload.extend_from_slice(client_pub);

        let relay_cell = RelayCell::new(0, RelayCommand::Extend2, extend_payload);
        let relay_payload = relay_cell.encode();

        // Encrypt through existing layers
        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let encrypted = keys.encrypt_forward(&relay_payload)?;

        Cell::new(self.id.value(), CellType::Relay, encrypted)
    }

    /// Process EXTENDED response
    pub fn process_extended(&mut self, encrypted_payload: &[u8]) -> MuonResult<()> {
        if self.state != CircuitState::Extending {
            return Err(MuonError::InvalidCircuitState(
                format!("Unexpected EXTENDED in state {:?}", self.state)
            ));
        }

        // Decrypt through existing layers
        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let decrypted = keys.decrypt_backward(encrypted_payload)?;
        let relay_cell = RelayCell::decode(&decrypted)?;

        if relay_cell.command != RelayCommand::Extended2 {
            return Err(MuonError::InvalidProtocolMessage(
                format!("Expected EXTENDED2, got {:?}", relay_cell.command)
            ));
        }

        // Parse EXTENDED2 payload
        if relay_cell.data.len() < 128 {
            return Err(MuonError::RelayHandshakeFailed(
                "EXTENDED2 payload too small".into()
            ));
        }

        let mut relay_ephemeral = [0u8; 64];
        let mut signature = [0u8; 64];
        relay_ephemeral.copy_from_slice(&relay_cell.data[0..64]);
        signature.copy_from_slice(&relay_cell.data[64..128]);

        let hop = self.path.hop_mut(self.current_hop)
            .ok_or_else(|| MuonError::InvalidCircuitState("No current hop".into()))?;

        let shared_secret = hop.process_created(&relay_ephemeral, &signature)?;

        // Add keys for this hop
        let key_material = derive_circuit_keys(&shared_secret)?;
        keys.add_hop(key_material);

        self.current_hop += 1;

        // Check if circuit is complete
        if self.current_hop >= self.path.len() {
            self.state = CircuitState::Ready;
        }

        self.last_activity = Instant::now();
        Ok(())
    }

    /// Allocate a new stream ID
    pub fn allocate_stream(&mut self, target: String) -> MuonResult<u16> {
        if !self.is_ready() {
            return Err(MuonError::CircuitNotReady(self.id.value()));
        }

        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);

        // Check for wrap-around
        if stream_id == 0 {
            return Err(MuonError::StreamLimitReached(self.id.value()));
        }

        self.streams.insert(stream_id, StreamInfo {
            id: stream_id,
            target,
            state: StreamState::Connecting,
            created_at: Instant::now(),
        });

        Ok(stream_id)
    }

    /// Create BEGIN cell for stream
    pub fn create_begin(&mut self, stream_id: u16, address: &str) -> MuonResult<Cell> {
        if !self.is_ready() {
            return Err(MuonError::CircuitNotReady(self.id.value()));
        }

        let relay_cell = RelayCell::begin(stream_id, address);
        let relay_payload = relay_cell.encode();

        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let encrypted = keys.encrypt_forward(&relay_payload)?;

        self.last_activity = Instant::now();
        Cell::new(self.id.value(), CellType::Relay, encrypted)
    }

    /// Process CONNECTED response for stream
    pub fn process_connected(&mut self, encrypted_payload: &[u8]) -> MuonResult<u16> {
        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let decrypted = keys.decrypt_backward(encrypted_payload)?;
        let relay_cell = RelayCell::decode(&decrypted)?;

        if relay_cell.command != RelayCommand::Connected {
            return Err(MuonError::InvalidProtocolMessage(
                format!("Expected CONNECTED, got {:?}", relay_cell.command)
            ));
        }

        let stream_id = relay_cell.stream_id;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Connected;
        }

        self.last_activity = Instant::now();
        Ok(stream_id)
    }

    /// Create DATA cell
    pub fn create_data(&mut self, stream_id: u16, data: &[u8]) -> MuonResult<Cell> {
        if !self.is_ready() {
            return Err(MuonError::CircuitNotReady(self.id.value()));
        }

        let relay_cell = RelayCell::data(stream_id, data.to_vec());
        let relay_payload = relay_cell.encode();

        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let encrypted = keys.encrypt_forward(&relay_payload)?;

        self.last_activity = Instant::now();
        Cell::new(self.id.value(), CellType::Relay, encrypted)
    }

    /// Process incoming relay cell
    pub fn process_relay(&mut self, encrypted_payload: &[u8]) -> MuonResult<RelayCell> {
        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let decrypted = keys.decrypt_backward(encrypted_payload)?;
        let relay_cell = RelayCell::decode(&decrypted)?;

        self.last_activity = Instant::now();
        Ok(relay_cell)
    }

    /// Create END cell for stream
    pub fn create_end(&mut self, stream_id: u16, reason: crate::cell::EndReason) -> MuonResult<Cell> {
        let relay_cell = RelayCell::end(stream_id, reason);
        let relay_payload = relay_cell.encode();

        let keys = self.keys.as_mut()
            .ok_or_else(|| MuonError::InvalidCircuitState("No keys".into()))?;

        let encrypted = keys.encrypt_forward(&relay_payload)?;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Closing;
        }

        self.last_activity = Instant::now();
        Cell::new(self.id.value(), CellType::Relay, encrypted)
    }

    /// Close a stream
    pub fn close_stream(&mut self, stream_id: u16) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Closed;
        }
    }

    /// Remove a stream
    pub fn remove_stream(&mut self, stream_id: u16) -> Option<StreamInfo> {
        self.streams.remove(&stream_id)
    }

    /// Get stream info
    pub fn stream(&self, stream_id: u16) -> Option<&StreamInfo> {
        self.streams.get(&stream_id)
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.values()
            .filter(|s| matches!(s.state, StreamState::Connecting | StreamState::Connected))
            .count()
    }

    /// Create DESTROY cell
    pub fn create_destroy(&mut self, reason: DestroyReason) -> Cell {
        self.state = CircuitState::Destroying;
        self.destroy_reason = Some(reason);
        Cell::destroy(self.id.value(), reason)
    }

    /// Mark circuit as destroyed
    pub fn mark_destroyed(&mut self, reason: DestroyReason) {
        self.state = CircuitState::Destroyed;
        self.destroy_reason = Some(reason);
    }

    /// Mark circuit as failed
    pub fn mark_failed(&mut self) {
        self.state = CircuitState::Failed;
    }

    /// Get circuit age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Check if circuit is idle
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.idle_time() > timeout && self.stream_count() == 0
    }
}

/// Builder for creating circuits
pub struct CircuitBuilder {
    path: CircuitPath,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self {
            path: CircuitPath::new(),
        }
    }

    /// Add guard relay
    pub fn guard(mut self, relay: RelayDescriptor) -> Self {
        self.path.add_hop(relay, RelayRole::Guard);
        self
    }

    /// Add middle relay
    pub fn middle(mut self, relay: RelayDescriptor) -> Self {
        self.path.add_hop(relay, RelayRole::Middle);
        self
    }

    /// Add exit relay
    pub fn exit(mut self, relay: RelayDescriptor) -> Self {
        self.path.add_hop(relay, RelayRole::Exit);
        self
    }

    /// Build the circuit
    pub fn build(self) -> MuonResult<Circuit> {
        if self.path.len() < 3 {
            return Err(MuonError::CircuitTooShort(self.path.len()));
        }

        Ok(Circuit::new(self.path))
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExitPolicy;

    fn test_relay(name: &str) -> RelayDescriptor {
        RelayDescriptor::new(
            name.into(),
            [0u8; 64],
            [0u8; 64],
            "127.0.0.1:9001".parse().unwrap(),
        )
    }

    #[test]
    fn test_circuit_id_generation() {
        let id1 = next_circuit_id();
        let id2 = next_circuit_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_circuit_path() {
        let mut path = CircuitPath::new();
        path.add_hop(test_relay("guard"), RelayRole::Guard);
        path.add_hop(test_relay("middle"), RelayRole::Middle);
        path.add_hop(test_relay("exit"), RelayRole::Exit);

        assert_eq!(path.len(), 3);
        assert_eq!(path.guard().unwrap().relay.nickname, "guard");
        assert_eq!(path.exit().unwrap().relay.nickname, "exit");
    }

    #[test]
    fn test_circuit_builder() {
        let circuit = CircuitBuilder::new()
            .guard(test_relay("guard"))
            .middle(test_relay("middle"))
            .exit(test_relay("exit"))
            .build()
            .unwrap();

        assert_eq!(circuit.state(), CircuitState::Building);
        assert_eq!(circuit.path().len(), 3);
    }

    #[test]
    fn test_circuit_builder_too_short() {
        let result = CircuitBuilder::new()
            .guard(test_relay("guard"))
            .middle(test_relay("middle"))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_states() {
        let circuit = CircuitBuilder::new()
            .guard(test_relay("guard"))
            .middle(test_relay("middle"))
            .exit(test_relay("exit"))
            .build()
            .unwrap();

        assert!(!circuit.is_ready());
        assert!(!circuit.state().is_terminal());
    }

    #[test]
    fn test_stream_allocation() {
        let mut circuit = CircuitBuilder::new()
            .guard(test_relay("guard"))
            .middle(test_relay("middle"))
            .exit(test_relay("exit"))
            .build()
            .unwrap();

        // Can't allocate streams when not ready
        assert!(circuit.allocate_stream("example.com:80".into()).is_err());
    }
}
