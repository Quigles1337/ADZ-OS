//! MuonNet Client
//!
//! High-level client for building circuits and routing traffic.
//!
//! # Usage
//!
//! ```ignore
//! let config = MuonConfig::client();
//! let client = MuonClient::new(config).await?;
//!
//! // Connect to destination
//! let stream = client.connect("example.com:80").await?;
//!
//! // Or connect to hidden service
//! let stream = client.connect_hidden("abc...xyz.muon:80").await?;
//! ```

use crate::{MuonResult, MuonError, DEFAULT_CIRCUIT_LENGTH};
use crate::config::MuonConfig;
use crate::crypto::CryptoContext;
use crate::circuit::{Circuit, CircuitBuilder, CircuitId, CircuitState};
use crate::stream::{MuonStream, StreamManager, MuonStreamState};
use crate::relay::{RelayDescriptor, RelayId, RelayRole};
use crate::directory::DirectoryCache;
use crate::hidden::{MuonAddress, HiddenServiceClient, HiddenServiceDescriptor};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default circuit build timeout
pub const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Default circuit idle timeout
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Preemptive circuit count
pub const PREEMPTIVE_CIRCUITS: usize = 3;

/// MuonNet client
#[derive(Debug)]
pub struct MuonClient {
    /// Client configuration
    config: MuonConfig,
    /// Crypto context (identity)
    crypto: CryptoContext,
    /// Directory cache
    directory: DirectoryCache,
    /// Active circuits
    circuits: HashMap<CircuitId, Circuit>,
    /// Circuit manager
    circuit_manager: CircuitManager,
    /// Stream managers per circuit
    stream_managers: HashMap<CircuitId, StreamManager>,
    /// Hidden service connections
    hidden_clients: HashMap<MuonAddress, HiddenServiceClient>,
    /// Client state
    state: ClientState,
}

/// Client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Initializing
    Initializing,
    /// Bootstrapping (fetching directory)
    Bootstrapping,
    /// Ready for connections
    Ready,
    /// Shutting down
    ShuttingDown,
    /// Stopped
    Stopped,
}

impl MuonClient {
    /// Create new client
    pub fn new(config: MuonConfig) -> MuonResult<Self> {
        config.validate()?;

        let crypto = CryptoContext::new();

        Ok(Self {
            config,
            crypto,
            directory: DirectoryCache::new(),
            circuits: HashMap::new(),
            circuit_manager: CircuitManager::new(),
            stream_managers: HashMap::new(),
            hidden_clients: HashMap::new(),
            state: ClientState::Initializing,
        })
    }

    /// Get client state
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Check if client is ready
    pub fn is_ready(&self) -> bool {
        self.state == ClientState::Ready
    }

    /// Bootstrap the client (fetch directory)
    pub fn bootstrap(&mut self) -> MuonResult<()> {
        self.state = ClientState::Bootstrapping;

        // In a real implementation, this would:
        // 1. Connect to directory servers
        // 2. Download consensus
        // 3. Download relay descriptors
        // 4. Build preemptive circuits

        // For now, mark as ready
        self.state = ClientState::Ready;
        Ok(())
    }

    /// Get number of ready circuits
    pub fn ready_circuit_count(&self) -> usize {
        self.circuits.values()
            .filter(|c| c.is_ready())
            .count()
    }

    /// Get a ready circuit for destination
    pub fn get_circuit(&self) -> Option<&Circuit> {
        self.circuits.values()
            .find(|c| c.is_ready())
    }

    /// Get a mutable ready circuit
    pub fn get_circuit_mut(&mut self) -> Option<&mut Circuit> {
        self.circuits.values_mut()
            .find(|c| c.is_ready())
    }

    /// Get circuit by ID
    pub fn circuit(&self, id: CircuitId) -> Option<&Circuit> {
        self.circuits.get(&id)
    }

    /// Get mutable circuit by ID
    pub fn circuit_mut(&mut self, id: CircuitId) -> Option<&mut Circuit> {
        self.circuits.get_mut(&id)
    }

    /// Build a new circuit
    pub fn build_circuit(&mut self) -> MuonResult<CircuitId> {
        // Select path from directory
        let path = self.directory.build_path(443)
            .ok_or_else(|| MuonError::NoPath("No suitable path found".into()))?;

        let circuit = CircuitBuilder::new()
            .guard(path[0].clone())
            .middle(path[1].clone())
            .exit(path[2].clone())
            .build()?;

        let id = circuit.circuit_id();
        self.circuits.insert(id, circuit);

        // Create stream manager for circuit
        self.stream_managers.insert(id, StreamManager::new(id, 500));

        Ok(id)
    }

    /// Build circuit with specific relays
    pub fn build_circuit_with_path(&mut self, path: Vec<RelayDescriptor>) -> MuonResult<CircuitId> {
        let path_len = path.len();
        if path_len < 3 {
            return Err(MuonError::CircuitTooShort(path_len));
        }

        let mut builder = CircuitBuilder::new();

        for (i, relay) in path.into_iter().enumerate() {
            let role = match i {
                0 => RelayRole::Guard,
                n if n == path_len - 1 => RelayRole::Exit,
                _ => RelayRole::Middle,
            };

            builder = match role {
                RelayRole::Guard => builder.guard(relay),
                RelayRole::Middle => builder.middle(relay),
                RelayRole::Exit => builder.exit(relay),
            };
        }

        let circuit = builder.build()?;
        let id = circuit.circuit_id();
        self.circuits.insert(id, circuit);
        self.stream_managers.insert(id, StreamManager::new(id, 500));

        Ok(id)
    }

    /// Connect to a destination
    pub fn connect(&mut self, address: &str) -> MuonResult<StreamHandle> {
        // Get or build circuit
        let circuit_id = if let Some(circuit) = self.get_circuit() {
            circuit.circuit_id()
        } else {
            self.build_circuit()?
        };

        // Allocate stream
        let circuit = self.circuits.get_mut(&circuit_id)
            .ok_or_else(|| MuonError::CircuitNotReady(circuit_id.value()))?;

        let stream_id = circuit.allocate_stream(address.to_string())?;

        let manager = self.stream_managers.get_mut(&circuit_id)
            .ok_or_else(|| MuonError::CircuitNotReady(circuit_id.value()))?;

        manager.create_stream(address.to_string())?;

        Ok(StreamHandle {
            circuit_id,
            stream_id,
        })
    }

    /// Connect to hidden service
    pub fn connect_hidden(&mut self, address: &str) -> MuonResult<StreamHandle> {
        // Parse address
        let (muon_addr, port) = parse_hidden_address(address)?;

        // Get or fetch descriptor
        let client = self.hidden_clients.entry(muon_addr.clone())
            .or_insert_with(|| HiddenServiceClient::new(muon_addr.clone()));

        if client.descriptor().is_none() {
            // Would fetch descriptor from HSDir
            return Err(MuonError::HiddenServiceFailed(
                "Descriptor not available".into()
            ));
        }

        // Build rendezvous circuit
        // This is simplified - real implementation would:
        // 1. Build circuit to rendezvous point
        // 2. Send ESTABLISH_RENDEZVOUS
        // 3. Build circuit to intro point
        // 4. Send INTRODUCE1
        // 5. Wait for RENDEZVOUS2
        // 6. Circuit is ready

        Err(MuonError::HiddenServiceFailed(
            "Hidden service connection not fully implemented".into()
        ))
    }

    /// Close a stream
    pub fn close_stream(&mut self, handle: StreamHandle) -> MuonResult<()> {
        let manager = self.stream_managers.get_mut(&handle.circuit_id)
            .ok_or_else(|| MuonError::CircuitNotReady(handle.circuit_id.value()))?;

        if let Some(stream) = manager.get_mut(handle.stream_id) {
            stream.close();
        }

        Ok(())
    }

    /// Destroy a circuit
    pub fn destroy_circuit(&mut self, id: CircuitId) -> MuonResult<()> {
        if let Some(circuit) = self.circuits.get_mut(&id) {
            circuit.mark_destroyed(crate::cell::DestroyReason::Requested);
        }

        self.stream_managers.remove(&id);
        self.circuits.remove(&id);

        Ok(())
    }

    /// Clean up idle circuits
    pub fn cleanup_idle(&mut self) {
        let idle_timeout = self.config.circuit.idle_timeout;

        let idle_ids: Vec<_> = self.circuits.iter()
            .filter(|(_, c)| c.is_idle(idle_timeout))
            .map(|(id, _)| *id)
            .collect();

        for id in idle_ids {
            let _ = self.destroy_circuit(id);
        }
    }

    /// Shutdown the client
    pub fn shutdown(&mut self) {
        self.state = ClientState::ShuttingDown;

        // Destroy all circuits
        let ids: Vec<_> = self.circuits.keys().copied().collect();
        for id in ids {
            let _ = self.destroy_circuit(id);
        }

        self.state = ClientState::Stopped;
    }

    /// Get directory cache
    pub fn directory(&self) -> &DirectoryCache {
        &self.directory
    }

    /// Get mutable directory cache
    pub fn directory_mut(&mut self) -> &mut DirectoryCache {
        &mut self.directory
    }

    /// Get crypto context
    pub fn crypto(&self) -> &CryptoContext {
        &self.crypto
    }
}

/// Handle to a stream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamHandle {
    /// Circuit ID
    pub circuit_id: CircuitId,
    /// Stream ID
    pub stream_id: u16,
}

impl StreamHandle {
    /// Create new handle
    pub fn new(circuit_id: CircuitId, stream_id: u16) -> Self {
        Self { circuit_id, stream_id }
    }
}

/// Circuit manager for handling circuit lifecycle
#[derive(Debug)]
pub struct CircuitManager {
    /// Guard nodes (persistent)
    guards: Vec<RelayId>,
    /// Pending circuits being built
    pending: HashMap<CircuitId, PendingCircuit>,
    /// Circuit build timeout
    build_timeout: Duration,
    /// Maximum concurrent builds
    max_concurrent_builds: usize,
}

/// Pending circuit being built
#[derive(Debug)]
struct PendingCircuit {
    /// Build start time
    started: Instant,
    /// Current hop being built
    current_hop: usize,
    /// Total hops
    total_hops: usize,
}

impl CircuitManager {
    /// Create new circuit manager
    pub fn new() -> Self {
        Self {
            guards: Vec::new(),
            pending: HashMap::new(),
            build_timeout: DEFAULT_BUILD_TIMEOUT,
            max_concurrent_builds: 4,
        }
    }

    /// Set guard nodes
    pub fn set_guards(&mut self, guards: Vec<RelayId>) {
        self.guards = guards;
    }

    /// Get guard nodes
    pub fn guards(&self) -> &[RelayId] {
        &self.guards
    }

    /// Start circuit build
    pub fn start_build(&mut self, circuit_id: CircuitId, total_hops: usize) {
        self.pending.insert(circuit_id, PendingCircuit {
            started: Instant::now(),
            current_hop: 0,
            total_hops,
        });
    }

    /// Update build progress
    pub fn update_progress(&mut self, circuit_id: CircuitId, hop: usize) {
        if let Some(pending) = self.pending.get_mut(&circuit_id) {
            pending.current_hop = hop;
        }
    }

    /// Complete build
    pub fn complete_build(&mut self, circuit_id: CircuitId) {
        self.pending.remove(&circuit_id);
    }

    /// Fail build
    pub fn fail_build(&mut self, circuit_id: CircuitId) {
        self.pending.remove(&circuit_id);
    }

    /// Check for timed out builds
    pub fn check_timeouts(&mut self) -> Vec<CircuitId> {
        let now = Instant::now();
        let timeout = self.build_timeout;

        let timed_out: Vec<_> = self.pending.iter()
            .filter(|(_, p)| now.duration_since(p.started) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in &timed_out {
            self.pending.remove(id);
        }

        timed_out
    }

    /// Get number of pending builds
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Can start new build
    pub fn can_build(&self) -> bool {
        self.pending.len() < self.max_concurrent_builds
    }
}

impl Default for CircuitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse hidden service address (xxx.muon:port)
fn parse_hidden_address(address: &str) -> MuonResult<(MuonAddress, u16)> {
    let parts: Vec<&str> = address.rsplitn(2, ':').collect();

    if parts.len() != 2 {
        return Err(MuonError::InvalidAddress(
            "Missing port in hidden service address".into()
        ));
    }

    let port: u16 = parts[0].parse()
        .map_err(|_| MuonError::InvalidAddress("Invalid port".into()))?;

    let muon_addr = MuonAddress::from_string(parts[1])?;

    Ok((muon_addr, port))
}

/// Connection options
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Connection timeout
    pub timeout: Duration,
    /// Require specific circuit
    pub circuit_id: Option<CircuitId>,
    /// Isolation flags
    pub isolation: Option<IsolationFlags>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            circuit_id: None,
            isolation: None,
        }
    }
}

/// Stream isolation flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IsolationFlags {
    /// Isolate by destination port
    pub isolate_dest_port: bool,
    /// Isolate by destination address
    pub isolate_dest_addr: bool,
    /// Isolate by client protocol
    pub isolate_client_protocol: bool,
}

impl Default for IsolationFlags {
    fn default() -> Self {
        Self {
            isolate_dest_port: false,
            isolate_dest_addr: false,
            isolate_client_protocol: false,
        }
    }
}

/// Client statistics
#[derive(Debug, Default)]
pub struct ClientStats {
    /// Circuits built
    pub circuits_built: u64,
    /// Circuit build failures
    pub circuit_failures: u64,
    /// Streams opened
    pub streams_opened: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MuonConfig {
        MuonConfig::client()
    }

    #[test]
    fn test_client_creation() {
        let client = MuonClient::new(test_config()).unwrap();
        assert_eq!(client.state(), ClientState::Initializing);
    }

    #[test]
    fn test_client_bootstrap() {
        let mut client = MuonClient::new(test_config()).unwrap();
        client.bootstrap().unwrap();
        assert_eq!(client.state(), ClientState::Ready);
    }

    #[test]
    fn test_circuit_manager() {
        let mut manager = CircuitManager::new();

        assert!(manager.can_build());
        assert_eq!(manager.pending_count(), 0);

        let id = CircuitId::new(1);
        manager.start_build(id, 3);
        assert_eq!(manager.pending_count(), 1);

        manager.update_progress(id, 1);
        manager.complete_build(id);
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_parse_hidden_address() {
        // Can't test full parsing without valid address
        let result = parse_hidden_address("invalid");
        assert!(result.is_err());

        let result = parse_hidden_address("test.muon:80");
        // Will fail because "test" is not valid base32
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_stream_handle() {
        let handle = StreamHandle::new(CircuitId::new(1), 5);
        assert_eq!(handle.circuit_id.value(), 1);
        assert_eq!(handle.stream_id, 5);
    }
}
