//! Relay Management
//!
//! Relay descriptors, connections, and selection.
//!
//! # Relay Types
//!
//! - **Guard**: Entry point to the network (long-term)
//! - **Middle**: Intermediate hop (random selection)
//! - **Exit**: Final hop that connects to destination
//!
//! # Relay Descriptor
//!
//! Contains relay identity, capabilities, and network info.

use crate::{MuonResult, MuonError};
use crate::config::ExitPolicy;
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use libmu_crypto::MuHash;

/// Unique relay identifier (hash of identity public key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayId([u8; 32]);

impl RelayId {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from public key
    pub fn from_public_key(public_key: &[u8; 64]) -> Self {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-relay-id-v1");
        hasher.update(public_key);
        Self(hasher.finalize())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> MuonResult<Self> {
        if hex.len() != 64 {
            return Err(MuonError::InvalidRelayDescriptor(
                "Invalid relay ID length".into()
            ));
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk)
                .map_err(|_| MuonError::InvalidRelayDescriptor("Invalid hex".into()))?;
            bytes[i] = u8::from_str_radix(s, 16)
                .map_err(|_| MuonError::InvalidRelayDescriptor("Invalid hex".into()))?;
        }

        Ok(Self(bytes))
    }
}

impl std::fmt::Display for RelayId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16]) // Short form
    }
}

/// Relay flags indicating capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayFlags {
    /// Relay allows exit traffic
    pub exit: bool,
    /// Relay is a guard node
    pub guard: bool,
    /// Relay is stable (high uptime)
    pub stable: bool,
    /// Relay is fast (high bandwidth)
    pub fast: bool,
    /// Relay is running
    pub running: bool,
    /// Relay is valid (passes checks)
    pub valid: bool,
    /// Relay supports v2 handshakes
    pub v2dir: bool,
    /// Relay is an authority
    pub authority: bool,
    /// Relay supports hidden service directory
    pub hsdir: bool,
}

impl RelayFlags {
    /// Create flags for a new relay
    pub fn new() -> Self {
        Self {
            running: true,
            valid: true,
            ..Default::default()
        }
    }

    /// Check if relay can be used as guard
    pub fn can_guard(&self) -> bool {
        self.guard && self.stable && self.running && self.valid
    }

    /// Check if relay can be used as exit
    pub fn can_exit(&self) -> bool {
        self.exit && self.running && self.valid
    }

    /// Check if relay can be used as middle
    pub fn can_middle(&self) -> bool {
        self.running && self.valid
    }
}

/// Relay descriptor containing all relay information
#[derive(Debug, Clone)]
pub struct RelayDescriptor {
    /// Unique relay identifier
    pub id: RelayId,

    /// Relay nickname
    pub nickname: String,

    /// Identity public key
    pub identity_key: [u8; 64],

    /// Onion routing public key (for circuit handshakes)
    pub onion_key: [u8; 64],

    /// Network address for OR connections
    pub or_address: SocketAddr,

    /// Directory port (if any)
    pub dir_port: Option<u16>,

    /// Relay flags
    pub flags: RelayFlags,

    /// Exit policy
    pub exit_policy: ExitPolicy,

    /// Advertised bandwidth (bytes/sec)
    pub bandwidth: u64,

    /// Measured bandwidth by authorities (bytes/sec)
    pub measured_bandwidth: Option<u64>,

    /// Platform/version string
    pub platform: String,

    /// Contact information
    pub contact: Option<String>,

    /// Publication time
    pub published: SystemTime,

    /// Signature over descriptor
    pub signature: [u8; 64],
}

impl RelayDescriptor {
    /// Create a new unsigned relay descriptor
    pub fn new(
        nickname: String,
        identity_key: [u8; 64],
        onion_key: [u8; 64],
        or_address: SocketAddr,
    ) -> Self {
        let id = RelayId::from_public_key(&identity_key);

        Self {
            id,
            nickname,
            identity_key,
            onion_key,
            or_address,
            dir_port: None,
            flags: RelayFlags::new(),
            exit_policy: ExitPolicy::NoExit,
            bandwidth: 0,
            measured_bandwidth: None,
            platform: format!("MuonNet/0.1.0"),
            contact: None,
            published: SystemTime::now(),
            signature: [0u8; 64],
        }
    }

    /// Get effective bandwidth (measured or advertised)
    pub fn effective_bandwidth(&self) -> u64 {
        self.measured_bandwidth.unwrap_or(self.bandwidth)
    }

    /// Check if descriptor is expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        match self.published.elapsed() {
            Ok(age) => age > max_age,
            Err(_) => true, // Future timestamp, treat as expired
        }
    }

    /// Compute digest for signing
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-relay-descriptor-v1");
        hasher.update(self.id.as_bytes());
        hasher.update(self.nickname.as_bytes());
        hasher.update(&self.identity_key);
        hasher.update(&self.onion_key);
        hasher.update(self.or_address.to_string().as_bytes());
        hasher.update(&self.bandwidth.to_be_bytes());
        hasher.finalize()
    }

    /// Check if this relay allows exit to given address/port
    pub fn allows_exit(&self, _address: &str, port: u16) -> bool {
        match &self.exit_policy {
            ExitPolicy::NoExit => false,
            ExitPolicy::AllowAll => true,
            ExitPolicy::AllowPorts(ports) => ports.contains(&port),
            ExitPolicy::RejectPorts(ports) => !ports.contains(&port),
            ExitPolicy::Custom(rules) => {
                // Default deny, process rules in order
                use crate::config::PolicyAction;
                for rule in rules {
                    if port >= rule.ports.0 && port <= rule.ports.1 {
                        return rule.action == PolicyAction::Accept;
                    }
                }
                false
            }
        }
    }
}

/// Role of a relay in a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    /// Entry guard
    Guard,
    /// Middle relay
    Middle,
    /// Exit relay
    Exit,
}

/// Relay selection weights
#[derive(Debug, Clone)]
pub struct SelectionWeights {
    /// Weight for guard selection
    pub guard_weight: f64,
    /// Weight for middle selection
    pub middle_weight: f64,
    /// Weight for exit selection
    pub exit_weight: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            guard_weight: 1.0,
            middle_weight: 1.0,
            exit_weight: 1.0,
        }
    }
}

/// Relay selection criteria
#[derive(Debug, Clone, Default)]
pub struct RelaySelector {
    /// Required flags
    pub required_flags: RelayFlags,
    /// Excluded relay IDs
    pub exclude: Vec<RelayId>,
    /// Required exit port (for exit selection)
    pub exit_port: Option<u16>,
    /// Minimum bandwidth
    pub min_bandwidth: u64,
}

impl RelaySelector {
    /// Create selector for guard nodes
    pub fn for_guard() -> Self {
        Self {
            required_flags: RelayFlags {
                guard: true,
                stable: true,
                running: true,
                valid: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create selector for middle nodes
    pub fn for_middle(exclude: Vec<RelayId>) -> Self {
        Self {
            required_flags: RelayFlags {
                running: true,
                valid: true,
                ..Default::default()
            },
            exclude,
            ..Default::default()
        }
    }

    /// Create selector for exit nodes
    pub fn for_exit(port: u16, exclude: Vec<RelayId>) -> Self {
        Self {
            required_flags: RelayFlags {
                exit: true,
                running: true,
                valid: true,
                ..Default::default()
            },
            exclude,
            exit_port: Some(port),
            ..Default::default()
        }
    }

    /// Check if relay matches selection criteria
    pub fn matches(&self, relay: &RelayDescriptor) -> bool {
        // Check excluded
        if self.exclude.contains(&relay.id) {
            return false;
        }

        // Check required flags
        let flags = &relay.flags;
        let req = &self.required_flags;

        if req.guard && !flags.guard { return false; }
        if req.exit && !flags.exit { return false; }
        if req.stable && !flags.stable { return false; }
        if req.fast && !flags.fast { return false; }
        if req.running && !flags.running { return false; }
        if req.valid && !flags.valid { return false; }

        // Check exit port
        if let Some(port) = self.exit_port {
            if !relay.allows_exit("*", port) {
                return false;
            }
        }

        // Check bandwidth
        if relay.effective_bandwidth() < self.min_bandwidth {
            return false;
        }

        true
    }
}

/// Connection state to a relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting
    Connecting,
    /// TLS handshake in progress
    TlsHandshake,
    /// Link protocol negotiation
    Negotiating,
    /// Connected and ready
    Connected,
    /// Connection failed
    Failed,
}

/// Statistics for a relay connection
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    /// Cells sent
    pub cells_sent: u64,
    /// Cells received
    pub cells_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Circuits created through this relay
    pub circuits_created: u32,
    /// Circuit creation failures
    pub circuit_failures: u32,
    /// Connection established time
    pub connected_at: Option<SystemTime>,
}

impl RelayStats {
    /// Record cells sent
    pub fn record_sent(&mut self, cells: u64, bytes: u64) {
        self.cells_sent += cells;
        self.bytes_sent += bytes;
    }

    /// Record cells received
    pub fn record_received(&mut self, cells: u64, bytes: u64) {
        self.cells_received += cells;
        self.bytes_received += bytes;
    }

    /// Record circuit created
    pub fn record_circuit_created(&mut self) {
        self.circuits_created += 1;
    }

    /// Record circuit failure
    pub fn record_circuit_failure(&mut self) {
        self.circuit_failures += 1;
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.circuits_created + self.circuit_failures;
        if total == 0 {
            1.0
        } else {
            self.circuits_created as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_id_creation() {
        let pubkey = [42u8; 64];
        let id = RelayId::from_public_key(&pubkey);

        // Same key should produce same ID
        let id2 = RelayId::from_public_key(&pubkey);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_relay_id_hex() {
        let id = RelayId::from_bytes([0xab; 32]);
        let hex = id.to_hex();

        assert_eq!(hex.len(), 64);

        let parsed = RelayId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_relay_flags() {
        let mut flags = RelayFlags::new();
        assert!(flags.can_middle());
        assert!(!flags.can_guard());
        assert!(!flags.can_exit());

        flags.guard = true;
        flags.stable = true;
        assert!(flags.can_guard());

        flags.exit = true;
        assert!(flags.can_exit());
    }

    #[test]
    fn test_relay_descriptor() {
        let identity = [1u8; 64];
        let onion = [2u8; 64];
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let desc = RelayDescriptor::new(
            "TestRelay".into(),
            identity,
            onion,
            addr,
        );

        assert_eq!(desc.nickname, "TestRelay");
        assert_eq!(desc.or_address, addr);
    }

    #[test]
    fn test_exit_policy() {
        let mut desc = RelayDescriptor::new(
            "ExitRelay".into(),
            [0u8; 64],
            [0u8; 64],
            "0.0.0.0:9001".parse().unwrap(),
        );

        // NoExit
        assert!(!desc.allows_exit("example.com", 80));

        // AllowAll
        desc.exit_policy = ExitPolicy::AllowAll;
        assert!(desc.allows_exit("example.com", 80));
        assert!(desc.allows_exit("example.com", 443));

        // AllowPorts
        desc.exit_policy = ExitPolicy::AllowPorts(vec![80, 443]);
        assert!(desc.allows_exit("example.com", 80));
        assert!(desc.allows_exit("example.com", 443));
        assert!(!desc.allows_exit("example.com", 22));

        // RejectPorts
        desc.exit_policy = ExitPolicy::RejectPorts(vec![25, 465]);
        assert!(desc.allows_exit("example.com", 80));
        assert!(!desc.allows_exit("example.com", 25));
    }

    #[test]
    fn test_relay_selector() {
        let desc = RelayDescriptor::new(
            "TestRelay".into(),
            [0u8; 64],
            [0u8; 64],
            "0.0.0.0:9001".parse().unwrap(),
        );

        // Middle selector should match
        let selector = RelaySelector::for_middle(vec![]);
        assert!(selector.matches(&desc));

        // Guard selector should not match (no guard flag)
        let selector = RelaySelector::for_guard();
        assert!(!selector.matches(&desc));
    }

    #[test]
    fn test_relay_stats() {
        let mut stats = RelayStats::default();

        stats.record_sent(10, 5120);
        stats.record_received(8, 4096);
        stats.record_circuit_created();
        stats.record_circuit_created();
        stats.record_circuit_failure();

        assert_eq!(stats.cells_sent, 10);
        assert_eq!(stats.bytes_received, 4096);
        assert!((stats.success_rate() - 0.666).abs() < 0.01);
    }
}
