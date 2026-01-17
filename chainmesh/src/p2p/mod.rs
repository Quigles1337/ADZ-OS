//! P2P Gossip Protocol for ChainMesh
//!
//! Institutional-grade peer-to-peer networking with:
//! - μ-crypto based peer identity
//! - Epidemic gossip propagation
//! - Peer scoring and reputation
//! - Eclipse attack protection
//! - Efficient sync protocols

pub mod peer;
pub mod message;
pub mod gossip;
pub mod discovery;
pub mod scoring;
pub mod sync;

use crate::types::{Address, Block, BlockHash, SignedTransaction, TxHash};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// Re-exports
pub use peer::{PeerId, PeerInfo, PeerState, PeerManager};
pub use message::{Message, MessageId, MessageType};
pub use gossip::{GossipConfig, GossipEngine, GossipEvent};
pub use discovery::{Discovery, DiscoveryConfig, DiscoveryEvent};
pub use scoring::{PeerScore, PeerScorer, ScoreParams, ScoreDecay};
pub use sync::{SyncConfig, SyncEngine, SyncState};

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Maximum inbound peers
    pub max_inbound: usize,
    /// Maximum outbound peers
    pub max_outbound: usize,
    /// Target total peer count
    pub target_peers: usize,
    /// Bootstrap/seed nodes
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Network magic bytes (chain identifier)
    pub network_magic: [u8; 4],
    /// Protocol version
    pub protocol_version: u32,
    /// User agent string
    pub user_agent: String,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Ping interval
    pub ping_interval: Duration,
    /// Peer eviction interval
    pub eviction_interval: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30303".parse().unwrap(),
            max_inbound: 50,
            max_outbound: 25,
            target_peers: 50,
            bootstrap_nodes: Vec::new(),
            network_magic: [0x4D, 0x55, 0x4F, 0x53], // "MUOS"
            protocol_version: 1,
            user_agent: format!("ChainMesh/{}", env!("CARGO_PKG_VERSION")),
            connection_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(30),
            eviction_interval: Duration::from_secs(60),
        }
    }
}

impl NetworkConfig {
    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            network_magic: [0x54, 0x45, 0x53, 0x54], // "TEST"
            ..Default::default()
        }
    }

    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            max_inbound: 100,
            max_outbound: 50,
            target_peers: 100,
            ..Default::default()
        }
    }
}

/// Network statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Total peers ever connected
    pub total_peers_connected: u64,
    /// Current peer count
    pub current_peers: usize,
    /// Inbound peer count
    pub inbound_peers: usize,
    /// Outbound peer count
    pub outbound_peers: usize,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Transactions propagated
    pub txs_propagated: u64,
    /// Blocks propagated
    pub blocks_propagated: u64,
    /// Invalid messages received
    pub invalid_messages: u64,
    /// Duplicate messages received
    pub duplicate_messages: u64,
    /// Banned peers count
    pub banned_peers: usize,
}

/// Network events
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected {
        peer_id: PeerId,
        addr: SocketAddr,
        inbound: bool,
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: PeerId,
        reason: DisconnectReason,
    },
    /// New transaction received
    TransactionReceived {
        tx_hash: TxHash,
        from_peer: PeerId,
    },
    /// New block received
    BlockReceived {
        block_hash: BlockHash,
        from_peer: PeerId,
    },
    /// Peer misbehaved
    PeerMisbehavior {
        peer_id: PeerId,
        offense: PeerOffense,
    },
    /// Sync progress update
    SyncProgress {
        current_height: u64,
        target_height: u64,
        peers_syncing: usize,
    },
}

/// Reasons for disconnection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Client requested disconnect
    Requested,
    /// Protocol violation
    ProtocolViolation,
    /// Too many peers
    TooManyPeers,
    /// Timeout
    Timeout,
    /// Bad score
    BadScore,
    /// Banned
    Banned,
    /// Duplicate connection
    DuplicateConnection,
    /// Incompatible version
    IncompatibleVersion,
    /// Network error
    NetworkError(String),
    /// Sync completed
    SyncCompleted,
}

/// Peer offenses for scoring
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOffense {
    /// Sent invalid message format
    InvalidMessageFormat,
    /// Sent invalid transaction
    InvalidTransaction,
    /// Sent invalid block
    InvalidBlock,
    /// Sent duplicate message excessively
    ExcessiveDuplicates,
    /// Not responding to requests
    Unresponsive,
    /// Slow response
    SlowResponse,
    /// Sent unsolicited message
    UnsolicitedMessage,
    /// Eclipse attack suspected
    EclipseAttempt,
    /// Spam detected
    Spam,
    /// Protocol version mismatch during session
    VersionMismatch,
}

/// Connection direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Result type for P2P operations
pub type P2PResult<T> = Result<T, P2PError>;

/// P2P errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum P2PError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Peer banned: {0}")]
    PeerBanned(String),

    #[error("Too many peers")]
    TooManyPeers,

    #[error("Message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Sync error: {0}")]
    SyncError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Message priority for propagation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessagePriority {
    /// Low priority (peer exchange, status)
    Low = 0,
    /// Normal priority (transactions)
    Normal = 1,
    /// High priority (blocks, attestations)
    High = 2,
    /// Critical priority (emergency messages)
    Critical = 3,
}

/// Bandwidth limits
#[derive(Debug, Clone)]
pub struct BandwidthConfig {
    /// Maximum bytes per second upload
    pub max_upload_rate: u64,
    /// Maximum bytes per second download
    pub max_download_rate: u64,
    /// Burst allowance multiplier
    pub burst_multiplier: f64,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self {
            max_upload_rate: 10 * 1024 * 1024, // 10 MB/s
            max_download_rate: 50 * 1024 * 1024, // 50 MB/s
            burst_multiplier: 2.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.max_inbound, 50);
        assert_eq!(config.max_outbound, 25);
        assert_eq!(config.network_magic, [0x4D, 0x55, 0x4F, 0x53]);
    }

    #[test]
    fn test_testnet_config() {
        let config = NetworkConfig::testnet();
        assert_eq!(config.network_magic, [0x54, 0x45, 0x53, 0x54]);
    }

    #[test]
    fn test_mainnet_config() {
        let config = NetworkConfig::mainnet();
        assert_eq!(config.max_inbound, 100);
        assert_eq!(config.target_peers, 100);
    }
}
