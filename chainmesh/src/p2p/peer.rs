//! Peer Identity and Management
//!
//! Secure peer identification using μ-crypto:
//! - PeerId derived from μ-public key
//! - Handshake with signature verification
//! - Peer state machine
//! - Connection management

use crate::types::Address;
use super::{ConnectionDirection, DisconnectReason, P2PError, P2PResult};
use libmu_crypto::{MuKeyPair, MuPublicKey, MuHash};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Unique peer identifier derived from μ-public key
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

// Custom serialization for PeerId
impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as hex string for readability
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("PeerId must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PeerId(arr))
    }
}

impl PeerId {
    /// Create PeerId from public key
    pub fn from_public_key(pubkey: &MuPublicKey) -> Self {
        let hash = MuHash::hash(&pubkey.to_bytes());
        Self(hash)
    }

    /// Create PeerId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Short hex representation (first 8 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> P2PResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| P2PError::InvalidMessage(format!("Invalid peer ID hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(P2PError::InvalidMessage("Peer ID must be 32 bytes".into()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", self.short_hex())
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

/// Peer state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Connection initiated, awaiting TCP connect
    Connecting,
    /// TCP connected, performing handshake
    Handshaking,
    /// Handshake complete, peer is active
    Connected,
    /// Syncing blockchain data
    Syncing,
    /// Disconnecting gracefully
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Information about a peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub id: PeerId,
    /// Public key for verification
    pub public_key: Option<[u8; 64]>,
    /// Socket address
    pub addr: SocketAddr,
    /// Connection direction
    pub direction: ConnectionDirection,
    /// Current state
    pub state: PeerState,
    /// Protocol version
    pub protocol_version: u32,
    /// User agent
    pub user_agent: String,
    /// Chain ID
    pub chain_id: u64,
    /// Best known block height
    pub best_height: u64,
    /// Best known block hash
    pub best_hash: [u8; 32],
    /// Connection established time
    pub connected_at: Option<Instant>,
    /// Last message received time
    pub last_seen: Instant,
    /// Last ping time
    pub last_ping: Option<Instant>,
    /// Round-trip time (latency)
    pub rtt: Option<Duration>,
    /// Bytes sent to this peer
    pub bytes_sent: u64,
    /// Bytes received from this peer
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Is this peer a validator?
    pub is_validator: bool,
    /// Validator address if known
    pub validator_address: Option<Address>,
}

impl PeerInfo {
    /// Create new peer info for outbound connection
    pub fn new_outbound(addr: SocketAddr) -> Self {
        Self {
            id: PeerId([0u8; 32]), // Will be set after handshake
            public_key: None,
            addr,
            direction: ConnectionDirection::Outbound,
            state: PeerState::Connecting,
            protocol_version: 0,
            user_agent: String::new(),
            chain_id: 0,
            best_height: 0,
            best_hash: [0u8; 32],
            connected_at: None,
            last_seen: Instant::now(),
            last_ping: None,
            rtt: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            is_validator: false,
            validator_address: None,
        }
    }

    /// Create new peer info for inbound connection
    pub fn new_inbound(addr: SocketAddr) -> Self {
        let mut info = Self::new_outbound(addr);
        info.direction = ConnectionDirection::Inbound;
        info
    }

    /// Update peer as connected with handshake info
    pub fn set_connected(&mut self, handshake: &Handshake) {
        self.id = PeerId::from_bytes(handshake.peer_id);
        self.public_key = Some(handshake.public_key);
        self.protocol_version = handshake.protocol_version;
        self.user_agent = handshake.user_agent.clone();
        self.chain_id = handshake.chain_id;
        self.best_height = handshake.best_height;
        self.best_hash = handshake.best_hash;
        self.state = PeerState::Connected;
        self.connected_at = Some(Instant::now());
        self.last_seen = Instant::now();
    }

    /// Check if peer is usable for requests
    pub fn is_active(&self) -> bool {
        matches!(self.state, PeerState::Connected | PeerState::Syncing)
    }

    /// Check if peer appears healthy
    pub fn is_healthy(&self, timeout: Duration) -> bool {
        self.is_active() && self.last_seen.elapsed() < timeout
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Record bytes sent
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.messages_sent += 1;
    }

    /// Record bytes received
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.messages_received += 1;
        self.touch();
    }

    /// Calculate connection duration
    pub fn connection_duration(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }
}

/// Handshake message for establishing connection
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Network magic bytes
    pub network_magic: [u8; 4],
    /// Protocol version
    pub protocol_version: u32,
    /// Peer ID (hash of public key)
    pub peer_id: [u8; 32],
    /// Public key for verification
    #[serde_as(as = "[_; 64]")]
    pub public_key: [u8; 64],
    /// User agent string
    pub user_agent: String,
    /// Chain ID
    pub chain_id: u64,
    /// Best block height
    pub best_height: u64,
    /// Best block hash
    pub best_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Random nonce for replay protection
    pub nonce: [u8; 32],
    /// Signature of handshake data
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl Handshake {
    /// Create and sign a new handshake
    pub fn new(
        keypair: &MuKeyPair,
        network_magic: [u8; 4],
        protocol_version: u32,
        user_agent: String,
        chain_id: u64,
        best_height: u64,
        best_hash: [u8; 32],
    ) -> Self {
        let peer_id = {
            let hash = MuHash::hash(&keypair.public_key().to_bytes());
            hash
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate random nonce
        let nonce = {
            let mut rng = libmu_crypto::MuRng::new().unwrap();
            rng.random_bytes::<32>()
        };

        let mut handshake = Self {
            network_magic,
            protocol_version,
            peer_id,
            public_key: keypair.public_key().to_bytes(),
            user_agent,
            chain_id,
            best_height,
            best_hash,
            timestamp,
            nonce,
            signature: [0u8; 64],
        };

        // Sign the handshake data
        let data = handshake.signable_data();
        let sig = keypair.sign(&data);
        handshake.signature = sig.to_bytes();

        handshake
    }

    /// Get data to sign/verify
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.network_magic);
        data.extend_from_slice(&self.protocol_version.to_le_bytes());
        data.extend_from_slice(&self.peer_id);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(self.user_agent.as_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.best_height.to_le_bytes());
        data.extend_from_slice(&self.best_hash);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.nonce);
        data
    }

    /// Verify handshake signature
    pub fn verify(&self) -> P2PResult<()> {
        // Verify peer_id matches public key hash
        let expected_id = MuHash::hash(&self.public_key);
        if self.peer_id != expected_id {
            return Err(P2PError::HandshakeFailed("Peer ID mismatch".into()));
        }

        // Verify signature
        let pubkey = MuPublicKey::from_bytes(&self.public_key)
            .map_err(|_| P2PError::HandshakeFailed("Invalid public key".into()))?;

        let sig = libmu_crypto::MuSignature::from_bytes(&self.signature)
            .map_err(|_| P2PError::HandshakeFailed("Invalid signature".into()))?;

        let data = self.signable_data();
        pubkey.verify(&data, &sig)
            .map_err(|_| P2PError::HandshakeFailed("Signature verification failed".into()))?;

        // Check timestamp is reasonable (within 5 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };

        if time_diff > 300 {
            return Err(P2PError::HandshakeFailed("Handshake timestamp too old".into()));
        }

        Ok(())
    }
}

/// Manages all peer connections
pub struct PeerManager {
    /// Our node's keypair
    keypair: MuKeyPair,
    /// Our peer ID
    our_id: PeerId,
    /// Connected peers
    peers: HashMap<PeerId, PeerInfo>,
    /// Peers by address (for duplicate detection)
    peers_by_addr: HashMap<SocketAddr, PeerId>,
    /// Banned peers with expiry time
    banned: HashMap<PeerId, Instant>,
    /// Banned addresses
    banned_addrs: HashMap<SocketAddr, Instant>,
    /// Recently seen peer IDs (for eclipse protection)
    recently_seen: VecDeque<PeerId>,
    /// Maximum inbound connections
    max_inbound: usize,
    /// Maximum outbound connections
    max_outbound: usize,
    /// Ban duration
    ban_duration: Duration,
    /// Network magic for handshake
    network_magic: [u8; 4],
    /// Protocol version
    protocol_version: u32,
    /// User agent
    user_agent: String,
    /// Chain ID
    chain_id: u64,
}

impl std::fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("our_id", &self.our_id)
            .field("peer_count", &self.peers.len())
            .field("max_inbound", &self.max_inbound)
            .field("max_outbound", &self.max_outbound)
            .field("banned_count", &self.banned.len())
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl PeerManager {
    /// Create new peer manager
    pub fn new(
        keypair: MuKeyPair,
        max_inbound: usize,
        max_outbound: usize,
        network_magic: [u8; 4],
        protocol_version: u32,
        user_agent: String,
        chain_id: u64,
    ) -> Self {
        let our_id = PeerId::from_public_key(keypair.public_key());

        Self {
            keypair,
            our_id,
            peers: HashMap::new(),
            peers_by_addr: HashMap::new(),
            banned: HashMap::new(),
            banned_addrs: HashMap::new(),
            recently_seen: VecDeque::with_capacity(1000),
            max_inbound,
            max_outbound,
            ban_duration: Duration::from_secs(3600), // 1 hour default
            network_magic,
            protocol_version,
            user_agent,
            chain_id,
        }
    }

    /// Get our peer ID
    pub fn our_id(&self) -> PeerId {
        self.our_id
    }

    /// Get number of connected peers
    pub fn peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_active()).count()
    }

    /// Get number of inbound peers
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.is_active() && p.direction == ConnectionDirection::Inbound)
            .count()
    }

    /// Get number of outbound peers
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.is_active() && p.direction == ConnectionDirection::Outbound)
            .count()
    }

    /// Check if we can accept more inbound connections
    pub fn can_accept_inbound(&self) -> bool {
        self.inbound_count() < self.max_inbound
    }

    /// Check if we can make more outbound connections
    pub fn can_make_outbound(&self) -> bool {
        self.outbound_count() < self.max_outbound
    }

    /// Check if address is banned
    pub fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(expiry) = self.banned_addrs.get(addr) {
            if Instant::now() < *expiry {
                return true;
            }
        }
        false
    }

    /// Check if peer is banned
    pub fn is_peer_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(expiry) = self.banned.get(peer_id) {
            if Instant::now() < *expiry {
                return true;
            }
        }
        false
    }

    /// Ban a peer
    pub fn ban_peer(&mut self, peer_id: PeerId, duration: Option<Duration>) {
        let dur = duration.unwrap_or(self.ban_duration);
        let expiry = Instant::now() + dur;
        self.banned.insert(peer_id, expiry);

        // Also ban their address if known
        if let Some(peer) = self.peers.get(&peer_id) {
            self.banned_addrs.insert(peer.addr, expiry);
        }

        // Remove from connected peers
        self.remove_peer(&peer_id);
    }

    /// Create handshake for new connection
    pub fn create_handshake(&self, best_height: u64, best_hash: [u8; 32]) -> Handshake {
        Handshake::new(
            &self.keypair,
            self.network_magic,
            self.protocol_version,
            self.user_agent.clone(),
            self.chain_id,
            best_height,
            best_hash,
        )
    }

    /// Process received handshake
    pub fn process_handshake(
        &mut self,
        addr: SocketAddr,
        handshake: Handshake,
        direction: ConnectionDirection,
    ) -> P2PResult<PeerId> {
        // Verify handshake
        handshake.verify()?;

        // Check network magic
        if handshake.network_magic != self.network_magic {
            return Err(P2PError::HandshakeFailed("Network magic mismatch".into()));
        }

        // Check chain ID
        if handshake.chain_id != self.chain_id {
            return Err(P2PError::HandshakeFailed("Chain ID mismatch".into()));
        }

        let peer_id = PeerId::from_bytes(handshake.peer_id);

        // Check if connecting to ourselves
        if peer_id == self.our_id {
            return Err(P2PError::HandshakeFailed("Cannot connect to self".into()));
        }

        // Check if banned
        if self.is_peer_banned(&peer_id) {
            return Err(P2PError::PeerBanned(peer_id.to_hex()));
        }

        // Check connection limits
        match direction {
            ConnectionDirection::Inbound if !self.can_accept_inbound() => {
                return Err(P2PError::TooManyPeers);
            }
            ConnectionDirection::Outbound if !self.can_make_outbound() => {
                return Err(P2PError::TooManyPeers);
            }
            _ => {}
        }

        // Check for duplicate connection
        if self.peers.contains_key(&peer_id) {
            return Err(P2PError::HandshakeFailed("Already connected".into()));
        }

        // Create peer info
        let mut peer_info = match direction {
            ConnectionDirection::Inbound => PeerInfo::new_inbound(addr),
            ConnectionDirection::Outbound => PeerInfo::new_outbound(addr),
        };
        peer_info.set_connected(&handshake);

        // Add to peer maps
        self.peers.insert(peer_id, peer_info);
        self.peers_by_addr.insert(addr, peer_id);

        // Track for eclipse protection
        self.recently_seen.push_back(peer_id);
        if self.recently_seen.len() > 1000 {
            self.recently_seen.pop_front();
        }

        Ok(peer_id)
    }

    /// Get peer info
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get mutable peer info
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Get peer by address
    pub fn get_peer_by_addr(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers_by_addr.get(addr).and_then(|id| self.peers.get(id))
    }

    /// Get all active peers
    pub fn active_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.is_active()).collect()
    }

    /// Get all peer IDs
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Remove peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(peer) = self.peers.remove(peer_id) {
            self.peers_by_addr.remove(&peer.addr);
            Some(peer)
        } else {
            None
        }
    }

    /// Update peer state
    pub fn set_peer_state(&mut self, peer_id: &PeerId, state: PeerState) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = state;
        }
    }

    /// Update peer's best block
    pub fn update_peer_best(&mut self, peer_id: &PeerId, height: u64, hash: [u8; 32]) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.best_height = height;
            peer.best_hash = hash;
            peer.touch();
        }
    }

    /// Get peers sorted by best height (descending)
    pub fn peers_by_height(&self) -> Vec<&PeerInfo> {
        let mut peers: Vec<_> = self.active_peers();
        peers.sort_by(|a, b| b.best_height.cmp(&a.best_height));
        peers
    }

    /// Evict worst peers if over limit
    pub fn evict_if_needed(&mut self, scorer: &super::scoring::PeerScorer) -> Vec<PeerId> {
        let mut evicted = Vec::new();

        // Check inbound limit
        while self.inbound_count() > self.max_inbound {
            if let Some(peer_id) = self.find_worst_inbound(scorer) {
                self.remove_peer(&peer_id);
                evicted.push(peer_id);
            } else {
                break;
            }
        }

        // Check outbound limit
        while self.outbound_count() > self.max_outbound {
            if let Some(peer_id) = self.find_worst_outbound(scorer) {
                self.remove_peer(&peer_id);
                evicted.push(peer_id);
            } else {
                break;
            }
        }

        evicted
    }

    /// Find worst inbound peer (lowest score)
    fn find_worst_inbound(&self, scorer: &super::scoring::PeerScorer) -> Option<PeerId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.is_active() && p.direction == ConnectionDirection::Inbound)
            .min_by(|(id_a, _), (id_b, _)| {
                let score_a = scorer.get_score(id_a).map(|s| s.total()).unwrap_or(0.0);
                let score_b = scorer.get_score(id_b).map(|s| s.total()).unwrap_or(0.0);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id)
    }

    /// Find worst outbound peer (lowest score)
    fn find_worst_outbound(&self, scorer: &super::scoring::PeerScorer) -> Option<PeerId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.is_active() && p.direction == ConnectionDirection::Outbound)
            .min_by(|(id_a, _), (id_b, _)| {
                let score_a = scorer.get_score(id_a).map(|s| s.total()).unwrap_or(0.0);
                let score_b = scorer.get_score(id_b).map(|s| s.total()).unwrap_or(0.0);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id)
    }

    /// Clean up expired bans
    pub fn cleanup_bans(&mut self) {
        let now = Instant::now();
        self.banned.retain(|_, expiry| *expiry > now);
        self.banned_addrs.retain(|_, expiry| *expiry > now);
    }

    /// Get banned peer count
    pub fn banned_count(&self) -> usize {
        self.banned.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair(seed: &[u8]) -> MuKeyPair {
        MuKeyPair::from_seed(seed)
    }

    #[test]
    fn test_peer_id_from_public_key() {
        let keypair = test_keypair(b"test_seed_for_peer_id");
        let peer_id = PeerId::from_public_key(keypair.public_key());

        // Same key should produce same ID
        let peer_id2 = PeerId::from_public_key(keypair.public_key());
        assert_eq!(peer_id, peer_id2);

        // Different key should produce different ID
        let keypair2 = test_keypair(b"different_seed_here!");
        let peer_id3 = PeerId::from_public_key(keypair2.public_key());
        assert_ne!(peer_id, peer_id3);
    }

    #[test]
    fn test_peer_id_hex_roundtrip() {
        let keypair = test_keypair(b"hex_roundtrip_test_!");
        let peer_id = PeerId::from_public_key(keypair.public_key());

        let hex = peer_id.to_hex();
        let parsed = PeerId::from_hex(&hex).unwrap();
        assert_eq!(peer_id, parsed);
    }

    #[test]
    fn test_handshake_sign_verify() {
        let keypair = test_keypair(b"handshake_test_seed!");

        let handshake = Handshake::new(
            &keypair,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "TestAgent/1.0".into(),
            137,
            1000,
            [1u8; 32],
        );

        // Should verify successfully
        assert!(handshake.verify().is_ok());
    }

    #[test]
    fn test_handshake_detects_tampering() {
        let keypair = test_keypair(b"tamper_test_seed_123");

        let handshake = Handshake::new(
            &keypair,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "TestAgent/1.0".into(),
            137,
            1000,
            [1u8; 32],
        );

        // Get the original signable data
        let original_data = handshake.signable_data();

        // Tamper with the data by corrupting the peer_id
        // (peer_id mismatch is always checked)
        let mut tampered = handshake.clone();
        tampered.peer_id[0] ^= 0xFF; // Flip bits in peer_id

        // Should fail verification due to peer_id mismatch
        assert!(tampered.verify().is_err());

        // Also verify that original still works
        assert!(handshake.verify().is_ok());
    }

    #[test]
    fn test_peer_manager_connection() {
        let keypair1 = test_keypair(b"manager_peer_1_seed!");
        let keypair2 = test_keypair(b"manager_peer_2_seed!");

        let mut manager = PeerManager::new(
            keypair1,
            10,
            10,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Test/1.0".into(),
            137,
        );

        let handshake = Handshake::new(
            &keypair2,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Peer/1.0".into(),
            137,
            500,
            [2u8; 32],
        );

        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let peer_id = manager.process_handshake(addr, handshake, ConnectionDirection::Inbound).unwrap();

        assert_eq!(manager.peer_count(), 1);
        assert_eq!(manager.inbound_count(), 1);

        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.best_height, 500);
        assert!(peer.is_active());
    }

    #[test]
    fn test_peer_manager_rejects_self_connection() {
        // Use same seed for both keypairs to simulate self-connection
        let seed = b"self_connect_test_!!";
        let keypair1 = test_keypair(seed);
        let keypair2 = test_keypair(seed);

        let mut manager = PeerManager::new(
            keypair1,
            10,
            10,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Test/1.0".into(),
            137,
        );

        // Create handshake with same identity (same seed = same keys)
        let handshake = Handshake::new(
            &keypair2,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Test/1.0".into(),
            137,
            100,
            [1u8; 32],
        );
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        // Should reject self-connection
        let result = manager.process_handshake(addr, handshake, ConnectionDirection::Inbound);
        assert!(matches!(result, Err(P2PError::HandshakeFailed(_))));
    }

    #[test]
    fn test_peer_manager_banning() {
        let keypair1 = test_keypair(b"ban_test_peer_1_!!");
        let keypair2 = test_keypair(b"ban_test_peer_2_!!");

        let mut manager = PeerManager::new(
            keypair1,
            10,
            10,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Test/1.0".into(),
            137,
        );

        let peer_id = PeerId::from_public_key(keypair2.public_key());

        // Ban the peer
        manager.ban_peer(peer_id, Some(Duration::from_secs(3600)));
        assert!(manager.is_peer_banned(&peer_id));

        // Try to connect
        let handshake = Handshake::new(
            &keypair2,
            [0x54, 0x45, 0x53, 0x54],
            1,
            "Banned/1.0".into(),
            137,
            100,
            [1u8; 32],
        );
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let result = manager.process_handshake(addr, handshake, ConnectionDirection::Inbound);
        assert!(matches!(result, Err(P2PError::PeerBanned(_))));
    }
}
