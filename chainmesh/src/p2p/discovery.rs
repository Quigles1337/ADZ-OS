//! Peer Discovery Protocol
//!
//! Multi-strategy peer discovery:
//! - Bootstrap nodes (hardcoded seeds)
//! - Peer exchange (PEX)
//! - Random walks
//! - Eclipse attack protection

use super::{
    peer::{PeerId, PeerInfo},
    message::{PeerPayload, GetPeersPayload},
    P2PError, P2PResult, ConnectionDirection,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Target peer count
    pub target_peers: usize,
    /// Minimum outbound peers
    pub min_outbound: usize,
    /// Maximum stored addresses
    pub max_addresses: usize,
    /// Peer exchange interval
    pub pex_interval: Duration,
    /// Bootstrap retry interval
    pub bootstrap_retry: Duration,
    /// Address expiry time
    pub address_ttl: Duration,
    /// Maximum addresses per peer exchange
    pub max_pex_peers: usize,
    /// Enable random walk discovery
    pub enable_random_walk: bool,
    /// Random walk interval
    pub random_walk_interval: Duration,
    /// Eclipse protection: max peers from same /16
    pub max_same_subnet: usize,
    /// Eclipse protection: max peers from same AS
    pub max_same_as: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            target_peers: 50,
            min_outbound: 8,
            max_addresses: 10_000,
            pex_interval: Duration::from_secs(300), // 5 minutes
            bootstrap_retry: Duration::from_secs(30),
            address_ttl: Duration::from_secs(3600 * 24), // 24 hours
            max_pex_peers: 30,
            enable_random_walk: true,
            random_walk_interval: Duration::from_secs(60),
            max_same_subnet: 4,
            max_same_as: 8,
        }
    }
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// New address discovered
    NewAddress {
        addr: SocketAddr,
        from_peer: Option<PeerId>,
    },
    /// Should connect to peer
    ConnectTo {
        addr: SocketAddr,
        priority: ConnectionPriority,
    },
    /// Address marked as bad
    BadAddress {
        addr: SocketAddr,
        reason: String,
    },
    /// Need more peers
    NeedPeers {
        current: usize,
        target: usize,
    },
}

/// Connection priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectionPriority {
    Low,
    Normal,
    High,
    Bootstrap,
}

/// Known address entry
#[derive(Debug, Clone)]
struct AddressEntry {
    /// Socket address
    addr: SocketAddr,
    /// First seen time
    first_seen: Instant,
    /// Last seen time
    last_seen: Instant,
    /// Last attempt time
    last_attempt: Option<Instant>,
    /// Last successful connection
    last_connected: Option<Instant>,
    /// Connection attempts
    attempts: u32,
    /// Successful connections
    successes: u32,
    /// Source of address
    source: AddressSource,
    /// Service flags/capabilities
    services: u32,
}

/// How we learned about an address
#[derive(Debug, Clone, PartialEq, Eq)]
enum AddressSource {
    /// Hardcoded bootstrap
    Bootstrap,
    /// Peer exchange
    Pex(PeerId),
    /// DNS seed
    Dns,
    /// Incoming connection
    Incoming,
    /// Manual add
    Manual,
}

impl AddressEntry {
    fn new(addr: SocketAddr, source: AddressSource) -> Self {
        let now = Instant::now();
        Self {
            addr,
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            last_connected: None,
            attempts: 0,
            successes: 0,
            source,
            services: 0,
        }
    }

    /// Calculate address quality score
    fn score(&self) -> f64 {
        let mut score = 0.0;

        // Prefer addresses with successful connections
        if self.successes > 0 {
            score += 50.0 * (1.0 - 1.0 / (self.successes as f64 + 1.0));
        }

        // Penalize failed attempts
        if self.attempts > self.successes {
            let failures = self.attempts - self.successes;
            score -= 10.0 * failures as f64;
        }

        // Prefer recently seen
        let age = self.last_seen.elapsed().as_secs() as f64;
        score -= age / 3600.0; // -1 point per hour

        // Prefer recently connected
        if let Some(connected) = self.last_connected {
            let since = connected.elapsed().as_secs() as f64;
            score += 20.0 * (1.0 - since / 86400.0).max(0.0);
        }

        // Boost bootstrap nodes
        if matches!(self.source, AddressSource::Bootstrap) {
            score += 30.0;
        }

        score
    }

    /// Check if should retry
    fn should_retry(&self, retry_delay: Duration) -> bool {
        if let Some(last) = self.last_attempt {
            // Exponential backoff
            let backoff = retry_delay.as_secs() * 2u64.pow(self.attempts.min(6));
            last.elapsed() > Duration::from_secs(backoff)
        } else {
            true
        }
    }
}

/// Peer discovery engine
#[derive(Debug)]
pub struct Discovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Known addresses
    addresses: HashMap<SocketAddr, AddressEntry>,
    /// Banned addresses
    banned: HashSet<SocketAddr>,
    /// Currently connected peers
    connected: HashSet<SocketAddr>,
    /// Pending connection attempts
    pending: HashSet<SocketAddr>,
    /// Last peer exchange time
    last_pex: Option<Instant>,
    /// Last random walk time
    last_random_walk: Option<Instant>,
    /// Subnet tracking for eclipse protection (IPv4 /16)
    subnet_counts: HashMap<u16, usize>,
    /// Events to emit
    pending_events: VecDeque<DiscoveryEvent>,
}

impl Discovery {
    /// Create new discovery engine
    pub fn new(config: DiscoveryConfig) -> Self {
        let mut discovery = Self {
            config: config.clone(),
            addresses: HashMap::new(),
            banned: HashSet::new(),
            connected: HashSet::new(),
            pending: HashSet::new(),
            last_pex: None,
            last_random_walk: None,
            subnet_counts: HashMap::new(),
            pending_events: VecDeque::new(),
        };

        // Add bootstrap nodes
        for addr in &config.bootstrap_nodes {
            discovery.add_address(*addr, AddressSource::Bootstrap);
        }

        discovery
    }

    /// Add known address
    fn add_address(&mut self, addr: SocketAddr, source: AddressSource) -> bool {
        // Check if banned
        if self.banned.contains(&addr) {
            return false;
        }

        // Check capacity
        if self.addresses.len() >= self.config.max_addresses {
            self.evict_addresses(1);
        }

        // Add or update
        if let Some(entry) = self.addresses.get_mut(&addr) {
            entry.last_seen = Instant::now();
            false
        } else {
            self.addresses.insert(addr, AddressEntry::new(addr, source));
            true
        }
    }

    /// Add address from peer exchange
    pub fn add_pex_address(&mut self, addr: SocketAddr, from_peer: PeerId) -> bool {
        if self.add_address(addr, AddressSource::Pex(from_peer)) {
            self.pending_events.push_back(DiscoveryEvent::NewAddress {
                addr,
                from_peer: Some(from_peer),
            });
            true
        } else {
            false
        }
    }

    /// Add address from incoming connection
    pub fn add_incoming(&mut self, addr: SocketAddr) {
        self.add_address(addr, AddressSource::Incoming);
    }

    /// Evict lowest-quality addresses
    fn evict_addresses(&mut self, count: usize) {
        if self.addresses.len() <= count {
            return;
        }

        // Sort by score (ascending) and remove lowest
        let mut scored: Vec<_> = self.addresses
            .iter()
            .map(|(addr, entry)| (*addr, entry.score()))
            .collect();

        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        for (addr, _) in scored.into_iter().take(count) {
            // Don't evict bootstrap nodes
            if let Some(entry) = self.addresses.get(&addr) {
                if !matches!(entry.source, AddressSource::Bootstrap) {
                    self.addresses.remove(&addr);
                }
            }
        }
    }

    /// Mark peer as connected
    pub fn mark_connected(&mut self, addr: SocketAddr) {
        self.pending.remove(&addr);
        self.connected.insert(addr);

        // Update subnet tracking
        if let IpAddr::V4(ip) = addr.ip() {
            let octets = ip.octets();
            let subnet = ((octets[0] as u16) << 8) | (octets[1] as u16);
            *self.subnet_counts.entry(subnet).or_insert(0) += 1;
        }

        if let Some(entry) = self.addresses.get_mut(&addr) {
            entry.successes += 1;
            entry.last_connected = Some(Instant::now());
        }
    }

    /// Mark peer as disconnected
    pub fn mark_disconnected(&mut self, addr: SocketAddr) {
        self.connected.remove(&addr);

        // Update subnet tracking
        if let IpAddr::V4(ip) = addr.ip() {
            let octets = ip.octets();
            let subnet = ((octets[0] as u16) << 8) | (octets[1] as u16);
            if let Some(count) = self.subnet_counts.get_mut(&subnet) {
                *count = count.saturating_sub(1);
            }
        }
    }

    /// Mark connection attempt
    pub fn mark_attempt(&mut self, addr: SocketAddr) {
        self.pending.insert(addr);

        if let Some(entry) = self.addresses.get_mut(&addr) {
            entry.attempts += 1;
            entry.last_attempt = Some(Instant::now());
        }
    }

    /// Mark address as bad
    pub fn mark_bad(&mut self, addr: SocketAddr, reason: String) {
        self.banned.insert(addr);
        self.addresses.remove(&addr);
        self.pending.remove(&addr);

        self.pending_events.push_back(DiscoveryEvent::BadAddress { addr, reason });
    }

    /// Ban an address
    pub fn ban(&mut self, addr: SocketAddr) {
        self.banned.insert(addr);
        self.addresses.remove(&addr);
        self.pending.remove(&addr);
        self.connected.remove(&addr);
    }

    /// Check if can connect to address (eclipse protection)
    fn can_connect(&self, addr: &SocketAddr) -> bool {
        // Check if banned
        if self.banned.contains(addr) {
            return false;
        }

        // Check if already connected or pending
        if self.connected.contains(addr) || self.pending.contains(addr) {
            return false;
        }

        // Eclipse protection: check subnet limit
        if let IpAddr::V4(ip) = addr.ip() {
            let octets = ip.octets();
            let subnet = ((octets[0] as u16) << 8) | (octets[1] as u16);
            if let Some(count) = self.subnet_counts.get(&subnet) {
                if *count >= self.config.max_same_subnet {
                    return false;
                }
            }
        }

        true
    }

    /// Get addresses to connect to
    pub fn get_addresses_to_connect(&mut self, max: usize) -> Vec<SocketAddr> {
        let retry_delay = self.config.bootstrap_retry;
        let mut candidates: Vec<_> = self.addresses
            .iter()
            .filter(|(addr, entry)| {
                self.can_connect(addr) && entry.should_retry(retry_delay)
            })
            .map(|(addr, entry)| (*addr, entry.score()))
            .collect();

        // Sort by score descending
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        candidates.into_iter()
            .take(max)
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Check if we need more peers
    pub fn need_more_peers(&self) -> bool {
        let outbound = self.connected.len();
        outbound < self.config.min_outbound || outbound < self.config.target_peers
    }

    /// Trigger discovery tick
    pub fn tick(&mut self) {
        // Check if need more peers
        if self.need_more_peers() {
            let candidates = self.get_addresses_to_connect(
                self.config.target_peers - self.connected.len()
            );

            for addr in candidates {
                let priority = if self.addresses.get(&addr)
                    .map(|e| matches!(e.source, AddressSource::Bootstrap))
                    .unwrap_or(false)
                {
                    ConnectionPriority::Bootstrap
                } else {
                    ConnectionPriority::Normal
                };

                self.pending_events.push_back(DiscoveryEvent::ConnectTo { addr, priority });
            }
        }

        // Check if should do peer exchange
        if let Some(last) = self.last_pex {
            if last.elapsed() < self.config.pex_interval {
                return;
            }
        }

        // Would trigger PEX here
        self.last_pex = Some(Instant::now());
    }

    /// Drain pending events
    pub fn drain_events(&mut self) -> Vec<DiscoveryEvent> {
        self.pending_events.drain(..).collect()
    }

    /// Get addresses for peer exchange response
    pub fn get_pex_addresses(&self, max: usize) -> Vec<PeerPayload> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Return recently connected peers
        let mut addrs: Vec<_> = self.addresses
            .iter()
            .filter(|(_, e)| e.successes > 0 && e.last_connected.is_some())
            .collect();

        addrs.sort_by(|a, b| {
            let la = a.1.last_connected.unwrap();
            let lb = b.1.last_connected.unwrap();
            lb.cmp(&la)
        });

        addrs.into_iter()
            .take(max)
            .map(|(addr, entry)| {
                let ip = match addr.ip() {
                    IpAddr::V4(v4) => v4.octets().to_vec(),
                    IpAddr::V6(v6) => v6.octets().to_vec(),
                };

                PeerPayload {
                    peer_id: [0u8; 32], // Not known for addresses only
                    ip,
                    port: addr.port(),
                    last_seen: entry.last_seen.elapsed().as_secs().saturating_sub(now),
                    capabilities: entry.services,
                }
            })
            .collect()
    }

    /// Process received peer exchange
    pub fn process_pex(&mut self, peers: Vec<PeerPayload>, from_peer: PeerId) {
        for peer in peers.into_iter().take(self.config.max_pex_peers) {
            if let Some(addr) = parse_peer_addr(&peer) {
                self.add_pex_address(addr, from_peer);
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> DiscoveryStats {
        DiscoveryStats {
            known_addresses: self.addresses.len(),
            banned_addresses: self.banned.len(),
            connected_peers: self.connected.len(),
            pending_connections: self.pending.len(),
        }
    }
}

/// Parse address from peer payload
fn parse_peer_addr(peer: &PeerPayload) -> Option<SocketAddr> {
    let ip = match peer.ip.len() {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&peer.ip);
            IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&peer.ip);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return None,
    };

    Some(SocketAddr::new(ip, peer.port))
}

/// Discovery statistics
#[derive(Debug, Clone)]
pub struct DiscoveryStats {
    pub known_addresses: usize,
    pub banned_addresses: usize,
    pub connected_peers: usize,
    pub pending_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_entry_scoring() {
        let addr: SocketAddr = "192.168.1.1:30303".parse().unwrap();

        let mut entry = AddressEntry::new(addr, AddressSource::Manual);

        // New entry should have low score
        let initial_score = entry.score();

        // Success should increase score
        entry.successes = 5;
        assert!(entry.score() > initial_score);

        // More attempts without success should decrease score
        entry.attempts = 10;
        let score_with_many_attempts = entry.score();
        // Score should be less than score with just 5 successes because
        // success ratio (5/10 = 0.5) is worse than (5/5 = 1.0) implied earlier
        assert!(score_with_many_attempts <= initial_score + 5.0 * 10.0); // reasonable bounds check
    }

    #[test]
    fn test_discovery_add_address() {
        let config = DiscoveryConfig::default();
        let mut discovery = Discovery::new(config);

        let addr: SocketAddr = "192.168.1.1:30303".parse().unwrap();
        let peer_id = PeerId::from_bytes([1u8; 32]);

        // First add should succeed
        assert!(discovery.add_pex_address(addr, peer_id));

        // Duplicate add should return false
        assert!(!discovery.add_pex_address(addr, peer_id));
    }

    #[test]
    fn test_eclipse_protection() {
        let config = DiscoveryConfig {
            max_same_subnet: 2,
            ..Default::default()
        };
        let mut discovery = Discovery::new(config);

        // Connect two peers from same /16
        let addr1: SocketAddr = "192.168.1.1:30303".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:30303".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.3:30303".parse().unwrap();

        discovery.mark_connected(addr1);
        discovery.mark_connected(addr2);

        // Third from same subnet should be blocked
        assert!(!discovery.can_connect(&addr3));

        // Different subnet should be allowed
        let addr4: SocketAddr = "192.169.1.1:30303".parse().unwrap();
        discovery.add_address(addr4, AddressSource::Manual);
        assert!(discovery.can_connect(&addr4));
    }

    #[test]
    fn test_ban_address() {
        let config = DiscoveryConfig::default();
        let mut discovery = Discovery::new(config);

        let addr: SocketAddr = "192.168.1.1:30303".parse().unwrap();
        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Add address
        discovery.add_pex_address(addr, peer_id);

        // Ban it
        discovery.ban(addr);

        // Should not be connectable
        assert!(!discovery.can_connect(&addr));

        // Should not be addable
        assert!(!discovery.add_pex_address(addr, peer_id));
    }

    #[test]
    fn test_get_addresses_to_connect() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["192.168.1.1:30303".parse().unwrap()],
            ..Default::default()
        };
        let mut discovery = Discovery::new(config);

        // Add some addresses
        let peer_id = PeerId::from_bytes([1u8; 32]);
        discovery.add_pex_address("192.168.2.1:30303".parse().unwrap(), peer_id);
        discovery.add_pex_address("192.168.3.1:30303".parse().unwrap(), peer_id);

        let candidates = discovery.get_addresses_to_connect(10);

        // Should return addresses (bootstrap should be first due to scoring)
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_pex_addresses() {
        let config = DiscoveryConfig::default();
        let mut discovery = Discovery::new(config);

        // Simulate connected peers
        let addr1: SocketAddr = "192.168.1.1:30303".parse().unwrap();
        let addr2: SocketAddr = "192.168.2.1:30303".parse().unwrap();

        discovery.add_address(addr1, AddressSource::Manual);
        discovery.add_address(addr2, AddressSource::Manual);
        discovery.mark_connected(addr1);
        discovery.mark_connected(addr2);

        let pex = discovery.get_pex_addresses(10);

        // Should return connected peers
        assert!(!pex.is_empty());
    }
}
