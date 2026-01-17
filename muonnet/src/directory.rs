//! Directory Authority System
//!
//! Manages relay discovery and network consensus.
//!
//! # Design
//!
//! - Directory authorities publish signed relay lists
//! - Clients fetch consensus from multiple authorities
//! - Relays publish descriptors to authorities
//! - Consensus includes relay flags, bandwidth, and policies
//!
//! # Decentralization via ChainMesh
//!
//! Directory data can be anchored to ChainMesh for:
//! - Tamper-evident relay lists
//! - Decentralized authority voting
//! - Historical audit trail

use crate::{MuonResult, MuonError};
use crate::relay::{RelayDescriptor, RelayId, RelayFlags, RelaySelector};
use crate::crypto::CryptoContext;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use libmu_crypto::MuHash;

/// Consensus validity period
pub const CONSENSUS_VALIDITY: Duration = Duration::from_secs(3600); // 1 hour

/// Minimum authorities for valid consensus
pub const MIN_AUTHORITIES: usize = 3;

/// Directory authority identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorityId([u8; 32]);

impl AuthorityId {
    /// Create from public key
    pub fn from_public_key(public_key: &[u8; 64]) -> Self {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-authority-id-v1");
        hasher.update(public_key);
        Self(hasher.finalize())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Directory authority
#[derive(Debug, Clone)]
pub struct DirectoryAuthority {
    /// Authority identifier
    pub id: AuthorityId,
    /// Authority nickname
    pub nickname: String,
    /// Identity public key
    pub identity_key: [u8; 64],
    /// Directory address
    pub dir_address: SocketAddr,
    /// OR address (if also a relay)
    pub or_address: Option<SocketAddr>,
    /// Is voting authority
    pub is_voting: bool,
    /// Contact info
    pub contact: Option<String>,
}

impl DirectoryAuthority {
    /// Create a new authority
    pub fn new(
        nickname: String,
        identity_key: [u8; 64],
        dir_address: SocketAddr,
    ) -> Self {
        let id = AuthorityId::from_public_key(&identity_key);
        Self {
            id,
            nickname,
            identity_key,
            dir_address,
            or_address: None,
            is_voting: true,
            contact: None,
        }
    }
}

/// Network consensus
#[derive(Debug, Clone)]
pub struct Consensus {
    /// Consensus version
    pub version: u32,
    /// Valid-after time
    pub valid_after: SystemTime,
    /// Fresh-until time
    pub fresh_until: SystemTime,
    /// Valid-until time
    pub valid_until: SystemTime,
    /// Voting authorities
    pub authorities: Vec<AuthorityId>,
    /// Relay entries
    pub relays: Vec<ConsensusRelay>,
    /// Bandwidth weights
    pub bandwidth_weights: BandwidthWeights,
    /// Consensus digest
    pub digest: [u8; 32],
    /// Authority signatures
    pub signatures: Vec<AuthoritySignature>,
}

impl Consensus {
    /// Create a new consensus
    pub fn new(relays: Vec<ConsensusRelay>, authorities: Vec<AuthorityId>) -> Self {
        let now = SystemTime::now();
        let valid_after = now;
        let fresh_until = now + Duration::from_secs(1800); // 30 min
        let valid_until = now + CONSENSUS_VALIDITY;

        let mut consensus = Self {
            version: 1,
            valid_after,
            fresh_until,
            valid_until,
            authorities,
            relays,
            bandwidth_weights: BandwidthWeights::default(),
            digest: [0u8; 32],
            signatures: Vec::new(),
        };

        consensus.digest = consensus.compute_digest();
        consensus
    }

    /// Compute consensus digest
    fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-consensus-v1");
        hasher.update(&self.version.to_be_bytes());

        for relay in &self.relays {
            hasher.update(relay.id.as_bytes());
        }

        hasher.finalize()
    }

    /// Check if consensus is valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();

        // Check time validity
        if now < self.valid_after || now > self.valid_until {
            return false;
        }

        // Check minimum signatures
        if self.signatures.len() < MIN_AUTHORITIES {
            return false;
        }

        true
    }

    /// Check if consensus is fresh
    pub fn is_fresh(&self) -> bool {
        SystemTime::now() < self.fresh_until
    }

    /// Get relay count
    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    /// Get relay by ID
    pub fn get_relay(&self, id: &RelayId) -> Option<&ConsensusRelay> {
        self.relays.iter().find(|r| &r.id == id)
    }

    /// Select relays matching criteria
    pub fn select_relays(&self, selector: &RelaySelector) -> Vec<&ConsensusRelay> {
        self.relays.iter()
            .filter(|relay| {
                // Check excluded
                if selector.exclude.contains(&relay.id) {
                    return false;
                }

                // Check required flags
                let req = &selector.required_flags;
                if req.guard && !relay.flags.guard { return false; }
                if req.exit && !relay.flags.exit { return false; }
                if req.stable && !relay.flags.stable { return false; }
                if req.fast && !relay.flags.fast { return false; }
                if req.running && !relay.flags.running { return false; }
                if req.valid && !relay.flags.valid { return false; }

                // Check bandwidth
                if relay.bandwidth < selector.min_bandwidth {
                    return false;
                }

                true
            })
            .collect()
    }

    /// Get guards
    pub fn guards(&self) -> Vec<&ConsensusRelay> {
        self.relays.iter()
            .filter(|r| r.flags.can_guard())
            .collect()
    }

    /// Get exits
    pub fn exits(&self) -> Vec<&ConsensusRelay> {
        self.relays.iter()
            .filter(|r| r.flags.can_exit())
            .collect()
    }

    /// Get middle relays
    pub fn middles(&self) -> Vec<&ConsensusRelay> {
        self.relays.iter()
            .filter(|r| r.flags.can_middle())
            .collect()
    }
}

/// Relay entry in consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRelay {
    /// Relay ID
    pub id: RelayId,
    /// Relay nickname
    pub nickname: String,
    /// OR addresses
    pub or_addresses: Vec<SocketAddr>,
    /// Directory port
    pub dir_port: Option<u16>,
    /// Relay flags
    pub flags: RelayFlags,
    /// Measured bandwidth
    pub bandwidth: u64,
    /// Exit policy summary
    pub exit_policy_summary: ExitPolicySummary,
    /// Onion key digest
    pub onion_key_digest: [u8; 32],
    /// Descriptor digest
    pub descriptor_digest: [u8; 32],
}

impl ConsensusRelay {
    /// Create from full descriptor
    pub fn from_descriptor(desc: &RelayDescriptor, bandwidth: u64) -> Self {
        let mut onion_key_digest = [0u8; 32];
        let mut hasher = MuHash::new();
        hasher.update(&desc.onion_key);
        onion_key_digest.copy_from_slice(&hasher.finalize());

        Self {
            id: desc.id,
            nickname: desc.nickname.clone(),
            or_addresses: vec![desc.or_address],
            dir_port: desc.dir_port,
            flags: desc.flags,
            bandwidth,
            exit_policy_summary: ExitPolicySummary::from_policy(&desc.exit_policy),
            onion_key_digest,
            descriptor_digest: desc.digest(),
        }
    }
}

/// Summarized exit policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPolicySummary {
    /// Accept by default
    pub default_accept: bool,
    /// Port ranges (accept/reject based on default)
    pub port_ranges: Vec<(u16, u16)>,
}

impl ExitPolicySummary {
    /// Create from exit policy
    pub fn from_policy(policy: &crate::config::ExitPolicy) -> Self {
        use crate::config::ExitPolicy;

        match policy {
            ExitPolicy::NoExit => Self {
                default_accept: false,
                port_ranges: vec![],
            },
            ExitPolicy::AllowAll => Self {
                default_accept: true,
                port_ranges: vec![],
            },
            ExitPolicy::AllowPorts(ports) => Self {
                default_accept: false,
                port_ranges: ports.iter().map(|p| (*p, *p)).collect(),
            },
            ExitPolicy::RejectPorts(ports) => Self {
                default_accept: true,
                port_ranges: ports.iter().map(|p| (*p, *p)).collect(),
            },
            ExitPolicy::Custom(_) => Self {
                default_accept: false,
                port_ranges: vec![],
            },
        }
    }

    /// Check if port is allowed
    pub fn allows_port(&self, port: u16) -> bool {
        let in_ranges = self.port_ranges.iter()
            .any(|(start, end)| port >= *start && port <= *end);

        if self.default_accept {
            !in_ranges
        } else {
            in_ranges
        }
    }
}

/// Bandwidth weights for path selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthWeights {
    /// Weight for guard position
    pub guard: f64,
    /// Weight for middle position
    pub middle: f64,
    /// Weight for exit position
    pub exit: f64,
    /// Weight for guard+exit
    pub guard_exit: f64,
}

impl Default for BandwidthWeights {
    fn default() -> Self {
        Self {
            guard: 1.0,
            middle: 1.0,
            exit: 1.0,
            guard_exit: 1.0,
        }
    }
}

/// Authority signature on consensus
#[derive(Debug, Clone)]
pub struct AuthoritySignature {
    /// Authority ID
    pub authority_id: AuthorityId,
    /// Signature over digest
    pub signature: [u8; 64],
}

/// Directory cache for clients
#[derive(Debug)]
pub struct DirectoryCache {
    /// Known authorities
    authorities: Vec<DirectoryAuthority>,
    /// Current consensus
    consensus: Option<Consensus>,
    /// Full relay descriptors
    descriptors: HashMap<RelayId, RelayDescriptor>,
    /// Last update time
    last_update: Option<SystemTime>,
}

impl DirectoryCache {
    /// Create new directory cache
    pub fn new() -> Self {
        Self {
            authorities: Vec::new(),
            consensus: None,
            descriptors: HashMap::new(),
            last_update: None,
        }
    }

    /// Add authority
    pub fn add_authority(&mut self, authority: DirectoryAuthority) {
        if !self.authorities.iter().any(|a| a.id == authority.id) {
            self.authorities.push(authority);
        }
    }

    /// Get authorities
    pub fn authorities(&self) -> &[DirectoryAuthority] {
        &self.authorities
    }

    /// Set consensus
    pub fn set_consensus(&mut self, consensus: Consensus) {
        self.consensus = Some(consensus);
        self.last_update = Some(SystemTime::now());
    }

    /// Get consensus
    pub fn consensus(&self) -> Option<&Consensus> {
        self.consensus.as_ref()
    }

    /// Check if consensus is valid
    pub fn has_valid_consensus(&self) -> bool {
        self.consensus.as_ref().map(|c| c.is_valid()).unwrap_or(false)
    }

    /// Add relay descriptor
    pub fn add_descriptor(&mut self, descriptor: RelayDescriptor) {
        self.descriptors.insert(descriptor.id, descriptor);
    }

    /// Get relay descriptor
    pub fn get_descriptor(&self, id: &RelayId) -> Option<&RelayDescriptor> {
        self.descriptors.get(id)
    }

    /// Get relay count
    pub fn relay_count(&self) -> usize {
        self.consensus.as_ref().map(|c| c.relay_count()).unwrap_or(0)
    }

    /// Select random guard
    pub fn select_guard(&self) -> Option<&RelayDescriptor> {
        let consensus = self.consensus.as_ref()?;
        let guards = consensus.guards();

        if guards.is_empty() {
            return None;
        }

        // Simple random selection (should use weighted selection in production)
        let idx = crate::crypto::random_bytes::<1>()[0] as usize % guards.len();
        let relay = guards[idx];

        self.descriptors.get(&relay.id)
    }

    /// Select random middle relay
    pub fn select_middle(&self, exclude: &[RelayId]) -> Option<&RelayDescriptor> {
        let consensus = self.consensus.as_ref()?;

        let candidates: Vec<_> = consensus.middles()
            .into_iter()
            .filter(|r| !exclude.contains(&r.id))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let idx = crate::crypto::random_bytes::<1>()[0] as usize % candidates.len();
        let relay = candidates[idx];

        self.descriptors.get(&relay.id)
    }

    /// Select random exit for port
    pub fn select_exit(&self, port: u16, exclude: &[RelayId]) -> Option<&RelayDescriptor> {
        let consensus = self.consensus.as_ref()?;

        let candidates: Vec<_> = consensus.exits()
            .into_iter()
            .filter(|r| {
                !exclude.contains(&r.id) &&
                r.exit_policy_summary.allows_port(port)
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let idx = crate::crypto::random_bytes::<1>()[0] as usize % candidates.len();
        let relay = candidates[idx];

        self.descriptors.get(&relay.id)
    }

    /// Build circuit path for destination
    pub fn build_path(&self, dest_port: u16) -> Option<Vec<&RelayDescriptor>> {
        let guard = self.select_guard()?;
        let middle = self.select_middle(&[guard.id])?;
        let exit = self.select_exit(dest_port, &[guard.id, middle.id])?;

        Some(vec![guard, middle, exit])
    }
}

impl Default for DirectoryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Vote from a directory authority
#[derive(Debug, Clone)]
pub struct AuthorityVote {
    /// Authority ID
    pub authority_id: AuthorityId,
    /// Relay entries
    pub relays: Vec<VoteRelay>,
    /// Vote time
    pub published: SystemTime,
    /// Signature
    pub signature: [u8; 64],
}

/// Relay entry in a vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRelay {
    /// Relay ID
    pub id: RelayId,
    /// Proposed flags
    pub flags: RelayFlags,
    /// Measured bandwidth
    pub bandwidth: u64,
}

/// Build consensus from votes
pub fn build_consensus(
    votes: &[AuthorityVote],
    authorities: &[DirectoryAuthority],
) -> MuonResult<Consensus> {
    if votes.len() < MIN_AUTHORITIES {
        return Err(MuonError::ConsensusFailed(
            format!("Not enough votes: {} < {}", votes.len(), MIN_AUTHORITIES)
        ));
    }

    // Collect relay votes
    let mut relay_votes: HashMap<RelayId, Vec<&VoteRelay>> = HashMap::new();

    for vote in votes {
        for relay in &vote.relays {
            relay_votes.entry(relay.id).or_default().push(relay);
        }
    }

    // Build consensus relays (majority voting)
    let threshold = votes.len() / 2 + 1;
    let mut consensus_relays = Vec::new();

    for (id, relay_votes) in relay_votes {
        if relay_votes.len() < threshold {
            continue;
        }

        // Merge flags (require majority for each flag)
        let flags = merge_flags(&relay_votes, threshold);

        // Average bandwidth
        let bandwidth: u64 = relay_votes.iter().map(|r| r.bandwidth).sum::<u64>()
            / relay_votes.len() as u64;

        // Create minimal consensus relay
        consensus_relays.push(ConsensusRelay {
            id,
            nickname: String::new(), // Would be filled from descriptors
            or_addresses: vec![],
            dir_port: None,
            flags,
            bandwidth,
            exit_policy_summary: ExitPolicySummary {
                default_accept: false,
                port_ranges: vec![],
            },
            onion_key_digest: [0u8; 32],
            descriptor_digest: [0u8; 32],
        });
    }

    let authority_ids: Vec<_> = authorities.iter().map(|a| a.id).collect();
    Ok(Consensus::new(consensus_relays, authority_ids))
}

/// Merge flags from multiple votes
fn merge_flags(votes: &[&VoteRelay], threshold: usize) -> RelayFlags {
    let count = |flag_fn: fn(&RelayFlags) -> bool| -> bool {
        votes.iter().filter(|v| flag_fn(&v.flags)).count() >= threshold
    };

    RelayFlags {
        exit: count(|f| f.exit),
        guard: count(|f| f.guard),
        stable: count(|f| f.stable),
        fast: count(|f| f.fast),
        running: count(|f| f.running),
        valid: count(|f| f.valid),
        v2dir: count(|f| f.v2dir),
        authority: count(|f| f.authority),
        hsdir: count(|f| f.hsdir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_relay_descriptor() -> RelayDescriptor {
        RelayDescriptor::new(
            "TestRelay".into(),
            [0u8; 64],
            [0u8; 64],
            "127.0.0.1:9001".parse().unwrap(),
        )
    }

    #[test]
    fn test_authority_creation() {
        let auth = DirectoryAuthority::new(
            "TestAuth".into(),
            [1u8; 64],
            "127.0.0.1:9030".parse().unwrap(),
        );

        assert_eq!(auth.nickname, "TestAuth");
        assert!(auth.is_voting);
    }

    #[test]
    fn test_consensus_creation() {
        let relay = ConsensusRelay::from_descriptor(&test_relay_descriptor(), 1000);
        let consensus = Consensus::new(vec![relay], vec![]);

        assert_eq!(consensus.relay_count(), 1);
        // Note: is_valid() requires MIN_AUTHORITIES signatures
        // For unit test, just check structure is created correctly
        assert!(consensus.is_fresh());
    }

    #[test]
    fn test_exit_policy_summary() {
        let summary = ExitPolicySummary {
            default_accept: false,
            port_ranges: vec![(80, 80), (443, 443)],
        };

        assert!(summary.allows_port(80));
        assert!(summary.allows_port(443));
        assert!(!summary.allows_port(22));
    }

    #[test]
    fn test_directory_cache() {
        let mut cache = DirectoryCache::new();

        let desc = test_relay_descriptor();
        cache.add_descriptor(desc.clone());

        assert!(cache.get_descriptor(&desc.id).is_some());
    }

    #[test]
    fn test_consensus_relay_selection() {
        let mut desc = test_relay_descriptor();
        desc.flags.running = true;
        desc.flags.valid = true;
        desc.flags.guard = true;
        desc.flags.stable = true;

        let relay = ConsensusRelay::from_descriptor(&desc, 1000);
        let consensus = Consensus::new(vec![relay], vec![]);

        let guards = consensus.guards();
        assert_eq!(guards.len(), 1);
    }
}
