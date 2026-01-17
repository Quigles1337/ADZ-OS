//! Hidden Services
//!
//! .muon addresses for anonymous services.
//!
//! # Design Overview
//!
//! Hidden services allow servers to be reached without revealing their
//! IP address. Clients connect through rendezvous points.
//!
//! # Protocol Flow
//!
//! 1. Service generates keypair, derives .muon address from public key
//! 2. Service establishes introduction points on the network
//! 3. Service publishes descriptor (intro points) to HSDir
//! 4. Client fetches descriptor, chooses intro point
//! 5. Client builds circuit to rendezvous point, sends cookie
//! 6. Client sends INTRODUCE to intro point with rendezvous info
//! 7. Service builds circuit to rendezvous point
//! 8. Service sends RENDEZVOUS with cookie, circuit is joined
//! 9. Communication flows through rendezvous circuit

use crate::{MuonResult, MuonError, MUON_ADDRESS_LENGTH};
use crate::circuit::{Circuit, CircuitId};
use crate::relay::RelayId;
use crate::crypto::CryptoContext;
use libmu_crypto::{MuHash, signature::MuKeyPair};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Hidden service address (.muon)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MuonAddress {
    /// Address bytes (32 bytes)
    bytes: [u8; 32],
    /// Version
    version: u8,
}

impl MuonAddress {
    /// Current address version
    pub const VERSION: u8 = 1;

    /// Create from public key
    pub fn from_public_key(public_key: &[u8; 64]) -> Self {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-hidden-service-v1");
        hasher.update(public_key);

        Self {
            bytes: hasher.finalize(),
            version: Self::VERSION,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32], version: u8) -> Self {
        Self { bytes, version }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get version
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Encode to base32 string (xxxxx...xxxxx.muon)
    pub fn to_string(&self) -> String {
        // Custom base32 encoding (lowercase, no padding)
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

        let mut result = String::with_capacity(MUON_ADDRESS_LENGTH);

        // Version byte
        result.push(ALPHABET[(self.version & 0x1f) as usize] as char);

        // Address bytes (5 bits at a time)
        let mut buffer: u64 = 0;
        let mut bits = 0;

        for byte in &self.bytes {
            buffer = (buffer << 8) | (*byte as u64);
            bits += 8;

            while bits >= 5 {
                bits -= 5;
                let index = ((buffer >> bits) & 0x1f) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        if bits > 0 {
            let index = ((buffer << (5 - bits)) & 0x1f) as usize;
            result.push(ALPHABET[index] as char);
        }

        // Append .muon suffix
        result.push_str(".muon");

        result
    }

    /// Parse from string (xxxxx.muon)
    pub fn from_string(s: &str) -> MuonResult<Self> {
        let s = s.trim().to_lowercase();

        // Remove .muon suffix
        let address_part = s.strip_suffix(".muon")
            .ok_or_else(|| MuonError::InvalidAddress("Missing .muon suffix".into()))?;

        if address_part.is_empty() {
            return Err(MuonError::InvalidAddress("Empty address".into()));
        }

        // Base32 decode
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

        let decode_char = |c: char| -> Option<u8> {
            ALPHABET.iter().position(|&x| x == c as u8).map(|p| p as u8)
        };

        let mut chars = address_part.chars();

        // Version byte
        let version = decode_char(chars.next().unwrap())
            .ok_or_else(|| MuonError::InvalidAddress("Invalid version character".into()))?;

        // Address bytes
        let mut bytes = [0u8; 32];
        let mut buffer: u64 = 0;
        let mut bits = 0;
        let mut byte_idx = 0;

        for c in chars {
            let value = decode_char(c)
                .ok_or_else(|| MuonError::InvalidAddress(
                    format!("Invalid character: {}", c)
                ))?;

            buffer = (buffer << 5) | (value as u64);
            bits += 5;

            while bits >= 8 && byte_idx < 32 {
                bits -= 8;
                bytes[byte_idx] = ((buffer >> bits) & 0xff) as u8;
                byte_idx += 1;
            }
        }

        Ok(Self { bytes, version })
    }

    /// Get short form (first 16 chars)
    pub fn short(&self) -> String {
        let full = self.to_string();
        let without_suffix = full.strip_suffix(".muon").unwrap();
        format!("{}...muon", &without_suffix[..8])
    }
}

impl std::fmt::Display for MuonAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Hidden service keypair
pub struct HiddenServiceKeys {
    /// Identity keypair
    identity: MuKeyPair,
    /// Original seed for persistence
    seed: [u8; 32],
    /// Derived address
    address: MuonAddress,
    /// Blinding factor for this period
    blinding_factor: Option<[u8; 32]>,
}

impl std::fmt::Debug for HiddenServiceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HiddenServiceKeys")
            .field("address", &self.address)
            .finish()
    }
}

impl HiddenServiceKeys {
    /// Generate new hidden service keys
    pub fn generate() -> Self {
        let seed = crate::crypto::random_bytes::<32>();
        let identity = MuKeyPair::from_seed(&seed);
        let address = MuonAddress::from_public_key(&identity.public_key().to_bytes());

        Self {
            identity,
            seed,
            address,
            blinding_factor: None,
        }
    }

    /// Load from seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let identity = MuKeyPair::from_seed(seed);
        let address = MuonAddress::from_public_key(&identity.public_key().to_bytes());

        Self {
            identity,
            seed: *seed,
            address,
            blinding_factor: None,
        }
    }

    /// Get address
    pub fn address(&self) -> &MuonAddress {
        &self.address
    }

    /// Get public key
    pub fn public_key(&self) -> [u8; 64] {
        self.identity.public_key().to_bytes()
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.identity.sign(data).to_bytes()
    }

    /// Get seed for persistence
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
}

/// Introduction point
#[derive(Debug, Clone)]
pub struct IntroductionPoint {
    /// Relay ID
    pub relay_id: RelayId,
    /// Onion key for handshake
    pub onion_key: [u8; 64],
    /// Authentication key (signed by service)
    pub auth_key: [u8; 64],
    /// Encryption key
    pub enc_key: [u8; 32],
    /// Link specifiers
    pub link_specifiers: Vec<LinkSpecifier>,
}

/// Link specifier for routing
#[derive(Debug, Clone)]
pub enum LinkSpecifier {
    /// IPv4 address
    IPv4(SocketAddr),
    /// IPv6 address
    IPv6(SocketAddr),
    /// Relay identity
    Identity([u8; 32]),
}

/// Hidden service descriptor (published to HSDir)
#[derive(Debug, Clone)]
pub struct HiddenServiceDescriptor {
    /// Descriptor version
    pub version: u8,
    /// Service public key
    pub public_key: [u8; 64],
    /// Descriptor creation time
    pub timestamp: SystemTime,
    /// Descriptor lifetime
    pub lifetime: Duration,
    /// Introduction points
    pub intro_points: Vec<IntroductionPoint>,
    /// Encrypted body (for descriptor v3)
    pub encrypted_body: Option<Vec<u8>>,
    /// Signature
    pub signature: [u8; 64],
}

impl HiddenServiceDescriptor {
    /// Current descriptor version
    pub const VERSION: u8 = 3;

    /// Default lifetime (24 hours)
    pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(86400);

    /// Create new descriptor
    pub fn new(keys: &HiddenServiceKeys, intro_points: Vec<IntroductionPoint>) -> Self {
        let mut desc = Self {
            version: Self::VERSION,
            public_key: keys.public_key(),
            timestamp: SystemTime::now(),
            lifetime: Self::DEFAULT_LIFETIME,
            intro_points,
            encrypted_body: None,
            signature: [0u8; 64],
        };

        // Sign descriptor
        let digest = desc.digest();
        desc.signature = keys.sign(&digest);

        desc
    }

    /// Compute descriptor digest
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-hs-descriptor-v3");
        hasher.update(&[self.version]);
        hasher.update(&self.public_key);
        hasher.finalize()
    }

    /// Compute descriptor ID (for HSDir lookup)
    pub fn descriptor_id(&self, time_period: u64) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(b"muonnet-hsdir-desc-id");
        hasher.update(&self.public_key);
        hasher.update(&time_period.to_be_bytes());
        hasher.finalize()
    }

    /// Check if descriptor is valid
    pub fn is_valid(&self) -> bool {
        // Check expiry
        if let Ok(age) = self.timestamp.elapsed() {
            if age > self.lifetime {
                return false;
            }
        } else {
            return false;
        }

        // Check intro points
        if self.intro_points.is_empty() {
            return false;
        }

        true
    }

    /// Get address
    pub fn address(&self) -> MuonAddress {
        MuonAddress::from_public_key(&self.public_key)
    }
}

/// HSDir (Hidden Service Directory) relay selection
#[derive(Debug, Clone)]
pub struct HSDirRing {
    /// HSDir relays sorted by position in ring
    relays: Vec<(RelayId, [u8; 32])>,
}

impl HSDirRing {
    /// Create new HSDir ring
    pub fn new() -> Self {
        Self { relays: Vec::new() }
    }

    /// Add relay to ring
    pub fn add_relay(&mut self, relay_id: RelayId, identity_hash: [u8; 32]) {
        self.relays.push((relay_id, identity_hash));
        self.relays.sort_by_key(|(_, hash)| *hash);
    }

    /// Get responsible HSDirs for descriptor ID
    pub fn responsible_dirs(&self, descriptor_id: &[u8; 32], count: usize) -> Vec<RelayId> {
        if self.relays.is_empty() {
            return vec![];
        }

        // Find position in ring
        let pos = self.relays.iter()
            .position(|(_, hash)| hash >= descriptor_id)
            .unwrap_or(0);

        // Return next `count` relays (wrapping)
        (0..count)
            .map(|i| {
                let idx = (pos + i) % self.relays.len();
                self.relays[idx].0
            })
            .collect()
    }
}

impl Default for HSDirRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Rendezvous cookie for circuit joining
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RendezvousCookie([u8; 20]);

impl RendezvousCookie {
    /// Generate new random cookie
    pub fn generate() -> Self {
        let random = crate::crypto::random_bytes::<20>();
        Self(random)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

/// Hidden service configuration
#[derive(Debug, Clone)]
pub struct HiddenServiceConfig {
    /// Service directory (keys and hostname)
    pub directory: PathBuf,
    /// Port mappings (virtual -> local)
    pub ports: Vec<(u16, SocketAddr)>,
    /// Number of introduction points
    pub intro_points: usize,
    /// Maximum streams
    pub max_streams: usize,
    /// Descriptor publish interval
    pub publish_interval: Duration,
}

impl Default for HiddenServiceConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".muon_hidden_service"),
            ports: vec![(80, "127.0.0.1:8080".parse().unwrap())],
            intro_points: 3,
            max_streams: 100,
            publish_interval: Duration::from_secs(3600),
        }
    }
}

/// Hidden service state
#[derive(Debug)]
pub struct HiddenService {
    /// Service keys
    keys: HiddenServiceKeys,
    /// Configuration
    config: HiddenServiceConfig,
    /// Current descriptor
    descriptor: Option<HiddenServiceDescriptor>,
    /// Introduction circuits
    intro_circuits: HashMap<RelayId, CircuitId>,
    /// Active rendezvous circuits
    rendezvous_circuits: HashMap<RendezvousCookie, CircuitId>,
}

impl HiddenService {
    /// Create new hidden service
    pub fn new(config: HiddenServiceConfig) -> MuonResult<Self> {
        // Try to load existing keys or generate new ones
        let keys_path = config.directory.join("private_key");
        let keys = if keys_path.exists() {
            let seed_hex = std::fs::read_to_string(&keys_path)
                .map_err(|e| MuonError::Io(e.to_string()))?;

            let mut seed = [0u8; 32];
            for (i, chunk) in seed_hex.trim().as_bytes().chunks(2).enumerate() {
                if i >= 32 { break; }
                let s = std::str::from_utf8(chunk)
                    .map_err(|_| MuonError::InvalidAddress("Invalid key file".into()))?;
                seed[i] = u8::from_str_radix(s, 16)
                    .map_err(|_| MuonError::InvalidAddress("Invalid key file".into()))?;
            }

            HiddenServiceKeys::from_seed(&seed)
        } else {
            // Generate new keys
            let keys = HiddenServiceKeys::generate();

            // Save keys
            std::fs::create_dir_all(&config.directory)
                .map_err(|e| MuonError::Io(e.to_string()))?;

            let seed_hex: String = keys.seed().iter()
                .map(|b| format!("{:02x}", b))
                .collect();

            std::fs::write(&keys_path, &seed_hex)
                .map_err(|e| MuonError::Io(e.to_string()))?;

            // Write hostname file
            let hostname_path = config.directory.join("hostname");
            std::fs::write(&hostname_path, keys.address().to_string())
                .map_err(|e| MuonError::Io(e.to_string()))?;

            keys
        };

        Ok(Self {
            keys,
            config,
            descriptor: None,
            intro_circuits: HashMap::new(),
            rendezvous_circuits: HashMap::new(),
        })
    }

    /// Get service address
    pub fn address(&self) -> &MuonAddress {
        self.keys.address()
    }

    /// Get configuration
    pub fn config(&self) -> &HiddenServiceConfig {
        &self.config
    }

    /// Get current descriptor
    pub fn descriptor(&self) -> Option<&HiddenServiceDescriptor> {
        self.descriptor.as_ref()
    }

    /// Set descriptor
    pub fn set_descriptor(&mut self, descriptor: HiddenServiceDescriptor) {
        self.descriptor = Some(descriptor);
    }

    /// Add introduction circuit
    pub fn add_intro_circuit(&mut self, relay_id: RelayId, circuit_id: CircuitId) {
        self.intro_circuits.insert(relay_id, circuit_id);
    }

    /// Remove introduction circuit
    pub fn remove_intro_circuit(&mut self, relay_id: &RelayId) {
        self.intro_circuits.remove(relay_id);
    }

    /// Get introduction circuits
    pub fn intro_circuits(&self) -> &HashMap<RelayId, CircuitId> {
        &self.intro_circuits
    }

    /// Add rendezvous circuit
    pub fn add_rendezvous(&mut self, cookie: RendezvousCookie, circuit_id: CircuitId) {
        self.rendezvous_circuits.insert(cookie, circuit_id);
    }

    /// Get and remove rendezvous circuit
    pub fn take_rendezvous(&mut self, cookie: &RendezvousCookie) -> Option<CircuitId> {
        self.rendezvous_circuits.remove(cookie)
    }

    /// Map virtual port to local address
    pub fn map_port(&self, virtual_port: u16) -> Option<SocketAddr> {
        self.config.ports.iter()
            .find(|(vp, _)| *vp == virtual_port)
            .map(|(_, addr)| *addr)
    }
}

/// Client-side hidden service connection
#[derive(Debug)]
pub struct HiddenServiceClient {
    /// Target address
    address: MuonAddress,
    /// Fetched descriptor
    descriptor: Option<HiddenServiceDescriptor>,
    /// Rendezvous cookie
    rend_cookie: Option<RendezvousCookie>,
    /// Circuit to rendezvous point
    rend_circuit: Option<CircuitId>,
}

impl HiddenServiceClient {
    /// Create new client connection
    pub fn new(address: MuonAddress) -> Self {
        Self {
            address,
            descriptor: None,
            rend_cookie: None,
            rend_circuit: None,
        }
    }

    /// Get target address
    pub fn address(&self) -> &MuonAddress {
        &self.address
    }

    /// Set fetched descriptor
    pub fn set_descriptor(&mut self, descriptor: HiddenServiceDescriptor) {
        self.descriptor = Some(descriptor);
    }

    /// Get descriptor
    pub fn descriptor(&self) -> Option<&HiddenServiceDescriptor> {
        self.descriptor.as_ref()
    }

    /// Generate rendezvous cookie
    pub fn generate_cookie(&mut self) -> RendezvousCookie {
        let cookie = RendezvousCookie::generate();
        self.rend_cookie = Some(cookie);
        cookie
    }

    /// Get rendezvous cookie
    pub fn cookie(&self) -> Option<RendezvousCookie> {
        self.rend_cookie
    }

    /// Set rendezvous circuit
    pub fn set_rend_circuit(&mut self, circuit_id: CircuitId) {
        self.rend_circuit = Some(circuit_id);
    }

    /// Get rendezvous circuit
    pub fn rend_circuit(&self) -> Option<CircuitId> {
        self.rend_circuit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_muon_address_roundtrip() {
        let pubkey = [42u8; 64];
        let addr = MuonAddress::from_public_key(&pubkey);

        let encoded = addr.to_string();
        assert!(encoded.ends_with(".muon"));

        let decoded = MuonAddress::from_string(&encoded).unwrap();
        assert_eq!(addr.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_hidden_service_keys() {
        let keys = HiddenServiceKeys::generate();
        let addr = keys.address();

        assert_eq!(addr.version(), MuonAddress::VERSION);

        // Check deterministic from seed
        let seed = keys.seed();
        let keys2 = HiddenServiceKeys::from_seed(&seed);
        assert_eq!(keys.address().as_bytes(), keys2.address().as_bytes());
    }

    #[test]
    fn test_rendezvous_cookie() {
        let cookie1 = RendezvousCookie::generate();
        let cookie2 = RendezvousCookie::generate();

        assert_ne!(cookie1, cookie2);
        assert_eq!(cookie1.as_bytes().len(), 20);
    }

    #[test]
    fn test_descriptor_creation() {
        let keys = HiddenServiceKeys::generate();
        let desc = HiddenServiceDescriptor::new(&keys, vec![]);

        assert_eq!(desc.version, HiddenServiceDescriptor::VERSION);
        assert_eq!(desc.public_key, keys.public_key());
    }

    #[test]
    fn test_hsdir_ring() {
        let mut ring = HSDirRing::new();

        ring.add_relay(RelayId::from_bytes([1u8; 32]), [0x10; 32]);
        ring.add_relay(RelayId::from_bytes([2u8; 32]), [0x30; 32]);
        ring.add_relay(RelayId::from_bytes([3u8; 32]), [0x50; 32]);

        let desc_id = [0x20; 32];
        let dirs = ring.responsible_dirs(&desc_id, 2);

        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn test_address_short() {
        let pubkey = [42u8; 64];
        let addr = MuonAddress::from_public_key(&pubkey);
        let short = addr.short();

        assert!(short.ends_with("...muon"));
    }
}
