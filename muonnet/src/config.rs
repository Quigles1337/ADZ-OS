//! MuonNet Configuration
//!
//! Configuration options for MuonNet clients and relays.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use serde::{Serialize, Deserialize};

/// MuonNet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuonConfig {
    /// Node mode (client, relay, or both)
    pub mode: NodeMode,

    /// Data directory for state and keys
    pub data_dir: PathBuf,

    /// SOCKS proxy listen address (for clients)
    pub socks_addr: Option<SocketAddr>,

    /// Control port address
    pub control_addr: Option<SocketAddr>,

    /// OR (Onion Router) listen address (for relays)
    pub or_addr: Option<SocketAddr>,

    /// Directory server addresses
    pub directory_servers: Vec<SocketAddr>,

    /// Circuit settings
    pub circuit: CircuitConfig,

    /// Relay settings (if running as relay)
    pub relay: RelayConfig,

    /// Hidden service settings
    pub hidden_services: Vec<HiddenServiceConfig>,

    /// Logging level
    pub log_level: String,

    /// Enable bandwidth limiting
    pub bandwidth_limit: Option<BandwidthConfig>,
}

impl Default for MuonConfig {
    fn default() -> Self {
        Self {
            mode: NodeMode::Client,
            data_dir: default_data_dir(),
            socks_addr: Some("127.0.0.1:9050".parse().unwrap()),
            control_addr: Some("127.0.0.1:9051".parse().unwrap()),
            or_addr: None,
            directory_servers: default_directory_servers(),
            circuit: CircuitConfig::default(),
            relay: RelayConfig::default(),
            hidden_services: Vec::new(),
            log_level: "info".into(),
            bandwidth_limit: None,
        }
    }
}

impl MuonConfig {
    /// Create client-only configuration
    pub fn client() -> Self {
        Self::default()
    }

    /// Create relay configuration
    pub fn relay(or_addr: SocketAddr) -> Self {
        Self {
            mode: NodeMode::Relay,
            or_addr: Some(or_addr),
            ..Self::default()
        }
    }

    /// Create configuration for running both client and relay
    pub fn bridge(or_addr: SocketAddr) -> Self {
        Self {
            mode: NodeMode::Bridge,
            or_addr: Some(or_addr),
            ..Self::default()
        }
    }

    /// Load configuration from file
    pub fn load(path: &std::path::Path) -> crate::MuonResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::MuonError::InvalidConfiguration(e.to_string()))?;

        serde_json::from_str(&content)
            .map_err(|e| crate::MuonError::InvalidConfiguration(e.to_string()))
    }

    /// Save configuration to file
    pub fn save(&self, path: &std::path::Path) -> crate::MuonResult<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::MuonError::InvalidConfiguration(e.to_string()))?;

        std::fs::write(path, content)
            .map_err(|e| crate::MuonError::InvalidConfiguration(e.to_string()))
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::MuonResult<()> {
        // Check data directory exists or can be created
        if !self.data_dir.exists() {
            std::fs::create_dir_all(&self.data_dir)
                .map_err(|e| crate::MuonError::InvalidConfiguration(
                    format!("Cannot create data dir: {}", e)
                ))?;
        }

        // Check relay config if running as relay
        if matches!(self.mode, NodeMode::Relay | NodeMode::Bridge) {
            if self.or_addr.is_none() {
                return Err(crate::MuonError::MissingConfiguration(
                    "OR address required for relay mode".into()
                ));
            }
        }

        // Check client config if running as client
        if matches!(self.mode, NodeMode::Client | NodeMode::Bridge) {
            if self.socks_addr.is_none() {
                return Err(crate::MuonError::MissingConfiguration(
                    "SOCKS address required for client mode".into()
                ));
            }
        }

        Ok(())
    }
}

/// Node operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    /// Client only (connects through network)
    Client,
    /// Relay only (forwards traffic)
    Relay,
    /// Both client and relay
    Bridge,
}

/// Circuit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Number of hops in circuits (minimum 3)
    pub circuit_length: usize,

    /// Maximum concurrent circuits
    pub max_circuits: usize,

    /// Circuit build timeout
    #[serde(with = "humantime_serde")]
    pub build_timeout: Duration,

    /// Circuit idle timeout
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Maximum streams per circuit
    pub max_streams: usize,

    /// Preemptively build circuits
    pub preemptive_circuits: usize,

    /// Guard node selection strategy
    pub guard_selection: GuardSelection,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            circuit_length: 3,
            max_circuits: 32,
            build_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_streams: 500,
            preemptive_circuits: 3,
            guard_selection: GuardSelection::Stable,
        }
    }
}

/// Guard node selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardSelection {
    /// Use stable, high-uptime guards
    Stable,
    /// Random guard selection
    Random,
    /// Use specific entry guards
    Fixed,
}

/// Relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Relay nickname
    pub nickname: String,

    /// Contact information
    pub contact: Option<String>,

    /// Exit policy (what destinations this relay allows)
    pub exit_policy: ExitPolicy,

    /// Advertised bandwidth (bytes/sec)
    pub bandwidth_rate: u64,

    /// Burst bandwidth (bytes/sec)
    pub bandwidth_burst: u64,

    /// Accept connections from these networks only
    pub allowed_networks: Vec<String>,

    /// Maximum connections
    pub max_connections: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            nickname: "MuonRelay".into(),
            contact: None,
            exit_policy: ExitPolicy::NoExit,
            bandwidth_rate: 1_000_000,    // 1 MB/s
            bandwidth_burst: 2_000_000,   // 2 MB/s
            allowed_networks: vec!["0.0.0.0/0".into()],
            max_connections: 1000,
        }
    }
}

/// Exit policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitPolicy {
    /// No exit traffic allowed (middle relay only)
    NoExit,
    /// Allow exit to specific ports
    AllowPorts(Vec<u16>),
    /// Allow all except specific ports
    RejectPorts(Vec<u16>),
    /// Full exit relay
    AllowAll,
    /// Custom policy rules
    Custom(Vec<PolicyRule>),
}

/// Custom exit policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Accept or reject
    pub action: PolicyAction,
    /// Network pattern (e.g., "192.168.0.0/16")
    pub network: String,
    /// Port range
    pub ports: (u16, u16),
}

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Accept,
    Reject,
}

/// Hidden service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenServiceConfig {
    /// Hidden service directory (for keys and hostname)
    pub directory: PathBuf,

    /// Virtual port mappings (virtual_port -> target)
    pub ports: Vec<(u16, SocketAddr)>,

    /// Number of introduction points
    pub intro_points: usize,

    /// Maximum streams
    pub max_streams: usize,
}

/// Bandwidth limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthConfig {
    /// Rate limit (bytes/sec)
    pub rate: u64,
    /// Burst limit (bytes)
    pub burst: u64,
}

/// Get default data directory
fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("muonnet"))
        .unwrap_or_else(|| PathBuf::from(".muonnet"))
}

/// Get default directory servers
fn default_directory_servers() -> Vec<SocketAddr> {
    // These would be replaced with actual directory authority addresses
    vec![
        // Placeholder directory servers
        // "198.51.100.1:9030".parse().unwrap(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = MuonConfig::default();
        assert_eq!(config.mode, NodeMode::Client);
        assert!(config.socks_addr.is_some());
    }

    #[test]
    fn test_client_config() {
        let config = MuonConfig::client();
        assert_eq!(config.mode, NodeMode::Client);
    }

    #[test]
    fn test_relay_config() {
        let addr: SocketAddr = "0.0.0.0:9001".parse().unwrap();
        let config = MuonConfig::relay(addr);
        assert_eq!(config.mode, NodeMode::Relay);
        assert_eq!(config.or_addr, Some(addr));
    }

    #[test]
    fn test_config_save_load() {
        let tmp = tempdir().unwrap();
        let config_path = tmp.path().join("config.json");

        let config = MuonConfig::default();
        config.save(&config_path).unwrap();

        let loaded = MuonConfig::load(&config_path).unwrap();
        assert_eq!(loaded.mode, config.mode);
    }

    #[test]
    fn test_circuit_config_defaults() {
        let config = CircuitConfig::default();
        assert_eq!(config.circuit_length, 3);
        assert!(config.max_circuits > 0);
    }
}
