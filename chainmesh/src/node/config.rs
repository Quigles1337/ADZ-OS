//! Node Configuration
//!
//! Configuration options for ChainMesh node including network settings,
//! storage paths, RPC endpoints, and validator keys.

use crate::ChainConfig;
use crate::types::Address;
use std::path::PathBuf;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Mainnet
    Mainnet,
    /// Testnet
    Testnet,
    /// Local development
    Devnet,
}

impl Default for Network {
    fn default() -> Self {
        Self::Testnet
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Devnet => write!(f, "devnet"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Ok(Network::Mainnet),
            "testnet" | "test" => Ok(Network::Testnet),
            "devnet" | "dev" | "local" => Ok(Network::Devnet),
            _ => Err(format!("Unknown network: {}", s)),
        }
    }
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Network type (mainnet, testnet, devnet)
    pub network: Network,

    /// Data directory for blockchain state
    pub data_dir: PathBuf,

    /// P2P listen address
    pub p2p_addr: SocketAddr,

    /// RPC server address
    pub rpc_addr: SocketAddr,

    /// Bootstrap nodes for P2P discovery
    pub bootstrap_nodes: Vec<String>,

    /// Maximum peer connections
    pub max_peers: u32,

    /// Validator private key (hex encoded, if this node is a validator)
    pub validator_key: Option<String>,

    /// Coinbase address for block rewards (if validator)
    pub coinbase: Option<Address>,

    /// Enable RPC server
    pub rpc_enabled: bool,

    /// Enable metrics server
    pub metrics_enabled: bool,

    /// Metrics server address
    pub metrics_addr: SocketAddr,

    /// Log level
    pub log_level: String,

    /// Cache size in MB
    pub cache_size_mb: usize,

    /// Mempool size (max transactions)
    pub mempool_size: usize,

    /// Enable state pruning
    pub pruning_enabled: bool,

    /// Number of blocks to keep when pruning
    pub pruning_retention: u64,

    /// Sync mode (full, fast, light)
    pub sync_mode: SyncMode,

    /// Enable transaction indexing
    pub tx_index: bool,

    /// Block gas limit
    pub block_gas_limit: u64,

    /// Minimum gas price to accept transactions
    pub min_gas_price: u64,
}

/// Sync mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    /// Full sync - download and verify all blocks
    Full,
    /// Fast sync - download state at recent checkpoint
    Fast,
    /// Light client - only download headers
    Light,
}

impl Default for SyncMode {
    fn default() -> Self {
        Self::Full
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            data_dir: default_data_dir(),
            p2p_addr: "0.0.0.0:30303".parse().unwrap(),
            rpc_addr: "127.0.0.1:8545".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            validator_key: None,
            coinbase: None,
            rpc_enabled: true,
            metrics_enabled: false,
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            log_level: "info".into(),
            cache_size_mb: 512,
            mempool_size: 10_000,
            pruning_enabled: true,
            pruning_retention: 128,
            sync_mode: SyncMode::Full,
            tx_index: true,
            block_gas_limit: 30_000_000,
            min_gas_price: 1,
        }
    }
}

impl NodeConfig {
    /// Create testnet configuration
    pub fn testnet(data_dir: PathBuf) -> Self {
        Self {
            network: Network::Testnet,
            data_dir,
            bootstrap_nodes: vec![
                // Testnet bootstrap nodes (placeholder)
                // "enode://...@testnet1.chainmesh.io:30303".into(),
            ],
            ..Default::default()
        }
    }

    /// Create mainnet configuration
    pub fn mainnet(data_dir: PathBuf) -> Self {
        Self {
            network: Network::Mainnet,
            data_dir,
            cache_size_mb: 1024,
            mempool_size: 50_000,
            pruning_retention: 256,
            bootstrap_nodes: vec![
                // Mainnet bootstrap nodes (placeholder)
            ],
            ..Default::default()
        }
    }

    /// Create devnet configuration for local testing
    pub fn devnet(data_dir: PathBuf) -> Self {
        Self {
            network: Network::Devnet,
            data_dir,
            cache_size_mb: 128,
            mempool_size: 1_000,
            pruning_enabled: false,
            max_peers: 10,
            ..Default::default()
        }
    }

    /// Load configuration from file
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;

        let config: NodeConfig = if path.extension().map_or(false, |e| e == "json") {
            serde_json::from_str(&content)
                .map_err(|e| ConfigError::Parse(e.to_string()))?
        } else {
            // Assume TOML for other extensions
            return Err(ConfigError::Parse("Only JSON config files supported currently".into()));
        };

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;

        std::fs::write(path, content)
            .map_err(|e| ConfigError::Io(e.to_string()))?;

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate data directory
        if !self.data_dir.exists() {
            std::fs::create_dir_all(&self.data_dir)
                .map_err(|e| ConfigError::Io(format!("Failed to create data dir: {}", e)))?;
        }

        // Validate cache size
        if self.cache_size_mb < 16 {
            return Err(ConfigError::Invalid("Cache size must be at least 16 MB".into()));
        }

        // Validate mempool size
        if self.mempool_size < 100 {
            return Err(ConfigError::Invalid("Mempool size must be at least 100".into()));
        }

        // Validate max peers
        if self.max_peers < 1 {
            return Err(ConfigError::Invalid("Max peers must be at least 1".into()));
        }

        // Validate validator key if provided
        if let Some(ref key) = self.validator_key {
            if hex::decode(key).is_err() || key.len() != 64 {
                return Err(ConfigError::Invalid("Invalid validator key format (expected 32 bytes hex)".into()));
            }
        }

        Ok(())
    }

    /// Get chain configuration based on network
    pub fn chain_config(&self) -> ChainConfig {
        match self.network {
            Network::Mainnet => ChainConfig::mainnet(),
            Network::Testnet => ChainConfig::testnet(),
            Network::Devnet => ChainConfig {
                chain_id: 1337,
                block_time: 2, // Faster blocks for dev
                epoch_length: 8,
                ..ChainConfig::testnet()
            },
        }
    }

    /// Get P2P configuration
    pub fn network_config(&self) -> crate::p2p::NetworkConfig {
        let mut config = match self.network {
            Network::Mainnet => crate::p2p::NetworkConfig::mainnet(),
            Network::Testnet => crate::p2p::NetworkConfig::testnet(),
            Network::Devnet => crate::p2p::NetworkConfig::default(),
        };
        config.listen_addr = self.p2p_addr;
        config.target_peers = self.max_peers as usize;
        config
    }

    /// Check if this node is configured as a validator
    pub fn is_validator(&self) -> bool {
        self.validator_key.is_some()
    }

    /// Get validator private key bytes
    pub fn validator_key_bytes(&self) -> Option<[u8; 32]> {
        self.validator_key.as_ref().and_then(|k| {
            let bytes = hex::decode(k).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        })
    }
}

/// Configuration errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Get default data directory
fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("chainmesh"))
        .unwrap_or_else(|| PathBuf::from(".chainmesh"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.network, Network::Testnet);
        assert!(config.rpc_enabled);
        assert_eq!(config.cache_size_mb, 512);
    }

    #[test]
    fn test_testnet_config() {
        let tmp = tempdir().unwrap();
        let config = NodeConfig::testnet(tmp.path().to_path_buf());
        assert_eq!(config.network, Network::Testnet);
    }

    #[test]
    fn test_devnet_config() {
        let tmp = tempdir().unwrap();
        let config = NodeConfig::devnet(tmp.path().to_path_buf());
        assert_eq!(config.network, Network::Devnet);
        assert!(!config.pruning_enabled);
    }

    #[test]
    fn test_network_parse() {
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("devnet".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("dev".parse::<Network>().unwrap(), Network::Devnet);
    }

    #[test]
    fn test_config_validation() {
        let tmp = tempdir().unwrap();
        let mut config = NodeConfig::testnet(tmp.path().to_path_buf());
        assert!(config.validate().is_ok());

        config.cache_size_mb = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chain_config() {
        let tmp = tempdir().unwrap();

        let testnet = NodeConfig::testnet(tmp.path().to_path_buf());
        assert_eq!(testnet.chain_config().chain_id, 137);

        let devnet = NodeConfig::devnet(tmp.path().to_path_buf());
        assert_eq!(devnet.chain_config().chain_id, 1337);
    }

    #[test]
    fn test_save_load_config() {
        let tmp = tempdir().unwrap();
        let config_path = tmp.path().join("config.json");

        let config = NodeConfig::testnet(tmp.path().to_path_buf());
        config.save(&config_path).unwrap();

        let loaded = NodeConfig::load(&config_path).unwrap();
        assert_eq!(loaded.network, config.network);
        assert_eq!(loaded.cache_size_mb, config.cache_size_mb);
    }

    #[test]
    fn test_validator_key() {
        let tmp = tempdir().unwrap();
        let mut config = NodeConfig::testnet(tmp.path().to_path_buf());

        assert!(!config.is_validator());
        assert!(config.validator_key_bytes().is_none());

        // Valid 32-byte hex key
        config.validator_key = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into());
        assert!(config.is_validator());
        assert!(config.validator_key_bytes().is_some());
        assert!(config.validate().is_ok());

        // Invalid key
        config.validator_key = Some("invalid".into());
        assert!(config.validate().is_err());
    }
}
