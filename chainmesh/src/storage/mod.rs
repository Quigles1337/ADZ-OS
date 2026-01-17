//! State Storage for ChainMesh
//!
//! Institutional-grade state management with:
//! - Merkle Patricia Trie for authenticated state
//! - Efficient key-value storage backend
//! - State snapshots for fast sync
//! - LRU caching for performance
//! - Pruning for disk efficiency

pub mod kv;
pub mod trie;
pub mod state;
pub mod cache;
pub mod snapshot;

use crate::types::{Address, BlockHash};
use std::sync::Arc;

// Re-exports
pub use kv::{KeyValueStore, MemoryKV, BatchWrite, WriteBatch};
pub use trie::{MerkleTrie, TrieNode, TrieProof, StateRoot};
pub use state::{StateDB, AccountState, StorageValue};
pub use cache::{StateCache, CacheConfig};
pub use snapshot::{Snapshot, SnapshotConfig, SnapshotManager};

/// Empty trie root hash (Keccak-256 of empty trie)
/// Used as sentinel value for empty/non-existent state
pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to database directory
    pub db_path: String,
    /// Cache size in MB
    pub cache_size_mb: usize,
    /// Enable write-ahead log
    pub enable_wal: bool,
    /// Compression enabled
    pub compression: bool,
    /// Maximum open files
    pub max_open_files: i32,
    /// Block cache size
    pub block_cache_size: usize,
    /// Write buffer size
    pub write_buffer_size: usize,
    /// Number of write buffers
    pub max_write_buffer_number: i32,
    /// Enable bloom filters
    pub bloom_filter_bits: i32,
    /// State pruning enabled
    pub pruning_enabled: bool,
    /// Blocks to keep for pruning
    pub pruning_retention: u64,
    /// Snapshot interval (blocks)
    pub snapshot_interval: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: "chainmesh_data".into(),
            cache_size_mb: 512,
            enable_wal: true,
            compression: true,
            max_open_files: 1000,
            block_cache_size: 128 * 1024 * 1024, // 128 MB
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            max_write_buffer_number: 3,
            bloom_filter_bits: 10,
            pruning_enabled: true,
            pruning_retention: 128, // Keep last 128 blocks
            snapshot_interval: 1024, // Snapshot every 1024 blocks
        }
    }
}

impl StorageConfig {
    /// Configuration for testing
    pub fn test() -> Self {
        Self {
            db_path: ":memory:".into(),
            cache_size_mb: 16,
            enable_wal: false,
            compression: false,
            max_open_files: 100,
            block_cache_size: 8 * 1024 * 1024,
            write_buffer_size: 4 * 1024 * 1024,
            max_write_buffer_number: 2,
            bloom_filter_bits: 10,
            pruning_enabled: false,
            pruning_retention: 0,
            snapshot_interval: 100,
        }
    }

    /// Configuration for archive node (no pruning)
    pub fn archive() -> Self {
        Self {
            pruning_enabled: false,
            pruning_retention: 0,
            cache_size_mb: 1024,
            ..Default::default()
        }
    }
}

/// Storage result type
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid state root: expected {expected}, got {actual}")]
    InvalidStateRoot {
        expected: String,
        actual: String,
    },

    #[error("Trie error: {0}")]
    TrieError(String),

    #[error("Snapshot error: {0}")]
    SnapshotError(String),

    #[error("Pruning error: {0}")]
    PruningError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Corruption detected: {0}")]
    Corruption(String),

    #[error("IO error: {0}")]
    IoError(String),
}

/// Database key prefixes for different data types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPrefix {
    /// Account state
    Account = 0x01,
    /// Contract storage
    ContractStorage = 0x02,
    /// Contract code
    ContractCode = 0x03,
    /// Block headers
    BlockHeader = 0x10,
    /// Block bodies
    BlockBody = 0x11,
    /// Transaction receipts
    Receipt = 0x12,
    /// Transaction index
    TxIndex = 0x13,
    /// Trie nodes
    TrieNode = 0x20,
    /// State root mapping
    StateRoot = 0x21,
    /// Snapshot metadata
    Snapshot = 0x30,
    /// Pruning markers
    PruneMarker = 0x40,
}

impl KeyPrefix {
    /// Create a prefixed key
    pub fn key(&self, suffix: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + suffix.len());
        key.push(*self as u8);
        key.extend_from_slice(suffix);
        key
    }

    /// Create account key
    pub fn account_key(address: &Address) -> Vec<u8> {
        Self::Account.key(&address.bytes)
    }

    /// Create contract storage key
    pub fn storage_key(address: &Address, slot: &[u8; 32]) -> Vec<u8> {
        let mut suffix = Vec::with_capacity(20 + 32);
        suffix.extend_from_slice(&address.bytes);
        suffix.extend_from_slice(slot);
        Self::ContractStorage.key(&suffix)
    }

    /// Create contract code key
    pub fn code_key(code_hash: &[u8; 32]) -> Vec<u8> {
        Self::ContractCode.key(code_hash)
    }

    /// Create block header key
    pub fn header_key(hash: &BlockHash) -> Vec<u8> {
        Self::BlockHeader.key(&hash.0)
    }

    /// Create trie node key
    pub fn trie_key(node_hash: &[u8; 32]) -> Vec<u8> {
        Self::TrieNode.key(node_hash)
    }
}

/// Statistics about storage usage
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total keys stored
    pub total_keys: u64,
    /// Total bytes used
    pub total_bytes: u64,
    /// Account count
    pub account_count: u64,
    /// Contract count
    pub contract_count: u64,
    /// Trie node count
    pub trie_node_count: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Disk reads
    pub disk_reads: u64,
    /// Disk writes
    pub disk_writes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_prefix() {
        let addr = Address::zero();
        let key = KeyPrefix::account_key(&addr);
        assert_eq!(key[0], KeyPrefix::Account as u8);
        assert_eq!(&key[1..], &addr.bytes);
    }

    #[test]
    fn test_storage_key() {
        let addr = Address::zero();
        let slot = [1u8; 32];
        let key = KeyPrefix::storage_key(&addr, &slot);
        assert_eq!(key[0], KeyPrefix::ContractStorage as u8);
        assert_eq!(key.len(), 1 + 20 + 32);
    }

    #[test]
    fn test_default_config() {
        let config = StorageConfig::default();
        assert!(config.pruning_enabled);
        assert_eq!(config.cache_size_mb, 512);
    }

    #[test]
    fn test_archive_config() {
        let config = StorageConfig::archive();
        assert!(!config.pruning_enabled);
    }
}
