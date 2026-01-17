//! State Snapshots
//!
//! Snapshot management for fast sync and state pruning.
//! Supports periodic snapshots and incremental state reconstruction.

use super::{KeyValueStore, StateRoot, StorageError, StorageResult, KeyPrefix, WriteBatch, EMPTY_ROOT};
use crate::types::BlockHash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Snapshot configuration
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Interval between snapshots (in blocks)
    pub snapshot_interval: u64,
    /// Maximum snapshots to keep
    pub max_snapshots: usize,
    /// Enable automatic pruning
    pub auto_prune: bool,
    /// Compression enabled
    pub compression: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: 1024,
            max_snapshots: 16,
            auto_prune: true,
            compression: true,
        }
    }
}

impl SnapshotConfig {
    /// Archive config (no pruning)
    pub fn archive() -> Self {
        Self {
            snapshot_interval: 4096,
            max_snapshots: 0, // Keep all
            auto_prune: false,
            compression: true,
        }
    }

    /// Fast sync config
    pub fn fast_sync() -> Self {
        Self {
            snapshot_interval: 256,
            max_snapshots: 64,
            auto_prune: true,
            compression: true,
        }
    }
}

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Snapshot ID
    pub id: u64,
    /// Block height at snapshot
    pub block_height: u64,
    /// Block hash at snapshot
    pub block_hash: BlockHash,
    /// State root at snapshot
    pub state_root: StateRoot,
    /// Timestamp
    pub timestamp: u64,
    /// Number of accounts
    pub account_count: u64,
    /// Approximate size in bytes
    pub size_bytes: u64,
    /// Checksum for verification
    pub checksum: [u8; 32],
}

/// A state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Metadata
    pub metadata: SnapshotMetadata,
    /// Account states (address -> encoded account)
    pub accounts: BTreeMap<[u8; 20], Vec<u8>>,
    /// Storage states (address || slot -> value)
    pub storage: BTreeMap<Vec<u8>, [u8; 32]>,
    /// Contract codes (code_hash -> code)
    pub codes: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Snapshot {
    /// Create new empty snapshot
    pub fn new(block_height: u64, block_hash: BlockHash, state_root: StateRoot) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            metadata: SnapshotMetadata {
                id: block_height, // Use height as ID
                block_height,
                block_hash,
                state_root,
                timestamp,
                account_count: 0,
                size_bytes: 0,
                checksum: [0u8; 32],
            },
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            codes: BTreeMap::new(),
        }
    }

    /// Add account to snapshot
    pub fn add_account(&mut self, address: [u8; 20], data: Vec<u8>) {
        self.metadata.size_bytes += (20 + data.len()) as u64;
        self.metadata.account_count += 1;
        self.accounts.insert(address, data);
    }

    /// Add storage to snapshot
    pub fn add_storage(&mut self, address: [u8; 20], slot: [u8; 32], value: [u8; 32]) {
        let mut key = Vec::with_capacity(52);
        key.extend_from_slice(&address);
        key.extend_from_slice(&slot);
        self.metadata.size_bytes += 84; // key + value
        self.storage.insert(key, value);
    }

    /// Add code to snapshot
    pub fn add_code(&mut self, hash: [u8; 32], code: Vec<u8>) {
        self.metadata.size_bytes += (32 + code.len()) as u64;
        self.codes.insert(hash, code);
    }

    /// Compute checksum
    pub fn compute_checksum(&mut self) {
        use libmu_crypto::MuHash;

        let mut hasher = MuHash::new();

        // Hash metadata
        hasher.update(&self.metadata.block_height.to_le_bytes());
        hasher.update(&self.metadata.block_hash.0);
        hasher.update(&self.metadata.state_root);

        // Hash accounts (sorted by key)
        for (addr, data) in &self.accounts {
            hasher.update(addr);
            hasher.update(data);
        }

        // Hash storage (sorted by key)
        for (key, value) in &self.storage {
            hasher.update(key);
            hasher.update(value);
        }

        // Hash codes (sorted by hash)
        for (hash, code) in &self.codes {
            hasher.update(hash);
            hasher.update(code);
        }

        self.metadata.checksum = hasher.finalize();
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let mut copy = self.clone();
        copy.compute_checksum();
        copy.metadata.checksum == self.metadata.checksum
    }

    /// Serialize snapshot
    pub fn encode(&self) -> StorageResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| StorageError::SerializationError(e.to_string()))
    }

    /// Deserialize snapshot
    pub fn decode(data: &[u8]) -> StorageResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| StorageError::SerializationError(e.to_string()))
    }
}

/// Snapshot manager
pub struct SnapshotManager<S: KeyValueStore> {
    /// Underlying storage
    store: Arc<S>,
    /// Configuration
    config: SnapshotConfig,
    /// Cached snapshot metadata
    snapshots: RwLock<BTreeMap<u64, SnapshotMetadata>>,
    /// Next snapshot ID
    next_id: RwLock<u64>,
}

impl<S: KeyValueStore> SnapshotManager<S> {
    /// Create new snapshot manager
    pub fn new(store: Arc<S>, config: SnapshotConfig) -> Self {
        Self {
            store,
            config,
            snapshots: RwLock::new(BTreeMap::new()),
            next_id: RwLock::new(0),
        }
    }

    /// Initialize from existing snapshots
    pub fn initialize(&self) -> StorageResult<()> {
        // Load snapshot metadata from storage
        let prefix = KeyPrefix::Snapshot.key(&[]);
        let mut snapshots = self.snapshots.write().unwrap();
        let mut max_id = 0u64;

        for (key, value) in self.store.iter_prefix(&prefix)? {
            if key.len() > 1 {
                let metadata: SnapshotMetadata = bincode::deserialize(&value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                max_id = max_id.max(metadata.id);
                snapshots.insert(metadata.id, metadata);
            }
        }

        *self.next_id.write().unwrap() = max_id + 1;
        Ok(())
    }

    /// Check if snapshot should be created at this height
    pub fn should_snapshot(&self, block_height: u64) -> bool {
        block_height > 0 && block_height % self.config.snapshot_interval == 0
    }

    /// Create a new snapshot
    pub fn create_snapshot(&self, snapshot: Snapshot) -> StorageResult<u64> {
        let mut snapshot = snapshot;
        let id = *self.next_id.read().unwrap();
        snapshot.metadata.id = id;
        snapshot.compute_checksum();

        // Store snapshot data
        let key = self.snapshot_key(id);
        let data = snapshot.encode()?;
        self.store.put(&key, &data)?;

        // Store metadata separately for quick listing
        let meta_key = self.metadata_key(id);
        let meta_data = bincode::serialize(&snapshot.metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.store.put(&meta_key, &meta_data)?;

        // Update cache
        self.snapshots.write().unwrap().insert(id, snapshot.metadata);
        *self.next_id.write().unwrap() = id + 1;

        // Auto-prune if enabled
        if self.config.auto_prune {
            self.prune_old_snapshots()?;
        }

        Ok(id)
    }

    /// Get snapshot by ID
    pub fn get_snapshot(&self, id: u64) -> StorageResult<Option<Snapshot>> {
        let key = self.snapshot_key(id);
        match self.store.get(&key)? {
            Some(data) => Ok(Some(Snapshot::decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Get snapshot metadata by ID
    pub fn get_metadata(&self, id: u64) -> Option<SnapshotMetadata> {
        self.snapshots.read().unwrap().get(&id).cloned()
    }

    /// List all snapshot metadata
    pub fn list_snapshots(&self) -> Vec<SnapshotMetadata> {
        self.snapshots.read().unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Get latest snapshot
    pub fn latest_snapshot(&self) -> Option<SnapshotMetadata> {
        self.snapshots.read().unwrap()
            .values()
            .last()
            .cloned()
    }

    /// Get nearest snapshot at or before given height
    pub fn nearest_snapshot(&self, height: u64) -> Option<SnapshotMetadata> {
        self.snapshots.read().unwrap()
            .values()
            .filter(|s| s.block_height <= height)
            .max_by_key(|s| s.block_height)
            .cloned()
    }

    /// Delete snapshot
    pub fn delete_snapshot(&self, id: u64) -> StorageResult<bool> {
        let key = self.snapshot_key(id);
        let meta_key = self.metadata_key(id);

        let existed = self.store.exists(&key)?;
        if existed {
            let mut batch = WriteBatch::new();
            batch.delete(key);
            batch.delete(meta_key);
            self.store.write_batch(batch)?;
            self.snapshots.write().unwrap().remove(&id);
        }

        Ok(existed)
    }

    /// Prune old snapshots keeping only max_snapshots
    pub fn prune_old_snapshots(&self) -> StorageResult<usize> {
        if self.config.max_snapshots == 0 {
            return Ok(0); // Keep all
        }

        let snapshots: Vec<_> = self.snapshots.read().unwrap()
            .keys()
            .cloned()
            .collect();

        if snapshots.len() <= self.config.max_snapshots {
            return Ok(0);
        }

        let to_delete = snapshots.len() - self.config.max_snapshots;
        let mut deleted = 0;

        for id in snapshots.into_iter().take(to_delete) {
            if self.delete_snapshot(id)? {
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Export snapshot to bytes (for network transfer)
    pub fn export_snapshot(&self, id: u64) -> StorageResult<Option<Vec<u8>>> {
        match self.get_snapshot(id)? {
            Some(snapshot) => {
                let data = snapshot.encode()?;
                // Optionally compress
                if self.config.compression {
                    // For now, return uncompressed (would use zstd/lz4 in production)
                    Ok(Some(data))
                } else {
                    Ok(Some(data))
                }
            }
            None => Ok(None),
        }
    }

    /// Import snapshot from bytes
    pub fn import_snapshot(&self, data: &[u8]) -> StorageResult<u64> {
        // Optionally decompress
        let snapshot = Snapshot::decode(data)?;

        // Verify checksum
        if !snapshot.verify_checksum() {
            return Err(StorageError::SnapshotError("Checksum verification failed".into()));
        }

        self.create_snapshot(snapshot)
    }

    /// Snapshot key
    fn snapshot_key(&self, id: u64) -> Vec<u8> {
        KeyPrefix::Snapshot.key(&id.to_be_bytes())
    }

    /// Metadata key
    fn metadata_key(&self, id: u64) -> Vec<u8> {
        let mut suffix = b"meta:".to_vec();
        suffix.extend_from_slice(&id.to_be_bytes());
        KeyPrefix::Snapshot.key(&suffix)
    }
}

/// Pruning manager for state history
pub struct PruningManager<S: KeyValueStore> {
    /// Underlying storage
    store: Arc<S>,
    /// Blocks to retain
    retention_blocks: u64,
    /// Last pruned block
    last_pruned: RwLock<u64>,
}

impl<S: KeyValueStore> PruningManager<S> {
    /// Create new pruning manager
    pub fn new(store: Arc<S>, retention_blocks: u64) -> Self {
        Self {
            store,
            retention_blocks,
            last_pruned: RwLock::new(0),
        }
    }

    /// Prune state older than given block
    pub fn prune_before(&self, block_height: u64) -> StorageResult<PruneStats> {
        let cutoff = block_height.saturating_sub(self.retention_blocks);
        let last = *self.last_pruned.read().unwrap();

        if cutoff <= last {
            return Ok(PruneStats::default());
        }

        let mut stats = PruneStats::default();

        // Mark blocks for pruning
        for height in (last + 1)..=cutoff {
            let marker_key = KeyPrefix::PruneMarker.key(&height.to_be_bytes());
            self.store.put(&marker_key, &[1])?;
            stats.blocks_pruned += 1;
        }

        *self.last_pruned.write().unwrap() = cutoff;
        Ok(stats)
    }

    /// Get pruning status
    pub fn status(&self) -> PruneStatus {
        PruneStatus {
            last_pruned_block: *self.last_pruned.read().unwrap(),
            retention_blocks: self.retention_blocks,
        }
    }
}

/// Pruning statistics
#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    /// Blocks pruned
    pub blocks_pruned: u64,
    /// Accounts removed
    pub accounts_removed: u64,
    /// Storage slots removed
    pub storage_removed: u64,
    /// Bytes freed
    pub bytes_freed: u64,
}

/// Pruning status
#[derive(Debug, Clone)]
pub struct PruneStatus {
    /// Last pruned block height
    pub last_pruned_block: u64,
    /// Blocks being retained
    pub retention_blocks: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryKV;

    fn create_test_manager() -> SnapshotManager<MemoryKV> {
        let store = Arc::new(MemoryKV::new());
        SnapshotManager::new(store, SnapshotConfig::default())
    }

    #[test]
    fn test_snapshot_creation() {
        let manager = create_test_manager();

        let mut snapshot = Snapshot::new(
            1024,
            BlockHash([1u8; 32]),
            [2u8; 32],
        );

        snapshot.add_account([1u8; 20], b"account_data".to_vec());
        snapshot.add_storage([1u8; 20], [2u8; 32], [3u8; 32]);
        snapshot.add_code([4u8; 32], b"code".to_vec());

        let id = manager.create_snapshot(snapshot).unwrap();
        assert_eq!(id, 0);

        let loaded = manager.get_snapshot(id).unwrap().unwrap();
        assert_eq!(loaded.metadata.block_height, 1024);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.storage.len(), 1);
        assert_eq!(loaded.codes.len(), 1);
    }

    #[test]
    fn test_snapshot_checksum() {
        let mut snapshot = Snapshot::new(
            100,
            BlockHash([1u8; 32]),
            [2u8; 32],
        );

        snapshot.add_account([1u8; 20], b"data".to_vec());
        snapshot.compute_checksum();

        assert!(snapshot.verify_checksum());

        // Tamper with data
        snapshot.accounts.insert([2u8; 20], b"tampered".to_vec());
        assert!(!snapshot.verify_checksum());
    }

    #[test]
    fn test_should_snapshot() {
        let manager = create_test_manager();

        // Default interval is 1024
        assert!(!manager.should_snapshot(0));
        assert!(!manager.should_snapshot(1));
        assert!(!manager.should_snapshot(1023));
        assert!(manager.should_snapshot(1024));
        assert!(!manager.should_snapshot(1025));
        assert!(manager.should_snapshot(2048));
    }

    #[test]
    fn test_list_snapshots() {
        let manager = create_test_manager();

        for i in 0..5 {
            let snapshot = Snapshot::new(
                i * 1024,
                BlockHash([i as u8; 32]),
                [i as u8; 32],
            );
            manager.create_snapshot(snapshot).unwrap();
        }

        let list = manager.list_snapshots();
        assert_eq!(list.len(), 5);
    }

    #[test]
    fn test_nearest_snapshot() {
        let manager = create_test_manager();

        for i in 1..=3 {
            let snapshot = Snapshot::new(
                i * 1000,
                BlockHash([i as u8; 32]),
                [i as u8; 32],
            );
            manager.create_snapshot(snapshot).unwrap();
        }

        let nearest = manager.nearest_snapshot(2500).unwrap();
        assert_eq!(nearest.block_height, 2000);

        let nearest = manager.nearest_snapshot(1000).unwrap();
        assert_eq!(nearest.block_height, 1000);

        assert!(manager.nearest_snapshot(500).is_none());
    }

    #[test]
    fn test_auto_prune() {
        let config = SnapshotConfig {
            max_snapshots: 3,
            auto_prune: true,
            ..Default::default()
        };
        let store = Arc::new(MemoryKV::new());
        let manager = SnapshotManager::new(store, config);

        for i in 0..5 {
            let snapshot = Snapshot::new(
                i * 1024,
                BlockHash([i as u8; 32]),
                [i as u8; 32],
            );
            manager.create_snapshot(snapshot).unwrap();
        }

        // Should only have 3 snapshots after auto-prune
        assert_eq!(manager.list_snapshots().len(), 3);
    }

    #[test]
    fn test_export_import() {
        let manager = create_test_manager();

        let mut snapshot = Snapshot::new(
            100,
            BlockHash([1u8; 32]),
            [2u8; 32],
        );
        snapshot.add_account([1u8; 20], b"data".to_vec());

        let id = manager.create_snapshot(snapshot).unwrap();
        let exported = manager.export_snapshot(id).unwrap().unwrap();

        // Import into new manager
        let manager2 = create_test_manager();
        let id2 = manager2.import_snapshot(&exported).unwrap();

        let imported = manager2.get_snapshot(id2).unwrap().unwrap();
        assert_eq!(imported.metadata.block_height, 100);
        assert_eq!(imported.accounts.len(), 1);
    }

    #[test]
    fn test_snapshot_encode_decode() {
        let mut snapshot = Snapshot::new(
            100,
            BlockHash([1u8; 32]),
            [2u8; 32],
        );
        snapshot.add_account([1u8; 20], b"test".to_vec());
        snapshot.compute_checksum();

        let encoded = snapshot.encode().unwrap();
        let decoded = Snapshot::decode(&encoded).unwrap();

        assert_eq!(snapshot.metadata.block_height, decoded.metadata.block_height);
        assert_eq!(snapshot.metadata.checksum, decoded.metadata.checksum);
    }
}
