//! State Cache
//!
//! LRU-based caching layer for state access optimization.
//! Supports multiple cache levels and warm/hot data separation.

use super::{StorageResult, StorageError};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum entries in account cache
    pub account_cache_size: usize,
    /// Maximum entries in storage cache
    pub storage_cache_size: usize,
    /// Maximum entries in code cache
    pub code_cache_size: usize,
    /// Maximum entries in trie node cache
    pub trie_cache_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            account_cache_size: 10_000,
            storage_cache_size: 100_000,
            code_cache_size: 1_000,
            trie_cache_size: 50_000,
        }
    }
}

impl CacheConfig {
    /// Minimal cache for testing
    pub fn minimal() -> Self {
        Self {
            account_cache_size: 100,
            storage_cache_size: 1000,
            code_cache_size: 50,
            trie_cache_size: 500,
        }
    }

    /// Large cache for high-performance nodes
    pub fn large() -> Self {
        Self {
            account_cache_size: 100_000,
            storage_cache_size: 1_000_000,
            code_cache_size: 10_000,
            trie_cache_size: 500_000,
        }
    }
}

/// LRU cache entry
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    /// Access counter for LRU
    access_count: u64,
}

/// Simple LRU cache implementation
pub struct LruCache<K, V> {
    /// Maximum entries
    capacity: usize,
    /// Stored entries
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    /// Global access counter
    access_counter: RwLock<u64>,
    /// Statistics
    stats: RwLock<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Evictions
    pub evictions: u64,
    /// Current size
    pub size: usize,
}

impl CacheStats {
    /// Calculate hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> LruCache<K, V> {
    /// Create new cache with capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: RwLock::new(HashMap::with_capacity(capacity)),
            access_counter: RwLock::new(0),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Get value from cache
    pub fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();

        if let Some(entry) = entries.get_mut(key) {
            let mut counter = self.access_counter.write().unwrap();
            *counter += 1;
            entry.access_count = *counter;

            let mut stats = self.stats.write().unwrap();
            stats.hits += 1;

            Some(entry.value.clone())
        } else {
            let mut stats = self.stats.write().unwrap();
            stats.misses += 1;
            None
        }
    }

    /// Put value into cache
    pub fn put(&self, key: K, value: V) {
        let mut entries = self.entries.write().unwrap();

        // Evict if at capacity and key doesn't exist
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            self.evict_lru(&mut entries);
        }

        let mut counter = self.access_counter.write().unwrap();
        *counter += 1;

        entries.insert(key, CacheEntry {
            value,
            access_count: *counter,
        });

        let mut stats = self.stats.write().unwrap();
        stats.size = entries.len();
    }

    /// Remove value from cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();
        let removed = entries.remove(key).map(|e| e.value);

        let mut stats = self.stats.write().unwrap();
        stats.size = entries.len();

        removed
    }

    /// Check if key exists
    pub fn contains(&self, key: &K) -> bool {
        self.entries.read().unwrap().contains_key(key)
    }

    /// Get current size
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();

        let mut stats = self.stats.write().unwrap();
        stats.size = 0;
    }

    /// Get statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Evict least recently used entry
    fn evict_lru(&self, entries: &mut HashMap<K, CacheEntry<V>>) {
        if entries.is_empty() {
            return;
        }

        // Find entry with lowest access count
        let lru_key = entries
            .iter()
            .min_by_key(|(_, v)| v.access_count)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            entries.remove(&key);

            let mut stats = self.stats.write().unwrap();
            stats.evictions += 1;
        }
    }
}

/// Combined state cache
pub struct StateCache {
    /// Account state cache
    accounts: LruCache<[u8; 20], Vec<u8>>,
    /// Contract storage cache: (address, slot) -> value
    storage: LruCache<([u8; 20], [u8; 32]), [u8; 32]>,
    /// Contract code cache: code_hash -> code
    code: LruCache<[u8; 32], Vec<u8>>,
    /// Trie node cache: node_hash -> node
    trie_nodes: LruCache<[u8; 32], Vec<u8>>,
}

impl StateCache {
    /// Create new state cache with config
    pub fn new(config: CacheConfig) -> Self {
        Self {
            accounts: LruCache::new(config.account_cache_size),
            storage: LruCache::new(config.storage_cache_size),
            code: LruCache::new(config.code_cache_size),
            trie_nodes: LruCache::new(config.trie_cache_size),
        }
    }

    /// Get account from cache
    pub fn get_account(&self, address: &[u8; 20]) -> Option<Vec<u8>> {
        self.accounts.get(address)
    }

    /// Put account in cache
    pub fn put_account(&self, address: [u8; 20], data: Vec<u8>) {
        self.accounts.put(address, data);
    }

    /// Remove account from cache
    pub fn remove_account(&self, address: &[u8; 20]) {
        self.accounts.remove(address);
    }

    /// Get storage value from cache
    pub fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> Option<[u8; 32]> {
        self.storage.get(&(*address, *slot))
    }

    /// Put storage value in cache
    pub fn put_storage(&self, address: [u8; 20], slot: [u8; 32], value: [u8; 32]) {
        self.storage.put((address, slot), value);
    }

    /// Remove storage from cache
    pub fn remove_storage(&self, address: &[u8; 20], slot: &[u8; 32]) {
        self.storage.remove(&(*address, *slot));
    }

    /// Get code from cache
    pub fn get_code(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.code.get(hash)
    }

    /// Put code in cache
    pub fn put_code(&self, hash: [u8; 32], code: Vec<u8>) {
        self.code.put(hash, code);
    }

    /// Get trie node from cache
    pub fn get_trie_node(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.trie_nodes.get(hash)
    }

    /// Put trie node in cache
    pub fn put_trie_node(&self, hash: [u8; 32], node: Vec<u8>) {
        self.trie_nodes.put(hash, node);
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.accounts.clear();
        self.storage.clear();
        self.code.clear();
        self.trie_nodes.clear();
    }

    /// Get combined statistics
    pub fn stats(&self) -> StateCacheStats {
        StateCacheStats {
            accounts: self.accounts.stats(),
            storage: self.storage.stats(),
            code: self.code.stats(),
            trie_nodes: self.trie_nodes.stats(),
        }
    }
}

/// Combined cache statistics
#[derive(Debug, Clone)]
pub struct StateCacheStats {
    pub accounts: CacheStats,
    pub storage: CacheStats,
    pub code: CacheStats,
    pub trie_nodes: CacheStats,
}

impl StateCacheStats {
    /// Total hits across all caches
    pub fn total_hits(&self) -> u64 {
        self.accounts.hits + self.storage.hits + self.code.hits + self.trie_nodes.hits
    }

    /// Total misses across all caches
    pub fn total_misses(&self) -> u64 {
        self.accounts.misses + self.storage.misses + self.code.misses + self.trie_nodes.misses
    }

    /// Overall hit ratio
    pub fn overall_hit_ratio(&self) -> f64 {
        let total = self.total_hits() + self.total_misses();
        if total == 0 {
            0.0
        } else {
            self.total_hits() as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_cache_basic() {
        let cache: LruCache<u32, String> = LruCache::new(3);

        cache.put(1, "one".into());
        cache.put(2, "two".into());
        cache.put(3, "three".into());

        assert_eq!(cache.get(&1), Some("one".into()));
        assert_eq!(cache.get(&2), Some("two".into()));
        assert_eq!(cache.get(&3), Some("three".into()));
        assert_eq!(cache.get(&4), None);
    }

    #[test]
    fn test_lru_eviction() {
        let cache: LruCache<u32, String> = LruCache::new(2);

        cache.put(1, "one".into());
        cache.put(2, "two".into());

        // Access 1 to make it more recent
        cache.get(&1);

        // Add 3, should evict 2 (least recently used)
        cache.put(3, "three".into());

        assert_eq!(cache.get(&1), Some("one".into()));
        assert_eq!(cache.get(&2), None); // Evicted
        assert_eq!(cache.get(&3), Some("three".into()));
    }

    #[test]
    fn test_lru_update() {
        let cache: LruCache<u32, String> = LruCache::new(2);

        cache.put(1, "one".into());
        cache.put(1, "ONE".into()); // Update

        assert_eq!(cache.get(&1), Some("ONE".into()));
        assert_eq!(cache.len(), 1); // No duplicate
    }

    #[test]
    fn test_cache_stats() {
        let cache: LruCache<u32, String> = LruCache::new(10);

        cache.put(1, "one".into());
        cache.get(&1); // Hit
        cache.get(&2); // Miss
        cache.get(&3); // Miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert!((stats.hit_ratio() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_state_cache() {
        let cache = StateCache::new(CacheConfig::minimal());

        // Test account cache
        let addr = [1u8; 20];
        cache.put_account(addr, b"account_data".to_vec());
        assert_eq!(cache.get_account(&addr), Some(b"account_data".to_vec()));

        // Test storage cache
        let slot = [2u8; 32];
        let value = [3u8; 32];
        cache.put_storage(addr, slot, value);
        assert_eq!(cache.get_storage(&addr, &slot), Some(value));

        // Test code cache
        let hash = [4u8; 32];
        cache.put_code(hash, b"code".to_vec());
        assert_eq!(cache.get_code(&hash), Some(b"code".to_vec()));
    }

    #[test]
    fn test_cache_clear() {
        let cache = StateCache::new(CacheConfig::minimal());

        cache.put_account([1u8; 20], b"data".to_vec());
        cache.put_code([2u8; 32], b"code".to_vec());

        cache.clear();

        assert_eq!(cache.get_account(&[1u8; 20]), None);
        assert_eq!(cache.get_code(&[2u8; 32]), None);
    }

    #[test]
    fn test_remove() {
        let cache: LruCache<u32, String> = LruCache::new(10);

        cache.put(1, "one".into());
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&1);
        assert_eq!(removed, Some("one".into()));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get(&1), None);
    }
}
