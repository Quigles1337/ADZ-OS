//! Key-Value Storage Backend
//!
//! Abstract interface for key-value storage with:
//! - In-memory implementation for testing
//! - Batch write support
//! - Iterator support
//! - Atomic operations

use super::{StorageError, StorageResult};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Key-value store trait
pub trait KeyValueStore: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>>;

    /// Put a key-value pair
    fn put(&self, key: &[u8], value: &[u8]) -> StorageResult<()>;

    /// Delete a key
    fn delete(&self, key: &[u8]) -> StorageResult<()>;

    /// Check if key exists
    fn exists(&self, key: &[u8]) -> StorageResult<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Get multiple keys
    fn multi_get(&self, keys: &[&[u8]]) -> StorageResult<Vec<Option<Vec<u8>>>> {
        keys.iter().map(|k| self.get(k)).collect()
    }

    /// Write a batch atomically
    fn write_batch(&self, batch: WriteBatch) -> StorageResult<()>;

    /// Create an iterator over a key range
    fn iter_range(&self, start: &[u8], end: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>>;

    /// Iterate with prefix
    fn iter_prefix(&self, prefix: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>>;

    /// Flush to disk
    fn flush(&self) -> StorageResult<()>;

    /// Get approximate size
    fn approximate_size(&self) -> StorageResult<u64>;
}

/// Batch write operations
#[derive(Debug, Clone)]
pub struct WriteBatch {
    /// Operations to perform
    pub operations: Vec<BatchOperation>,
}

/// Single batch operation
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Put a key-value pair
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Delete a key
    Delete { key: Vec<u8> },
}

impl WriteBatch {
    /// Create new empty batch
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Create batch with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            operations: Vec::with_capacity(capacity),
        }
    }

    /// Add put operation
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.operations.push(BatchOperation::Put { key, value });
    }

    /// Add delete operation
    pub fn delete(&mut self, key: Vec<u8>) {
        self.operations.push(BatchOperation::Delete { key });
    }

    /// Number of operations
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Clear all operations
    pub fn clear(&mut self) {
        self.operations.clear();
    }

    /// Approximate size in bytes
    pub fn approximate_size(&self) -> usize {
        self.operations.iter().map(|op| match op {
            BatchOperation::Put { key, value } => key.len() + value.len(),
            BatchOperation::Delete { key } => key.len(),
        }).sum()
    }
}

impl Default for WriteBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch write trait for convenience
pub trait BatchWrite {
    /// Put with batch
    fn batch_put(&mut self, key: &[u8], value: &[u8]);
    /// Delete with batch
    fn batch_delete(&mut self, key: &[u8]);
    /// Get underlying batch
    fn into_batch(self) -> WriteBatch;
}

impl BatchWrite for WriteBatch {
    fn batch_put(&mut self, key: &[u8], value: &[u8]) {
        self.put(key.to_vec(), value.to_vec());
    }

    fn batch_delete(&mut self, key: &[u8]) {
        self.delete(key.to_vec());
    }

    fn into_batch(self) -> WriteBatch {
        self
    }
}

/// In-memory key-value store for testing
#[derive(Debug)]
pub struct MemoryKV {
    data: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryKV {
    /// Create new in-memory store
    pub fn new() -> Self {
        Self {
            data: RwLock::new(BTreeMap::new()),
        }
    }

    /// Create from existing data
    pub fn from_data(data: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            data: RwLock::new(data),
        }
    }

    /// Get a snapshot of all data
    pub fn snapshot(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.data.read().unwrap().clone()
    }

    /// Number of keys
    pub fn len(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.read().unwrap().is_empty()
    }
}

impl Default for MemoryKV {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyValueStore for MemoryKV {
    fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let data = self.data.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        Ok(data.get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        data.remove(key);
        Ok(())
    }

    fn write_batch(&self, batch: WriteBatch) -> StorageResult<()> {
        let mut data = self.data.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        for op in batch.operations {
            match op {
                BatchOperation::Put { key, value } => {
                    data.insert(key, value);
                }
                BatchOperation::Delete { key } => {
                    data.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn iter_range(&self, start: &[u8], end: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        let data = self.data.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Collect to avoid lifetime issues
        let items: Vec<_> = data
            .range(start.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(Box::new(items.into_iter()))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        let data = self.data.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let prefix_vec = prefix.to_vec();
        let items: Vec<_> = data
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix_vec))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(Box::new(items.into_iter()))
    }

    fn flush(&self) -> StorageResult<()> {
        // No-op for in-memory
        Ok(())
    }

    fn approximate_size(&self) -> StorageResult<u64> {
        let data = self.data.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let size: usize = data.iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();

        Ok(size as u64)
    }
}

/// Thread-safe wrapper for any KV store
pub struct SharedKV<T: KeyValueStore> {
    inner: Arc<T>,
}

impl<T: KeyValueStore> SharedKV<T> {
    pub fn new(store: T) -> Self {
        Self {
            inner: Arc::new(store),
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: KeyValueStore> Clone for SharedKV<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: KeyValueStore> KeyValueStore for SharedKV<T> {
    fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        self.inner.put(key, value)
    }

    fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.inner.delete(key)
    }

    fn write_batch(&self, batch: WriteBatch) -> StorageResult<()> {
        self.inner.write_batch(batch)
    }

    fn iter_range(&self, start: &[u8], end: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        self.inner.iter_range(start, end)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        self.inner.iter_prefix(prefix)
    }

    fn flush(&self) -> StorageResult<()> {
        self.inner.flush()
    }

    fn approximate_size(&self) -> StorageResult<u64> {
        self.inner.approximate_size()
    }
}

/// Overlay store for transaction-style operations
pub struct OverlayKV<T: KeyValueStore> {
    /// Base store
    base: Arc<T>,
    /// Overlay modifications
    overlay: RwLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl<T: KeyValueStore> OverlayKV<T> {
    /// Create new overlay on top of base store
    pub fn new(base: Arc<T>) -> Self {
        Self {
            base,
            overlay: RwLock::new(BTreeMap::new()),
        }
    }

    /// Commit overlay to base store
    pub fn commit(&self) -> StorageResult<()> {
        let overlay = self.overlay.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut batch = WriteBatch::with_capacity(overlay.len());
        for (key, value) in overlay.iter() {
            match value {
                Some(v) => batch.put(key.clone(), v.clone()),
                None => batch.delete(key.clone()),
            }
        }

        self.base.write_batch(batch)
    }

    /// Discard overlay changes
    pub fn rollback(&self) -> StorageResult<()> {
        let mut overlay = self.overlay.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        overlay.clear();
        Ok(())
    }

    /// Get pending changes count
    pub fn pending_changes(&self) -> usize {
        self.overlay.read().map(|o| o.len()).unwrap_or(0)
    }
}

impl<T: KeyValueStore> KeyValueStore for OverlayKV<T> {
    fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let overlay = self.overlay.read()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Check overlay first
        if let Some(value) = overlay.get(key) {
            return Ok(value.clone());
        }

        // Fall back to base
        self.base.get(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let mut overlay = self.overlay.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        overlay.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let mut overlay = self.overlay.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        overlay.insert(key.to_vec(), None);
        Ok(())
    }

    fn write_batch(&self, batch: WriteBatch) -> StorageResult<()> {
        let mut overlay = self.overlay.write()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        for op in batch.operations {
            match op {
                BatchOperation::Put { key, value } => {
                    overlay.insert(key, Some(value));
                }
                BatchOperation::Delete { key } => {
                    overlay.insert(key, None);
                }
            }
        }
        Ok(())
    }

    fn iter_range(&self, start: &[u8], end: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        // For simplicity, just delegate to base (would need merge in production)
        self.base.iter_range(start, end)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> StorageResult<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>> {
        self.base.iter_prefix(prefix)
    }

    fn flush(&self) -> StorageResult<()> {
        self.commit()?;
        self.base.flush()
    }

    fn approximate_size(&self) -> StorageResult<u64> {
        self.base.approximate_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_kv_basic() {
        let kv = MemoryKV::new();

        // Put and get
        kv.put(b"key1", b"value1").unwrap();
        assert_eq!(kv.get(b"key1").unwrap(), Some(b"value1".to_vec()));

        // Overwrite
        kv.put(b"key1", b"value2").unwrap();
        assert_eq!(kv.get(b"key1").unwrap(), Some(b"value2".to_vec()));

        // Delete
        kv.delete(b"key1").unwrap();
        assert_eq!(kv.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_memory_kv_exists() {
        let kv = MemoryKV::new();

        assert!(!kv.exists(b"key1").unwrap());
        kv.put(b"key1", b"value1").unwrap();
        assert!(kv.exists(b"key1").unwrap());
    }

    #[test]
    fn test_write_batch() {
        let kv = MemoryKV::new();

        let mut batch = WriteBatch::new();
        batch.put(b"key1".to_vec(), b"value1".to_vec());
        batch.put(b"key2".to_vec(), b"value2".to_vec());
        batch.put(b"key3".to_vec(), b"value3".to_vec());

        kv.write_batch(batch).unwrap();

        assert_eq!(kv.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(kv.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(kv.get(b"key3").unwrap(), Some(b"value3".to_vec()));
    }

    #[test]
    fn test_write_batch_with_delete() {
        let kv = MemoryKV::new();
        kv.put(b"key1", b"value1").unwrap();

        let mut batch = WriteBatch::new();
        batch.delete(b"key1".to_vec());
        batch.put(b"key2".to_vec(), b"value2".to_vec());

        kv.write_batch(batch).unwrap();

        assert_eq!(kv.get(b"key1").unwrap(), None);
        assert_eq!(kv.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_iter_prefix() {
        let kv = MemoryKV::new();

        kv.put(b"prefix:key1", b"value1").unwrap();
        kv.put(b"prefix:key2", b"value2").unwrap();
        kv.put(b"other:key1", b"value3").unwrap();

        let items: Vec<_> = kv.iter_prefix(b"prefix:").unwrap().collect();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_overlay_kv() {
        let base = Arc::new(MemoryKV::new());
        base.put(b"key1", b"value1").unwrap();

        let overlay = OverlayKV::new(Arc::clone(&base));

        // Read from base
        assert_eq!(overlay.get(b"key1").unwrap(), Some(b"value1".to_vec()));

        // Write to overlay
        overlay.put(b"key1", b"modified").unwrap();
        overlay.put(b"key2", b"new").unwrap();

        // Overlay should have new value
        assert_eq!(overlay.get(b"key1").unwrap(), Some(b"modified".to_vec()));
        assert_eq!(overlay.get(b"key2").unwrap(), Some(b"new".to_vec()));

        // Base should be unchanged
        assert_eq!(base.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(base.get(b"key2").unwrap(), None);

        // Commit
        overlay.commit().unwrap();

        // Base should now have changes
        assert_eq!(base.get(b"key1").unwrap(), Some(b"modified".to_vec()));
        assert_eq!(base.get(b"key2").unwrap(), Some(b"new".to_vec()));
    }

    #[test]
    fn test_overlay_rollback() {
        let base = Arc::new(MemoryKV::new());
        base.put(b"key1", b"value1").unwrap();

        let overlay = OverlayKV::new(Arc::clone(&base));
        overlay.put(b"key1", b"modified").unwrap();

        assert_eq!(overlay.pending_changes(), 1);

        overlay.rollback().unwrap();

        assert_eq!(overlay.pending_changes(), 0);
        // After rollback, reads go through to base again
        assert_eq!(overlay.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_multi_get() {
        let kv = MemoryKV::new();
        kv.put(b"key1", b"value1").unwrap();
        kv.put(b"key2", b"value2").unwrap();

        let keys: Vec<&[u8]> = vec![b"key1", b"key2", b"key3"];
        let values = kv.multi_get(&keys).unwrap();

        assert_eq!(values[0], Some(b"value1".to_vec()));
        assert_eq!(values[1], Some(b"value2".to_vec()));
        assert_eq!(values[2], None);
    }
}
