//! Merkle Patricia Trie
//!
//! A modified Merkle Patricia Trie for efficient authenticated state storage.
//! Based on Ethereum's MPT but with μ-Hash for all hashing operations.
//!
//! Features:
//! - O(log n) lookups, insertions, deletions
//! - Merkle proofs for any key
//! - Efficient state root computation
//! - Node caching for performance

use super::{KeyValueStore, StorageError, StorageResult, KeyPrefix, WriteBatch};
use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// 32-byte state root
pub type StateRoot = [u8; 32];

/// Empty state root (hash of empty trie)
pub const EMPTY_ROOT: StateRoot = [0u8; 32];

/// Nibble (4-bit value)
type Nibble = u8;

/// Convert bytes to nibbles
fn bytes_to_nibbles(bytes: &[u8]) -> Vec<Nibble> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Convert nibbles back to bytes
fn nibbles_to_bytes(nibbles: &[Nibble]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((nibbles.len() + 1) / 2);
    for chunk in nibbles.chunks(2) {
        if chunk.len() == 2 {
            bytes.push((chunk[0] << 4) | chunk[1]);
        } else {
            bytes.push(chunk[0] << 4);
        }
    }
    bytes
}

/// Compact encoding for path (HP encoding)
/// Adds prefix to indicate whether path has odd length and whether it's a leaf
fn compact_encode(nibbles: &[Nibble], is_leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let prefix = if is_leaf { 2 } else { 0 } + if odd { 1 } else { 0 };

    let mut result = Vec::with_capacity((nibbles.len() + 2) / 2);

    if odd {
        result.push((prefix << 4) | nibbles[0]);
        for chunk in nibbles[1..].chunks(2) {
            result.push((chunk[0] << 4) | chunk.get(1).copied().unwrap_or(0));
        }
    } else {
        result.push(prefix << 4);
        for chunk in nibbles.chunks(2) {
            result.push((chunk[0] << 4) | chunk[1]);
        }
    }

    result
}

/// Decode compact encoding
fn compact_decode(encoded: &[u8]) -> (Vec<Nibble>, bool) {
    if encoded.is_empty() {
        return (vec![], false);
    }

    let prefix = encoded[0] >> 4;
    let is_leaf = prefix >= 2;
    let odd = prefix % 2 == 1;

    let mut nibbles = Vec::new();

    if odd {
        nibbles.push(encoded[0] & 0x0F);
    }

    for &byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }

    // Remove trailing zero if even length encoding
    if !odd && !nibbles.is_empty() && encoded.len() > 1 {
        // Keep all nibbles from bytes after the prefix byte
    }

    (nibbles, is_leaf)
}

/// Trie node types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNode {
    /// Empty node
    Empty,

    /// Leaf node: (encoded_path, value)
    Leaf {
        /// Encoded path (remaining key nibbles)
        path: Vec<u8>,
        /// Value stored
        value: Vec<u8>,
    },

    /// Extension node: (encoded_path, child_hash)
    Extension {
        /// Encoded path (shared prefix)
        path: Vec<u8>,
        /// Hash of child node
        child: [u8; 32],
    },

    /// Branch node: 16 children + optional value
    Branch {
        /// 16 children (one per nibble 0-15)
        children: [Option<[u8; 32]>; 16],
        /// Value at this node (if key ends here)
        value: Option<Vec<u8>>,
    },
}

impl TrieNode {
    /// Compute hash of this node
    pub fn hash(&self) -> [u8; 32] {
        match self {
            TrieNode::Empty => EMPTY_ROOT,
            _ => {
                let encoded = bincode::serialize(self).unwrap_or_default();
                MuHash::hash(&encoded)
            }
        }
    }

    /// Check if node is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, TrieNode::Empty)
    }

    /// Create new leaf node
    pub fn leaf(nibbles: &[Nibble], value: Vec<u8>) -> Self {
        TrieNode::Leaf {
            path: compact_encode(nibbles, true),
            value,
        }
    }

    /// Create new extension node
    pub fn extension(nibbles: &[Nibble], child: [u8; 32]) -> Self {
        TrieNode::Extension {
            path: compact_encode(nibbles, false),
            child,
        }
    }

    /// Create new branch node
    pub fn branch() -> Self {
        TrieNode::Branch {
            children: Default::default(),
            value: None,
        }
    }

    /// Get path nibbles from leaf or extension
    pub fn path_nibbles(&self) -> Option<Vec<Nibble>> {
        match self {
            TrieNode::Leaf { path, .. } | TrieNode::Extension { path, .. } => {
                let (nibbles, _) = compact_decode(path);
                Some(nibbles)
            }
            _ => None,
        }
    }
}

/// Merkle Patricia Trie
pub struct MerkleTrie<S: KeyValueStore> {
    /// Underlying storage
    store: Arc<S>,
    /// Current root hash
    root: RwLock<StateRoot>,
    /// Node cache for performance
    cache: RwLock<HashMap<[u8; 32], TrieNode>>,
    /// Maximum cache entries
    cache_limit: usize,
    /// Dirty nodes (modified but not persisted)
    dirty: RwLock<HashMap<[u8; 32], TrieNode>>,
}

impl<S: KeyValueStore> MerkleTrie<S> {
    /// Create new trie with empty root
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            root: RwLock::new(EMPTY_ROOT),
            cache: RwLock::new(HashMap::new()),
            cache_limit: 10000,
            dirty: RwLock::new(HashMap::new()),
        }
    }

    /// Create trie with existing root
    pub fn with_root(store: Arc<S>, root: StateRoot) -> Self {
        Self {
            store,
            root: RwLock::new(root),
            cache: RwLock::new(HashMap::new()),
            cache_limit: 10000,
            dirty: RwLock::new(HashMap::new()),
        }
    }

    /// Get current state root
    pub fn root(&self) -> StateRoot {
        *self.root.read().unwrap()
    }

    /// Set cache limit
    pub fn set_cache_limit(&mut self, limit: usize) {
        self.cache_limit = limit;
    }

    /// Get value by key
    pub fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let root = self.root();
        if root == EMPTY_ROOT {
            return Ok(None);
        }

        let nibbles = bytes_to_nibbles(key);
        self.get_recursive(&root, &nibbles, 0)
    }

    /// Recursive get implementation
    fn get_recursive(&self, node_hash: &[u8; 32], nibbles: &[Nibble], pos: usize) -> StorageResult<Option<Vec<u8>>> {
        if *node_hash == EMPTY_ROOT {
            return Ok(None);
        }

        let node = self.get_node(node_hash)?;

        match node {
            TrieNode::Empty => Ok(None),

            TrieNode::Leaf { path, value } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                if remaining == node_nibbles.as_slice() {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }

            TrieNode::Extension { path, child } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                if remaining.starts_with(&node_nibbles) {
                    self.get_recursive(&child, nibbles, pos + node_nibbles.len())
                } else {
                    Ok(None)
                }
            }

            TrieNode::Branch { children, value } => {
                if pos >= nibbles.len() {
                    Ok(value)
                } else {
                    let idx = nibbles[pos] as usize;
                    match children[idx] {
                        Some(child_hash) => self.get_recursive(&child_hash, nibbles, pos + 1),
                        None => Ok(None),
                    }
                }
            }
        }
    }

    /// Insert or update a value
    pub fn put(&self, key: &[u8], value: Vec<u8>) -> StorageResult<StateRoot> {
        let nibbles = bytes_to_nibbles(key);
        let root = self.root();

        let new_root_hash = if root == EMPTY_ROOT {
            let leaf = TrieNode::leaf(&nibbles, value);
            let hash = leaf.hash();
            self.put_node(hash, leaf)?;
            hash
        } else {
            self.put_recursive(&root, &nibbles, 0, value)?
        };

        *self.root.write().unwrap() = new_root_hash;
        Ok(new_root_hash)
    }

    /// Recursive put implementation
    fn put_recursive(&self, node_hash: &[u8; 32], nibbles: &[Nibble], pos: usize, value: Vec<u8>) -> StorageResult<[u8; 32]> {
        if *node_hash == EMPTY_ROOT {
            let leaf = TrieNode::leaf(&nibbles[pos..], value);
            let hash = leaf.hash();
            self.put_node(hash, leaf)?;
            return Ok(hash);
        }

        let node = self.get_node(node_hash)?;

        match node {
            TrieNode::Empty => {
                let leaf = TrieNode::leaf(&nibbles[pos..], value);
                let hash = leaf.hash();
                self.put_node(hash, leaf)?;
                Ok(hash)
            }

            TrieNode::Leaf { path, value: existing_value } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                // Find common prefix length
                let common_len = remaining.iter()
                    .zip(node_nibbles.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                if common_len == remaining.len() && common_len == node_nibbles.len() {
                    // Same key, update value
                    let new_leaf = TrieNode::leaf(remaining, value);
                    let hash = new_leaf.hash();
                    self.put_node(hash, new_leaf)?;
                    Ok(hash)
                } else {
                    // Need to create a branch
                    self.split_leaf(remaining, &node_nibbles, value, existing_value, common_len)
                }
            }

            TrieNode::Extension { path, child } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                let common_len = remaining.iter()
                    .zip(node_nibbles.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                if common_len == node_nibbles.len() {
                    // Extension path is a prefix, recurse into child
                    let new_child = self.put_recursive(&child, nibbles, pos + common_len, value)?;
                    let new_ext = TrieNode::extension(&node_nibbles, new_child);
                    let hash = new_ext.hash();
                    self.put_node(hash, new_ext)?;
                    Ok(hash)
                } else {
                    // Need to split extension
                    self.split_extension(&node_nibbles, &child, remaining, value, common_len)
                }
            }

            TrieNode::Branch { mut children, value: branch_value } => {
                if pos >= nibbles.len() {
                    // Key ends at this branch
                    let new_branch = TrieNode::Branch {
                        children,
                        value: Some(value),
                    };
                    let hash = new_branch.hash();
                    self.put_node(hash, new_branch)?;
                    Ok(hash)
                } else {
                    // Recurse into child
                    let idx = nibbles[pos] as usize;
                    let child_hash = children[idx].unwrap_or(EMPTY_ROOT);
                    let new_child = self.put_recursive(&child_hash, nibbles, pos + 1, value)?;
                    children[idx] = Some(new_child);

                    let new_branch = TrieNode::Branch {
                        children,
                        value: branch_value,
                    };
                    let hash = new_branch.hash();
                    self.put_node(hash, new_branch)?;
                    Ok(hash)
                }
            }
        }
    }

    /// Split a leaf node when inserting a conflicting key
    fn split_leaf(&self, new_nibbles: &[Nibble], existing_nibbles: &[Nibble], new_value: Vec<u8>, existing_value: Vec<u8>, common_len: usize) -> StorageResult<[u8; 32]> {
        let mut branch = TrieNode::branch();

        if let TrieNode::Branch { ref mut children, ref mut value } = branch {
            // Handle existing leaf
            if common_len < existing_nibbles.len() {
                let idx = existing_nibbles[common_len] as usize;
                if common_len + 1 == existing_nibbles.len() {
                    // Existing becomes value at branch child
                    let leaf = TrieNode::leaf(&[], existing_value);
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                } else {
                    let leaf = TrieNode::leaf(&existing_nibbles[common_len + 1..], existing_value);
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                }
            } else {
                *value = Some(existing_value);
            }

            // Handle new leaf
            if common_len < new_nibbles.len() {
                let idx = new_nibbles[common_len] as usize;
                if common_len + 1 == new_nibbles.len() {
                    let leaf = TrieNode::leaf(&[], new_value);
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                } else {
                    let leaf = TrieNode::leaf(&new_nibbles[common_len + 1..], new_value);
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                }
            } else {
                *value = Some(new_value);
            }
        }

        let branch_hash = branch.hash();
        self.put_node(branch_hash, branch)?;

        // Create extension if there's a common prefix
        if common_len > 0 {
            let ext = TrieNode::extension(&new_nibbles[..common_len], branch_hash);
            let ext_hash = ext.hash();
            self.put_node(ext_hash, ext)?;
            Ok(ext_hash)
        } else {
            Ok(branch_hash)
        }
    }

    /// Split an extension node
    fn split_extension(&self, ext_nibbles: &[Nibble], child: &[u8; 32], new_nibbles: &[Nibble], new_value: Vec<u8>, common_len: usize) -> StorageResult<[u8; 32]> {
        let mut branch = TrieNode::branch();

        if let TrieNode::Branch { ref mut children, ref mut value } = branch {
            // Handle existing extension's child
            if common_len < ext_nibbles.len() {
                let idx = ext_nibbles[common_len] as usize;
                if common_len + 1 == ext_nibbles.len() {
                    children[idx] = Some(*child);
                } else {
                    let new_ext = TrieNode::extension(&ext_nibbles[common_len + 1..], *child);
                    let hash = new_ext.hash();
                    self.put_node(hash, new_ext)?;
                    children[idx] = Some(hash);
                }
            }

            // Handle new value
            if common_len < new_nibbles.len() {
                let idx = new_nibbles[common_len] as usize;
                if common_len + 1 >= new_nibbles.len() {
                    let leaf = TrieNode::leaf(&[], new_value.clone());
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                } else {
                    let leaf = TrieNode::leaf(&new_nibbles[common_len + 1..], new_value.clone());
                    let hash = leaf.hash();
                    self.put_node(hash, leaf)?;
                    children[idx] = Some(hash);
                }
            } else {
                *value = Some(new_value.clone());
            }
        }

        let branch_hash = branch.hash();
        self.put_node(branch_hash, branch)?;

        if common_len > 0 {
            let ext = TrieNode::extension(&new_nibbles[..common_len], branch_hash);
            let ext_hash = ext.hash();
            self.put_node(ext_hash, ext)?;
            Ok(ext_hash)
        } else {
            Ok(branch_hash)
        }
    }

    /// Delete a key
    pub fn delete(&self, key: &[u8]) -> StorageResult<StateRoot> {
        let root = self.root();
        if root == EMPTY_ROOT {
            return Ok(EMPTY_ROOT);
        }

        let nibbles = bytes_to_nibbles(key);
        let (new_root, _) = self.delete_recursive(&root, &nibbles, 0)?;

        *self.root.write().unwrap() = new_root;
        Ok(new_root)
    }

    /// Recursive delete implementation
    fn delete_recursive(&self, node_hash: &[u8; 32], nibbles: &[Nibble], pos: usize) -> StorageResult<([u8; 32], bool)> {
        if *node_hash == EMPTY_ROOT {
            return Ok((EMPTY_ROOT, false));
        }

        let node = self.get_node(node_hash)?;

        match node {
            TrieNode::Empty => Ok((EMPTY_ROOT, false)),

            TrieNode::Leaf { path, .. } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                if remaining == node_nibbles.as_slice() {
                    Ok((EMPTY_ROOT, true))
                } else {
                    Ok((*node_hash, false))
                }
            }

            TrieNode::Extension { path, child } => {
                let (node_nibbles, _) = compact_decode(&path);
                let remaining = &nibbles[pos..];

                if remaining.starts_with(&node_nibbles) {
                    let (new_child, deleted) = self.delete_recursive(&child, nibbles, pos + node_nibbles.len())?;

                    if !deleted {
                        return Ok((*node_hash, false));
                    }

                    if new_child == EMPTY_ROOT {
                        return Ok((EMPTY_ROOT, true));
                    }

                    // May need to collapse extension with child
                    let new_ext = TrieNode::extension(&node_nibbles, new_child);
                    let hash = new_ext.hash();
                    self.put_node(hash, new_ext)?;
                    Ok((hash, true))
                } else {
                    Ok((*node_hash, false))
                }
            }

            TrieNode::Branch { mut children, value } => {
                if pos >= nibbles.len() {
                    // Delete value at this branch
                    if value.is_none() {
                        return Ok((*node_hash, false));
                    }

                    let new_branch = TrieNode::Branch {
                        children,
                        value: None,
                    };

                    // Check if branch can be collapsed
                    let hash = new_branch.hash();
                    self.put_node(hash, new_branch)?;
                    Ok((hash, true))
                } else {
                    let idx = nibbles[pos] as usize;
                    match children[idx] {
                        None => Ok((*node_hash, false)),
                        Some(child_hash) => {
                            let (new_child, deleted) = self.delete_recursive(&child_hash, nibbles, pos + 1)?;

                            if !deleted {
                                return Ok((*node_hash, false));
                            }

                            if new_child == EMPTY_ROOT {
                                children[idx] = None;
                            } else {
                                children[idx] = Some(new_child);
                            }

                            let new_branch = TrieNode::Branch {
                                children,
                                value,
                            };
                            let hash = new_branch.hash();
                            self.put_node(hash, new_branch)?;
                            Ok((hash, true))
                        }
                    }
                }
            }
        }
    }

    /// Get a node by hash
    fn get_node(&self, hash: &[u8; 32]) -> StorageResult<TrieNode> {
        if *hash == EMPTY_ROOT {
            return Ok(TrieNode::Empty);
        }

        // Check dirty nodes first
        if let Some(node) = self.dirty.read().unwrap().get(hash) {
            return Ok(node.clone());
        }

        // Check cache
        if let Some(node) = self.cache.read().unwrap().get(hash) {
            return Ok(node.clone());
        }

        // Load from storage
        let key = KeyPrefix::trie_key(hash);
        match self.store.get(&key)? {
            Some(data) => {
                let node: TrieNode = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                // Add to cache
                let mut cache = self.cache.write().unwrap();
                if cache.len() < self.cache_limit {
                    cache.insert(*hash, node.clone());
                }

                Ok(node)
            }
            None => Err(StorageError::NotFound(hex::encode(hash))),
        }
    }

    /// Store a node
    fn put_node(&self, hash: [u8; 32], node: TrieNode) -> StorageResult<()> {
        // Add to dirty set
        self.dirty.write().unwrap().insert(hash, node.clone());

        // Also update cache
        let mut cache = self.cache.write().unwrap();
        if cache.len() < self.cache_limit {
            cache.insert(hash, node);
        }

        Ok(())
    }

    /// Commit all dirty nodes to storage
    pub fn commit(&self) -> StorageResult<()> {
        let dirty = std::mem::take(&mut *self.dirty.write().unwrap());

        let mut batch = WriteBatch::with_capacity(dirty.len());
        for (hash, node) in dirty {
            let key = KeyPrefix::trie_key(&hash);
            let value = bincode::serialize(&node)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put(key, value);
        }

        self.store.write_batch(batch)
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Generate proof for a key
    pub fn prove(&self, key: &[u8]) -> StorageResult<TrieProof> {
        let root = self.root();
        let nibbles = bytes_to_nibbles(key);
        let mut proof_nodes = Vec::new();

        self.prove_recursive(&root, &nibbles, 0, &mut proof_nodes)?;

        Ok(TrieProof {
            key: key.to_vec(),
            root,
            nodes: proof_nodes,
        })
    }

    /// Recursive proof generation
    fn prove_recursive(&self, node_hash: &[u8; 32], nibbles: &[Nibble], pos: usize, proof: &mut Vec<Vec<u8>>) -> StorageResult<()> {
        if *node_hash == EMPTY_ROOT {
            return Ok(());
        }

        let node = self.get_node(node_hash)?;
        let encoded = bincode::serialize(&node)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        proof.push(encoded);

        match node {
            TrieNode::Empty | TrieNode::Leaf { .. } => Ok(()),

            TrieNode::Extension { path, child } => {
                let (node_nibbles, _) = compact_decode(&path);
                if nibbles[pos..].starts_with(&node_nibbles) {
                    self.prove_recursive(&child, nibbles, pos + node_nibbles.len(), proof)
                } else {
                    Ok(())
                }
            }

            TrieNode::Branch { children, .. } => {
                if pos < nibbles.len() {
                    let idx = nibbles[pos] as usize;
                    if let Some(child) = children[idx] {
                        self.prove_recursive(&child, nibbles, pos + 1, proof)?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// Merkle proof for a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieProof {
    /// Key being proved
    pub key: Vec<u8>,
    /// State root
    pub root: StateRoot,
    /// Proof nodes (serialized)
    pub nodes: Vec<Vec<u8>>,
}

impl TrieProof {
    /// Verify proof and return value if valid
    pub fn verify(&self) -> StorageResult<Option<Vec<u8>>> {
        if self.nodes.is_empty() {
            return Ok(None);
        }

        let nibbles = bytes_to_nibbles(&self.key);
        self.verify_recursive(&self.root, &nibbles, 0, 0)
    }

    fn verify_recursive(&self, expected_hash: &[u8; 32], nibbles: &[Nibble], pos: usize, proof_idx: usize) -> StorageResult<Option<Vec<u8>>> {
        if *expected_hash == EMPTY_ROOT {
            return Ok(None);
        }

        if proof_idx >= self.nodes.len() {
            return Err(StorageError::TrieError("Incomplete proof".into()));
        }

        let node: TrieNode = bincode::deserialize(&self.nodes[proof_idx])
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        // Verify hash
        let actual_hash = node.hash();
        if actual_hash != *expected_hash {
            return Err(StorageError::TrieError("Hash mismatch in proof".into()));
        }

        match node {
            TrieNode::Empty => Ok(None),

            TrieNode::Leaf { path, value } => {
                let (node_nibbles, _) = compact_decode(&path);
                if &nibbles[pos..] == node_nibbles.as_slice() {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }

            TrieNode::Extension { path, child } => {
                let (node_nibbles, _) = compact_decode(&path);
                if nibbles[pos..].starts_with(&node_nibbles) {
                    self.verify_recursive(&child, nibbles, pos + node_nibbles.len(), proof_idx + 1)
                } else {
                    Ok(None)
                }
            }

            TrieNode::Branch { children, value } => {
                if pos >= nibbles.len() {
                    Ok(value)
                } else {
                    let idx = nibbles[pos] as usize;
                    match children[idx] {
                        Some(child) => self.verify_recursive(&child, nibbles, pos + 1, proof_idx + 1),
                        None => Ok(None),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryKV;

    fn create_test_trie() -> MerkleTrie<MemoryKV> {
        let store = Arc::new(MemoryKV::new());
        MerkleTrie::new(store)
    }

    #[test]
    fn test_empty_trie() {
        let trie = create_test_trie();
        assert_eq!(trie.root(), EMPTY_ROOT);
        assert_eq!(trie.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_single_insert() {
        let trie = create_test_trie();
        trie.put(b"key", b"value".to_vec()).unwrap();

        assert_ne!(trie.root(), EMPTY_ROOT);
        assert_eq!(trie.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_multiple_inserts() {
        let trie = create_test_trie();

        trie.put(b"key1", b"value1".to_vec()).unwrap();
        trie.put(b"key2", b"value2".to_vec()).unwrap();
        trie.put(b"key3", b"value3".to_vec()).unwrap();

        assert_eq!(trie.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(trie.get(b"key3").unwrap(), Some(b"value3".to_vec()));
    }

    #[test]
    fn test_overwrite() {
        let trie = create_test_trie();

        trie.put(b"key", b"value1".to_vec()).unwrap();
        let root1 = trie.root();

        trie.put(b"key", b"value2".to_vec()).unwrap();
        let root2 = trie.root();

        assert_ne!(root1, root2);
        assert_eq!(trie.get(b"key").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_delete() {
        let trie = create_test_trie();

        trie.put(b"key1", b"value1".to_vec()).unwrap();
        trie.put(b"key2", b"value2".to_vec()).unwrap();

        trie.delete(b"key1").unwrap();

        assert_eq!(trie.get(b"key1").unwrap(), None);
        assert_eq!(trie.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_delete_nonexistent() {
        let trie = create_test_trie();
        trie.put(b"key", b"value".to_vec()).unwrap();
        let root_before = trie.root();

        trie.delete(b"nonexistent").unwrap();
        let root_after = trie.root();

        // Root shouldn't change when deleting nonexistent key
        assert_eq!(root_before, root_after);
    }

    #[test]
    fn test_state_root_deterministic() {
        let trie1 = create_test_trie();
        let trie2 = create_test_trie();

        // Same insertions should produce same root
        trie1.put(b"a", b"1".to_vec()).unwrap();
        trie1.put(b"b", b"2".to_vec()).unwrap();

        trie2.put(b"a", b"1".to_vec()).unwrap();
        trie2.put(b"b", b"2".to_vec()).unwrap();

        assert_eq!(trie1.root(), trie2.root());
    }

    #[test]
    fn test_nibble_conversion() {
        let bytes = vec![0x12, 0x34, 0xAB];
        let nibbles = bytes_to_nibbles(&bytes);
        assert_eq!(nibbles, vec![0x1, 0x2, 0x3, 0x4, 0xA, 0xB]);

        let back = nibbles_to_bytes(&nibbles);
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_proof_verification() {
        let trie = create_test_trie();

        trie.put(b"key1", b"value1".to_vec()).unwrap();
        trie.put(b"key2", b"value2".to_vec()).unwrap();

        trie.commit().unwrap();

        let proof = trie.prove(b"key1").unwrap();
        let value = proof.verify().unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_compact_encoding() {
        // Even length, leaf
        let nibbles = vec![1, 2, 3, 4];
        let encoded = compact_encode(&nibbles, true);
        let (decoded, is_leaf) = compact_decode(&encoded);
        assert!(is_leaf);
        assert_eq!(decoded, nibbles);

        // Odd length, extension
        let nibbles = vec![1, 2, 3];
        let encoded = compact_encode(&nibbles, false);
        let (decoded, is_leaf) = compact_decode(&encoded);
        assert!(!is_leaf);
        assert_eq!(decoded, nibbles);
    }
}
