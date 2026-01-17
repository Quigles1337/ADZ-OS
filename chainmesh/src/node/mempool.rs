//! Transaction Mempool
//!
//! Pending transaction pool with priority ordering, account nonce tracking,
//! and eviction policies for maintaining a healthy transaction pool.

use crate::types::{SignedTransaction, Address, MuCoin, TxHash};
use crate::ChainResult;
use super::NodeError;

use std::collections::{HashMap, BTreeMap, HashSet};
use parking_lot::RwLock;
use std::time::{Instant, Duration};
use tracing::{debug, warn};

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in the pool
    pub max_size: usize,
    /// Maximum transactions per account
    pub max_per_account: usize,
    /// Minimum gas price to accept
    pub min_gas_price: u64,
    /// Transaction lifetime before expiry
    pub tx_lifetime: Duration,
    /// Enable replacement by higher gas price
    pub enable_replacement: bool,
    /// Minimum gas price bump for replacement (percentage)
    pub replacement_bump_percent: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            max_per_account: 64,
            min_gas_price: 1,
            tx_lifetime: Duration::from_secs(3600), // 1 hour
            enable_replacement: true,
            replacement_bump_percent: 10,
        }
    }
}

/// Transaction entry in the mempool
#[derive(Debug, Clone)]
struct TxEntry {
    /// The transaction
    tx: SignedTransaction,
    /// Transaction hash
    hash: TxHash,
    /// Sender address
    sender: Address,
    /// Gas price for ordering
    gas_price: u64,
    /// Time added to pool
    added_at: Instant,
    /// Effective priority (gas_price * gas_limit)
    priority: u128,
}

impl TxEntry {
    fn new(tx: SignedTransaction) -> Self {
        let hash = tx.hash();
        let sender = tx.sender().clone();
        let gas_price = tx.transaction.gas_price;
        let priority = (gas_price as u128) * (tx.transaction.gas_limit as u128);

        Self {
            tx,
            hash,
            sender,
            gas_price,
            added_at: Instant::now(),
            priority,
        }
    }
}

/// Account transaction queue
#[derive(Debug, Default)]
struct AccountTxs {
    /// Transactions by nonce
    by_nonce: BTreeMap<u64, TxHash>,
    /// Total transactions
    count: usize,
}

/// Transaction mempool
pub struct Mempool {
    /// Configuration
    config: MempoolConfig,
    /// All transactions by hash
    txs: RwLock<HashMap<TxHash, TxEntry>>,
    /// Transactions grouped by sender
    by_sender: RwLock<HashMap<Address, AccountTxs>>,
    /// Priority queue (priority -> tx hashes)
    by_priority: RwLock<BTreeMap<u128, HashSet<TxHash>>>,
    /// Statistics
    stats: RwLock<MempoolStats>,
}

/// Mempool statistics
#[derive(Debug, Clone, Default)]
pub struct MempoolStats {
    /// Total transactions added
    pub total_added: u64,
    /// Total transactions removed
    pub total_removed: u64,
    /// Transactions replaced
    pub total_replaced: u64,
    /// Transactions expired
    pub total_expired: u64,
    /// Transactions evicted (capacity)
    pub total_evicted: u64,
    /// Current size
    pub current_size: usize,
    /// Unique senders
    pub unique_senders: usize,
}

impl Mempool {
    /// Create a new mempool with configuration
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            txs: RwLock::new(HashMap::new()),
            by_sender: RwLock::new(HashMap::new()),
            by_priority: RwLock::new(BTreeMap::new()),
            stats: RwLock::new(MempoolStats::default()),
        }
    }

    /// Add a transaction to the mempool
    pub fn add(&self, tx: SignedTransaction) -> ChainResult<TxHash> {
        let entry = TxEntry::new(tx);
        let hash = entry.hash;
        let sender = entry.sender.clone();
        let nonce = entry.tx.transaction.nonce;
        let priority = entry.priority;

        // Check gas price
        if entry.gas_price < self.config.min_gas_price {
            return Err(crate::ChainError::Transaction(
                crate::types::transaction::TransactionError::InvalidGasPrice
            ));
        }

        let mut txs = self.txs.write();
        let mut by_sender = self.by_sender.write();
        let mut by_priority = self.by_priority.write();
        let mut stats = self.stats.write();

        // Check if already exists
        if txs.contains_key(&hash) {
            debug!("Transaction {} already in mempool", hash.to_hex());
            return Ok(hash);
        }

        // Check account limit
        let account_txs = by_sender.entry(sender.clone()).or_default();
        if account_txs.count >= self.config.max_per_account {
            return Err(crate::ChainError::Network(
                format!("Account {} has too many pending transactions", sender)
            ));
        }

        // Check for replacement
        if let Some(&existing_hash) = account_txs.by_nonce.get(&nonce) {
            if self.config.enable_replacement {
                if let Some(existing) = txs.get(&existing_hash) {
                    let min_new_price = existing.gas_price +
                        (existing.gas_price * self.config.replacement_bump_percent / 100);

                    if entry.gas_price >= min_new_price {
                        // Remove old transaction
                        self.remove_tx_internal(
                            &mut txs,
                            &mut by_sender,
                            &mut by_priority,
                            &existing_hash,
                        );
                        stats.total_replaced += 1;
                        debug!("Replaced transaction {} with {}", existing_hash.to_hex(), hash.to_hex());
                    } else {
                        return Err(crate::ChainError::Network(
                            format!("Replacement gas price too low, need at least {}", min_new_price)
                        ));
                    }
                }
            } else {
                return Err(crate::ChainError::Transaction(
                    crate::types::transaction::TransactionError::InvalidNonce
                ));
            }
        }

        // Evict if at capacity
        while txs.len() >= self.config.max_size {
            if let Some(evicted) = self.evict_lowest_priority(&mut txs, &mut by_sender, &mut by_priority) {
                stats.total_evicted += 1;
                debug!("Evicted transaction {} to make room", evicted.to_hex());
            } else {
                break;
            }
        }

        // Add transaction
        txs.insert(hash, entry);

        // Update by_sender index
        let account_txs = by_sender.entry(sender).or_default();
        account_txs.by_nonce.insert(nonce, hash);
        account_txs.count += 1;

        // Update priority queue
        by_priority.entry(priority).or_default().insert(hash);

        // Update stats
        stats.total_added += 1;
        stats.current_size = txs.len();
        stats.unique_senders = by_sender.len();

        debug!("Added transaction {} to mempool (size: {})", hash.to_hex(), txs.len());

        Ok(hash)
    }

    /// Remove a transaction by hash
    pub fn remove(&self, hash: &TxHash) -> Option<SignedTransaction> {
        let mut txs = self.txs.write();
        let mut by_sender = self.by_sender.write();
        let mut by_priority = self.by_priority.write();
        let mut stats = self.stats.write();

        let tx = self.remove_tx_internal(&mut txs, &mut by_sender, &mut by_priority, hash);

        if tx.is_some() {
            stats.total_removed += 1;
            stats.current_size = txs.len();
            stats.unique_senders = by_sender.len();
        }

        tx
    }

    /// Remove multiple transactions (after block inclusion)
    pub fn remove_batch(&self, hashes: &[TxHash]) {
        let mut txs = self.txs.write();
        let mut by_sender = self.by_sender.write();
        let mut by_priority = self.by_priority.write();
        let mut stats = self.stats.write();

        for hash in hashes {
            if self.remove_tx_internal(&mut txs, &mut by_sender, &mut by_priority, hash).is_some() {
                stats.total_removed += 1;
            }
        }

        stats.current_size = txs.len();
        stats.unique_senders = by_sender.len();
    }

    /// Internal remove helper
    fn remove_tx_internal(
        &self,
        txs: &mut HashMap<TxHash, TxEntry>,
        by_sender: &mut HashMap<Address, AccountTxs>,
        by_priority: &mut BTreeMap<u128, HashSet<TxHash>>,
        hash: &TxHash,
    ) -> Option<SignedTransaction> {
        let entry = txs.remove(hash)?;

        // Remove from sender index
        if let Some(account_txs) = by_sender.get_mut(&entry.sender) {
            account_txs.by_nonce.remove(&entry.tx.transaction.nonce);
            account_txs.count = account_txs.count.saturating_sub(1);

            if account_txs.count == 0 {
                by_sender.remove(&entry.sender);
            }
        }

        // Remove from priority queue
        if let Some(set) = by_priority.get_mut(&entry.priority) {
            set.remove(hash);
            if set.is_empty() {
                by_priority.remove(&entry.priority);
            }
        }

        Some(entry.tx)
    }

    /// Evict lowest priority transaction
    fn evict_lowest_priority(
        &self,
        txs: &mut HashMap<TxHash, TxEntry>,
        by_sender: &mut HashMap<Address, AccountTxs>,
        by_priority: &mut BTreeMap<u128, HashSet<TxHash>>,
    ) -> Option<TxHash> {
        // Get lowest priority
        let lowest_priority = *by_priority.keys().next()?;
        let hash = {
            let set = by_priority.get(&lowest_priority)?;
            *set.iter().next()?
        };

        self.remove_tx_internal(txs, by_sender, by_priority, &hash)?;
        Some(hash)
    }

    /// Get transaction by hash
    pub fn get(&self, hash: &TxHash) -> Option<SignedTransaction> {
        self.txs.read().get(hash).map(|e| e.tx.clone())
    }

    /// Check if transaction exists
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.txs.read().contains_key(hash)
    }

    /// Get pending transactions for an account
    pub fn get_pending_for_account(&self, address: &Address) -> Vec<SignedTransaction> {
        let txs = self.txs.read();
        let by_sender = self.by_sender.read();

        let Some(account_txs) = by_sender.get(address) else {
            return Vec::new();
        };

        account_txs.by_nonce
            .values()
            .filter_map(|hash| txs.get(hash).map(|e| e.tx.clone()))
            .collect()
    }

    /// Get next nonce for account (current + pending)
    pub fn get_pending_nonce(&self, address: &Address, current_nonce: u64) -> u64 {
        let by_sender = self.by_sender.read();

        let Some(account_txs) = by_sender.get(address) else {
            return current_nonce;
        };

        // Find the highest consecutive nonce starting from current
        let mut next = current_nonce;
        while account_txs.by_nonce.contains_key(&next) {
            next += 1;
        }

        next
    }

    /// Select transactions for block (ordered by priority, respecting nonces)
    pub fn select_for_block(&self, max_gas: u64) -> Vec<SignedTransaction> {
        let txs = self.txs.read();
        let by_priority = self.by_priority.read();

        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut account_nonces: HashMap<Address, u64> = HashMap::new();

        // Iterate by priority (highest first)
        for (_, hashes) in by_priority.iter().rev() {
            for hash in hashes {
                if let Some(entry) = txs.get(hash) {
                    let tx_gas = entry.tx.transaction.gas_limit;

                    // Check gas limit
                    if total_gas + tx_gas > max_gas {
                        continue;
                    }

                    // Check nonce ordering
                    let expected_nonce = account_nonces
                        .get(&entry.sender)
                        .copied()
                        .unwrap_or(0);

                    if entry.tx.transaction.nonce == expected_nonce {
                        selected.push(entry.tx.clone());
                        total_gas += tx_gas;
                        account_nonces.insert(entry.sender.clone(), expected_nonce + 1);
                    }
                }
            }
        }

        selected
    }

    /// Remove expired transactions
    pub fn remove_expired(&self) -> usize {
        let now = Instant::now();
        let mut txs = self.txs.write();
        let mut by_sender = self.by_sender.write();
        let mut by_priority = self.by_priority.write();
        let mut stats = self.stats.write();

        let expired: Vec<TxHash> = txs.iter()
            .filter(|(_, entry)| now.duration_since(entry.added_at) > self.config.tx_lifetime)
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();

        for hash in expired {
            self.remove_tx_internal(&mut txs, &mut by_sender, &mut by_priority, &hash);
        }

        stats.total_expired += count as u64;
        stats.current_size = txs.len();
        stats.unique_senders = by_sender.len();

        if count > 0 {
            debug!("Removed {} expired transactions", count);
        }

        count
    }

    /// Get current mempool size
    pub fn len(&self) -> usize {
        self.txs.read().len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.txs.read().is_empty()
    }

    /// Clear all transactions
    pub fn clear(&self) {
        let mut txs = self.txs.write();
        let mut by_sender = self.by_sender.write();
        let mut by_priority = self.by_priority.write();
        let mut stats = self.stats.write();

        stats.total_removed += txs.len() as u64;

        txs.clear();
        by_sender.clear();
        by_priority.clear();

        stats.current_size = 0;
        stats.unique_senders = 0;
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        self.stats.read().clone()
    }

    /// Get all transaction hashes
    pub fn all_hashes(&self) -> Vec<TxHash> {
        self.txs.read().keys().copied().collect()
    }

    /// Get content summary for debugging
    pub fn content(&self) -> MempoolContent {
        let txs = self.txs.read();
        let by_sender = self.by_sender.read();

        let mut pending = HashMap::new();
        for (addr, account_txs) in by_sender.iter() {
            let txs_list: Vec<_> = account_txs.by_nonce
                .iter()
                .filter_map(|(nonce, hash)| {
                    txs.get(hash).map(|e| (*nonce, e.tx.transaction.gas_price))
                })
                .collect();
            pending.insert(addr.clone(), txs_list);
        }

        MempoolContent {
            pending,
            size: txs.len(),
        }
    }
}

/// Mempool content for debugging
#[derive(Debug, Clone)]
pub struct MempoolContent {
    /// Pending transactions by sender: address -> [(nonce, gas_price), ...]
    pub pending: HashMap<Address, Vec<(u64, u64)>>,
    /// Total size
    pub size: usize,
}

impl std::fmt::Debug for Mempool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mempool")
            .field("size", &self.len())
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require creating proper SignedTransaction instances
    // which need keypairs and signing - simplified for now

    #[test]
    fn test_mempool_creation() {
        let mempool = Mempool::new(MempoolConfig::default());
        assert_eq!(mempool.len(), 0);
        assert!(mempool.is_empty());
    }

    #[test]
    fn test_mempool_stats() {
        let mempool = Mempool::new(MempoolConfig::default());
        let stats = mempool.stats();
        assert_eq!(stats.total_added, 0);
        assert_eq!(stats.current_size, 0);
    }

    #[test]
    fn test_mempool_config() {
        let config = MempoolConfig {
            max_size: 100,
            max_per_account: 10,
            min_gas_price: 50,
            ..Default::default()
        };

        assert_eq!(config.max_size, 100);
        assert_eq!(config.max_per_account, 10);
        assert_eq!(config.min_gas_price, 50);
    }
}
