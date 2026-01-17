//! Chain Manager
//!
//! Manages the blockchain state, block import/export, and chain reorganization.
//! Provides the core interface for interacting with the blockchain.

use crate::storage::{StateDB, MemoryKV, KeyValueStore, EMPTY_ROOT};
use crate::types::{Block, BlockHeader, BlockHash, SignedTransaction, Address, MuCoin};
use crate::{ChainConfig, ChainResult, ChainError};

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, debug};

/// State root type alias
pub type StateRoot = [u8; 32];

/// Chain state information
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Current block height
    pub height: u64,
    /// Current block hash
    pub head: BlockHash,
    /// Current state root
    pub state_root: StateRoot,
    /// Total difficulty (for PoW compatibility)
    pub total_difficulty: u128,
    /// Genesis hash
    pub genesis_hash: BlockHash,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            height: 0,
            head: BlockHash::ZERO,
            state_root: EMPTY_ROOT,
            total_difficulty: 0,
            genesis_hash: BlockHash::ZERO,
        }
    }
}

/// Block validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStatus {
    /// Block is valid and added to chain
    Valid,
    /// Block already exists
    Known,
    /// Block's parent not found
    Orphan,
    /// Block is invalid
    Invalid(String),
}

/// Chain manager handles blockchain state
pub struct ChainManager<KV: KeyValueStore = MemoryKV> {
    /// Chain configuration
    config: ChainConfig,
    /// State database
    state: Arc<StateDB<KV>>,
    /// Current chain state
    chain_state: RwLock<ChainState>,
    /// Block storage (hash -> block)
    blocks: RwLock<HashMap<BlockHash, Block>>,
    /// Height to hash index
    height_index: RwLock<HashMap<u64, BlockHash>>,
    /// Orphan blocks (parent_hash -> blocks)
    orphans: RwLock<HashMap<BlockHash, Vec<Block>>>,
}

impl ChainManager<MemoryKV> {
    /// Create a new chain manager with in-memory storage
    pub fn new(state: Arc<StateDB<MemoryKV>>, config: ChainConfig) -> ChainResult<Self> {
        Ok(Self {
            config,
            state,
            chain_state: RwLock::new(ChainState::default()),
            blocks: RwLock::new(HashMap::new()),
            height_index: RwLock::new(HashMap::new()),
            orphans: RwLock::new(HashMap::new()),
        })
    }

    /// Initialize genesis block
    pub fn initialize_genesis(&self) -> ChainResult<BlockHash> {
        let mut chain_state = self.chain_state.write();

        // Check if genesis already exists (head is not zero hash)
        if chain_state.head != BlockHash::ZERO {
            return Err(ChainError::Consensus("Genesis already initialized".into()));
        }

        info!("Creating genesis block...");

        // Create genesis state
        self.create_genesis_state()?;

        // Get state root after genesis allocation
        let state_root = self.state.root();

        // Create genesis block
        let mut genesis = Block::genesis(self.config.genesis_timestamp);
        genesis.header.state_root = state_root;
        let genesis_hash = genesis.hash();

        info!("Genesis block hash: {}", genesis_hash.to_hex());
        info!("Genesis state root: {}", hex::encode(state_root));

        // Store genesis
        self.blocks.write().insert(genesis_hash, genesis);
        self.height_index.write().insert(0, genesis_hash);

        // Update chain state
        chain_state.height = 0;
        chain_state.head = genesis_hash;
        chain_state.state_root = state_root;
        chain_state.genesis_hash = genesis_hash;

        // Commit state
        self.state.commit()?;

        Ok(genesis_hash)
    }

    /// Create genesis state with initial allocations
    fn create_genesis_state(&self) -> ChainResult<()> {
        // Genesis allocations - initial token distribution
        let allocations = self.genesis_allocations();

        for (address, balance) in allocations {
            let amount = MuCoin::from_muons(balance);
            self.state.set_balance(&address, amount)?;
            debug!("Genesis allocation: {} = {} MUC", address, amount);
        }

        Ok(())
    }

    /// Get genesis allocations based on network
    fn genesis_allocations(&self) -> Vec<(Address, u64)> {
        match self.config.chain_id {
            1 => {
                // Mainnet allocations (placeholder)
                vec![
                    // Foundation: 20% of supply
                    (Address::zero(), 27_407_200_000_000_000), // 27.4072M MUC
                ]
            }
            137 => {
                // Testnet allocations
                vec![
                    // Testnet faucet
                    (Address::zero(), 100_000_000_000_000_000), // 100M MUC for testing
                ]
            }
            1337 => {
                // Devnet allocations
                vec![
                    // Dev account 1
                    (Address::zero(), 1_000_000_000_000_000), // 1M MUC

                    // Dev account 2
                    (Address::from_bytes([1u8; 20]), 1_000_000_000_000_000),
                ]
            }
            _ => Vec::new(),
        }
    }

    /// Import a block
    pub fn import_block(&self, block: Block) -> ChainResult<BlockStatus> {
        let block_hash = block.hash();
        let parent_hash = block.header.parent_hash;

        debug!("Importing block {} at height {}", block_hash.to_hex(), block.height());

        // Check if already known
        if self.blocks.read().contains_key(&block_hash) {
            return Ok(BlockStatus::Known);
        }

        // Validate block structure
        self.validate_block_structure(&block)?;

        // Check if parent exists
        let parent_exists = {
            let blocks = self.blocks.read();
            blocks.contains_key(&parent_hash) || block.height() == 0
        };

        if !parent_exists {
            // Store as orphan
            debug!("Block {} is orphan (parent {} not found)",
                block_hash.to_hex(), parent_hash.to_hex());
            self.orphans.write()
                .entry(parent_hash)
                .or_default()
                .push(block);
            return Ok(BlockStatus::Orphan);
        }

        // Validate state transition
        self.validate_state_transition(&block)?;

        // Apply block
        self.apply_block(&block)?;

        // Store block
        let height = block.height();
        self.blocks.write().insert(block_hash, block);
        self.height_index.write().insert(height, block_hash);

        // Update chain state
        {
            let mut chain_state = self.chain_state.write();
            chain_state.height = height;
            chain_state.head = block_hash;
            chain_state.state_root = self.state.root();
        }

        info!("Block {} imported at height {}", block_hash.to_hex(), height);

        // Process orphans that depend on this block
        self.process_orphans(&block_hash)?;

        Ok(BlockStatus::Valid)
    }

    /// Validate block structure
    fn validate_block_structure(&self, block: &Block) -> ChainResult<()> {
        // Validate header
        block.header.validate_basic().map_err(|e| ChainError::Block(e))?;

        // Validate block (includes tx root check)
        block.validate().map_err(|e| ChainError::Block(e))?;

        // Validate all transaction signatures
        for tx in &block.transactions {
            if !tx.verify() {
                return Err(ChainError::Transaction(
                    crate::types::transaction::TransactionError::InvalidSignature
                ));
            }
        }

        Ok(())
    }

    /// Validate state transition
    fn validate_state_transition(&self, block: &Block) -> ChainResult<()> {
        // Check timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if block.header.timestamp > now + 15 {
            return Err(ChainError::Block(
                crate::types::block::BlockError::FutureTimestamp
            ));
        }

        Ok(())
    }

    /// Apply block to state
    fn apply_block(&self, block: &Block) -> ChainResult<()> {
        // Execute each transaction
        for tx in &block.transactions {
            self.apply_transaction(tx)?;
        }

        // Apply block rewards
        self.apply_block_rewards(block)?;

        // Commit state changes
        self.state.commit()?;

        Ok(())
    }

    /// Apply a single transaction
    fn apply_transaction(&self, tx: &SignedTransaction) -> ChainResult<()> {
        let sender = tx.sender();

        // Get current sender state
        let sender_account = self.state.get_account(sender)?;
        let sender_balance = sender_account.balance;
        let sender_nonce = sender_account.nonce;

        // Check nonce
        if tx.transaction.nonce != sender_nonce {
            return Err(ChainError::Transaction(
                crate::types::transaction::TransactionError::InvalidNonce
            ));
        }

        // Calculate gas cost
        let gas_cost = tx.transaction.gas_limit.saturating_mul(tx.transaction.gas_price);

        // Get value from transaction type
        let value = self.get_tx_value(&tx.transaction.tx_type);
        let total_cost = value.saturating_add(gas_cost);

        // Check balance
        if sender_balance < total_cost {
            return Err(ChainError::Transaction(
                crate::types::transaction::TransactionError::InsufficientBalance
            ));
        }

        // Deduct from sender
        self.state.set_balance(sender, MuCoin::from_muons(sender_balance - total_cost))?;
        self.state.increment_nonce(sender)?;

        // Credit recipient based on transaction type
        if let Some((to_addr, amount)) = self.get_tx_recipient(&tx.transaction.tx_type) {
            self.state.add_balance(&to_addr, MuCoin::from_muons(amount))?;
        }

        // Gas refund (simplified - actual gas used would be calculated)
        let gas_used = tx.transaction.tx_type.estimate_gas();
        let gas_refund = tx.transaction.gas_limit.saturating_sub(gas_used)
            .saturating_mul(tx.transaction.gas_price);
        if gas_refund > 0 {
            self.state.add_balance(sender, MuCoin::from_muons(gas_refund))?;
        }

        Ok(())
    }

    /// Get value from transaction type
    fn get_tx_value(&self, tx_type: &crate::types::TransactionType) -> u64 {
        use crate::types::TransactionType;
        match tx_type {
            TransactionType::Transfer { amount, .. } => amount.muons(),
            TransactionType::Stake { amount } => amount.muons(),
            TransactionType::Delegate { amount, .. } => amount.muons(),
            TransactionType::ContractCall { value, .. } => value.muons(),
            _ => 0,
        }
    }

    /// Get recipient from transaction type
    fn get_tx_recipient(&self, tx_type: &crate::types::TransactionType) -> Option<(Address, u64)> {
        use crate::types::TransactionType;
        match tx_type {
            TransactionType::Transfer { to, amount } => Some((to.clone(), amount.muons())),
            TransactionType::ContractCall { contract, value, .. } => {
                Some((contract.clone(), value.muons()))
            }
            _ => None,
        }
    }

    /// Apply block rewards
    fn apply_block_rewards(&self, block: &Block) -> ChainResult<()> {
        // Get block reward for this height
        let reward = MuCoin::block_reward(block.height());

        // Add reward to validator
        self.state.add_balance(&block.header.validator, reward)?;

        debug!("Applied block reward {} to {}", reward, block.header.validator);

        Ok(())
    }

    /// Process orphan blocks
    fn process_orphans(&self, parent_hash: &BlockHash) -> ChainResult<()> {
        let orphans = self.orphans.write().remove(parent_hash);

        if let Some(blocks) = orphans {
            for block in blocks {
                match self.import_block(block) {
                    Ok(BlockStatus::Valid) => {
                        debug!("Processed orphan block");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Failed to import orphan block: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get current chain height
    pub fn height(&self) -> u64 {
        self.chain_state.read().height
    }

    /// Get current state root
    pub fn state_root(&self) -> StateRoot {
        self.chain_state.read().state_root
    }

    /// Get current head hash
    pub fn head(&self) -> BlockHash {
        self.chain_state.read().head
    }

    /// Get genesis hash
    pub fn genesis_hash(&self) -> BlockHash {
        self.chain_state.read().genesis_hash
    }

    /// Get chain state
    pub fn chain_state(&self) -> ChainState {
        self.chain_state.read().clone()
    }

    /// Get block by hash
    pub fn get_block(&self, hash: &BlockHash) -> ChainResult<Option<Block>> {
        Ok(self.blocks.read().get(hash).cloned())
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> ChainResult<Option<Block>> {
        let hash = self.height_index.read().get(&height).cloned();
        match hash {
            Some(h) => self.get_block(&h),
            None => Ok(None),
        }
    }

    /// Get block header by hash
    pub fn get_header(&self, hash: &BlockHash) -> ChainResult<Option<BlockHeader>> {
        Ok(self.blocks.read().get(hash).map(|b| b.header.clone()))
    }

    /// Get block header by height
    pub fn get_header_by_height(&self, height: u64) -> ChainResult<Option<BlockHeader>> {
        let hash = self.height_index.read().get(&height).cloned();
        match hash {
            Some(h) => self.get_header(&h),
            None => Ok(None),
        }
    }

    /// Check if block exists
    pub fn has_block(&self, hash: &BlockHash) -> bool {
        self.blocks.read().contains_key(hash)
    }

    /// Get chain configuration
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Get state database
    pub fn state_db(&self) -> &Arc<StateDB<MemoryKV>> {
        &self.state
    }

    /// Get ancestors of a block (for sync)
    pub fn get_ancestors(&self, hash: &BlockHash, count: usize) -> ChainResult<Vec<BlockHash>> {
        let mut ancestors = Vec::with_capacity(count);
        let mut current = *hash;

        for _ in 0..count {
            let block = match self.blocks.read().get(&current) {
                Some(b) => b.clone(),
                None => break,
            };

            if block.height() == 0 {
                break;
            }

            ancestors.push(block.header.parent_hash);
            current = block.header.parent_hash;
        }

        Ok(ancestors)
    }

    /// Get block locator for sync
    pub fn get_locator(&self) -> ChainResult<Vec<BlockHash>> {
        let chain_state = self.chain_state.read();
        let height = chain_state.height;

        let mut locator = Vec::new();
        let mut step = 1u64;
        let mut index = height;

        // Add hashes at exponentially increasing intervals
        while index > 0 {
            if let Some(hash) = self.height_index.read().get(&index) {
                locator.push(*hash);
            }

            if locator.len() >= 10 {
                step *= 2;
            }

            if index < step {
                break;
            }
            index -= step;
        }

        // Always include genesis
        if let Some(hash) = self.height_index.read().get(&0) {
            if locator.last() != Some(hash) {
                locator.push(*hash);
            }
        }

        Ok(locator)
    }
}

impl<KV: KeyValueStore> std::fmt::Debug for ChainManager<KV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.chain_state.read();
        f.debug_struct("ChainManager")
            .field("height", &state.height)
            .field("head", &state.head.to_hex())
            .field("state_root", &hex::encode(state.state_root))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_chain() -> ChainManager<MemoryKV> {
        let kv = Arc::new(MemoryKV::new());
        let state = Arc::new(StateDB::new(kv));

        ChainManager::new(state, ChainConfig::testnet()).unwrap()
    }

    #[test]
    fn test_chain_creation() {
        let chain = create_test_chain();
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn test_genesis_initialization() {
        let chain = create_test_chain();
        let genesis_hash = chain.initialize_genesis().unwrap();

        assert_eq!(chain.height(), 0);
        assert!(chain.has_block(&genesis_hash));

        let genesis = chain.get_block(&genesis_hash).unwrap().unwrap();
        assert_eq!(genesis.height(), 0);
    }

    #[test]
    fn test_genesis_already_initialized() {
        let chain = create_test_chain();
        chain.initialize_genesis().unwrap();

        let result = chain.initialize_genesis();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_block_by_height() {
        let chain = create_test_chain();
        chain.initialize_genesis().unwrap();

        let block = chain.get_block_by_height(0).unwrap();
        assert!(block.is_some());

        let block = chain.get_block_by_height(100).unwrap();
        assert!(block.is_none());
    }

    #[test]
    fn test_chain_state() {
        let chain = create_test_chain();
        chain.initialize_genesis().unwrap();

        let state = chain.chain_state();
        assert_eq!(state.height, 0);
        assert_eq!(state.genesis_hash, state.head);
    }

    #[test]
    fn test_block_locator() {
        let chain = create_test_chain();
        chain.initialize_genesis().unwrap();

        let locator = chain.get_locator().unwrap();
        assert!(!locator.is_empty());
        assert_eq!(locator[0], chain.genesis_hash());
    }

    #[test]
    fn test_genesis_allocations() {
        let kv = Arc::new(MemoryKV::new());
        let state = Arc::new(StateDB::new(kv));

        // Devnet config with known allocations
        let config = ChainConfig {
            chain_id: 1337,
            ..ChainConfig::testnet()
        };

        let chain = ChainManager::new(Arc::clone(&state), config).unwrap();
        chain.initialize_genesis().unwrap();

        // Check dev allocation
        let balance = state.get_balance(&Address::zero()).unwrap();
        assert!(balance.muons() > 0);
    }
}
