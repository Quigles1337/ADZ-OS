//! ChainMesh Node Implementation
//!
//! Full node implementation that ties together:
//! - Consensus (μ-Proof-of-Stake)
//! - P2P networking (gossip protocol)
//! - State storage (Merkle Patricia Trie)
//! - Transaction pool (mempool)
//! - JSON-RPC API

pub mod config;
pub mod mempool;
pub mod chain;
pub mod rpc;

use crate::consensus::{MuPoS, ValidatorSet, ConsensusConfig};
use crate::storage::{StateDB, MemoryKV};
use crate::types::{Block, BlockHash, SignedTransaction, Address, MuCoin, TxHash};
use crate::{ChainConfig, ChainError, ChainResult};

pub use config::NodeConfig;
pub use mempool::{Mempool, MempoolConfig};
pub use chain::{ChainManager, ChainState};
pub use rpc::{RpcServer, RpcConfig};

use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::{broadcast, oneshot};
use tracing::{info, debug};

/// Node status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is starting up
    Starting,
    /// Node is syncing with the network
    Syncing,
    /// Node is fully synced and operational
    Running,
    /// Node is a validator and producing blocks
    Validating,
    /// Node is shutting down
    Stopping,
    /// Node has stopped
    Stopped,
}

/// Node events broadcast to subscribers
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// New block added to chain
    NewBlock(BlockHash, u64),
    /// New transaction in mempool
    NewTransaction(TxHash),
    /// Peer connected
    PeerConnected(String),
    /// Peer disconnected
    PeerDisconnected(String),
    /// Sync progress update
    SyncProgress { current: u64, target: u64 },
    /// Node status changed
    StatusChanged(NodeStatus),
    /// Validator produced a block
    BlockProduced(BlockHash),
    /// Received reward
    RewardReceived(MuCoin),
}

/// Node statistics
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Blocks processed
    pub blocks_processed: u64,
    /// Transactions processed
    pub txs_processed: u64,
    /// Peers connected
    pub peers_connected: u32,
    /// Blocks produced (if validator)
    pub blocks_produced: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Sync percentage
    pub sync_percentage: f64,
    /// Mempool size
    pub mempool_size: usize,
    /// Storage size bytes
    pub storage_bytes: u64,
}

/// ChainMesh full node
pub struct Node {
    /// Node configuration
    config: NodeConfig,
    /// Chain configuration
    chain_config: ChainConfig,
    /// Current status
    status: Arc<RwLock<NodeStatus>>,
    /// Chain manager
    chain: Arc<ChainManager<MemoryKV>>,
    /// Transaction mempool
    mempool: Arc<Mempool>,
    /// Consensus engine
    consensus: Arc<RwLock<MuPoS>>,
    /// Validator set
    validators: Arc<RwLock<ValidatorSet>>,
    /// State database
    state: Arc<StateDB<MemoryKV>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<NodeEvent>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Node statistics
    stats: Arc<RwLock<NodeStats>>,
    /// Start time
    start_time: std::time::Instant,
}

impl Node {
    /// Create a new node with configuration
    pub fn new(config: NodeConfig) -> ChainResult<Self> {
        let chain_config = config.chain_config();

        info!("Initializing ChainMesh node...");
        info!("  Network: {}", config.network);
        info!("  Data dir: {}", config.data_dir.display());

        // Initialize storage with in-memory KV for now
        let kv = Arc::new(MemoryKV::new());
        let state = Arc::new(StateDB::new(kv));

        // Initialize chain manager
        let chain = Arc::new(ChainManager::new(
            Arc::clone(&state),
            chain_config.clone(),
        )?);

        // Initialize mempool
        let mempool_config = MempoolConfig {
            max_size: config.mempool_size,
            max_per_account: 64,
            min_gas_price: 1,
            ..MempoolConfig::default()
        };
        let mempool = Arc::new(Mempool::new(mempool_config));

        // Initialize consensus with ConsensusConfig
        let consensus_config = ConsensusConfig {
            epoch_length: chain_config.epoch_length,
            block_time: chain_config.block_time,
            ..ConsensusConfig::default()
        };
        let consensus = Arc::new(RwLock::new(MuPoS::new(consensus_config)));
        let validators = Arc::new(RwLock::new(ValidatorSet::new()));

        // Event broadcasting
        let (event_tx, _) = broadcast::channel(1000);

        info!("Node initialized successfully");

        Ok(Self {
            config,
            chain_config,
            status: Arc::new(RwLock::new(NodeStatus::Starting)),
            chain,
            mempool,
            consensus,
            validators,
            state,
            event_tx,
            shutdown_tx: None,
            stats: Arc::new(RwLock::new(NodeStats::default())),
            start_time: std::time::Instant::now(),
        })
    }

    /// Start the node
    pub async fn start(&mut self) -> ChainResult<()> {
        info!("Starting ChainMesh node...");

        // Set status to syncing
        self.set_status(NodeStatus::Syncing);

        // Initialize genesis if needed
        if self.chain.height() == 0 {
            info!("Initializing genesis block...");
            self.chain.initialize_genesis()?;
        }

        // Create shutdown channel
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Set status to running
        self.set_status(NodeStatus::Running);

        info!("Node started successfully");
        info!("  Chain height: {}", self.chain.height());
        info!("  State root: {}", hex::encode(self.chain.state_root()));

        Ok(())
    }

    /// Stop the node gracefully
    pub async fn stop(&mut self) -> ChainResult<()> {
        info!("Stopping ChainMesh node...");
        self.set_status(NodeStatus::Stopping);

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Flush state to disk
        self.state.commit()?;

        self.set_status(NodeStatus::Stopped);
        info!("Node stopped");

        Ok(())
    }

    /// Set node status and broadcast event
    fn set_status(&self, new_status: NodeStatus) {
        let mut status = self.status.write();
        *status = new_status;
        let _ = self.event_tx.send(NodeEvent::StatusChanged(new_status));
    }

    /// Get current node status
    pub fn status(&self) -> NodeStatus {
        *self.status.read()
    }

    /// Get node statistics
    pub fn stats(&self) -> NodeStats {
        let mut stats = self.stats.read().clone();
        stats.uptime_secs = self.start_time.elapsed().as_secs();
        stats
    }

    /// Subscribe to node events
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Get chain manager reference
    pub fn chain(&self) -> &Arc<ChainManager<MemoryKV>> {
        &self.chain
    }

    /// Get mempool reference
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// Get state database reference
    pub fn state(&self) -> &Arc<StateDB<MemoryKV>> {
        &self.state
    }

    /// Submit a transaction to the mempool
    pub fn submit_transaction(&self, tx: SignedTransaction) -> ChainResult<TxHash> {
        // Validate transaction signature
        if !tx.verify() {
            return Err(ChainError::Transaction(
                crate::types::transaction::TransactionError::InvalidSignature
            ));
        }

        let tx_hash = tx.hash();

        // Add to mempool
        self.mempool.add(tx)?;

        // Broadcast event
        let _ = self.event_tx.send(NodeEvent::NewTransaction(tx_hash));

        debug!("Transaction {} added to mempool", tx_hash.to_hex());

        Ok(tx_hash)
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> ChainResult<MuCoin> {
        let account = self.state.get_account(address)?;
        Ok(MuCoin::from_muons(account.balance))
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> ChainResult<u64> {
        let account = self.state.get_account(address)?;
        Ok(account.nonce)
    }

    /// Get block by hash
    pub fn get_block(&self, hash: &BlockHash) -> ChainResult<Option<Block>> {
        self.chain.get_block(hash)
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> ChainResult<Option<Block>> {
        self.chain.get_block_by_height(height)
    }

    /// Get current chain height
    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Get current state root
    pub fn state_root(&self) -> [u8; 32] {
        self.chain.state_root()
    }

    /// Check if node is synced
    pub fn is_synced(&self) -> bool {
        matches!(self.status(), NodeStatus::Running | NodeStatus::Validating)
    }

    /// Get node configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("status", &self.status())
            .field("height", &self.chain.height())
            .field("mempool_size", &self.mempool.len())
            .finish()
    }
}

/// Node result type
pub type NodeResult<T> = Result<T, NodeError>;

/// Node errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Mempool error: {0}")]
    Mempool(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Node not running")]
    NotRunning,

    #[error("Node already running")]
    AlreadyRunning,

    #[error("Shutdown in progress")]
    ShuttingDown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_node_creation() {
        let tmp = tempdir().unwrap();
        let config = NodeConfig::testnet(tmp.path().to_path_buf());

        let node = Node::new(config).unwrap();
        assert_eq!(node.status(), NodeStatus::Starting);
        assert_eq!(node.height(), 0);
    }

    #[tokio::test]
    async fn test_node_start_stop() {
        let tmp = tempdir().unwrap();
        let config = NodeConfig::testnet(tmp.path().to_path_buf());

        let mut node = Node::new(config).unwrap();
        node.start().await.unwrap();

        assert_eq!(node.status(), NodeStatus::Running);
        // Genesis block is at height 0, check that genesis block exists
        assert_eq!(node.height(), 0);
        let genesis = node.get_block_by_height(0).unwrap();
        assert!(genesis.is_some()); // Genesis block was created

        node.stop().await.unwrap();
        assert_eq!(node.status(), NodeStatus::Stopped);
    }

    #[test]
    fn test_node_stats() {
        let tmp = tempdir().unwrap();
        let config = NodeConfig::testnet(tmp.path().to_path_buf());

        let node = Node::new(config).unwrap();
        let stats = node.stats();

        assert_eq!(stats.blocks_processed, 0);
        assert_eq!(stats.peers_connected, 0);
    }
}
