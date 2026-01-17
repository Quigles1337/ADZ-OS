//! JSON-RPC Server
//!
//! Ethereum-compatible JSON-RPC API for ChainMesh node.
//! Provides standard eth_* methods plus ChainMesh-specific extensions.

use crate::types::{Address, Block, BlockHash, SignedTransaction, MuCoin, TransactionType};
use crate::ChainResult;
use super::{NodeStats, NodeStatus};
use super::chain::ChainState;
use super::mempool::MempoolStats;

use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{info, debug};

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Listen address
    pub addr: SocketAddr,
    /// Enable CORS
    pub cors_enabled: bool,
    /// Allowed origins for CORS
    pub cors_origins: Vec<String>,
    /// Maximum connections
    pub max_connections: u32,
    /// Request timeout (seconds)
    pub request_timeout: u64,
    /// Enable debug methods
    pub debug_enabled: bool,
    /// Enable admin methods
    pub admin_enabled: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8545".parse().unwrap(),
            cors_enabled: true,
            cors_origins: vec!["*".into()],
            max_connections: 100,
            request_timeout: 30,
            debug_enabled: false,
            admin_enabled: false,
        }
    }
}

/// RPC error codes (Ethereum compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcErrorCode {
    /// Parse error
    ParseError = -32700,
    /// Invalid request
    InvalidRequest = -32600,
    /// Method not found
    MethodNotFound = -32601,
    /// Invalid params
    InvalidParams = -32602,
    /// Internal error
    InternalError = -32603,
    /// Server error
    ServerError = -32000,
    /// Transaction rejected
    TransactionRejected = -32003,
    /// Resource not found
    ResourceNotFound = -32001,
}

/// RPC response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub state_root: String,
    pub tx_root: String,
    pub validator: String,
    pub transaction_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<TransactionResponse>>,
}

impl From<&Block> for BlockResponse {
    fn from(block: &Block) -> Self {
        Self {
            hash: format!("0x{}", block.hash().to_hex()),
            parent_hash: format!("0x{}", block.header.parent_hash.to_hex()),
            height: block.header.height,
            timestamp: block.header.timestamp,
            state_root: format!("0x{}", hex::encode(block.header.state_root)),
            tx_root: format!("0x{}", hex::encode(block.header.tx_root)),
            validator: block.header.validator.to_string(),
            transaction_count: block.transactions.len(),
            transactions: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub tx_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

impl From<&SignedTransaction> for TransactionResponse {
    fn from(tx: &SignedTransaction) -> Self {
        let sender = tx.sender().to_string();
        let (to, value) = extract_tx_details(&tx.transaction.tx_type);

        Self {
            hash: format!("0x{}", tx.hash().to_hex()),
            from: sender,
            to,
            value,
            nonce: tx.transaction.nonce,
            gas_price: tx.transaction.gas_price,
            gas_limit: tx.transaction.gas_limit,
            tx_type: tx.transaction.tx_type.name().to_string(),
            block_hash: None,
            block_number: None,
        }
    }
}

/// Extract to address and value from transaction type
fn extract_tx_details(tx_type: &TransactionType) -> (Option<String>, String) {
    match tx_type {
        TransactionType::Transfer { to, amount } => {
            (Some(to.to_string()), format!("{}", amount))
        }
        TransactionType::ContractCall { contract, value, .. } => {
            (Some(contract.to_string()), format!("{}", value))
        }
        TransactionType::Stake { amount } => {
            (None, format!("{}", amount))
        }
        TransactionType::Delegate { validator, amount } => {
            (Some(validator.to_string()), format!("{}", amount))
        }
        _ => (None, "0 MUC".to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfoResponse {
    pub version: String,
    pub network: String,
    pub chain_id: u64,
    pub protocol_version: u32,
    pub status: String,
    pub peers: u32,
    pub height: u64,
    pub head: String,
    pub state_root: String,
    pub uptime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    pub syncing: bool,
    pub current_block: u64,
    pub highest_block: u64,
    pub starting_block: u64,
}

/// RPC server handle
pub struct RpcServer {
    /// Configuration
    config: RpcConfig,
    /// Server handle (for shutdown)
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl RpcServer {
    /// Create new RPC server
    pub fn new(config: RpcConfig) -> Self {
        Self {
            config,
            handle: None,
        }
    }

    /// Start the RPC server
    pub async fn start(&mut self, node: Arc<RwLock<NodeContext>>) -> ChainResult<()> {
        let addr = self.config.addr;

        info!("Starting JSON-RPC server on {}", addr);

        // For now, we'll use a simple implementation
        // In production, this would use jsonrpsee properly

        let _node_clone = Arc::clone(&node);
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            // Placeholder for actual RPC server implementation
            // This would use jsonrpsee::server::ServerBuilder
            info!("RPC server listening on {}", config.addr);

            // Keep running until shutdown
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        self.handle = Some(handle);

        Ok(())
    }

    /// Stop the RPC server
    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            info!("RPC server stopped");
        }
    }

    /// Get server address
    pub fn addr(&self) -> SocketAddr {
        self.config.addr
    }
}

/// Node context for RPC handlers
pub struct NodeContext {
    /// Chain state getter
    pub get_chain_state: Box<dyn Fn() -> ChainState + Send + Sync>,
    /// Get block by hash
    pub get_block: Box<dyn Fn(&BlockHash) -> ChainResult<Option<Block>> + Send + Sync>,
    /// Get block by height
    pub get_block_by_height: Box<dyn Fn(u64) -> ChainResult<Option<Block>> + Send + Sync>,
    /// Get balance
    pub get_balance: Box<dyn Fn(&Address) -> ChainResult<MuCoin> + Send + Sync>,
    /// Get nonce
    pub get_nonce: Box<dyn Fn(&Address) -> ChainResult<u64> + Send + Sync>,
    /// Submit transaction
    pub submit_tx: Box<dyn Fn(SignedTransaction) -> ChainResult<[u8; 32]> + Send + Sync>,
    /// Get mempool stats
    pub mempool_stats: Box<dyn Fn() -> MempoolStats + Send + Sync>,
    /// Get node stats
    pub node_stats: Box<dyn Fn() -> NodeStats + Send + Sync>,
    /// Get node status
    pub node_status: Box<dyn Fn() -> NodeStatus + Send + Sync>,
    /// Chain config
    pub chain_id: u64,
    /// Network name
    pub network: String,
}

/// RPC method implementations
pub struct RpcMethods;

impl RpcMethods {
    /// eth_chainId - Returns the chain ID
    pub fn chain_id(ctx: &NodeContext) -> String {
        format!("0x{:x}", ctx.chain_id)
    }

    /// eth_blockNumber - Returns current block number
    pub fn block_number(ctx: &NodeContext) -> String {
        format!("0x{:x}", (ctx.get_chain_state)().height)
    }

    /// eth_getBalance - Returns balance of address
    pub fn get_balance(ctx: &NodeContext, address: &str, _block: &str) -> ChainResult<String> {
        let addr = parse_address(address)?;
        let balance = (ctx.get_balance)(&addr)?;
        Ok(format!("0x{:x}", balance.muons()))
    }

    /// eth_getTransactionCount - Returns nonce of address
    pub fn get_transaction_count(ctx: &NodeContext, address: &str, _block: &str) -> ChainResult<String> {
        let addr = parse_address(address)?;
        let nonce = (ctx.get_nonce)(&addr)?;
        Ok(format!("0x{:x}", nonce))
    }

    /// eth_getBlockByNumber - Returns block by number
    pub fn get_block_by_number(ctx: &NodeContext, number: &str, full: bool) -> ChainResult<Option<BlockResponse>> {
        let height = parse_block_number(number, (ctx.get_chain_state)().height)?;
        let block = (ctx.get_block_by_height)(height)?;

        Ok(block.map(|b| {
            let mut resp = BlockResponse::from(&b);
            if full {
                resp.transactions = Some(
                    b.transactions.iter().map(TransactionResponse::from).collect()
                );
            }
            resp
        }))
    }

    /// eth_getBlockByHash - Returns block by hash
    pub fn get_block_by_hash(ctx: &NodeContext, hash: &str, full: bool) -> ChainResult<Option<BlockResponse>> {
        let block_hash = parse_hash(hash)?;
        let block = (ctx.get_block)(&block_hash)?;

        Ok(block.map(|b| {
            let mut resp = BlockResponse::from(&b);
            if full {
                resp.transactions = Some(
                    b.transactions.iter().map(TransactionResponse::from).collect()
                );
            }
            resp
        }))
    }

    /// eth_sendRawTransaction - Submit signed transaction
    pub fn send_raw_transaction(ctx: &NodeContext, data: &str) -> ChainResult<String> {
        let bytes = parse_hex(data)?;
        let tx: SignedTransaction = bincode::deserialize(&bytes)
            .map_err(|e| crate::ChainError::Network(format!("Invalid transaction: {}", e)))?;

        let hash = (ctx.submit_tx)(tx)?;
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// eth_gasPrice - Returns current gas price
    pub fn gas_price(_ctx: &NodeContext) -> String {
        // Return minimum gas price (1 gwei equivalent)
        "0x1".to_string()
    }

    /// eth_estimateGas - Estimate gas for transaction
    pub fn estimate_gas(_ctx: &NodeContext, _tx: &serde_json::Value) -> String {
        // Return base gas for transfer
        format!("0x{:x}", 21000u64)
    }

    /// net_version - Returns network ID
    pub fn net_version(ctx: &NodeContext) -> String {
        ctx.chain_id.to_string()
    }

    /// net_listening - Returns if node is listening
    pub fn net_listening(_ctx: &NodeContext) -> bool {
        true
    }

    /// net_peerCount - Returns peer count
    pub fn net_peer_count(ctx: &NodeContext) -> String {
        let stats = (ctx.node_stats)();
        format!("0x{:x}", stats.peers_connected)
    }

    /// web3_clientVersion - Returns client version
    pub fn client_version(_ctx: &NodeContext) -> String {
        format!("ChainMesh/{}", env!("CARGO_PKG_VERSION"))
    }

    /// chainmesh_nodeInfo - ChainMesh specific node info
    pub fn node_info(ctx: &NodeContext) -> NodeInfoResponse {
        let chain_state = (ctx.get_chain_state)();
        let stats = (ctx.node_stats)();
        let status = (ctx.node_status)();

        NodeInfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            network: ctx.network.clone(),
            chain_id: ctx.chain_id,
            protocol_version: 1,
            status: format!("{:?}", status),
            peers: stats.peers_connected,
            height: chain_state.height,
            head: format!("0x{}", chain_state.head.to_hex()),
            state_root: format!("0x{}", hex::encode(chain_state.state_root)),
            uptime: stats.uptime_secs,
        }
    }

    /// chainmesh_syncStatus - Get sync status
    pub fn sync_status(ctx: &NodeContext) -> SyncStatusResponse {
        let chain_state = (ctx.get_chain_state)();
        let status = (ctx.node_status)();

        SyncStatusResponse {
            syncing: status == NodeStatus::Syncing,
            current_block: chain_state.height,
            highest_block: chain_state.height, // Would come from peers
            starting_block: 0,
        }
    }

    /// chainmesh_mempoolStats - Get mempool statistics
    pub fn mempool_stats(ctx: &NodeContext) -> MempoolStats {
        (ctx.mempool_stats)()
    }
}

/// Parse Ethereum-style address
fn parse_address(s: &str) -> ChainResult<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);

    // Handle ChainMesh addresses (mu1...)
    if s.starts_with("mu") {
        return Address::from_str(s)
            .map_err(|e| crate::ChainError::Network(format!("Invalid address: {}", e)));
    }

    // Handle hex addresses
    let bytes = hex::decode(s)
        .map_err(|_| crate::ChainError::Network("Invalid hex address".into()))?;

    if bytes.len() != 20 {
        return Err(crate::ChainError::Network("Address must be 20 bytes".into()));
    }

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(Address::from_bytes(addr))
}

/// Parse block number (handles "latest", "earliest", "pending", hex numbers)
fn parse_block_number(s: &str, current_height: u64) -> ChainResult<u64> {
    match s.to_lowercase().as_str() {
        "latest" | "pending" => Ok(current_height),
        "earliest" => Ok(0),
        _ => {
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16)
                .map_err(|_| crate::ChainError::Network("Invalid block number".into()))
        }
    }
}

/// Parse hex hash
fn parse_hash(s: &str) -> ChainResult<BlockHash> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|_| crate::ChainError::Network("Invalid hex hash".into()))?;

    if bytes.len() != 32 {
        return Err(crate::ChainError::Network("Hash must be 32 bytes".into()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(BlockHash(hash))
}

/// Parse hex bytes
fn parse_hex(s: &str) -> ChainResult<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s)
        .map_err(|_| crate::ChainError::Network("Invalid hex data".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_hex() {
        let addr = parse_address("0x0000000000000000000000000000000000000000").unwrap();
        assert_eq!(addr, Address::zero());
    }

    #[test]
    fn test_parse_block_number() {
        assert_eq!(parse_block_number("latest", 100).unwrap(), 100);
        assert_eq!(parse_block_number("earliest", 100).unwrap(), 0);
        assert_eq!(parse_block_number("0x64", 100).unwrap(), 100);
        assert_eq!(parse_block_number("0xa", 100).unwrap(), 10);
    }

    #[test]
    fn test_parse_hash() {
        let hash = parse_hash("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(hash.0, [0u8; 32]);
    }

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.addr.port(), 8545);
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_block_response_from_block() {
        let block = Block::genesis(0);
        let response = BlockResponse::from(&block);

        assert_eq!(response.height, 0);
        assert!(response.transactions.is_none());
    }
}
