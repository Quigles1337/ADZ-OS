//! ChainMesh: Blockchain Marketplace for μOS
//!
//! ChainMesh is a proof-of-stake blockchain designed for digital ownership
//! and trading. It uses μ-cryptography for all cryptographic operations.
//!
//! ## Core Features
//! - μ-Proof-of-Stake consensus with golden ratio validator selection
//! - Native NFT support for digital game ownership
//! - Smart contract platform for ownership primitives
//! - P2P gossip protocol for transaction and block propagation
//!
//! ## Modules
//! - `types` - Core data structures (blocks, transactions, accounts)
//! - `consensus` - μ-Proof-of-Stake consensus engine
//! - `crypto` - Cryptographic operations using libmu-crypto
//! - `storage` - State storage and Merkle trees
//! - `p2p` - Peer-to-peer networking
//! - `contracts` - Smart contract execution
//! - `node` - Full node implementation

pub mod types;
pub mod consensus;
pub mod contracts;
// pub mod crypto;
// pub mod storage;
// pub mod p2p;
// pub mod node;

pub use types::*;

/// ChainMesh network configuration
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Network chain ID
    pub chain_id: u64,
    /// Genesis timestamp
    pub genesis_timestamp: u64,
    /// Block time target (seconds)
    pub block_time: u64,
    /// Epoch length in blocks (μ^8 = 1 → 8 blocks)
    pub epoch_length: u64,
    /// Minimum stake to become validator
    pub min_validator_stake: MuCoin,
    /// Maximum validators per epoch
    pub max_validators: u32,
    /// Unbonding period in epochs
    pub unbonding_epochs: u64,
    /// Slashing percentage for double-signing (basis points)
    pub double_sign_slash_bps: u16,
    /// Slashing percentage for downtime (basis points)
    pub downtime_slash_bps: u16,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            genesis_timestamp: 0,
            block_time: 6, // 6 second blocks
            epoch_length: 8, // μ^8 = 1
            min_validator_stake: MuCoin::from_muons(crate::types::token::MIN_VALIDATOR_STAKE),
            max_validators: 100,
            unbonding_epochs: 21, // ~21 epochs unbonding
            double_sign_slash_bps: 500, // 5%
            downtime_slash_bps: 100, // 1%
        }
    }
}

impl ChainConfig {
    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            chain_id: 137, // Fine-structure tribute
            genesis_timestamp: 1700000000, // Arbitrary testnet genesis
            block_time: 6,
            epoch_length: 8,
            min_validator_stake: MuCoin::from_muc(100), // Lower for testnet
            max_validators: 21,
            unbonding_epochs: 7,
            double_sign_slash_bps: 500,
            downtime_slash_bps: 100,
        }
    }

    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            chain_id: 1,
            genesis_timestamp: 0, // TBD
            block_time: 6,
            epoch_length: 8,
            min_validator_stake: MuCoin::from_muons(crate::types::token::MIN_VALIDATOR_STAKE),
            max_validators: 100,
            unbonding_epochs: 21,
            double_sign_slash_bps: 500,
            downtime_slash_bps: 100,
        }
    }
}

/// Result type for ChainMesh operations
pub type ChainResult<T> = Result<T, ChainError>;

/// Errors that can occur in ChainMesh
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("Block error: {0}")]
    Block(#[from] types::block::BlockError),

    #[error("Transaction error: {0}")]
    Transaction(#[from] types::transaction::TransactionError),

    #[error("Account error: {0}")]
    Account(#[from] types::account::AccountError),

    #[error("Token error: {0}")]
    Token(#[from] types::token::TokenError),

    #[error("Address error: {0}")]
    Address(#[from] types::address::AddressError),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),
}
