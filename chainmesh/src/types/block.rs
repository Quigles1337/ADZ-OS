//! Block and BlockHeader definitions
//!
//! Blocks in ChainMesh use μ-cryptography for hashing and signatures.
//! The block structure supports μ-Proof-of-Stake consensus.

use super::{Address, SignedTransaction, TxHash};
use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;

/// Block hash (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    /// Zero hash (genesis parent)
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Block header containing metadata and proof
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version
    pub version: u32,
    /// Block height (0 for genesis)
    pub height: u64,
    /// Hash of parent block
    pub parent_hash: BlockHash,
    /// Merkle root of transactions
    pub tx_root: [u8; 32],
    /// Merkle root of state
    pub state_root: [u8; 32],
    /// Merkle root of receipts
    pub receipts_root: [u8; 32],
    /// Block timestamp (Unix seconds)
    pub timestamp: u64,
    /// Validator who proposed this block
    pub validator: Address,
    /// Validator's signature over the block
    #[serde_as(as = "[_; 64]")]
    pub validator_signature: [u8; 64],
    /// Total stake participating in this epoch
    pub total_stake: u64,
    /// Block difficulty (for tie-breaking)
    pub difficulty: u64,
    /// Extra data (up to 32 bytes)
    pub extra_data: Vec<u8>,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Gas used by transactions
    pub gas_used: u64,
}

impl BlockHeader {
    /// Current block version
    pub const CURRENT_VERSION: u32 = 1;

    /// Maximum extra data size
    pub const MAX_EXTRA_DATA: usize = 32;

    /// Create a new block header
    pub fn new(
        height: u64,
        parent_hash: BlockHash,
        validator: Address,
        timestamp: u64,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            height,
            parent_hash,
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            receipts_root: [0u8; 32],
            timestamp,
            validator,
            validator_signature: [0u8; 64],
            total_stake: 0,
            difficulty: 1,
            extra_data: Vec::new(),
            gas_limit: 10_000_000,
            gas_used: 0,
        }
    }

    /// Compute block hash
    pub fn hash(&self) -> BlockHash {
        let mut hasher = MuHash::new();

        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.parent_hash.0);
        hasher.update(&self.tx_root);
        hasher.update(&self.state_root);
        hasher.update(&self.receipts_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.validator.bytes);
        // Note: signature not included in hash (circular dependency)
        hasher.update(&self.total_stake.to_le_bytes());
        hasher.update(&self.difficulty.to_le_bytes());
        hasher.update(&self.extra_data);
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.gas_used.to_le_bytes());

        BlockHash(hasher.finalize())
    }

    /// Get signing message (what the validator signs)
    pub fn signing_message(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(&self.hash().0);
        hasher.update(b"chainmesh-block-sign-v1");
        hasher.finalize()
    }

    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.parent_hash.is_zero()
    }

    /// Validate basic header constraints
    pub fn validate_basic(&self) -> Result<(), BlockError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(BlockError::InvalidVersion);
        }

        if self.extra_data.len() > Self::MAX_EXTRA_DATA {
            return Err(BlockError::ExtraDataTooLong);
        }

        if self.gas_used > self.gas_limit {
            return Err(BlockError::GasExceedsLimit);
        }

        if self.height > 0 && self.parent_hash.is_zero() {
            return Err(BlockError::InvalidParentHash);
        }

        Ok(())
    }
}

/// A complete block with header and transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Transactions in this block
    pub transactions: Vec<SignedTransaction>,
    /// Validator votes/attestations for this block
    pub attestations: Vec<Attestation>,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
            attestations: Vec::new(),
        }
    }

    /// Get block hash
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get block height
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Compute transaction root (Merkle root of tx hashes)
    pub fn compute_tx_root(&self) -> [u8; 32] {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }

        let tx_hashes: Vec<[u8; 32]> = self.transactions
            .iter()
            .map(|tx| tx.hash().0)
            .collect();

        compute_merkle_root(&tx_hashes)
    }

    /// Update header with computed roots
    pub fn finalize_header(&mut self) {
        self.header.tx_root = self.compute_tx_root();
        self.header.gas_used = self.transactions
            .iter()
            .map(|tx| tx.transaction.gas_limit)
            .sum();
    }

    /// Create genesis block
    pub fn genesis(timestamp: u64) -> Self {
        let header = BlockHeader {
            version: BlockHeader::CURRENT_VERSION,
            height: 0,
            parent_hash: BlockHash::ZERO,
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            receipts_root: [0u8; 32],
            timestamp,
            validator: Address::system(),
            validator_signature: [0u8; 64],
            total_stake: 0,
            difficulty: 1,
            extra_data: b"ChainMesh Genesis".to_vec(),
            gas_limit: 10_000_000,
            gas_used: 0,
        };

        Self {
            header,
            transactions: Vec::new(),
            attestations: Vec::new(),
        }
    }

    /// Validate block structure
    pub fn validate(&self) -> Result<(), BlockError> {
        self.header.validate_basic()?;

        // Verify transaction root
        let computed_root = self.compute_tx_root();
        if computed_root != self.header.tx_root {
            return Err(BlockError::InvalidTxRoot);
        }

        // Verify gas accounting
        let total_gas: u64 = self.transactions
            .iter()
            .map(|tx| tx.transaction.gas_limit)
            .sum();

        if total_gas > self.header.gas_limit {
            return Err(BlockError::GasExceedsLimit);
        }

        Ok(())
    }
}

/// Validator attestation for a block
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Block hash being attested
    pub block_hash: BlockHash,
    /// Block height
    pub height: u64,
    /// Validator address
    pub validator: Address,
    /// Signature over (block_hash, height)
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
    /// Validator's stake at time of attestation
    pub stake: u64,
}

impl Attestation {
    /// Get signing message
    pub fn signing_message(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(&self.block_hash.0);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(b"chainmesh-attest-v1");
        hasher.finalize()
    }
}

/// Compute Merkle root from a list of hashes
pub fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current_level: Vec<[u8; 32]> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let mut hasher = MuHash::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]); // Duplicate if odd
            }
            next_level.push(hasher.finalize());
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Block-related errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("Invalid block version")]
    InvalidVersion,
    #[error("Extra data too long")]
    ExtraDataTooLong,
    #[error("Gas used exceeds gas limit")]
    GasExceedsLimit,
    #[error("Invalid parent hash")]
    InvalidParentHash,
    #[error("Invalid transaction root")]
    InvalidTxRoot,
    #[error("Invalid validator signature")]
    InvalidSignature,
    #[error("Block not found")]
    NotFound,
    #[error("Block already exists")]
    AlreadyExists,
    #[error("Invalid block height")]
    InvalidHeight,
    #[error("Timestamp too far in future")]
    FutureTimestamp,
    #[error("Timestamp before parent")]
    TimestampBeforeParent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_hash() {
        let header = BlockHeader::new(
            1,
            BlockHash::ZERO,
            Address::system(),
            1234567890,
        );

        let hash = header.hash();
        assert!(!hash.is_zero());

        // Hash should be deterministic
        let hash2 = header.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(0);

        assert_eq!(genesis.height(), 0);
        assert!(genesis.header.parent_hash.is_zero());
        assert!(genesis.header.is_genesis());
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];

        let root = compute_merkle_root(&hashes);
        assert!(!root.iter().all(|&b| b == 0));

        // Single element
        let single_root = compute_merkle_root(&[[5u8; 32]]);
        assert_eq!(single_root, [5u8; 32]);

        // Empty
        let empty_root = compute_merkle_root(&[]);
        assert_eq!(empty_root, [0u8; 32]);
    }

    #[test]
    fn test_block_validation() {
        let mut block = Block::genesis(0);
        assert!(block.validate().is_ok());

        // Invalid gas
        block.header.gas_used = block.header.gas_limit + 1;
        assert!(matches!(block.validate(), Err(BlockError::GasExceedsLimit)));
    }
}
