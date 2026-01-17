//! μ-Proof-of-Stake Consensus Engine
//!
//! ChainMesh uses a novel proof-of-stake consensus mechanism based on
//! μ-cryptography principles:
//!
//! ## Key Features
//! - Stake weight calculated using V_Z quantization
//! - Validator selection via golden ratio distribution {n·φ}
//! - Finality through μ^8 closure cycles (8-block epochs)
//!
//! ## Modules
//! - `mu_pos` - Core μ-PoS consensus logic
//! - `validator` - Validator set management
//! - `epoch` - Epoch and finality tracking
//! - `reward` - Block reward distribution

pub mod mu_pos;
pub mod validator;
pub mod epoch;
pub mod reward;

pub use mu_pos::{MuPoS, ConsensusState, ProposerSelection};
pub use validator::{ValidatorSet, ValidatorEntry, ValidatorStatus};
pub use epoch::{Epoch, EpochState, Finality};
pub use reward::{RewardCalculator, RewardDistribution};

use crate::types::{Address, Block, BlockHash, MuCoin};

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Epoch length in blocks (8 for μ^8 = 1)
    pub epoch_length: u64,
    /// Minimum stake to become validator
    pub min_stake: MuCoin,
    /// Maximum validators per epoch
    pub max_validators: u32,
    /// Block time target (seconds)
    pub block_time: u64,
    /// Quorum threshold (basis points, 6667 = 2/3)
    pub quorum_bps: u16,
    /// Proposer bonus (basis points of block reward)
    pub proposer_bonus_bps: u16,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            epoch_length: 8,
            min_stake: MuCoin::from_muc(1000),
            max_validators: 100,
            block_time: 6,
            quorum_bps: 6667, // 2/3 + 1
            proposer_bonus_bps: 500, // 5% bonus
        }
    }
}

/// Consensus events for monitoring
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    /// New block proposed
    BlockProposed {
        height: u64,
        hash: BlockHash,
        proposer: Address,
    },
    /// Block finalized
    BlockFinalized {
        height: u64,
        hash: BlockHash,
    },
    /// New epoch started
    EpochStarted {
        epoch: u64,
        validators: Vec<Address>,
    },
    /// Validator slashed
    ValidatorSlashed {
        validator: Address,
        amount: MuCoin,
        reason: SlashingReason,
    },
}

/// Reasons for slashing a validator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashingReason {
    /// Signed two different blocks at same height
    DoubleSigning,
    /// Failed to produce block when selected
    Downtime,
    /// Produced invalid block
    InvalidBlock,
}

/// Consensus-related errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsensusError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("Invalid proposer for slot")]
    InvalidProposer,
    #[error("Block from future")]
    FutureBlock,
    #[error("Block too old")]
    StaleBlock,
    #[error("Invalid validator signature")]
    InvalidSignature,
    #[error("Insufficient stake: have {have}, need {need}")]
    InsufficientStake { have: MuCoin, need: MuCoin },
    #[error("Validator not found: {0}")]
    ValidatorNotFound(Address),
    #[error("Validator already exists")]
    ValidatorExists,
    #[error("Not enough validators for quorum")]
    NoQuorum,
    #[error("Epoch not found: {0}")]
    EpochNotFound(u64),
    #[error("Block not finalized")]
    NotFinalized,
    #[error("Fork detected at height {0}")]
    ForkDetected(u64),
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;
