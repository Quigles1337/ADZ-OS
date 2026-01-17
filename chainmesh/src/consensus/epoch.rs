//! Epoch and Finality Management
//!
//! Epochs in ChainMesh are 8 blocks long, based on the μ^8 = 1 closure property.
//! Finality is achieved after 2/3 of validators attest to an epoch.

use crate::types::{Address, BlockHash, MuCoin};
use super::{ConsensusError, ConsensusResult, ValidatorSet};
use std::collections::{HashMap, HashSet};

/// Length of an epoch in blocks (μ^8 = 1)
pub const EPOCH_LENGTH: u64 = 8;

/// Quorum threshold for finalization (2/3 in basis points)
pub const FINALITY_QUORUM_BPS: u16 = 6667;

/// An epoch in the blockchain
#[derive(Debug, Clone)]
pub struct Epoch {
    /// Epoch number
    pub number: u64,
    /// Starting block height
    pub start_height: u64,
    /// Ending block height (inclusive)
    pub end_height: u64,
    /// Validator set for this epoch
    pub validators: ValidatorSet,
    /// Block hashes in this epoch
    pub blocks: Vec<BlockHash>,
    /// Attestations received for each block
    pub attestations: HashMap<BlockHash, HashSet<Address>>,
    /// Current state
    pub state: EpochState,
    /// Total stake that has attested
    pub attested_stake: MuCoin,
}

impl Epoch {
    /// Create a new epoch
    pub fn new(number: u64, validators: ValidatorSet) -> Self {
        Self {
            number,
            start_height: number * EPOCH_LENGTH,
            end_height: (number + 1) * EPOCH_LENGTH - 1,
            validators,
            blocks: Vec::with_capacity(EPOCH_LENGTH as usize),
            attestations: HashMap::new(),
            state: EpochState::Active,
            attested_stake: MuCoin::ZERO,
        }
    }

    /// Add a block to the epoch
    pub fn add_block(&mut self, hash: BlockHash) -> ConsensusResult<()> {
        if self.blocks.len() >= EPOCH_LENGTH as usize {
            return Err(ConsensusError::InvalidBlock("Epoch full".into()));
        }
        self.blocks.push(hash);
        self.attestations.insert(hash, HashSet::new());
        Ok(())
    }

    /// Add an attestation from a validator
    pub fn add_attestation(&mut self, block_hash: &BlockHash, validator: Address) -> ConsensusResult<()> {
        let attesters = self.attestations.get_mut(block_hash)
            .ok_or_else(|| ConsensusError::InvalidBlock("Block not in epoch".into()))?;

        if attesters.contains(&validator) {
            return Ok(()); // Already attested
        }

        // Get validator stake
        let stake = self.validators.get(&validator)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(validator.clone()))?
            .stake;

        attesters.insert(validator);
        self.attested_stake = self.attested_stake + stake;

        // Check if we've reached finality
        self.check_finality();

        Ok(())
    }

    /// Check if epoch has reached finality
    fn check_finality(&mut self) {
        let total_stake = self.validators.total_stake();
        if total_stake.is_zero() {
            return;
        }

        // Calculate attested percentage (basis points)
        let attested_bps = (self.attested_stake.muons() * 10000) / total_stake.muons();

        if attested_bps >= FINALITY_QUORUM_BPS as u64 {
            self.state = EpochState::Finalized;
        }
    }

    /// Get attestation count for a block
    pub fn attestation_count(&self, block_hash: &BlockHash) -> usize {
        self.attestations.get(block_hash)
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Get attestation stake for a block
    pub fn attestation_stake(&self, block_hash: &BlockHash) -> MuCoin {
        self.attestations.get(block_hash)
            .map(|attesters| {
                attesters.iter()
                    .filter_map(|addr| self.validators.get(addr))
                    .fold(MuCoin::ZERO, |acc, v| acc + v.stake)
            })
            .unwrap_or(MuCoin::ZERO)
    }

    /// Check if epoch is finalized
    pub fn is_finalized(&self) -> bool {
        self.state == EpochState::Finalized
    }

    /// Check if epoch is complete (all 8 blocks)
    pub fn is_complete(&self) -> bool {
        self.blocks.len() >= EPOCH_LENGTH as usize
    }

    /// Get block height for slot within epoch
    pub fn slot_to_height(&self, slot: u8) -> u64 {
        self.start_height + slot as u64
    }

    /// Get slot for a block height
    pub fn height_to_slot(&self, height: u64) -> Option<u8> {
        if height >= self.start_height && height <= self.end_height {
            Some((height - self.start_height) as u8)
        } else {
            None
        }
    }
}

/// State of an epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    /// Epoch is in progress
    Active,
    /// Epoch completed but not finalized
    Pending,
    /// Epoch has reached finality
    Finalized,
    /// Epoch was abandoned (fork)
    Orphaned,
}

/// Finality tracker across epochs
#[derive(Debug)]
pub struct Finality {
    /// Current epoch number
    pub current_epoch: u64,
    /// Last finalized epoch
    pub finalized_epoch: u64,
    /// Last finalized block hash
    pub finalized_hash: BlockHash,
    /// Last finalized block height
    pub finalized_height: u64,
    /// Recent epochs (for reorg handling)
    epochs: HashMap<u64, Epoch>,
    /// Configuration
    lookback_epochs: u64,
}

impl Finality {
    /// Create new finality tracker
    pub fn new() -> Self {
        Self {
            current_epoch: 0,
            finalized_epoch: 0,
            finalized_hash: BlockHash::ZERO,
            finalized_height: 0,
            epochs: HashMap::new(),
            lookback_epochs: 3, // Keep last 3 epochs for reorg
        }
    }

    /// Initialize with genesis epoch
    pub fn from_genesis(genesis_hash: BlockHash, validators: ValidatorSet) -> Self {
        let mut finality = Self::new();
        let mut epoch0 = Epoch::new(0, validators);
        epoch0.add_block(genesis_hash).ok();
        finality.epochs.insert(0, epoch0);
        finality.finalized_hash = genesis_hash;
        finality
    }

    /// Start a new epoch
    pub fn start_epoch(&mut self, validators: ValidatorSet) -> ConsensusResult<&Epoch> {
        let epoch_num = self.current_epoch + 1;
        let epoch = Epoch::new(epoch_num, validators);
        self.epochs.insert(epoch_num, epoch);
        self.current_epoch = epoch_num;

        // Clean up old epochs
        self.cleanup_old_epochs();

        Ok(self.epochs.get(&epoch_num).unwrap())
    }

    /// Get current epoch
    pub fn current(&self) -> Option<&Epoch> {
        self.epochs.get(&self.current_epoch)
    }

    /// Get current epoch mutably
    pub fn current_mut(&mut self) -> Option<&mut Epoch> {
        self.epochs.get_mut(&self.current_epoch)
    }

    /// Get epoch by number
    pub fn get_epoch(&self, number: u64) -> Option<&Epoch> {
        self.epochs.get(&number)
    }

    /// Add block to current epoch
    pub fn add_block(&mut self, height: u64, hash: BlockHash) -> ConsensusResult<()> {
        let expected_epoch = height / EPOCH_LENGTH;

        // Check for epoch transition
        if expected_epoch > self.current_epoch {
            // Need to finalize current epoch first
            if let Some(epoch) = self.epochs.get(&self.current_epoch) {
                if epoch.is_complete() && epoch.is_finalized() {
                    // Update finality
                    if let Some(last_hash) = epoch.blocks.last() {
                        self.finalized_hash = *last_hash;
                        self.finalized_height = epoch.end_height;
                        self.finalized_epoch = epoch.number;
                    }
                }
            }
        }

        // Add to appropriate epoch
        let epoch = self.epochs.get_mut(&expected_epoch)
            .ok_or(ConsensusError::EpochNotFound(expected_epoch))?;

        epoch.add_block(hash)
    }

    /// Add attestation
    pub fn add_attestation(
        &mut self,
        height: u64,
        block_hash: &BlockHash,
        validator: Address,
    ) -> ConsensusResult<()> {
        let epoch_num = height / EPOCH_LENGTH;
        let epoch = self.epochs.get_mut(&epoch_num)
            .ok_or(ConsensusError::EpochNotFound(epoch_num))?;

        epoch.add_attestation(block_hash, validator)
    }

    /// Check if a height is finalized
    pub fn is_finalized(&self, height: u64) -> bool {
        height <= self.finalized_height
    }

    /// Get finalized block at height
    pub fn finalized_block_at(&self, height: u64) -> Option<&BlockHash> {
        if !self.is_finalized(height) {
            return None;
        }

        let epoch_num = height / EPOCH_LENGTH;
        let slot = (height % EPOCH_LENGTH) as usize;

        self.epochs.get(&epoch_num)
            .and_then(|e| e.blocks.get(slot))
    }

    /// Clean up epochs older than lookback
    fn cleanup_old_epochs(&mut self) {
        if self.current_epoch > self.lookback_epochs {
            let cutoff = self.current_epoch - self.lookback_epochs;
            self.epochs.retain(|&num, _| num >= cutoff);
        }
    }

    /// Get epoch for a block height
    pub fn epoch_for_height(height: u64) -> u64 {
        height / EPOCH_LENGTH
    }

    /// Get slot within epoch for a block height
    pub fn slot_for_height(height: u64) -> u8 {
        (height % EPOCH_LENGTH) as u8
    }

    /// Calculate how many blocks until next epoch
    pub fn blocks_until_next_epoch(&self, height: u64) -> u64 {
        EPOCH_LENGTH - (height % EPOCH_LENGTH)
    }
}

impl Default for Finality {
    fn default() -> Self {
        Self::new()
    }
}

/// Checkpoint for light client sync
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Epoch number
    pub epoch: u64,
    /// Block hash at end of epoch
    pub block_hash: BlockHash,
    /// Block height
    pub height: u64,
    /// State root at this point
    pub state_root: [u8; 32],
    /// Validator set hash
    pub validator_set_hash: [u8; 32],
}

impl Checkpoint {
    /// Create checkpoint from epoch
    pub fn from_epoch(epoch: &Epoch, state_root: [u8; 32]) -> Option<Self> {
        if !epoch.is_finalized() {
            return None;
        }

        let block_hash = *epoch.blocks.last()?;

        // Compute validator set hash
        let validator_set_hash = compute_validator_set_hash(&epoch.validators);

        Some(Self {
            epoch: epoch.number,
            block_hash,
            height: epoch.end_height,
            state_root,
            validator_set_hash,
        })
    }
}

/// Compute a hash of the validator set for checkpointing
fn compute_validator_set_hash(validators: &ValidatorSet) -> [u8; 32] {
    use libmu_crypto::MuHash;

    let mut hasher = MuHash::new();
    for v in validators.active_validators() {
        hasher.update(&v.address.bytes);
        hasher.update(&v.stake.muons().to_le_bytes());
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator::ValidatorEntry;
    use libmu_crypto::MuKeyPair;

    fn test_validator(seed: &[u8], stake_muc: u64) -> ValidatorEntry {
        let keypair = MuKeyPair::from_seed(seed);
        let address = Address::from_public_key(keypair.public_key());
        // to_bytes() returns [u8; 64]
        ValidatorEntry::new(address, keypair.public_key().to_bytes(), MuCoin::from_muc(stake_muc), 500)
    }

    fn test_validator_set() -> ValidatorSet {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        set.add(test_validator(b"v1", 1000)).unwrap();
        set.add(test_validator(b"v2", 1000)).unwrap();
        set.add(test_validator(b"v3", 1000)).unwrap();
        set
    }

    #[test]
    fn test_epoch_creation() {
        let validators = test_validator_set();
        let epoch = Epoch::new(0, validators);

        assert_eq!(epoch.number, 0);
        assert_eq!(epoch.start_height, 0);
        assert_eq!(epoch.end_height, 7);
        assert_eq!(epoch.state, EpochState::Active);
    }

    #[test]
    fn test_epoch_blocks() {
        let validators = test_validator_set();
        let mut epoch = Epoch::new(1, validators);

        for i in 0..8 {
            let hash = BlockHash::from_bytes([i as u8; 32]);
            epoch.add_block(hash).unwrap();
        }

        assert!(epoch.is_complete());
        assert_eq!(epoch.blocks.len(), 8);

        // Adding 9th block should fail
        let result = epoch.add_block(BlockHash::from_bytes([9u8; 32]));
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_finality() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        let v1 = test_validator(b"v1", 1000);
        let v2 = test_validator(b"v2", 1000);
        let v3 = test_validator(b"v3", 1000);

        let addr1 = v1.address.clone();
        let addr2 = v2.address.clone();
        let addr3 = v3.address.clone();

        set.add(v1).unwrap();
        set.add(v2).unwrap();
        set.add(v3).unwrap();

        let mut epoch = Epoch::new(0, set);
        let block_hash = BlockHash::from_bytes([1u8; 32]);
        epoch.add_block(block_hash).unwrap();

        // Add attestations
        epoch.add_attestation(&block_hash, addr1).unwrap();
        assert!(!epoch.is_finalized()); // 1/3 stake

        epoch.add_attestation(&block_hash, addr2).unwrap();
        assert!(!epoch.is_finalized()); // 2/3 stake exactly (need > 2/3)

        epoch.add_attestation(&block_hash, addr3).unwrap();
        assert!(epoch.is_finalized()); // 3/3 stake
    }

    #[test]
    fn test_slot_height_conversion() {
        let validators = test_validator_set();
        let epoch = Epoch::new(5, validators);

        assert_eq!(epoch.start_height, 40);
        assert_eq!(epoch.end_height, 47);

        assert_eq!(epoch.slot_to_height(0), 40);
        assert_eq!(epoch.slot_to_height(7), 47);

        assert_eq!(epoch.height_to_slot(40), Some(0));
        assert_eq!(epoch.height_to_slot(47), Some(7));
        assert_eq!(epoch.height_to_slot(48), None);
        assert_eq!(epoch.height_to_slot(39), None);
    }

    #[test]
    fn test_finality_tracker() {
        let validators = test_validator_set();
        let genesis = BlockHash::from_bytes([0u8; 32]);
        let mut finality = Finality::from_genesis(genesis, validators.clone());

        assert_eq!(finality.current_epoch, 0);
        assert_eq!(finality.finalized_hash, genesis);

        // Start new epoch
        finality.start_epoch(validators).unwrap();
        assert_eq!(finality.current_epoch, 1);
    }

    #[test]
    fn test_epoch_number_calculation() {
        assert_eq!(Finality::epoch_for_height(0), 0);
        assert_eq!(Finality::epoch_for_height(7), 0);
        assert_eq!(Finality::epoch_for_height(8), 1);
        assert_eq!(Finality::epoch_for_height(15), 1);
        assert_eq!(Finality::epoch_for_height(16), 2);
    }
}
