//! μ-Proof-of-Stake Core Consensus
//!
//! Implements the novel μ-PoS consensus using:
//! - Golden ratio quasirandom sequence for fair validator selection
//! - V_Z quantization for stake weight computation
//! - 8-block epochs based on μ^8 = 1 closure property

use crate::types::{Address, Block, BlockHash, BlockHeader, MuCoin, SignedTransaction};
use super::{ConsensusConfig, ConsensusError, ConsensusResult, ValidatorSet, ValidatorEntry};
use libmu_crypto::{MuHash, MuKeyPair, MuPublicKey, MuSignature};
use std::collections::HashMap;

/// Golden ratio for validator selection
const PHI: f64 = 1.618033988749895;

/// Fine-structure constant for V_Z quantization
const ALPHA: f64 = 1.0 / 137.035999084;

/// μ-Proof-of-Stake consensus engine
#[derive(Debug)]
pub struct MuPoS {
    /// Configuration
    config: ConsensusConfig,
    /// Current consensus state
    state: ConsensusState,
    /// Pending blocks awaiting validation
    pending_blocks: HashMap<BlockHash, Block>,
    /// Block proposals for current slot
    proposals: HashMap<u64, Vec<BlockProposal>>,
}

/// Current state of the consensus engine
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current block height
    pub height: u64,
    /// Current epoch number
    pub epoch: u64,
    /// Latest finalized block hash
    pub finalized_hash: BlockHash,
    /// Latest finalized height
    pub finalized_height: u64,
    /// Active validator set
    pub validators: ValidatorSet,
    /// Current slot within epoch (0-7)
    pub slot: u8,
    /// Total network stake
    pub total_stake: MuCoin,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            height: 0,
            epoch: 0,
            finalized_hash: BlockHash::ZERO,
            finalized_height: 0,
            validators: ValidatorSet::new(),
            slot: 0,
            total_stake: MuCoin::ZERO,
        }
    }
}

/// A block proposal from a validator
#[derive(Debug, Clone)]
pub struct BlockProposal {
    /// Proposed block
    pub block: Block,
    /// Proposer's public key
    pub proposer_pubkey: [u8; 32],
    /// Signature over block hash
    pub signature: [u8; 64],
}

/// Proposer selection result
#[derive(Debug, Clone)]
pub struct ProposerSelection {
    /// Selected validator address
    pub validator: Address,
    /// Selection weight (for tie-breaking)
    pub weight: u64,
    /// Slot in the epoch
    pub slot: u8,
    /// VRF proof (for verifiability)
    pub vrf_proof: [u8; 32],
}

impl MuPoS {
    /// Create new μ-PoS engine
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            state: ConsensusState::default(),
            pending_blocks: HashMap::new(),
            proposals: HashMap::new(),
        }
    }

    /// Initialize from genesis
    pub fn from_genesis(config: ConsensusConfig, genesis: &Block, validators: ValidatorSet) -> Self {
        let mut engine = Self::new(config);
        engine.state.validators = validators;
        engine.state.finalized_hash = genesis.hash();
        engine.state.total_stake = engine.state.validators.total_stake();
        engine
    }

    /// Get current consensus state
    pub fn state(&self) -> &ConsensusState {
        &self.state
    }

    /// Select proposer for a given height using golden ratio sequence
    ///
    /// The proposer is selected using:
    /// 1. Compute index = floor(height * φ) mod num_validators
    /// 2. Weight by V_Z quantized stake
    /// 3. Deterministic tie-breaking via block hash
    pub fn select_proposer(&self, height: u64, parent_hash: &BlockHash) -> ConsensusResult<ProposerSelection> {
        let validators = self.state.validators.active_validators();
        if validators.is_empty() {
            return Err(ConsensusError::NoQuorum);
        }

        // Golden ratio based index selection
        let phi_index = golden_sequence_index(height, validators.len());

        // Compute VRF-like proof for verifiability
        let vrf_input = compute_vrf_input(height, parent_hash);

        // Weight validators by V_Z quantized stake
        let weighted = self.compute_weighted_selection(&validators, &vrf_input);

        // Select based on golden ratio with stake weighting
        let selected_idx = self.select_by_weight(&weighted, phi_index);
        let selected = &validators[selected_idx];

        // Compute slot within epoch
        let slot = (height % self.config.epoch_length) as u8;

        Ok(ProposerSelection {
            validator: selected.address.clone(),
            weight: selected.stake.muons(),
            slot,
            vrf_proof: vrf_input,
        })
    }

    /// Propose a new block
    pub fn propose_block(
        &mut self,
        parent: &Block,
        transactions: Vec<SignedTransaction>,
        keypair: &MuKeyPair,
        timestamp: u64,
    ) -> ConsensusResult<Block> {
        let height = parent.height() + 1;
        let proposer = Address::from_public_key(keypair.public_key());

        // Verify we are the selected proposer
        let selection = self.select_proposer(height, &parent.hash())?;
        if selection.validator != proposer {
            return Err(ConsensusError::InvalidProposer);
        }

        // Create block header
        let mut header = BlockHeader::new(
            height,
            parent.hash(),
            proposer,
            timestamp,
        );

        // Set consensus fields
        header.total_stake = self.state.total_stake.muons();
        header.difficulty = compute_difficulty(height, self.state.total_stake);

        // Create block
        let mut block = Block::new(header, transactions);
        block.finalize_header();

        // Sign block
        let signing_msg = block.header.signing_message();
        let signature = keypair.sign(&signing_msg);
        block.header.validator_signature = signature.to_bytes();

        Ok(block)
    }

    /// Validate an incoming block
    pub fn validate_block(&self, block: &Block, parent: &Block) -> ConsensusResult<()> {
        // Basic structure validation
        block.validate()
            .map_err(|e| ConsensusError::InvalidBlock(e.to_string()))?;

        // Check height continuity
        if block.height() != parent.height() + 1 {
            return Err(ConsensusError::InvalidBlock("Invalid height".into()));
        }

        // Check parent hash
        if block.header.parent_hash != parent.hash() {
            return Err(ConsensusError::InvalidBlock("Invalid parent hash".into()));
        }

        // Check timestamp
        if block.header.timestamp <= parent.header.timestamp {
            return Err(ConsensusError::InvalidBlock("Timestamp not increasing".into()));
        }

        // Verify proposer selection
        let selection = self.select_proposer(block.height(), &parent.hash())?;
        if block.header.validator != selection.validator {
            return Err(ConsensusError::InvalidProposer);
        }

        // Verify validator signature
        self.verify_block_signature(block)?;

        Ok(())
    }

    /// Verify block signature from validator
    fn verify_block_signature(&self, block: &Block) -> ConsensusResult<()> {
        // Get validator's public key
        let validator = self.state.validators.get(&block.header.validator)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(block.header.validator.clone()))?;

        let pubkey = MuPublicKey::from_bytes(&validator.pubkey)
            .map_err(|_| ConsensusError::InvalidSignature)?;

        let signature = MuSignature::from_bytes(&block.header.validator_signature)
            .map_err(|_| ConsensusError::InvalidSignature)?;

        let signing_msg = block.header.signing_message();
        pubkey.verify(&signing_msg, &signature)
            .map_err(|_| ConsensusError::InvalidSignature)
    }

    /// Process a validated block
    pub fn process_block(&mut self, block: Block) -> ConsensusResult<()> {
        // Update state
        self.state.height = block.height();
        self.state.slot = (block.height() % self.config.epoch_length) as u8;

        // Check for epoch transition
        if self.state.slot == 0 && block.height() > 0 {
            self.transition_epoch()?;
        }

        // Add to pending if not yet finalized
        self.pending_blocks.insert(block.hash(), block);

        // Check for finalization (after epoch completion)
        self.try_finalize()?;

        Ok(())
    }

    /// Transition to new epoch
    fn transition_epoch(&mut self) -> ConsensusResult<()> {
        self.state.epoch += 1;

        // Recalculate validator set for new epoch
        // In production, this would consider unbonding, new registrations, etc.
        self.state.total_stake = self.state.validators.total_stake();

        Ok(())
    }

    /// Try to finalize blocks
    fn try_finalize(&mut self) -> ConsensusResult<()> {
        // Simple finalization: finalize after 2/3 epoch completion
        let finality_threshold = (self.config.epoch_length * 2) / 3;
        let blocks_in_epoch = self.state.slot as u64 + 1;

        if blocks_in_epoch >= finality_threshold {
            // Finalize all blocks in previous epoch
            let finalize_height = self.state.epoch * self.config.epoch_length;
            if finalize_height > self.state.finalized_height {
                // Find block at finalize height
                for (hash, block) in &self.pending_blocks {
                    if block.height() == finalize_height {
                        self.state.finalized_hash = *hash;
                        self.state.finalized_height = finalize_height;
                        break;
                    }
                }

                // Clean up old pending blocks
                self.pending_blocks.retain(|_, b| b.height() > self.state.finalized_height);
            }
        }

        Ok(())
    }

    /// Compute V_Z quantized stake weight
    ///
    /// Uses the formula: weight = stake * |V_Z|
    /// where V_Z = Z * α * μ and Z is derived from stake ranking
    fn compute_weighted_selection(&self, validators: &[&ValidatorEntry], vrf_input: &[u8; 32]) -> Vec<(usize, u64)> {
        let mut weights: Vec<(usize, u64)> = validators.iter()
            .enumerate()
            .map(|(i, v)| {
                let z = (i + 1) as f64; // Z quantization number
                let v_z_mag = z * ALPHA; // |V_Z| ≈ Z * α
                let stake = v.stake.muons() as f64;
                let weight = (stake * v_z_mag * 1000.0) as u64;
                (i, weight)
            })
            .collect();

        // Add VRF entropy for additional randomness
        let entropy = u64::from_le_bytes(vrf_input[0..8].try_into().unwrap());
        for (i, (_, weight)) in weights.iter_mut().enumerate() {
            // Mix in entropy without overwhelming stake weight
            *weight = weight.saturating_add((entropy >> (i % 64)) & 0xFF);
        }

        weights
    }

    /// Select validator by combined golden ratio index and stake weight
    fn select_by_weight(&self, weighted: &[(usize, u64)], phi_index: usize) -> usize {
        if weighted.is_empty() {
            return 0;
        }

        // Start from golden ratio index, select highest weighted in window
        let window_size = 3.min(weighted.len());
        let start = phi_index % weighted.len();

        let mut best_idx = start;
        let mut best_weight = 0;

        for i in 0..window_size {
            let idx = (start + i) % weighted.len();
            if weighted[idx].1 > best_weight {
                best_weight = weighted[idx].1;
                best_idx = idx;
            }
        }

        weighted[best_idx].0
    }
}

/// Compute golden sequence index: floor(n * φ) mod size
fn golden_sequence_index(n: u64, size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    let phi_n = (n as f64 * PHI).floor() as u64;
    (phi_n % size as u64) as usize
}

/// Compute VRF-like input from height and parent hash
fn compute_vrf_input(height: u64, parent_hash: &BlockHash) -> [u8; 32] {
    let mut hasher = MuHash::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(&parent_hash.0);
    hasher.update(b"chainmesh-vrf-v1");
    hasher.finalize()
}

/// Compute block difficulty based on height and stake
fn compute_difficulty(height: u64, total_stake: MuCoin) -> u64 {
    // Simple difficulty: based on total stake
    // Higher stake = more security = higher "difficulty"
    let base = total_stake.muons() / 1_000_000_000; // Normalize
    (base.max(1) + height / 1000).min(u64::MAX / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::token::MIN_VALIDATOR_STAKE;

    fn create_test_validator(seed: &[u8]) -> (ValidatorEntry, MuKeyPair) {
        let keypair = MuKeyPair::from_seed(seed);
        let address = Address::from_public_key(keypair.public_key());
        // to_bytes() returns [u8; 64]
        let entry = ValidatorEntry {
            address,
            pubkey: keypair.public_key().to_bytes(),
            stake: MuCoin::from_muons(MIN_VALIDATOR_STAKE),
            commission_bps: 500,
            status: super::super::validator::ValidatorStatus::Active,
            jailed_until: None,
        };
        (entry, keypair)
    }

    #[test]
    fn test_golden_sequence_distribution() {
        // Test that golden sequence provides good distribution
        let mut counts = vec![0u32; 10];
        for i in 0..1000 {
            let idx = golden_sequence_index(i, 10);
            counts[idx] += 1;
        }

        // Each validator should be selected roughly equally
        for count in &counts {
            assert!(*count > 50 && *count < 150, "Uneven distribution: {:?}", counts);
        }
    }

    #[test]
    fn test_proposer_selection_deterministic() {
        let config = ConsensusConfig::default();
        let mut engine = MuPoS::new(config);

        // Add validators
        let (v1, _) = create_test_validator(b"validator1");
        let (v2, _) = create_test_validator(b"validator2");
        let (v3, _) = create_test_validator(b"validator3");

        engine.state.validators.add(v1).unwrap();
        engine.state.validators.add(v2).unwrap();
        engine.state.validators.add(v3).unwrap();
        engine.state.total_stake = engine.state.validators.total_stake();

        let parent_hash = BlockHash::ZERO;

        // Same inputs should give same output
        let sel1 = engine.select_proposer(100, &parent_hash).unwrap();
        let sel2 = engine.select_proposer(100, &parent_hash).unwrap();

        assert_eq!(sel1.validator, sel2.validator);
        assert_eq!(sel1.slot, sel2.slot);
    }

    #[test]
    fn test_vrf_input_uniqueness() {
        let h1 = BlockHash::from_bytes([1u8; 32]);
        let h2 = BlockHash::from_bytes([2u8; 32]);

        let vrf1 = compute_vrf_input(100, &h1);
        let vrf2 = compute_vrf_input(100, &h2);
        let vrf3 = compute_vrf_input(101, &h1);

        assert_ne!(vrf1, vrf2);
        assert_ne!(vrf1, vrf3);
    }
}
