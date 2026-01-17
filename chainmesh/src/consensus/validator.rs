//! Validator Set Management
//!
//! Handles validator registration, delegation, slashing, and set transitions.

use crate::types::{Address, MuCoin};
use super::{ConsensusError, ConsensusResult};
use std::collections::HashMap;

/// Status of a validator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Validator is active and can participate
    Active,
    /// Validator is unbonding (waiting period)
    Unbonding,
    /// Validator is jailed (slashed, needs manual unjail)
    Jailed,
    /// Validator is tombstoned (permanently removed)
    Tombstoned,
}

/// A validator entry in the validator set
#[derive(Debug, Clone)]
pub struct ValidatorEntry {
    /// Validator address
    pub address: Address,
    /// Validator's public key for signing (64 bytes for μ-signatures)
    pub pubkey: [u8; 64],
    /// Self-bonded stake
    pub stake: MuCoin,
    /// Commission rate (basis points)
    pub commission_bps: u16,
    /// Current status
    pub status: ValidatorStatus,
    /// Block height until which validator is jailed (if jailed)
    pub jailed_until: Option<u64>,
}

impl ValidatorEntry {
    /// Create a new validator entry
    pub fn new(address: Address, pubkey: [u8; 64], stake: MuCoin, commission_bps: u16) -> Self {
        Self {
            address,
            pubkey,
            stake,
            commission_bps: commission_bps.min(10000),
            status: ValidatorStatus::Active,
            jailed_until: None,
        }
    }

    /// Check if validator is active
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Calculate commission for a reward amount
    pub fn commission(&self, reward: MuCoin) -> MuCoin {
        reward.percentage(self.commission_bps as u64)
    }
}

/// The active validator set for an epoch
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// All validators by address
    validators: HashMap<Address, ValidatorEntry>,
    /// Ordered list of active validators (by stake, descending)
    active_order: Vec<Address>,
    /// Maximum number of active validators
    max_validators: u32,
    /// Minimum stake required
    min_stake: MuCoin,
}

impl ValidatorSet {
    /// Create empty validator set
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            active_order: Vec::new(),
            max_validators: 100,
            min_stake: MuCoin::from_muc(1000),
        }
    }

    /// Create with custom parameters
    pub fn with_config(max_validators: u32, min_stake: MuCoin) -> Self {
        Self {
            validators: HashMap::new(),
            active_order: Vec::new(),
            max_validators,
            min_stake,
        }
    }

    /// Add a new validator
    pub fn add(&mut self, entry: ValidatorEntry) -> ConsensusResult<()> {
        if self.validators.contains_key(&entry.address) {
            return Err(ConsensusError::ValidatorExists);
        }

        if entry.stake < self.min_stake {
            return Err(ConsensusError::InsufficientStake {
                have: entry.stake,
                need: self.min_stake,
            });
        }

        let address = entry.address.clone();
        self.validators.insert(address.clone(), entry);
        self.recompute_active_order();

        Ok(())
    }

    /// Remove a validator
    pub fn remove(&mut self, address: &Address) -> ConsensusResult<ValidatorEntry> {
        let entry = self.validators.remove(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;
        self.recompute_active_order();
        Ok(entry)
    }

    /// Get validator by address
    pub fn get(&self, address: &Address) -> Option<&ValidatorEntry> {
        self.validators.get(address)
    }

    /// Get mutable validator by address
    pub fn get_mut(&mut self, address: &Address) -> Option<&mut ValidatorEntry> {
        self.validators.get_mut(address)
    }

    /// Get all active validators (references to entries)
    pub fn active_validators(&self) -> Vec<&ValidatorEntry> {
        self.active_order.iter()
            .filter_map(|addr| self.validators.get(addr))
            .filter(|v| v.is_active())
            .take(self.max_validators as usize)
            .collect()
    }

    /// Get number of active validators
    pub fn active_count(&self) -> usize {
        self.active_validators().len()
    }

    /// Get total stake of all active validators
    pub fn total_stake(&self) -> MuCoin {
        self.active_validators()
            .iter()
            .fold(MuCoin::ZERO, |acc, v| acc + v.stake)
    }

    /// Update validator stake
    pub fn update_stake(&mut self, address: &Address, new_stake: MuCoin) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        validator.stake = new_stake;
        self.recompute_active_order();

        Ok(())
    }

    /// Jail a validator
    pub fn jail(&mut self, address: &Address, until_height: u64) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        validator.status = ValidatorStatus::Jailed;
        validator.jailed_until = Some(until_height);
        self.recompute_active_order();

        Ok(())
    }

    /// Unjail a validator (if jail period has passed)
    pub fn unjail(&mut self, address: &Address, current_height: u64) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        if validator.status != ValidatorStatus::Jailed {
            return Ok(()); // Not jailed
        }

        if let Some(until) = validator.jailed_until {
            if current_height < until {
                return Err(ConsensusError::InvalidBlock("Jail period not over".into()));
            }
        }

        validator.status = ValidatorStatus::Active;
        validator.jailed_until = None;
        self.recompute_active_order();

        Ok(())
    }

    /// Tombstone a validator (permanent removal from active set)
    pub fn tombstone(&mut self, address: &Address) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        validator.status = ValidatorStatus::Tombstoned;
        self.recompute_active_order();

        Ok(())
    }

    /// Slash a validator's stake
    pub fn slash(&mut self, address: &Address, slash_bps: u16) -> ConsensusResult<MuCoin> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        let slash_amount = validator.stake.percentage(slash_bps as u64);
        validator.stake = validator.stake.saturating_sub(slash_amount);

        // Check if stake fell below minimum
        if validator.stake < self.min_stake {
            validator.status = ValidatorStatus::Unbonding;
        }

        self.recompute_active_order();

        Ok(slash_amount)
    }

    /// Begin unbonding for a validator
    pub fn begin_unbonding(&mut self, address: &Address) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(address.clone()))?;

        validator.status = ValidatorStatus::Unbonding;
        self.recompute_active_order();

        Ok(())
    }

    /// Recompute the active validator ordering by stake
    fn recompute_active_order(&mut self) {
        let mut entries: Vec<_> = self.validators.iter()
            .filter(|(_, v)| v.is_active())
            .collect();

        // Sort by stake descending, then by address for determinism
        entries.sort_by(|(addr_a, a), (addr_b, b)| {
            b.stake.cmp(&a.stake)
                .then_with(|| addr_a.bytes.cmp(&addr_b.bytes))
        });

        self.active_order = entries.into_iter()
            .map(|(addr, _)| addr.clone())
            .collect();
    }

    /// Check if we have enough validators for consensus
    pub fn has_quorum(&self, quorum_count: usize) -> bool {
        self.active_count() >= quorum_count
    }

    /// Get validator at position in stake-ordered list
    pub fn get_by_rank(&self, rank: usize) -> Option<&ValidatorEntry> {
        self.active_order.get(rank)
            .and_then(|addr| self.validators.get(addr))
    }

    /// Iterator over all validators
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorEntry> {
        self.validators.values()
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Delegation record
#[derive(Debug, Clone)]
pub struct Delegation {
    /// Delegator address
    pub delegator: Address,
    /// Validator address
    pub validator: Address,
    /// Delegated amount
    pub amount: MuCoin,
    /// Accumulated rewards
    pub rewards: MuCoin,
    /// Shares in validator's delegation pool
    pub shares: u64,
}

impl Delegation {
    /// Create new delegation
    pub fn new(delegator: Address, validator: Address, amount: MuCoin) -> Self {
        Self {
            delegator,
            validator,
            amount,
            rewards: MuCoin::ZERO,
            shares: amount.muons(), // 1:1 initial share ratio
        }
    }

    /// Add rewards
    pub fn add_rewards(&mut self, amount: MuCoin) {
        self.rewards = self.rewards.saturating_add(amount);
    }

    /// Claim accumulated rewards
    pub fn claim_rewards(&mut self) -> MuCoin {
        let claimed = self.rewards;
        self.rewards = MuCoin::ZERO;
        claimed
    }
}

/// Unbonding entry for stake being withdrawn
#[derive(Debug, Clone)]
pub struct UnbondingEntry {
    /// Address withdrawing
    pub delegator: Address,
    /// Validator being withdrawn from
    pub validator: Address,
    /// Amount being unbonded
    pub amount: MuCoin,
    /// Block height when unbonding completes
    pub completion_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmu_crypto::MuKeyPair;

    fn test_validator(seed: &[u8], stake_muc: u64) -> ValidatorEntry {
        let keypair = MuKeyPair::from_seed(seed);
        let address = Address::from_public_key(keypair.public_key());
        // to_bytes() returns [u8; 64]
        ValidatorEntry::new(address, keypair.public_key().to_bytes(), MuCoin::from_muc(stake_muc), 500)
    }

    #[test]
    fn test_add_validator() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        let v = test_validator(b"test", 1000);

        assert!(set.add(v.clone()).is_ok());
        assert_eq!(set.active_count(), 1);
        assert!(set.get(&v.address).is_some());
    }

    #[test]
    fn test_insufficient_stake() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(1000));
        let v = test_validator(b"low_stake", 500);

        let result = set.add(v);
        assert!(matches!(result, Err(ConsensusError::InsufficientStake { .. })));
    }

    #[test]
    fn test_stake_ordering() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));

        let v1 = test_validator(b"v1", 1000);
        let v2 = test_validator(b"v2", 2000);
        let v3 = test_validator(b"v3", 1500);

        set.add(v1.clone()).unwrap();
        set.add(v2.clone()).unwrap();
        set.add(v3.clone()).unwrap();

        // Should be ordered by stake: v2, v3, v1
        let ranked = set.get_by_rank(0).unwrap();
        assert_eq!(ranked.stake.muc(), 2000);

        let ranked = set.get_by_rank(1).unwrap();
        assert_eq!(ranked.stake.muc(), 1500);
    }

    #[test]
    fn test_jail_unjail() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        let v = test_validator(b"jailable", 1000);
        let addr = v.address.clone();

        set.add(v).unwrap();
        assert_eq!(set.active_count(), 1);

        // Jail
        set.jail(&addr, 100).unwrap();
        assert_eq!(set.active_count(), 0);

        // Try unjail too early
        assert!(set.unjail(&addr, 50).is_err());

        // Unjail after period
        set.unjail(&addr, 100).unwrap();
        assert_eq!(set.active_count(), 1);
    }

    #[test]
    fn test_slashing() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        let v = test_validator(b"slashable", 1000);
        let addr = v.address.clone();

        set.add(v).unwrap();

        // Slash 5%
        let slashed = set.slash(&addr, 500).unwrap();
        assert_eq!(slashed.muc(), 50);

        let validator = set.get(&addr).unwrap();
        assert_eq!(validator.stake.muc(), 950);
    }

    #[test]
    fn test_total_stake() {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));

        set.add(test_validator(b"v1", 1000)).unwrap();
        set.add(test_validator(b"v2", 2000)).unwrap();
        set.add(test_validator(b"v3", 1500)).unwrap();

        assert_eq!(set.total_stake().muc(), 4500);
    }
}
