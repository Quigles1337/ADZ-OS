//! Block Reward Distribution
//!
//! Handles calculation and distribution of block rewards to validators
//! and their delegators.
//!
//! ## Reward Sources
//! - Block reward (inflation schedule)
//! - Transaction fees
//!
//! ## Distribution
//! - Proposer bonus (5% of block reward)
//! - Remaining split by stake weight
//! - Validator commission applied to delegator rewards

use crate::types::{Address, MuCoin, Block};
use crate::types::token::{INITIAL_BLOCK_REWARD, HALVING_INTERVAL};
use super::{ValidatorSet, ValidatorEntry};
use std::collections::HashMap;

/// Reward calculator for block rewards
#[derive(Debug, Clone)]
pub struct RewardCalculator {
    /// Proposer bonus (basis points of block reward)
    pub proposer_bonus_bps: u16,
    /// Community pool share (basis points)
    pub community_pool_bps: u16,
}

impl Default for RewardCalculator {
    fn default() -> Self {
        Self {
            proposer_bonus_bps: 500,  // 5% proposer bonus
            community_pool_bps: 200,  // 2% to community pool
        }
    }
}

impl RewardCalculator {
    /// Create with custom parameters
    pub fn new(proposer_bonus_bps: u16, community_pool_bps: u16) -> Self {
        Self {
            proposer_bonus_bps: proposer_bonus_bps.min(5000), // Max 50%
            community_pool_bps: community_pool_bps.min(2000), // Max 20%
        }
    }

    /// Calculate block reward for a given height
    pub fn block_reward(height: u64) -> MuCoin {
        MuCoin::block_reward(height)
    }

    /// Calculate total fees from a block
    pub fn total_fees(block: &Block) -> MuCoin {
        block.transactions.iter()
            .fold(MuCoin::ZERO, |acc, tx| {
                let fee = MuCoin::from_muons(
                    tx.transaction.gas_price.saturating_mul(tx.transaction.gas_limit)
                );
                acc + fee
            })
    }

    /// Calculate reward distribution for a block
    pub fn calculate_distribution(
        &self,
        height: u64,
        proposer: &Address,
        validators: &ValidatorSet,
        total_fees: MuCoin,
    ) -> RewardDistribution {
        let block_reward = Self::block_reward(height);
        let total_reward = block_reward + total_fees;

        // Community pool allocation
        let community_pool = total_reward.percentage(self.community_pool_bps as u64);

        // Remaining after community pool
        let distributable = total_reward - community_pool;

        // Proposer bonus
        let proposer_bonus = distributable.percentage(self.proposer_bonus_bps as u64);

        // Remaining for stake-weighted distribution
        let stake_rewards = distributable - proposer_bonus;

        // Calculate per-validator rewards based on stake
        let total_stake = validators.total_stake();
        let mut validator_rewards = HashMap::new();

        if !total_stake.is_zero() {
            for validator in validators.active_validators() {
                // Stake-weighted share
                let stake_share_bps = (validator.stake.muons() * 10000) / total_stake.muons();
                let base_reward = stake_rewards.percentage(stake_share_bps);

                // Add proposer bonus if this is the proposer
                let total_validator_reward = if &validator.address == proposer {
                    base_reward + proposer_bonus
                } else {
                    base_reward
                };

                if !total_validator_reward.is_zero() {
                    let commission = validator.commission(total_validator_reward);
                    validator_rewards.insert(
                        validator.address.clone(),
                        ValidatorReward {
                            base_reward,
                            proposer_bonus: if &validator.address == proposer { proposer_bonus } else { MuCoin::ZERO },
                            commission,
                            delegator_pool: total_validator_reward - commission,
                        },
                    );
                }
            }
        }

        RewardDistribution {
            height,
            block_reward,
            total_fees,
            community_pool,
            proposer_bonus,
            validator_rewards,
        }
    }

    /// Calculate cumulative rewards for an epoch
    pub fn epoch_rewards(
        &self,
        start_height: u64,
        num_blocks: u64,
    ) -> MuCoin {
        let mut total = MuCoin::ZERO;
        for h in start_height..start_height + num_blocks {
            total = total + Self::block_reward(h);
        }
        total
    }

    /// Estimate annual inflation rate at a given height
    pub fn annual_inflation_rate(height: u64) -> f64 {
        // Assuming 6-second blocks
        let blocks_per_year = 365 * 24 * 60 * 60 / 6;
        let reward_per_block = Self::block_reward(height).muons();
        let annual_reward = reward_per_block as f64 * blocks_per_year as f64;

        // Calculate total supply at this height
        let total_supply = calculate_circulating_supply(height);

        if total_supply == 0 {
            0.0
        } else {
            (annual_reward / total_supply as f64) * 100.0
        }
    }
}

/// Distribution of rewards for a single block
#[derive(Debug, Clone)]
pub struct RewardDistribution {
    /// Block height
    pub height: u64,
    /// Base block reward
    pub block_reward: MuCoin,
    /// Total transaction fees
    pub total_fees: MuCoin,
    /// Amount to community pool
    pub community_pool: MuCoin,
    /// Proposer bonus amount
    pub proposer_bonus: MuCoin,
    /// Per-validator rewards
    pub validator_rewards: HashMap<Address, ValidatorReward>,
}

impl RewardDistribution {
    /// Get total rewards distributed
    pub fn total_distributed(&self) -> MuCoin {
        self.validator_rewards.values()
            .fold(MuCoin::ZERO, |acc, r| acc + r.total())
            + self.community_pool
    }

    /// Get reward for a specific validator
    pub fn get_validator_reward(&self, address: &Address) -> Option<&ValidatorReward> {
        self.validator_rewards.get(address)
    }
}

/// Reward breakdown for a single validator
#[derive(Debug, Clone)]
pub struct ValidatorReward {
    /// Base stake-weighted reward
    pub base_reward: MuCoin,
    /// Proposer bonus (only for block proposer)
    pub proposer_bonus: MuCoin,
    /// Validator's commission
    pub commission: MuCoin,
    /// Amount available for delegators
    pub delegator_pool: MuCoin,
}

impl ValidatorReward {
    /// Get total reward before commission
    pub fn total(&self) -> MuCoin {
        self.base_reward + self.proposer_bonus
    }

    /// Get validator's take (commission + self-stake portion)
    pub fn validator_take(&self) -> MuCoin {
        self.commission
    }
}

/// Calculate circulating supply at a given block height
fn calculate_circulating_supply(height: u64) -> u64 {
    let mut supply = 0u64;
    let mut reward = INITIAL_BLOCK_REWARD;
    let mut blocks_counted = 0u64;

    while blocks_counted < height {
        let halving_epoch = blocks_counted / HALVING_INTERVAL;
        let epoch_end = (halving_epoch + 1) * HALVING_INTERVAL;
        let blocks_in_this_epoch = (epoch_end.min(height) - blocks_counted).min(height - blocks_counted);

        supply = supply.saturating_add(reward.saturating_mul(blocks_in_this_epoch));
        blocks_counted += blocks_in_this_epoch;

        // Halving
        if blocks_counted % HALVING_INTERVAL == 0 && blocks_counted > 0 {
            reward /= 2;
        }
    }

    supply
}

/// Delegator reward calculator
#[derive(Debug)]
pub struct DelegatorRewards {
    /// Accumulated rewards by delegator
    rewards: HashMap<Address, MuCoin>,
}

impl DelegatorRewards {
    /// Create new delegator rewards tracker
    pub fn new() -> Self {
        Self {
            rewards: HashMap::new(),
        }
    }

    /// Distribute validator's delegator pool to delegators
    pub fn distribute(
        &mut self,
        validator: &ValidatorEntry,
        delegator_pool: MuCoin,
        delegations: &[(Address, MuCoin)], // (delegator, amount)
    ) {
        // Total delegated to this validator
        let total_delegated: MuCoin = delegations.iter()
            .fold(MuCoin::ZERO, |acc, (_, amount)| acc + *amount);

        if total_delegated.is_zero() {
            // All goes to validator's self-stake
            *self.rewards.entry(validator.address.clone()).or_insert(MuCoin::ZERO) =
                self.rewards.get(&validator.address).unwrap_or(&MuCoin::ZERO).saturating_add(delegator_pool);
            return;
        }

        // Distribute proportionally
        for (delegator, amount) in delegations {
            let share_bps = (amount.muons() * 10000) / total_delegated.muons();
            let reward = delegator_pool.percentage(share_bps);

            *self.rewards.entry(delegator.clone()).or_insert(MuCoin::ZERO) =
                self.rewards.get(delegator).unwrap_or(&MuCoin::ZERO).saturating_add(reward);
        }
    }

    /// Get accumulated rewards for a delegator
    pub fn get(&self, delegator: &Address) -> MuCoin {
        *self.rewards.get(delegator).unwrap_or(&MuCoin::ZERO)
    }

    /// Claim rewards (returns and resets)
    pub fn claim(&mut self, delegator: &Address) -> MuCoin {
        self.rewards.remove(delegator).unwrap_or(MuCoin::ZERO)
    }

    /// Get all pending rewards
    pub fn all_pending(&self) -> &HashMap<Address, MuCoin> {
        &self.rewards
    }
}

impl Default for DelegatorRewards {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator::ValidatorStatus;
    use libmu_crypto::MuKeyPair;

    fn test_validator(seed: &[u8], stake_muc: u64, commission_bps: u16) -> ValidatorEntry {
        let keypair = MuKeyPair::from_seed(seed);
        let address = Address::from_public_key(keypair.public_key());
        // to_bytes() returns [u8; 64]
        ValidatorEntry::new(address, keypair.public_key().to_bytes(), MuCoin::from_muc(stake_muc), commission_bps)
    }

    fn test_validator_set() -> (ValidatorSet, Vec<Address>) {
        let mut set = ValidatorSet::with_config(10, MuCoin::from_muc(100));
        let v1 = test_validator(b"v1", 1000, 500);
        let v2 = test_validator(b"v2", 2000, 1000);
        let v3 = test_validator(b"v3", 1000, 500);

        let addrs = vec![v1.address.clone(), v2.address.clone(), v3.address.clone()];

        set.add(v1).unwrap();
        set.add(v2).unwrap();
        set.add(v3).unwrap();

        (set, addrs)
    }

    #[test]
    fn test_block_reward_halving() {
        let reward0 = RewardCalculator::block_reward(0);
        let reward_h1 = RewardCalculator::block_reward(HALVING_INTERVAL);
        let reward_h2 = RewardCalculator::block_reward(HALVING_INTERVAL * 2);

        assert_eq!(reward0.muons(), INITIAL_BLOCK_REWARD);
        assert_eq!(reward_h1.muons(), INITIAL_BLOCK_REWARD / 2);
        assert_eq!(reward_h2.muons(), INITIAL_BLOCK_REWARD / 4);
    }

    #[test]
    fn test_reward_distribution() {
        let (validators, addrs) = test_validator_set();
        let calculator = RewardCalculator::default();

        let dist = calculator.calculate_distribution(
            0,
            &addrs[0], // v1 is proposer
            &validators,
            MuCoin::from_muc(10), // 10 MUC in fees
        );

        // Check community pool (2%)
        let total = dist.block_reward + dist.total_fees;
        assert!(dist.community_pool.muons() > 0);

        // Check proposer bonus exists for v1
        let v1_reward = dist.get_validator_reward(&addrs[0]).unwrap();
        assert!(v1_reward.proposer_bonus.muons() > 0);

        // v2 has 2x stake so should get roughly 2x base reward
        let v2_reward = dist.get_validator_reward(&addrs[1]).unwrap();
        let v3_reward = dist.get_validator_reward(&addrs[2]).unwrap();

        // v2 base should be roughly 2x v3 base (they have same stake as v1)
        assert!(v2_reward.base_reward.muons() > v3_reward.base_reward.muons());
    }

    #[test]
    fn test_circulating_supply() {
        // At genesis
        let supply_0 = calculate_circulating_supply(0);
        assert_eq!(supply_0, 0);

        // After 1 block
        let supply_1 = calculate_circulating_supply(1);
        assert_eq!(supply_1, INITIAL_BLOCK_REWARD);

        // After 100 blocks
        let supply_100 = calculate_circulating_supply(100);
        assert_eq!(supply_100, INITIAL_BLOCK_REWARD * 100);
    }

    #[test]
    fn test_delegator_distribution() {
        let v = test_validator(b"validator", 1000, 1000); // 10% commission
        let mut rewards = DelegatorRewards::new();

        let d1 = Address::from_hex("0000000000000000000000000000000000000001").unwrap();
        let d2 = Address::from_hex("0000000000000000000000000000000000000002").unwrap();

        let delegations = vec![
            (d1.clone(), MuCoin::from_muc(100)),
            (d2.clone(), MuCoin::from_muc(300)),
        ];

        // Distribute 100 MUC
        rewards.distribute(&v, MuCoin::from_muc(100), &delegations);

        // d1 should get 25% (100/400), d2 should get 75% (300/400)
        assert_eq!(rewards.get(&d1).muc(), 25);
        assert_eq!(rewards.get(&d2).muc(), 75);
    }

    #[test]
    fn test_commission_calculation() {
        let v = test_validator(b"v", 1000, 1000); // 10% commission

        let reward = MuCoin::from_muc(100);
        let commission = v.commission(reward);

        assert_eq!(commission.muc(), 10);
    }

    #[test]
    fn test_annual_inflation_estimation() {
        let rate_0 = RewardCalculator::annual_inflation_rate(1);
        let rate_halving = RewardCalculator::annual_inflation_rate(HALVING_INTERVAL);

        // Rate should decrease after halving
        assert!(rate_0 > rate_halving);
    }
}
