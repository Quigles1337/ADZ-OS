//! Account state and management
//!
//! Accounts in ChainMesh track:
//! - MUC balance
//! - Nonce (transaction counter)
//! - Staking state
//! - Contract code (if applicable)

use super::{Address, MuCoin, TokenId};
use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Account state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Account address
    pub address: Address,
    /// MUC balance
    pub balance: MuCoin,
    /// Transaction nonce
    pub nonce: u64,
    /// Staked amount (self-staked)
    pub staked: MuCoin,
    /// Delegated stake (from others)
    pub delegated: MuCoin,
    /// Account type-specific state
    pub state: AccountState,
    /// Custom token balances
    pub token_balances: HashMap<[u8; 32], u64>,
    /// NFTs owned (token_id -> true)
    pub nfts: HashMap<[u8; 32], bool>,
}

impl Account {
    /// Create a new empty account
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: MuCoin::ZERO,
            nonce: 0,
            staked: MuCoin::ZERO,
            delegated: MuCoin::ZERO,
            state: AccountState::User,
            token_balances: HashMap::new(),
            nfts: HashMap::new(),
        }
    }

    /// Create account with initial balance
    pub fn with_balance(address: Address, balance: MuCoin) -> Self {
        let mut account = Self::new(address);
        account.balance = balance;
        account
    }

    /// Get total balance (available + staked)
    pub fn total_balance(&self) -> MuCoin {
        self.balance + self.staked
    }

    /// Get available balance (not staked)
    pub fn available_balance(&self) -> MuCoin {
        self.balance
    }

    /// Check if account can afford a transfer
    pub fn can_afford(&self, amount: MuCoin, fee: MuCoin) -> bool {
        self.balance >= amount + fee
    }

    /// Deduct balance (for sending)
    pub fn deduct(&mut self, amount: MuCoin) -> Result<(), AccountError> {
        self.balance = self.balance.checked_sub(amount)
            .ok_or(AccountError::InsufficientBalance)?;
        Ok(())
    }

    /// Credit balance (for receiving)
    pub fn credit(&mut self, amount: MuCoin) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.wrapping_add(1);
    }

    /// Stake tokens
    pub fn stake(&mut self, amount: MuCoin) -> Result<(), AccountError> {
        self.balance = self.balance.checked_sub(amount)
            .ok_or(AccountError::InsufficientBalance)?;
        self.staked = self.staked.saturating_add(amount);
        Ok(())
    }

    /// Unstake tokens (moves to pending)
    pub fn unstake(&mut self, amount: MuCoin) -> Result<(), AccountError> {
        self.staked = self.staked.checked_sub(amount)
            .ok_or(AccountError::InsufficientStake)?;
        // Note: In full implementation, this would move to a pending state
        // with unbonding period. For now, we return to balance immediately.
        self.balance = self.balance.saturating_add(amount);
        Ok(())
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        matches!(self.state, AccountState::Contract { .. })
    }

    /// Check if this is a validator
    pub fn is_validator(&self) -> bool {
        matches!(self.state, AccountState::Validator { .. })
    }

    /// Get contract code hash if contract
    pub fn code_hash(&self) -> Option<[u8; 32]> {
        match &self.state {
            AccountState::Contract { code_hash, .. } => Some(*code_hash),
            _ => None,
        }
    }

    /// Compute account hash (for state root)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(&self.address.bytes);
        hasher.update(&self.balance.muons().to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.staked.muons().to_le_bytes());
        hasher.update(&self.delegated.muons().to_le_bytes());

        // Include state hash
        let state_hash = match &self.state {
            AccountState::User => [0u8; 32],
            AccountState::Contract { code_hash, storage_root } => {
                let mut h = MuHash::new();
                h.update(code_hash);
                h.update(storage_root);
                h.finalize()
            }
            AccountState::Validator { commission_rate, .. } => {
                let mut h = MuHash::new();
                h.update(&commission_rate.to_le_bytes());
                h.finalize()
            }
        };
        hasher.update(&state_hash);

        hasher.finalize()
    }

    /// Get token balance
    pub fn token_balance(&self, token_id: &[u8; 32]) -> u64 {
        *self.token_balances.get(token_id).unwrap_or(&0)
    }

    /// Set token balance
    pub fn set_token_balance(&mut self, token_id: [u8; 32], amount: u64) {
        if amount == 0 {
            self.token_balances.remove(&token_id);
        } else {
            self.token_balances.insert(token_id, amount);
        }
    }

    /// Add NFT to account
    pub fn add_nft(&mut self, token_id: [u8; 32]) {
        self.nfts.insert(token_id, true);
    }

    /// Remove NFT from account
    pub fn remove_nft(&mut self, token_id: &[u8; 32]) -> bool {
        self.nfts.remove(token_id).is_some()
    }

    /// Check if account owns NFT
    pub fn owns_nft(&self, token_id: &[u8; 32]) -> bool {
        self.nfts.contains_key(token_id)
    }
}

/// Account type-specific state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccountState {
    /// Regular user account
    User,

    /// Contract account
    Contract {
        /// Hash of contract code
        code_hash: [u8; 32],
        /// Root of contract storage trie
        storage_root: [u8; 32],
    },

    /// Validator account
    Validator {
        /// Commission rate (basis points)
        commission_rate: u16,
        /// Validator metadata URI
        metadata: String,
        /// Is currently active?
        active: bool,
        /// Total delegated to this validator
        total_delegated: MuCoin,
        /// Pending unbonding delegations
        unbonding: Vec<UnbondingEntry>,
    },
}

/// Entry for unbonding stake
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// Amount being unbonded
    pub amount: MuCoin,
    /// When unbonding completes (block height)
    pub completion_height: u64,
    /// Delegator address
    pub delegator: Address,
}

/// Delegation record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    /// Delegator address
    pub delegator: Address,
    /// Validator address
    pub validator: Address,
    /// Delegated amount
    pub amount: MuCoin,
    /// Accumulated rewards
    pub rewards: MuCoin,
    /// Last reward claim height
    pub last_claim_height: u64,
}

impl Delegation {
    /// Create new delegation
    pub fn new(delegator: Address, validator: Address, amount: MuCoin, height: u64) -> Self {
        Self {
            delegator,
            validator,
            amount,
            rewards: MuCoin::ZERO,
            last_claim_height: height,
        }
    }

    /// Add rewards
    pub fn add_rewards(&mut self, amount: MuCoin) {
        self.rewards = self.rewards.saturating_add(amount);
    }

    /// Claim rewards
    pub fn claim_rewards(&mut self, height: u64) -> MuCoin {
        let claimed = self.rewards;
        self.rewards = MuCoin::ZERO;
        self.last_claim_height = height;
        claimed
    }
}

/// Validator info for display
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: Address,
    /// Self-staked amount
    pub self_stake: MuCoin,
    /// Total delegated amount
    pub total_delegated: MuCoin,
    /// Commission rate (basis points)
    pub commission_rate: u16,
    /// Is active?
    pub active: bool,
    /// Metadata URI
    pub metadata: String,
    /// Uptime percentage (0-10000)
    pub uptime: u16,
    /// Blocks produced
    pub blocks_produced: u64,
}

impl ValidatorInfo {
    /// Get total stake (self + delegated)
    pub fn total_stake(&self) -> MuCoin {
        self.self_stake + self.total_delegated
    }

    /// Calculate voting power (proportional to stake)
    pub fn voting_power(&self, total_network_stake: MuCoin) -> u64 {
        if total_network_stake.is_zero() {
            return 0;
        }
        // Basis points of total stake
        (self.total_stake().muons() * 10000) / total_network_stake.muons()
    }
}

/// Account-related errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Insufficient stake")]
    InsufficientStake,
    #[error("Account not found")]
    NotFound,
    #[error("Account already exists")]
    AlreadyExists,
    #[error("Not a validator")]
    NotValidator,
    #[error("Not a contract")]
    NotContract,
    #[error("Invalid nonce")]
    InvalidNonce,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        use libmu_crypto::MuKeyPair;
        let keypair = MuKeyPair::from_seed(b"test account");
        Address::from_public_key(keypair.public_key())
    }

    #[test]
    fn test_account_creation() {
        let addr = test_address();
        let account = Account::new(addr.clone());

        assert_eq!(account.balance, MuCoin::ZERO);
        assert_eq!(account.nonce, 0);
        assert!(!account.is_contract());
    }

    #[test]
    fn test_balance_operations() {
        let addr = test_address();
        let mut account = Account::with_balance(addr, MuCoin::from_muc(100));

        assert_eq!(account.balance.muc(), 100);

        // Credit
        account.credit(MuCoin::from_muc(50));
        assert_eq!(account.balance.muc(), 150);

        // Deduct
        account.deduct(MuCoin::from_muc(30)).unwrap();
        assert_eq!(account.balance.muc(), 120);

        // Insufficient
        let result = account.deduct(MuCoin::from_muc(200));
        assert!(result.is_err());
    }

    #[test]
    fn test_staking() {
        let addr = test_address();
        let mut account = Account::with_balance(addr, MuCoin::from_muc(100));

        // Stake
        account.stake(MuCoin::from_muc(40)).unwrap();
        assert_eq!(account.balance.muc(), 60);
        assert_eq!(account.staked.muc(), 40);
        assert_eq!(account.total_balance().muc(), 100);

        // Unstake
        account.unstake(MuCoin::from_muc(20)).unwrap();
        assert_eq!(account.balance.muc(), 80);
        assert_eq!(account.staked.muc(), 20);
    }

    #[test]
    fn test_nonce() {
        let addr = test_address();
        let mut account = Account::new(addr);

        assert_eq!(account.nonce, 0);
        account.increment_nonce();
        assert_eq!(account.nonce, 1);
        account.increment_nonce();
        assert_eq!(account.nonce, 2);
    }

    #[test]
    fn test_account_hash_deterministic() {
        let addr = test_address();
        let account = Account::with_balance(addr.clone(), MuCoin::from_muc(100));

        let hash1 = account.hash();
        let hash2 = account.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nft_ownership() {
        let addr = test_address();
        let mut account = Account::new(addr);

        let nft_id = [1u8; 32];

        assert!(!account.owns_nft(&nft_id));

        account.add_nft(nft_id);
        assert!(account.owns_nft(&nft_id));

        account.remove_nft(&nft_id);
        assert!(!account.owns_nft(&nft_id));
    }
}
