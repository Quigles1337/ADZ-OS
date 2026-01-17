//! μCoin (MUC) token and NFT definitions
//!
//! ## Token Economics
//! - Total supply: 137,036,000 MUC (tribute to fine-structure constant)
//! - Smallest unit: 1 muon = 10^-8 MUC
//! - Native NFT support for digital ownership

use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub, Mul, Div};

/// Total supply of μCoin in muons (smallest unit)
/// 137,036,000 MUC * 10^8 muons/MUC
pub const TOTAL_SUPPLY_MUONS: u64 = 137_036_000 * 100_000_000;

/// Number of muons per MUC
pub const MUONS_PER_MUC: u64 = 100_000_000;

/// Initial block reward in muons (13.7036 MUC)
pub const INITIAL_BLOCK_REWARD: u64 = 1_370_360_000;

/// Block reward halving interval (every ~4 years at 6-second blocks)
pub const HALVING_INTERVAL: u64 = 21_000_000;

/// Minimum stake required to become a validator (1000 MUC)
pub const MIN_VALIDATOR_STAKE: u64 = 1000 * MUONS_PER_MUC;

/// μCoin amount in muons (smallest unit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct MuCoin(u64);

impl MuCoin {
    /// Zero amount
    pub const ZERO: Self = Self(0);

    /// One muon (smallest unit)
    pub const ONE_MUON: Self = Self(1);

    /// One MUC
    pub const ONE_MUC: Self = Self(MUONS_PER_MUC);

    /// Create from muons (smallest unit)
    pub const fn from_muons(muons: u64) -> Self {
        Self(muons)
    }

    /// Create from MUC (whole units)
    pub fn from_muc(muc: u64) -> Self {
        Self(muc.saturating_mul(MUONS_PER_MUC))
    }

    /// Create from decimal MUC string (e.g., "1.5")
    pub fn from_muc_str(s: &str) -> Result<Self, TokenError> {
        let parts: Vec<&str> = s.split('.').collect();

        let whole = parts[0].parse::<u64>()
            .map_err(|_| TokenError::InvalidAmount)?;

        let fractional = if parts.len() > 1 {
            let frac_str = parts[1];
            if frac_str.len() > 8 {
                return Err(TokenError::TooManyDecimals);
            }
            let padded = format!("{:0<8}", frac_str);
            padded[..8].parse::<u64>()
                .map_err(|_| TokenError::InvalidAmount)?
        } else {
            0
        };

        let muons = whole.checked_mul(MUONS_PER_MUC)
            .and_then(|w| w.checked_add(fractional))
            .ok_or(TokenError::Overflow)?;

        Ok(Self(muons))
    }

    /// Get raw muon amount
    pub const fn muons(&self) -> u64 {
        self.0
    }

    /// Get whole MUC amount (truncated)
    pub const fn muc(&self) -> u64 {
        self.0 / MUONS_PER_MUC
    }

    /// Get fractional muons (after decimal point)
    pub const fn fractional_muons(&self) -> u64 {
        self.0 % MUONS_PER_MUC
    }

    /// Check if zero
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Checked addition
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Checked multiplication
    pub fn checked_mul(self, multiplier: u64) -> Option<Self> {
        self.0.checked_mul(multiplier).map(Self)
    }

    /// Checked division
    pub fn checked_div(self, divisor: u64) -> Option<Self> {
        self.0.checked_div(divisor).map(Self)
    }

    /// Saturating addition
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Calculate percentage (basis points, 10000 = 100%)
    pub fn percentage(self, basis_points: u64) -> Self {
        Self(self.0.saturating_mul(basis_points) / 10000)
    }

    /// Calculate block reward for given block height
    pub fn block_reward(height: u64) -> Self {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            return Self::ZERO;
        }
        Self(INITIAL_BLOCK_REWARD >> halvings)
    }
}

impl Add for MuCoin {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

impl Sub for MuCoin {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for MuCoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.muc();
        let frac = self.fractional_muons();
        if frac == 0 {
            write!(f, "{} MUC", whole)
        } else {
            write!(f, "{}.{:08} MUC", whole, frac)
        }
    }
}

/// Token ID for fungible tokens (other than MUC)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    /// Create token ID from contract address and token index
    pub fn new(contract: &super::Address, index: u64) -> Self {
        let mut hasher = MuHash::new();
        hasher.update(&contract.bytes);
        hasher.update(&index.to_le_bytes());
        hasher.update(b"token-id");
        Self(hasher.finalize())
    }

    /// Native MUC token ID (all zeros)
    pub fn native() -> Self {
        Self([0u8; 32])
    }

    /// Check if this is the native token
    pub fn is_native(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_native() {
            write!(f, "MUC")
        } else {
            write!(f, "{}", hex::encode(&self.0[..8]))
        }
    }
}

/// Non-Fungible Token for digital ownership
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NFT {
    /// Unique token ID
    pub id: [u8; 32],
    /// Collection/contract address
    pub collection: super::Address,
    /// Current owner
    pub owner: super::Address,
    /// Token metadata URI
    pub metadata_uri: String,
    /// Content hash (for verification)
    pub content_hash: [u8; 32],
    /// Royalty percentage (basis points, e.g., 250 = 2.5%)
    pub royalty_bps: u16,
    /// Original creator (receives royalties)
    pub creator: super::Address,
    /// Creation timestamp
    pub created_at: u64,
    /// Is this token transferable?
    pub transferable: bool,
    /// Is this token burnable?
    pub burnable: bool,
}

impl NFT {
    /// Create a new NFT
    pub fn new(
        collection: super::Address,
        creator: super::Address,
        metadata_uri: String,
        content_hash: [u8; 32],
        royalty_bps: u16,
        timestamp: u64,
    ) -> Self {
        // Generate unique ID
        let mut hasher = MuHash::new();
        hasher.update(&collection.bytes);
        hasher.update(&creator.bytes);
        hasher.update(&content_hash);
        hasher.update(&timestamp.to_le_bytes());
        let id = hasher.finalize();

        Self {
            id,
            collection,
            owner: creator.clone(),
            metadata_uri,
            content_hash,
            royalty_bps: royalty_bps.min(10000), // Max 100%
            creator,
            created_at: timestamp,
            transferable: true,
            burnable: true,
        }
    }

    /// Calculate royalty amount for a sale
    pub fn calculate_royalty(&self, sale_price: MuCoin) -> MuCoin {
        sale_price.percentage(self.royalty_bps as u64)
    }

    /// Check if transfer is allowed
    pub fn can_transfer(&self, from: &super::Address) -> bool {
        self.transferable && &self.owner == from
    }

    /// Transfer ownership
    pub fn transfer(&mut self, to: super::Address) -> Result<(), TokenError> {
        if !self.transferable {
            return Err(TokenError::NotTransferable);
        }
        self.owner = to;
        Ok(())
    }
}

/// Game license token (special NFT for game ownership)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameLicense {
    /// Base NFT
    pub nft: NFT,
    /// Game identifier
    pub game_id: [u8; 32],
    /// License type (single, family, etc.)
    pub license_type: LicenseType,
    /// Number of allowed activations
    pub max_activations: u32,
    /// Current activations
    pub current_activations: u32,
    /// Can this license be resold?
    pub resellable: bool,
}

/// License types for games
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseType {
    /// Single user license
    Personal,
    /// Family sharing (up to 5 users)
    Family,
    /// Developer/review copy
    Developer,
    /// Limited time license
    TimeLimited { expires_at: u64 },
}

impl GameLicense {
    /// Create a new game license
    pub fn new(
        game_id: [u8; 32],
        creator: super::Address,
        license_type: LicenseType,
        max_activations: u32,
        timestamp: u64,
    ) -> Self {
        let collection = super::Address::system(); // System game registry

        let content_hash = {
            let mut hasher = MuHash::new();
            hasher.update(&game_id);
            hasher.update(b"game-license");
            hasher.finalize()
        };

        let nft = NFT::new(
            collection,
            creator,
            format!("game://{}", hex::encode(&game_id[..8])),
            content_hash,
            500, // 5% royalty
            timestamp,
        );

        Self {
            nft,
            game_id,
            license_type,
            max_activations,
            current_activations: 0,
            resellable: true,
        }
    }

    /// Try to activate the license
    pub fn activate(&mut self) -> Result<(), TokenError> {
        if self.current_activations >= self.max_activations {
            return Err(TokenError::MaxActivationsReached);
        }

        if let LicenseType::TimeLimited { expires_at } = self.license_type {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expires_at {
                return Err(TokenError::LicenseExpired);
            }
        }

        self.current_activations += 1;
        Ok(())
    }

    /// Deactivate one activation
    pub fn deactivate(&mut self) {
        self.current_activations = self.current_activations.saturating_sub(1);
    }
}

/// Token-related errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("Invalid amount format")]
    InvalidAmount,
    #[error("Too many decimal places (max 8)")]
    TooManyDecimals,
    #[error("Arithmetic overflow")]
    Overflow,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Token not transferable")]
    NotTransferable,
    #[error("Maximum activations reached")]
    MaxActivationsReached,
    #[error("License expired")]
    LicenseExpired,
    #[error("Token not found")]
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mucoin_from_muc() {
        let one_muc = MuCoin::from_muc(1);
        assert_eq!(one_muc.muons(), MUONS_PER_MUC);
        assert_eq!(one_muc.muc(), 1);
    }

    #[test]
    fn test_mucoin_from_str() {
        let amount = MuCoin::from_muc_str("1.5").unwrap();
        assert_eq!(amount.muc(), 1);
        assert_eq!(amount.fractional_muons(), 50_000_000);

        let amount2 = MuCoin::from_muc_str("100").unwrap();
        assert_eq!(amount2.muc(), 100);
        assert_eq!(amount2.fractional_muons(), 0);
    }

    #[test]
    fn test_mucoin_display() {
        let amount = MuCoin::from_muons(150_000_000);
        assert_eq!(format!("{}", amount), "1.50000000 MUC");

        let whole = MuCoin::from_muc(100);
        assert_eq!(format!("{}", whole), "100 MUC");
    }

    #[test]
    fn test_mucoin_arithmetic() {
        let a = MuCoin::from_muc(10);
        let b = MuCoin::from_muc(5);

        assert_eq!((a + b).muc(), 15);
        assert_eq!((a - b).muc(), 5);
    }

    #[test]
    fn test_block_reward_halving() {
        let reward0 = MuCoin::block_reward(0);
        let reward1 = MuCoin::block_reward(HALVING_INTERVAL);
        let reward2 = MuCoin::block_reward(HALVING_INTERVAL * 2);

        assert_eq!(reward0.muons(), INITIAL_BLOCK_REWARD);
        assert_eq!(reward1.muons(), INITIAL_BLOCK_REWARD / 2);
        assert_eq!(reward2.muons(), INITIAL_BLOCK_REWARD / 4);
    }

    #[test]
    fn test_total_supply() {
        // Verify total supply matches spec
        assert_eq!(TOTAL_SUPPLY_MUONS, 137_036_000 * 100_000_000);
    }

    #[test]
    fn test_percentage() {
        let amount = MuCoin::from_muc(100);
        let ten_percent = amount.percentage(1000); // 10%
        assert_eq!(ten_percent.muc(), 10);
    }
}
