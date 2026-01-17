//! Smart Contracts for ChainMesh
//!
//! This module provides ownership primitives and contract implementations:
//!
//! ## Ownership Contracts
//! - `nft` - NFT minting, transfer, and management
//! - `collection` - NFT collection management
//! - `game_license` - Digital game ownership and licensing
//! - `marketplace` - P2P trading with escrow
//! - `royalty` - Creator royalty distribution
//!
//! ## Contract Model
//! Contracts in ChainMesh are stateful objects that:
//! - Have an address derived from deployer + nonce
//! - Store state in a key-value Merkle trie
//! - Execute methods via transactions
//! - Emit events for indexing

pub mod nft;
pub mod collection;
pub mod game_license;
pub mod marketplace;
pub mod royalty;

pub use nft::{NFTContract, NFTState, NFTMetadata};
pub use collection::{Collection, CollectionConfig, CollectionState};
pub use game_license::{GameLicenseContract, LicenseState, LicenseType};
pub use marketplace::{Marketplace, Listing, ListingStatus, Escrow, EscrowState};
pub use royalty::{RoyaltyConfig, RoyaltyDistributor};

use crate::types::{Address, MuCoin};
use libmu_crypto::MuHash;

/// Contract execution result
pub type ContractResult<T> = Result<T, ContractError>;

/// Contract errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("NFT not found: {0}")]
    NFTNotFound(String),
    #[error("Collection not found: {0}")]
    CollectionNotFound(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: MuCoin, need: MuCoin },
    #[error("Transfer failed: {0}")]
    TransferFailed(String),
    #[error("Listing not found")]
    ListingNotFound,
    #[error("Listing expired")]
    ListingExpired,
    #[error("Escrow error: {0}")]
    EscrowError(String),
    #[error("License error: {0}")]
    LicenseError(String),
    #[error("Max supply reached")]
    MaxSupplyReached,
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),
    #[error("Royalty too high: {0} bps")]
    RoyaltyTooHigh(u16),
}

/// Contract event for logging
#[derive(Debug, Clone)]
pub enum ContractEvent {
    /// NFT minted
    NFTMinted {
        collection: Address,
        token_id: [u8; 32],
        owner: Address,
        metadata_uri: String,
    },
    /// NFT transferred
    NFTTransferred {
        collection: Address,
        token_id: [u8; 32],
        from: Address,
        to: Address,
    },
    /// NFT burned
    NFTBurned {
        collection: Address,
        token_id: [u8; 32],
        owner: Address,
    },
    /// Collection created
    CollectionCreated {
        address: Address,
        name: String,
        creator: Address,
    },
    /// Listing created
    ListingCreated {
        listing_id: [u8; 32],
        token_id: [u8; 32],
        seller: Address,
        price: MuCoin,
    },
    /// Listing sold
    ListingSold {
        listing_id: [u8; 32],
        buyer: Address,
        price: MuCoin,
    },
    /// Listing cancelled
    ListingCancelled {
        listing_id: [u8; 32],
    },
    /// Escrow created
    EscrowCreated {
        escrow_id: [u8; 32],
        buyer: Address,
        seller: Address,
        amount: MuCoin,
    },
    /// Escrow released
    EscrowReleased {
        escrow_id: [u8; 32],
        to: Address,
        amount: MuCoin,
    },
    /// Royalty paid
    RoyaltyPaid {
        token_id: [u8; 32],
        creator: Address,
        amount: MuCoin,
    },
    /// License activated
    LicenseActivated {
        license_id: [u8; 32],
        user: Address,
        game_id: [u8; 32],
    },
}

/// Generate a unique ID from components
pub fn generate_id(components: &[&[u8]]) -> [u8; 32] {
    let mut hasher = MuHash::new();
    for component in components {
        hasher.update(component);
    }
    hasher.finalize()
}

/// Timestamp helper (would be provided by runtime in production)
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
