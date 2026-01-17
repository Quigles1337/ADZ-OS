//! NFT Collection Management
//!
//! Collections are containers for NFTs with shared configuration:
//! - Metadata standards
//! - Royalty settings
//! - Minting rules
//! - Access control

use crate::types::{Address, MuCoin};
use super::{ContractError, ContractResult, ContractEvent, generate_id};
use std::collections::HashMap;

/// Collection configuration
#[derive(Debug, Clone)]
pub struct CollectionConfig {
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Description
    pub description: String,
    /// Collection image URI
    pub image_uri: String,
    /// External link
    pub external_link: Option<String>,
    /// Default royalty (basis points)
    pub default_royalty_bps: u16,
    /// Maximum supply (None = unlimited)
    pub max_supply: Option<u64>,
    /// Mint price (None = free)
    pub mint_price: Option<MuCoin>,
    /// Is public minting allowed
    pub public_mint: bool,
    /// Maximum mints per address (None = unlimited)
    pub max_per_address: Option<u64>,
    /// Whitelist only period end timestamp
    pub whitelist_end: Option<u64>,
}

impl CollectionConfig {
    /// Create a basic collection config
    pub fn new(name: String, symbol: String) -> Self {
        Self {
            name,
            symbol,
            description: String::new(),
            image_uri: String::new(),
            external_link: None,
            default_royalty_bps: 500, // 5% default
            max_supply: None,
            mint_price: None,
            public_mint: true,
            max_per_address: None,
            whitelist_end: None,
        }
    }

    /// Builder: set description
    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    /// Builder: set max supply
    pub fn with_max_supply(mut self, max: u64) -> Self {
        self.max_supply = Some(max);
        self
    }

    /// Builder: set mint price
    pub fn with_mint_price(mut self, price: MuCoin) -> Self {
        self.mint_price = Some(price);
        self
    }

    /// Builder: set royalty
    pub fn with_royalty(mut self, bps: u16) -> Self {
        self.default_royalty_bps = bps.min(2500);
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> ContractResult<()> {
        if self.name.is_empty() {
            return Err(ContractError::InvalidMetadata("Name required".into()));
        }
        if self.name.len() > 64 {
            return Err(ContractError::InvalidMetadata("Name too long".into()));
        }
        if self.symbol.is_empty() {
            return Err(ContractError::InvalidMetadata("Symbol required".into()));
        }
        if self.symbol.len() > 10 {
            return Err(ContractError::InvalidMetadata("Symbol too long".into()));
        }
        if self.default_royalty_bps > 2500 {
            return Err(ContractError::RoyaltyTooHigh(self.default_royalty_bps));
        }
        Ok(())
    }
}

/// Collection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionState {
    /// Collection is active
    Active,
    /// Minting is paused
    Paused,
    /// Collection is frozen (no more changes)
    Frozen,
    /// Collection is deprecated
    Deprecated,
}

/// Whitelist entry
#[derive(Debug, Clone)]
pub struct WhitelistEntry {
    /// Address
    pub address: Address,
    /// Number of mints allowed
    pub mints_allowed: u64,
    /// Number of mints used
    pub mints_used: u64,
}

/// NFT Collection contract
#[derive(Debug)]
pub struct Collection {
    /// Collection address
    pub address: Address,
    /// Configuration
    pub config: CollectionConfig,
    /// Creator/owner
    pub creator: Address,
    /// Admins who can manage the collection
    admins: HashMap<Address, bool>,
    /// Current state
    pub state: CollectionState,
    /// Total minted
    pub total_minted: u64,
    /// Total burned
    pub total_burned: u64,
    /// Mints per address tracking
    mints_per_address: HashMap<Address, u64>,
    /// Whitelist
    whitelist: HashMap<Address, WhitelistEntry>,
    /// Revenue collected
    pub revenue: MuCoin,
    /// Created at timestamp
    pub created_at: u64,
    /// Events
    events: Vec<ContractEvent>,
}

impl Collection {
    /// Create a new collection
    pub fn new(
        address: Address,
        creator: Address,
        config: CollectionConfig,
    ) -> ContractResult<Self> {
        config.validate()?;

        let mut admins = HashMap::new();
        admins.insert(creator.clone(), true);

        Ok(Self {
            address: address.clone(),
            config: config.clone(),
            creator: creator.clone(),
            admins,
            state: CollectionState::Active,
            total_minted: 0,
            total_burned: 0,
            mints_per_address: HashMap::new(),
            whitelist: HashMap::new(),
            revenue: MuCoin::ZERO,
            created_at: super::current_timestamp(),
            events: vec![ContractEvent::CollectionCreated {
                address,
                name: config.name,
                creator,
            }],
        })
    }

    /// Check if address can mint
    pub fn can_mint(&self, minter: &Address, quantity: u64) -> ContractResult<()> {
        // Check state
        if self.state != CollectionState::Active {
            return Err(ContractError::InvalidOperation("Collection not active".into()));
        }

        // Check max supply
        if let Some(max) = self.config.max_supply {
            if self.total_minted + quantity > max {
                return Err(ContractError::MaxSupplyReached);
            }
        }

        // Check per-address limit
        if let Some(max_per) = self.config.max_per_address {
            let current = self.mints_per_address.get(minter).copied().unwrap_or(0);
            if current + quantity > max_per {
                return Err(ContractError::InvalidOperation(
                    format!("Max {} mints per address", max_per)
                ));
            }
        }

        // Check whitelist period
        let now = super::current_timestamp();
        if let Some(whitelist_end) = self.config.whitelist_end {
            if now < whitelist_end {
                // In whitelist period
                let entry = self.whitelist.get(minter)
                    .ok_or_else(|| ContractError::Unauthorized("Not on whitelist".into()))?;

                if entry.mints_used + quantity > entry.mints_allowed {
                    return Err(ContractError::InvalidOperation("Whitelist allocation exceeded".into()));
                }
            }
        }

        // Check public mint
        if !self.config.public_mint && !self.is_admin(minter) {
            return Err(ContractError::Unauthorized("Public minting disabled".into()));
        }

        Ok(())
    }

    /// Record a mint
    pub fn record_mint(&mut self, minter: &Address, quantity: u64, payment: MuCoin) -> ContractResult<()> {
        self.can_mint(minter, quantity)?;

        // Check payment
        if let Some(price) = &self.config.mint_price {
            let required = MuCoin::from_muons(price.muons().saturating_mul(quantity));
            if payment < required {
                return Err(ContractError::InsufficientFunds {
                    have: payment,
                    need: required,
                });
            }
            self.revenue = self.revenue + payment;
        }

        // Update tracking
        *self.mints_per_address.entry(minter.clone()).or_insert(0) += quantity;
        self.total_minted += quantity;

        // Update whitelist if applicable
        if let Some(entry) = self.whitelist.get_mut(minter) {
            entry.mints_used += quantity;
        }

        Ok(())
    }

    /// Record a burn
    pub fn record_burn(&mut self) {
        self.total_burned += 1;
    }

    /// Get current supply
    pub fn current_supply(&self) -> u64 {
        self.total_minted - self.total_burned
    }

    /// Get remaining supply
    pub fn remaining_supply(&self) -> Option<u64> {
        self.config.max_supply.map(|max| max.saturating_sub(self.total_minted))
    }

    /// Add admin
    pub fn add_admin(&mut self, admin: Address, caller: &Address) -> ContractResult<()> {
        if caller != &self.creator {
            return Err(ContractError::Unauthorized("Only creator can add admins".into()));
        }
        self.admins.insert(admin, true);
        Ok(())
    }

    /// Remove admin
    pub fn remove_admin(&mut self, admin: &Address, caller: &Address) -> ContractResult<()> {
        if caller != &self.creator {
            return Err(ContractError::Unauthorized("Only creator can remove admins".into()));
        }
        if admin == &self.creator {
            return Err(ContractError::InvalidOperation("Cannot remove creator".into()));
        }
        self.admins.remove(admin);
        Ok(())
    }

    /// Check if address is admin
    pub fn is_admin(&self, address: &Address) -> bool {
        self.admins.get(address).copied().unwrap_or(false)
    }

    /// Add to whitelist
    pub fn add_to_whitelist(
        &mut self,
        addresses: Vec<(Address, u64)>,
        caller: &Address,
    ) -> ContractResult<()> {
        if !self.is_admin(caller) {
            return Err(ContractError::Unauthorized("Admin required".into()));
        }

        for (address, mints_allowed) in addresses {
            self.whitelist.insert(address.clone(), WhitelistEntry {
                address,
                mints_allowed,
                mints_used: 0,
            });
        }

        Ok(())
    }

    /// Remove from whitelist
    pub fn remove_from_whitelist(
        &mut self,
        addresses: Vec<Address>,
        caller: &Address,
    ) -> ContractResult<()> {
        if !self.is_admin(caller) {
            return Err(ContractError::Unauthorized("Admin required".into()));
        }

        for address in addresses {
            self.whitelist.remove(&address);
        }

        Ok(())
    }

    /// Check whitelist status
    pub fn whitelist_status(&self, address: &Address) -> Option<&WhitelistEntry> {
        self.whitelist.get(address)
    }

    /// Set collection state
    pub fn set_state(&mut self, state: CollectionState, caller: &Address) -> ContractResult<()> {
        if !self.is_admin(caller) {
            return Err(ContractError::Unauthorized("Admin required".into()));
        }

        // Cannot unfreeze
        if self.state == CollectionState::Frozen && state != CollectionState::Frozen {
            return Err(ContractError::InvalidOperation("Collection is frozen".into()));
        }

        self.state = state;
        Ok(())
    }

    /// Update configuration (before frozen)
    pub fn update_config<F>(&mut self, updater: F, caller: &Address) -> ContractResult<()>
    where
        F: FnOnce(&mut CollectionConfig),
    {
        if self.state == CollectionState::Frozen {
            return Err(ContractError::InvalidOperation("Collection is frozen".into()));
        }
        if !self.is_admin(caller) {
            return Err(ContractError::Unauthorized("Admin required".into()));
        }

        updater(&mut self.config);
        self.config.validate()?;
        Ok(())
    }

    /// Withdraw revenue
    pub fn withdraw_revenue(&mut self, caller: &Address) -> ContractResult<MuCoin> {
        if caller != &self.creator {
            return Err(ContractError::Unauthorized("Only creator can withdraw".into()));
        }

        let amount = self.revenue;
        self.revenue = MuCoin::ZERO;
        Ok(amount)
    }

    /// Get and clear events
    pub fn take_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmu_crypto::MuKeyPair;

    fn test_address(seed: &[u8]) -> Address {
        let keypair = MuKeyPair::from_seed(seed);
        Address::from_public_key(keypair.public_key())
    }

    #[test]
    fn test_create_collection() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");

        let config = CollectionConfig::new("Test".into(), "TST".into())
            .with_max_supply(1000)
            .with_royalty(500);

        let collection = Collection::new(address, creator, config).unwrap();
        assert_eq!(collection.state, CollectionState::Active);
        assert_eq!(collection.total_minted, 0);
    }

    #[test]
    fn test_mint_tracking() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");
        let minter = test_address(b"minter");

        let config = CollectionConfig::new("Test".into(), "TST".into())
            .with_max_supply(10);

        let mut collection = Collection::new(address, creator, config).unwrap();

        // Record mints
        collection.record_mint(&minter, 3, MuCoin::ZERO).unwrap();
        assert_eq!(collection.total_minted, 3);
        assert_eq!(collection.remaining_supply(), Some(7));

        collection.record_mint(&minter, 7, MuCoin::ZERO).unwrap();
        assert_eq!(collection.remaining_supply(), Some(0));

        // Should fail - max supply reached
        let result = collection.record_mint(&minter, 1, MuCoin::ZERO);
        assert!(matches!(result, Err(ContractError::MaxSupplyReached)));
    }

    #[test]
    fn test_per_address_limit() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");
        let minter = test_address(b"minter");

        let mut config = CollectionConfig::new("Test".into(), "TST".into());
        config.max_per_address = Some(5);

        let mut collection = Collection::new(address, creator, config).unwrap();

        collection.record_mint(&minter, 5, MuCoin::ZERO).unwrap();

        // Should fail - per address limit
        let result = collection.record_mint(&minter, 1, MuCoin::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_paid_mint() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");
        let minter = test_address(b"minter");

        let config = CollectionConfig::new("Test".into(), "TST".into())
            .with_mint_price(MuCoin::from_muc(10));

        let mut collection = Collection::new(address, creator.clone(), config).unwrap();

        // Insufficient payment
        let result = collection.record_mint(&minter, 1, MuCoin::from_muc(5));
        assert!(matches!(result, Err(ContractError::InsufficientFunds { .. })));

        // Correct payment
        collection.record_mint(&minter, 1, MuCoin::from_muc(10)).unwrap();
        assert_eq!(collection.revenue.muc(), 10);

        // Withdraw
        let withdrawn = collection.withdraw_revenue(&creator).unwrap();
        assert_eq!(withdrawn.muc(), 10);
        assert_eq!(collection.revenue.muc(), 0);
    }

    #[test]
    fn test_whitelist() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");
        let whitelisted = test_address(b"whitelisted");
        let not_whitelisted = test_address(b"not_whitelisted");

        let mut config = CollectionConfig::new("Test".into(), "TST".into());
        config.whitelist_end = Some(super::super::current_timestamp() + 3600); // 1 hour from now
        config.public_mint = true;

        let mut collection = Collection::new(address, creator.clone(), config).unwrap();

        // Add to whitelist
        collection.add_to_whitelist(vec![(whitelisted.clone(), 3)], &creator).unwrap();

        // Whitelisted can mint
        collection.record_mint(&whitelisted, 2, MuCoin::ZERO).unwrap();

        // Not whitelisted cannot during whitelist period
        let result = collection.record_mint(&not_whitelisted, 1, MuCoin::ZERO);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_freeze_collection() {
        let creator = test_address(b"creator");
        let address = test_address(b"collection");

        let config = CollectionConfig::new("Test".into(), "TST".into());
        let mut collection = Collection::new(address, creator.clone(), config).unwrap();

        // Freeze
        collection.set_state(CollectionState::Frozen, &creator).unwrap();

        // Cannot unfreeze
        let result = collection.set_state(CollectionState::Active, &creator);
        assert!(result.is_err());

        // Cannot update config
        let result = collection.update_config(|c| c.name = "New".into(), &creator);
        assert!(result.is_err());
    }
}
