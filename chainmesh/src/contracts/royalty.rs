//! Royalty Distribution Contract
//!
//! Manages creator royalties for NFT sales:
//! - Configurable royalty splits
//! - Multi-recipient support
//! - Accumulated royalty tracking
//! - Withdrawal management

use crate::types::{Address, MuCoin};
use super::{ContractError, ContractResult, ContractEvent};
use std::collections::HashMap;

/// Maximum total royalty (25%)
pub const MAX_ROYALTY_BPS: u16 = 2500;

/// Royalty recipient share
#[derive(Debug, Clone)]
pub struct RoyaltyShare {
    /// Recipient address
    pub recipient: Address,
    /// Share of royalty (basis points of the royalty amount)
    pub share_bps: u16,
    /// Role description
    pub role: String,
}

/// Royalty configuration for a collection
#[derive(Debug, Clone)]
pub struct RoyaltyConfig {
    /// Collection or token this applies to
    pub collection: Address,
    /// Total royalty percentage (basis points)
    pub royalty_bps: u16,
    /// Recipients and their shares
    pub recipients: Vec<RoyaltyShare>,
    /// Is configuration locked (immutable)
    pub locked: bool,
    /// Admin who can modify (before lock)
    pub admin: Address,
}

impl RoyaltyConfig {
    /// Create new royalty config with single recipient
    pub fn new(collection: Address, royalty_bps: u16, recipient: Address) -> ContractResult<Self> {
        if royalty_bps > MAX_ROYALTY_BPS {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        Ok(Self {
            collection: collection.clone(),
            royalty_bps,
            recipients: vec![RoyaltyShare {
                recipient: recipient.clone(),
                share_bps: 10000, // 100%
                role: "Creator".into(),
            }],
            locked: false,
            admin: recipient,
        })
    }

    /// Create with multiple recipients
    pub fn with_splits(
        collection: Address,
        royalty_bps: u16,
        recipients: Vec<(Address, u16, String)>, // (address, share_bps, role)
        admin: Address,
    ) -> ContractResult<Self> {
        if royalty_bps > MAX_ROYALTY_BPS {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        // Validate shares sum to 100%
        let total_shares: u64 = recipients.iter().map(|(_, s, _)| *s as u64).sum();
        if total_shares != 10000 {
            return Err(ContractError::InvalidOperation(
                format!("Shares must sum to 10000, got {}", total_shares)
            ));
        }

        let shares = recipients
            .into_iter()
            .map(|(recipient, share_bps, role)| RoyaltyShare {
                recipient,
                share_bps,
                role,
            })
            .collect();

        Ok(Self {
            collection,
            royalty_bps,
            recipients: shares,
            locked: false,
            admin,
        })
    }

    /// Calculate royalty amount from sale price
    pub fn calculate_royalty(&self, sale_price: MuCoin) -> MuCoin {
        sale_price.percentage(self.royalty_bps as u64)
    }

    /// Calculate distribution for a royalty amount
    pub fn calculate_distribution(&self, royalty_amount: MuCoin) -> Vec<(Address, MuCoin)> {
        self.recipients
            .iter()
            .map(|share| {
                let amount = royalty_amount.percentage(share.share_bps as u64);
                (share.recipient.clone(), amount)
            })
            .collect()
    }

    /// Update royalty percentage
    pub fn set_royalty_bps(&mut self, royalty_bps: u16, caller: &Address) -> ContractResult<()> {
        if self.locked {
            return Err(ContractError::InvalidOperation("Config is locked".into()));
        }
        if caller != &self.admin {
            return Err(ContractError::Unauthorized("Not admin".into()));
        }
        if royalty_bps > MAX_ROYALTY_BPS {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        self.royalty_bps = royalty_bps;
        Ok(())
    }

    /// Update recipients
    pub fn set_recipients(
        &mut self,
        recipients: Vec<(Address, u16, String)>,
        caller: &Address,
    ) -> ContractResult<()> {
        if self.locked {
            return Err(ContractError::InvalidOperation("Config is locked".into()));
        }
        if caller != &self.admin {
            return Err(ContractError::Unauthorized("Not admin".into()));
        }

        let total_shares: u64 = recipients.iter().map(|(_, s, _)| *s as u64).sum();
        if total_shares != 10000 {
            return Err(ContractError::InvalidOperation(
                format!("Shares must sum to 10000, got {}", total_shares)
            ));
        }

        self.recipients = recipients
            .into_iter()
            .map(|(recipient, share_bps, role)| RoyaltyShare {
                recipient,
                share_bps,
                role,
            })
            .collect();

        Ok(())
    }

    /// Lock configuration (irreversible)
    pub fn lock(&mut self, caller: &Address) -> ContractResult<()> {
        if caller != &self.admin {
            return Err(ContractError::Unauthorized("Not admin".into()));
        }
        self.locked = true;
        Ok(())
    }

    /// Transfer admin
    pub fn transfer_admin(&mut self, new_admin: Address, caller: &Address) -> ContractResult<()> {
        if self.locked {
            return Err(ContractError::InvalidOperation("Config is locked".into()));
        }
        if caller != &self.admin {
            return Err(ContractError::Unauthorized("Not admin".into()));
        }
        self.admin = new_admin;
        Ok(())
    }
}

/// Royalty distributor contract
#[derive(Debug)]
pub struct RoyaltyDistributor {
    /// Contract address
    pub address: Address,
    /// Royalty configurations by collection
    configs: HashMap<Address, RoyaltyConfig>,
    /// Accumulated royalties by recipient
    pending_royalties: HashMap<Address, MuCoin>,
    /// Total royalties distributed
    pub total_distributed: MuCoin,
    /// Events
    events: Vec<ContractEvent>,
}

impl RoyaltyDistributor {
    /// Create new distributor
    pub fn new(address: Address) -> Self {
        Self {
            address,
            configs: HashMap::new(),
            pending_royalties: HashMap::new(),
            total_distributed: MuCoin::ZERO,
            events: Vec::new(),
        }
    }

    /// Register royalty config for a collection
    pub fn register_config(&mut self, config: RoyaltyConfig) -> ContractResult<()> {
        if self.configs.contains_key(&config.collection) {
            return Err(ContractError::AlreadyExists("Config already exists".into()));
        }

        self.configs.insert(config.collection.clone(), config);
        Ok(())
    }

    /// Get config for collection
    pub fn get_config(&self, collection: &Address) -> Option<&RoyaltyConfig> {
        self.configs.get(collection)
    }

    /// Get mutable config
    pub fn get_config_mut(&mut self, collection: &Address) -> Option<&mut RoyaltyConfig> {
        self.configs.get_mut(collection)
    }

    /// Distribute royalty for a sale
    pub fn distribute(
        &mut self,
        collection: &Address,
        token_id: [u8; 32],
        sale_price: MuCoin,
    ) -> ContractResult<Vec<(Address, MuCoin)>> {
        let config = self.configs.get(collection)
            .ok_or_else(|| ContractError::CollectionNotFound(format!("{}", collection)))?;

        let royalty_amount = config.calculate_royalty(sale_price);
        if royalty_amount.is_zero() {
            return Ok(Vec::new());
        }

        let distribution = config.calculate_distribution(royalty_amount);

        // Add to pending
        for (recipient, amount) in &distribution {
            let pending = self.pending_royalties
                .entry(recipient.clone())
                .or_insert(MuCoin::ZERO);
            *pending = *pending + *amount;

            self.events.push(ContractEvent::RoyaltyPaid {
                token_id,
                creator: recipient.clone(),
                amount: *amount,
            });
        }

        self.total_distributed = self.total_distributed + royalty_amount;

        Ok(distribution)
    }

    /// Get pending royalties for address
    pub fn pending(&self, recipient: &Address) -> MuCoin {
        self.pending_royalties
            .get(recipient)
            .copied()
            .unwrap_or(MuCoin::ZERO)
    }

    /// Withdraw pending royalties
    pub fn withdraw(&mut self, caller: &Address) -> ContractResult<MuCoin> {
        let amount = self.pending_royalties
            .remove(caller)
            .unwrap_or(MuCoin::ZERO);

        if amount.is_zero() {
            return Err(ContractError::InvalidOperation("No pending royalties".into()));
        }

        Ok(amount)
    }

    /// Get and clear events
    pub fn take_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.events)
    }
}

/// EIP-2981 compatible royalty info
#[derive(Debug, Clone)]
pub struct RoyaltyInfo {
    /// Primary royalty recipient
    pub receiver: Address,
    /// Royalty amount for a given sale price
    pub royalty_amount: MuCoin,
}

impl RoyaltyConfig {
    /// Get EIP-2981 compatible royalty info
    pub fn royalty_info(&self, sale_price: MuCoin) -> RoyaltyInfo {
        let royalty_amount = self.calculate_royalty(sale_price);

        // Return primary recipient (first one)
        let receiver = self.recipients
            .first()
            .map(|r| r.recipient.clone())
            .unwrap_or_else(|| self.admin.clone());

        RoyaltyInfo {
            receiver,
            royalty_amount,
        }
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
    fn test_single_recipient() {
        let collection = test_address(b"collection");
        let creator = test_address(b"creator");

        let config = RoyaltyConfig::new(collection, 500, creator.clone()).unwrap(); // 5%

        let sale_price = MuCoin::from_muc(100);
        let royalty = config.calculate_royalty(sale_price);
        assert_eq!(royalty.muc(), 5);

        let distribution = config.calculate_distribution(royalty);
        assert_eq!(distribution.len(), 1);
        assert_eq!(distribution[0].0, creator);
        assert_eq!(distribution[0].1.muc(), 5);
    }

    #[test]
    fn test_multi_recipient() {
        let collection = test_address(b"collection");
        let artist = test_address(b"artist");
        let label = test_address(b"label");
        let agent = test_address(b"agent");

        let config = RoyaltyConfig::with_splits(
            collection,
            1000, // 10%
            vec![
                (artist.clone(), 7000, "Artist".into()), // 70%
                (label.clone(), 2000, "Label".into()),   // 20%
                (agent.clone(), 1000, "Agent".into()),   // 10%
            ],
            artist.clone(),
        ).unwrap();

        let sale_price = MuCoin::from_muc(1000);
        let royalty = config.calculate_royalty(sale_price);
        assert_eq!(royalty.muc(), 100); // 10% of 1000

        let distribution = config.calculate_distribution(royalty);
        assert_eq!(distribution.len(), 3);

        // Artist gets 70% of 100 = 70
        assert_eq!(distribution[0].1.muc(), 70);
        // Label gets 20% of 100 = 20
        assert_eq!(distribution[1].1.muc(), 20);
        // Agent gets 10% of 100 = 10
        assert_eq!(distribution[2].1.muc(), 10);
    }

    #[test]
    fn test_invalid_shares() {
        let collection = test_address(b"collection");
        let artist = test_address(b"artist");

        // Shares don't sum to 100%
        let result = RoyaltyConfig::with_splits(
            collection,
            500,
            vec![
                (artist.clone(), 5000, "Artist".into()), // 50%
            ],
            artist,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_royalty_too_high() {
        let collection = test_address(b"collection");
        let creator = test_address(b"creator");

        let result = RoyaltyConfig::new(collection, 3000, creator); // 30%
        assert!(matches!(result, Err(ContractError::RoyaltyTooHigh(_))));
    }

    #[test]
    fn test_distributor() {
        let distributor_addr = test_address(b"distributor");
        let collection = test_address(b"collection");
        let creator = test_address(b"creator");

        let mut distributor = RoyaltyDistributor::new(distributor_addr);

        let config = RoyaltyConfig::new(collection.clone(), 500, creator.clone()).unwrap();
        distributor.register_config(config).unwrap();

        // Distribute
        let distribution = distributor.distribute(
            &collection,
            [1u8; 32],
            MuCoin::from_muc(100),
        ).unwrap();

        assert_eq!(distribution.len(), 1);
        assert_eq!(distributor.pending(&creator).muc(), 5);

        // Withdraw
        let withdrawn = distributor.withdraw(&creator).unwrap();
        assert_eq!(withdrawn.muc(), 5);
        assert_eq!(distributor.pending(&creator).muc(), 0);
    }

    #[test]
    fn test_lock_config() {
        let collection = test_address(b"collection");
        let creator = test_address(b"creator");

        let mut config = RoyaltyConfig::new(collection, 500, creator.clone()).unwrap();

        // Can modify before lock
        config.set_royalty_bps(600, &creator).unwrap();
        assert_eq!(config.royalty_bps, 600);

        // Lock
        config.lock(&creator).unwrap();

        // Cannot modify after lock
        let result = config.set_royalty_bps(700, &creator);
        assert!(result.is_err());
    }

    #[test]
    fn test_eip2981_compatibility() {
        let collection = test_address(b"collection");
        let creator = test_address(b"creator");

        let config = RoyaltyConfig::new(collection, 250, creator.clone()).unwrap(); // 2.5%

        let info = config.royalty_info(MuCoin::from_muc(1000));
        assert_eq!(info.receiver, creator);
        assert_eq!(info.royalty_amount.muc(), 25); // 2.5% of 1000
    }
}
