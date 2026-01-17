//! NFT Contract Implementation
//!
//! Provides core NFT functionality:
//! - Minting with metadata
//! - Transfers with ownership verification
//! - Burning
//! - Approval and operator management
//! - Royalty tracking

use crate::types::{Address, MuCoin};
use super::{ContractError, ContractResult, ContractEvent, generate_id};
use libmu_crypto::MuHash;
use std::collections::{HashMap, HashSet};

/// Maximum royalty in basis points (25%)
pub const MAX_ROYALTY_BPS: u16 = 2500;

/// NFT metadata structure
#[derive(Debug, Clone)]
pub struct NFTMetadata {
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Image/content URI
    pub uri: String,
    /// Content hash for verification
    pub content_hash: [u8; 32],
    /// Additional attributes
    pub attributes: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: u64,
}

impl NFTMetadata {
    /// Create new metadata
    pub fn new(name: String, description: String, uri: String, content_hash: [u8; 32]) -> Self {
        Self {
            name,
            description,
            uri,
            content_hash,
            attributes: HashMap::new(),
            created_at: super::current_timestamp(),
        }
    }

    /// Add attribute
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }

    /// Validate metadata
    pub fn validate(&self) -> ContractResult<()> {
        if self.name.is_empty() {
            return Err(ContractError::InvalidMetadata("Name required".into()));
        }
        if self.name.len() > 256 {
            return Err(ContractError::InvalidMetadata("Name too long".into()));
        }
        if self.uri.is_empty() {
            return Err(ContractError::InvalidMetadata("URI required".into()));
        }
        if self.uri.len() > 2048 {
            return Err(ContractError::InvalidMetadata("URI too long".into()));
        }
        Ok(())
    }

    /// Compute metadata hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(self.name.as_bytes());
        hasher.update(self.description.as_bytes());
        hasher.update(self.uri.as_bytes());
        hasher.update(&self.content_hash);
        hasher.finalize()
    }
}

/// State of a single NFT
#[derive(Debug, Clone)]
pub struct NFTState {
    /// Unique token ID
    pub token_id: [u8; 32],
    /// Collection address
    pub collection: Address,
    /// Current owner
    pub owner: Address,
    /// Original creator
    pub creator: Address,
    /// Metadata
    pub metadata: NFTMetadata,
    /// Royalty percentage (basis points)
    pub royalty_bps: u16,
    /// Is token locked (non-transferable temporarily)
    pub locked: bool,
    /// Approved address for transfer (single approval)
    pub approved: Option<Address>,
    /// Token index in collection
    pub token_index: u64,
}

impl NFTState {
    /// Check if address can transfer this NFT
    pub fn can_transfer(&self, operator: &Address) -> bool {
        if self.locked {
            return false;
        }
        // Owner can always transfer
        if &self.owner == operator {
            return true;
        }
        // Approved address can transfer
        if let Some(ref approved) = self.approved {
            if approved == operator {
                return true;
            }
        }
        false
    }

    /// Calculate royalty amount for a sale
    pub fn calculate_royalty(&self, sale_price: MuCoin) -> MuCoin {
        sale_price.percentage(self.royalty_bps as u64)
    }
}

/// NFT Contract for a collection
#[derive(Debug)]
pub struct NFTContract {
    /// Collection address (contract address)
    pub address: Address,
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Collection creator/owner
    pub creator: Address,
    /// All NFTs in this collection
    tokens: HashMap<[u8; 32], NFTState>,
    /// Token ownership index (owner -> token_ids)
    ownership: HashMap<Address, HashSet<[u8; 32]>>,
    /// Operator approvals (owner -> operators)
    operators: HashMap<Address, HashSet<Address>>,
    /// Next token index
    next_index: u64,
    /// Total supply
    pub total_supply: u64,
    /// Maximum supply (None = unlimited)
    pub max_supply: Option<u64>,
    /// Default royalty for new mints
    pub default_royalty_bps: u16,
    /// Is minting paused
    pub paused: bool,
    /// Events emitted
    events: Vec<ContractEvent>,
}

impl NFTContract {
    /// Create a new NFT contract/collection
    pub fn new(
        address: Address,
        name: String,
        symbol: String,
        creator: Address,
        max_supply: Option<u64>,
        default_royalty_bps: u16,
    ) -> ContractResult<Self> {
        if default_royalty_bps > MAX_ROYALTY_BPS {
            return Err(ContractError::RoyaltyTooHigh(default_royalty_bps));
        }

        Ok(Self {
            address,
            name,
            symbol,
            creator,
            tokens: HashMap::new(),
            ownership: HashMap::new(),
            operators: HashMap::new(),
            next_index: 0,
            total_supply: 0,
            max_supply,
            default_royalty_bps,
            paused: false,
            events: Vec::new(),
        })
    }

    /// Mint a new NFT
    pub fn mint(
        &mut self,
        to: Address,
        metadata: NFTMetadata,
        royalty_bps: Option<u16>,
        caller: &Address,
    ) -> ContractResult<[u8; 32]> {
        // Check authorization (only creator can mint)
        if caller != &self.creator {
            return Err(ContractError::Unauthorized("Only creator can mint".into()));
        }

        // Check paused
        if self.paused {
            return Err(ContractError::InvalidOperation("Minting paused".into()));
        }

        // Check max supply
        if let Some(max) = self.max_supply {
            if self.total_supply >= max {
                return Err(ContractError::MaxSupplyReached);
            }
        }

        // Validate metadata
        metadata.validate()?;

        // Determine royalty
        let royalty = royalty_bps.unwrap_or(self.default_royalty_bps);
        if royalty > MAX_ROYALTY_BPS {
            return Err(ContractError::RoyaltyTooHigh(royalty));
        }

        // Generate token ID
        let token_id = generate_id(&[
            &self.address.bytes,
            &self.next_index.to_le_bytes(),
            &metadata.content_hash,
        ]);

        // Create NFT state
        let nft = NFTState {
            token_id,
            collection: self.address.clone(),
            owner: to.clone(),
            creator: self.creator.clone(),
            metadata: metadata.clone(),
            royalty_bps: royalty,
            locked: false,
            approved: None,
            token_index: self.next_index,
        };

        // Update state
        self.tokens.insert(token_id, nft);
        self.ownership
            .entry(to.clone())
            .or_insert_with(HashSet::new)
            .insert(token_id);
        self.next_index += 1;
        self.total_supply += 1;

        // Emit event
        self.events.push(ContractEvent::NFTMinted {
            collection: self.address.clone(),
            token_id,
            owner: to,
            metadata_uri: metadata.uri,
        });

        Ok(token_id)
    }

    /// Transfer an NFT
    pub fn transfer(
        &mut self,
        token_id: &[u8; 32],
        to: Address,
        caller: &Address,
    ) -> ContractResult<()> {
        // First check authorization with immutable borrow
        let (can_transfer, owner, is_op) = {
            let nft = self.tokens.get(token_id)
                .ok_or_else(|| ContractError::NFTNotFound(hex::encode(token_id)))?;
            (nft.can_transfer(caller), nft.owner.clone(), self.is_operator(&nft.owner, caller))
        };

        if !can_transfer && !is_op {
            return Err(ContractError::Unauthorized("Not authorized to transfer".into()));
        }

        let from = owner;

        // Now get mutable borrow
        let nft = self.tokens.get_mut(token_id).unwrap();

        // Update ownership
        if let Some(owned) = self.ownership.get_mut(&from) {
            owned.remove(token_id);
        }
        self.ownership
            .entry(to.clone())
            .or_insert_with(HashSet::new)
            .insert(*token_id);

        // Update NFT state
        nft.owner = to.clone();
        nft.approved = None; // Clear approval on transfer

        // Emit event
        self.events.push(ContractEvent::NFTTransferred {
            collection: self.address.clone(),
            token_id: *token_id,
            from,
            to,
        });

        Ok(())
    }

    /// Burn an NFT
    pub fn burn(&mut self, token_id: &[u8; 32], caller: &Address) -> ContractResult<()> {
        // Get NFT
        let nft = self.tokens.get(token_id)
            .ok_or_else(|| ContractError::NFTNotFound(hex::encode(token_id)))?;

        // Check authorization (only owner can burn)
        if &nft.owner != caller {
            return Err(ContractError::Unauthorized("Only owner can burn".into()));
        }

        let owner = nft.owner.clone();

        // Remove from ownership index
        if let Some(owned) = self.ownership.get_mut(&owner) {
            owned.remove(token_id);
        }

        // Remove NFT
        self.tokens.remove(token_id);
        self.total_supply -= 1;

        // Emit event
        self.events.push(ContractEvent::NFTBurned {
            collection: self.address.clone(),
            token_id: *token_id,
            owner,
        });

        Ok(())
    }

    /// Approve address to transfer a specific NFT
    pub fn approve(
        &mut self,
        token_id: &[u8; 32],
        approved: Option<Address>,
        caller: &Address,
    ) -> ContractResult<()> {
        let nft = self.tokens.get_mut(token_id)
            .ok_or_else(|| ContractError::NFTNotFound(hex::encode(token_id)))?;

        // Only owner can approve
        if &nft.owner != caller {
            return Err(ContractError::Unauthorized("Only owner can approve".into()));
        }

        nft.approved = approved;
        Ok(())
    }

    /// Set operator approval for all tokens
    pub fn set_approval_for_all(
        &mut self,
        operator: Address,
        approved: bool,
        caller: &Address,
    ) -> ContractResult<()> {
        let operators = self.operators
            .entry(caller.clone())
            .or_insert_with(HashSet::new);

        if approved {
            operators.insert(operator);
        } else {
            operators.remove(&operator);
        }

        Ok(())
    }

    /// Check if address is approved operator
    pub fn is_operator(&self, owner: &Address, operator: &Address) -> bool {
        self.operators
            .get(owner)
            .map(|ops| ops.contains(operator))
            .unwrap_or(false)
    }

    /// Lock/unlock NFT
    pub fn set_locked(
        &mut self,
        token_id: &[u8; 32],
        locked: bool,
        caller: &Address,
    ) -> ContractResult<()> {
        let nft = self.tokens.get_mut(token_id)
            .ok_or_else(|| ContractError::NFTNotFound(hex::encode(token_id)))?;

        // Only owner can lock/unlock
        if &nft.owner != caller {
            return Err(ContractError::Unauthorized("Only owner can lock".into()));
        }

        nft.locked = locked;
        Ok(())
    }

    /// Get NFT by token ID
    pub fn get(&self, token_id: &[u8; 32]) -> Option<&NFTState> {
        self.tokens.get(token_id)
    }

    /// Get all tokens owned by address
    pub fn tokens_of(&self, owner: &Address) -> Vec<&NFTState> {
        self.ownership
            .get(owner)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.tokens.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get balance (number of NFTs owned)
    pub fn balance_of(&self, owner: &Address) -> u64 {
        self.ownership
            .get(owner)
            .map(|ids| ids.len() as u64)
            .unwrap_or(0)
    }

    /// Get owner of token
    pub fn owner_of(&self, token_id: &[u8; 32]) -> Option<&Address> {
        self.tokens.get(token_id).map(|nft| &nft.owner)
    }

    /// Pause/unpause minting (admin only)
    pub fn set_paused(&mut self, paused: bool, caller: &Address) -> ContractResult<()> {
        if caller != &self.creator {
            return Err(ContractError::Unauthorized("Only creator can pause".into()));
        }
        self.paused = paused;
        Ok(())
    }

    /// Get and clear emitted events
    pub fn take_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get total number of tokens
    pub fn total_tokens(&self) -> u64 {
        self.total_supply
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

    fn test_metadata() -> NFTMetadata {
        NFTMetadata::new(
            "Test NFT".into(),
            "A test NFT".into(),
            "ipfs://QmTest".into(),
            [1u8; 32],
        )
    }

    #[test]
    fn test_create_collection() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");

        let contract = NFTContract::new(
            contract_addr,
            "Test Collection".into(),
            "TEST".into(),
            creator,
            Some(1000),
            500, // 5% royalty
        ).unwrap();

        assert_eq!(contract.total_supply, 0);
        assert_eq!(contract.max_supply, Some(1000));
    }

    #[test]
    fn test_mint_nft() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");
        let recipient = test_address(b"recipient");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            None,
            500,
        ).unwrap();

        let metadata = test_metadata();
        let token_id = contract.mint(recipient.clone(), metadata, None, &creator).unwrap();

        assert_eq!(contract.total_supply, 1);
        assert_eq!(contract.owner_of(&token_id), Some(&recipient));
        assert_eq!(contract.balance_of(&recipient), 1);
    }

    #[test]
    fn test_transfer_nft() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");
        let owner = test_address(b"owner");
        let recipient = test_address(b"recipient");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            None,
            500,
        ).unwrap();

        let token_id = contract.mint(owner.clone(), test_metadata(), None, &creator).unwrap();

        // Transfer
        contract.transfer(&token_id, recipient.clone(), &owner).unwrap();

        assert_eq!(contract.owner_of(&token_id), Some(&recipient));
        assert_eq!(contract.balance_of(&owner), 0);
        assert_eq!(contract.balance_of(&recipient), 1);
    }

    #[test]
    fn test_unauthorized_transfer() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");
        let owner = test_address(b"owner");
        let attacker = test_address(b"attacker");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            None,
            500,
        ).unwrap();

        let token_id = contract.mint(owner.clone(), test_metadata(), None, &creator).unwrap();

        // Attacker tries to transfer
        let result = contract.transfer(&token_id, attacker.clone(), &attacker);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_approval() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");
        let owner = test_address(b"owner");
        let approved = test_address(b"approved");
        let recipient = test_address(b"recipient");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            None,
            500,
        ).unwrap();

        let token_id = contract.mint(owner.clone(), test_metadata(), None, &creator).unwrap();

        // Approve
        contract.approve(&token_id, Some(approved.clone()), &owner).unwrap();

        // Approved can transfer
        contract.transfer(&token_id, recipient.clone(), &approved).unwrap();
        assert_eq!(contract.owner_of(&token_id), Some(&recipient));
    }

    #[test]
    fn test_burn() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            None,
            500,
        ).unwrap();

        let token_id = contract.mint(creator.clone(), test_metadata(), None, &creator).unwrap();
        assert_eq!(contract.total_supply, 1);

        contract.burn(&token_id, &creator).unwrap();
        assert_eq!(contract.total_supply, 0);
        assert!(contract.get(&token_id).is_none());
    }

    #[test]
    fn test_max_supply() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");

        let mut contract = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator.clone(),
            Some(2), // Max 2
            500,
        ).unwrap();

        // Mint 2
        contract.mint(creator.clone(), test_metadata(), None, &creator).unwrap();
        contract.mint(creator.clone(), test_metadata(), None, &creator).unwrap();

        // Third should fail
        let result = contract.mint(creator.clone(), test_metadata(), None, &creator);
        assert!(matches!(result, Err(ContractError::MaxSupplyReached)));
    }

    #[test]
    fn test_royalty_limit() {
        let creator = test_address(b"creator");
        let contract_addr = test_address(b"contract");

        // 30% royalty should fail
        let result = NFTContract::new(
            contract_addr,
            "Test".into(),
            "TST".into(),
            creator,
            None,
            3000,
        );
        assert!(matches!(result, Err(ContractError::RoyaltyTooHigh(_))));
    }
}
